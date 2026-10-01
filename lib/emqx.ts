// EMQX admin API client — the piece that makes revocation *act* instead of wait.
//
// Until this existed, "revoked" meant "will be refused next time": deleting the
// ACL entry stopped the next publish, and deleting `mqtt_auth:{pk}` stopped the
// next connect, but a client already connected and subscribed kept receiving.
// The only bound on that was the MQTT token's lifetime, which is why the token
// was five minutes long — the TTL *was* the revocation mechanism (ASVS-1, LAT-1).
//
// With a kick available, the two decouple: revocation happens now, and the token
// lifetime goes back to being what it should be — a bound on a stolen credential,
// not a polling interval.
//
// Every call here is BEST EFFORT. A failed kick must never fail the user-facing
// operation that triggered it (you unfriended someone; that must succeed even if
// the broker is unreachable) — it is logged and surfaced. For a friendship the
// deleted row still stands: the topic ids it held are never handed out or
// published to again, so a subscription this failed to drop goes quiet.

import { logger } from "./logger";
import { conversationTopic, handshakeTopic } from "./topics";
import { emqxApi as call, emqxApiConfigured } from "./emqx-api";

export const EMQX = {
  /** True when an admin credential is configured at all. */
  get enabled(): boolean {
    return emqxApiConfigured();
  },

  /**
   * Disconnect a client outright. Its session (and any queued QoS-1 backlog)
   * goes with it, so use this for "this identity should not be connected at
   * all" — account deletion, a revoked device — not for unfriending, where the
   * client's other conversations are none of our business.
   *
   * 404 means "not connected", which is success for our purposes.
   */
  async kick(clientId: string): Promise<boolean> {
    if (!EMQX.enabled) return false;
    try {
      const res = await call("DELETE", `clients/${encodeURIComponent(clientId)}`);
      if (res.ok || res.status === 404) return true;
      logger.warn(`[emqx] kick ${clientId.slice(0, 12)}… → ${res.status}`);
      return false;
    } catch (e) {
      logger.error(`[emqx] kick failed for ${clientId.slice(0, 12)}…: ${(e as Error).message}`);
      return false;
    }
  },

  /**
   * Drop ONE live subscription, leaving the connection and every other
   * conversation intact. This is the unfriend path: the friendship row's
   * deletion retires the topic, and this stops the delivery already in flight.
   *
   * `POST /clients/{id}/unsubscribe` with the topic in the body. It used to be
   * `DELETE /clients/{id}/subscriptions/{topic}` — a route EMQX 5.8 does not
   * have. The broker answered with its generic HTML 404, and a 404 was read as
   * "already gone", so every unfriend reported success while the ex-friend's
   * subscription kept delivering. Found by the e2e unfriend test once it
   * checked delivery rather than a decrypted-message count.
   *
   * So a 404 counts as done ONLY when the broker says the CLIENT is not
   * connected (`CLIENTID_NOT_FOUND`) — there is then nothing to drop, and its
   * next CONNECT resubscribes only to what its directory still names.
   */
  async unsubscribe(clientId: string, topic: string): Promise<boolean> {
    if (!EMQX.enabled) return false;
    try {
      const res = await call("POST", `clients/${encodeURIComponent(clientId)}/unsubscribe`, { topic });
      if (res.ok) return true;
      if (res.status === 404) {
        const body = (await res.json().catch(() => null)) as { code?: string } | null;
        if (body?.code === "CLIENTID_NOT_FOUND") return true;
      }
      // The topic is a capability: log its kind, never its id.
      logger.warn(`[emqx] unsubscribe ${clientId.slice(0, 12)}… from ${topic.slice(0, 3)}… → ${res.status}`);
      return false;
    } catch (e) {
      logger.error(`[emqx] unsubscribe failed: ${(e as Error).message}`);
      return false;
    }
  },

  /** Both members of a friendship, off the shared topic. */
  async revokeTopic(pkA: string, pkB: string, topic: string): Promise<void> {
    await Promise.all([EMQX.unsubscribe(pkA, topic), EMQX.unsubscribe(pkB, topic)]);
  },

  /** Both members off BOTH of an ended friendship's topics. The handshake topic
   *  matters as much as the conversation: it is where an `init` is proven, so an
   *  ex-friend left on it could keep answering challenges. */
  async revokeFriendshipTopics(
    idA: string,
    idB: string,
    topics: { convoId: string; handshakeId: string }
  ): Promise<void> {
    await Promise.all([
      EMQX.revokeTopic(idA, idB, conversationTopic(topics.convoId)),
      EMQX.revokeTopic(idA, idB, handshakeTopic(topics.handshakeId)),
    ]);
  },

  /**
   * Tell these clients their friend graph changed, so they pull it now instead
   * of on their next poll.
   *
   * The graph is the one piece of state the server owns and the client can only
   * learn by asking. Nothing pushed it, so every change waited on a 60-second
   * timer — which is why an invite needed a manual refresh to appear, and why an
   * `init` from a freshly accepted contact could arrive before the recipient had
   * any idea who the sender was. The frame named a client id the recipient's
   * directory did not contain yet, so it was dropped.
   *
   * A nudge carries NOTHING but the fact that something changed. It travels on a
   * topic the owner alone may subscribe to, and the client answers it by calling
   * the same authenticated `/friends` it always did — so this adds no way to
   * learn anything that endpoint would not already tell that caller, and a
   * spoofed nudge costs one directory fetch.
   *
   * Not retained: a client that was offline pulls the directory on connect
   * anyway, so a retained nudge would only make every reconnect do it twice.
   *
   * Best-effort by design. Every caller is a state change that has ALREADY been
   * committed; failing to announce it costs latency, not correctness, because
   * the poll is still there underneath.
   */
  async notifyGraphChanged(ids: string[]): Promise<void> {
    if (!EMQX.enabled) return;
    await Promise.all(ids.filter(Boolean).map(async (id) => {
      try {
        const res = await call("POST", "publish", {
          topic: `u/${id}/graph`,
          payload: JSON.stringify({ t: "graph" }),
          qos: 1,
          retain: false,
        });
        // 202 is EMQX's "accepted, but no subscriber right now" — the ordinary
        // answer for an offline client, and not a failure.
        if (!res.ok && res.status !== 202) {
          logger.warn(`[emqx] graph nudge ${id.slice(0, 12)}… → ${res.status}`);
        }
      } catch (e) {
        logger.warn(`[emqx] graph nudge failed for ${id.slice(0, 12)}…: ${(e as Error).message}`);
      }
    }));
  },
};
