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
// the broker is unreachable) — it is logged and surfaced, and the ACL edit still
// stands, so the next authorization check refuses them anyway.

import { logger } from "./logger";

const API = `${process.env.EMQX_API_URL || "http://emqx:18083"}/api/v5`;
const USER = process.env.EMQX_DASHBOARD_USER || "admin";
const PASS = process.env.EMQX_DASHBOARD_PASSWORD || "";

let token: string | null = null;

async function login(): Promise<string> {
  const res = await fetch(`${API}/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: USER, password: PASS }),
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error(`emqx login ${res.status}`);
  const body = (await res.json()) as { token?: string };
  if (!body.token) throw new Error("emqx login returned no token");
  return body.token;
}

/** One admin call, re-authenticating once on 401 so an expired token self-heals. */
async function call(method: string, path: string, body?: unknown, retry = true): Promise<Response> {
  if (!token) token = await login();
  const res = await fetch(`${API}/${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(5000),
  });
  if (res.status === 401 && retry) {
    token = null;
    return call(method, path, body, false);
  }
  return res;
}

export const EMQX = {
  /** True when an admin credential is configured at all. */
  get enabled(): boolean {
    return PASS.length > 0;
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
   * conversation intact. This is the unfriend path: the ACL edit blocks the next
   * authorization check, and this stops the delivery already in flight.
   */
  async unsubscribe(clientId: string, topic: string): Promise<boolean> {
    if (!EMQX.enabled) return false;
    try {
      const res = await call(
        "DELETE",
        `clients/${encodeURIComponent(clientId)}/subscriptions/${encodeURIComponent(topic)}`
      );
      if (res.ok || res.status === 404) return true;
      logger.warn(`[emqx] unsubscribe ${clientId.slice(0, 12)}… from ${topic} → ${res.status}`);
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
