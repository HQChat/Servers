// Push-bridge entrypoint (Phase 2 — see deploy/EXTRACTION_PLAN.md).
//
// Subscribes to every conversation topic and fires a CONTENT-FREE APNs wake to
// any conversation member who is currently offline. It sees ciphertext +
// metadata only — never plaintext.
//
// Presence is learned purely over MQTT (no EMQX API key needed): clients publish
// a RETAINED `u/{id}/presence` = {"s":"online"} on connect and set an LWT
// {"s":"offline"} so a drop flips them offline. The bridge tracks this in-memory
// from the `u/+/presence` wildcard (each replica sees all presence). The message
// subscription is SHARED (`$share/…`) so replicas split the fan-in.
//
// Both are WILDCARD subscriptions, which the broker refuses to every ordinary
// client (`mqtt.wildcard_subscription = false` — the setting that keeps anyone
// from scraping `cv/+`). This bridge connects to the INTERNAL listener instead,
// whose zone allows them and whose authentication admits only the internal
// identity (infra/deploy/emqx/emqx.conf).
//
// ⚠️ This file PARSES topics, which makes it the one service that would keep
// working while being wrong if the topic scheme changed under it. `{id}` here is
// the client id — sha256(hex(pk)), 64 hex characters — and the `online` set,
// the members `getTopicMembers` returns and `ApnsService.send` are all keyed on
// that same value. A conversation topic is `cv/{convo_id}`, the friendship's
// random topic id, NOT anything derived from the members.
// Extracting one form and looking up the other would produce a bridge that
// never wakes anybody and never logs an error.
//
// It authenticates to EMQX with the privileged internal credential, which the
// auth server's /mqtt/authn grants superuser (bypassing the static ACL).

// Must be first: importing it loads .env + resolves *_FILE secrets before
// anything reads env. `assertConfig` is called below, once the log sink is up.
import { assertConfig } from "../lib/config";
import { initObservability } from "../lib/observability";
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import * as http from "http";
import mqtt from "mqtt";
import { DB } from "../services/db/api";
import { ApnsService, keyProblem, type SendOutcome } from "../services/apns/api";
import { apnsGaps, apnsIntended, apnsSummary } from "../lib/apns-config";
import { listenOn, parseHosts } from "../lib/listen";

// The one service that sends a push is the one that validates APNs. That used
// to be nobody: `assertConfig` was called by auth and app-api — neither of which
// is mounted the .p8 — and never here, so a half-configured or entirely absent
// APNs setup produced a bridge that booted cleanly and woke no one, forever.
//
// It warns rather than exits (see lib/config.ts): waking nobody is what both a
// half-config and no config do, and only one of those also crash-loops the
// container. What this service adds is the escalation — an INTENDED but broken
// APNs setup is a deploy mistake somebody is waiting on, so it goes to
// logger.error and therefore to Sentry, once, at boot.
assertConfig(["apns"]);
const keyIssue = keyProblem();
if (keyIssue && apnsIntended(process.env) && !apnsGaps(process.env).includes("APNS_KEY_P8")) {
  // The key is present and unusable — a different failure from a missing one,
  // and the only one that used to reach the log as an OpenSSL stack trace.
  logger.error(`[push-bridge] APNs key is unusable: ${keyIssue}. No device will be woken.`);
}
if (apnsGaps(process.env).length && apnsIntended(process.env)) {
  logger.error(
    `[push-bridge] ${apnsSummary(process.env)}. An APNs key is present but the rest ` +
    `is not, so every wake will be dropped in silence. The credentials are secrets; ` +
    `APNS_KEY_ID / APNS_TEAM_ID / APNS_TOPIC_IOS / APNS_TOPIC_MACOS / APNS_ENV are not ` +
    `and belong in server.env. scripts/check-push.ts reports the full picture.`
  );
}

const PORT = Number(process.env.PORT || 8080);
// The internal listener, not the public WS one: see the header.
const EMQX_URL = process.env.EMQX_URL || "mqtt://emqx:1884";
const INTERNAL_MQTT_USER = process.env.INTERNAL_MQTT_USER || "svc-internal";
const INTERNAL_MQTT_SECRET = process.env.INTERNAL_MQTT_SECRET || "";
const SHARE_GROUP = process.env.PUSH_SHARE_GROUP || "pushbridge";

// In-memory presence by client id, kept current from retained/LWT
// `u/{id}/presence` messages.
const online = new Set<string>();

/**
 * What this bridge does with one inbound MQTT message, separated from the client
 * that delivers them.
 *
 * SEPARATED SO IT CAN BE TESTED. This module used to connect to EMQX and open a
 * port at import time, so nothing could load it, and the two decisions that
 * matter went unchecked: presence tracking (get it wrong and a device is never
 * woken, with no error anywhere) and the wake rule itself.
 *
 * The dependencies are injected rather than imported so a test can drive the
 * logic without a broker, a database or APNs. In production they are `DB` and
 * `ApnsService`, wired below.
 */
export interface PushDeps {
  getTopicMembers: (convoId: string) => Promise<string[]>;
  send: (id: string, title: string, body: string) => Promise<SendOutcome>;
}

export function createPushBridge(deps: PushDeps, presence: Set<string> = new Set()) {
  async function handleMessage(topic: string, payload: Buffer): Promise<void> {
    try {
      // Presence update: u/{id}/presence
      //
      // The id pattern is spelled out rather than left as `[^/]+`: a topic that
      // does not carry a well-formed id is one this bridge would happily add to
      // `online` under a name nothing else uses, and the only symptom would be a
      // device that stops being woken.
      const pres = topic.match(/^u\/([0-9a-f]{64})\/presence$/);
      if (pres && pres[1]) {
        const id = pres[1];
        const s = payloadState(payload);
        if (s === "online") presence.add(id);
        else presence.delete(id); // "offline" or a cleared retained message
        return;
      }

      // Conversation message: cv/{convo_id} → wake offline members.
      const convo = topic.match(/^cv\/([0-9a-f]{64})$/);
      if (convo && convo[1]) {
        const convoId = convo[1];
        // Ids, same as `presence` holds and same as ApnsService keys tokens on.
        const members = await deps.getTopicMembers(convoId);
        if (members.length === 0) {
          // An id no friendship holds. Unlike the old derived topics this is not
          // necessarily a bug: an ex-friend still knows a retired id and may
          // publish to it, and nobody should be woken for that. Once per id, so
          // a persistent one does not repeat per message.
          sayOnce(`convo:${convoId}`,
                  `[push-bridge] no friendship holds ${short(convoId)} — nobody to wake ` +
                  `(a retired topic, or friendships.convo_id and the client disagree).`);
          return;
        }
        for (const id of members) {
          // The sender is online and skipped here too: that is not a special
          // case, it is the same rule.
          if (presence.has(id)) continue;
          // Content-free wake — the payload is ciphertext and never inspected.
          report(id, await deps.send(id, "New message", "You have a new message"));
        }
      }
    } catch (e) {
      logger.error(`[push-bridge] handling ${topic}: ${(e as Error).message}`);
    }
  }
  return { handleMessage, presence };
}

/**
 * What this bridge subscribes to, and how.
 *
 * The two lines are not symmetrical and must not be made so:
 *
 *   PRESENCE IS UNSHARED. Every replica needs every presence update, because
 *   each keeps its own `online` set and consults it before waking anybody. Put
 *   this in a shared group and each update reaches exactly one replica — the
 *   others then believe a device is offline when it is not, or the reverse, and
 *   the only symptom is a phone that buzzes during a conversation the user is
 *   already reading, or does not buzz at all.
 *
 *   CONVERSATIONS ARE SHARED. Every replica seeing every message means every
 *   replica sends the same push, so a two-replica deployment wakes each device
 *   twice. QoS 1 because a dropped conversation message is a wake that never
 *   happens, and nothing retries it.
 *
 * Separated from the connect handler so both halves can be asserted — the
 * failure in either direction is silent, and neither is visible from inside the
 * process.
 */
export function pushSubscriptions(shareGroup: string = SHARE_GROUP): Array<{ topic: string; qos: 0 | 1 }> {
  return [
    { topic: "u/+/presence", qos: 0 },
    { topic: `$share/${shareGroup}/cv/+`, qos: 1 },
  ];
}

/** The compose healthcheck endpoint. */
export function createHealthHandler(presence: Set<string>): http.RequestListener {
  return (req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ ok: true, service: "push-bridge", online: presence.size }));
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  };
}

// --- Boot -------------------------------------------------------------------
//
// Only when this file is the process entry point. Imported, it defines the
// bridge and connects to nothing — no broker, no port, no APNs, and no
// `process.exit` from assertConfig.
if (require.main === module) {
  initObservability("push-bridge");
  bootPushBridge();
}

function bootPushBridge(): void {
  assertConfig(["apns"]);
  const keyIssue = keyProblem();
  if (keyIssue) logger.error(`[push-bridge] ${keyIssue}`);

  const bridge = createPushBridge({
    getTopicMembers: (convoId) => DB.getTopicMembers(convoId),
    send: (id, title, body) => ApnsService.send(id, title, body),
  }, online);

  listenOn(() => http.createServer(createHealthHandler(online)), PORT, parseHosts(process.env.LISTEN_HOST),
    (host) => logger.startup(`📨 push-bridge health on ${host}:${PORT}`));

  // Event-loop / memory / query-latency early warning → Sentry. A stalled bridge
  // silently stops waking offline devices, so it needs the same watch as the relay.
  healthMonitor.start();

  if (!INTERNAL_MQTT_SECRET) {
    logger.error("[push-bridge] INTERNAL_MQTT_SECRET unset — cannot authenticate to EMQX");
  }

  const client = mqtt.connect(EMQX_URL, {
    clientId: `pushbridge-${Math.random().toString(16).slice(2, 10)}`,
    username: INTERNAL_MQTT_USER,
    password: INTERNAL_MQTT_SECRET,
    clean: true,
    reconnectPeriod: 5000,
    keepalive: 30,
  });

  client.on("connect", () => {
    logger.startup(`📨 push-bridge connected to EMQX at ${EMQX_URL}`);
    // Said on every connect, not just at boot: this line is the answer to "why
    // did my phone not buzz", and it should be in the log the operator is
    // already reading rather than one they have to go find.
    logger.startup(`📨 ${apnsSummary(process.env)}`);
    for (const { topic, qos } of pushSubscriptions()) client.subscribe(topic, { qos });
  });

  client.on("error", (e) => logger.error(`[push-bridge] mqtt: ${e.message}`));
  client.on("reconnect", () => logger.warn("[push-bridge] reconnecting to EMQX…"));

  // The decision itself lives in createPushBridge, where a test can reach it.
  client.on("message", (topic, payload) => { void bridge.handleMessage(topic, payload); });
}

/** Ids are 64 hex characters and unreadable at full length; 8 is enough to
 *  correlate a line with `check-push` output without putting a whole identifier
 *  in a log file. */
function short(id: string): string {
  return `${id.slice(0, 8)}…`;
}

// A wake failure repeats on every single message, so each reason is said once
// and then kept quiet — otherwise the one line worth reading is buried under
// thousands of copies of itself.
//
// Deploy mistakes are the SAME for every account, so they are deduplicated
// globally rather than per id: `no-config` on ten thousand users is one fact,
// not ten thousand. Per-device failures keep their id.
const said = new Set<string>();

/** Warn the first time this key is seen, and never again. */
function sayOnce(key: string, message: string): void {
  if (said.has(key)) return;
  said.add(key);
  logger.warn(message);
}

/** Log what became of one wake, without drowning the log in repeats. */
function report(id: string, outcome: SendOutcome): void {
  switch (outcome) {
    case "sent":
      logger.debug(`[push-bridge] woke ${short(id)}`);
      return;
    case "no-token":
      // Ordinary: a peer who has never opened the app on a device that
      // registered, or a macOS-only account. Nothing to fix.
      logger.debug(`[push-bridge] ${short(id)} is offline and has no push token`);
      return;
    case "bad-key":
    case "no-config":
    case "no-topic-ios":
    case "no-topic-macos":
      // Not about this account — it is the same for everyone. Say it once,
      // globally, and point at the fix.
      sayOnce(outcome,
              `[push-bridge] waking NOBODY: ${outcome}. ${apnsSummary(process.env)} — ` +
              `run scripts/check-push.ts for the full report.`);
      return;
    case "rejected":
    case "error":
      // These are per-device: a token Apple refuses belongs to one install.
      sayOnce(`${id}:${outcome}`, `[push-bridge] could not wake ${short(id)}: ${outcome}`);
      return;
  }
}

/** Parse a presence payload → "online" | "offline". Empty/cleared retained = offline. */
function payloadState(payload: Buffer): "online" | "offline" {
  const raw = payload.toString("utf8").trim();
  if (!raw) return "offline";
  try {
    const j = JSON.parse(raw);
    return j?.s === "online" ? "online" : "offline";
  } catch {
    return raw === "online" ? "online" : "offline";
  }
}
