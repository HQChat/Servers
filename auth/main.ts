// Auth server entrypoint (Phase 1 — see deploy/EXTRACTION_PLAN.md).
//
// Owns the HQC-KEM handshake that proves a client owns its public key, the
// admission gate, and token issuance. It replaces the WS AUTH_INIT/AUTH_CHALLENGE
// /AUTH_VERIFY flow from server.ts with stateless REST:
//
//   POST /auth/free/init    { pk }                -> { ct }         (KEM challenge)
//   POST /auth/free/verify  { pk, solution, mqttSigningKey? } -> free session
//   POST /auth/paid/init    { pk }                -> { ct } or 403   (admission gate)
//   POST /auth/paid/verify  { pk, solution, mqttSigningKey? } -> premium session
//   POST /auth/refresh (Bearer) { mqttSigningKey? } -> key id + serverTime (+ legacy token)
//   GET  /auth/transport                          -> the hqn/1 gateway, if enabled
//   POST /mqtt/authn  (EMQX hook)                 -> { result }  (v1 signed proof, or legacy token)
//
// `pk` is the full public key, and these routes are the ONLY place it enters the
// system: the server has to encapsulate to it, which nothing else in the stack
// does. Everything downstream — the session, the ACL, the topics, the broker's
// client id, `/mqtt/authn`'s username — names the caller by `peerId(pk)`
// instead. `/auth/*/verify` is where the two are tied together (DB.ensureUser),
// immediately after the KEM proof establishes that the caller holds the key.
//
// TWO DOORS, not one endpoint with a flag. Nothing is sold at either — the
// product is free and donation-funded — and on the default `open` policy both
// admit anyone who proves key possession. What separates them is what they
// MINT: the free door grants a bot-only session, the full door grants the whole
// friend graph. The split survives the paywall because it is what lets a client
// fall back instead of failing shut when a private (`allowlist`) server refuses
// it. The full door's wire name is still "paid"; nothing behind it costs money.
//
// Transport confidentiality is TLS (WSS via nginx) or hqn/1 (raw TCP through
// noise-gw, lib/noise.ts) — there is NO per-connection AES session key here any
// more (the SESSION_KEY step is deleted; the transport replaces it).
// Runs the SAME image as the monolith via `command:` in the compose overlay.

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import "../lib/config";
import { initObservability } from "../lib/observability";
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import * as http from "http";
import { readJson, send, bearer, clientIp, requireString, HttpError } from "../lib/http";
import * as crypto from "crypto";
// hqc is lazy-required inside /auth/init (it dlopen's the native x86 .so; keeping
// it out of the import graph lets the auth server boot — and serve the token/
// refresh/authn paths — anywhere the lib is absent, matching secure-transport.ts).
import { authProof } from "../lib/auth-proof";
import { resolveTransportInfo } from "../lib/transport-config";
import {
  isV1Password,
  parseProofPassword,
  proofMessage,
  isFreshTimestamp,
  verifyProofSignature,
  ed25519PublicKey,
  MQTT_PROOF_NONCE_TTL_SECONDS,
} from "../lib/mqtt-proof";
import { checkAdmission, type Door } from "../lib/admission";
import { peerId } from "../lib/identity";
import { DB, type SessionScope } from "../services/db/api";
import { listenOn, parseHosts } from "../lib/listen";

const PORT = Number(process.env.PORT || 8080);

// --- Anti-automation (ASVS-3, ASVS-4) --------------------------------------
// `/auth/init` cannot require authentication — proving who you are is what it is
// for — and every call runs an HQC encapsulation (CPU) plus a database write. Left
// open it is a cheap way to make the auth service the bottleneck for everyone.
// nginx rate-limits the REST zone, but that is one bucket shared with every
// other route; these are per-IP and per-key.
//
// Lowered when the paywall was removed. An unclaimed key used to be turned away
// at the full door for the cost of one primary-key lookup, so the encapsulation
// sat behind a subscription; now nothing stands in front of it but these two
// counters. A real client runs one init per login, so the per-key ceiling is
// generous at 6; the per-IP one has to stay loose enough for a NAT.
const INIT_PER_IP_PER_MIN = Number(process.env.AUTH_INIT_IP_LIMIT || 20);
const INIT_PER_PK_PER_MIN = Number(process.env.AUTH_INIT_PK_LIMIT || 6);
// Repeated FAILED proofs against one public key are the signature of someone
// trying to authenticate as a key they do not hold. Nothing counted them before,
// so the attempt was invisible however long it went on.
const VERIFY_FAILURE_ALERT = Number(process.env.AUTH_VERIFY_FAILURE_ALERT || 5);
// Internal service credential (push-bridge etc.): a privileged MQTT identity that
// authn grants superuser so it can subscribe across conversations. The secret is
// a compose secret resolved via INTERNAL_MQTT_SECRET_FILE.
const INTERNAL_MQTT_USER = process.env.INTERNAL_MQTT_USER || "svc-internal";
const INTERNAL_MQTT_SECRET = process.env.INTERNAL_MQTT_SECRET || "";

const BOT_USERNAME = process.env.BOT_USERNAME || "helper";

/**
 * Friend the helper bot to a user, so a brand-new account opens on a
 * conversation instead of an empty screen (the bot's welcome message rides that
 * friendship). The `/ws` monolith did this on every login and was the ONLY
 * place it happened, so retiring it at Phase 4 would have silently removed the
 * first thing a new user ever sees. It lives here now, on the one path every
 * client — apps and bot alike — goes through.
 *
 * Idempotent and best-effort: on a cold stack the bot may not have claimed its
 * handle yet, and a login must never fail because of that. The next login
 * retries.
 */
async function ensureBotFriendship(id: string): Promise<void> {
  try {
    const botId = await DB.getIdByUsername(BOT_USERNAME);
    if (!botId || botId === id) return; // bot not registered yet, or this IS the bot
    // The row is the whole friendship: its topic ids are minted by the column
    // default and reach both sides through /friends.
    if (!(await DB.areFriends(id, botId))) await DB.createFriendship(id, botId);
  } catch (e) {
    logger.warn(`[auth] helper-bot auto-friend failed for ${id.slice(0, 12)}…: ${(e as Error).message}`);
  }
}

/** Constant-time equality for two utf8/hex strings of possibly differing length. */
function safeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/**
 * Refuse a door, in the shape the client can act on.
 *
 * Only 403 is left. It used to also answer 402 "this key has no live
 * subscription", which the app read as "fall back to the free door" — there is
 * no subscription to lack now, so nothing produces it. The app still HANDLES
 * 402 on the way to the free door, deliberately: that is what keeps a current
 * build working against a server that has not been updated yet.
 */
function refuse(res: http.ServerResponse, admission: { reason: "denied" }): void {
  return send(res, 403, { error: "NOT_ADMITTED" });
}

/**
 * Open a KEM challenge for a door.
 *
 * The order of the checks is the point. Cheap shape check, then the rate-limit
 * counters, then admission — and only then the native HQC library and the
 * encapsulation. An unclaimed key knocking on the paid door costs one
 * primary-key lookup and never reaches `dlopen`, let alone a keygen-sized CPU burn.
 */
async function handleInit(req: http.IncomingMessage, res: http.ServerResponse, door: Door): Promise<void> {
  const { pk } = await readJson(req);
  const pkHex = String(pk || "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(pkHex)) return send(res, 400, { error: "bad public key" });
  // Everything below names this caller by its id. The key is kept only for the
  // encapsulation and for the `users` row.
  const id = peerId(pkHex);

  const ip = clientIp(req);
  const [ipHits, pkHits] = await Promise.all([
    DB.bumpCounter(`init:ip:${ip}`, 60),
    // `init:pk:{id}`, not `init:pk:{key}`. The counter key used to carry a whole
    // 14 kB public key into `rate_counters`, which is why that table needed the
    // same digest-index treatment as the identity tables.
    DB.bumpCounter(`init:pk:${id}`, 60),
  ]);
  if (ipHits > INIT_PER_IP_PER_MIN || pkHits > INIT_PER_PK_PER_MIN) {
    logger.warn(`[auth] ${door} init rate-limited (ip=${ipHits}/${INIT_PER_IP_PER_MIN}, pk=${pkHits}/${INIT_PER_PK_PER_MIN})`);
    return send(res, 429, { error: "RATE_LIMITED" });
  }

  const admission = await checkAdmission(pkHex, door);
  if (!admission.ok) return refuse(res, admission);

  const { HqcWrapper, HQC_CONSTANTS } = require("../lib/hqc") as typeof import("../lib/hqc");
  if (pkHex.length !== HQC_CONSTANTS.PUBLIC_KEY_BYTES * 2) {
    return send(res, 400, { error: "bad public key" });
  }

  const { ct, ss } = HqcWrapper.encapsulate(Buffer.from(pkHex, "hex"));
  await DB.startAuthChallenge(id, authProof(ss).toString("hex"));
  return send(res, 200, { ct: ct.toString("base64") });
}

/**
 * The optional `mqttSigningKey` a client registers at sign-in and refresh: the
 * public half of its per-session Ed25519 key, raw 32 bytes, base64. Absent is
 * fine — an older client still lives on the legacy token — but present and
 * malformed is a 400, checked BEFORE anything is consumed, so a client bug
 * cannot burn a sign-in challenge on its way to failing.
 */
function readSigningKey(body: any): Buffer | null {
  if (body?.mqttSigningKey === undefined || body?.mqttSigningKey === null) return null;
  const raw = Buffer.from(String(body.mqttSigningKey), "base64");
  if (raw.length !== 32 || raw.toString("base64") !== String(body.mqttSigningKey) || !ed25519PublicKey(raw)) {
    throw new HttpError(400, "INVALID_MQTT_SIGNING_KEY", "mqttSigningKey must be a raw 32-byte Ed25519 public key, base64");
  }
  return raw;
}

/** What a session response carries about the v1 CONNECT proof. `serverTime`
 *  goes out on every response, key or not: the proof's timestamp is judged by
 *  THIS clock, and a phone's can be minutes off. */
async function mqttKeyFields(id: string, signingKey: Buffer | null) {
  const serverTime = Math.floor(Date.now() / 1000);
  if (!signingKey) return { serverTime };
  const { keyId, expiresAt } = await DB.registerMqttKey(id, signingKey);
  return { serverTime, mqttKeyId: keyId, mqttKeyExpiresAt: expiresAt };
}

/** Whether the pre-v1 opaque token is still accepted on CONNECT. Every client
 *  in this repository signs its CONNECTs — the app, the helper bot, the e2e
 *  client (run-local.sh runs the whole suite with this OFF to prove it) — so
 *  the token remains only for app builds already installed. Turn it off with
 *  `MQTT_LEGACY_TOKEN=0` once those have aged out. Read per request so it can be
 *  flipped without a rebuild. */
function legacyTokenAllowed(): boolean {
  return process.env.MQTT_LEGACY_TOKEN !== "0";
}

type ConnectVerdict = { ok: true; expireAt: number } | { ok: false };

/**
 * Check a v1 CONNECT proof (lib/mqtt-proof.ts). The ORDER is the security:
 *
 *   shape → clientid binding → timestamp window → key lookup → signature → nonce
 *
 * The nonce is spent LAST, only for a proof that verified. Spend it earlier and
 * anyone could burn a client's nonce with a garbage signature — harmless for a
 * random 16-byte nonce, but it would make "the nonce was already used" mean
 * two different things.
 */
async function verifyV1Connect(id: string, clientid: string, password: string): Promise<ConnectVerdict> {
  const proof = parseProofPassword(password);
  if (!proof) return { ok: false };
  if (clientid !== id) {
    logger.warn(`[auth] v1 CONNECT clientid does not match username id=${id.slice(0, 12)}…`);
    return { ok: false };
  }
  if (!isFreshTimestamp(proof.ts, Math.floor(Date.now() / 1000))) return { ok: false };
  const key = await DB.getMqttSessionKey(id, proof.keyId);
  if (!key) return { ok: false };
  const message = proofMessage(clientid, proof.keyId, proof.ts, proof.nonce);
  if (!verifyProofSignature(key.publicKey, message, proof.sig)) return { ok: false };
  if (!(await DB.useNonce(`v1:${id}:${proof.nonce.toString("hex")}`, MQTT_PROOF_NONCE_TTL_SECONDS))) {
    // A valid signature on a spent nonce is a replayed CONNECT — the one case
    // the proof exists to stop. Visible, because it means someone holds a copy.
    logger.warn(`[auth] v1 CONNECT replayed for id=${id.slice(0, 12)}…`);
    return { ok: false };
  }
  return { ok: true, expireAt: key.expireAt };
}

/**
 * Consume the challenge, re-check admission, and mint a session at the door's
 * scope.
 *
 * Admission is checked AGAIN here, not because the client could have changed
 * doors — it can, freely — but because the subscription can lapse inside the
 * challenge's 60-second window, and the scope minted here outlives the request.
 *
 * The free door deliberately does NOT revoke friend topics. Cancellation
 * revokes, on the webhook, where an actual event says so; a client that lands
 * on the free door because a database read blipped would otherwise tear down every
 * conversation it has and rebuild them on the next successful paid login.
 */
async function handleVerify(req: http.IncomingMessage, res: http.ServerResponse, door: Door): Promise<void> {
  const body = await readJson(req);
  const { pk, solution } = body;
  const signingKey = readSigningKey(body);
  const pkHex = String(pk || "").toLowerCase();
  const id = peerId(pkHex);
  const solutionHex = Buffer.from(String(solution || ""), "base64").toString("hex");

  // Atomically consume the open challenge (single-use — no replay).
  const expectedHex = await DB.takeAuthChallenge(id);
  if (!expectedHex || !safeEqualStr(solutionHex, expectedHex)) {
    // A wrong proof is either a client bug or someone trying to sign in as a key
    // they do not hold. Either way it should be visible: logger.error reaches
    // Sentry, so a run of them raises an alert instead of vanishing.
    const failures = await DB.bumpCounter(`verify:fail:${id}`, 15 * 60);
    if (failures === VERIFY_FAILURE_ALERT) {
      logger.error(`🚨 [auth] ${failures} failed key-possession proofs in 15m for one public key (ip=${clientIp(req)})`);
    }
    return send(res, 401, { error: "auth failed" });
  }
  // A success clears the run, so an alert means a genuine sustained burst.
  await DB.clearCounter(`verify:fail:${id}`);

  const admission = await checkAdmission(pkHex, door);
  if (!admission.ok) return refuse(res, admission);

  const scope: SessionScope = door === "paid" ? "premium" : "free";

  // Record the identity: the id, and the key that id names.
  //
  // This is the only place `users.identity_pk` is written, and it happens HERE
  // rather than at /username because this is the moment the caller has proved
  // it holds the secret key. It is also what makes `GET /peer/{id}/key`
  // answerable at all: no table stored an account's identity key before this
  // change, because `users.pk` was identity and key material at once.
  await DB.ensureUser(id, pkHex);

  // No topic grants: the broker's ACL is static (infra/deploy/emqx/acl.conf)
  // and keys the per-user topics on the authenticated clientid.
  await ensureBotFriendship(id);

  const username = await DB.getUsername(id);
  const sessionToken = await DB.mintSessionToken(id, scope);
  const mqttToken = await DB.mintMqttToken(id);
  const keyFields = await mqttKeyFields(id, signingKey);
  return send(res, 200, {
    // The client's own identity, both halves. `id` is what it must present as
    // its MQTT client id and username; `pk` is echoed back so a client can
    // confirm the server read the key it sent.
    id,
    pk: pkHex,
    username: username || null,
    scope,
    sessionToken,
    mqttToken,
    mqttTtl: DB.MQTT_TOKEN_TTL_SECONDS,
    // Absolute expiry (unix seconds) so the client can refresh proactively,
    // before EMQX force-disconnects at expire_at.
    mqttExpiresAt: Math.floor(Date.now() / 1000) + DB.MQTT_TOKEN_TTL_SECONDS,
    // v1 CONNECT proof: the id of the key just registered, when one was sent.
    ...keyFields,
  });
}

/**
 * Every route this service answers, as a plain request listener.
 *
 * SEPARATED FROM THE LISTENER so it can be tested. This module used to build the
 * server and call `listen()` at import time, which meant no test could load it
 * at all — importing it opened a socket — and `/mqtt/authn`, the hook EMQX calls
 * on every single CONNECT and the barrier between one conversation and another,
 * had no test of any kind. Neither did the handshake routes.
 *
 * Nothing about the behaviour changes: the same closure, now reachable.
 */
export function createAuthHandler(): http.RequestListener {
  return async (req, res) => {
  const url = req.url || "";
  const method = req.method || "GET";
  try {
    if (method === "GET" && url === "/health") {
      return send(res, 200, { ok: true, service: "auth" });
    }

    // Where the raw-TCP transport lives and which keys to pin — and the switch
    // that turns it off for everyone. Public, unauthenticated: a client asks
    // before it has a session, and nothing in it is secret. lib/transport-config.ts.
    if (method === "GET" && url === "/auth/transport") {
      return send(res, 200, await resolveTransportInfo());
    }

    // --- 1. HQC-KEM challenge, per door -------------------------------------
    if (method === "POST" && (url === "/auth/free/init" || url === "/auth/paid/init")) {
      return await handleInit(req, res, url === "/auth/paid/init" ? "paid" : "free");
    }

    // --- 2. Verify the proof, admit, issue a scoped session ------------------
    if (method === "POST" && (url === "/auth/free/verify" || url === "/auth/paid/verify")) {
      return await handleVerify(req, res, url === "/auth/paid/verify" ? "paid" : "free");
    }

    // --- 3. Rotate the MQTT token (proactive refresh / after expiry) ---------
    // Authenticated by the REST session bearer, so a client refreshes without
    // redoing the KEM handshake. The scope rides along untouched: a refresh
    // rotates a credential, it does not re-decide an entitlement.
    if (method === "POST" && url === "/auth/refresh") {
      const session = await DB.resolveSessionToken(bearer(req));
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const signingKey = readSigningKey(await readJson(req));
      const mqttToken = await DB.mintMqttToken(session.id);
      return send(res, 200, {
        mqttToken,
        scope: session.scope,
        mqttTtl: DB.MQTT_TOKEN_TTL_SECONDS,
        mqttExpiresAt: Math.floor(Date.now() / 1000) + DB.MQTT_TOKEN_TTL_SECONDS,
        ...(await mqttKeyFields(session.id, signingKey)),
      });
    }

    // --- 4. EMQX HTTP authentication hook ------------------------------------
    // EMQX posts { username, password, clientid } on every CONNECT to the
    // public listeners. Never a superuser here (see /mqtt/authn/internal).
    // username = the CLIENT ID (sha256 of the hex public key), password =
    // the opaque token; we verify it and hand EMQX the token's `expire_at` so
    // EMQX DISCONNECTS the client at expiry → the client refreshes and
    // reconnects (expiration-based rotation). A v1 password is instead a signed,
    // single-use proof (lib/mqtt-proof.ts), and that is what blocks replay.
    // EMQX expects HTTP 200 with { result: "allow"|"deny", is_superuser?, expire_at? }.
    //
    // The username used to be the whole 14474-character public key, which the
    // broker also carried as the clientid on every CONNECT packet. Both are 64
    // characters now, and the static ACL (acl.conf) interpolates ${clientid}
    // into the per-user topics.
    // The INTERNAL listener's hook (emqx.conf `listeners.tcp.internal`): the
    // privileged identity, and nobody else. That listener's zone allows wildcard
    // subscriptions — the push-bridge needs `u/+/presence` and
    // `$share/…/cv/+` — so an ordinary client admitted there could scrape every
    // conversation. The public hook below, conversely, never grants superuser:
    // a leaked internal secret presented on the public WS listener is refused
    // rather than handed a session that bypasses the ACL.
    if (method === "POST" && url === "/mqtt/authn/internal") {
      const body = await readJson(req);
      const username = String(body.username || "");
      const password = String(body.password || "");
      const ok =
        !!INTERNAL_MQTT_SECRET &&
        username === INTERNAL_MQTT_USER &&
        safeEqualStr(password, INTERNAL_MQTT_SECRET);
      return send(res, 200, ok ? { result: "allow", is_superuser: true } : { result: "deny" });
    }

    if (method === "POST" && url === "/mqtt/authn") {
      const body = await readJson(req);
      const username = String(body.username || "");
      const password = String(body.password || "");

      const id = username.toLowerCase();
      if (!id || !password) return send(res, 200, { result: "deny" });

      // v1: a signed, single-use proof (lib/mqtt-proof.ts). Decided by the
      // password's shape alone — a legacy token is 64 hex characters and can
      // never start with "v1.".
      if (isV1Password(password)) {
        const verdict = await verifyV1Connect(id, String(body.clientid || ""), password);
        return send(res, 200, verdict.ok
          ? { result: "allow", expire_at: verdict.expireAt }
          : { result: "deny" });
      }
      // The legacy token. It had an optional "CONNECT nonce" replay guard here
      // that could never run — EMQX's authn body never carries a nonce, and
      // MQTT 3.1.1 has no field for one. Replay protection is the v1 proof's
      // single-use nonce above; a client that wants it signs its CONNECT.
      if (!legacyTokenAllowed()) return send(res, 200, { result: "deny" });

      const { ok, expireAt } = await DB.verifyMqttToken(id, password);
      if (!ok) return send(res, 200, { result: "deny" });

      // The token proves who the USERNAME is; the broker authorizes by the
      // CLIENTID (`u/${clientid}/…` in acl.conf). Unless the two are the same
      // id, any client holding a token of its own could CONNECT as
      // `clientid = <victim>`, subscribe to the victim's inbox, publish the
      // victim's presence, and take over — kick — the victim's live session. Exact match against the lowercased
      // username: an upper-cased clientid would match no ACL row anyway, and
      // accepting it would only make the id mean two things. Checked after the
      // token, so the warning names a real token holder trying it, not noise.
      const clientid = String(body.clientid || "");
      if (clientid !== id) {
        logger.warn(`[auth] CONNECT clientid does not match username id=${id.slice(0, 12)}…`);
        return send(res, 200, { result: "deny" });
      }

      // expire_at (unix seconds) → EMQX force-disconnects at this time.
      return send(res, 200, { result: "allow", expire_at: expireAt });
    }

    return send(res, 404, { error: "not found" });
  } catch (e) {
    if (e instanceof HttpError) {
      return send(res, e.status, { error: e.code, message: e.message });
    }
    logger.error(`[auth] ${method} ${url} — ${(e as Error).message}`, e as Error);
    return send(res, 500, { error: "INTERNAL" });
  }
  };
}

// --- Boot -------------------------------------------------------------------
//
// Only when this file is the process entry point. Imported — by a test, or by a
// tool that wants the handler — it defines routes and opens nothing: no socket,
// no Sentry transport, no health-monitor timer keeping the event loop alive.
//
// This process no longer sends any mail: /claim/* went with the paywall, and the
// claim code and the "your subscription is active" notice were the only two
// things the server ever emailed. The `assertConfig(["mail"])` that stood here,
// refusing boot without a mail credential, has nothing left to protect.
if (require.main === module) {
  initObservability("auth");
  // LISTEN_HOST: loopback for nginx plus the WireGuard address for the broker's
  // hooks, off Docker. Unset = every interface (compose).
  listenOn(() => http.createServer(createAuthHandler()), PORT, parseHosts(process.env.LISTEN_HOST), (host) => {
    logger.startup(`🔐 auth server on ${host}:${PORT} — /auth/{free,paid}/*, EMQX hook /mqtt/authn`);
  });

  // Event-loop / memory / query-latency early warning → Sentry. This process
  // gates every CONNECT (EMQX calls /mqtt/authn synchronously), so a stall here
  // stalls the whole broker — worth watching in its own right.
  healthMonitor.start();
}
