/**
 * DissQus helper bot — an always-on protocol client.
 *
 * It authenticates like a normal user (HQC-KEM handshake over REST), claims a
 * username, accepts friend invites, completes the KEM secure-channel handshake
 * and replies to messages. Its identity (seed) and per-friend keys are persisted
 * so it survives restarts.
 *
 * TRANSPORT (Phase 4 — see deploy/EXTRACTION_PLAN.md). The bot used to be the
 * heaviest user of the `/ws` monolith: one socket carrying auth, the friend
 * graph, presence and messages. It now speaks exactly what the apps speak —
 * REST for control (auth + friends + username) and MQTT for conversations — so
 * retiring `/ws` leaves it untouched, and there is no protocol only the bot
 * knows how to talk.
 *
 * One behavioural consequence, shared with the apps: nothing pushes graph
 * changes any more, so invites are picked up by POLLING (`FRIEND_POLL_MS`)
 * rather than arriving as an event.
 *
 * The bot is a NORMAL MQTT user, not a service: it connects with its own CLIENT
 * ID as client id and username and a short-lived token as password, and EMQX
 * holds it to the same per-topic ACL as everyone else. It never touches the
 * `svc-internal` superuser credential — a bot that could read every
 * conversation would undo the point of the ACL.
 *
 * IDENTITY. The bot holds a keypair; everything that NAMES it is
 * `peerId(pkHex)` — sha256 of the lowercase hex key, 64 characters. The key
 * itself is used for exactly three things: decapsulating the auth challenge,
 * answering an inbound `init`, and riding on the `init` frames the bot sends so
 * a peer can verify it. Peers are named by their ids too, and their keys are
 * fetched once (`GET /peer/{id}/key`) and VERIFIED against the id before being
 * pinned — the server cannot substitute one, even for itself.
 *
 * Run on the VPS (it needs the Linux HQC lib). Env:
 *   AUTH_BASE_URL   default http://auth:8080
 *   API_BASE_URL    default http://app-api:8080
 *   EMQX_URL        default ws://emqx:8083/mqtt
 *   BOT_USERNAME    default "helper"
 *   BOT_SEED        32-byte hex seed (optional; generated + saved if absent)
 *
 * The bot self-admits: on startup it writes its own public key into the
 * `admission:exempt` set (shared with the auth server), so it's admitted under
 * any ADMISSION_POLICY without an operator hand-copying its key into
 * EXEMPT_PUBLIC_KEYS. That survives the bot's seed/identity changing.
 */

// First import: loads .env and resolves *_FILE Docker secrets (e.g. BOT_SEED_FILE).
import "../lib/config";
// Init Sentry + global crash handlers (uncaughtException / unhandledRejection)
// before anything else runs — the bot is a long-lived client that must survive
// server hiccups and reconnects without silently dying.
import { initObservability } from "../lib/observability";
initObservability("bot");
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import mqtt, { type MqttClient } from "mqtt";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "../lib/hqc";
import { hqcEncapsulate, hqcDecapsulate, aesEncryptRaw, aesDecryptRaw } from "./crypto";
import {
  Kem,
  SessionState,
  InitHeader,
  MessageHeader,
  PrekeyBundle,
  startAsInitiator,
  startAsResponder,
  seal,
  open as openRatchet,
} from "../lib/ratchet-session";
import { Frame, frameHeader, encodeFrame, decodeFrame, validateFrame } from "../lib/frame";
import {
  handshakeNonce,
  handshakeProof,
  handshakeProofMatches,
  encodeHandshake,
  decodeHandshake,
} from "../lib/handshake";
import { authProof } from "../lib/auth-proof";
import { newSigningKey, signConnect, type SigningKey } from "../lib/mqtt-proof";
import { liveFriendIds, staleFriendIds } from "./friend-graph";
import { reply as replyOf, type ReplyDeps } from "./replies";
import { friendshipHash } from "../lib/crypto-utils";
import { keyMatchesId, peerId } from "../lib/identity";
import { DB } from "../services/db/api";

const AUTH_BASE = (process.env.AUTH_BASE_URL || "http://auth:8080").replace(/\/$/, "");
const API_BASE = (process.env.API_BASE_URL || "http://app-api:8080").replace(/\/$/, "");
const EMQX_URL = process.env.EMQX_URL || "ws://emqx:8083/mqtt";
const USERNAME = process.env.BOT_USERNAME || "helper";
// Shown by the bot's /support reply. Deployment config, not a code constant.
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@example.com";
/// How often to re-read the friend graph. There is no server push for it any
/// more, and an invite that waits a few seconds is not worth a second protocol.
const FRIEND_POLL_MS = Number(process.env.FRIEND_POLL_MS || 15_000);
// Persist state (seed + per-friend keys) in a directory SEPARATE from the code.
// In Docker the bot-state volume mounts at BOT_STATE_DIR — never over /app/bot
// (the code dir), which would shadow bot.ts and pin the container to stale code
// across image updates. Defaults to __dirname for local / pm2 runs.
const STATE_DIR = process.env.BOT_STATE_DIR || __dirname;
fs.mkdirSync(STATE_DIR, { recursive: true });
const SEED_FILE = path.join(STATE_DIR, ".bot-seed");
const STATE_FILE = path.join(STATE_DIR, ".bot-state.json");

// ── Identity ─────────────────────────────────────────────────────────────────
function loadSeed(): Buffer {
  if (process.env.BOT_SEED) return Buffer.from(process.env.BOT_SEED, "hex");
  if (fs.existsSync(SEED_FILE)) return Buffer.from(fs.readFileSync(SEED_FILE, "utf8").trim(), "hex");
  const seed = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
  // `wx` — create, or fail if it already exists. The check above is not enough
  // on its own: two processes starting together both miss the file, both write,
  // and the second one's seed wins. That is not a lost temp file, it is the
  // bot's IDENTITY changing, which takes every conversation with it. On the
  // race, read back the seed that won rather than overwriting it.
  try {
    fs.writeFileSync(SEED_FILE, seed.toString("hex"), { mode: 0o600, flag: "wx" });
    return seed;
  } catch (e: any) {
    if (e?.code !== "EEXIST") throw e;
    return Buffer.from(fs.readFileSync(SEED_FILE, "utf8").trim(), "hex");
  }
}

const seed = loadSeed();
const { pk, sk } = HqcWrapper.keypairFromSeed(seed);
const pkHex = pk.toString("hex");
/** What every other layer calls this bot: sha256(lowercase-hex(pk)), 64 chars. */
const myId = peerId(pkHex);

/** Ids are 64 characters and keys are 14474; logs get the ends only. */
function short(hex: string): string {
  return hex.length <= 20 ? hex : `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

// ── The KEM the ratchet rides on ─────────────────────────────────────────────
// A thin adapter so the state machine never imports HQC — which is what lets it
// be tested against a stub on a machine with no native library.
const kem: Kem = {
  generateKeypair() {
    const s = crypto.randomBytes(HQC_CONSTANTS.SEED_BYTES);
    return HqcWrapper.keypairFromSeed(s);
  },
  encapsulate: (peerPk) => hqcEncapsulate(peerPk),
  decapsulate: (secret, ct) => hqcDecapsulate(secret, ct),
};

// ── Per-friend state ─────────────────────────────────────────────────────────
//
// One v2 double-ratchet session per peer. v1 kept a static channel key, its two
// contributed secrets, the stored KEM ciphertext AND an epoch ratchet beside
// them — because the handshake was a mutual exchange whose halves arrived
// separately and whose product was a key every message then reused. All of that
// collapses into `session`.
//
// Buffers do not survive JSON, so the session is stored with every Buffer as
// base64 and revived on load (see `reviveSession` / `dehydrateSession`).
interface FriendState {
  /** The peer's client id — how the graph, the topics and the ACL name them. */
  id: string;
  /**
   * The peer's identity public key, hex — absent until it has been fetched and
   * VERIFIED against `id`.
   *
   * Absent is a real state, not a bug: the directory ships ids, so a friend
   * appears before their key does. Nothing that needs a key runs without one
   * (`openSession` fetches it first), and a key that fails `keyMatchesId` is
   * refused rather than stored, so this field is either missing or correct.
   */
  pk?: string;
  username?: string; // display only — logs and the greeting text
  /** The double-ratchet session, or absent when none is open yet. */
  session?: SessionState;
  // Whether this user has had the welcome message. Persisted with the rest of
  // the friend state so a bot restart never re-greets someone.
  greeted?: boolean;
}

/// Keyed by the peer's CLIENT ID — the same identity the conversation topic, the
/// EMQX ACL and the envelope's `sender` are keyed on. It was keyed by the public
/// key, and before that by username (the `/ws` server resolved names for us;
/// MQTT has no such mediator, and a mutable display name must never be what
/// decides which key decrypts a message).
type State = { friends: Record<string, FriendState> };

let state: State = { friends: {} };

// ── Session serialisation ────────────────────────────────────────────────────
//
// `SessionState` is full of Buffers and the bot persists to a JSON file, where a
// Buffer round-trips as `{type:"Buffer",data:[…]}` — which still parses, still
// typechecks, and produces a plain object that every crypto call then treats as
// empty. That failure is silent and total: every message stops decrypting and
// nothing says why. So the conversion is explicit in both directions.

/** Every Buffer field in a session, by path. Nested ones are handled inline. */
function dehydrateSession(s: SessionState): unknown {
  return {
    ...s,
    root: s.root.toString("base64"),
    rkPub: s.rkPub.toString("base64"),
    rkSec: s.rkSec.toString("base64"),
    peerRkPub: s.peerRkPub ? s.peerRkPub.toString("base64") : null,
    send: s.send ? { ck: s.send.ck.toString("base64"), n: s.send.n } : null,
    recv: s.recv ? { ck: s.recv.ck.toString("base64"), n: s.recv.n } : null,
    skipped: s.skipped.map((k) => ({ chain: k.chain, n: k.n, key: k.key.toString("base64") })),
    pendingInit: s.pendingInit
      ? {
        ctId: s.pendingInit.ctId.toString("base64"),
        ctMt: s.pendingInit.ctMt.toString("base64"),
        ctOt: s.pendingInit.ctOt ? s.pendingInit.ctOt.toString("base64") : null,
        otId: s.pendingInit.otId,
        rk: s.pendingInit.rk.toString("base64"),
        cid: s.pendingInit.cid,
      }
      : undefined,
  };
}

const b64 = (v: unknown): Buffer => Buffer.from(String(v ?? ""), "base64");

/** Rebuild a session from the JSON form. Returns null if it is not one. */
function reviveSession(raw: unknown): SessionState | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, any>;
  if (typeof r.root !== "string" || typeof r.rkPub !== "string") return null;
  try {
    return {
      root: b64(r.root),
      rkPub: b64(r.rkPub),
      rkSec: b64(r.rkSec),
      peerRkPub: r.peerRkPub ? b64(r.peerRkPub) : null,
      send: r.send ? { ck: b64(r.send.ck), n: Number(r.send.n) } : null,
      recv: r.recv ? { ck: b64(r.recv.ck), n: Number(r.recv.n) } : null,
      prevSendN: Number(r.prevSendN ?? 0),
      skipped: Array.isArray(r.skipped)
        ? r.skipped.map((k: any) => ({ chain: String(k.chain), n: Number(k.n), key: b64(k.key) }))
        : [],
      seenChains: Array.isArray(r.seenChains) ? r.seenChains.map(String) : [],
      ...(r.pendingInit
        ? {
          pendingInit: {
            ctId: b64(r.pendingInit.ctId),
            ctMt: b64(r.pendingInit.ctMt),
            ctOt: r.pendingInit.ctOt ? b64(r.pendingInit.ctOt) : null,
            otId: r.pendingInit.otId ?? null,
            rk: b64(r.pendingInit.rk),
            cid: String(r.pendingInit.cid),
          } as InitHeader,
        }
        : {}),
      sentOnChain: Number(r.sentOnChain ?? 0),
      chainStartedAt: Number(r.chainStartedAt ?? 0),
    };
  } catch {
    return null;
  }
}

function loadState() {
  if (!fs.existsSync(STATE_FILE)) return;
  let raw: any;
  try { raw = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch { return; }

  // Re-key the store to CLIENT IDS.
  //
  // Two earlier shapes exist in the wild: username-keyed (the `/ws` era) and
  // public-key-keyed. Both carry the peer's `pk`, so both can be converted
  // without asking the server — `peerId(pk)` is the new key, and the old public
  // key is kept as `pk` because it is still needed to encapsulate.
  //
  // An entry with no usable key is DROPPED rather than guessed at: there is no
  // way to derive an id from a username, so there is no topic to reach that peer
  // on and no way to seal anything for them. They come back on the next sync.
  const friends: Record<string, FriendState> = {};
  let migrated = 0;
  let dropped = 0;
  for (const [key, entry] of Object.entries((raw?.friends ?? {}) as Record<string, any>)) {
    const peerPk = String(entry?.pk || "").toLowerCase();
    // A full HQC-256 public key, or nothing. The old check was `{16,}`, which
    // accepted a truncated key and produced an id for a peer that does not exist.
    const hasKey = peerPk.length === HQC_CONSTANTS.PUBLIC_KEY_BYTES * 2 && /^[0-9a-f]+$/.test(peerPk);
    const storedId = String(entry?.id || "").toLowerCase();
    const peerId_ = hasKey ? peerId(peerPk) : storedId;
    if (!/^[0-9a-f]{64}$/.test(peerId_)) { dropped++; continue; }
    if (peerId_ !== key) {
      // The old key was a username or a public key; keep a username as the
      // display name, since that is all it was ever good for.
      if (!entry.username && !/^[0-9a-f]+$/.test(key)) entry.username = key;
      migrated++;
    }
    const next: FriendState = {
      id: peerId_,
      ...(hasKey ? { pk: peerPk } : {}),
      ...(entry.username ? { username: String(entry.username) } : {}),
      ...(entry.greeted ? { greeted: true } : {}),
    };
    // v1 state (a static `sharedKey`, seeds, an epoch ratchet) cannot open a v2
    // frame, so it is dropped rather than migrated — the pair simply re-opens a
    // session on the next message.
    const revived = reviveSession(entry?.session);
    if (revived) next.session = revived;
    friends[peerId_] = next;
  }
  state = { friends };
  if (migrated || dropped) {
    logger.startup(`🤖 [bot] state re-keyed by client id: ${migrated} migrated, ${dropped} unusable`);
    saveState();
  }
}
function saveState() {
  const out = {
    friends: Object.fromEntries(
      Object.entries(state.friends).map(([k, f]) => [
        k,
        f.session ? { ...f, session: dehydrateSession(f.session) } : f,
      ])
    ),
  };
  fs.writeFileSync(STATE_FILE, JSON.stringify(out, null, 2), { mode: 0o600 });
}
loadState();

/** Log/greeting label for a peer — its username if we know one, else its id. */
function label(peerId_: string): string {
  return state.friends[peerId_]?.username || short(peerId_);
}

// ── REST control plane (auth + directory + friend graph) ─────────────────────
// The `/ws` protocol carried all of this inline; it is now plain HTTP against
// the auth server and app-api, exactly as the apps do it.

/** REST session bearer (app-api + token refresh), and the pre-v1 MQTT token —
 *  used only against a server that does not hand back a signing-key id. */
let sessionToken = "";
let mqttToken = "";

/** The v1 CONNECT proof (lib/mqtt-proof.ts): a per-session Ed25519 key whose
 *  public half is registered at sign-in and on every refresh, and the server
 *  clock offset the proof's timestamp is corrected by. Every CONNECT signs a
 *  fresh proof — which is why the bot reconnects by hand rather than letting
 *  mqtt.js replay one password. */
let mqttKey: SigningKey | null = null;
let mqttKeyId = "";
let clockOffsetSec = 0;

function adoptSigningKey(key: SigningKey, body: any): void {
  if (typeof body?.mqttKeyId === "string") {
    mqttKey = key;
    mqttKeyId = body.mqttKeyId;
  } else {
    mqttKey = null;   // a server that predates v1: the token is the password
    mqttKeyId = "";
  }
  if (typeof body?.serverTime === "number") clockOffsetSec = body.serverTime - Date.now() / 1000;
}

/** The password for the next CONNECT: a fresh signed proof, or the token. */
function mqttPassword(): string {
  if (!mqttKey || !mqttKeyId) return mqttToken;
  return signConnect({ clientid: myId, keyId: mqttKeyId, privateKey: mqttKey.privateKey,
    nowSec: Date.now() / 1000 + clockOffsetSec });
}

/** A 401: the REST session itself is gone, so the KEM handshake must be redone. */
class Unauthenticated extends Error { }

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function httpJson(
  url: string,
  opts: { method: string; body?: unknown; bearer?: string }
): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.bearer) headers.authorization = `Bearer ${opts.bearer}`;
  const init: RequestInit = { method: opts.method, headers };
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  const res = await fetch(url, init);
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { /* non-JSON error page */ }
  return { status: res.status, body };
}

/** Call app-api with our session bearer. Throws Unauthenticated on 401. */
/**
 * A non-2xx from the API, carrying the parts a caller needs to decide whether
 * it is exceptional.
 *
 * It used to throw a bare Error whose message was the whole story, so every
 * caller had to treat "this peer has published no prekeys yet" — which is
 * ordinary, expected and self-resolving — exactly like a real fault. That is
 * what turned `openSession` into a Sentry firehose: 404 NO_PREKEYS, once per
 * peer per 15s poll, each one an event.
 */
class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function api(method: string, path: string, body?: unknown): Promise<any> {
  const opts: { method: string; body?: unknown; bearer?: string } = { method, bearer: sessionToken };
  if (body !== undefined) opts.body = body;
  const r = await httpJson(`${API_BASE}${path}`, opts);
  if (r.status === 401) throw new Unauthenticated(`${method} ${path} → 401`);
  if (r.status < 200 || r.status >= 300) {
    const code = typeof (r.body as any)?.error === "string" ? (r.body as any).error : "";
    throw new ApiError(r.status, code, `${method} ${path} → ${r.status} ${JSON.stringify(r.body)}`);
  }
  return r.body ?? {};
}

/**
 * Conditions the bot meets constantly and should never report as faults: a peer
 * who has not published prekeys yet (they will, on their first directory sync),
 * or one whose one-time keys are momentarily exhausted.
 */
function isExpectedPeerState(e: unknown): boolean {
  return e instanceof ApiError && e.status === 404 &&
    (e.code === "NO_PREKEYS" || e.code === "NOT_FOUND");
}

/**
 * Which door of auth/main.ts the bot knocks on.
 *
 * The PAID door, not the free one. The bot is admission-exempt (registerExempt
 * below), so both doors let it through — but the door decides the SCOPE the
 * session carries, and a free scope is refused by `POST /friends/accept`
 * (api/main.ts: `scope !== "premium"` → 402). Accepting invites is the bot's
 * whole job, so the free door would authenticate it and then leave it unable to
 * do that job. The paid door also re-grants its conversation topics on login,
 * which is what restores the bot's MQTT ACLs after a restart.
 *
 * There is no plain `/auth/init` any more: the doors split in 0b10528 and the
 * bot was not moved with them, which is the 404 it has been retrying against.
 */
const AUTH_DOOR = "/auth/paid";

/**
 * The HQC-KEM handshake, over REST (auth/main.ts): the server encapsulates to
 * our public key, we decapsulate and return HKDF(ss,"auth") to prove we hold the
 * secret key. We never send ss or any decrypted plaintext. Yields a REST session
 * bearer plus the first (~5m) MQTT connect token.
 */
async function handshake(): Promise<void> {
  const init = await httpJson(`${AUTH_BASE}${AUTH_DOOR}/init`, { method: "POST", body: { pk: pkHex } });
  if (init.status !== 200 || typeof init.body?.ct !== "string") {
    throw new Error(`${AUTH_DOOR}/init → ${init.status}`);
  }
  const ss = hqcDecapsulate(sk, Buffer.from(init.body.ct, "base64"));
  const signing = newSigningKey();
  const verify = await httpJson(`${AUTH_BASE}${AUTH_DOOR}/verify`, {
    method: "POST",
    body: { pk: pkHex, solution: authProof(ss).toString("base64"), mqttSigningKey: signing.publicKeyB64 },
  });
  if (verify.status === 402 || verify.status === 403) {
    // Self-admission (registerExempt) should make this impossible; if it does
    // happen the exempt write failed, so say so rather than spin silently.
    throw new Error(`not admitted (${verify.status}) — the admission exemption did not stick`);
  }
  if (verify.status !== 200 || typeof verify.body?.sessionToken !== "string") {
    throw new Error(`${AUTH_DOOR}/verify → ${verify.status}`);
  }
  sessionToken = verify.body.sessionToken;
  mqttToken = String(verify.body.mqttToken || "");
  adoptSigningKey(signing, verify.body);
  logger.startup(`🤖 [bot] authenticated as ${short(myId)}`);
}

/**
 * Rotate the MQTT token on the existing REST session — the ordinary path after
 * EMQX force-disconnects us at token expiry. Returns false when the session
 * itself has lapsed (401), which is the caller's cue to redo the handshake.
 */
async function refreshMqttToken(): Promise<boolean> {
  if (!sessionToken) return false;
  const signing = newSigningKey();
  const r = await httpJson(`${AUTH_BASE}/auth/refresh`, {
    method: "POST", bearer: sessionToken, body: { mqttSigningKey: signing.publicKeyB64 },
  });
  if (r.status === 401) return false;
  if (r.status !== 200 || typeof r.body?.mqttToken !== "string") {
    throw new Error(`/auth/refresh → ${r.status}`);
  }
  mqttToken = r.body.mqttToken;
  adoptSigningKey(signing, r.body);
  return true;
}

/** Claim the reserved handle. app-api lets an admission-exempt pk reclaim it. */
async function claimUsername(): Promise<void> {
  await api("POST", "/username", { username: USERNAME });
  logger.startup(`🤖 [bot] username @${USERNAME}`);
}

/**
 * Re-read the friend graph: auto-accept anything pending, then make sure every
 * friend has state, a subscription and a secure channel. This is the whole
 * replacement for FRIEND_REQUEST / FRIEND_ADDED — there is nothing to push it
 * to us any more.
 */
async function syncGraph(): Promise<void> {
  const invites = await api("GET", "/friends/invites");
  for (const invite of (invites?.invites ?? []) as Array<{ id?: string; username?: string }>) {
    const from = String(invite?.id || "").toLowerCase();
    if (!from) continue;
    logger.debug(`🤖 [bot] invite from @${invite?.username ?? short(from)} — accepting`);
    // Accepting is also what grants BOTH of us the conversation topic in the
    // EMQX ACL, so it must land before we try to subscribe.
    await api("POST", "/friends/accept", { from });
  }

  const list = await api("GET", "/friends");
  const live = liveFriendIds(list, myId);
  if (!live) {
    // A 200 whose body is not a list is not an empty friend graph. Pruning on it
    // would delete every session the bot holds.
    logger.error(`🤖 [bot] /friends returned no list — skipping this sync rather than pruning`);
    return;
  }

  for (const friend of (list.friends ?? []) as Array<{ id?: string; username?: string }>) {
    const peerId_ = String(friend?.id || "").toLowerCase();
    if (!live.has(peerId_)) continue;
    trackFriend(peerId_, String(friend?.username || ""));
  }
  pruneFriends(live);
}

/**
 * Drop peers the server no longer lists.
 *
 * This is what kept the bot in a permanent reconnect loop. `syncGraph` only ever
 * ADDED, so an unfriended peer stayed in `.bot-state.json` for good — while
 * `revokeFriendTopic` deleted its row from `mqtt_acl`. Every reconnect the bot
 * subscribed to a topic it was no longer entitled to, and with
 * `authorization.deny_action = disconnect` the broker answered by closing the
 * link. Connect, subscribe, 0x87, drop, repeat, for as long as that entry
 * existed — which was forever, because nothing removed it.
 *
 * The damage was worse than one dead conversation: the denial arrives mid-batch,
 * and `subscribeConversation` returns early once the link is gone, so every
 * friend queued AFTER the stale one was silently skipped too. One removed
 * contact took the whole bot offline.
 */
function pruneFriends(live: Set<string>) {
  const stale = staleFriendIds(Object.keys(state.friends), live);
  if (!stale.length) return;

  for (const peerId_ of stale) {
    // The session goes with it: it was derived for a friendship that no longer
    // exists, and keeping it would let a re-friend resume a ratchet the peer has
    // long since dropped.
    const name = label(peerId_);
    delete state.friends[peerId_];
    // Best-effort — the grant is already gone, so this may be refused too. It is
    // issued anyway so a peer removed WHILE we are connected stops being
    // delivered without waiting for a reconnect.
    if (client?.connected) client.unsubscribe(convoTopic(peerId_), () => { });
    logger.warn(
      `🤖 [bot] dropped @${name} — no longer in the friend graph ` +
      `(its topic grant is revoked, and re-subscribing to it drops the link)`
    );
  }
  saveState();
}

/** Ensure state + subscription + key agreement for one peer. Idempotent. */
function trackFriend(peerId_: string, username: string) {
  const known = state.friends[peerId_];
  const f: FriendState = known ?? { id: peerId_ };
  const renamed = !!username && username !== f.username;
  if (renamed) f.username = username;
  state.friends[peerId_] = f;
  // The poll runs every few seconds; only touch the state file when it changed.
  if (!known || renamed) saveState();
  if (!known) logger.debug(`🤖 [bot] friend: @${username || short(peerId_)}`);
  subscribeConversation(peerId_);
  // Nothing to do about a missing session here. v1 re-offered its KEM ciphertext
  // on a timer, because an offer published into a topic with no subscriber was
  // simply lost and the retry WAS the recovery. A session now opens on demand
  // from published prekeys, and the `init` frame goes to the peer's inbox where
  // the broker queues it — so there is nothing to retry and nothing to sweep.
  greet(peerId_);
}

/**
 * The peer's identity public key, fetched once and VERIFIED against their id.
 *
 * The directory ships ids, so this is where a key enters the bot's world. The
 * check is the whole point of the identifier being a digest: `GET /peer/{id}/key`
 * is an unauthenticated route on a server the protocol does not trust, and a
 * substituted key is refused rather than pinned — TOFU narrows to "trust the id
 * the graph gave you", and everything after that is arithmetic.
 *
 * Returns null when the key is unavailable or does not match. A null is not an
 * error to recover from here; the caller simply cannot open a session yet.
 */
async function peerKey(f: FriendState): Promise<string | null> {
  if (f.pk) return f.pk;
  let served: string;
  try {
    const body = await api("GET", `/peer/${f.id}/key`);
    served = String(body?.publicKey || "").toLowerCase();
  } catch (e: any) {
    logger.error(`🤖 [bot] could not fetch @${label(f.id)}'s key: ${e.message}`);
    return null;
  }
  if (!keyMatchesId(served, f.id)) {
    // Loud, and refused. Either the server is lying or the directory and the
    // key store disagree; both mean this key must not be encrypted to.
    logger.error(
      `🚨 [bot] the key served for @${label(f.id)} does NOT hash to their id ` +
      `(${short(f.id)}) — refusing it. This is what the identifier being a ` +
      `commitment exists to catch.`
    );
    return null;
  }
  f.pk = served;
  saveState();
  return served;
}

/**
 * Adopt the key an `init` frame carried, if we did not already hold one.
 *
 * `parseEnvelope` has already refused any frame whose `senderPk` does not hash
 * to its `sender`, so by the time this runs the key is known to be the one the
 * id names. Taking it here is what makes first contact cost no round trip.
 */
function adoptSenderKey(f: FriendState, env: Frame): void {
  if (f.pk || !env.senderPk) return;
  // Bytes on the wire; hex is what `keyMatchesId` hashes and what every stored
  // digest uses, so it is hex that gets kept.
  f.pk = env.senderPk.toString("hex");
  saveState();
}

// ── MQTT conversations ───────────────────────────────────────────────────────
// One topic per friendship, `c/{friendshipHash}`, which only the two members may
// publish to (EMQX enforces it from the `mqtt_acl` table app-api maintains). The broker
// sees ciphertext and our own public key, never plaintext.

let client: MqttClient | null = null;
/** True while a relink is already scheduled/in flight, so one drop = one retry. */
let relinking = false;
let relinkDelay = 2_000;
const MAX_RELINK_MS = 30_000;
/** Bumped per connection. A discarded client's late `close` carries the old
 *  generation, so it can be ignored instead of tearing down its replacement.
 *  (We can't just drop its listeners — mqtt.js keeps its own on the client.) */
let linkGeneration = 0;

function convoTopic(peerId_: string): string {
  return `c/${friendshipHash(myId, peerId_)}`;
}
const PRESENCE_TOPIC = `u/${myId}/presence`;
const PRESENCE_ONLINE = JSON.stringify({ s: "online" });
const PRESENCE_OFFLINE = JSON.stringify({ s: "offline" });

/**
 * Publish a frame to `peerPk`, on whichever topic can actually deliver it.
 *
 * An `init` goes to the peer's INBOX, everything else to the shared conversation
 * topic. The distinction is delivery, not secrecy: MQTT drops a publish to a
 * topic nobody has subscribed to, which is exactly what a brand-new friendship
 * is. Every client subscribes to its own inbox on connect with a persistent
 * session, so the broker queues it for an offline peer instead.
 */
function publish(peerId_: string, envelope: Frame) {
  if (!client) return;
  const bytes = encodeFrame(envelope);
  if (!bytes) {
    // The seam refuses to spell a frame it could not also read back. Reaching
    // here means a caller built one from values that are not a client id, a
    // chain selector or a u32 — which used to produce a frame naming client
    // 0000…0000 rather than an error.
    logger.error(
      `🤖 [bot] refusing to publish a malformed ${envelope.t} for @${label(peerId_)}: ` +
      `${validateFrame(envelope) ?? "empty payload"}`
    );
    return;
  }
  const topic = envelope.t === "init" ? inboxTopic(peerId_) : convoTopic(peerId_);
  // QoS 1 into the client's own outgoing store: a publish issued while the link
  // is down is delivered on the next connect rather than lost.
  client.publish(topic, bytes, { qos: 1 });
}

/** A peer's inbox — where their `init` frames land, and ours are read from. */
function inboxTopic(peerId_: string): string {
  return `u/${peerId_}/inbox`;
}

/**
 * Where the two of us prove an `init` came from the peer it names.
 *
 * A separate topic from the inbox, and that is the point: every friend may
 * publish to an inbox, so a challenge sitting there would be readable — and
 * forgeable — by exactly the attacker this exchange exists to stop. Only the two
 * members are granted this one (DB.grantFriendTopic).
 */
function handshakeTopic(peerId_: string): string {
  return `h/${friendshipHash(myId, peerId_)}`;
}

/** Our own inbox — where peers put their `init` frames. Subscribed on every
 *  connect, which is what lets the broker queue one while the bot is down. */
function subscribeInbox() {
  if (!client?.connected) return;
  const op = `SUBSCRIBE ${inboxTopic(myId)} (own inbox)`;
  opStart(op);
  client.subscribe(inboxTopic(myId), { qos: 1 }, (err, granted) => {
    opDone(op);
    if (err) return logger.error(`🤖 [bot] subscribe inbox: ${err.message}`);
    const refused = (granted ?? []).filter((g) => g.qos >= 128);
    if (refused.length) {
      logger.error(
        `🤖 [bot] subscribe REFUSED for our OWN inbox ${inboxTopic(myId)} ` +
        `(0x${refused[0]!.qos.toString(16)}) — grantSelfTopics has not run for this id, ` +
        `or its row is missing from mqtt_acl`
      );
    }
  });
}

function subscribeConversation(peerId_: string) {
  if (!client?.connected) return; // (re)subscribed wholesale on CONNACK
  // The handshake topic rides along with the conversation: they are granted
  // together and there is never a reason to hold one without the other.
  const op = `SUBSCRIBE ${convoTopic(peerId_)} (conversation with @${label(peerId_)})`;
  opStart(op);
  client.subscribe([convoTopic(peerId_), handshakeTopic(peerId_)], { qos: 1 }, (err, granted) => {
    opDone(op);
    if (err) {
      logger.error(`🤖 [bot] subscribe ${label(peerId_)}: ${err.message}`);
      return;
    }
    // A broker that REFUSES a subscription does not produce an error: MQTT
    // returns it in the SUBACK as granted QoS 0x80, and mqtt.js reports that in
    // `granted` with `err` null. Checking only `err` meant an ACL denial looked
    // exactly like success — the bot would sit there, subscribed to nothing,
    // answering nobody, with a clean log.
    // Under MQTT 5 a denial is a reason code >= 0x80 here; 128 is the 3.1.1
    // spelling of the same thing. With deny_action=disconnect the broker may
    // drop the link INSTEAD of answering, which is why the `disconnect` handler
    // above matters as much as this check does.
    const refused = (granted ?? []).filter((g) => g.qos >= 128);
    if (refused.length) {
      logger.error(
        `🤖 [bot] subscribe REFUSED for ${label(peerId_)} on ${convoTopic(peerId_)} ` +
        `(0x${refused[0]!.qos.toString(16)}) — the EMQX ACL has no grant for this pair ` +
        `(mqtt_acl); nothing will be received`
      );
    }
  });
}

/**
 * MQTT 5 DISCONNECT reason codes worth naming, from the broker's side.
 *
 * Only the ones this deployment can actually produce. The first two are the
 * whole reason this table exists: they are the two causes of a connect/drop
 * loop, they are indistinguishable under 3.1.1, and the remedies are opposite —
 * one is a missing ACL row, the other is a second process holding the same
 * client id.
 */
const DISCONNECT_REASONS: Record<number, string> = {
  0x87: "0x87 NOT AUTHORIZED — an ACL denial (deny_action=disconnect). " +
    "Check mqtt_acl for this pk; note the authorizer caches for 15m",
  0x8e: "0x8E SESSION TAKEN OVER — another connection used the same client id " +
    "(a second bot process, or an old container still running)",
  0x8d: "0x8D KEEPALIVE TIMEOUT — we stopped responding (a blocked event loop)",
  0x89: "0x89 SERVER BUSY",
  0x8b: "0x8B SERVER SHUTTING DOWN",
  0x95: "0x95 PACKET TOO LARGE",
  0x9a: "0x9A RETAIN NOT SUPPORTED",
  0x82: "0x82 PROTOCOL ERROR",
};

/**
 * MQTT operations issued but not yet acknowledged, in the order they went out.
 *
 * `deny_action = disconnect` kills the link on the FIRST denial, and the broker
 * handles packets in order — so when a disconnect arrives, the head of this list
 * is the operation that caused it. Everything behind it was simply in flight.
 *
 * This exists because the reason code says WHY but not WHAT: "0x87 not
 * authorized" with five subscribes and a publish in flight names none of them,
 * and the six candidates have six different remedies.
 */
let pendingOps: string[] = [];

function opStart(op: string) {
  pendingOps.push(op);
}
function opDone(op: string) {
  const i = pendingOps.indexOf(op);
  if (i !== -1) pendingOps.splice(i, 1);
}

function connectMqtt() {
  const gen = ++linkGeneration;
  logger.debug(`🤖 [bot] connecting to ${EMQX_URL} as ${short(myId)}`);
  const c = mqtt.connect(EMQX_URL, {
    // The client id IS our identity: EMQX keys the topic ACL on it
    // (`WHERE id = ${clientid}`), and a duplicate id kicks the previous session
    // (single-session enforcement). It used to be the whole 14474-character
    // public key, which travelled in every CONNECT packet and made every
    // per-client admin call — every kick — a ~14.5 kB URL the broker answered
    // with 414.
    clientId: myId,
    username: myId,
    password: mqttPassword(),
    // MQTT 5, where 3.1.1 would do — because 3.1.1 gives the broker NO way to
    // say why it dropped us. It just closes the socket, and every cause arrives
    // as the same "connection closed".
    //
    // That is not hypothetical here: `authorization.deny_action = disconnect`
    // (infra/deploy/emqx/emqx.conf) means an ACL denial is DELIVERED as a
    // disconnect, so a missing grant and a dead network look identical from this
    // side. Under MQTT 5 the broker names it — 0x87 not authorized, 0x8E session
    // taken over, 0x8D keepalive — which is the difference between reading a log
    // and guessing at one.
    //
    // The apps still speak 3.1.1 (MQTTWireClient.swift). EMQX serves both at
    // once; this is per-connection and changes nothing for them.
    protocolVersion: 5,
    // Persistent session — this IS the offline queue. Messages published to our
    // conversations while the bot is restarting are held by the broker and
    // delivered on reconnect, which is what the `/ws` pending-queue used to do.
    //
    // `clean: false` ALONE does not do that on MQTT 5, and this connection is
    // MQTT 5. In 3.1.1 a non-clean session persists until the broker decides
    // otherwise; in 5 the lifetime is `sessionExpiryInterval`, and its default
    // is ZERO — the session ends the instant the connection does, and every
    // queued message with it. So the comment above described 3.1.1 behaviour on
    // a 5 connection, and the offline queue it promised did not exist: the
    // messages a restart was supposed to catch were being dropped by the
    // broker, silently, which is exactly the shape of "the bot missed something
    // while it was down".
    //
    // The apps are unaffected — they speak 3.1.1 (MQTTWireClient.swift), where
    // `clean: false` means what this comment originally assumed.
    clean: false,
    properties: {
      // Long enough to cover a deploy, a crash loop or a broker restart; short
      // enough that an abandoned identity does not hold queued messages
      // forever. Session state is per client id, and there is one bot.
      sessionExpiryInterval: Number(process.env.MQTT_SESSION_EXPIRY_SECONDS || 3600),
    },
    // We reconnect by hand, because a reconnect needs a FRESH token: the library
    // would happily retry forever with the expired password that just got us
    // disconnected.
    reconnectPeriod: 0,
    keepalive: 30,
    will: {
      topic: PRESENCE_TOPIC,
      payload: Buffer.from(PRESENCE_OFFLINE),
      qos: 1,
      retain: true,
    },
  });
  client = c;

  c.on("connect", () => {
    relinkDelay = 2_000;
    logger.startup(`🤖 [bot] connected to EMQX at ${EMQX_URL}`);
    pendingOps = [];
    const presenceOp = `PUBLISH ${PRESENCE_TOPIC} (retain)`;
    opStart(presenceOp);
    c.publish(PRESENCE_TOPIC, PRESENCE_ONLINE, { qos: 1, retain: true }, () => opDone(presenceOp));
    subscribeInbox();
    for (const peerId_ of Object.keys(state.friends)) subscribeConversation(peerId_);
    // Our own bundle is what lets anyone open a session with us, so it has to be
    // in place before the first `init` could arrive rather than after.
    void ensurePrekeysPublished();
  });
  c.on("message", (topic, payload) => { void onEnvelope(topic, payload); });
  c.on("error", (e) => logger.error(`🤖 [bot] mqtt: ${e.message}`));
  // The broker's own account of why it is closing the link. Without this the
  // `close` handler below logs "connection closed" for every cause there is.
  c.on("disconnect", (packet: { reasonCode?: number; properties?: { reasonString?: string } }) => {
    const code = packet?.reasonCode;
    const named = code !== undefined ? (DISCONNECT_REASONS[code] ?? `unknown (0x${code.toString(16)})`) : "no reason given";
    const detail = packet?.properties?.reasonString;
    logger.error(`🤖 [bot] broker disconnected us: ${named}${detail ? ` — ${detail}` : ""}`);
    if (pendingOps.length) {
      // In order, and the broker stops at the first refusal — so the head is the
      // operation that did it, not merely one that happened to be open.
      logger.error(
        `🤖 [bot]   ↳ culprit: ${pendingOps[0]}` +
        (pendingOps.length > 1 ? `  (also in flight: ${pendingOps.slice(1).join(", ")})` : "")
      );
    }
  });
  c.on("close", () => { if (gen === linkGeneration) relink("connection closed"); });
}

/**
 * Come back after a drop. EMQX disconnects us at token expiry (~5m), so the
 * first thing a reconnect needs is a new password: rotate it on the REST
 * session, and if that session has lapsed too, redo the whole KEM handshake.
 */
function relink(why: string) {
  if (relinking) return;
  relinking = true;
  const stale = client;
  client = null;
  stale?.end(true); // force — the link is already gone; don't wait on DISCONNECT
  const delay = relinkDelay;
  relinkDelay = Math.min(MAX_RELINK_MS, relinkDelay * 2);
  logger.warn(`🤖 [bot] link down (${why}) — reconnecting in ${delay}ms`);
  setTimeout(() => {
    void (async () => {
      try {
        if (!(await refreshMqttToken())) await handshake();
        relinking = false;
        connectMqtt();
      } catch (e: any) {
        logger.error(`🤖 [bot] reconnect failed: ${e.message}`);
        relinking = false;
        relink("reconnect failed");
      }
    })();
  }, delay);
}

// ── Proving an `init` came from the peer it names ────────────────────────────
//
// An `init` is derived entirely from PUBLIC values: the responder's prekey
// bundle is published for anyone to claim, and `senderPk` is fetchable without a
// session. So any accepted friend can produce one that names a third party and
// authenticates perfectly — reproduced, and the reason this file now holds a
// challenge before it holds a session.
//
// A KEM cannot fix that in one flight: encapsulation demonstrates the
// RECIPIENT's secret, never the sender's. So the initiator has to receive
// something first, and what it receives is an ordinary HQC encapsulation to its
// identity key. See lib/handshake.ts.

/** How long a challenge stands. A peer that cannot answer in this window has
 *  its `init` dropped; the initiator carries `pendingInit` on every frame, so
 *  the next thing they send starts a fresh exchange. */
const HANDSHAKE_TTL_MS = 60_000;

/** Challenges we have issued and are waiting on, keyed by the peer's id. */
const pendingChallenges = new Map<string, {
  nonce: Buffer;
  expected: Buffer;
  /** The `init` being held until the proof lands, with the AAD it opens against. */
  heldInit: { env: Frame; aad: Buffer };
  expiresAt: number;
}>();

/** Peers that have proven possession of their identity key this process. */
const proven = new Set<string>();

function sweepChallenges(now = Date.now()) {
  for (const [peer, c] of pendingChallenges) {
    if (c.expiresAt <= now) {
      pendingChallenges.delete(peer);
      logger.debug(`🤖 [bot] handshake with @${label(peer)} timed out — the init was dropped`);
    }
  }
}

/**
 * Challenge the sender of an `init` to prove it holds the key it claims.
 *
 * The key we encapsulate to comes from the frame itself, which is safe for the
 * one reason that matters: `decodeFrame` has already refused any `init` whose
 * `senderPk` does not hash to its `sender`. So it IS that peer's real key — the
 * commitment does its job — and only that peer can decapsulate.
 */
function challengeInitiator(f: FriendState, env: Frame, aad: Buffer): void {
  if (!client || !env.senderPk) return;
  sweepChallenges();

  const nonce = handshakeNonce();
  let ct: Buffer, ss: Buffer;
  try {
    ({ ct, ss } = hqcEncapsulate(env.senderPk));
  } catch (e: any) {
    logger.warn(`🤖 [bot] could not build a challenge for @${label(f.id)}: ${e.message}`);
    return;
  }
  pendingChallenges.set(f.id, {
    nonce,
    expected: handshakeProof(ss, nonce, myId, f.id),
    heldInit: { env, aad },
    expiresAt: Date.now() + HANDSHAKE_TTL_MS,
  });
  client.publish(
    handshakeTopic(f.id),
    encodeHandshake({ kind: "chal", from: myId, to: f.id, nonce, ct }),
    { qos: 1 }
  );
  logger.debug(`🤖 [bot] challenged @${label(f.id)} — holding their init`);
}

/** Inbound on a handshake topic. */
function onHandshake(topic: string, raw: Buffer) {
  const frame = decodeHandshake(raw);
  if (!frame) return;
  if (frame.to !== myId) return;          // not addressed to us
  if (frame.from === myId) return;        // our own publish, echoed back
  const f = state.friends[frame.from];
  if (!f) return;
  // The topic is derived from the two ids, so a frame claiming to be from a peer
  // must arrive on the topic that peer's id builds — the same rule `onEnvelope`
  // applies to conversation frames.
  if (topic !== handshakeTopic(frame.from)) return;

  if (frame.kind === "chal") {
    // Answer ONLY a challenge for a handshake we started. Otherwise this is a
    // standing HKDF-of-a-decapsulation service for anyone who can reach the
    // topic — harmless in itself (implicit rejection means a forged ciphertext
    // yields a pseudo-random secret) but there is no reason to offer it.
    if (!f.session?.pendingInit) return;
    if (!frame.ct) return;
    let ss: Buffer;
    // `sk` is this bot's identity secret — the one value that makes the proof
    // unforgeable, and the one an impersonator does not have.
    try { ss = hqcDecapsulate(sk, frame.ct); } catch { return; }
    client?.publish(
      handshakeTopic(frame.from),
      encodeHandshake({
        kind: "proof",
        from: myId,
        to: frame.from,
        nonce: frame.nonce,
        proof: handshakeProof(ss, frame.nonce, frame.from, myId),
      }),
      { qos: 1 }
    );
    logger.debug(`🤖 [bot] proved our identity to @${label(frame.from)}`);
    return;
  }

  // A proof. It only means anything against a challenge we are waiting on.
  sweepChallenges();
  const pending = pendingChallenges.get(frame.from);
  if (!pending || !frame.proof) return;
  if (!frame.nonce.equals(pending.nonce)) return;
  if (!handshakeProofMatches(pending.expected, frame.proof)) {
    // Not a transport failure. Somebody sent an `init` naming this peer and
    // could not prove they hold its key — which is the attack, arriving.
    logger.warn(
      `🤖 [bot] handshake FAILED for @${label(frame.from)} — an init named this peer ` +
      `and the sender could not prove possession of its key; the init was discarded`
    );
    pendingChallenges.delete(frame.from);
    return;
  }
  pendingChallenges.delete(frame.from);
  proven.add(frame.from);
  logger.debug(`🤖 [bot] @${label(frame.from)} proved possession — opening their init`);
  onInit(f, pending.heldInit.env, pending.heldInit.aad);
}

/** Inbound conversation payload. */
async function onEnvelope(topic: string, raw: Buffer) {
  // From the BYTES. There is one wire format and nothing to discriminate, so
  // this is not a choice any more: `decodeFrame` either reads a frame or does
  // not.
  //
  // The AAD comes back WITH the frame — it is the literal byte range that
  // arrived, because the header is the frame's own prefix. Taking it from there
  // rather than rebuilding it is what makes this function unable to pick wrong.
  // The handshake topic carries its own two frame kinds and no envelope.
  if (topic.startsWith("h/")) return onHandshake(topic, raw);

  const decoded = decodeFrame(raw);
  if (!decoded) return;  // not a well-formed frame
  const { frame: env, aad } = decoded;

  // The decoder has already established that `sender` is a well-formed client id
  // and — for an `init` — that `senderPk` is the key it names.
  const sender = env.sender;
  // MQTT delivers our own publishes back to us (we subscribe to the topic we
  // publish on). Nothing to do with them.
  if (sender === myId) return;

  const f = state.friends[sender];
  if (!f) return;

  // A frame says who it was FOR, inside the AAD, so one addressed to somebody
  // else cannot be re-aimed at us without breaking the tag, whatever topic
  // carries it.
  //
  // This was guarded on `to !== undefined` because a v2 frame had no recipient
  // field, and the binding failed open to the topic check below. There is no
  // such frame any more — `to` is required on `Frame` — so the check is
  // unconditional, which is strictly stronger, and the topic check below is
  // defence in depth rather than the load-bearing part.
  if (env.to !== myId) return;

  // A frame must arrive where that sender is entitled to put it: an `init` on
  // OUR inbox, anything else on the conversation topic derived from the two
  // ids. Without this a friend could publish a `msg` naming a different sender
  // into a topic they do share, and be read as that person.
  const expected = env.t === "init" ? inboxTopic(myId) : convoTopic(sender);
  if (topic !== expected) return;

  if (env.t === "init") {
    // An `init` proves nothing about who sent it — every value in one is public.
    // So it is HELD, not opened, until the sender answers a challenge on the
    // handshake topic. `proven` is per-process: a restart re-challenges, which
    // costs one round trip and is the safe direction to be wrong in.
    if (!proven.has(sender)) return challengeInitiator(f, env, aad);
    return onInit(f, env, aad);
  }
  return onMessage(f, env, aad);
}

/**
 * Open one inbound frame: the ratchet offers a candidate key, the AEAD decides.
 *
 * The two are one call because the tag is the ONLY authenticator this protocol
 * has — HQC decapsulation returns a pseudo-random secret for a forged ciphertext
 * rather than failing, so nothing before the tag check has established anything.
 * Passing the decrypt in as the verifier is what keeps a fabricated ratchet step
 * from mutating the session before something has vouched for it; see the note on
 * `open` in lib/ratchet-session.ts.
 *
 * Returns the plaintext, or null for every kind of refusal — the caller cannot
 * usefully tell them apart and must not report any of them as an error.
 */
function openFrame(session: SessionState, env: Frame, aad: Buffer): string | null {
  const out: { text?: string } = {};
  const opened = openRatchet(kem, session, messageHeaderFrom(env), (mk) => {
    try {
      out.text = aesDecryptRaw(env.payload, mk, aad);
      return true;
    } catch {
      return false;
    }
  });
  return opened === null ? null : out.text ?? null;
}

/** Open a session from an inbound `init`. */
function onInit(f: FriendState, env: Frame, aad: Buffer) {
  // A session already running is NOT replaced. That is the difference between
  // "my peer reinstalled" and "somebody replayed a frame to wipe the
  // conversation", and nothing here can tell them apart.
  //
  // PROTO-1. Not replacing the session was right; RETURNING was not. The init
  // header rides every frame the initiator sends until they hear back from us —
  // `pendingInit` is cleared in `open`, which is to say on the first thing we
  // send them — so a peer who says "hi", "you there?", "it's about tomorrow"
  // before we reply sends three frames all typed `init`. Dropping them here lost
  // two of the three, silently, and measured exactly that against a real broker.
  //
  // The header is what must be ignored, not the frame. The payload is an
  // ordinary message on the sender's chain, and `onMessage` opens it against the
  // session we already hold — with every replay protection intact, because
  // `open` still commits nothing until the tag verifies and `seenChains` still
  // refuses a re-entered chain. We simply never re-root from the header.
  if (f.session) {
    logger.debug(`🤖 [bot] init from @${label(f.id)} — session already open, opening its payload as a message`);
    return onMessage(f, env, aad);
  }
  const header = initHeaderFrom(env);
  if (!header) return;

  const secrets = prekeySecrets();
  if (!secrets) {
    // OUR prekeys, not theirs — so this says the bot has not finished publishing
    // its own, which is a startup-ordering window that closes on its own. warn,
    // not error: the same peer re-sending an init would otherwise bill one
    // Sentry event per attempt.
    logger.warn(`🤖 [bot] init from @${label(f.id)} dropped — this bot has not published prekeys yet`);
    return;
  }

  const session = startAsResponder(kem, secrets, header);
  if (!session) {
    // A one-time secret we no longer hold, or a ciphertext that is not ours.
    // Both ordinary — a duplicate init, or one built on a consumed key.
    logger.debug(`🤖 [bot] could not derive a session from @${label(f.id)}'s init`);
    return;
  }

  // Open the message the init carried BEFORE burning the one-time key, so a
  // frame that turns out to be undecryptable does not cost us the key.
  const text = openFrame(session, env, aad);
  if (text === null) {
    logger.debug(`🤖 [bot] init from @${label(f.id)} did not decrypt`);
    return;
  }

  // The initiator's key rode on the frame, already verified against `sender` —
  // so replying costs no fetch. This is the second of the two journeys the full
  // key makes (the other is friend-add), and both are checked on arrival.
  adoptSenderKey(f, env);
  f.session = session;
  if (env.otId !== undefined && env.otId !== null) consumeOneTimePrekey(env.otId);
  saveState();
  logger.debug(`🤖 [bot] ✅ session open with @${label(f.id)}`);
  void handleText(f, text);
}

/** Decrypt and act on a text message. */
function onMessage(f: FriendState, env: Frame, aad: Buffer) {
  if (!f.session) {
    logger.debug(`🤖 [bot] no session with @${label(f.id)}`);
    return;
  }
  const text = openFrame(f.session, env, aad);
  if (text === null) {
    // A replay, a straggler from a retired chain, a gap too large to bridge, or
    // a frame that did not authenticate. All ordinary, and none of them has
    // changed the session: `open` commits nothing until the tag verifies, so
    // there is no state here to write. Saving on a failed tag is precisely what
    // let a forged step persist and killed the conversation for good.
    logger.debug(`🤖 [bot] no key for @${label(f.id)} (cid ${env.cid.slice(0, 8)}…, n ${env.n})`);
    return;
  }
  saveState();
  void handleText(f, text);
}

// ── Header adapters ──────────────────────────────────────────────────────────
// The wire carries base64; the ratchet works in bytes. Keeping the conversion
// here means neither the state machine nor the envelope knows about the other.

function messageHeaderFrom(e: Frame): MessageHeader {
  return {
    cid: e.cid,
    n: e.n,
    pn: e.pn,
    ...(e.rk ? { rk: e.rk } : {}),
    ...(e.kemCt ? { kemCt: e.kemCt } : {}),
  };
}

function initHeaderFrom(e: Frame): InitHeader | null {
  if (!e.ctId || !e.ctMt || !e.rk) return null;
  const ctOt = e.ctOt ?? null;
  return {
    ctId: e.ctId,
    ctMt: e.ctMt,
    ctOt,
    otId: ctOt ? (e.otId ?? null) : null,
    rk: e.rk,
    cid: e.cid,
  };
}

// ── Prekeys ──────────────────────────────────────────────────────────────────
//
// The bot publishes a bundle like any other client — it is the responder in
// nearly every conversation, so without one nobody could open a session with it.
// Secrets live in the state file beside everything else.

const PREKEY_POOL = 8;
const PREKEY_REPLENISH_AT = 4;
/** A medium-term key is reused by every handshake that misses the one-time
 *  pool, so its lifetime IS the forward-secrecy window for those sessions. */
const MEDIUM_TERM_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;

interface PrekeyStore {
  mediumPk: string;  // base64
  mediumSk: string;  // base64
  oneTime: Record<string, { pk: string; sk: string }>;
  nextId: number;
  rotatedAt: number;
}
let prekeys: PrekeyStore | null = null;
const PREKEY_FILE = path.join(STATE_DIR, ".bot-prekeys.json");

function loadPrekeys() {
  if (!fs.existsSync(PREKEY_FILE)) return;
  try { prekeys = JSON.parse(fs.readFileSync(PREKEY_FILE, "utf8")); } catch { prekeys = null; }
}
function savePrekeys() {
  if (!prekeys) return;
  fs.writeFileSync(PREKEY_FILE, JSON.stringify(prekeys), { mode: 0o600 });
}

/** The secrets needed to answer an inbound `init`. */
function prekeySecrets() {
  if (!prekeys) return null;
  return {
    identitySk: sk,
    mediumSk: Buffer.from(prekeys.mediumSk, "base64"),
    oneTimeSk: (id: number) => {
      const e = prekeys?.oneTime[String(id)];
      return e ? Buffer.from(e.sk, "base64") : null;
    },
  };
}

/** Burn a one-time secret once it has opened a handshake. Separate from
 *  `prekeySecrets` so a frame that failed to decapsulate does not cost a key. */
function consumeOneTimePrekey(id: number) {
  if (!prekeys) return;
  if (delete prekeys.oneTime[String(id)]) savePrekeys();
}

/** Make sure a bundle is published, minting and uploading one as needed. */
async function ensurePrekeysPublished(): Promise<void> {
  try {
    const rotate = !prekeys || Date.now() - prekeys.rotatedAt > MEDIUM_TERM_LIFETIME_MS;
    let want = PREKEY_POOL;
    if (!rotate) {
      // Ask the SERVER how many are left, not our own store: ours still holds
      // every secret we minted, including the ones already claimed.
      const count = await api("GET", "/prekeys/count");
      const remaining = Number(count?.remaining ?? 0);
      if (remaining > PREKEY_REPLENISH_AT) return;
      want = PREKEY_POOL - remaining;
    }

    if (rotate || !prekeys) {
      const pair = kem.generateKeypair();
      prekeys = {
        mediumPk: pair.pk.toString("base64"),
        mediumSk: pair.sk.toString("base64"),
        oneTime: prekeys?.oneTime ?? {},
        nextId: prekeys?.nextId ?? 0,
        rotatedAt: Date.now(),
      };
    }

    const minted: Array<{ id: number; prekey: string }> = [];
    for (let i = 0; i < Math.max(0, Math.min(want, PREKEY_POOL)); i++) {
      const pair = kem.generateKeypair();
      const id = prekeys.nextId++;
      prekeys.oneTime[String(id)] = {
        pk: pair.pk.toString("base64"),
        sk: pair.sk.toString("base64"),
      };
      minted.push({ id, prekey: pair.pk.toString("hex") });
    }

    // Persist BEFORE publishing. Holding secrets nobody can claim costs nothing;
    // publishing keys we cannot open would make every claim against them an
    // `init` we must refuse.
    savePrekeys();
    await api("POST", "/prekeys", {
      medium: Buffer.from(prekeys.mediumPk, "base64").toString("hex"),
      oneTime: minted,
    });
    logger.debug(`🤖 [bot] published ${minted.length} one-time prekey(s)`);
  } catch (e: any) {
    // Not fatal: a missing bundle costs first contact, not an open conversation.
    logger.error(`🤖 [bot] could not publish prekeys: ${e.message}`);
  }
}

// ── Crypto-aware senders ─────────────────────────────────────────────────────

/** Greets in flight, and greets already reported as stuck. Deliberately NOT in
 *  `state`: a restart should retry a greeting that never went out, and should
 *  re-report one that still cannot. Only `greeted` — set once the frame is
 *  actually published — is persisted. */
const greeting = new Set<string>();
const greetWarned = new Set<string>();

/** The first thing a new user ever receives. The server auto-friends the bot to
 *  every account, so this lands moments after the first login — which used to
 *  leave the new user staring at an empty conversation with an account they
 *  hadn't chosen and no idea what it was for.
 *
 *  Sent exactly once per user — `greeted` is persisted, but only after the frame
 *  is actually published, so an attempt that could not send is retried rather
 *  than lost. No longer waits for a channel: the message IS the handshake now. */
function greet(peerId_: string) {
  const f = state.friends[peerId_];
  if (!f || f.greeted || greeting.has(peerId_)) return;
  if (!client?.connected) return;  // retried on the next poll

  // In flight, in memory. The flag that stops a double greet must NOT be the
  // persisted one: `greeted` used to be set here, before the send, so that two
  // polls could not both welcome the same user — but `sendMessage` fails for
  // reasons that are ordinary and temporary (the peer has published no prekeys
  // yet, the link dropped between this check and the publish), and a persisted
  // flag turned every one of those into a welcome message that was never sent
  // and never retried. That is what a brand-new account looked like after a
  // data wipe: the bot friended, said nothing, and the conversation stayed
  // "not encrypted" because the `init` frame the greeting carries never went.
  greeting.add(peerId_);
  const name = f.username || "there";
  void (async () => {
    try {
      const sent = await sendMessage(
        peerId_,
        [
          `welcome to dissqus, @${name}.`,
          "",
          "i'm helper — the account you start with, so your first conversation isn't an empty screen. this chat is end-to-end encrypted like every other one: the server relays it and can't read it.",
          "",
          "try /help for what i can do, or just say hello.",
        ].join("\n")
      );
      if (!sent) {
        // Visible ONCE per peer. Everything `sendMessage` and `openSession` say
        // about why is logger.debug, which is off in production — so the whole
        // failure was silent, on the one path whose result a user sees directly.
        // Repeating it every FRIEND_POLL_MS would be noise, so subsequent
        // attempts drop back to debug.
        const first = !greetWarned.has(peerId_);
        greetWarned.add(peerId_);
        const line = `👋 [bot] could not greet @${label(peerId_)} yet — will retry every ${FRIEND_POLL_MS}ms ` +
          `(usually: they have published no prekeys, which happens on their first directory sync)`;
        if (first) logger.warn(line); else logger.debug(line);
        return;
      }
      f.greeted = true;
      greetWarned.delete(peerId_);
      saveState();
      logger.debug(`👋 [bot] greeted @${label(peerId_)}`);
    } finally {
      greeting.delete(peerId_);
    }
  })();
}

/** Reply to a decrypted message. */
async function handleText(f: FriendState, text: string): Promise<void> {
  await sendMessage(f.id, reply(text));
}

/**
 * Seal and send one message, opening a session first if there is none.
 *
 * Opening on demand is what lets the bot greet somebody who has never been
 * online at the same time as it: the frame carries the handshake, and the
 * broker queues it on their inbox.
 */
async function sendMessage(peerId_: string, text: string): Promise<boolean> {
  const f = state.friends[peerId_];
  if (!f) return false;
  // Checked BEFORE opening a session, not just before publishing. Opening one
  // claims a one-time prekey from the peer — spending that on a message we
  // cannot then send would burn their key for nothing and leave us holding a
  // session they were never told about.
  //
  // The false returns are load-bearing: `greet` only records a user as welcomed
  // when this says the frame went out.
  if (!client?.connected) return false;

  if (!f.session) {
    const opened = await openSession(f);
    if (!opened) return false;
  }

  try {
    const sealed = seal(kem, f.session!);
    // One wire format. There is no longer a version to choose: the emit flag
    // and its ternary went with v2.
    const fields: Omit<Frame, "payload"> = {
      v: 3,
      t: sealed.initHeader ? "init" : "msg",
      sender: myId,
      // Bound as AAD, which is what turned the topic check from the only thing
      // holding the braces up into a belt. v2 had no recipient field at all;
      // that gap is why this binding was worth a wire-format change.
      to: peerId_,
      msgId: crypto.randomUUID(),
      cid: sealed.header.cid,
      n: sealed.header.n,
      pn: sealed.header.pn,
      ...(sealed.initHeader
        ? {
          // `senderPk` rides on `init` alone: it is the frame the peer may
          // receive before they have ever fetched our key, and they verify it
          // against `sender` rather than trusting it. Repeating 14 kB on every
          // message afterwards would undo most of what the id buys.
          senderPk: Buffer.from(pkHex, "hex"),
          rk: sealed.initHeader.rk,
          ctId: sealed.initHeader.ctId,
          ctMt: sealed.initHeader.ctMt,
          ...(sealed.initHeader.ctOt
            ? { ctOt: sealed.initHeader.ctOt, otId: sealed.initHeader.otId ?? 0 }
            : {}),
        }
        : {
          ...(sealed.header.rk ? { rk: sealed.header.rk } : {}),
          ...(sealed.header.kemCt ? { kemCt: sealed.header.kemCt } : {}),
        }),
    };
    // The header IS the AAD, so it has to exist before the payload can be sealed
    // against it. `encodeFrame` re-derives the same bytes, so the two cannot
    // drift apart.
    // Null when the fields cannot make a well-formed frame — an empty peer id,
    // most reachably. Caught HERE rather than at publish, because by then a
    // message has already been sealed against a header nobody can place.
    const aad = frameHeader(fields);
    if (!aad) {
      logger.error(`🤖 [bot] cannot seal for @${label(peerId_)}: ${validateFrame(fields)}`);
      return false;
    }
    const payload = aesEncryptRaw(text, sealed.key, aad);
    publish(peerId_, { ...fields, payload });
    saveState();
    return true;
  } catch (e: any) {
    logger.error(`🤖 [bot] could not seal a message for @${label(peerId_)}: ${e.message}`);
    return false;
  }
}

/** Claim a peer's prekeys and derive a session. */
async function openSession(f: FriendState): Promise<boolean> {
  try {
    // The peer's identity key, fetched once and verified against their id. This
    // has to happen BEFORE the claim: a claimed one-time prekey is consumed, and
    // spending one on a peer whose key we cannot establish would burn it for
    // nothing.
    const identityPkHex = await peerKey(f);
    if (!identityPkHex) {
      logger.debug(`🤖 [bot] no verified identity key for @${label(f.id)} — cannot open a session`);
      return false;
    }
    const claimed = await api("POST", "/prekeys/claim", { peer: f.id });
    if (!claimed?.medium) {
      logger.debug(`🤖 [bot] @${label(f.id)} has published no prekeys yet`);
      return false;
    }
    if (!claimed.oneTime) {
      logger.debug(`🤖 [bot] @${label(f.id)} had no one-time prekey — ` +
        `this session's forward secrecy runs to their next rotation`);
    }
    const bundle: PrekeyBundle = {
      // The PINNED identity key, never anything the claim returned. That is what
      // makes a substituted prekey worthless: the server cannot produce the
      // identity shared secret, so it cannot derive the root however it answers.
      // "Pinned" now means something stronger than "whatever we saw first" — the
      // key was checked against the id the graph named (peerKey), so a server
      // that serves the wrong one is caught rather than believed.
      identityPk: Buffer.from(identityPkHex, "hex"),
      mediumPk: Buffer.from(String(claimed.medium), "hex"),
      oneTimePk: claimed.oneTime ? Buffer.from(String(claimed.oneTime.prekey), "hex") : null,
      oneTimeId: claimed.oneTime ? Number(claimed.oneTime.id) : null,
    };
    const started = startAsInitiator(kem, bundle);
    f.session = started.state;
    saveState();
    logger.debug(`🤖 [bot] ✅ session opened with @${label(f.id)}`);
    return true;
  } catch (e: any) {
    // The peer simply has no prekeys yet. The graceful branch above was written
    // for exactly this and never ran, because `api` threw before it could —
    // which is how one expected condition became 240 Sentry events an hour per
    // affected user, on a 15-second poll that never gives up.
    if (isExpectedPeerState(e)) {
      logger.debug(`🤖 [bot] @${label(f.id)} has published no prekeys yet — retrying on the next poll`);
      return false;
    }
    logger.warn(`🤖 [bot] could not open a session with @${label(f.id)}: ${e.message}`);
    return false;
  }
}

// ── Bot brain ────────────────────────────────────────────────────────────────
// The replies themselves live in ./replies.ts, which is pure and therefore
// testable; this binds them to the deployment's support address.
const replyDeps: ReplyDeps = { supportEmail: SUPPORT_EMAIL };
const reply = (text: string) => replyOf(text, replyDeps);

// ── Self-admission ────────────────────────────────────────────────────────────
// Register our id in the shared `admission_exempt` table BEFORE authenticating,
// so it's in place by the time the auth server runs checkAdmission on our
// /auth/verify. The table holds ids because that is what names a client
// everywhere else; EXEMPT_PUBLIC_KEYS still holds KEYS, because that is what an
// operator has in hand (lib/admission.ts converts).
// The insert is idempotent; retry a few times so a database still coming up at boot
// doesn't leave us un-exempt. Non-fatal: connect regardless (harmless under the
// default open policy, and a later reconnect re-runs the handshake).
async function registerExempt(attempts = 5): Promise<void> {
  for (let i = 1; i <= attempts; i++) {
    try {
      await DB.addAdmissionExempt(myId);
      logger.debug("🤖 [bot] self-registered in admission exempt set");
      return;
    } catch (e: any) {
      logger.error(`🤖 [bot] exempt registration failed (try ${i}/${attempts}): ${e.message}`);
      await new Promise((r) => setTimeout(r, 1000 * i));
    }
  }
  logger.error("🤖 [bot] could not register admission exemption — connecting anyway");
}

// ── Boot ─────────────────────────────────────────────────────────────────────

/** One poll of the friend graph, re-authenticating if the session has lapsed. */
async function pollGraph(): Promise<void> {
  try {
    await syncGraph();
  } catch (e: any) {
    if (!(e instanceof Unauthenticated)) {
      logger.error(`🤖 [bot] friend poll: ${e.message}`);
      return;
    }
    logger.warn("🤖 [bot] REST session lapsed — redoing the handshake");
    try {
      await handshake();
      await claimUsername();
      await syncGraph();
    } catch (e2: any) {
      logger.error(`🤖 [bot] re-authentication failed: ${e2.message}`);
    }
  }
}

/** Authenticate, claim the handle, learn the graph, then open the broker link.
 *  Retries with backoff so a bot that boots before auth/app-api are up recovers
 *  on its own instead of exiting into a restart loop. */
async function start(): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await handshake();
      await claimUsername();
      await syncGraph(); // populate state BEFORE connecting, so CONNACK subscribes everything
      connectMqtt();
      setInterval(() => { void pollGraph(); }, FRIEND_POLL_MS);
      // The hourly wire-version tally stood here. It existed for one decision —
      // whether v2 acceptance could be dropped — and it is deleted with the
      // thing it was counting. A sunset telemetry that outlives its sunset is a
      // log line nobody can act on.
      return;
    } catch (e: any) {
      const wait = Math.min(30_000, 2_000 * attempt);
      logger.error(`🤖 [bot] startup attempt ${attempt} failed (${e.message}) — retrying in ${wait}ms`);
      await sleep(wait);
    }
  }
}

// --- Boot -------------------------------------------------------------------
//
// Only when this file is the process entry point. Imported, it derives its
// identity from the seed in BOT_STATE_DIR and reads its state file — both cheap
// and both contained by that variable — but it starts no timer, opens no socket
// and joins no broker.
//
// This guard is what makes the file testable at all. It is 1,594 lines, it holds
// the only non-Swift implementation of the ratchet's client half, and none of it
// had ever been loaded by a test: importing it connected to EMQX.
if (require.main === module) {
  // Event-loop / memory / query-latency early warning → Sentry.
  healthMonitor.start();
  registerExempt().finally(() => { void start(); });
}

// --- The testable seam ------------------------------------------------------
//
// Exported for test/bot-internals.test.ts. Deliberately the pure decisions
// rather than the wiring: topic derivation (a FOURTH copy of a scheme the server
// and the Swift client also spell out), frame-header parsing (attacker-controlled
// input), and the session persistence round-trip (get it wrong and every
// conversation resets on restart).
export {
  myId,
  convoTopic,
  inboxTopic,
  handshakeTopic,
  PRESENCE_TOPIC,
  dehydrateSession,
  reviveSession,
  messageHeaderFrom,
  initHeaderFrom,
  isExpectedPeerState,
  sweepChallenges,
  pendingChallenges,
  short,
  label,
};
