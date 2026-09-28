/**
 * A headless protocol client, for the end-to-end suite.
 *
 * This is the replacement for `legacy/test-client.ts`, which drove the retired
 * `/ws` monolith. That file was the ONLY end-to-end coverage of the handshake
 * and the ratchet against a running server, and `legacy/README.md` set the
 * condition for deleting it: "connect through EMQX with a real token, publish a
 * ConversationEnvelope, assert the peer decrypts it, assert the topic ACL
 * refuses a stranger." That is what this does.
 *
 * It speaks exactly what the apps speak — REST for auth and the friend graph,
 * MQTT for conversations — so a bug it does not see is a bug the apps would not
 * see either. Nothing here re-implements crypto: it drives `lib/ratchet-session`
 * and `lib/envelope` directly, which is the point.
 */

import mqtt, { type MqttClient } from "mqtt";
import * as crypto from "crypto";
import { authProof } from "../../lib/auth-proof";
import { newSigningKey, signConnect } from "../../lib/mqtt-proof";
import { friendshipHash } from "../../lib/crypto-utils";
import { keyMatchesId, peerId } from "../../lib/identity";
import {
  Kem,
  SessionState,
  InitHeader,
  MessageHeader,
  startAsInitiator,
  startAsResponder,
  seal,
  open as openRatchet,
} from "../../lib/ratchet-session";
import { Frame, frameHeader, encodeFrame, decodeFrame } from "../../lib/frame";

const AUTH_BASE = (process.env.TEST_AUTH_URL || "http://127.0.0.1:8081").replace(/\/$/, "");
const API_BASE = (process.env.TEST_API_URL || "http://127.0.0.1:8080").replace(/\/$/, "");
const EMQX_URL = process.env.TEST_EMQX_URL || "ws://127.0.0.1:8083/mqtt";

/**
 * The native HQC library is loaded LAZILY.
 *
 * `lib/hqc.ts` dlopen's an x86 `.so` at module scope and throws if it is not
 * loadable — on an arm64 laptop, say. A top-level import would therefore crash
 * this file before any test could skip, which is exactly what it did the first
 * time. So the crypto arrives through `loadCrypto()`, the same bargain
 * `legacy/test-client.ts` made.
 */
type Crypto = {
  kem: Kem;
  seedBytes: number;
  hqcDecapsulate: (sk: Buffer, ct: Buffer) => Buffer;
  aesEncrypt: (text: string, key: Buffer, aad?: Buffer) => string;
  aesDecrypt: (b64: string, key: Buffer, aad?: Buffer) => string;
  keypair: () => { pk: Buffer; sk: Buffer };
};

let cached: Crypto | null = null;

export async function loadCrypto(): Promise<Crypto> {
  if (cached) return cached;
  const hqc = await import("../../lib/hqc");
  const bot = await import("../../bot/crypto");
  const keypair = () =>
    hqc.HqcWrapper.keypairFromSeed(crypto.randomBytes(hqc.HQC_CONSTANTS.SEED_BYTES));
  cached = {
    kem: {
      generateKeypair: keypair,
      encapsulate: (pk) => bot.hqcEncapsulate(pk),
      decapsulate: (sk, ct) => bot.hqcDecapsulate(sk, ct),
    },
    seedBytes: hqc.HQC_CONSTANTS.SEED_BYTES,
    hqcDecapsulate: bot.hqcDecapsulate,
    aesEncrypt: bot.aesEncrypt,
    aesDecrypt: bot.aesDecrypt,
    keypair,
  };
  return cached;
}

export interface Received {
  from: string;
  text: string;
}

/** Thrown when the environment cannot support the suite, so callers can skip. */
export class NotAvailable extends Error {}

async function http(base: string, method: string, path: string, body?: unknown, token?: string) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  let json: any;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  return { status: res.status, body: json };
}

export class TestClient {
  readonly pk: Buffer;
  readonly sk: Buffer;
  readonly pkHex: string;
  /** What the server, the broker and every peer call this client. */
  readonly id: string;
  username = "";

  private sessionToken = "";
  /** The REST bearer, for e2e tests that call an auth route this helper does
   *  not wrap (the hqn/1 suite registers its own signing key). */
  get bearer(): string { return this.sessionToken; }
  private mqttToken = "";
  private readonly signing = newSigningKey();
  private mqttKeyId = "";
  private clockOffsetSec = 0;
  /** A fresh v1 proof per CONNECT; the token only against a server without v1. */
  private mqttPassword(): string {
    if (!this.mqttKeyId) return this.mqttToken;
    return signConnect({ clientid: this.id, keyId: this.mqttKeyId, privateKey: this.signing.privateKey,
      nowSec: Date.now() / 1000 + this.clockOffsetSec });
  }
  private client: MqttClient | undefined;
  private sessions = new Map<string, SessionState>();
  /** Our own prekey secrets, by id. */
  private prekeySecrets: { mediumSk: Buffer; oneTime: Map<number, Buffer> } = {
    mediumSk: Buffer.alloc(0),
    oneTime: new Map(),
  };

  readonly inbox: Received[] = [];
  private cursor = 0;
  /** Frames that arrived but could not be opened — the suite asserts on these. */
  readonly undecryptable: string[] = [];
  /** Why frames were dropped, in order. Every `return` in `onFrame` records a
   *  reason: without this a failure is only ever "no message within 8000ms",
   *  which says nothing about whether the frame arrived, was addressed
   *  elsewhere, or failed to open. That silence is why this suite was
   *  undiagnosable the whole time it was skipping. */
  readonly drops: string[] = [];

  private readonly c: Crypto;

  constructor(c: Crypto) {
    this.c = c;
    const pair = c.keypair();
    this.pk = pair.pk;
    this.sk = pair.sk;
    this.pkHex = pair.pk.toString("hex");
    this.id = peerId(this.pkHex);
  }

  // ── REST ───────────────────────────────────────────────────────────────────

  /**
   * The FULL door (`/auth/paid/*`), not the free one.
   *
   * This mattered more than it looked. The free door mints a `free` scope,
   * which grants self topics and the helper bot and NOTHING else — no friend
   * topics, so two clients on it can never hold a conversation. While the
   * paywall existed, `/friends/invite` answered 402 to a free session and
   * `pair()` skipped on it, so the entire conversation suite quietly ran
   * nothing and the job went green anyway. That is the failure mode this
   * helper's own `brokerReachable` comment warns about, reached by a different
   * road.
   *
   * The door's wire name is still "paid"; nothing behind it costs money.
   */
  async register(username: string): Promise<void> {
    const init = await http(AUTH_BASE, "POST", "/auth/paid/init", { pk: this.pkHex });
    if (init.status !== 200 || !init.body?.ct) {
      throw new NotAvailable(`auth/init returned ${init.status}`);
    }
    // The challenge proves possession of the secret key: decapsulate, then HKDF
    // with the "auth" label. It is NOT a decryption oracle — the server never
    // sees a plaintext we chose.
    const ss = this.c.hqcDecapsulate(this.sk, Buffer.from(String(init.body.ct), "base64"));
    const verify = await http(AUTH_BASE, "POST", "/auth/paid/verify", {
      pk: this.pkHex,
      // BASE64, not the raw Buffer. `handleVerify` does
      // `Buffer.from(String(solution), "base64")`, and JSON.stringify turns a
      // Buffer into `{"type":"Buffer","data":[…]}` — so `String(...)` of that is
      // "[object Object]", which base64-decodes to garbage and 401s. Every e2e
      // test failed on this and none of them could say why, because a wrong
      // proof and a wrong ENCODING of a right proof are the same 401.
      solution: authProof(ss).toString("base64"),
      // A per-session signing key: every CONNECT below is a fresh v1 proof
      // (lib/mqtt-proof.ts), the way the app and the bot connect.
      mqttSigningKey: this.signing.publicKeyB64,
    });
    if (verify.status !== 200) {
      throw new Error(`auth/verify returned ${verify.status} ${JSON.stringify(verify.body)}`);
    }
    this.sessionToken = verify.body.sessionToken;
    this.mqttToken = verify.body.mqttToken;
    this.mqttKeyId = typeof verify.body.mqttKeyId === "string" ? verify.body.mqttKeyId : "";
    if (typeof verify.body.serverTime === "number") this.clockOffsetSec = verify.body.serverTime - Date.now() / 1000;
    // The server's view of who we are has to match ours, or every topic we touch
    // belongs to somebody else and the broker refuses it with 0x87.
    if (verify.body.id && verify.body.id !== this.id) {
      throw new Error(`the server named us ${verify.body.id}, we are ${this.id}`);
    }

    this.username = username;
    const named = await http(API_BASE, "POST", "/username", { username }, this.sessionToken);
    if (named.status !== 200) {
      throw new Error(`username returned ${named.status} ${JSON.stringify(named.body)}`);
    }
  }

  api(method: string, path: string, body?: unknown) {
    return http(API_BASE, method, path, body, this.sessionToken);
  }

  /** Publish a bundle so peers can open sessions with us. */
  async publishPrekeys(count = 4): Promise<void> {
    const medium = this.c.kem.generateKeypair();
    this.prekeySecrets.mediumSk = medium.sk;
    const oneTime: Array<{ id: number; prekey: string }> = [];
    for (let id = 0; id < count; id++) {
      const pair = this.c.kem.generateKeypair();
      this.prekeySecrets.oneTime.set(id, pair.sk);
      oneTime.push({ id, prekey: pair.pk.toString("hex") });
    }
    const res = await this.api("POST", "/prekeys", {
      medium: medium.pk.toString("hex"),
      oneTime,
    });
    if (res.status !== 200) {
      throw new Error(`POST /prekeys returned ${res.status} ${JSON.stringify(res.body)}`);
    }
  }

  // ── MQTT ───────────────────────────────────────────────────────────────────

  async connect(timeoutMs = 15000): Promise<void> {
    return new Promise((resolve, reject) => {
      const c = mqtt.connect(EMQX_URL, {
        // The client id, not the public key. EMQX keys the topic ACL on this
        // (`WHERE id = ${clientid}`), and it used to carry 14474 characters in
        // every CONNECT packet.
        clientId: this.id,
        username: this.id,
        password: this.mqttPassword(),
        protocolVersion: 5,
        // Persistent — this is what makes the broker queue an `init` for a
        // client that is offline. On MQTT 5 that needs BOTH halves: `clean:
        // false` says "resume a session", and `sessionExpiryInterval` says how
        // long one may outlive its connection. The default is 0, so without it
        // the session dies with the socket and the queue is empty on reconnect.
        // The bot had the same omission; see bot.ts.
        clean: false,
        properties: { sessionExpiryInterval: 3600 },
        reconnectPeriod: 0,
        connectTimeout: timeoutMs,
      });
      const timer = setTimeout(() => reject(new NotAvailable("MQTT connect timed out")), timeoutMs);
      c.on("connect", () => {
        clearTimeout(timer);
        this.client = c;
        c.subscribe(`u/${this.id}/inbox`, { qos: 1 }, (err) =>
          err ? reject(err) : resolve()
        );
      });
      c.on("error", (e) => { clearTimeout(timer); reject(new NotAvailable(e.message)); });
      c.on("message", (topic, payload) => this.onFrame(topic, payload));
    });
  }

  /** Drop the connection without unsubscribing, so the broker keeps queueing. */
  async goOffline(): Promise<void> {
    await new Promise<void>((r) => this.client?.end(true, {}, () => r()));
    this.client = undefined;
  }

  /** Subscribe, and always settle — same disconnect hazard as `publishRaw`. */
  subscribeConversation(peerId_: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const c = this.client;
      if (!c) return reject(new NotAvailable("not connected"));
      let settled = false;
      const finish = (e?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        c.removeListener("close", onGone);
        e ? reject(e) : resolve();
      };
      const onGone = () => finish(new NotAvailable("broker closed the connection during SUBSCRIBE"));
      const timer = setTimeout(() => finish(new NotAvailable("SUBSCRIBE timed out")), 5000);
      c.once("close", onGone);
      c.subscribe(`c/${friendshipHash(this.id, peerId_)}`, { qos: 1 }, (err) =>
        finish(err ?? undefined)
      );
    });
  }

  /**
   * Fetch a peer's identity key and VERIFY it against their id.
   *
   * Exactly what the real clients do at friend-add: the directory ships ids, and
   * the key is checked rather than trusted. A key that does not hash to the id
   * is refused, which is the property the whole identifier change buys.
   */
  async fetchPeerKey(peerId_: string): Promise<Buffer> {
    const res = await http(API_BASE, "GET", `/peer/${peerId_}/key`);
    if (res.status !== 200 || typeof res.body?.publicKey !== "string") {
      throw new Error(`GET /peer/{id}/key returned ${res.status} ${JSON.stringify(res.body)}`);
    }
    const served = String(res.body.publicKey);
    if (!keyMatchesId(served, peerId_)) {
      throw new Error(`the key served for ${peerId_.slice(0, 12)}… does not hash to that id`);
    }
    return Buffer.from(served, "hex");
  }

  /** Attempt a publish and report whether the broker accepted it. Used to prove
   *  the ACL refuses a stranger — an unauthorized publish is dropped, and with
   *  MQTT 5 the broker returns a reason code for it. */
  /**
   * Publish, and ALWAYS settle.
   *
   * The obvious version — `publish(..., {qos: 1}, cb)` and nothing else — hangs
   * forever on exactly the case this suite exists to test. The broker's
   * `deny_action = disconnect` drops a client that publishes where it may not,
   * and a QoS-1 publish in flight when that happens is never acknowledged and
   * never failed: mqtt.js flushes only QoS-0 callbacks on close, keeps QoS-1
   * for retransmission, and `reconnectPeriod: 0` means the retransmission never
   * comes. The callback is simply never called.
   *
   * That is what stalled the ACL test for six minutes until the job timed out,
   * with four green tests above it and no error anywhere — the run looked
   * "finished but hung" rather than failed.
   *
   * So a close or an error settles it as a refusal, which is what a refusal
   * looks like on this broker, and a timeout backstops both.
   */
  publishRaw(topic: string, payload: string | Buffer): Promise<{ accepted: boolean; reason?: number }> {
    return new Promise((resolve) => {
      const c = this.client;
      if (!c) return resolve({ accepted: false });

      let settled = false;
      const finish = (r: { accepted: boolean; reason?: number }) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        c.removeListener("close", onGone);
        c.removeListener("error", onGone);
        resolve(r);
      };
      const onGone = () => finish({ accepted: false });
      // Generous: a permitted publish is acknowledged in milliseconds, so this
      // only ever fires if both the ack and the disconnect fail to arrive.
      const timer = setTimeout(() => finish({ accepted: false }), 5000);

      c.once("close", onGone);
      c.once("error", onGone);
      c.publish(topic, payload, { qos: 1 }, (err: any) => {
        finish(err ? { accepted: false, reason: err?.code } : { accepted: true });
      });
    });
  }

  // ── Protocol ───────────────────────────────────────────────────────────────

  /** Seal a frame WITHOUT publishing it, so a test can reorder or tamper first. */
  async sealOnly(peer: TestClient, text: string): Promise<Frame> {
    let session = this.sessions.get(peer.id);
    if (!session) {
      // The CLIENT ID, exactly as the bot and the app send it. This used to send
      // `peer.username`, which is why the suite passed while both real clients
      // were being refused with `peer must be 1–128 characters`: the test was
      // exercising an input shape nothing in production uses. Sending the id is
      // now that shape.
      const claimed = await this.api("POST", "/prekeys/claim", { peer: peer.id });
      if (claimed.status !== 200) {
        throw new Error(`claim returned ${claimed.status} ${JSON.stringify(claimed.body)}`);
      }
      // The identity key comes from the server and is VERIFIED against the id,
      // rather than being reached for out of the peer object — the real clients
      // have no such shortcut, and the check is the thing worth exercising.
      const identityPk = await this.fetchPeerKey(peer.id);
      const started = startAsInitiator(this.c.kem, {
        identityPk,
        mediumPk: Buffer.from(String(claimed.body.medium), "hex"),
        oneTimePk: claimed.body.oneTime
          ? Buffer.from(String(claimed.body.oneTime.prekey), "hex")
          : null,
        oneTimeId: claimed.body.oneTime ? Number(claimed.body.oneTime.id) : null,
      });
      session = started.state;
      this.sessions.set(peer.id, session);
    }

    const sealed = seal(this.c.kem, session);
    // Every binary field is BYTES. v2 spelled them as base64 strings inside
    // JSON, which is the conversion this harness used to do twice per frame and
    // no longer does at all.
    const fields: Omit<Frame, "payload"> = {
      v: 3,
      t: sealed.initHeader ? "init" : "msg",
      sender: this.id,
      // Bound as AAD. v2 had no recipient field, so a v2 receiver could only ask
      // which TOPIC a frame arrived on; this is the field that made that check a
      // belt rather than the whole belt-and-braces.
      to: peer.id,
      msgId: crypto.randomUUID(),
      cid: sealed.header.cid,
      n: sealed.header.n,
      pn: sealed.header.pn,
      ...(sealed.initHeader
        ? {
            // On `init` only: the responder may never have fetched our key, and
            // verifies this against `sender` rather than trusting it.
            senderPk: Buffer.from(this.pkHex, "hex"),
            rk: sealed.initHeader.rk,
            ctId: sealed.initHeader.ctId,
            ctMt: sealed.initHeader.ctMt,
            // Both or neither: `validateV3` refuses a ctOt without its id, and
            // the two travel together in the header too. Spelled as one
            // condition so a null id cannot produce half a pair.
            ...(sealed.initHeader.ctOt && sealed.initHeader.otId !== null
              ? { ctOt: sealed.initHeader.ctOt, otId: sealed.initHeader.otId }
              : {}),
          }
        : {
            ...(sealed.header.rk ? { rk: sealed.header.rk } : {}),
            ...(sealed.header.kemCt ? { kemCt: sealed.header.kemCt } : {}),
          }),
    };

    // The header has to exist before the payload, because the payload is sealed
    // AGAINST it. `encodeFrame` re-derives the same bytes, so the two cannot
    // drift — and under v3 those bytes are the frame's own prefix rather than a
    // parallel canonical encoding.
    const aad = frameHeader(fields);
    if (!aad) throw new Error(`the harness built a frame validateFrame refuses: ${JSON.stringify({ ...fields, senderPk: undefined })}`);
    return {
      ...fields,
      payload: Buffer.from(this.c.aesEncrypt(text, sealed.key, aad), "base64"),
    };
  }

  /** Seal and publish, on whichever topic can deliver the frame. */
  /**
   * Where a frame belongs, by its type.
   *
   * An `init` goes to the peer's INBOX: it is the frame they may receive before
   * any conversation exists, and `onFrame` refuses one that arrives anywhere
   * else. Everything after it goes to the shared conversation topic.
   *
   * Exposed because a test that publishes by hand — to reorder, delay or tamper
   * — has to obey the same rule, and one that hand-rolled the topic instead
   * sent three inits to `c/…` and watched all three be dropped as
   * "arrived on the wrong topic".
   */
  topicFor(env: Frame, peer: TestClient): string {
    return env.t === "init"
      ? `u/${peer.id}/inbox`
      : `c/${friendshipHash(this.id, peer.id)}`;
  }

  async send(peer: TestClient, text: string): Promise<Frame> {
    const env = await this.sealOnly(peer, text);
    const bytes = encodeFrame(env);
    if (!bytes) throw new Error("the harness built a frame encodeFrame refuses");
    await this.publishRaw(this.topicFor(env, peer), bytes);
    return env;
  }

  private onFrame(topic: string, payload: Buffer) {
    // From the BYTES, like every other receiver. Under v2 that mattered because
    // the text-level rules — a repeated JSON key, an unpaired surrogate — were
    // exactly the ones a client that parsed first could not enforce. v3 has no
    // text form at all, so the hazard is gone rather than guarded against.
    //
    // `decodeFrame` has already refused any frame whose `sender` is not a
    // well-formed client id, and any `init` whose `senderPk` does not hash to
    // it.
    const got = decodeFrame(payload);
    if (!got) { this.drops.push(`decodeFrame rejected a frame on ${topic}`); return; }
    const { frame: env, aad } = got;
    if (env.sender === this.id) { this.drops.push("own frame echoed back"); return; }

    // The recipient is in the frame now, and it is bound as AAD — so a frame
    // addressed to somebody else cannot be re-aimed at us by republishing it on
    // our topic. Under v2 the topic was the ONLY answer to "was this for me",
    // which is the gap that made a wire-format change worth making.
    if (env.to !== this.id) {
      this.drops.push(`addressed to ${env.to.slice(0, 8)}…, not us`);
      return;
    }

    const expected = env.t === "init"
      ? `u/${this.id}/inbox`
      : `c/${friendshipHash(this.id, env.sender)}`;
    if (topic !== expected) {
      this.drops.push(`t=${env.t} arrived on ${topic}, expected ${expected}`);
      return;
    }

    const header: MessageHeader = {
      cid: env.cid,
      n: env.n,
      pn: env.pn,
      ...(env.rk ? { rk: env.rk } : {}),
      ...(env.kemCt ? { kemCt: env.kemCt } : {}),
    };

    let session = this.sessions.get(env.sender);
    // An init BUILDS a session only when we have none. A live session is never
    // replaced from an inbound init — that is the difference between "my peer
    // reinstalled" and "somebody replayed a frame to wipe the conversation".
    //
    // PROTO-1: that used to be spelled as a drop, and the drop was the bug. The
    // initiator attaches the init header to every frame until it hears back, so
    // a burst sent before we reply is entirely typed `init`; refusing those
    // threw away the messages inside them, two in three, measured against a real
    // broker. Falling THROUGH is the fix — the header is ignored, the payload is
    // an ordinary message on the sender's chain, and the code below opens it
    // against the session we already hold with every existing protection intact.
    if (env.t === "init" && !session) {
      if (!env.ctId || !env.ctMt || !env.rk) {
        this.drops.push(`init missing ${!env.ctId ? "ctId" : !env.ctMt ? "ctMt" : "rk"}`);
        return;
      }
      const init: InitHeader = {
        ctId: env.ctId,
        ctMt: env.ctMt,
        ctOt: env.ctOt ?? null,
        otId: env.ctOt ? (env.otId ?? null) : null,
        rk: env.rk,
        cid: env.cid,
      };
      const opened = startAsResponder(this.c.kem, {
        identitySk: this.sk,
        mediumSk: this.prekeySecrets.mediumSk,
        oneTimeSk: (id) => this.prekeySecrets.oneTime.get(id) ?? null,
      }, init);
      if (!opened) {
        this.undecryptable.push(env.msgId);
        this.drops.push("startAsResponder returned null — the init did not open");
        return;
      }
      session = opened;
    }
    if (!session) {
      this.undecryptable.push(env.msgId);
      this.drops.push(`msg from ${env.sender.slice(0, 8)}… with no session`);
      return;
    }

    // The AEAD open IS the verifier: `openRatchet` commits nothing to the
    // session until it returns true. See lib/ratchet-session.ts.
    //
    // `aad` came back from `decodeFrame` as the literal bytes that arrived. It
    // is NOT rebuilt from the parsed fields, and that is the property v3 exists
    // for: a rebuild is a second construction, and a second construction can
    // differ from the first.
    const out: { text?: string; err?: string } = {};
    const mk = openRatchet(this.c.kem, session, header, (key) => {
      try {
        out.text = this.c.aesDecrypt(env.payload.toString("base64"), key, aad);
        return true;
      } catch (e) {
        out.err = (e as Error).message;
        return false;
      }
    });
    if (!mk || out.text === undefined) {
      this.undecryptable.push(env.msgId);
      this.drops.push(
        out.err !== undefined
          ? `AES decrypt failed: ${out.err}`
          : `openRatchet returned no message key (n=${env.n})`
      );
      return;
    }
    this.sessions.set(env.sender, session);
    this.inbox.push({ from: env.sender, text: out.text });
  }

  /** Next unread message, waiting up to `timeoutMs` for it to arrive. */
  async next(timeoutMs = 8000): Promise<Received> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.cursor < this.inbox.length) return this.inbox[this.cursor++]!;
      await new Promise((r) => setTimeout(r, 50));
    }
    // The whole point of `drops`. A bare timeout cannot distinguish "the
    // broker never delivered it" from "it arrived and would not open", and
    // those have entirely different causes.
    const why = this.drops.length
      ? ` — ${this.drops.length} frame(s) dropped: ${this.drops.join("; ")}`
      : " — no frame reached this client at all";
    throw new Error(`no message within ${timeoutMs}ms${why}`);
  }

  async close(): Promise<void> {
    await new Promise<void>((r) => this.client?.end(true, {}, () => r()));
  }
}

/** Probe: are a live auth server, api and broker actually reachable? */
export async function e2eAvailable(): Promise<boolean> {
  try {
    await loadCrypto();
  } catch {
    return false; // native HQC library missing (an arm64 laptop, for instance)
  }
  try {
    const [auth, api, broker] = await Promise.all([
      fetch(`${AUTH_BASE}/health`).then((r) => r.ok).catch(() => false),
      fetch(`${API_BASE}/health`).then((r) => r.ok).catch(() => false),
      brokerReachable(),
    ]);
    return auth && api && broker;
  } catch {
    return false;
  }
}

/** A broker that answers a CONNECT. Checked separately from the HTTP services
 *  because a missing one would otherwise surface as a test timeout rather than
 *  a skip — and, in CI, as a green job that ran nothing. */
function brokerReachable(timeoutMs = 4000): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = mqtt.connect(EMQX_URL, {
      reconnectPeriod: 0,
      connectTimeout: timeoutMs,
      clientId: `probe-${crypto.randomBytes(6).toString("hex")}`,
    });
    const done = (ok: boolean) => {
      probe.end(true, {}, () => resolve(ok));
    };
    // A refused CONNECT still proves a broker is THERE — the credentials are
    // what it is rejecting, and the real clients bring their own.
    probe.on("connect", () => done(true));
    probe.on("error", (e) => done(/not authorized|bad user|unauthorized/i.test(e.message)));
    setTimeout(() => done(false), timeoutMs + 500);
  });
}
