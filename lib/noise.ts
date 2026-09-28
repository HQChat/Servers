import * as crypto from "crypto";

/**
 * hqn/1 — the handshake and framing for MQTT over raw TCP.
 *
 * WHY THIS EXISTS. The mobile client moves off MQTT-over-WSS (nginx +
 * Cloudflare) onto a raw TCP socket, because the WebSocket upgrade costs a
 * round trip per connect and roughly 3x the packets under loss (PR #156's
 * bench). TLS on that socket would put the round trip back. This is a Noise
 * handshake whose FIRST flight already carries the MQTT CONNECT, so a connect
 * is TCP's round trip plus one — the same as plaintext MQTT — while the stream
 * is encrypted and authenticated end to end between the app and the gateway
 * (noise-gw) in front of the broker.
 *
 * PATTERN: NK, made hybrid post-quantum. The client knows the server's static
 * keys in advance (pinned in the app); the client itself is anonymous at this
 * layer, because its identity is proven INSIDE the stream by the v1 MQTT
 * CONNECT proof (lib/mqtt-proof.ts). IK would need client static keys
 * registered with the server and a lookup per unauthenticated first message;
 * XK costs another half round trip and loses the 0-RTT CONNECT.
 *
 *   Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256
 *
 *   <- s, s_pq                 pre-message: both server statics, pinned
 *   ...
 *   -> e, es, kem, [payload]   msg1: CONNECT rides here
 *   <- e, ee, [payload]        msg2
 *
 *   e     write/read the ephemeral X25519 public key; MixHash(e)
 *   es    MixKey(DH(e_client, s_server))
 *   kem   (ct, ss) = HQC-256.Encaps(s_pq); EncryptAndHash(ct); MixKey(ss)
 *   ee    MixKey(DH(e_client, e_server))
 *
 * Every transport key depends on es, the HQC secret AND ee: breaking X25519
 * (a quantum adversary) still leaves HQC-256, and a flaw in HQC still leaves
 * X25519. Metadata on this channel — who connects, to which topics — was
 * post-quantum over Cloudflare's hybrid TLS, and must not get weaker here.
 *
 * ACCEPTED PROPERTIES, stated so nobody rediscovers them as bugs:
 *   - msg1's payload is keyed from es + kem only, so it has no forward secrecy
 *     against a later compromise of BOTH server static keys. It is also
 *     replayable byte for byte. The CONNECT it carries is a single-use,
 *     timestamped proof, so a replay authenticates nothing.
 *   - msg1 is ~14.7 kB (the HQC-256 ciphertext is 14421 bytes), just over a
 *     10-segment initial congestion window.
 *
 * WIRE. The client opens with two cleartext bytes, [version][keyId], which name
 * the protocol version and which pinned server key pair it used. Both are in
 * the prologue, so tampering with either breaks the handshake. Every message
 * after that — msg1, msg2, and each transport frame — is a u16 big-endian
 * length followed by that many bytes. A transport frame is ChaCha20-Poly1305
 * ciphertext, at most 65535 bytes including the 16-byte tag.
 *
 * Mirrored by apps/apple/DissQus/Services/NoiseHQN.swift. The two are held
 * together by test/helpers/noise-hqn-vectors.json, and the generic Noise core
 * here is also checked against the published Noise_NK_25519_ChaChaPoly_SHA256
 * vectors (test/noise.test.ts).
 */

export const HQN_VERSION = 1;
export const HQN_PROTOCOL_NAME = "Noise_pqNK_25519+HQC256_ChaChaPoly_SHA256";
export const HQN_PROLOGUE_LABEL = "hqchat-noise/1";

export const DH_LEN = 32;
export const TAG_LEN = 16;
export const HASH_LEN = 32;
/** Largest ciphertext a u16 length prefix can describe. */
export const MAX_FRAME = 65535;
/** Largest plaintext one transport frame can carry. */
export const MAX_FRAME_PLAINTEXT = MAX_FRAME - TAG_LEN;

export const HQC_PUBLIC_KEY_BYTES = 7237;
export const HQC_SECRET_KEY_BYTES = 7333;
export const HQC_CIPHERTEXT_BYTES = 14421;
export const HQC_SHARED_SECRET_BYTES = 32;

/** msg1 length for a given payload: e + encrypted ct + encrypted payload. The
 *  gateway knows the exact length to expect from the payload it is prepared to
 *  accept, and refuses anything else before doing any cryptography. */
export function msg1Length(payloadLen: number): number {
  return DH_LEN + (HQC_CIPHERTEXT_BYTES + TAG_LEN) + (payloadLen + TAG_LEN);
}

export class NoiseError extends Error {}

// --- Primitives ---------------------------------------------------------------

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export interface KeyPair {
  priv: Buffer;
  pub: Buffer;
}

export function x25519KeyPair(priv?: Buffer): KeyPair {
  const secret = priv ?? crypto.randomBytes(DH_LEN);
  if (secret.length !== DH_LEN) throw new NoiseError("X25519 private key must be 32 bytes");
  const key = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, secret]),
    format: "der",
    type: "pkcs8",
  });
  const spki = crypto.createPublicKey(key).export({ format: "der", type: "spki" }) as Buffer;
  return { priv: Buffer.from(secret), pub: Buffer.from(spki.subarray(spki.length - DH_LEN)) };
}

/** X25519. Refuses an all-zero result — a low-order public key would otherwise
 *  let an attacker fix the shared secret to a known value. */
export function dh(priv: Buffer, pub: Buffer): Buffer {
  if (pub.length !== DH_LEN) throw new NoiseError("X25519 public key must be 32 bytes");
  let out: Buffer;
  try {
    out = crypto.diffieHellman({
      privateKey: crypto.createPrivateKey({
        key: Buffer.concat([X25519_PKCS8_PREFIX, priv]),
        format: "der",
        type: "pkcs8",
      }),
      publicKey: crypto.createPublicKey({
        key: Buffer.concat([X25519_SPKI_PREFIX, pub]),
        format: "der",
        type: "spki",
      }),
    });
  } catch {
    throw new NoiseError("X25519 failed");
  }
  if (out.every((b) => b === 0)) throw new NoiseError("X25519 produced the all-zero secret");
  return out;
}

function hash(...parts: Buffer[]): Buffer {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

function hmac(key: Buffer, ...parts: Buffer[]): Buffer {
  const h = crypto.createHmac("sha256", key);
  for (const p of parts) h.update(p);
  return h.digest();
}

/** The Noise HKDF: two 32-byte outputs, HMAC-SHA256 chained. */
export function hkdf2(chainingKey: Buffer, ikm: Buffer): [Buffer, Buffer] {
  const temp = hmac(chainingKey, ikm);
  const out1 = hmac(temp, Buffer.from([1]));
  const out2 = hmac(temp, out1, Buffer.from([2]));
  return [out1, out2];
}

/** ChaCha20-Poly1305 nonce: 32 zero bits, then the counter little-endian. */
function nonceBytes(n: bigint): Buffer {
  const b = Buffer.alloc(12);
  b.writeBigUInt64LE(n, 4);
  return b;
}

function aeadEncrypt(key: Buffer, n: bigint, ad: Buffer, pt: Buffer): Buffer {
  const c = crypto.createCipheriv("chacha20-poly1305", key, nonceBytes(n), { authTagLength: TAG_LEN });
  c.setAAD(ad, { plaintextLength: pt.length });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}

function aeadDecrypt(key: Buffer, n: bigint, ad: Buffer, ct: Buffer): Buffer {
  if (ct.length < TAG_LEN) throw new NoiseError("ciphertext shorter than its tag");
  const d = crypto.createDecipheriv("chacha20-poly1305", key, nonceBytes(n), { authTagLength: TAG_LEN });
  d.setAAD(ad, { plaintextLength: ct.length - TAG_LEN });
  d.setAuthTag(ct.subarray(ct.length - TAG_LEN));
  try {
    return Buffer.concat([d.update(ct.subarray(0, ct.length - TAG_LEN)), d.final()]);
  } catch {
    throw new NoiseError("decryption failed");
  }
}

// --- CipherState / SymmetricState (Noise spec §5.1, §5.2) --------------------

/** 2^64 - 1 is reserved by the spec; a state that reaches it is exhausted. */
const MAX_NONCE = (1n << 64n) - 1n;

export class CipherState {
  private n = 0n;
  constructor(private k: Buffer | null = null) {}

  hasKey(): boolean {
    return this.k !== null;
  }

  encryptWithAd(ad: Buffer, pt: Buffer): Buffer {
    if (!this.k) return Buffer.from(pt);
    if (this.n >= MAX_NONCE) throw new NoiseError("nonce exhausted");
    const out = aeadEncrypt(this.k, this.n, ad, pt);
    this.n += 1n;
    return out;
  }

  /** On failure the nonce does NOT advance, per the spec — but every caller here
   *  treats a failure as fatal for the connection anyway. */
  decryptWithAd(ad: Buffer, ct: Buffer): Buffer {
    if (!this.k) return Buffer.from(ct);
    if (this.n >= MAX_NONCE) throw new NoiseError("nonce exhausted");
    const out = aeadDecrypt(this.k, this.n, ad, ct);
    this.n += 1n;
    return out;
  }

  /** Test hook: jump the counter to check the exhaustion guard. */
  __setNonceForTesting(n: bigint): void {
    this.n = n;
  }
}

export class SymmetricState {
  ck: Buffer;
  h: Buffer;
  private cs = new CipherState();

  constructor(protocolName: string) {
    const name = Buffer.from(protocolName, "utf8");
    this.h = name.length <= HASH_LEN ? Buffer.concat([name, Buffer.alloc(HASH_LEN - name.length)]) : hash(name);
    this.ck = Buffer.from(this.h);
  }

  mixKey(ikm: Buffer): void {
    const [ck, k] = hkdf2(this.ck, ikm);
    this.ck = ck;
    this.cs = new CipherState(k);
  }

  mixHash(data: Buffer): void {
    this.h = hash(this.h, data);
  }

  encryptAndHash(pt: Buffer): Buffer {
    const ct = this.cs.encryptWithAd(this.h, pt);
    this.mixHash(ct);
    return ct;
  }

  decryptAndHash(ct: Buffer): Buffer {
    const pt = this.cs.decryptWithAd(this.h, ct);
    this.mixHash(ct);
    return pt;
  }

  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdf2(this.ck, Buffer.alloc(0));
    return [new CipherState(k1), new CipherState(k2)];
  }
}

// --- The KEM seam -------------------------------------------------------------

/** HQC-256 as the handshake uses it. Injected so the vectors can pin a
 *  (ct, ss) pair — real encapsulation is randomized — and so this module does
 *  not dlopen the native library until a handshake actually needs it. */
export interface Kem {
  encapsulate(pk: Buffer): { ct: Buffer; ss: Buffer };
  decapsulate(sk: Buffer, ct: Buffer): Buffer;
}

export function hqcKem(): Kem {
  // Lazy, like auth/main.ts: the library is native and platform-specific.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { HqcWrapper } = require("./hqc") as typeof import("./hqc");
  return {
    encapsulate: (pk) => HqcWrapper.encapsulate(pk),
    decapsulate: (sk, ct) => HqcWrapper.decapsulate(sk, ct),
  };
}

// --- The handshake --------------------------------------------------------------

export interface ServerStatic {
  keyId: number;
  x25519: KeyPair;
  hqc: { pk: Buffer; sk: Buffer };
}

export interface ServerStaticPublic {
  keyId: number;
  x25519: Buffer;
  hqc: Buffer;
}

export function prologue(version: number, keyId: number): Buffer {
  return Buffer.concat([Buffer.from(HQN_PROLOGUE_LABEL, "utf8"), Buffer.from([version, keyId])]);
}

function initialState(version: number, server: ServerStaticPublic): SymmetricState {
  if (server.x25519.length !== DH_LEN) throw new NoiseError("server X25519 key must be 32 bytes");
  if (server.hqc.length !== HQC_PUBLIC_KEY_BYTES) throw new NoiseError("server HQC key has the wrong size");
  const ss = new SymmetricState(HQN_PROTOCOL_NAME);
  ss.mixHash(prologue(version, server.keyId));
  // Pre-message `<- s, s_pq`: both statics bound into the transcript.
  ss.mixHash(server.x25519);
  ss.mixHash(server.hqc);
  return ss;
}

export interface Transport {
  /** Client → server. */
  send: CipherState;
  /** Server → client. */
  recv: CipherState;
  /** The handshake hash: a channel binding, identical on both ends. */
  handshakeHash: Buffer;
}

/** The client's side. `ephemeral` and `kem` are injectable for vectors only. */
export class HqnInitiator {
  private ss: SymmetricState;
  private e: KeyPair;
  private kem: Kem | undefined;
  private sent = false;

  constructor(
    private server: ServerStaticPublic,
    opts: { ephemeral?: KeyPair; kem?: Kem; version?: number } = {},
  ) {
    this.ss = initialState(opts.version ?? HQN_VERSION, server);
    this.e = opts.ephemeral ?? x25519KeyPair();
    this.kem = opts.kem;
  }

  /** msg1 = e ‖ enc(ct) ‖ enc(payload). */
  writeMessage1(payload: Buffer): Buffer {
    if (this.sent) throw new NoiseError("message 1 already written");
    this.sent = true;
    this.ss.mixHash(this.e.pub);
    this.ss.mixKey(dh(this.e.priv, this.server.x25519));
    const { ct, ss } = (this.kem ?? hqcKem()).encapsulate(this.server.hqc);
    if (ct.length !== HQC_CIPHERTEXT_BYTES || ss.length !== HQC_SHARED_SECRET_BYTES) {
      throw new NoiseError("KEM returned the wrong sizes");
    }
    const encCt = this.ss.encryptAndHash(ct);
    this.ss.mixKey(ss);
    const encPayload = this.ss.encryptAndHash(payload);
    return Buffer.concat([this.e.pub, encCt, encPayload]);
  }

  /** msg2 = re ‖ enc(payload). Returns the payload and the transport. */
  readMessage2(msg: Buffer): { payload: Buffer; transport: Transport } {
    if (!this.sent) throw new NoiseError("message 1 not written yet");
    if (msg.length < DH_LEN + TAG_LEN) throw new NoiseError("message 2 too short");
    const re = msg.subarray(0, DH_LEN);
    this.ss.mixHash(re);
    this.ss.mixKey(dh(this.e.priv, re));
    const payload = this.ss.decryptAndHash(msg.subarray(DH_LEN));
    const [c1, c2] = this.ss.split();
    return { payload, transport: { send: c1, recv: c2, handshakeHash: Buffer.from(this.ss.h) } };
  }
}

/** The server's side, for one connection. */
export class HqnResponder {
  private ss: SymmetricState;
  private kem: Kem | undefined;
  private re: Buffer | null = null;
  private pendingPayload: Buffer | null = null;
  private opened = false;

  constructor(
    private server: ServerStatic,
    opts: { kem?: Kem; version?: number } = {},
  ) {
    this.ss = initialState(opts.version ?? HQN_VERSION, {
      keyId: server.keyId,
      x25519: server.x25519.pub,
      hqc: server.hqc.pk,
    });
    this.kem = opts.kem;
  }

  /** The client's ephemeral key, readable before any expensive work — the
   *  gateway checks it against a replay cache ahead of the KEM decapsulation. */
  static ephemeralOf(msg1: Buffer): Buffer {
    if (msg1.length < DH_LEN) throw new NoiseError("message 1 too short");
    return msg1.subarray(0, DH_LEN);
  }

  /**
   * msg1, in one step, with the injected (or default) KEM. The gateway uses the
   * two halves below instead, so the decapsulation can run off its event loop.
   */
  readMessage1(msg: Buffer): Buffer {
    const ct = this.openMessage1(msg);
    return this.finishMessage1((this.kem ?? hqcKem()).decapsulate(this.server.hqc.sk, ct));
  }

  /**
   * Phase 1 of msg1: X25519 and the AEAD tag over the KEM ciphertext. Returns
   * the ciphertext to decapsulate.
   *
   * This split is the gateway's DoS budget. Random bytes fail the tag here, for
   * the cost of one X25519, and never reach the HQC decapsulation — only a msg1
   * built by a real Noise client against our pinned key costs one.
   */
  openMessage1(msg: Buffer): Buffer {
    if (this.re) throw new NoiseError("message 1 already read");
    const min = DH_LEN + HQC_CIPHERTEXT_BYTES + TAG_LEN + TAG_LEN;
    if (msg.length < min) throw new NoiseError("message 1 too short");
    const re = msg.subarray(0, DH_LEN);
    this.re = Buffer.from(re);
    this.ss.mixHash(re);
    this.ss.mixKey(dh(this.server.x25519.priv, re));
    const encCtEnd = DH_LEN + HQC_CIPHERTEXT_BYTES + TAG_LEN;
    const ct = this.ss.decryptAndHash(msg.subarray(DH_LEN, encCtEnd));
    this.pendingPayload = Buffer.from(msg.subarray(encCtEnd));
    return ct;
  }

  /** Phase 2 of msg1: mix the KEM secret in and open the payload (the CONNECT). */
  finishMessage1(sharedSecret: Buffer): Buffer {
    if (!this.pendingPayload) throw new NoiseError("message 1 not opened");
    if (sharedSecret.length !== HQC_SHARED_SECRET_BYTES) throw new NoiseError("KEM secret has the wrong size");
    const enc = this.pendingPayload;
    this.pendingPayload = null;
    this.ss.mixKey(sharedSecret);
    const payload = this.ss.decryptAndHash(enc);
    this.opened = true;
    return payload;
  }

  writeMessage2(payload: Buffer, ephemeral?: KeyPair): { message: Buffer; transport: Transport } {
    if (!this.re || !this.opened) throw new NoiseError("message 1 not read yet");
    const e = ephemeral ?? x25519KeyPair();
    this.ss.mixHash(e.pub);
    this.ss.mixKey(dh(e.priv, this.re));
    const enc = this.ss.encryptAndHash(payload);
    const [c1, c2] = this.ss.split();
    return {
      message: Buffer.concat([e.pub, enc]),
      transport: { send: c2, recv: c1, handshakeHash: Buffer.from(this.ss.h) },
    };
  }
}

// --- The plain NK pattern, for the published vectors --------------------------
//
// hqn/1 is NK with one extra token. Running plain NK through the SAME
// SymmetricState, dh and AEAD, and matching the published
// Noise_NK_25519_ChaChaPoly_SHA256 vectors, is what shows the core is Noise and
// not merely self-consistent.

export function nkInitiatorMessage1(
  prologueBytes: Buffer, rs: Buffer, e: KeyPair, payload: Buffer,
): { message: Buffer; state: SymmetricState } {
  const ss = new SymmetricState("Noise_NK_25519_ChaChaPoly_SHA256");
  ss.mixHash(prologueBytes);
  ss.mixHash(rs);
  ss.mixHash(e.pub);
  ss.mixKey(dh(e.priv, rs));
  return { message: Buffer.concat([e.pub, ss.encryptAndHash(payload)]), state: ss };
}

export function nkResponderMessage2(
  prologueBytes: Buffer, s: KeyPair, msg1: Buffer, e: KeyPair, payload: Buffer,
): { payload1: Buffer; message: Buffer; state: SymmetricState } {
  const ss = new SymmetricState("Noise_NK_25519_ChaChaPoly_SHA256");
  ss.mixHash(prologueBytes);
  ss.mixHash(s.pub);
  const re = msg1.subarray(0, DH_LEN);
  ss.mixHash(re);
  ss.mixKey(dh(s.priv, re));
  const payload1 = ss.decryptAndHash(msg1.subarray(DH_LEN));
  ss.mixHash(e.pub);
  ss.mixKey(dh(e.priv, re));
  return { payload1, message: Buffer.concat([e.pub, ss.encryptAndHash(payload)]), state: ss };
}

// --- Framing -------------------------------------------------------------------

/** One length-prefixed message or transport frame. */
export function frame(body: Buffer): Buffer {
  if (body.length > MAX_FRAME) throw new NoiseError("frame too large");
  const out = Buffer.alloc(2 + body.length);
  out.writeUInt16BE(body.length, 0);
  body.copy(out, 2);
  return out;
}

/** Encrypt an arbitrary byte stream chunk into as few frames as it needs. */
export function sealFrames(cs: CipherState, data: Buffer): Buffer {
  const out: Buffer[] = [];
  for (let off = 0; off < data.length; off += MAX_FRAME_PLAINTEXT) {
    out.push(frame(cs.encryptWithAd(Buffer.alloc(0), data.subarray(off, off + MAX_FRAME_PLAINTEXT))));
  }
  return Buffer.concat(out);
}

/**
 * A rolling reader of length-prefixed frames from a byte stream: feed it bytes
 * in whatever pieces TCP delivers, take whole frames out. A caller that drains
 * `next()` after every `push` holds at most one partial frame — the u16 prefix
 * caps that at 65537 bytes, whatever the peer sends.
 */
export class FrameReader {
  private buf = Buffer.alloc(0);

  push(chunk: Buffer): void {
    this.buf = this.buf.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buf, chunk]);
  }

  /** The next whole frame body, or null if it has not all arrived. */
  next(): Buffer | null {
    if (this.buf.length < 2) return null;
    const len = this.buf.readUInt16BE(0);
    if (this.buf.length < 2 + len) return null;
    const body = this.buf.subarray(2, 2 + len);
    this.buf = this.buf.subarray(2 + len);
    return Buffer.from(body);
  }

  /** Bytes buffered and not yet returned. */
  get pending(): number {
    return this.buf.length;
  }
}
