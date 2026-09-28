import * as crypto from "crypto";

/**
 * The v1 MQTT CONNECT proof: an Ed25519 signature in the password field.
 *
 * The password used to be an opaque bearer token, reusable for 12 hours. Anyone
 * who saw one CONNECT could connect as that client until it expired, and could
 * replay the packet verbatim to take over — kick — the live session. On the
 * raw-TCP transport the CONNECT is the first thing on the wire.
 *
 * Instead, at sign-in and on refresh (over HTTPS) the client registers the
 * public half of a fresh Ed25519 key, and every CONNECT signs
 *
 *   "hqchat-mqtt-connect/1" 0x00 clientid 0x00 keyId 0x00 ts 0x00 nonce(16 raw bytes)
 *
 * and carries it as
 *
 *   v1.<keyId: 32 hex>.<ts: unix seconds>.<nonce: 16 B base64url>.<sig: 64 B base64url>
 *
 * The server holds no secret — a copy of `mqtt_session_keys` lets nobody
 * connect — and a captured CONNECT dies with its nonce (single-use) or its
 * timestamp (±60 s). `clientid` is inside the signature, so a proof cannot be
 * lifted onto another client id either.
 *
 * Every field is fixed-format (hex, decimal, fixed-length bytes) and none can
 * contain 0x00, so the separators make the encoding unambiguous.
 *
 * Mirrored by apps/apple/DissQus/Services/MQTTConnectProof.swift and pinned
 * between the two by test/helpers/mqtt-proof-vectors.json.
 */

export const MQTT_PROOF_CONTEXT = "hqchat-mqtt-connect/1";

/** How far a CONNECT's timestamp may sit from the server clock, either way. The
 *  client corrects for its own clock with the `serverTime` it is handed at
 *  sign-in, so this only has to absorb latency and drift since then. */
export const MQTT_PROOF_SKEW_SECONDS = 60;

/** How long a spent nonce is remembered. It must outlive every timestamp that
 *  could still be accepted alongside it — anything shorter and a replay after
 *  the nonce is forgotten, but inside the skew window, would succeed. */
export const MQTT_PROOF_NONCE_TTL_SECONDS = 2 * MQTT_PROOF_SKEW_SECONDS;

export interface ParsedProof {
  keyId: string;
  ts: number;
  nonce: Buffer;
  sig: Buffer;
}

const PASSWORD_RE =
  /^v1\.([0-9a-f]{32})\.(0|[1-9][0-9]{0,11})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{86})$/;

/** True when the password is a v1 proof rather than a legacy token. Cheap, so
 *  the hook can pick a path before any parsing. */
export function isV1Password(password: string): boolean {
  return password.startsWith("v1.");
}

/** Parse strictly. Anything that is not exactly the v1 shape is null — there is
 *  no lenient reading of a credential. */
export function parseProofPassword(password: string): ParsedProof | null {
  const m = PASSWORD_RE.exec(password);
  if (!m) return null;
  const [, keyId, ts, nonceText, sigText] = m;
  if (!keyId || !ts || !nonceText || !sigText) return null;
  const nonce = Buffer.from(nonceText, "base64url");
  const sig = Buffer.from(sigText, "base64url");
  // base64url of the right LENGTH can still carry trailing bits that decode to
  // the same bytes; re-encoding rejects every spelling but the canonical one,
  // so one proof has exactly one password.
  if (nonce.length !== 16 || sig.length !== 64) return null;
  if (nonce.toString("base64url") !== nonceText || sig.toString("base64url") !== sigText) return null;
  return { keyId, ts: Number(ts), nonce, sig };
}

export function formatProofPassword(p: ParsedProof): string {
  return `v1.${p.keyId}.${p.ts}.${p.nonce.toString("base64url")}.${p.sig.toString("base64url")}`;
}

/** The exact bytes that are signed. */
export function proofMessage(clientid: string, keyId: string, ts: number, nonce: Buffer): Buffer {
  const sep = Buffer.from([0]);
  return Buffer.concat([
    Buffer.from(MQTT_PROOF_CONTEXT, "utf8"), sep,
    Buffer.from(clientid, "utf8"), sep,
    Buffer.from(keyId, "utf8"), sep,
    Buffer.from(String(ts), "utf8"), sep,
    nonce,
  ]);
}

/** Whether `ts` (unix seconds) is inside the accepted window around `nowSec`. */
export function isFreshTimestamp(ts: number, nowSec: number): boolean {
  return Number.isSafeInteger(ts) && Math.abs(nowSec - ts) <= MQTT_PROOF_SKEW_SECONDS;
}

// DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** A raw 32-byte Ed25519 public key as a KeyObject, or null if it is not one. */
export function ed25519PublicKey(raw: Buffer): crypto.KeyObject | null {
  if (raw.length !== 32) return null;
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
  } catch {
    return null;
  }
}

/** Verify a signature against a raw public key. Never throws. */
export function verifyProofSignature(publicKeyRaw: Buffer, message: Buffer, sig: Buffer): boolean {
  const key = ed25519PublicKey(publicKeyRaw);
  if (!key || sig.length !== 64) return false;
  try {
    return crypto.verify(null, message, key, sig);
  } catch {
    return false;
  }
}

// --- For TypeScript clients: the helper bot and the e2e suite ------------------
//
// The app's half is MQTTConnectProof.swift. These are the same two steps for a
// client written here: make a per-session key, register its public half at
// sign-in or refresh (`mqttSigningKey`), then sign every CONNECT fresh.

export interface SigningKey {
  privateKey: crypto.KeyObject;
  /** Raw 32-byte public key, base64 — the `mqttSigningKey` field. */
  publicKeyB64: string;
}

export function newSigningKey(): SigningKey {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { privateKey, publicKeyB64: spki.subarray(spki.length - 32).toString("base64") };
}

/** A fresh v1 password: new nonce every call. `nowSec` must be SERVER time. */
export function signConnect(o: { clientid: string; keyId: string; privateKey: crypto.KeyObject; nowSec: number }): string {
  const ts = Math.floor(o.nowSec);
  const nonce = crypto.randomBytes(16);
  const sig = crypto.sign(null, proofMessage(o.clientid, o.keyId, ts, nonce), o.privateKey);
  return formatProofPassword({ keyId: o.keyId, ts, nonce, sig });
}
