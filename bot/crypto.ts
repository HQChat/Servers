import * as crypto from "crypto";
import { HqcWrapper, HQC_CONSTANTS } from "../lib/hqc";

const { SHARED_SECRET_BYTES } = HQC_CONSTANTS;

// ── HQC IND-CCA2 KEM (SECURITY_AUDIT §KM-1) ──────────────────────────────────
// The old 24-byte PKE chunking is gone. Key agreement is now a KEM encapsulation:
// encapsulate to the peer's public key → (ct, ss); the peer decapsulates ct with
// its secret key to recover the same 32-byte shared secret `ss`. Callers stretch
// `ss` with HKDF (see deriveSharedKey / the domain-separated session/auth KDFs).
//
// Migration note: wherever the old flow did `hqcEncrypt(peerPk, freshSeed())` to
// contribute a seed, encapsulate instead — the transported value is `ct` and the
// contributed secret is `ss` (which the peer recovers by decapsulating). The
// mutual-key derivation (deriveSharedKey of the two shared secrets) is unchanged.

/** Encapsulate to a peer public key → { ct (relay this), ss (keep secret) }. */
export function hqcEncapsulate(pk: Buffer): { ct: Buffer; ss: Buffer } {
  return HqcWrapper.encapsulate(pk);
}

/** Decapsulate a peer's KEM ciphertext with our secret key → the 32-byte ss. */
export function hqcDecapsulate(sk: Buffer, ct: Buffer): Buffer {
  return HqcWrapper.decapsulate(sk, ct);
}

// ── AES-256-GCM (matches Swift AESService: [IV 12][tag 16][ct], base64) ───────

/**
 * `aad` binds cleartext the ciphertext does not carry — the frame header, whose
 * fields (epoch/idx today, the v2 ratchet header next) are read to CHOOSE the key
 * and so cannot be authenticated by the payload that key opens. Both sides must
 * pass byte-identical AAD or the tag check fails; the canonical serializer is the
 * one place that is decided. Omit it and this is plain AES-GCM, as before.
 */
/**
 * Seal to RAW bytes: `[IV 12][tag 16][ct]`.
 *
 * The raw form is the real one, and base64 is a v2 spelling of it — v3 carries
 * the payload as bytes. Keeping one implementation means the tag-length rule
 * below cannot end up applying to one path and not the other.
 */
export function aesEncryptRaw(plaintext: string, key: Buffer, aad?: Buffer): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

export function aesEncrypt(plaintext: string, key: Buffer, aad?: Buffer): string {
  return aesEncryptRaw(plaintext, key, aad).toString("base64");
}

/** GCM tags are 16 bytes here and nowhere else. Stated to the cipher AND checked
 *  before `setAuthTag`, because neither alone is enough: node accepts a short tag
 *  without `authTagLength`, and `subarray` silently yields a short one from a
 *  truncated payload rather than throwing. A verifier that will compare fewer
 *  bytes than it should is a forgery oracle — 2^-32 for a 4-byte tag instead of
 *  2^-128. The sender is `aesEncrypt` above, which always writes 16. */
const GCM_TAG_BYTES = 16;

export function aesDecrypt(b64: string, key: Buffer, aad?: Buffer): string {
  return aesDecryptRaw(Buffer.from(b64, "base64"), key, aad);
}

export function aesDecryptRaw(data: Buffer, key: Buffer, aad?: Buffer): string {
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 12 + GCM_TAG_BYTES);
  const ct = data.subarray(12 + GCM_TAG_BYTES);
  if (tag.length !== GCM_TAG_BYTES) {
    throw new Error(`aesDecrypt: truncated GCM tag (${tag.length} of ${GCM_TAG_BYTES} bytes)`);
  }
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, {
    authTagLength: GCM_TAG_BYTES,
  });
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

// ── Shared key (HKDF-SHA256 of the two sorted shared secrets) ─────────────────
// Inputs are now 32-byte KEM shared secrets (were 24-byte seeds). Sorting keeps
// the derivation order-independent, so both peers compute the same key regardless
// of who initiated. `info` gives domain separation (§KM-2): pass a per-channel
// context like `channel:<sorted-peer-pk>` for content keys; the legacy default
// "info" is the epoch-0 static-key context (see lib/ratchet.ts / §KM-5).
export function deriveSharedKey(ssA: Buffer, ssB: Buffer, info = "info"): Buffer {
  const [s1, s2] = Buffer.compare(ssA, ssB) <= 0 ? [ssA, ssB] : [ssB, ssA];
  const combined = Buffer.concat([s1, s2]);
  const dk = crypto.hkdfSync("sha256", combined, Buffer.from("salt", "utf8"), Buffer.from(info, "utf8"), 32);
  return Buffer.from(dk);
}

/** Fresh 32-byte value (e.g. an explicit epoch seed contribution). */
export function freshSeed(): Buffer {
  return crypto.randomBytes(SHARED_SECRET_BYTES);
}
