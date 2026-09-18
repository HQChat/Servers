import * as crypto from "crypto";

/**
 * Proof of key possession for the HQC-KEM handshake.
 *
 * The client decapsulates the server's ciphertext to recover the shared secret
 * and returns HKDF(ss, "auth") — never the secret itself, and never any
 * decrypted plaintext, so the handshake is not a decryption oracle.
 *
 * This is all that survives of `secure-transport.ts`. The rest of that module
 * was the per-connection AES layer the old `/ws` protocol needed because it ran
 * its own framing; TLS does that job now, and the remainder lives in `legacy/`
 * with the monolith that used it.
 */
export function authProof(ss: Buffer): Buffer {
  return Buffer.from(
    crypto.hkdfSync("sha256", ss, Buffer.from("salt", "utf8"), Buffer.from("auth", "utf8"), 32)
  );
}
