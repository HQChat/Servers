// The client identifier.
//
//   id = sha256( lowercase-hex(publicKey) )      // 64 hex characters
//
// Everything that NAMES a client uses this: the MQTT client id, the EMQX ACL,
// the topic strings, the friend graph, the envelope's `sender`, every route
// parameter. The 7237-byte HQC public key is kept only where the key itself is
// needed — encapsulating to it, or showing a safety number.
//
// ── Why a digest at all ──────────────────────────────────────────────────────
//
// A public key is 14474 lowercase hex characters, and using it as a name broke
// everything that has a length limit:
//
//   * `DELETE /clients/{clientid}` built a ~14.5 kB URL, and EMQX answered
//     `414 URI Too Long` to EVERY kick this deployment ever attempted. Because
//     authorization is checked at SUBSCRIBE and not per message, an unfriended
//     peer's open subscription kept delivering long after its ACL row was gone.
//   * `/prekeys/claim` capped `peer` at 128 characters and refused both real
//     clients.
//   * An `mqtt_acl` row carried a key in `pk` AND another inside `topic`:
//     ~29 kB per row, for a fact that is a membership bit.
//
// ── Why THIS digest ──────────────────────────────────────────────────────────
//
// It is the one the database already uses. `001_schema.sql` opens with an essay
// on why no public key may be a btree key, and every identity index in it is
// `pk_digest(pk)`:
//
//   CREATE FUNCTION pk_digest(t text) RETURNS bytea
//     AS $$ SELECT sha256(convert_to(t, 'UTF8')) $$;
//
// which is exactly this function. `encode(pk_digest(pk),'hex') = peerId(pk)`,
// asserted against a real Postgres in test/identity.test.ts. So this is not a
// new construction — it is the one that was already there, promoted from an
// index expression to the identifier.
//
// Hex text rather than raw key bytes: marginally more hashing, materially more
// portable (every implementation already holds the key as a hex string), and it
// is what `pk_digest` does.
//
// ── The id is a COMMITMENT ───────────────────────────────────────────────────
//
// Because `id = sha256(hex(pk))`, a key can be checked against an id already
// held: `peerId(receivedPk) === knownId` proves the key is the one that id
// names, and second-preimage resistance means no substitute survives. That is
// what lets the graph carry ids while the full key travels — at friend-add and
// in the `init` frame — and be VERIFIED on arrival rather than trusted.
//
// ⚠️ An id is derivable by anyone who holds the public key. It is a NAME, never
// an authenticator. No route may treat possession of an id as proof of anything
// (SRV-1/DB-3 was precisely that mistake).
//
// ⚠️ Not `chainId` (lib/double-ratchet.ts), which is the same construction
// truncated to 32 hex. The id is the full 64.

import * as crypto from "crypto";

/** Length of an id in hex characters. */
export const PEER_ID_LENGTH = 64;

/** Matches an id exactly — lowercase hex, 64 characters, nothing else. */
export const PEER_ID_RE = /^[0-9a-f]{64}$/;

/**
 * The identifier for a public key.
 *
 * The input is normalised to lowercase first: the digest is over the hex TEXT,
 * so `AB…` and `ab…` would otherwise name two different clients for one key.
 * The wire form is lowercase everywhere, and this is what keeps a caller that
 * forgot from silently becoming a stranger.
 */
export function peerId(publicKeyHex: string): string {
  return crypto
    .createHash("sha256")
    .update(publicKeyHex.toLowerCase(), "utf8")
    .digest("hex");
}

/** Whether `value` has the shape of an id. Says nothing about whether anyone
 *  holds the key behind it — see the warning above. */
export function isPeerId(value: unknown): value is string {
  return typeof value === "string" && PEER_ID_RE.test(value);
}

/**
 * Whether `publicKeyHex` is the key that `id` names.
 *
 * The whole point of the digest. A key arriving from the server (friend-add,
 * `GET /peer/{id}/key`) or from a peer (`init.senderPk`) is checked against the
 * id we already hold; a key that fails is REFUSED, never pinned. TOFU narrows
 * to "trust the id you were first given" and everything after it is arithmetic.
 */
export function keyMatchesId(publicKeyHex: string, id: string): boolean {
  return peerId(publicKeyHex) === id.toLowerCase();
}
