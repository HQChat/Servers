/**
 * Proof that an `init` came from the peer it names.
 *
 * ── The hole this closes ─────────────────────────────────────────────────────
 * `startAsInitiator` encapsulates three times, and every one of them is to the
 * RESPONDER's keys. The initiator's own identity secret never enters the
 * derivation, and its fresh keypair is a ratchet key tied to nothing. So an
 * `init` frame is derived entirely from public values — the responder's prekey
 * bundle is published for anyone to claim, and `senderPk` is fetchable without
 * a session at all.
 *
 * The consequence, reproduced against this code: any accepted friend of A can
 * open a session with A while claiming to be a third party B, using only B's
 * public key. A stores a message attributed to B, and A's real conversation
 * with B is dead from then on — B's genuine `init` is refused as a replay and
 * B's messages decrypt against nothing.
 *
 * The docstring on `startAsInitiator` explains the first encapsulation as
 * authenticating the peer. That is the right sentence pointed the wrong way:
 * encapsulating to the responder's identity key means only the RESPONDER can
 * decapsulate, which authenticates the responder to the initiator. Nothing in
 * the frame ever authenticated the initiator.
 *
 * ── Why a round trip, and why a KEM one ──────────────────────────────────────
 * A KEM cannot authenticate a sender in one flight. Encapsulation demonstrates
 * the RECIPIENT's secret, never the sender's, so proving the initiator holds a
 * secret means the initiator has to receive something first. X3DH gets this
 * from DH(IK_A, SPK_B), which needs the initiator's secret; PQXDH keeps those
 * DHs for exactly this reason and adds a KEM only for forward secrecy.
 *
 * This project is HQC research, so it takes the round trip rather than the
 * second primitive: the challenge is an ordinary HQC encapsulation to the
 * initiator's IDENTITY key, and the proof is HKDF over the shared secret — the
 * same construction `authProof` already uses for the MQTT handshake, with a
 * different `info` so the two can never be confused.
 *
 * ── What the proof binds ─────────────────────────────────────────────────────
 * The shared secret alone would prove only "somebody decapsulated something".
 * The `info` binds the exchange to a nonce (freshness), and to BOTH client ids
 * in a fixed order (so a proof produced for one pair cannot be presented to
 * another). Every component is fixed-width, so there are no delimiters to
 * confuse and no encoding for the two implementations to disagree about.
 *
 *     info = "hqchat/handshake/v1" ‖ nonce(32) ‖ challenger(32) ‖ prover(32)
 *     proof = HKDF-SHA256(ikm = ss, salt = "salt", info, 32)
 *
 * ── What it does NOT defend against ──────────────────────────────────────────
 * A relay. Somebody who can both see the challenge and reach the real B could
 * forward it and return B's answer. What stops that here is the transport: the
 * exchange runs on `h/{friendshipHash}`, which only the two members are granted,
 * so the attacker of the finding above — a friend of A, with no grant on that
 * topic — cannot see the challenge at all. A malicious broker still can, and is
 * outside what any of this defends: it writes the ACL.
 *
 * The prover side additionally answers only a challenge for a handshake it
 * STARTED, so this is not a standing oracle for anybody who can reach the topic.
 */

import * as crypto from "crypto";

/** Bytes of freshness in a challenge. */
export const HANDSHAKE_NONCE_BYTES = 32;
/** Bytes of proof. Same width as `authProof`, and for the same reason. */
export const HANDSHAKE_PROOF_BYTES = 32;

const INFO_PREFIX = Buffer.from("hqchat/handshake/v1", "utf8");
const SALT = Buffer.from("salt", "utf8");
const ID_BYTES = 32;

/** A fresh challenge nonce. */
export function handshakeNonce(): Buffer {
  return crypto.randomBytes(HANDSHAKE_NONCE_BYTES);
}

/**
 * The proof a prover returns for one challenge.
 *
 * `challenger` and `prover` are client ids in lowercase hex — the same 64
 * characters the wire carries — and they are bound in that order, so the two
 * roles cannot be swapped to replay a proof back at its own author.
 */
export function handshakeProof(
  ss: Buffer,
  nonce: Buffer,
  challenger: string,
  prover: string
): Buffer {
  if (nonce.length !== HANDSHAKE_NONCE_BYTES) {
    throw new Error(`handshakeProof: nonce must be ${HANDSHAKE_NONCE_BYTES} bytes`);
  }
  const challengerRaw = Buffer.from(challenger, "hex");
  const proverRaw = Buffer.from(prover, "hex");
  if (challengerRaw.length !== ID_BYTES || proverRaw.length !== ID_BYTES) {
    throw new Error("handshakeProof: ids must be 64 lowercase hex characters");
  }
  const info = Buffer.concat([INFO_PREFIX, nonce, challengerRaw, proverRaw]);
  return Buffer.from(crypto.hkdfSync("sha256", ss, SALT, info, HANDSHAKE_PROOF_BYTES));
}

/**
 * Whether a returned proof is the one this challenge called for.
 *
 * Constant-time, and length-checked first: `timingSafeEqual` throws on a length
 * mismatch rather than returning false, which would turn a malformed proof into
 * an exception on the receive path instead of a refusal.
 */
export function handshakeProofMatches(expected: Buffer, offered: Buffer): boolean {
  if (offered.length !== expected.length) return false;
  return crypto.timingSafeEqual(expected, offered);
}

// ── The wire format ──────────────────────────────────────────────────────────
//
// Two tiny frames, and deliberately NOT JSON. Nothing here is AEAD-sealed —
// these carry no plaintext and bind nothing — so there is no canonical-header
// problem to solve, but there is still a two-implementations problem, and the
// v2 envelope is the standing demonstration of what JSON costs there. Fixed
// offsets and one length prefix have nothing to disagree about.
//
//   0   magic   4 bytes  "HQCH"
//   4   version u8       1
//   5   kind    u8       0 = challenge, 1 = proof
//   6   from    32 bytes raw client id
//   38  to      32 bytes raw client id
//   70  nonce   32 bytes
//   [challenge] u32 len + HQC ciphertext, encapsulated to `to`'s identity key
//   [proof]     32 bytes

const HS_MAGIC = Buffer.from("HQCH", "ascii");
export const HANDSHAKE_VERSION = 1;
const KIND_CHALLENGE = 0;
const KIND_PROOF = 1;

const HS_OFF_VERSION = 4;
const HS_OFF_KIND = 5;
const HS_OFF_FROM = 6;
const HS_OFF_TO = 38;
const HS_OFF_NONCE = 70;
const HS_OFF_BODY = 102;

/** A hostile length prefix must not read as an allocation request. */
const HS_MAX_CT_BYTES = 1 << 20;

export type HandshakeKind = "chal" | "proof";

export interface HandshakeFrame {
  kind: HandshakeKind;
  /** Lowercase hex client ids. */
  from: string;
  to: string;
  nonce: Buffer;
  /** Challenge only: HQC ciphertext encapsulated to `to`'s identity key. */
  ct?: Buffer;
  /** Proof only. */
  proof?: Buffer;
}

export function encodeHandshake(f: HandshakeFrame): Buffer {
  const from = Buffer.from(f.from, "hex");
  const to = Buffer.from(f.to, "hex");
  if (from.length !== ID_BYTES || to.length !== ID_BYTES) {
    throw new Error("encodeHandshake: ids must be 64 lowercase hex characters");
  }
  if (f.nonce.length !== HANDSHAKE_NONCE_BYTES) {
    throw new Error("encodeHandshake: wrong nonce width");
  }
  const head = Buffer.alloc(HS_OFF_BODY);
  HS_MAGIC.copy(head, 0);
  head.writeUInt8(HANDSHAKE_VERSION, HS_OFF_VERSION);
  head.writeUInt8(f.kind === "chal" ? KIND_CHALLENGE : KIND_PROOF, HS_OFF_KIND);
  from.copy(head, HS_OFF_FROM);
  to.copy(head, HS_OFF_TO);
  f.nonce.copy(head, HS_OFF_NONCE);

  if (f.kind === "chal") {
    if (!f.ct || f.ct.length === 0) throw new Error("encodeHandshake: a challenge needs a ciphertext");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(f.ct.length, 0);
    return Buffer.concat([head, len, f.ct]);
  }
  if (!f.proof || f.proof.length !== HANDSHAKE_PROOF_BYTES) {
    throw new Error("encodeHandshake: a proof must be exactly 32 bytes");
  }
  return Buffer.concat([head, f.proof]);
}

/** Decode, or null. Never throws: this reads bytes off the network. */
export function decodeHandshake(raw: Buffer): HandshakeFrame | null {
  if (raw.length < HS_OFF_BODY) return null;
  if (!raw.subarray(0, 4).equals(HS_MAGIC)) return null;
  if (raw.readUInt8(HS_OFF_VERSION) !== HANDSHAKE_VERSION) return null;

  const kindByte = raw.readUInt8(HS_OFF_KIND);
  if (kindByte !== KIND_CHALLENGE && kindByte !== KIND_PROOF) return null;

  const from = raw.subarray(HS_OFF_FROM, HS_OFF_FROM + ID_BYTES).toString("hex");
  const to = raw.subarray(HS_OFF_TO, HS_OFF_TO + ID_BYTES).toString("hex");
  const nonce = Buffer.from(raw.subarray(HS_OFF_NONCE, HS_OFF_NONCE + HANDSHAKE_NONCE_BYTES));

  if (kindByte === KIND_CHALLENGE) {
    if (raw.length < HS_OFF_BODY + 4) return null;
    const len = raw.readUInt32BE(HS_OFF_BODY);
    if (len === 0 || len > HS_MAX_CT_BYTES) return null;
    if (raw.length !== HS_OFF_BODY + 4 + len) return null; // no trailing bytes
    return {
      kind: "chal",
      from,
      to,
      nonce,
      ct: Buffer.from(raw.subarray(HS_OFF_BODY + 4, HS_OFF_BODY + 4 + len)),
    };
  }
  if (raw.length !== HS_OFF_BODY + HANDSHAKE_PROOF_BYTES) return null;
  return {
    kind: "proof",
    from,
    to,
    nonce,
    proof: Buffer.from(raw.subarray(HS_OFF_BODY, HS_OFF_BODY + HANDSHAKE_PROOF_BYTES)),
  };
}
