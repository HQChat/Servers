// Regenerates test/helpers/identity-vectors.json.
//
//   npx tsx scripts/gen-identity-vectors.ts > test/helpers/identity-vectors.json
//
// Two constructions are pinned here, and both are ones where a difference of a
// single byte between implementations is invisible until it is catastrophic:
//
//   peerId(pk)          the client identifier. Disagree about it and two
//                       implementations name the same key differently — a
//                       contact that cannot be found, a topic nobody is granted.
//   friendshipHash(a,b) the conversation topic. Disagree about it and the two
//                       members subscribe to different topics and never speak.
//
// 001_schema.sql has claimed since it was written that friendshipHash "has a
// Swift counterpart and a cross-impl test vector". The counterpart existed
// (MQTTTopics.conversation); the vector did not. It does now.
//
// The vectors are read by services/server/test/identity.test.ts, by
// apps/apple/tests/PeerIDTests.swift, and — for peerId — asserted against a
// real Postgres via `encode(pk_digest(pk),'hex')`. Three implementations, one
// file.

import { peerId } from "../lib/identity";
import { friendshipHash } from "../lib/crypto-utils";
import * as crypto from "crypto";

/** HQC-256 public key size (lib/hqc.ts). */
const PUBLIC_KEY_BYTES = 7237;

/**
 * A deterministic key of the TRUE size.
 *
 * Real-size rather than a short stand-in, because the short stand-in is exactly
 * what let `pk text PRIMARY KEY` reach production: a vector that fits
 * comfortably proves nothing about the case that does not.
 */
function deterministicKey(label: string): string {
  const out: Buffer[] = [];
  let block = crypto.createHash("sha256").update(label, "utf8").digest();
  while (Buffer.concat(out).length < PUBLIC_KEY_BYTES) {
    out.push(block);
    block = crypto.createHash("sha256").update(block).digest();
  }
  return Buffer.concat(out).subarray(0, PUBLIC_KEY_BYTES).toString("hex");
}

const keys = [
  {
    label: "full-size HQC-256 public key",
    publicKeyHex: deterministicKey("hqchat/identity-vector/a"),
  },
  {
    label: "a second full-size key, so the ids are known to differ",
    publicKeyHex: deterministicKey("hqchat/identity-vector/b"),
  },
  {
    // Not key-shaped, deliberately: the id is a digest of the hex TEXT, so it
    // is defined for any hex string, and a short one is the cheapest way for a
    // reader to check an implementation by hand.
    label: "a short value — the digest is over the hex text, not over key bytes",
    publicKeyHex: "a1b2c3d4e5f6",
  },
  {
    // The normalisation rule, pinned. Uppercase hex names the SAME client:
    // without lowercasing, one careless caller becomes a stranger with an
    // unreachable topic and no ACL row, and nothing anywhere errors.
    label: "uppercase hex names the same client as its lowercase form",
    publicKeyHex: "A1B2C3D4E5F6",
  },
];

const ids = keys.map((k) => peerId(k.publicKeyHex));

const friendships = [
  // Ordinary pair, both real ids.
  { a: ids[0]!, b: ids[1]! },
  // The same pair the other way round: the hash sorts its inputs, so this must
  // come out identical. (The `pk_lo < pk_hi` CHECK in 001_schema.sql carries
  // COLLATE "C" for the same reason — JavaScript's Array.sort() compares UTF-16
  // code units, and Postgres has to agree.)
  { a: ids[1]!, b: ids[0]! },
  // Boundary ids, so an implementation that trims or pads is caught.
  { a: "0".repeat(64), b: "f".repeat(64) },
];

console.log(
  JSON.stringify(
    {
      _comment:
        "The client identifier id = sha256(lowercase-hex(publicKey)), and the " +
        "conversation-topic hash friendshipHash(idA, idB) = sha256(sorted(a,b) joined). " +
        "Asserted by services/server/test/identity.test.ts (which ALSO checks " +
        "peerId against Postgres's pk_digest) and apps/apple/tests/PeerIDTests.swift, " +
        "both of which READ this file. Regenerate with scripts/gen-identity-vectors.ts.",
      version: 1,
      publicKeyBytes: PUBLIC_KEY_BYTES,
      keys: keys.map((k) => ({ ...k, id: peerId(k.publicKeyHex) })),
      friendships: friendships.map((f) => ({
        ...f,
        hash: friendshipHash(f.a, f.b),
        topic: `c/${friendshipHash(f.a, f.b)}`,
      })),
    },
    null,
    2
  )
);
