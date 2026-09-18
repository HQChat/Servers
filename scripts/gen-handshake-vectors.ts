// Regenerates test/helpers/handshake-vectors.json.
//
//   npx tsx scripts/gen-handshake-vectors.ts > test/helpers/handshake-vectors.json
//
// The proof is the one value in this exchange that both implementations must
// compute identically from the same inputs. If they disagree by a byte, every
// handshake fails and every first contact stops working — with a log line on
// each side saying the other could not prove possession, which is the most
// misleading failure this protocol could produce.
//
// So the derivation is pinned here, from a FIXED shared secret rather than a
// real decapsulation: what is under test is the HKDF and the binding, not HQC.

import {
  handshakeProof,
  encodeHandshake,
  HANDSHAKE_NONCE_BYTES,
  HANDSHAKE_PROOF_BYTES,
  HANDSHAKE_VERSION,
} from "../lib/handshake";
import { peerId } from "../lib/identity";
import * as crypto from "crypto";

function bytes(label: string, length: number): Buffer {
  const out: Buffer[] = [];
  let block = crypto.createHash("sha256").update(label, "utf8").digest();
  let total = 0;
  while (total < length) {
    out.push(block);
    total += block.length;
    block = crypto.createHash("sha256").update(block).digest();
  }
  return Buffer.concat(out).subarray(0, length);
}

const CHALLENGER = peerId(bytes("hqchat/handshake-vector/challenger", 7237).toString("hex"));
const PROVER = peerId(bytes("hqchat/handshake-vector/prover", 7237).toString("hex"));
const NONCE = bytes("hqchat/handshake-vector/nonce", HANDSHAKE_NONCE_BYTES);
const SS = bytes("hqchat/handshake-vector/ss", 32);
const CT = bytes("hqchat/handshake-vector/ct", 14421);

/** The same secret bound to a different pair, to pin that the ids are in. */
const SWAPPED = handshakeProof(SS, NONCE, PROVER, CHALLENGER);

console.log(JSON.stringify({
  _comment:
    "The client-to-client handshake proof, asserted by BOTH " +
    "services/server/test/handshake.test.ts and apps/apple/tests/HandshakeTests.swift, " +
    "which READ this file. `proof` is HKDF-SHA256(ikm=ss, salt='salt', " +
    "info='hqchat/handshake/v1'||nonce||challenger||prover, 32) — every component " +
    "fixed-width, so there are no delimiters for the two sides to disagree about. " +
    "`proofSwapped` pins that the two ids are bound IN ORDER: a proof cannot be " +
    "reflected back at its own author.",
  version: HANDSHAKE_VERSION,
  input: {
    challenger: CHALLENGER,
    prover: PROVER,
    nonceHex: NONCE.toString("hex"),
    ssHex: SS.toString("hex"),
  },
  proofHex: handshakeProof(SS, NONCE, CHALLENGER, PROVER).toString("hex"),
  proofBytes: HANDSHAKE_PROOF_BYTES,
  proofSwappedHex: SWAPPED.toString("hex"),
  frames: {
    challenge: {
      ctHex: CT.toString("hex"),
      frameHex: encodeHandshake({
        kind: "chal", from: CHALLENGER, to: PROVER, nonce: NONCE, ct: CT,
      }).toString("hex"),
    },
    proof: {
      frameHex: encodeHandshake({
        kind: "proof", from: PROVER, to: CHALLENGER, nonce: NONCE,
        proof: handshakeProof(SS, NONCE, CHALLENGER, PROVER),
      }).toString("hex"),
    },
  },
}, null, 2));
