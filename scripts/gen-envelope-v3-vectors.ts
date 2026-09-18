// Regenerates test/helpers/envelope-v3-vectors.json.
//
//   npx tsx scripts/gen-envelope-v3-vectors.ts > test/helpers/envelope-v3-vectors.json
//
// Same job as gen-envelope-vectors.ts, and for the same reason: the AAD is the
// one place where a single byte of difference between the Swift client and the
// TS bot means nothing decrypts, and it fails as a tag mismatch — which looks
// exactly like a wrong key.
//
// v3 makes that easier to get right, not harder: the header IS the frame prefix,
// so `aadHex` below is always a prefix of `frameHex`, and the vector asserts
// that too. There is no second construction to drift.

import { canonicalHeaderV3, encodeV3, EnvelopeV3 } from "../lib/envelope-v3";
import { peerId } from "../lib/identity";
import * as crypto from "crypto";

/** HQC-256 sizes (lib/hqc.ts). */
const PUBLIC_KEY_BYTES = 7237;
const CIPHERTEXT_BYTES = 14421;

/** Deterministic bytes of an exact length, from a label. */
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

const SENDER_PK = bytes("hqchat/v3-vector/sender", PUBLIC_KEY_BYTES);
const SENDER = peerId(SENDER_PK.toString("hex"));
const RECIPIENT_PK = bytes("hqchat/v3-vector/recipient", PUBLIC_KEY_BYTES);
const RECIPIENT = peerId(RECIPIENT_PK.toString("hex"));

const base = {
  v: 3 as const,
  t: "msg" as const,
  sender: SENDER,
  to: RECIPIENT,
  msgId: "01HQZX9K2M4N6P8R",
  cid: "0123456789abcdef0123456789abcdef",
  n: 7,
  pn: 3,
  payload: Buffer.from("ciphertext-goes-here", "utf8"),
};

const msg: EnvelopeV3 = base;

const stepping: EnvelopeV3 = {
  ...base,
  msgId: "01HQZX9K2M4N6P8S",
  n: 0,
  pn: 12,
  rk: bytes("hqchat/v3-vector/rk", PUBLIC_KEY_BYTES),
  kemCt: bytes("hqchat/v3-vector/kemCt", CIPHERTEXT_BYTES),
};

/** An init advertises `rk` and carries NO `kemCt` — v3 refuses one outright,
 *  where v2 could only tolerate a field it never read. */
const init: EnvelopeV3 = {
  ...base,
  t: "init",
  msgId: "01HQZX9K2M4N6P8T",
  n: 0,
  pn: 0,
  rk: bytes("hqchat/v3-vector/init-rk", PUBLIC_KEY_BYTES),
  senderPk: SENDER_PK,
  ctId: bytes("hqchat/v3-vector/ctId", CIPHERTEXT_BYTES),
  ctMt: bytes("hqchat/v3-vector/ctMt", CIPHERTEXT_BYTES),
  ctOt: bytes("hqchat/v3-vector/ctOt", CIPHERTEXT_BYTES),
  otId: 3,
};

/** The exhausted-pool path: no one-time prekey was available. */
const initNoOneTime: EnvelopeV3 = { ...init, msgId: "01HQZX9K2M4N6P8U" };
delete (initNoOneTime as Partial<EnvelopeV3>).ctOt;
delete (initNoOneTime as Partial<EnvelopeV3>).otId;

/** A msgId that is multi-byte but well inside the 128-BYTE bound. */
const unicode: EnvelopeV3 = { ...base, msgId: "id-café-🔒", n: 1, pn: 0 };

const cases = { msg, stepping, init, initNoOneTime, unicode };

console.log(JSON.stringify({
  _comment:
    "The v3 wire format: length-prefixed binary, with the canonical header as " +
    "the frame's own prefix. Asserted by BOTH services/server/test/envelope-v3.test.ts " +
    "and apps/apple/tests/EnvelopeV3Tests.swift, which READ this file. `frameHex` " +
    "is the complete frame; `aadHex` is the header, and it is ALWAYS a prefix of " +
    "`frameHex` — that is the property that removes v2's parallel canonical " +
    "encoding and the whole class of drift that came with it.",
  version: 3,
  cases: Object.fromEntries(
    Object.entries(cases).map(([name, env]) => {
      const frame = encodeV3(env);
      const aad = canonicalHeaderV3(env);
      // The encoder refuses anything it could not read back, so a null here is
      // a bug in this generator rather than an edge case to tolerate.
      if (!frame || !aad) throw new Error(`${name}: the encoder refused a vector case`);
      if (!frame.subarray(0, aad.length).equals(aad)) {
        throw new Error(`${name}: the AAD is not a prefix of the frame`);
      }
      return [name, {
        frameHex: frame.toString("hex"),
        frameBytes: frame.length,
        aadHex: aad.toString("hex"),
        aadBytes: aad.length,
        // The decoded fields, so a reader can see what the bytes mean without
        // parsing them by hand.
        fields: {
          t: env.t,
          sender: env.sender,
          to: env.to,
          msgId: env.msgId,
          cid: env.cid,
          n: env.n,
          pn: env.pn,
          ...(env.otId !== undefined ? { otId: env.otId } : {}),
          payloadUtf8: env.payload.toString("utf8"),
        },
      }];
    })
  ),
}, null, 2));
