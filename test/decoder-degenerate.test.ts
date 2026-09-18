// The empty-but-well-formed inputs, which line coverage cannot see.
//
// Mutation testing over the crypto modules scored 75.5% against ~96% line
// coverage, and the survivors were not scattered — they were one shape, repeated:
//
//     if (len === 0 || len > MAX) return null;
//                ^^^^ this half never fired
//
// Every decoder here guards a length twice, against zero and against a ceiling,
// and every test fed it something in between. So the LINE ran, the branch did
// not, and deleting `len === 0 ||` changed nothing any test could see. Stryker
// flagged exactly that mutation as surviving in handshake.ts, envelope.ts,
// envelope-v3.ts and frame.ts.
//
// It is not a theoretical gap. A zero-length ciphertext accepted by
// `decodeHandshake` becomes a KEM decapsulation against no bytes; a zero-length
// payload accepted by an envelope decoder becomes an AEAD open over nothing. The
// guards are right. Nothing was checking they stayed.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  decodeHandshake, encodeHandshake, handshakeProof,
  HANDSHAKE_NONCE_BYTES, HANDSHAKE_PROOF_BYTES, HANDSHAKE_VERSION,
} from "../lib/handshake";

const ID_A = "a".repeat(64);
const ID_B = "b".repeat(64);
const NONCE = Buffer.alloc(HANDSHAKE_NONCE_BYTES, 7);

// Offsets, from the wire format in lib/handshake.ts. Spelled out rather than
// imported because they are private there — and because a test that reads the
// layout from the implementation cannot catch the layout changing.
const OFF_BODY = 102;

/** A challenge frame with a ciphertext of exactly `len` bytes, built by hand so
 *  the length prefix can be a value `encodeHandshake` would refuse to write. */
function challengeWithCtLen(len: number, actualCt: Buffer): Buffer {
  const head = Buffer.alloc(OFF_BODY);
  Buffer.from("HQCH", "ascii").copy(head, 0);
  head.writeUInt8(HANDSHAKE_VERSION, 4);
  head.writeUInt8(0, 5);                              // KIND_CHALLENGE
  Buffer.from(ID_A, "hex").copy(head, 6);
  Buffer.from(ID_B, "hex").copy(head, 38);
  NONCE.copy(head, 70);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(len, 0);
  return Buffer.concat([head, lenBuf, actualCt]);
}

// --- the handshake --------------------------------------------------------------

test("a challenge claiming a zero-length ciphertext is refused", () => {
  // The mutant Stryker kept alive: `if (len === 0 || len > MAX)` with the first
  // half deleted. Accepting this hands the KEM a decapsulation over no bytes.
  assert.equal(decodeHandshake(challengeWithCtLen(0, Buffer.alloc(0))), null,
    "a zero-length ciphertext was accepted");
});

test("a challenge at the ciphertext ceiling is refused, and one below it is not", () => {
  // Both sides of the SAME guard, so neither half can be deleted silently. The
  // ceiling is 1 MiB; a frame claiming it plus one must not be buffered.
  const MAX = 1 << 20;
  assert.equal(decodeHandshake(challengeWithCtLen(MAX + 1, Buffer.alloc(0))), null,
    "a ciphertext over the ceiling was accepted");
  const ok = challengeWithCtLen(8, Buffer.alloc(8, 3));
  const got = decodeHandshake(ok);
  assert.ok(got, "an ordinary ciphertext must still decode");
  assert.equal(got!.ct?.length, 8);

  // EXACTLY at the ceiling, which must be accepted — `>` not `>=`. An HQC-256
  // ciphertext is 14421 bytes so nothing real is near this, but the boundary is
  // the only thing distinguishing the two operators, and the mutant that swaps
  // them survives every test that stays comfortably inside.
  const atMax = decodeHandshake(challengeWithCtLen(MAX, Buffer.alloc(MAX, 1)));
  assert.ok(atMax, "a ciphertext of exactly the ceiling was refused — the guard is off by one");
  assert.equal(atMax!.ct?.length, MAX);
});

test("a length that disagrees with the bytes that follow is refused", () => {
  // Claiming more than arrived, and claiming less — the second is the one that
  // matters, because trailing bytes are how a frame smuggles a second meaning
  // past a parser that stops at the length it was told.
  assert.equal(decodeHandshake(challengeWithCtLen(64, Buffer.alloc(8, 1))), null,
    "a claim longer than the body was accepted");
  assert.equal(decodeHandshake(challengeWithCtLen(8, Buffer.alloc(64, 1))), null,
    "trailing bytes after the ciphertext were accepted");
});

test("a challenge with no room for its length prefix is refused", () => {
  const head = challengeWithCtLen(8, Buffer.alloc(8)).subarray(0, OFF_BODY + 2);
  assert.equal(decodeHandshake(Buffer.from(head)), null, "a truncated length prefix was accepted");
});

test("encodeHandshake refuses the degenerate frames it would not be able to read back", () => {
  // The seam's own rule, and the mutants that survived on it. An empty
  // ciphertext and a wrong-width proof both produce a frame the decoder above
  // rejects, so spelling one is a bug the sender should hear about.
  assert.throws(() => encodeHandshake({ kind: "chal", from: ID_A, to: ID_B, nonce: NONCE }),
    /ciphertext/, "a challenge with no ciphertext was encoded");
  assert.throws(() => encodeHandshake({
    kind: "chal", from: ID_A, to: ID_B, nonce: NONCE, ct: Buffer.alloc(0),
  }), /ciphertext/, "a challenge with a zero-length ciphertext was encoded");

  for (const width of [0, 1, HANDSHAKE_PROOF_BYTES - 1, HANDSHAKE_PROOF_BYTES + 1]) {
    assert.throws(() => encodeHandshake({
      kind: "proof", from: ID_A, to: ID_B, nonce: NONCE, proof: Buffer.alloc(width),
    }), /32 bytes/, `a ${width}-byte proof was encoded`);
  }
  assert.throws(() => encodeHandshake({ kind: "proof", from: ID_A, to: ID_B, nonce: NONCE }),
    /32 bytes/, "a proof frame with no proof was encoded");
});

test("an id of the wrong width is refused on both sides of the frame", () => {
  // `from.length !== ID_BYTES || to.length !== ID_BYTES` — each half survived
  // separately, which means no test ever passed a bad `to` with a good `from`.
  const ct = Buffer.alloc(8, 1);
  for (const [from, to] of [
    ["", ID_B], [ID_A, ""],
    ["ab", ID_B], [ID_A, "ab"],
    [ID_A + "ab", ID_B], [ID_A, ID_B + "ab"],
  ] as Array<[string, string]>) {
    assert.throws(() => encodeHandshake({ kind: "chal", from, to, nonce: NONCE, ct }),
      /hex/, `from=${from.length} to=${to.length} was encoded`);
  }
});

test("handshakeProof refuses a bad id on either side, and a bad nonce", () => {
  const ss = Buffer.alloc(32, 5);
  assert.throws(() => handshakeProof(ss, Buffer.alloc(1), ID_A, ID_B), /nonce/);
  assert.throws(() => handshakeProof(ss, NONCE, "", ID_B), /ids/, "an empty challenger was accepted");
  assert.throws(() => handshakeProof(ss, NONCE, ID_A, ""), /ids/, "an empty prover was accepted");
  assert.throws(() => handshakeProof(ss, NONCE, "ab", ID_B), /ids/);
  assert.throws(() => handshakeProof(ss, NONCE, ID_A, "ab"), /ids/);

  // And the proof is a function of BOTH ids in that order — swapping them must
  // not produce the same value, or a challenge could be answered by replaying
  // the other direction's proof.
  const ab = handshakeProof(ss, NONCE, ID_A, ID_B);
  const ba = handshakeProof(ss, NONCE, ID_B, ID_A);
  assert.notDeepEqual(ab, ba, "the proof is symmetric in the two ids");
  assert.equal(ab.length, HANDSHAKE_PROOF_BYTES);
});

test("a round trip still works, so the refusals above are not 'always null'", () => {
  const ct = crypto.randomBytes(128);
  const chal = decodeHandshake(encodeHandshake({ kind: "chal", from: ID_A, to: ID_B, nonce: NONCE, ct }));
  assert.ok(chal, "a well-formed challenge must decode");
  assert.equal(chal!.kind, "chal");
  assert.equal(chal!.from, ID_A);
  assert.equal(chal!.to, ID_B);
  assert.deepEqual(chal!.ct, ct);

  const proof = Buffer.alloc(HANDSHAKE_PROOF_BYTES, 9);
  const p = decodeHandshake(encodeHandshake({ kind: "proof", from: ID_A, to: ID_B, nonce: NONCE, proof }));
  assert.ok(p, "a well-formed proof must decode");
  assert.deepEqual(p!.proof, proof);
});

test("a proof frame with trailing bytes is refused", () => {
  const good = encodeHandshake({
    kind: "proof", from: ID_A, to: ID_B, nonce: NONCE,
    proof: Buffer.alloc(HANDSHAKE_PROOF_BYTES, 9),
  });
  assert.equal(decodeHandshake(Buffer.concat([good, Buffer.alloc(1)])), null,
    "a proof with a trailing byte was accepted");
  assert.equal(decodeHandshake(good.subarray(0, good.length - 1)), null,
    "a truncated proof was accepted");
});

test("the magic, the version and the kind are each checked", () => {
  const good = encodeHandshake({
    kind: "chal", from: ID_A, to: ID_B, nonce: NONCE, ct: Buffer.alloc(8, 1),
  });
  const bad = (i: number, v: number) => {
    const c = Buffer.from(good); c.writeUInt8(v, i); return c;
  };
  assert.equal(decodeHandshake(bad(0, 0x00)), null, "a wrong magic was accepted");
  assert.equal(decodeHandshake(bad(4, HANDSHAKE_VERSION + 1)), null, "a future version was accepted");
  assert.equal(decodeHandshake(bad(5, 9)), null, "an unknown kind was accepted");
  // Short of the header entirely.
  for (const n of [0, 1, 4, 5, 101]) {
    assert.equal(decodeHandshake(good.subarray(0, n)), null, `${n} bytes was accepted`);
  }
});

// --- the v3 frame ---------------------------------------------------------------
//
// The same shape, in the module with the most of it. `decodeV3` guards a length
// against zero in seven places — msgId, rk, kemCt, the three init blobs, ctOt and
// the payload — and `validateV3` and `encodeV3` guard the outbound side. Stryker
// kept the `=== 0` half of every one of them alive, for the reason at the top of
// this file: each test fed a length in between.
//
// Offsets are spelled out here rather than imported from lib/envelope-v3.ts, where
// they are private. A test that reads the layout from the implementation cannot
// catch the layout changing, which is most of what a wire-format test is for.

import { decodeV3, encodeV3, validateV3, V3_VERSION } from "../lib/envelope-v3";
import { encodeFrame, validateFrame, decodeFrame } from "../lib/frame";

const V3_OFF_MSGID = 96;
const KIND_MSG = 0;
const KIND_INIT = 1;
const FLAG_RK = 0x01;
const FLAG_KEMCT = 0x02;
const FLAG_ONE_TIME = 0x04;

const CID = "c".repeat(32);
const MSGID = Buffer.from("m1", "utf8");

const u32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
};

/** A length-prefixed blob whose PREFIX may lie about what follows it — which is
 *  the whole point: `encodeV3` will not write a zero length, so the only way to
 *  hand the decoder one is to build the bytes by hand. */
const blob = (bytes: Buffer, claimed = bytes.length): Buffer =>
  Buffer.concat([u32(claimed), bytes]);

/** The id a given senderPk hashes to: sha256 over the LOWERCASE HEX of the key,
 *  as utf8 — `peerId` in lib/identity.ts, restated rather than imported so this
 *  test notices if that definition moves. An init whose sender is anything else
 *  is refused by the key commitment before any length guard is reached, which is
 *  how the first version of the init test below passed while proving nothing. */
const senderFor = (pk: Buffer): string =>
  crypto.createHash("sha256").update(pk.toString("hex"), "utf8").digest("hex");

/** The fixed 96-byte header plus the msgId, with `msgIdLen` settable
 *  independently of the bytes actually appended. */
function v3Head(
  kind: number, flags: number, msgId: Buffer,
  msgIdLen = msgId.length, sender = ID_A,
): Buffer {
  const head = Buffer.alloc(V3_OFF_MSGID);
  Buffer.from("HQCE", "ascii").copy(head, 0);
  head.writeUInt8(V3_VERSION, 4);
  head.writeUInt8(kind, 5);
  head.writeUInt8(flags, 6);
  Buffer.from(sender, "hex").copy(head, 7);
  Buffer.from(ID_B, "hex").copy(head, 39);   // to
  Buffer.from(CID, "hex").copy(head, 71);    // cid
  head.writeUInt32BE(1, 87);                 // n
  head.writeUInt32BE(0, 91);                 // pn
  head.writeUInt8(msgIdLen, 95);
  return Buffer.concat([head, msgId]);
}

/** A well-formed v3 `msg`: rk and kemCt together, a non-empty payload. */
const goodMsg = (): Buffer =>
  Buffer.concat([
    v3Head(KIND_MSG, FLAG_RK | FLAG_KEMCT, MSGID),
    blob(Buffer.alloc(8, 1)),   // rk
    blob(Buffer.alloc(8, 2)),   // kemCt
    blob(Buffer.alloc(4, 3)),   // payload
  ]);

test("the hand-built v3 frame decodes, or every refusal below proves nothing", () => {
  // The control. Without it "returns null" is satisfied by a builder that was
  // never producing a valid frame in the first place.
  const got = decodeV3(goodMsg());
  assert.ok(got, "the control frame must decode");
  assert.equal(got!.env.t, "msg");
  assert.equal(got!.env.msgId, "m1");
  assert.equal(got!.env.rk?.length, 8);
  assert.equal(got!.env.payload.length, 4);
});

test("a v3 frame claiming a zero-length msgId is refused", () => {
  // `if (msgIdLen === 0 || msgIdLen > MAX_MSGID_BYTES)`. Deleting the first half
  // admits a frame whose msgId is the empty string, which is the idempotency key
  // `store` dedupes on — every such frame would collide with every other.
  const raw = Buffer.concat([
    v3Head(KIND_MSG, FLAG_RK | FLAG_KEMCT, Buffer.alloc(0), 0),
    blob(Buffer.alloc(8, 1)),
    blob(Buffer.alloc(8, 2)),
    blob(Buffer.alloc(4, 3)),
  ]);
  assert.equal(decodeV3(raw), null);
});

test("a v3 msg with a zero-length rk or kemCt is refused", () => {
  // A ratchet key of no bytes names no chain, and a KEM ciphertext of no bytes
  // decapsulates to a pseudo-random secret HQC will not report as wrong.
  const zeroRk = Buffer.concat([
    v3Head(KIND_MSG, FLAG_RK | FLAG_KEMCT, MSGID),
    blob(Buffer.alloc(0)),
    blob(Buffer.alloc(8, 2)),
    blob(Buffer.alloc(4, 3)),
  ]);
  assert.equal(decodeV3(zeroRk), null, "rk of zero bytes");

  const zeroKemCt = Buffer.concat([
    v3Head(KIND_MSG, FLAG_RK | FLAG_KEMCT, MSGID),
    blob(Buffer.alloc(8, 1)),
    blob(Buffer.alloc(0)),
    blob(Buffer.alloc(4, 3)),
  ]);
  assert.equal(decodeV3(zeroKemCt), null, "kemCt of zero bytes");
});

/** An init whose `sender` is the id its `senderPk` actually hashes to, so the
 *  key commitment cannot be what refuses it. */
function v3Init(senderPk: Buffer, ctId: Buffer, ctMt: Buffer): Buffer {
  return Buffer.concat([
    v3Head(KIND_INIT, FLAG_RK, MSGID, MSGID.length, senderFor(senderPk)),
    blob(Buffer.alloc(8, 1)),   // rk — an init advertises one, and no kemCt
    blob(senderPk),
    blob(ctId),
    blob(ctMt),
    blob(Buffer.alloc(4, 3)),   // payload
  ]);
}

test("the hand-built v3 init decodes, or the refusals below prove nothing", () => {
  // This control is not decoration. The first version of the next test built an
  // init whose senderPk did not hash to its sender, so `keyMatchesId` refused
  // every case and all three assertions passed with the length guard deleted.
  // Injection caught it; this control is what stops it coming back.
  const got = decodeV3(v3Init(Buffer.alloc(8, 4), Buffer.alloc(8, 5), Buffer.alloc(8, 6)));
  assert.ok(got, "the control init must decode");
  assert.equal(got!.env.t, "init");
  assert.equal(got!.env.senderPk?.length, 8);
});

test("a v3 init with any of its three blobs zero-length is refused", () => {
  // senderPk, ctId, ctMt. An init is the one frame that introduces a key from a
  // peer nobody has heard from, so a degenerate one is the cheapest thing an
  // attacker can send.
  const full = [Buffer.alloc(8, 4), Buffer.alloc(8, 5), Buffer.alloc(8, 6)];
  const names = ["senderPk", "ctId", "ctMt"];
  for (let which = 0; which < 3; which++) {
    const parts = full.map((b, i) => (i === which ? Buffer.alloc(0) : b));
    // The sender id follows senderPk even when it is empty — sha256 of the empty
    // string is a perfectly good id, and the commitment holds. Only the length
    // guard is left to refuse this.
    const raw = v3Init(parts[0]!, parts[1]!, parts[2]!);
    assert.equal(decodeV3(raw), null, `${names[which]} of zero bytes`);
  }
});

test("a v3 frame with a zero-length one-time ciphertext is refused", () => {
  const raw = Buffer.concat([
    v3Head(KIND_MSG, FLAG_RK | FLAG_KEMCT | FLAG_ONE_TIME, MSGID),
    blob(Buffer.alloc(8, 1)),
    blob(Buffer.alloc(8, 2)),
    blob(Buffer.alloc(0)),                 // ctOt
    u32(7),                                // otId
    blob(Buffer.alloc(4, 3)),
  ]);
  assert.equal(decodeV3(raw), null);
});

test("a v3 frame with a zero-length payload is refused", () => {
  // An AEAD open over no bytes. The tag would still be checked, so this is not
  // a forgery — it is a frame that decrypts to nothing and stores as a message.
  const raw = Buffer.concat([
    v3Head(KIND_MSG, FLAG_RK | FLAG_KEMCT, MSGID),
    blob(Buffer.alloc(8, 1)),
    blob(Buffer.alloc(8, 2)),
    blob(Buffer.alloc(0)),
  ]);
  assert.equal(decodeV3(raw), null);
});

// --- the same guards on the way OUT ---------------------------------------------

/** A valid v3 envelope for the outbound validators, as an object. */
const outbound = () => ({
  v: 3 as const,
  t: "msg" as const,
  sender: ID_A,
  to: ID_B,
  msgId: "m1",
  cid: CID,
  n: 1,
  pn: 0,
  rk: Buffer.alloc(8, 1),
  kemCt: Buffer.alloc(8, 2),
  payload: Buffer.alloc(4, 3),
});

test("validateV3 refuses an empty msgId and a present-but-empty blob", () => {
  assert.equal(validateV3(outbound()), null, "the control envelope must validate");
  assert.match(validateV3({ ...outbound(), msgId: "" })!, /msgId/);
  assert.match(validateV3({ ...outbound(), rk: Buffer.alloc(0) })!, /present but empty/);
  assert.match(validateV3({ ...outbound(), kemCt: Buffer.alloc(0) })!, /present but empty/);
});

test("the encoders refuse to write a zero-length payload, on both versions", () => {
  // An encoder validating what it emits is what stops "my own decoder refuses my
  // own frame" reaching a broker.
  //
  // ⚠️ This assertion used to be VACUOUS on the v3 path and the file said so:
  // deleting `encodeFrame`'s own payload guard changed nothing, because
  // `encodeV3` refused the same frame a moment later. Injection proved it, and
  // the fix at the time was to add a v2 case where nothing downstream caught it.
  //
  // v2 is gone, and so is the duplicate guard — `encodeFrame` delegates, there
  // is exactly one check, and this is now the test of it. Which is the better
  // outcome than the one that was available before: the redundancy is resolved
  // by there being one implementation, not by a second test covering the second
  // copy.
  assert.ok(encodeV3(outbound()), "the control envelope must encode");
  assert.equal(encodeV3({ ...outbound(), payload: Buffer.alloc(0) }), null);

  assert.ok(encodeFrame(outbound()), "the control frame must encode");
  assert.equal(encodeFrame({ ...outbound(), payload: Buffer.alloc(0) }), null);
});

test("the frame seam refuses an empty msgId", () => {
  // This had a v2 half, which ran frame.ts's own hand-written field checks. That
  // second copy of the rules is what went with v2; `validateFrame` is now
  // `validateV3` and there is one place for a msgId bound to live.
  assert.equal(validateFrame(outbound()), null);
  assert.match(validateFrame({ ...outbound(), msgId: "" })!, /msgId/);
});

test("a well-formed frame still round-trips through the seam", () => {
  // The refusals above are only worth something if the accept path still works —
  // `return null` unconditionally would satisfy every one of them.
  const raw = encodeFrame(outbound());
  assert.ok(raw);
  const got = decodeFrame(raw!);
  assert.ok(got, "a frame this seam encoded must decode");
  assert.equal(got!.frame.v, 3);
  assert.equal(got!.frame.msgId, "m1");
  assert.deepEqual(got!.frame.payload, Buffer.alloc(4, 3));
});
