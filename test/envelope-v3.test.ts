// The v3 wire format, pinned against the shared vectors.
//
// The property that matters most here is one v2 could not have: `aadHex` is a
// PREFIX of `frameHex`. In v2 the canonical header is a second construction,
// written by hand twice, sitting beside a JSON encoding produced by two
// different libraries — and keeping those in step is unpaid work forever. Here
// there is one set of bytes and the AAD is a range of it, so a receiver binds
// what it was actually sent.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import {
  canonicalHeaderV3,
  encodeV3,
  decodeV3,
  looksLikeV3,
  EnvelopeV3,
} from "../lib/envelope-v3";
import {
  decodeFrame,
  encodeFrame,
  frameHeader,
  validateFrame,
  Frame,
} from "../lib/frame";
import { peerId } from "../lib/identity";

const V = JSON.parse(
  fs.readFileSync(path.join(__dirname, "helpers", "envelope-v3-vectors.json"), "utf8")
);
const caseNames = ["msg", "stepping", "init", "initNoOneTime", "unicode"] as const;

test("the vector file is the v3 shape and covers every case", () => {
  assert.equal(V.version, 3);
  for (const name of caseNames) assert.ok(V.cases[name], `missing the "${name}" case`);
});

test("every pinned frame decodes to the fields it claims", () => {
  for (const name of caseNames) {
    const c = V.cases[name];
    const got = decodeV3(Buffer.from(c.frameHex, "hex"));
    assert.ok(got, `${name}: decodes`);
    for (const [k, want] of Object.entries(c.fields)) {
      if (k === "payloadUtf8") {
        assert.equal(got!.env.payload.toString("utf8"), want, `${name}: payload`);
      } else {
        assert.equal((got!.env as never)[k as never], want, `${name}: ${k}`);
      }
    }
  }
});

test("the AAD is a PREFIX of the frame — the point of the format", () => {
  for (const name of caseNames) {
    const c = V.cases[name];
    const frame = Buffer.from(c.frameHex, "hex");
    const aad = Buffer.from(c.aadHex, "hex");
    assert.equal(aad.length, c.aadBytes, `${name}: AAD length`);
    assert.ok(frame.subarray(0, aad.length).equals(aad), `${name}: AAD is a prefix`);
    // And the decoder hands back that exact range, rather than a rebuild.
    const got = decodeV3(frame)!;
    assert.ok(got.aad.equals(aad), `${name}: the decoder returns the pinned AAD`);
  }
});

test("encoding is byte-stable against the pinned frames", () => {
  for (const name of caseNames) {
    const c = V.cases[name];
    const got = decodeV3(Buffer.from(c.frameHex, "hex"))!;
    assert.equal(encodeV3(got.env)?.toString("hex"), c.frameHex, `${name}: re-encodes identically`);
    assert.equal(canonicalHeaderV3(got.env)?.toString("hex"), c.aadHex, `${name}: header`);
  }
});

// ── The rules the format enforces that v2 could only ask for politely ────────

function liveFrame(): EnvelopeV3 {
  return decodeV3(Buffer.from(V.cases.stepping.frameHex, "hex"))!.env;
}

test("a msg carries rk and kemCt together or not at all", () => {
  const step = liveFrame();
  assert.ok(encodeV3(step), "both present is fine");

  // Refused by the ENCODER, which is the stronger place for it: an encoder that
  // can emit a frame its own decoder rejects is not much of a contract, and the
  // two implementations used to fail that differently on every malformed input.
  const { kemCt, ...noKemCt } = step;
  assert.equal(encodeV3(noKemCt as EnvelopeV3), null, "rk without kemCt is refused");

  const { rk, ...noRk } = step;
  assert.equal(encodeV3(noRk as EnvelopeV3), null, "kemCt without rk is refused");
});

test("an init advertises rk and may NOT carry a kemCt", () => {
  // v2 could only tolerate the meaningless field, and the two implementations
  // then disagreed about whether the pairing rule applied to an init — the bot
  // omitted `kemCt`, the TypeScript parser demanded it, and every e2e
  // conversation failed with the frame dropped at parse.
  const init = decodeV3(Buffer.from(V.cases.init.frameHex, "hex"))!.env;
  assert.ok(encodeV3(init), "rk alone is what an init looks like");

  const withKemCt = { ...init, kemCt: Buffer.alloc(32, 7) };
  assert.equal(encodeV3(withKemCt), null, "a kemCt on an init is refused");

  const { rk, ...noRk } = init;
  assert.equal(encodeV3(noRk as EnvelopeV3), null, "an init without rk is refused");
});

test("the version and the recipient are inside the AAD", () => {
  const frame = Buffer.from(V.cases.msg.frameHex, "hex");
  const aadLen = V.cases.msg.aadBytes;

  // Byte 4 is the version, byte 39.. is `to`. Both fall inside the AAD, so a
  // tamper cannot be spelled without invalidating the tag. In v2 `v` rode
  // entirely outside the canonical header and there was no recipient at all.
  assert.ok(4 < aadLen, "the version byte is covered");
  assert.ok(39 + 32 <= aadLen, "the recipient is covered");

  const flipped = Buffer.from(frame);
  flipped.writeUInt8(2, 4);
  assert.equal(decodeV3(flipped), null, "a downgraded version byte is not even parsed");

  const readdressed = Buffer.from(frame);
  readdressed.writeUInt8(readdressed.readUInt8(39) ^ 0xff, 39);
  const got = decodeV3(readdressed)!;
  assert.notEqual(got.aad.toString("hex"), V.cases.msg.aadHex,
    "re-addressing a frame changes the AAD, so the tag will not verify");
});

test("hostile frames are refused rather than throwing", () => {
  const frame = Buffer.from(V.cases.init.frameHex, "hex");
  const mutate = (fn: (b: Buffer) => Buffer) => fn(Buffer.from(frame));
  const cases: [string, Buffer][] = [
    ["empty", Buffer.alloc(0)],
    ["magic only", Buffer.from("HQCE", "ascii")],
    ["truncated", frame.subarray(0, frame.length - 1)],
    ["trailing byte", Buffer.concat([frame, Buffer.from([0])])],
    ["bad magic", mutate((b) => { b.write("XXXX", 0, "ascii"); return b; })],
    ["unknown flag bit", mutate((b) => { b.writeUInt8(0x80, 6); return b; })],
    ["unknown kind", mutate((b) => { b.writeUInt8(9, 5); return b; })],
    ["msgId length 0", mutate((b) => { b.writeUInt8(0, 95); return b; })],
    ["length prefix past the buffer", mutate((b) => { b.writeUInt32BE(0x0fffffff, 96 + 16); return b; })],
  ];
  for (const [name, bytes] of cases) {
    let result: unknown;
    assert.doesNotThrow(() => { result = decodeV3(bytes); }, `${name} must not throw`);
    assert.equal(result, null, `${name} must be refused`);
  }
});

test("a senderPk that does not hash to sender is refused", () => {
  const init = decodeV3(Buffer.from(V.cases.init.frameHex, "hex"))!.env;
  const substituted = { ...init, senderPk: Buffer.alloc(init.senderPk!.length, 0xab) };
  assert.equal(encodeV3(substituted), null,
    "a substituted key produces no frame, not a wrong session — refused on the way out too");
});

// ── The seam ─────────────────────────────────────────────────────────────────

test("decodeFrame round-trips a frame and hands back the bytes it read", () => {
  const pk = crypto.createHash("sha512").update("seam").digest();
  const fields: Omit<Frame, "payload"> = {
    v: 3,
    t: "msg",
    sender: peerId(Buffer.alloc(7237, 1).toString("hex")),
    to: peerId(Buffer.alloc(7237, 2).toString("hex")),
    msgId: "01HQZX9K2M4N6P8R",
    cid: "0123456789abcdef0123456789abcdef",
    n: 4,
    pn: 1,
  };
  const aad = frameHeader(fields)!;
  assert.ok(aad, "the header builds");
  const payload = crypto.createHash("sha256").update(aad).digest();
  const got = decodeFrame(encodeFrame({ ...fields, payload })!);
  assert.ok(got, "it decodes");
  assert.equal(got!.frame.v, 3);
  assert.ok(got!.aad.equals(aad), "the AAD round-trips");
  assert.ok(got!.frame.payload.equals(payload), "the payload round-trips");
  // The recipient is IN the frame. This used to be asserted as a difference
  // between the versions — "v2 has no recipient field; v3 carries it" — and it
  // is now simply what a frame is.
  assert.equal(got!.frame.to, fields.to);
  // …and it is inside the AAD, which is the whole reason the field was worth a
  // wire-format change. A frame re-aimed at somebody else does not open.
  assert.ok(aad.includes(Buffer.from(fields.to, "hex")), "the recipient is bound");
  assert.ok(pk.length > 0);
});

test("looksLikeV3 is total and cheap", () => {
  assert.equal(looksLikeV3(Buffer.alloc(0)), false);
  assert.equal(looksLikeV3(Buffer.from("{}", "utf8")), false);
  assert.equal(looksLikeV3(Buffer.from(V.cases.msg.frameHex, "hex")), true);
});


test("the encoders refuse what they could not read back", () => {
  // Finding 02: the two v3 encoders validated nothing and disagreed on every
  // malformed input, because they fail in structurally different ways —
  // TypeScript copies into a fixed buffer (short pads with zeros, long clips),
  // Swift appends (a wrong length SHIFTS every field after it), and
  // writeUInt32BE throws where UInt32(truncatingIfNeeded:) wraps.
  //
  // Finding 03: nothing guarded the ids before sealing, and `myID` /
  // `friend.peerID` are empty in ordinary states. On v2 that produced a frame
  // the receiver rejected; on v3 a well-formed one naming client 0000…0000.
  const good = {
    t: "msg" as const,
    sender: peerId(Buffer.alloc(7237, 1).toString("hex")),
    to: peerId(Buffer.alloc(7237, 2).toString("hex")),
    msgId: "01HQZX9K2M4N6P8R",
    cid: "0123456789abcdef0123456789abcdef",
    n: 4,
    pn: 1,
  };
  const payload = Buffer.alloc(16, 3);

  {
    const v = 3 as const;
    assert.ok(frameHeader({ ...good, v }), "the good case is accepted");

    const bad: [string, Partial<Frame>][] = [
      ["empty sender", { sender: "" }],
      ["short sender", { sender: "ab".repeat(16) }],
      ["long sender", { sender: "ab".repeat(64) }],
      ["non-hex sender", { sender: "z".repeat(64) }],
      ["empty cid", { cid: "" }],
      ["empty msgId", { msgId: "" }],
      ["msgId over 128 bytes", { msgId: "é".repeat(65) }],
      ["negative n", { n: -1 }],
      // Finding 07: v2 admitted these and v3 has four bytes, so there were v2
      // frames with no v3 expression at all. The bound outlives the format that
      // made it necessary — a counter past u32 is unrepresentable now, not
      // merely refused.
      ["n past u32", { n: 2 ** 32 }],
      ["n at the old v2 ceiling", { n: Number.MAX_SAFE_INTEGER }],
      ["fractional n", { n: 1.5 }],
    ];
    for (const [name, patch] of bad) {
      const f = { ...good, v, ...patch } as Omit<Frame, "payload">;
      assert.equal(frameHeader(f), null, `v${v}: ${name} produces no header`);
      assert.equal(encodeFrame({ ...f, payload }), null, `v${v}: ${name} produces no frame`);
      assert.ok(validateFrame(f), `v${v}: ${name} says why`);
    }

    // An empty payload is refused too — the decoder has always rejected one, so
    // emitting it would be a frame we could not read back.
    assert.equal(encodeFrame({ ...good, v, payload: Buffer.alloc(0) }), null,
      `v${v}: an empty payload produces no frame`);
  }
});
test("there is no second format to fall back to", () => {
  // This was the version TALLY — the hourly reading the v2 sunset waited on,
  // because v3's recipient binding bought nothing while v2 was still accepted
  // (an attacker avoiding the binding simply sent v2). The sunset happened, so
  // the counter is gone, and what replaces it is the property the counter was
  // waiting to permit: there is nothing to discriminate.
  //
  // Every case below WAS a legal frame before this change, or the entry point to
  // one. Each is now refused outright, with no second parser behind the refusal.
  const v2ish = JSON.stringify({
    v: 2, t: "msg",
    sender: peerId(Buffer.alloc(7237, 5).toString("hex")),
    msgId: "01HQZX9K2M4N6P8R",
    cid: "0123456789abcdef0123456789abcdef",
    n: 1, pn: 0, payload: Buffer.alloc(24, 7).toString("base64"),
  });
  assert.equal(decodeFrame(Buffer.from(v2ish, "utf8")), null,
    "a well-formed v2 frame is refused, not parsed");
  assert.equal(decodeFrame(Buffer.from("{}", "utf8")), null);
  assert.equal(decodeFrame(Buffer.from("not a frame at all", "utf8")), null);
  assert.equal(decodeFrame(Buffer.alloc(0)), null);

  // And the control, so the refusals above are not vacuously always-null.
  const fields: Omit<Frame, "payload"> = {
    v: 3,
    t: "msg",
    sender: peerId(Buffer.alloc(7237, 5).toString("hex")),
    to: peerId(Buffer.alloc(7237, 6).toString("hex")),
    msgId: "01HQZX9K2M4N6P8R",
    cid: "0123456789abcdef0123456789abcdef",
    n: 1,
    pn: 0,
  };
  const payload = Buffer.alloc(24, 7);
  assert.ok(decodeFrame(encodeFrame({ ...fields, payload })!), "a v3 frame still decodes");
});
