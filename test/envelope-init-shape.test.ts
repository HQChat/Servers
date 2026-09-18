// TypeScript and Swift must agree on what an `init` frame looks like.
//
// ── THE ORIGINAL FINDING ────────────────────────────────────────────────────
// They did not. v2's `parseEnvelope` applied the rk/kemCt pairing rule to every
// frame, so an init with `rk` and no `kemCt` was refused — while the Swift side
// asserted the opposite in as many words:
//
//   check(decodeMutated("init", ["kemCt": nil]) != nil,
//         "an init WITHOUT kemCt is accepted — the bot omits a field an init
//          has no use for")
//
// And the bot does omit it: it builds the init branch from `initHeader` alone,
// because an init has no peer ratchet key to encapsulate against — its root
// comes from ctId/ctMt/ctOt, which makes `kemCt` meaningless on one.
//
// So a TypeScript client could not read an init that a TypeScript client had
// written. Production survived on an asymmetry (the bot writes them, Swift reads
// them), and it surfaced only when the e2e suite — TS talking to TS — ran for
// the first time and dropped every init at parse.
//
// ── WHY THE FILE OUTLIVED THE FORMAT ────────────────────────────────────────
// v2 is deleted and this tested v2's parser, so the easy move was to delete it
// with the format. That would have thrown away the rule rather than the code.
//
// v3 is STRICTER here, and the difference is worth pinning: v2 tolerated an init
// that carried a `kemCt` (the old vector file's init case had one, which is why
// the vector round-trip never caught the original bug), where `validateV3`
// refuses it outright — `an init must not carry a kemCt`. So the shape went from
// "accepted, and also accepted with a meaningless field" to "one legal shape",
// and that is a tightening nothing else asserts.
//
// The last test is the one that found the divergence in the first place, and it
// is version-independent: it compares the two TypeScript writers of an init
// against each other by reading their source.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { validateV3, EnvelopeV3 } from "../lib/envelope-v3";
import { peerId } from "../lib/identity";

/** A well-formed init, built rather than loaded: the fields a test mutates are
 *  binary in v3, and the vector file carries the frame as hex rather than as an
 *  object to spread. `senderPk` has to hash to `sender` or nothing parses — the
 *  check that makes an id a commitment rather than a label. */
function init(): Omit<EnvelopeV3, "payload"> {
  const senderPk = Buffer.alloc(7237, 0x11);
  return {
    v: 3,
    t: "init",
    sender: peerId(senderPk.toString("hex")),
    to: peerId(Buffer.alloc(7237, 0x22).toString("hex")),
    msgId: "01HQZX9K2M4N6P8T",
    cid: "0123456789abcdef0123456789abcdef",
    n: 0,
    pn: 0,
    senderPk,
    rk: Buffer.alloc(32, 0x33),
    ctId: Buffer.alloc(64, 0x44),
    ctMt: Buffer.alloc(64, 0x55),
  };
}

test("an init without kemCt is accepted, as Swift and the bot require", () => {
  assert.equal(validateV3(init()), null, "the control init must validate");
  assert.ok(init().kemCt === undefined, "the fixture is the shape under test");
});

test("…and an init WITH a kemCt is now refused, which v2 allowed", () => {
  // The tightening. v2 accepted this and the old vector file's init case had
  // one, so nothing in the suite ever saw the field being meaningless — it just
  // rode along. One legal shape is easier to agree on across two languages than
  // one legal shape plus a tolerated one.
  const why = validateV3({ ...init(), kemCt: Buffer.alloc(32, 0x66) });
  assert.match(why ?? "", /kemCt/, "an init carrying a kemCt must say why it is refused");
});

test("an init still has to advertise its chain", () => {
  // The pairing rule being relaxed for inits must not relax this: without `rk`
  // the responder has no key to encapsulate back to.
  const { rk: _rk, ...noRk } = init();
  assert.match(validateV3(noRk as Omit<EnvelopeV3, "payload">)!, /rk/,
    "an init must advertise the initiator's chain");
});

test("an init must carry the key its sender id names", () => {
  // Not a shape rule but the one next to it, and the reason `senderPk` is on an
  // init at all: the responder may never have fetched this key, so it arrives
  // with the frame and is checked against the id rather than trusted.
  const { senderPk: _pk, ...noKey } = init();
  assert.match(validateV3(noKey as Omit<EnvelopeV3, "payload">)!, /senderPk/);
  assert.match(validateV3({ ...init(), senderPk: Buffer.alloc(7237, 0x99) })!, /hash/,
    "a senderPk that does not hash to sender is refused, not pinned");
});

test("a msg frame still needs both halves of a step", () => {
  // The pairing rule is right for `msg`; it was only ever wrong for `init`.
  const msg: Omit<EnvelopeV3, "payload"> = {
    v: 3, t: "msg",
    sender: peerId(Buffer.alloc(7237, 0x11).toString("hex")),
    to: peerId(Buffer.alloc(7237, 0x22).toString("hex")),
    msgId: "01HQZX9K2M4N6P8R",
    cid: "0123456789abcdef0123456789abcdef",
    n: 1, pn: 0,
    rk: Buffer.alloc(32, 0x33),
    kemCt: Buffer.alloc(64, 0x44),
  };
  assert.equal(validateV3(msg), null, "the control msg must validate");
  const { kemCt: _c, ...noKemCt } = msg;
  const { rk: _r, ...noRk } = msg;
  assert.ok(validateV3(noKemCt as Omit<EnvelopeV3, "payload">), "rk without kemCt");
  assert.ok(validateV3(noRk as Omit<EnvelopeV3, "payload">), "kemCt without rk");
});

test("the bot and the e2e harness build the same init field set", () => {
  // The divergence was invisible because two files build this object and nothing
  // compared them. They are the only two TypeScript writers of an init, and this
  // check does not care which wire format they write.
  const fields = (src: string): string[] => {
    const from = src.indexOf("senderPk:");
    assert.ok(from > 0, "could not find an init branch");
    const branch = src.slice(from, from + 1200);
    return ["senderPk", "rk", "ctId", "ctMt", "ctOt", "otId", "kemCt"]
      .filter((f) => new RegExp(`\\b${f}\\b`).test(branch));
  };
  const bot = fields(readFileSync(join(__dirname, "..", "bot", "bot.ts"), "utf8"));
  const harness = fields(readFileSync(join(__dirname, "helpers", "mqtt-client.ts"), "utf8"));
  assert.deepEqual(harness, bot,
    "the e2e harness must build the init the bot builds, or it is testing a shape " +
    "nothing in production sends");
});
