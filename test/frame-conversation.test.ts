// A whole conversation, through the real ratchet.
//
// Everything else about the frame is tested a layer at a time: the format
// against pinned vectors, the seam round-tripping, the two implementations
// against each other. None of that says a conversation WORKS. This does.
//
// It used to run the identical script over BOTH wire versions, and that was the
// claim the rollout depended on — acceptance was unconditional and the version
// was a spelling, so nothing above the seam behaved differently. The rollout is
// finished and there is one spelling, so the loop is gone. What it proved on the
// way is why anything above `lib/frame.ts` needed no change at all when v2 was
// deleted.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  Kem,
  SessionState,
  startAsInitiator,
  startAsResponder,
  seal,
  open,
} from "../lib/ratchet-session";
import { Frame, frameHeader, encodeFrame, decodeFrame } from "../lib/frame";
import { peerId } from "../lib/identity";

/** The stub KEM from ratchet-session.test.ts: implicit rejection and all. */
function stubKem(): Kem {
  return {
    generateKeypair() {
      const tag = crypto.randomBytes(32);
      return { pk: tag, sk: tag };
    },
    encapsulate(pk: Buffer) {
      const ss = crypto.randomBytes(32);
      const mask = crypto.createHash("sha256").update(pk).digest();
      const body = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) body[i] = ss[i]! ^ mask[i]!;
      return { ct: Buffer.concat([mask, body]), ss };
    },
    decapsulate(sk: Buffer, ct: Buffer) {
      if (ct.length !== 64) throw new Error("bad ciphertext");
      const mask = crypto.createHash("sha256").update(sk).digest();
      if (!ct.subarray(0, 32).equals(mask)) {
        return crypto.createHash("sha256").update(Buffer.concat([sk, ct])).digest();
      }
      const ss = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) ss[i] = ct[32 + i]! ^ mask[i]!;
      return ss;
    },
  };
}

function makePeer(kem: Kem) {
  const identity = kem.generateKeypair();
  const medium = kem.generateKeypair();
  const oneTime = kem.generateKeypair();
  return {
    identity,
    bundle: () => ({
      identityPk: identity.pk,
      mediumPk: medium.pk,
      oneTimePk: oneTime.pk,
      oneTimeId: 0,
    }),
    secrets: () => ({
      identitySk: identity.sk,
      mediumSk: medium.sk,
      oneTimeSk: (id: number) => (id === 0 ? oneTime.sk : null),
    }),
  };
}

/** AES-GCM over raw bytes, the way both clients do it. */
function sealPayload(text: string, key: Buffer, aad: Buffer): Buffer {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(text, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}
function openPayload(data: Buffer, key: Buffer, aad: Buffer): string {
  const d = crypto.createDecipheriv("aes-256-gcm", key, data.subarray(0, 12), {
    authTagLength: 16,
  });
  d.setAAD(aad);
  d.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([d.update(data.subarray(28)), d.final()]).toString("utf8");
}

{
  test("a conversation runs end to end", () => {
    const kem = stubKem();
    const bobPeer = makePeer(kem);
    // Real-shaped ids, and Alice's id is derived from the key she puts on the
    // init — both parsers refuse a frame whose `senderPk` does not hash to its
    // `sender`, which is the check that makes the id a commitment rather than a
    // label. Getting this wrong in the test is how it first failed — and it
    // failed identically on both wire versions back when there were two, which
    // was itself a small proof the seam was honest.
    const alicePk = crypto.randomBytes(7237);
    const aliceId = peerId(alicePk.toString("hex"));
    const bobId = peerId(crypto.randomBytes(7237).toString("hex"));

    /** Everything a sender does for one message. */
    function send(
      state: SessionState,
      from: string,
      to: string,
      text: string,
      senderPk?: Buffer
    ): Buffer {
      const sealed = seal(kem, state);
      const isInit = sealed.initHeader !== undefined;
      const fields: Omit<Frame, "payload"> = {
        v: 3,
        t: isInit ? "init" : "msg",
        sender: from,
        to,
        msgId: crypto.randomUUID(),
        cid: sealed.header.cid,
        n: sealed.header.n,
        pn: sealed.header.pn,
        ...(isInit
          ? {
            rk: sealed.initHeader!.rk,
            ctId: sealed.initHeader!.ctId,
            ctMt: sealed.initHeader!.ctMt,
            ...(senderPk ? { senderPk } : {}),
            ...(sealed.initHeader!.ctOt
              ? { ctOt: sealed.initHeader!.ctOt, otId: sealed.initHeader!.otId ?? 0 }
              : {}),
          }
          : {
            ...(sealed.header.rk ? { rk: sealed.header.rk } : {}),
            ...(sealed.header.kemCt ? { kemCt: sealed.header.kemCt } : {}),
          }),
      };
      // Non-null by construction here — the ids come from `peerId` and the
      // counters from the ratchet. A null would mean this test built something
      // the protocol cannot express, which is worth failing on rather than
      // papering over.
      const aad = frameHeader(fields)!;
      assert.ok(aad, "the header builds");
      return encodeFrame({ ...fields, payload: sealPayload(text, sealed.key, aad) })!;
    }

    /** Everything a receiver does. Null for any refusal, as the router treats it. */
    function receive(state: SessionState, bytes: Buffer): string | null {
      const got = decodeFrame(bytes);
      if (!got) return null;
      const { frame, aad } = got;
      let text: string | undefined;
      const key = open(
        kem,
        state,
        {
          cid: frame.cid,
          n: frame.n,
          pn: frame.pn,
          ...(frame.rk ? { rk: frame.rk } : {}),
          ...(frame.kemCt ? { kemCt: frame.kemCt } : {}),
        },
        (mk) => {
          try {
            text = openPayload(frame.payload, mk, aad);
            return true;
          } catch {
            return false;
          }
        }
      );
      return key === null ? null : text ?? null;
    }

    // 1. Alice opens the session and speaks first — no round trip.
    const { state: alice, header: initHeader } = startAsInitiator(kem, bobPeer.bundle());
    const first = send(alice, aliceId, bobId, "hello from the init", alicePk);

    // Bob derives the session from the frame alone.
    const bob = startAsResponder(kem, bobPeer.secrets(), initHeader)!;
    assert.equal(receive(bob, first), "hello from the init", "the init carries a real message");

    // 2. Bob replies, which is the first real ratchet step.
    const reply = send(bob, bobId, aliceId, "hello back");
    assert.equal(receive(alice, reply), "hello back", "Alice follows the step");

    // 3. Back and forth, across several steps.
    for (let i = 0; i < 12; i++) {
      const a = send(alice, aliceId, bobId, `a${i}`);
      assert.equal(receive(bob, a), `a${i}`, `A→B message ${i}`);
      const b = send(bob, bobId, aliceId, `b${i}`);
      assert.equal(receive(alice, b), `b${i}`, `B→A message ${i}`);
    }

    // 4. Out of order: three sent, the last delivered first, then the stragglers.
    const s0 = send(bob, bobId, aliceId, "straggler 0");
    const s1 = send(bob, bobId, aliceId, "straggler 1");
    const s2 = send(bob, bobId, aliceId, "straggler 2");
    assert.equal(receive(alice, s2), "straggler 2", "the newest arrives first");
    assert.equal(receive(alice, s0), "straggler 0", "…and the stragglers still open");
    assert.equal(receive(alice, s1), "straggler 1");

    // 5. A replay gets nothing, and does not disturb the session.
    assert.equal(receive(alice, s1), null, "a replay is refused");
    const after = send(bob, bobId, aliceId, "still working");
    assert.equal(receive(alice, after), "still working", "…and the session survives it");

    // 6. A tampered frame authenticates against nothing — and, because `open`
    //    commits nothing until the tag verifies, leaves the session intact.
    const good = send(bob, bobId, aliceId, "untouched");
    const tampered = Buffer.from(good);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0xff;
    assert.equal(receive(alice, tampered), null, "a flipped payload byte is refused");
    assert.equal(receive(alice, good), "untouched", "…and the real frame still opens");
  });
}

test("a frame names its recipient, and the name is bound", () => {
  // This was "a v3 frame names its recipient and a v2 frame cannot" — the one
  // behavioural difference the seam exposed upward, and the stated reason the
  // topic check had to stay for as long as v2 did.
  //
  // There is no v2 half to compare against any more, so the assertion moves to
  // the property that made the field worth a wire-format change: `to` is inside
  // the AAD. A frame republished on somebody else's topic does not merely fail a
  // topic check that a receiver might forget to make — it fails to open.
  //
  // ⚠️ The topic check in `ConversationRouter` and `bot.ts` STAYS regardless.
  // It is defence in depth now rather than load-bearing, it is cheap, and it is
  // what caught a real bug.
  const fields: Omit<Frame, "payload"> = {
    v: 3,
    t: "msg",
    sender: peerId(Buffer.alloc(7237, 1).toString("hex")),
    to: peerId(Buffer.alloc(7237, 2).toString("hex")),
    msgId: "01HQZX9K2M4N6P8R",
    cid: "0123456789abcdef0123456789abcdef",
    n: 0,
    pn: 0,
  };
  const payload = Buffer.alloc(40, 9);

  const got = decodeFrame(encodeFrame({ ...fields, payload })!)!;
  assert.equal(got.frame.to, fields.to, "the frame carries the recipient");
  assert.ok(got.aad.includes(Buffer.from(fields.to, "hex")),
    "…and the recipient is inside the AAD, or the field is decoration");

  // Re-addressing it produces a different AAD, so the payload sealed under the
  // first one cannot open under the second. Asserted rather than argued.
  const elsewhere = peerId(Buffer.alloc(7237, 3).toString("hex"));
  const reaimed = decodeFrame(encodeFrame({ ...fields, to: elsewhere, payload })!)!;
  assert.ok(!reaimed.aad.equals(got.aad),
    "changing the recipient must change what a receiver binds");
});
