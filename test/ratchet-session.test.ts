// The v2 KEM double ratchet, end to end.
//
// Driven over a STUB KEM, not HQC: the native library is built per architecture
// and is absent on an arm64 laptop, which is why bot-crypto.test.ts skips there.
// The stub is a real (if trivial) KEM — encapsulation picks a fresh secret and
// only the matching secret key recovers it — so every property below is about
// the ratchet, and none of them can pass by accident on a degenerate KEM.
//
// It also rejects IMPLICITLY, which is the one thing that matters most here: a
// ciphertext that was not encapsulated to you yields a pseudo-random secret, not
// an error. The stub used to throw instead, and called that "the way a real
// KEM's implicit rejection would" — an inversion that handed the state machine
// the exact property the forged-step defence needs to provide for itself.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  Kem,
  SessionState,
  MessageHeader,
  startAsInitiator,
  startAsResponder,
  seal,
  open,
  shouldStep,
  MAX_SKIPPED,
  RATCHET_MAX_MESSAGES_PER_CHAIN,
  RATCHET_MIN_STEP_INTERVAL_MS,
} from "../lib/ratchet-session";
import { initRoot, rootStep, messageKey, chainNext, walkChain, chainId } from "../lib/double-ratchet";

// ── A stub KEM ───────────────────────────────────────────────────────────────
// pk is a random tag; sk is the same tag. Encapsulating produces a random secret
// and a ciphertext that carries it XOR-masked under the tag, so decapsulating
// with the WRONG sk yields a WRONG SECRET rather than an error — the same
// implicit rejection HQC has, and the property the ratchet must be safe under.
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
      // The tag lets decapsulate tell "encapsulated to me" from "not" — but,
      // like the real KEM, it does not SAY so. See `decapsulate`.
      return { ct: Buffer.concat([crypto.createHash("sha256").update(pk).digest(), body]), ss };
    },
    decapsulate(sk: Buffer, ct: Buffer) {
      // Length is the one thing HQC's wrappers do reject: `hqc.ts` throws on a
      // wrong-sized ciphertext and on nothing else.
      if (ct.length !== 64) throw new Error("bad ciphertext");
      const mask = crypto.createHash("sha256").update(sk).digest();
      if (!ct.subarray(0, 32).equals(mask)) {
        // IMPLICIT REJECTION, which is what the real KEM does and what this stub
        // used to get exactly backwards. It threw here, "the way a real KEM's
        // implicit rejection would" — but an implicitly-rejecting KEM does not
        // signal failure at all: it hands back a pseudo-random key, which is the
        // entire point of the construction (hqc.ts: "a malformed/attacker-chosen
        // ciphertext yields a pseudo-random secret … never an error").
        //
        // While it threw, this suite validated the state machine against a KEM
        // strictly stronger than the one it ships on, and granted for free the
        // property the forged-step defence depends on. That is why a critical
        // bug lived under a green test file.
        return crypto.createHash("sha256").update(Buffer.concat([sk, ct])).digest();
      }
      const ss = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) ss[i] = ct[32 + i]! ^ mask[i]!;
      return ss;
    },
  };
}

/** A peer with published prekeys, as the directory would serve them. */
function makePeer(kem: Kem, oneTimeCount = 1) {
  const identity = kem.generateKeypair();
  const medium = kem.generateKeypair();
  const oneTime = Array.from({ length: oneTimeCount }, () => kem.generateKeypair());
  return {
    identity,
    medium,
    oneTime,
    bundle(id = 0) {
      const ot = oneTime[id];
      return {
        identityPk: identity.pk,
        mediumPk: medium.pk,
        oneTimePk: ot ? ot.pk : null,
        oneTimeId: ot ? id : null,
      };
    },
    secrets() {
      return {
        identitySk: identity.sk,
        mediumSk: medium.sk,
        oneTimeSk: (id: number) => oneTime[id]?.sk ?? null,
      };
    },
  };
}

const hex = (b: Buffer) => b.toString("hex");

// ── Pure derivations ─────────────────────────────────────────────────────────

test("initRoot separates the root from the initiator's first chain", () => {
  const [a, b, c] = [crypto.randomBytes(32), crypto.randomBytes(32), crypto.randomBytes(32)];
  const r = initRoot(a, b, c);
  assert.equal(r.root.length, 32);
  assert.equal(r.chain.length, 32);
  assert.notEqual(hex(r.root), hex(r.chain), "root and chain are separate derivations");

  // Deterministic — both peers derive it from the same secrets, with no exchange.
  assert.equal(hex(initRoot(a, b, c).root), hex(r.root));

  // The one-time secret genuinely contributes: dropping it is a different root,
  // which is what makes the exhausted-pool fallback a distinct (weaker) session
  // rather than silently the same one.
  assert.notEqual(hex(initRoot(a, b).root), hex(r.root));
});

test("rootStep chains — the new root depends on the old one", () => {
  const root = crypto.randomBytes(32);
  const ss = crypto.randomBytes(32);
  const stepped = rootStep(root, ss);

  assert.notEqual(hex(stepped.root), hex(root), "the root moves");
  assert.notEqual(hex(stepped.root), hex(stepped.chain), "root and chain are separate");

  // This is the property v1 lacked: the same fresh secret against a DIFFERENT
  // previous root gives a different result, so an attacker who missed a step
  // cannot rejoin by capturing later ciphertexts alone.
  const other = rootStep(crypto.randomBytes(32), ss);
  assert.notEqual(hex(other.root), hex(stepped.root));
  assert.notEqual(hex(other.chain), hex(stepped.chain));
});

test("walkChain refuses a gap past MAX_SKIPPED without walking it", () => {
  const ck = crypto.randomBytes(32);
  assert.doesNotThrow(() => walkChain(ck, 0, MAX_SKIPPED));

  const started = process.hrtime.bigint();
  assert.throws(() => walkChain(ck, 0, 2_000_000_000), /MAX_SKIPPED/);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(ms < 100, `refusal took ${ms}ms — it walked the chain`);
});

test("chainId distinguishes chains so skipped keys cannot cross them", () => {
  const kem = stubKem();
  const a = kem.generateKeypair().pk;
  const b = kem.generateKeypair().pk;
  assert.notEqual(chainId(a), chainId(b));
  assert.equal(chainId(a), chainId(Buffer.from(a)), "stable for the same key");
});

// ── Session flow ─────────────────────────────────────────────────────────────

/** Seal a message and hand back exactly what the wire would carry. */
function send(kem: Kem, state: SessionState, text: string, now?: number) {
  const { key, header } = seal(kem, state, now);
  return { header, key: hex(key), text };
}

/** Open a frame and assert the receiver derived the same key the sender used.
 *  `_now` is accepted so call sites read symmetrically with `send`, but opening
 *  does not consult a clock — only sending does, for the step policy. */
function receive(
  kem: Kem,
  state: SessionState,
  frame: ReturnType<typeof send>,
  _now?: number
): string | null {
  // The verifier stands in for AES-GCM, and it has to be modelled rather than
  // stubbed to `true`: a tag passes exactly when the key the receiver derived is
  // the key the sender sealed with. Since `open` commits nothing until the
  // verifier returns true, a stub that always agreed would re-open every hole
  // this file is here to guard.
  const key = open(kem, state, frame.header, (k) => hex(k) === frame.key);
  return key ? hex(key) : null;
}

/** `open` with a tag that CANNOT pass — a forged or corrupt frame. */
function receiveForged(kem: Kem, state: SessionState, header: MessageHeader): Buffer | null {
  return open(kem, state, header, () => false);
}

/** `open` with a tag that WOULD pass, for cases that must be refused before the
 *  payload is ever consulted. The stronger form of those assertions: not "this
 *  frame failed to authenticate" but "this frame never got that far". */
function receiveAssumingValid(kem: Kem, state: SessionState, header: MessageHeader): Buffer | null {
  return open(kem, state, header, () => true);
}

test("the initiator's FIRST message is already ratcheted and needs no round trip", () => {
  const kem = stubKem();
  const bob = makePeer(kem);

  // Alice never talks to Bob first — she claims his published bundle and sends.
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const first = send(kem, alice, "hello");

  assert.equal(first.header.n, 0);
  assert.equal(first.header.pn, 0);
  assert.ok(alice.send, "a sending chain exists before any reply");

  // Bob comes online later and opens it from the init frame alone.
  const bobState = startAsResponder(kem, bob.secrets(), header);
  assert.ok(bobState, "the init frame stands on its own");
  assert.equal(receive(kem, bobState!, first), first.key, "the first message decrypts");
});

test("a full conversation ratchets on direction flips and both sides stay in step", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());

  const opening = send(kem, alice, "m1");
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  assert.equal(receive(kem, bobState, opening), opening.key);

  // Bob replies. This is the first real asymmetric step — he has Alice's rk now.
  assert.ok(shouldStep(bobState), "the responder steps on its first reply");
  const reply = send(kem, bobState, "m2");
  assert.ok(reply.header.rk && reply.header.kemCt, "a step advertises a key and a ciphertext");
  assert.equal(receive(kem, alice, reply), reply.key, "Alice follows the step");

  // Several turns, each flipping direction. Far enough apart in time to step.
  let clock = Date.now();
  for (let turn = 0; turn < 4; turn++) {
    clock += RATCHET_MIN_STEP_INTERVAL_MS + 1;
    const fromA = send(kem, alice, `a${turn}`, clock);
    assert.equal(receive(kem, bobState, fromA, clock), fromA.key, `turn ${turn}: B opens A`);

    clock += RATCHET_MIN_STEP_INTERVAL_MS + 1;
    const fromB = send(kem, bobState, `b${turn}`, clock);
    assert.equal(receive(kem, alice, fromB, clock), fromB.key, `turn ${turn}: A opens B`);
  }

  // The roots moved together and are still equal — the whole point of chaining.
  assert.equal(hex(alice.root), hex(bobState.root), "both sides hold the same root");
});

test("a rapid exchange does NOT step every turn — the header stays small", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const opening = send(kem, alice, "hi");
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  receive(kem, bobState, opening);

  // Bob's first reply must step (he has no sending chain yet).
  const clock = Date.now();
  const firstReply = send(kem, bobState, "r0", clock);
  assert.ok(firstReply.header.rk, "the first reply steps");
  assert.equal(receive(kem, alice, firstReply, clock), firstReply.key);

  // Immediately afterwards, still inside the interval and under the message cap,
  // further messages continue the chain instead of paying ~29 kB each.
  let steps = 0;
  for (let i = 0; i < 10; i++) {
    const f = send(kem, bobState, `r${i + 1}`, clock + 1000);
    if (f.header.rk) steps++;
    assert.equal(receive(kem, alice, f, clock + 1000), f.key, `msg ${i} opens`);
  }
  assert.equal(steps, 0, "no step inside the rate limit");

  // But the message cap eventually forces one even with the clock frozen. It
  // fires DURING a long run, not after it — `sentOnChain` resets on each step —
  // so count steps across the run rather than probing the message after it.
  const frozen = clock + 1000;
  let capSteps = 0;
  const run = RATCHET_MAX_MESSAGES_PER_CHAIN * 3;
  for (let i = 0; i < run; i++) {
    const f = send(kem, bobState, `bulk${i}`, frozen);
    if (f.header.rk) capSteps++;
    assert.equal(receive(kem, alice, f, frozen), f.key, `bulk ${i} opens`);
  }
  assert.ok(capSteps >= 2, `the per-chain cap forced ${capSteps} steps over ${run} messages`);
  assert.ok(
    capSteps <= run / RATCHET_MAX_MESSAGES_PER_CHAIN + 1,
    "…and no more often than the cap requires"
  );
});

test("out-of-order delivery resolves, including across a ratchet step", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(
    kem,
    bob.secrets(),
    header
  )!;

  // Alice sends five on her opening chain; Bob receives them shuffled.
  const batch = [0, 1, 2, 3, 4].map((i) => send(kem, alice, `m${i}`));
  for (const i of [3, 1, 4, 0, 2]) {
    assert.equal(receive(kem, bobState, batch[i]!), batch[i]!.key, `idx ${i} out of order`);
  }

  // Bob replies (a step), then Alice sends more on a NEW chain — but two frames
  // from her OLD chain were still in flight. `pn` is what lets Bob finish it.
  const clock = Date.now();
  const reply = send(kem, bobState, "stepped", clock);
  receive(kem, alice, reply, clock);

  const strandedA = send(kem, alice, "old-chain-tail", clock);
  receive(kem, bobState, strandedA, clock);

  const later = clock + RATCHET_MIN_STEP_INTERVAL_MS + 1;
  const stepped = send(kem, alice, "new-chain", later);
  assert.ok(stepped.header.rk, "Alice steps in turn");
  assert.equal(receive(kem, bobState, stepped, later), stepped.key, "the new chain opens");
});

test("a replayed frame yields no key the second time", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;

  const once = send(kem, alice, "only once");
  assert.equal(receive(kem, bobState, once), once.key, "first delivery works");
  assert.equal(receive(kem, bobState, once), null, "the replay gets nothing");
});

test("a hostile n is refused without walking the chain", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;

  const started = process.hrtime.bigint();
  assert.equal(
    receiveAssumingValid(kem, bobState, { cid: chainId(bobState.peerRkPub!), n: 2_000_000_000, pn: 0 }),
    null,
    "refused"
  );
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(ms < 100, `took ${ms}ms — it walked the chain`);

  // Malformed indices are refused too, rather than reaching arithmetic. Each
  // carries a VALID cid, so what is under test is the index check alone.
  const liveCid = chainId(bobState.peerRkPub!);
  assert.equal(receiveAssumingValid(kem, bobState, { cid: liveCid, n: -1, pn: 0 }), null);
  assert.equal(receiveAssumingValid(kem, bobState, { cid: liveCid, n: 1.5, pn: 0 }), null);
  assert.equal(receiveAssumingValid(kem, bobState, { cid: liveCid, n: 0, pn: -1 }), null);

  // And a malformed chain selector is refused before it can select anything.
  assert.equal(receiveAssumingValid(kem, bobState, { cid: "not-hex", n: 0, pn: 0 }), null);
  assert.equal(receiveAssumingValid(kem, bobState, { cid: "", n: 0, pn: 0 }), null);

  // And the session still works afterwards — a refusal is not a teardown.
  const good = send(kem, alice, "still fine");
  assert.equal(receive(kem, bobState, good), good.key);
});

test("a step ciphertext meant for someone else is refused", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  receive(kem, bobState, send(kem, alice, "open the session"));

  const rootBefore = hex(alice.root);
  const stranger = kem.generateKeypair();
  const forged = kem.encapsulate(stranger.pk); // encapsulated to a key Alice does not hold

  // Note what does NOT reject this: the decapsulation. It succeeds, and hands
  // back a pseudo-random secret, because that is what implicit rejection means.
  // The tag is the only thing that can refuse it, so the tag is what does.
  assert.equal(
    receiveForged(kem, alice, {
      cid: chainId(stranger.pk),
      rk: stranger.pk,
      kemCt: forged.ct,
      n: 0,
      pn: 0,
    }),
    null,
    "a step whose payload does not authenticate is refused"
  );
  assert.equal(hex(alice.root), rootBefore, "and the root is left untouched");
});

test("a FORGED step cannot destroy a live session", () => {
  // The regression for the critical finding. Nothing in the frame below was ever
  // encapsulated to Alice — `rk` and `kemCt` are simply random bytes of the
  // right shape — and HQC's implicit rejection means the KEM will not say so.
  // Before the AEAD gate, this one frame replaced Alice's root, adopted the
  // attacker's ratchet key and reset her receive chain, and the caller then
  // persisted the wreckage. Bob's real messages could never be read again, and
  // no re-handshake could recover it.
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  receive(kem, bobState, send(kem, alice, "open the session"));
  const fromBob = send(kem, bobState, "a real reply");
  assert.equal(receive(kem, alice, fromBob), fromBob.key, "the session is live");

  const rootBefore = hex(alice.root);
  const peerRkBefore = hex(alice.peerRkPub!);
  const recvBefore = { ...alice.recv! };

  // Anyone entitled to publish to Alice can send this — on the shared topic or
  // her inbox, naming any third party as `sender`.
  const junkRk = crypto.randomBytes(32);
  assert.equal(
    receiveForged(kem, alice, {
      cid: chainId(junkRk),
      rk: junkRk,
      kemCt: crypto.randomBytes(64),
      n: 0,
      pn: 0,
    }),
    null,
    "the forged step yields no key"
  );

  assert.equal(hex(alice.root), rootBefore, "the root did not move");
  assert.equal(hex(alice.peerRkPub!), peerRkBefore, "the attacker's key was not adopted");
  assert.deepEqual({ ...alice.recv! }, recvBefore, "the receive chain did not reset");

  // The statement that actually matters: the conversation still works.
  const next = send(kem, bobState, "and the conversation survives");
  assert.equal(receive(kem, alice, next), next.key, "Bob's next real message still decrypts");
});

test("a forged step cannot evict genuinely skipped keys", () => {
  // Finding 03. The tail-walk that retires the outgoing chain used to run BEFORE
  // the decapsulation, and `cacheSkipped` evicts once the array passes
  // MAX_SKIPPED. So a frame repeated with a growing `pn` — attacker-chosen, and
  // never authenticated — pushed out the keys for messages the real peer had
  // sent and that had not arrived yet. Those messages then never decrypted.
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  receive(kem, bobState, send(kem, alice, "open the session"));

  // Bob's first reply steps, which is what gives Alice his chain to count within.
  const opener = send(kem, bobState, "bob's first reply");
  assert.equal(receive(kem, alice, opener), opener.key, "Alice is on Bob's chain");

  // Bob sends three more; Alice receives only the third, so the first two are
  // cached as skipped keys waiting for a delivery that is still in flight.
  const inFlight = [
    send(kem, bobState, "one"),
    send(kem, bobState, "two"),
    send(kem, bobState, "three"),
  ];
  assert.equal(receive(kem, alice, inFlight[2]!), inFlight[2]!.key);
  assert.equal(alice.skipped.length, 2, "the two undelivered positions are cached");
  const cachedBefore = alice.skipped.map((s) => `${s.chain}:${s.n}:${hex(s.key)}`);

  // Hammer with forged steps carrying an ever-growing `pn`.
  for (let pn = 1; pn <= 50; pn++) {
    const junkRk = crypto.randomBytes(32);
    assert.equal(
      receiveForged(kem, alice, {
        cid: chainId(junkRk),
        rk: junkRk,
        kemCt: crypto.randomBytes(64),
        n: 0,
        pn: pn * 40,
      }),
      null
    );
  }

  assert.deepEqual(
    alice.skipped.map((s) => `${s.chain}:${s.n}:${hex(s.key)}`),
    cachedBefore,
    "no cached key was walked over, evicted, or added"
  );
  // And the stragglers still open when they finally land.
  assert.equal(receive(kem, alice, inFlight[0]!), inFlight[0]!.key);
  assert.equal(receive(kem, alice, inFlight[1]!), inFlight[1]!.key);
});

test("a cached key is not burned by a frame that fails to authenticate", () => {
  // The same mistake as the step branch, on a quieter path: `takeSkipped` used
  // to remove the entry before the caller could check the tag, so one corrupt
  // frame at a skipped position destroyed the key for the real message there.
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  receive(kem, bobState, send(kem, alice, "open the session"));

  // As above: Bob's stepping reply has to land before Alice can read a plain
  // frame of his at all.
  const opener = send(kem, bobState, "bob's first reply");
  assert.equal(receive(kem, alice, opener), opener.key);

  const straggler = send(kem, bobState, "sent first, arrives second");
  const arrivesFirst = send(kem, bobState, "sent second, arrives first");
  assert.equal(receive(kem, alice, arrivesFirst), arrivesFirst.key);
  assert.equal(alice.skipped.length, 1, "the straggler's key is cached");

  assert.equal(receiveForged(kem, alice, straggler.header), null, "a bad tag gets nothing");
  assert.equal(alice.skipped.length, 1, "and the cached key is still there");

  assert.equal(receive(kem, alice, straggler), straggler.key, "the real straggler still opens");
  assert.equal(alice.skipped.length, 0, "and consumes the entry when it does");
});

test("the one-time prekey is optional — an exhausted pool still starts a session", () => {
  const kem = stubKem();
  const bob = makePeer(kem, 0); // no one-time keys published
  const bundle = bob.bundle();
  assert.equal(bundle.oneTimePk, null, "the directory served the medium-term key only");

  const { state: alice, header } = startAsInitiator(kem, bundle);
  assert.equal(header.ctOt, null);
  const first = send(kem, alice, "fallback path");

  const bobState = startAsResponder(kem, bob.secrets(), header);
  assert.ok(bobState, "the medium-term fallback starts a session");
  assert.equal(receive(kem, bobState!, first), first.key);
});

test("an init naming a one-time key this device no longer holds is refused", () => {
  const kem = stubKem();
  const bob = makePeer(kem, 1);
  const { header } = startAsInitiator(kem, bob.bundle(0));

  // Bob consumed that key already — a duplicate or replayed init.
  const spentSecrets = { ...bob.secrets(), oneTimeSk: () => null };
  assert.equal(
    startAsResponder(kem, spentSecrets, header),
    null,
    "no root is derived from a partial secret set"
  );
});

test("two sessions with the same peer share no key material", () => {
  const kem = stubKem();
  const bob = makePeer(kem, 2);

  const one = startAsInitiator(kem, bob.bundle(0));
  const two = startAsInitiator(kem, bob.bundle(1));

  assert.notEqual(hex(one.state.root), hex(two.state.root), "distinct roots");
  assert.notEqual(hex(one.state.send!.ck), hex(two.state.send!.ck), "distinct chains");

  // Even claiming the SAME one-time key twice must not collide, because the
  // encapsulations are independently random.
  const three = startAsInitiator(kem, bob.bundle(0));
  assert.notEqual(hex(one.state.root), hex(three.state.root));
});

test("message keys are one-way — a chain key does not reveal earlier ones", () => {
  const ck0 = crypto.randomBytes(32);
  const ck1 = chainNext(ck0);
  const ck2 = chainNext(ck1);

  const keys = [messageKey(ck0), messageKey(ck1), messageKey(ck2)].map(hex);
  assert.equal(new Set(keys).size, 3, "every position yields a distinct key");

  // Holding ck2 (what a compromise finds) must not reproduce mk0 — that is
  // forward secrecy at the symmetric layer.
  assert.notEqual(hex(messageKey(ck2)), keys[0]);
  assert.notEqual(hex(chainNext(ck2)), hex(ck1));
});

test("a gap larger than MAX_SKIPPED is refused rather than bridged", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;

  // The sender runs further ahead than the receiver is willing to walk. This is
  // undeliverable BY DESIGN: bridging it would mean deriving 2000+ keys that the
  // cache would immediately evict, so the frame is refused instead.
  let frame = send(kem, alice, "x");
  // Kept as it goes past: a frame from inside the bound has to be a REAL one.
  // This used to re-label the far frame's header with a reachable `n`, which
  // worked only because `open` did not consult the payload — the tag binds the
  // header to the position the sender actually sealed at, so a doctored header
  // is a tampered frame and refusing it is the correct answer, not a regression.
  let reachable = frame;
  for (let i = 0; i < MAX_SKIPPED + 200; i++) {
    frame = send(kem, alice, "x");
    if (frame.header.n === MAX_SKIPPED - 1) reachable = frame;
  }
  assert.equal(receive(kem, bobState, frame), null, "too far ahead to reach");

  // And the session is not broken by it — a frame inside the bound still opens.
  assert.ok(receive(kem, bobState, reachable), "a reachable index still resolves");
});

test("the skipped-key cache is bounded as gaps accumulate", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;

  // Each round skips a gap that is individually legal; together they exceed the
  // cap, which is the case that actually grows the cache in practice — an
  // intermittent connection, not one enormous jump.
  const GAP = 500;
  for (let round = 0; round < 6; round++) {
    let frame = send(kem, alice, "x");
    for (let i = 0; i < GAP; i++) frame = send(kem, alice, "x");
    assert.ok(receive(kem, bobState, frame), `round ${round} far frame opens`);
  }

  assert.ok(
    bobState.skipped.length <= MAX_SKIPPED,
    `cache grew to ${bobState.skipped.length}, past MAX_SKIPPED ${MAX_SKIPPED}`
  );
  assert.ok(bobState.skipped.length > 0, "and it is actually caching, not discarding everything");
});

// ── Regression: replaying a step must not rewind the ratchet ─────────────────
// `open` processes the header BEFORE the payload authenticates it — it has to,
// because the header is what selects the key. So a byte-identical replay of a
// real stepping frame reaches the step logic with a valid ciphertext. If the
// receiver steps into a chain it has already retired, it recomputes the root
// from the CURRENT root instead of the one that step originally advanced, and
// the two sides diverge permanently.
//
// This is the same failure class as TM-1 (a forged key_rotate desynchronising a
// conversation), which the v2 design is supposed to close.
test("replaying an old ratchet step does not rewind the root or break the session", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  receive(kem, bobState, send(kem, alice, "open it"));

  // Bob steps twice, with Alice never sending in between — so Alice's ratchet
  // secret does not rotate, and BOTH of Bob's step ciphertexts stay decapsulable
  // by her. That is what makes the replay land.
  let clock = Date.now();
  const stepOne = send(kem, bobState, "s1", clock);
  assert.ok(stepOne.header.rk, "first step");
  assert.equal(receive(kem, alice, stepOne, clock), stepOne.key);

  clock += RATCHET_MIN_STEP_INTERVAL_MS + 1;
  const stepTwo = send(kem, bobState, "s2", clock);
  assert.ok(stepTwo.header.rk, "second step");
  assert.equal(receive(kem, alice, stepTwo, clock), stepTwo.key);

  const rootAfterTwoSteps = hex(alice.root);

  // Now replay the FIRST step. Its key was already consumed, so there is nothing
  // legitimate to serve — it must be refused, not re-applied.
  assert.equal(receive(kem, alice, stepOne, clock), null, "the replayed step yields no key");
  assert.equal(hex(alice.root), rootAfterTwoSteps, "and the root did not move");

  // The session must still work in both directions afterwards.
  clock += RATCHET_MIN_STEP_INTERVAL_MS + 1;
  const afterA = send(kem, alice, "still talking", clock);
  assert.equal(receive(kem, bobState, afterA, clock), afterA.key, "A→B survives the replay");

  clock += RATCHET_MIN_STEP_INTERVAL_MS + 1;
  const afterB = send(kem, bobState, "still listening", clock);
  assert.equal(receive(kem, alice, afterB, clock), afterB.key, "B→A survives the replay");
  assert.equal(hex(alice.root), hex(bobState.root), "the two roots are still equal");
});

// A frame that names a ratchet key we are not on must not be read against the
// chain we ARE on — `n` means nothing outside the chain that produced it.
test("a frame naming a retired chain is refused, not read against the current one", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  receive(kem, bobState, send(kem, alice, "open it"));

  let clock = Date.now();
  const stepOne = send(kem, bobState, "s1", clock);
  receive(kem, alice, stepOne, clock);
  clock += RATCHET_MIN_STEP_INTERVAL_MS + 1;
  const stepTwo = send(kem, bobState, "s2", clock);
  receive(kem, alice, stepTwo, clock);

  const recvBefore = alice.recv!.n;
  const cacheBefore = alice.skipped.length;

  // An attacker replays the old chain's key with a large index. Interpreting `n`
  // against the CURRENT chain would advance it and cache keys for messages that
  // will never arrive.
  assert.equal(
    receiveAssumingValid(kem, alice, {
      cid: stepOne.header.cid,
      rk: stepOne.header.rk!,
      kemCt: stepOne.header.kemCt!,
      n: 900,
      pn: 0,
    }),
    null,
    "refused"
  );
  assert.equal(alice.recv!.n, recvBefore, "the current chain did not advance");
  assert.equal(alice.skipped.length, cacheBefore, "and nothing was cached for it");
});

// ── Regression: a bare frame must be read against the chain that produced it ──
// This is what the `cid` header field is for. A non-stepping frame carries no
// ratchet key (7237 bytes is too much to repeat on every message), so without a
// chain selector the receiver has only `n` to go on — and `n` restarts at 0 on
// every chain. A straggler from the sender's PREVIOUS chain, arriving after the
// receiver has already adopted the new one, would then be read against the new
// chain: wrong key, and a live chain advanced by a frame that had no claim on it.
test("stragglers from the previous chain resolve after the receiver has moved on", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;

  // Alice sends three on her opening chain. None of them reach Bob yet.
  const a0 = send(kem, alice, "a0");
  const a1 = send(kem, alice, "a1");
  const a2 = send(kem, alice, "a2");
  assert.ok(!a0.header.rk && !a1.header.rk && !a2.header.rk, "all bare frames");
  assert.equal(a0.header.cid, a2.header.cid, "…and all on one chain");

  // Bob replies, so Alice steps on her next send.
  const clock = Date.now() + RATCHET_MIN_STEP_INTERVAL_MS + 1;
  const bobReply = send(kem, bobState, "b0", clock);
  assert.equal(receive(kem, alice, bobReply, clock), bobReply.key);

  const later = clock + RATCHET_MIN_STEP_INTERVAL_MS + 1;
  const a3 = send(kem, alice, "a3", later);
  assert.ok(a3.header.rk, "Alice stepped");
  assert.notEqual(a3.header.cid, a0.header.cid, "onto a different chain");
  assert.equal(a3.header.pn, 3, "and pn reports the old chain ran to 3");

  // Bob receives the STEPPED frame first — the reordering that matters.
  assert.equal(receive(kem, bobState, a3, later), a3.key, "the new chain opens");

  // Now the three stragglers arrive, out of order, all on the retired chain.
  // `pn` let Bob drain that chain into the cache when he stepped, so each one
  // resolves to exactly the key Alice used.
  assert.equal(receive(kem, bobState, a1), a1.key, "straggler a1 resolves");
  assert.equal(receive(kem, bobState, a0), a0.key, "straggler a0 resolves");
  assert.equal(receive(kem, bobState, a2), a2.key, "straggler a2 resolves");

  // Each only once.
  assert.equal(receive(kem, bobState, a1), null, "and cannot be replayed");

  // The live chain was untouched by any of it.
  assert.equal(bobState.recv!.n, 1, "the current chain advanced only for a3");
});

// ── The handshake rides every frame until the peer answers ───────────────────
// Mirrors apps/apple/tests/RatchetSessionTests.swift. Clearing `pendingInit` on
// SEND would lose it whenever the publish failed or the send was retried: the
// retry would go out as a plain `msg` naming a session the peer had never been
// told about — undeliverable forever, with nothing to say why.
test("pendingInit survives a restart and persists until the peer replies", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  assert.ok(alice.pendingInit, "a fresh initiator session carries its handshake");

  // A restart: only what was serialised comes back. Buffers survive JSON as
  // base64 through a reviver in the real store; here the shape is what matters.
  assert.deepEqual(alice.pendingInit, header, "the stored header is the one to send");

  const first = send(kem, alice, "one");
  assert.ok(alice.pendingInit, "still attached — a failed send must not lose it");
  const retry = send(kem, alice, "one (retried)");
  assert.ok(alice.pendingInit, "…on a retry as well");

  const bobState = startAsResponder(kem, bob.secrets(), alice.pendingInit!)!;
  assert.ok(bobState, "the peer opens a session from it");
  assert.equal(receive(kem, bobState, first), first.key, "the first message decrypts");
  assert.equal(receive(kem, bobState, retry), retry.key, "and so does the retry");

  // Once the peer answers, it stops riding along.
  const reply = send(kem, bobState, "got it");
  assert.equal(receive(kem, alice, reply), reply.key);
  assert.equal(alice.pendingInit, undefined, "hearing back clears the handshake");

  // And never comes back.
  send(kem, alice, "after");
  assert.equal(alice.pendingInit, undefined, "…permanently");
});

test("seal reports the handshake so a caller cannot forget to attach it", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice } = startAsInitiator(kem, bob.bundle());

  const first = seal(kem, alice);
  assert.ok(first.initHeader, "the initiator's frame reports a handshake to attach");

  // The responder never has one — it answers, it does not initiate.
  const bobState = startAsResponder(kem, bob.secrets(), alice.pendingInit!)!;
  receiveAssumingValid(kem, bobState, first.header);
  const reply = seal(kem, bobState);
  assert.equal(reply.initHeader, undefined, "the responder has no handshake to send");
});


test("the step policy is count-first, with time as the backstop", () => {
  const kem = stubKem();
  const bob = makePeer(kem);
  const { state: alice, header } = startAsInitiator(kem, bob.bundle());
  const bobState = startAsResponder(kem, bob.secrets(), header)!;
  const t0 = 1_000_000;

  // Alice learns Bob's ratchet key, so she can step at all.
  receive(kem, bobState, send(kem, alice, "open", t0));
  const reply = send(kem, bobState, "hello", t0);
  receive(kem, alice, reply);

  // A chain that has SENT NOTHING never pays for a step, however old it is.
  // This is the half of the documented policy that was missing from the code.
  const fresh = { ...alice, sentOnChain: 0 };
  assert.equal(
    shouldStep(fresh, t0 + RATCHET_MIN_STEP_INTERVAL_MS * 10),
    false,
    "an unused chain does not step, however long it has existed"
  );

  // Count is the primary trigger: a busy conversation steps on volume.
  const busy = { ...alice, sentOnChain: RATCHET_MAX_MESSAGES_PER_CHAIN, chainStartedAt: t0 };
  assert.ok(shouldStep(busy, t0 + 1), "a chain at the message cap steps immediately");

  // Time is the backstop, and it is now long enough that an ordinary reply a
  // few minutes later does NOT drag a ~29 kB step along with it. That was the
  // whole cost: at 60 s every message in a slow conversation carried one.
  const slow = { ...alice, sentOnChain: 1, chainStartedAt: t0 };
  assert.equal(shouldStep(slow, t0 + 5 * 60_000), false, "a reply 5 minutes later is cheap");
  assert.equal(shouldStep(slow, t0 + 10 * 60_000), false, "…and so is one at 10 minutes");
  assert.ok(shouldStep(slow, t0 + RATCHET_MIN_STEP_INTERVAL_MS), "…and the backstop still fires");
});
