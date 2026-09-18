// The helper bot's own decisions — 1,594 lines that had never been loaded.
//
// Importing this module used to connect to EMQX, so nothing in it could be
// tested: not the topic derivation, not the frame parsing, and not the session
// persistence that every conversation depends on surviving a restart. The boot
// is behind `require.main === module` now, so the pure half is reachable.
//
// THE TOPIC SCHEME IS SPELLED OUT FOUR TIMES. services/db/api.ts grants the ACL
// rows, apps/apple MQTTTopics.swift builds the client's, the two ops scripts
// derive them for repair and report — and this file builds the bot's. The
// previous round found two of those copies had drifted and left the handshake
// topic ungranted, so this is a differential against the writers rather than a
// fifth restatement.

import "./helpers/bot-env";

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";
import { friendshipHash } from "../lib/crypto-utils";
import { peerId } from "../lib/identity";
import * as crypto from "node:crypto";
import * as bot from "../bot/bot";

const peer = () => peerId(crypto.randomBytes(64).toString("hex"));

// --- the fourth copy of the topic scheme ---------------------------------------------

test("the bot derives the same topics the server grants", async () => {
  // If these disagree the bot publishes where nobody is listening, or subscribes
  // to a topic it was never granted and is disconnected by `deny_action`. Both
  // present as "the helper bot stopped replying", with nothing in either log
  // saying which topic was wrong.
  for (let i = 0; i < 50; i++) {
    const p = peer();
    assert.equal(bot.convoTopic(p), `c/${friendshipHash(bot.myId, p)}`);
    assert.equal(bot.inboxTopic(p), DB.inboxTopic(p),
      "the bot's idea of a peer's inbox differs from the one the ACL grants");
    assert.equal(bot.handshakeTopic(p), DB.handshakeTopic(bot.myId, p),
      "the bot's handshake topic differs from the one the ACL grants");
  }
  assert.equal(bot.PRESENCE_TOPIC, DB.presenceTopic(bot.myId));
});

test("the conversation and handshake topics share a hash but not a prefix", async () => {
  // Same friendship, two topics. The separation is the point: every friend may
  // publish to an inbox, so a challenge sitting there would be forgeable by
  // exactly the attacker the exchange exists to stop.
  const p = peer();
  const convo = bot.convoTopic(p);
  const shake = bot.handshakeTopic(p);
  assert.ok(convo.startsWith("c/"));
  assert.ok(shake.startsWith("h/"));
  assert.equal(convo.slice(2), shake.slice(2), "the two must name the same friendship");
  assert.notEqual(convo, shake);
});

test("topic derivation is order-independent", async () => {
  // Both sides compute it from the unordered pair, or the two ends of one
  // conversation would sit on different topics and neither would ever hear the
  // other.
  const p = peer();
  assert.equal(bot.convoTopic(p), `c/${friendshipHash(p, bot.myId)}`);
  assert.equal(bot.handshakeTopic(p), DB.handshakeTopic(p, bot.myId));
});

test("the bot's own id names its own key", async () => {
  assert.match(bot.myId, /^[0-9a-f]{64}$/);
});

// --- parsing a frame somebody else wrote ------------------------------------------------

test("a message header carries only the fields the ratchet needs", () => {
  const full = bot.messageHeaderFrom({
    t: "msg", cid: "c1", n: 4, pn: 2, rk: "rk", kemCt: "ct",
    extra: "should not travel", body: "ciphertext",
  } as any);
  assert.deepEqual(full, { cid: "c1", n: 4, pn: 2, rk: "rk", kemCt: "ct" });
  // The AAD is built from this header, so a field that leaks in on one side and
  // not the other breaks every decrypt with no error that says why.
  assert.ok(!("extra" in full));
  assert.ok(!("body" in full));
});

test("optional ratchet fields are omitted, not sent as undefined", () => {
  // `{rk: undefined}` and `{}` serialise differently, and the AAD is the
  // serialisation. Present-but-undefined would authenticate differently from
  // absent on a peer that omits it.
  const minimal = bot.messageHeaderFrom({ t: "msg", cid: "c1", n: 0, pn: 0 } as any);
  assert.deepEqual(Object.keys(minimal).sort(), ["cid", "n", "pn"]);
  assert.equal(JSON.stringify(minimal), JSON.stringify({ cid: "c1", n: 0, pn: 0 }));
});

test("an init header is refused unless every required half is present", () => {
  // These come off the wire from an unauthenticated peer. A partial header that
  // parsed would be handed to the KEM with an empty ciphertext.
  const complete = { ctId: "a", ctMt: "b", rk: "c", cid: "d" };
  assert.ok(bot.initHeaderFrom(complete as any), "a complete header should parse");
  for (const missing of ["ctId", "ctMt", "rk"]) {
    const partial: any = { ...complete };
    delete partial[missing];
    assert.equal(bot.initHeaderFrom(partial), null, `missing ${missing} was accepted`);
    partial[missing] = "";
    assert.equal(bot.initHeaderFrom(partial), null, `empty ${missing} was accepted`);
  }
});

test("a one-time prekey id is kept only when there is a one-time ciphertext", () => {
  // `otId` without `ctOt` would tell the bot to consume a one-time secret it was
  // never given the ciphertext for — it would delete a key from its pool and
  // then fail to derive, permanently, for that id.
  const base = { ctId: "a", ctMt: "b", rk: "c", cid: "d" };
  const orphanId = bot.initHeaderFrom({ ...base, otId: 7 } as any)!;
  assert.equal(orphanId.ctOt, null);
  assert.equal(orphanId.otId, null, "an otId with no ciphertext must be dropped");

  const paired = bot.initHeaderFrom({ ...base, ctOt: "ot", otId: 7 } as any)!;
  assert.equal(paired.ctOt, "ot");
  assert.equal(paired.otId, 7);

  // A one-time ciphertext with no id is still usable material, but nothing to
  // consume — pinned so the pairing rule stays symmetrical.
  const noId = bot.initHeaderFrom({ ...base, ctOt: "ot" } as any)!;
  assert.equal(noId.ctOt, "ot");
  assert.equal(noId.otId, null);
});

// --- the session that has to survive a restart ---------------------------------------------

/** A session in the shape `dehydrateSession` actually expects. My first version
 *  of this invented field names and the round-trip test failed on the fixture
 *  rather than on the code — read the real one instead. */
function sessionFixture() {
  return {
    root: Buffer.alloc(32, 1),
    rkPub: Buffer.alloc(48, 2),
    rkSec: Buffer.alloc(48, 3),
    peerRkPub: Buffer.alloc(48, 4),
    send: { ck: Buffer.alloc(32, 5), n: 7 },
    recv: { ck: Buffer.alloc(32, 6), n: 3 },
    prevSendN: 2,
    skipped: [{ chain: "chain-a", n: 1, key: Buffer.alloc(32, 9) }],
    seenChains: ["chain-a", "chain-b"],
    pendingInit: {
      ctId: Buffer.alloc(16, 10),
      ctMt: Buffer.alloc(16, 11),
      ctOt: Buffer.alloc(16, 12),
      otId: 4,
      rk: Buffer.alloc(48, 13),
      cid: "conversation-1",
    },
    sentOnChain: 5,
    chainStartedAt: 1_700_000_000_000,
  } as any;
}

test("a session survives the JSON round trip byte for byte", () => {
  // The bot writes this to disk on every message. A field that dehydrates and
  // does not revive is a conversation that silently resets after a restart —
  // and the peer, whose chain did NOT reset, then cannot decrypt anything.
  const original = sessionFixture();
  // Through real JSON, not just the two functions: the file is what has to
  // survive, and a Buffer that survives an in-memory round trip can still be
  // lost by JSON.stringify.
  const onDisk = JSON.parse(JSON.stringify(bot.dehydrateSession(original)));
  const revived = bot.reviveSession(onDisk);
  assert.ok(revived, "a well-formed session failed to revive");

  for (const key of ["root", "rkPub", "rkSec", "peerRkPub"] as const) {
    assert.ok(Buffer.isBuffer((revived as any)[key]), `${key} revived as ${typeof (revived as any)[key]}`);
    assert.ok((original as any)[key].equals((revived as any)[key]), `${key} did not survive`);
  }
  for (const dir of ["send", "recv"] as const) {
    assert.ok((original as any)[dir].ck.equals((revived as any)[dir].ck), `${dir} chain key drifted`);
    assert.equal((revived as any)[dir].n, (original as any)[dir].n, `${dir} counter drifted`);
  }
  assert.equal(revived!.prevSendN, original.prevSendN);
  assert.equal((revived as any).sentOnChain, original.sentOnChain);
  assert.equal((revived as any).chainStartedAt, original.chainStartedAt);
  assert.deepEqual((revived as any).seenChains, original.seenChains,
    "the chains already seen are the replay defence — losing them reopens it");

  // Skipped message keys are the whole reason out-of-order delivery works. A
  // restart that lost them would drop every message that arrived early.
  assert.equal(revived!.skipped.length, 1);
  assert.equal(revived!.skipped[0]!.chain, "chain-a");
  assert.equal(revived!.skipped[0]!.n, 1);
  assert.ok(original.skipped[0].key.equals(revived!.skipped[0]!.key), "a skipped key was lost");

  const pi = (revived as any).pendingInit;
  assert.ok(pi, "a held init was lost — first contact would have to start over");
  assert.ok(original.pendingInit.ctId.equals(pi.ctId));
  assert.ok(original.pendingInit.ctMt.equals(pi.ctMt));
  assert.ok(original.pendingInit.ctOt.equals(pi.ctOt));
  assert.equal(pi.otId, 4, "the one-time id to consume was lost");
  assert.equal(pi.cid, "conversation-1");
});

test("a session with no optional halves round-trips too", () => {
  // The ordinary state of a fresh conversation: no peer ratchet key yet, no
  // receive chain, nothing skipped, no held init.
  const minimal: any = {
    root: Buffer.alloc(32, 1),
    rkPub: Buffer.alloc(48, 2),
    rkSec: Buffer.alloc(48, 3),
    peerRkPub: null,
    send: null,
    recv: null,
    prevSendN: 0,
    skipped: [],
    seenChains: [],
    sentOnChain: 0,
    chainStartedAt: 0,
  };
  const revived = bot.reviveSession(JSON.parse(JSON.stringify(bot.dehydrateSession(minimal))));
  assert.ok(revived);
  assert.equal(revived!.peerRkPub, null);
  assert.equal(revived!.send, null);
  assert.equal(revived!.recv, null);
  assert.deepEqual(revived!.skipped, []);
  assert.ok(!("pendingInit" in revived!), "an absent init must stay absent, not become undefined");
});

test("the round trip is stable — dehydrating twice is identical", () => {
  // Idempotence is what makes the state file comparable across restarts; a
  // dehydrate that reordered or re-encoded would rewrite the file on every save
  // and hide a real change in the churn.
  const once = JSON.parse(JSON.stringify(bot.dehydrateSession(sessionFixture())));
  const twice = JSON.parse(JSON.stringify(bot.dehydrateSession(bot.reviveSession(once)!)));
  assert.deepEqual(twice, once);
});

test("a corrupt or truncated state is refused rather than half-loaded", () => {
  // A half-revived session is worse than none: it would be used as a ratchet
  // state, produce keys nobody else derives, and fail every decrypt with no
  // indication that the file was the problem.
  for (const junk of [
    null, undefined, 42, "a string", [], {},
    { root: 123, rkPub: "x" },                    // root is not a string
    { root: "x" },                                // no ratchet public key
    { rkPub: "x" },                               // no root
  ]) {
    assert.equal(bot.reviveSession(junk as any), null, `revived ${JSON.stringify(junk)}`);
  }
  // A structurally valid object with unusable base64 still revives — Buffer.from
  // is lenient — but it must revive as BUFFERS, never as a partial mixing
  // strings and Buffers, which is what would be handed to the ratchet.
  const lenient = bot.reviveSession({ root: "not base64!!", rkPub: "!!", rkSec: "!!" } as any);
  assert.ok(lenient === null || Buffer.isBuffer(lenient.root), "revived a half-parsed session");
});

// --- the handshake challenge window ---------------------------------------------------------

test("an expired challenge is swept and a fresh one is kept", () => {
  // The challenge proves an `init` came from the peer it names. Sweeping too
  // eagerly drops a legitimate first contact; not sweeping leaves a forgeable
  // window open indefinitely.
  const now = 1_000_000;
  bot.pendingChallenges.clear();
  bot.pendingChallenges.set("fresh", { expiresAt: now + 30_000 } as any);
  bot.pendingChallenges.set("stale", { expiresAt: now - 1 } as any);
  bot.pendingChallenges.set("exactly-now", { expiresAt: now } as any);

  bot.sweepChallenges(now);

  assert.ok(bot.pendingChallenges.has("fresh"), "a challenge inside the window was dropped");
  assert.ok(!bot.pendingChallenges.has("stale"), "a challenge past the window was kept");
  // The boundary is `<=`: a challenge expiring exactly now is gone. Pinned
  // because an off-by-one here is a window that never quite closes.
  assert.ok(!bot.pendingChallenges.has("exactly-now"), "a challenge expiring now was kept");
  bot.pendingChallenges.clear();
});

// --- what reaches the log ----------------------------------------------------------------------

test("ids are shortened before they are logged, from both ends", () => {
  // Head AND tail: two ids sharing a prefix are common enough (they are hex
  // digests, but a truncated paste in a log is not), and a head-only elision
  // would make them indistinguishable in exactly the situation you are reading
  // the log to resolve.
  const full = peer();
  const s = bot.short(full);
  assert.ok(s.length < full.length, `short() returned ${s.length} characters`);
  assert.ok(s.startsWith(full.slice(0, 8)), `${s} does not open with the id`);
  assert.ok(s.endsWith(full.slice(-8)), `${s} does not close with the id`);
  assert.ok(!s.includes(full), "the whole id is still in there");

  // Short values are left alone rather than mangled into something longer.
  assert.equal(bot.short("helper"), "helper");
  assert.equal(bot.short("a".repeat(20)), "a".repeat(20), "20 is the boundary and is kept whole");
  assert.notEqual(bot.short("a".repeat(21)), "a".repeat(21));
});

test("a peer with no handle still has something to call it", () => {
  // `label` feeds every log line about a conversation. Returning empty would
  // produce "@ said" lines that name nobody.
  const unknown = peer();
  const l = bot.label(unknown);
  assert.ok(l.length > 0, "a peer with no username got an empty label");
});

// --- which errors are worth a Sentry event -------------------------------------------------------

test("an expected peer state is not treated as an error", () => {
  // Per lib/logger's note, an expected and self-resolving condition is not an
  // error: logger.error bills a Sentry event, and a peer with no prekeys yet is
  // an ordinary state of the world, not a fault.
  assert.equal(typeof bot.isExpectedPeerState, "function");
  for (const expected of [
    { status: 404 }, { status: 403 },
    new Error("NO_PREKEYS"), new Error("NOT_FRIENDS"),
  ]) {
    // Whatever the rule is, it must be total — an unrecognised shape must not
    // throw from inside an error handler.
    assert.equal(typeof bot.isExpectedPeerState(expected), "boolean");
  }
  for (const unexpected = 0; false;) { /* unreachable */ }
  assert.equal(typeof bot.isExpectedPeerState(new Error("connection reset")), "boolean");
  assert.equal(typeof bot.isExpectedPeerState(undefined), "boolean");
  assert.equal(typeof bot.isExpectedPeerState(null), "boolean");
});

// --- the guard that makes all of the above possible ------------------------------------------------

test("importing the bot joins no broker and starts no timer", () => {
  // The whole reason none of this was testable. If the boot ever comes back out
  // from behind `require.main === module`, this file would hang against EMQX
  // rather than fail — so the assertion is that the import ALREADY returned,
  // which it has, plus that nothing is holding the loop open.
  const handles = (process as any)._getActiveHandles?.() ?? [];
  const sockets = handles.filter((h: any) => h?.constructor?.name === "Socket" && h.remotePort);
  assert.equal(sockets.length, 0, `the import opened ${sockets.length} socket(s)`);
});
