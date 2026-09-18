// End-to-end: two real clients, a real broker, a real auth server and API.
//
// This is the coverage `legacy/e2e.test.ts` used to provide, ported to the
// protocol that actually ships. `legacy/README.md` set the condition for
// deleting that directory: "connect through EMQX with a real token, publish a
// ConversationEnvelope, assert the peer decrypts it, assert the topic ACL
// refuses a stranger." Everything below is that list, plus the three properties
// v2 adds and v1 could not have.
//
// Skips cleanly when the native HQC library, the servers or the broker are
// missing — the same bargain the rest of the suite makes.
//
//   npm run migrate && npm run test:e2e

import { test } from "node:test";
import assert from "node:assert/strict";
import { TestClient, e2eAvailable, loadCrypto } from "../helpers/mqtt-client";
import { friendshipHash } from "../../lib/crypto-utils";
import { keyMatchesId, peerId } from "../../lib/identity";
import { disconnect } from "../../services/db/pg";
import { Frame, encodeFrame } from "../../lib/frame";

/**
 * A frame's bytes, for the tests that publish by hand.
 *
 * These used to be `JSON.stringify(env)`, which worked because v2 WAS JSON. v3
 * is binary, so a frame has no text form and the encoder is the only way to
 * produce one — which is the point: a test that hand-rolls the bytes is testing
 * its own idea of the format rather than the format.
 */
function bytes(f: Frame): Buffer {
  const out = encodeFrame(f);
  if (!out) throw new Error(`this test built a frame encodeFrame refuses: t=${f.t} n=${f.n}`);
  return out;
}

const SKIP = "needs a live auth server, api and EMQX (see test/helpers/mqtt-client.ts)";
const tag = () => Math.random().toString(36).slice(2, 8);

/** Two registered, connected, mutually-friended clients with prekeys published. */
async function pair(t: { skip: (m: string) => void }) {
  const c = await loadCrypto();
  const a = new TestClient(c);
  const b = new TestClient(c);
  const id = tag();
  await a.register(`e2e_a_${id}`);
  await b.register(`e2e_b_${id}`);

  // Friendship is what grants the conversation topic AND publish on each
  // other's inbox, so it has to land before either connects.
  const invited = await a.api("POST", "/friends/invite", { to: b.username });
  // There used to be a `if (invited.status === 402) t.skip(...)` here, for when
  // the friend graph was a paid feature. It made this suite a no-op: the test
  // client authenticates on a door that minted a `free` scope, every invite was
  // refused, every conversation test skipped, and the job reported green having
  // exercised nothing. Nothing answers 402 any more — the paywall is gone — and
  // the client now uses the full door, so an invite that fails is a real
  // failure and must be asserted rather than skipped.
  assert.equal(invited.status, 200, "invite accepted");
  assert.equal((await b.api("POST", "/friends/accept", { from: a.username })).status, 200);

  await Promise.all([a.publishPrekeys(), b.publishPrekeys()]);
  await Promise.all([a.connect(), b.connect()]);
  await Promise.all([
    a.subscribeConversation(b.id),
    b.subscribeConversation(a.id),
  ]);
  return { a, b };
}

test("e2e: a burst before the peer replies arrives in full", async (t) => {
  // THE ONE-DIRECTIONAL BURST. Every conversation test in this file alternates
  // — a sends, b reads, b sends, a reads — and that pattern hides this, because
  // hearing back is exactly what clears `pendingInit`.
  //
  // A real person does not alternate. They send "hi", then "you there?", then
  // "it's about tomorrow", and the other phone has not replied to any of it.
  // `seal` attaches the init header to EVERY message until the peer answers
  // (ratchet-session.ts: "Present until the peer answers"), so all three are
  // typed `init` — and a receiver that already has a session refuses an init
  // without opening its payload. The bot returns early in `onInit`, the Swift
  // router returns on `.ignoreReplay`, and the test client drops it.
  //
  // Found by the load test on its first real run against a broker, as three
  // pairs failing with "init for a peer we already have a session with".
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    await a.send(b, "hi");
    await a.send(b, "you there?");
    await a.send(b, "it is about tomorrow");

    const got: string[] = [];
    for (let i = 0; i < 3; i++) {
      try { got.push((await b.next(4000)).text); } catch { break; }
    }
    assert.deepEqual(got, ["hi", "you there?", "it is about tomorrow"],
      `b received ${got.length}/3 before replying. Dropped: ${JSON.stringify(b.drops)}`);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("e2e: a first message opens the session and decrypts at the far end", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    const sent = await a.send(b, "first contact");
    assert.equal(sent.t, "init", "the first frame carries the handshake");
    assert.ok(sent.ctId && sent.ctMt, "…and the handshake ciphertexts");

    const got = await b.next();
    assert.equal(got.text, "first contact");
    assert.equal(got.from, a.id);

    // And back the other way, which is the responder's first ratchet step.
    await b.send(a, "received");
    assert.equal((await a.next()).text, "received");
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("e2e: a message sent while the peer is OFFLINE is delivered on reconnect", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    // This is the case v1 could not do at all. Its handshake needed both devices
    // online at once, and an offer published to a topic with no subscriber was
    // simply dropped — which is why the client grew a 15s poll and an offer
    // backoff. Here the `init` goes to B's inbox, which B subscribed to with a
    // persistent session, so the broker holds it.
    await b.goOffline();
    await a.send(b, "sent while you were away");

    await b.connect();
    const got = await b.next();
    assert.equal(got.text, "sent while you were away", "queued and delivered on reconnect");
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("e2e: a conversation ratchets and stays in sync across many turns", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    await a.send(b, "turn 0");
    assert.equal((await b.next()).text, "turn 0");

    for (let i = 1; i <= 5; i++) {
      await b.send(a, `b${i}`);
      assert.equal((await a.next()).text, `b${i}`, `A reads b${i}`);
      await a.send(b, `a${i}`);
      assert.equal((await b.next()).text, `a${i}`, `B reads a${i}`);
    }
    assert.equal(a.undecryptable.length, 0, "A dropped nothing");
    assert.equal(b.undecryptable.length, 0, "B dropped nothing");
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("e2e: out-of-order delivery still decrypts", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    await a.send(b, "opener");
    assert.equal((await b.next()).text, "opener");

    // B answers, and that reply is load-bearing rather than tidy-looking.
    //
    // A carries its handshake header on EVERY frame until it hears back
    // (`SessionState.pendingInit`), so without this reply all three frames
    // below would still be `init` frames. A responder that already holds a
    // session drops an inbound `init` outright — bot.ts `onInit`, the harness,
    // and Swift's `InitCollision.ignoreReplay` all do, to stop a replayed frame
    // wiping a conversation — so all three would vanish, and the failure would
    // look identical to a reordering bug.
    //
    // What this test is actually about is out-of-order `msg` delivery and the
    // ratchet's skipped-key handling, which only happens once the handshake is
    // behind both sides.
    await b.send(a, "ack");
    assert.equal((await a.next()).text, "ack", "A must hear back before it stops re-sending its init");

    // Seal three, deliver them back to front. The broker preserves order, so the
    // reordering is done by hand — publishing them in reverse.
    const envs = [];
    for (let i = 0; i < 3; i++) envs.push(await a.sealOnly(b, `ooo-${i}`));
    for (const e of envs) {
      assert.equal(e.t, "msg", "the reply should have cleared A's pendingInit");
    }
    // Routed by frame type rather than hard-coded, so a frame that is not the
    // type this test expects goes somewhere a responder will still look at it.
    for (const e of envs.reverse()) {
      await a.publishRaw(a.topicFor(e, b), bytes(e));
    }

    const seen = new Set<string>();
    for (let i = 0; i < 3; i++) seen.add((await b.next()).text);
    assert.deepEqual([...seen].sort(), ["ooo-0", "ooo-1", "ooo-2"],
      "every message resolved regardless of arrival order");
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("e2e: the topic ACL refuses a stranger", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  const stranger = new TestClient(await loadCrypto());
  try {
    await stranger.register(`e2e_x_${tag()}`);
    await stranger.connect();

    // The topic name is derivable by anyone who knows both client ids — and an
    // id is itself derivable by anyone holding the public key — so authorization
    // rests ENTIRELY on the ACL table, never on topic secrecy. A stranger who
    // computes it must still be refused.
    const convo = `c/${friendshipHash(a.id, b.id)}`;
    // The payload is deliberately not a real frame — the ACL refuses the
    // PUBLISH before anything reads a byte of it, which is the property under
    // test. It used to be a v2-shaped JSON object; a string makes it plainer
    // that its contents were never the point.
    const pub = await stranger.publishRaw(convo, "not a frame");
    assert.equal(pub.accepted, false, "a non-member cannot publish to the conversation topic");

    // Nor into a stranger's inbox: the publish grant comes with a friendship.
    const inbox = await stranger.publishRaw(`u/${b.id}/inbox`, "{}");
    assert.equal(inbox.accepted, false, "a non-member cannot publish to an inbox");

    // And the real members are unaffected.
    await a.send(b, "still working");
    assert.equal((await b.next()).text, "still working");
  } finally {
    await Promise.all([a.close(), b.close(), stranger.close()]);
  }
});

test("e2e: a tampered header does not decrypt", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    await a.send(b, "establish");
    assert.equal((await b.next()).text, "establish");
    // B answers so A stops re-sending its handshake — see the note in the
    // out-of-order test. Without it `sealOnly` still returns an `init`, which a
    // responder holding a session discards before it ever reaches the decrypt
    // path, and the frame is dropped for the wrong reason: no message, but
    // nothing recorded as undecryptable either, which is what this asserts.
    await b.send(a, "ack");
    assert.equal((await a.next()).text, "ack");

    // The header selects the key, so it is read before the payload can
    // authenticate it. Binding it as AAD is what stops a rewritten field from
    // producing a wrong message rather than no message — the TM-1 case.
    const env = await a.sealOnly(b, "tamper me");
    assert.equal(env.t, "msg", "the tamper case is about a message header, not a handshake");
    const tampered = { ...env, n: env.n + 1 };
    await a.publishRaw(a.topicFor(tampered, b), bytes(tampered));

    await new Promise((r) => setTimeout(r, 1500));
    // Still 1: B received "establish" and SENT "ack", so only the one real
    // message ever reached B's inbox. The tampered frame must not add to it.
    assert.equal(b.inbox.length, 1, "the tampered frame produced no message");
    assert.ok(b.undecryptable.length >= 1, "…and was recorded as undecryptable");
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

// ── The identifier, end to end ───────────────────────────────────────────────

test("e2e: a peer's key is served under its id, and verifies against it", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    // Both directions, because the property is symmetric and a server that got
    // one right by accident would be caught by the other.
    for (const [me, peer] of [[a, b], [b, a]] as const) {
      const served = await me.fetchPeerKey(peer.id);
      assert.equal(served.toString("hex"), peer.pkHex, "the key the id names");
      assert.ok(keyMatchesId(served.toString("hex"), peer.id), "…and it verifies");
    }

    // A substituted key is refused by arithmetic, not by trust. This is the
    // whole reason the directory can ship ids from a server the protocol does
    // not trust.
    const impostor = new TestClient(await loadCrypto());
    assert.ok(!keyMatchesId(impostor.pkHex, b.id),
      "another key must not verify against B's id");
    assert.notEqual(peerId(impostor.pkHex), b.id);

    // An unknown id is a 404, not an empty key: "nobody" and "no key" must not
    // be the same answer.
    const nobody = await a.api("GET", `/peer/${peerId("00")}/key`);
    assert.equal(nobody.status, 404);
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("e2e: unfriending DROPS the live subscription, not just the next check", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    // Establish, so both ends are subscribed and delivering.
    await a.send(b, "before");
    assert.equal((await b.next()).text, "before");
    const delivered = b.inbox.length;

    // The property that has NEVER worked on this deployment. `revokeFriendTopic`
    // deletes the ACL row, but EMQX checks authorization at SUBSCRIBE — so an
    // open subscription keeps delivering until the client disconnects. The admin
    // call that closes that window built a ~14.5 kB URL out of two public keys
    // and came back 414 every single time, silently, because a failed kick is
    // best-effort and only logged.
    const removed = await a.api("POST", "/friends/remove", { peer: b.id });
    assert.equal(removed.status, 200, "the unfriend itself succeeds");

    // Give the broker a moment to process the dropped subscription.
    await new Promise((r) => setTimeout(r, 1000));

    // A publish on the shared topic must not reach B any more. A is refused by
    // the ACL, so this is deliberately a RAW publish of a frame B would
    // otherwise have accepted — the question is delivery, not sealing.
    await a.publishRaw(`c/${friendshipHash(a.id, b.id)}`, "not a frame");
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(b.inbox.length, delivered, "nothing new reached the unfriended peer");
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test("e2e: an init carries the initiator's key, and a wrong one is refused", async (t) => {
  if (!(await e2eAvailable())) return t.skip(SKIP);
  const p = await pair(t);
  if (!p) return;
  const { a, b } = p;
  try {
    const env = await a.sealOnly(b, "first contact");
    assert.equal(env.t, "init");
    assert.equal(env.sender, a.id, "the sender is a client id");
    assert.equal(env.sender.length, 64);
    assert.equal(env.senderPk?.toString("hex"), a.pkHex, "…and the init carries the key it names");

    // Substituted: the frame is refused by `decodeV3` at the far end before any
    // key material is touched, so it produces no message AND no undecryptable
    // record — it never becomes a frame at all.
    //
    // The forged frame has to be built by hand rather than re-encoded, because
    // `encodeFrame` now REFUSES it: `validateV3` checks senderPk against sender
    // on the way out as well as the way in, so the encoder will not produce a
    // frame its own decoder would reject. That refusal is itself the first half
    // of the property, and is asserted before the hand-built frame goes out.
    const impostor = new TestClient(await loadCrypto());
    const forged = { ...env, senderPk: Buffer.from(impostor.pkHex, "hex") };
    assert.equal(encodeFrame(forged), null,
      "the encoder must refuse to build a frame whose senderPk does not hash to its sender");

    // Hand-built: take the genuine frame and overwrite the senderPk blob in
    // place, which is what an attacker with a hex editor would do.
    const genuine = bytes(env);
    const forgedBytes = Buffer.from(genuine);
    const at = genuine.indexOf(Buffer.from(a.pkHex, "hex"));
    assert.ok(at > 0, "the genuine frame must contain the key it advertises");
    Buffer.from(impostor.pkHex, "hex").copy(forgedBytes, at);

    const before = b.inbox.length + b.undecryptable.length;
    await a.publishRaw(`u/${b.id}/inbox`, forgedBytes);
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(b.inbox.length + b.undecryptable.length, before,
      "a frame whose senderPk does not hash to its sender is not a frame");

    // The genuine one still opens the session.
    await a.publishRaw(`u/${b.id}/inbox`, genuine);
    assert.equal((await b.next()).text, "first contact");
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test.after(async () => { await disconnect().catch(() => {}); });
