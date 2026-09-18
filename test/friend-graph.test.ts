// The bot's friend-list reconciliation.
//
// One of these decides which conversations to FORGET, sessions included, so the
// dangerous case is not "a stale peer survives" — it is "a healthy sync is read
// as an empty graph and prunes everything". That is what the null return exists
// for, and what most of this file is about.
//
// Pure by design: `bot.ts` loads the native HQC library and writes a seed file
// at import, so anything testable has to live outside it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { liveFriendIds, staleFriendIds } from "../bot/friend-graph";

// Client ids: exactly 64 lowercase hex. These stand-ins were already 64
// characters when the field held a 14474-character PUBLIC KEY — which is why
// this file passed unchanged across the switch, and why it would not have
// caught it. They are ids on purpose now, and the malformed cases below assert
// the exact width rather than a lower bound.
const SELF = "a".repeat(64);
const A = "b".repeat(64);
const B = "c".repeat(64);

test("a well-formed list yields the peers, minus ourselves", () => {
  const live = liveFriendIds({ friends: [{ id: A }, { id: B }, { id: SELF }] }, SELF);
  assert.deepEqual([...live!].sort(), [A, B].sort());
});

test("an empty list is a real answer — everyone was unfriended", () => {
  const live = liveFriendIds({ friends: [] }, SELF);
  assert.ok(live, "an empty array is a list, not a missing one");
  assert.equal(live!.size, 0);
});

test("anything that is not a list yields null, never an empty set", () => {
  // This is the guard that matters. Each of these would, if read as "no
  // friends", prune every peer the bot knows and destroy every ratchet session
  // with them — on a transient server hiccup.
  for (const body of [
    {},
    { friends: null },
    { friends: undefined },
    { friends: "none" },
    { friends: 0 },
    { friends: { id: A } },
    null,
    undefined,
    "not json",
    [],
  ]) {
    assert.equal(liveFriendIds(body, SELF), null, `${JSON.stringify(body)} must be null`);
  }
});

test("a malformed row is skipped without failing the rest of the sync", () => {
  // One bad entry must not cost the other peers their sessions, and must not
  // look like they were unfriended either.
  const live = liveFriendIds(
    { friends: [{ id: A }, { id: "" }, { id: "nothex!" }, {}, null, { id: B }] },
    SELF
  );
  assert.deepEqual([...live!].sort(), [A, B].sort());
});

test("a row carrying the OLD shape is skipped, not tracked", () => {
  // The whole reason the bound tightened. `[0-9a-f]{16,}` accepted a full public
  // key, a truncated one, and a chain id alike — so a peer sent in a shape this
  // deployment no longer uses would be TRACKED, subscribed to a topic nobody
  // holds a grant on, and (with deny_action = disconnect) take the bot's whole
  // link down on the next connect.
  const live = liveFriendIds(
    {
      friends: [
        { id: A },
        { id: "b".repeat(14474) },   // a full public key — the old wire form
        { id: "c".repeat(32) },      // a chainId, which is the same digest halved
        { id: "d".repeat(63) },      // one short
        { id: "e".repeat(65) },      // one long
        { id: A.toUpperCase() },     // uppercase; see below
        { id: B },
      ],
    },
    SELF
  );
  assert.deepEqual([...live!].sort(), [A, B].sort());
});

test("client ids are matched case-insensitively", () => {
  // The wire carries lowercase, but a peer that sent uppercase must not read as
  // a different person — that would prune the real one and re-handshake.
  const live = liveFriendIds({ friends: [{ id: A.toUpperCase() }] }, SELF);
  assert.ok(live!.has(A));
});

test("stale peers are the tracked ones the server no longer lists", () => {
  const live = new Set([A]);
  assert.deepEqual(staleFriendIds([A, B], live), [B]);
  assert.deepEqual(staleFriendIds([A], live), [], "nothing stale when they match");
  assert.deepEqual(staleFriendIds([], live), [], "an empty tracker prunes nothing");
});

test("everything is stale when the server lists nobody", () => {
  // Correct, and the reason the null case above must never reach here: with a
  // genuine empty list this SHOULD drop everyone.
  assert.deepEqual(staleFriendIds([A, B], new Set()).sort(), [A, B].sort());
});

test("the production failure: 14 tracked, 11 live, 3 dropped", () => {
  // The shape observed on the deployment — the bot had accumulated three peers
  // whose friendships were gone and whose topic grants had been revoked, and
  // re-subscribing to the first of them closed the link on every connect.
  // Distinct keys, deliberately: `String(i).repeat(64)` collides — peer 1 and
  // peer 11 both become "111…" — which quietly shrinks the Set and reports two
  // stale instead of three.
  const tracked = Array.from({ length: 14 }, (_, i) => i.toString(16).padStart(64, "0"));
  const live = new Set(tracked.slice(0, 11));
  assert.equal(staleFriendIds(tracked, live).length, 3);
});
