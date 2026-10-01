// A friendship's topic ids (009_friendship_topics.sql).
//
// With a static broker ACL, `cv/{convo_id}` and `hs/{handshake_id}` are the
// whole of a conversation's access control: anyone who knows an id can use it.
// So what is asserted here is what makes that safe — the ids are random, fresh
// per friendship, unique, handed only to the two members, and gone when the
// friendship is.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { DB } from "../services/db/api";
import { peerId } from "../lib/identity";
import { TOPIC_ID } from "../lib/topics";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

const tag = () => crypto.randomBytes(4).toString("hex");

async function user(prefix: string): Promise<string> {
  const pk = crypto.randomBytes(64).toString("hex");
  const id = peerId(pk);
  await DB.createUser(id, pk, `${prefix}_${tag()}`);
  return id;
}

test("both members see the same ids; a third party is never handed them", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await user("ft_a"), b = await user("ft_b"), c = await user("ft_c");
  try {
    await DB.createFriendship(a, b);
    await DB.createFriendship(a, c);

    const fromA = (await DB.getFriendsList(a)).find((f) => f.id === b)!;
    const fromB = (await DB.getFriendsList(b)).find((f) => f.id === a)!;
    assert.match(fromA.convo_id, TOPIC_ID);
    assert.match(fromA.handshake_id, TOPIC_ID);
    assert.equal(fromA.convo_id, fromB.convo_id, "both ends address the same conversation");
    assert.equal(fromA.handshake_id, fromB.handshake_id);
    assert.notEqual(fromA.convo_id, fromA.handshake_id, "two ids, not one used twice");

    // C is A's friend too, and must learn nothing about A–B from it.
    const cList = await DB.getFriendsList(c);
    const seenByC = new Set(cList.flatMap((f) => [f.convo_id, f.handshake_id]));
    assert.ok(!seenByC.has(fromA.convo_id), "a friend of A is not handed A–B's conversation");
    assert.ok(!seenByC.has(fromA.handshake_id), "…nor its handshake topic");

    assert.deepEqual(
      (await DB.getTopicMembers(fromA.convo_id)).sort(),
      [a, b].sort(),
      "push-bridge resolves the topic to exactly the two members"
    );
    assert.deepEqual(await DB.getFriendshipTopics(b, a), {
      convoId: fromA.convo_id, handshakeId: fromA.handshake_id,
    });
  } finally {
    for (const id of [a, b, c]) await DB.deleteUser(id);
  }
});

test("unfriending retires the ids, and re-friending mints fresh ones", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await user("fr_a"), b = await user("fr_b");
  try {
    await DB.createFriendship(a, b);
    const before = await DB.getFriendshipTopics(a, b);
    assert.ok(before);

    const removed = await DB.removeFriendTopics(b, a);
    assert.deepEqual(removed, before, "the delete reports the ids it retired, for the unsubscribe");
    assert.equal(await DB.getFriendshipTopics(a, b), null);
    assert.deepEqual(await DB.getTopicMembers(before.convoId), [],
      "a retired topic belongs to nobody — the ex-friend holding it wakes no one");
    assert.equal(await DB.removeFriendTopics(a, b), null, "a second remove finds nothing");

    // The ex-friend still knows the old ids; that is only harmless if a new
    // friendship does not reuse them.
    await DB.createFriendship(a, b);
    const after = await DB.getFriendshipTopics(a, b);
    assert.ok(after);
    assert.notEqual(after.convoId, before.convoId);
    assert.notEqual(after.handshakeId, before.handshakeId);
  } finally {
    for (const id of [a, b]) await DB.deleteUser(id);
  }
});

test("accepting an invite mints the ids too", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await user("fi_a"), b = await user("fi_b");
  try {
    const nb = (await DB.getUsername(b))!;
    await DB.invite(a, nb);
    assert.ok(await DB.acceptInvite(a, b));
    const topics = await DB.getFriendshipTopics(a, b);
    assert.ok(topics);
    assert.match(topics.convoId, TOPIC_ID);
    assert.match(topics.handshakeId, TOPIC_ID);
  } finally {
    for (const id of [a, b]) await DB.deleteUser(id);
  }
});

test.after(closePg);
