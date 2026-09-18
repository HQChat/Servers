// The conversation-topic hash.
//
// ⚠️ This file passed UNCHANGED across the move from public keys to client ids,
// because its stand-ins were already 64 characters — `"a".repeat(64)` happens to
// be exactly the width of an id, and `friendshipHash` is indifferent to what it
// is fed. So it proved nothing about the change, and would have proved nothing
// if the change had been wrong.
//
// It is re-asserted here deliberately, against the SHARED vector file, which is
// what makes it a cross-implementation check rather than a self-consistency one.
// The function has a Swift counterpart (`MQTTTopics.conversation`) and a SQL
// one (`pk_digest` over the sorted pair), and 001_schema.sql claimed for months
// that a vector existed to hold the three together. It does now:
// test/helpers/identity-vectors.json, asserted here, in
// services/server/test/identity.test.ts (including against a live Postgres) and
// in apps/apple/tests/PeerIDTests.swift.
//
// Getting this wrong does not fail loudly. The two members of a friendship
// derive different topic names, subscribe to different topics, and never speak —
// with no error anywhere, because MQTT drops a publish nobody is subscribed to.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { friendshipHash } from "../lib/crypto-utils";
import { peerId } from "../lib/identity";

const V = JSON.parse(
  fs.readFileSync(path.join(__dirname, "helpers", "identity-vectors.json"), "utf8")
) as { friendships: Array<{ a: string; b: string; hash: string; topic: string }> };

const ID_A = peerId("a".repeat(14474));
const ID_B = peerId("b".repeat(14474));
const ID_C = peerId("c".repeat(14474));

test("friendshipHash matches the pinned cross-implementation vectors", () => {
  // The assertion the previous version of this file was missing: a value the
  // Swift client and Postgres also compute, rather than one only this function
  // agrees with.
  assert.ok(V.friendships.length >= 3);
  for (const f of V.friendships) {
    assert.equal(friendshipHash(f.a, f.b), f.hash);
    assert.equal(`c/${f.hash}`, f.topic);
  }
});

test("friendshipHash is order-independent", () => {
  // Which is what lets ONE friendships row serve both directions, and what the
  // `id_lo < id_hi` CHECK in 004 relies on.
  assert.equal(friendshipHash(ID_A, ID_B), friendshipHash(ID_B, ID_A));
});

test("friendshipHash differs for different pairs", () => {
  assert.notEqual(friendshipHash(ID_A, ID_B), friendshipHash(ID_A, ID_C));
});

test("friendshipHash is a 64-char hex digest", () => {
  assert.match(friendshipHash(ID_A, ID_B), /^[0-9a-f]{64}$/);
});

test("it is fed CLIENT IDS, and the inputs are the width of one", () => {
  // Stated because it is the thing a stand-in of the same width silently hides.
  // The inputs above are real ids — derived from key-sized inputs — rather than
  // 64 characters that merely look like one.
  for (const id of [ID_A, ID_B, ID_C]) assert.match(id, /^[0-9a-f]{64}$/);
  assert.equal(new Set([ID_A, ID_B, ID_C]).size, 3);
});

test("the resulting topic is 66 characters, not tens of thousands", () => {
  // `c/{hash}` used to sit beside a 14474-character `pk` column in every
  // mqtt_acl row, and inside the presence topics the same table stored.
  assert.equal(`c/${friendshipHash(ID_A, ID_B)}`.length, 66);
});
