// Where a REAL public key still goes, and where one no longer does.
//
// ── What this file used to be ────────────────────────────────────────────────
//
// A btree index entry may not exceed about 2704 bytes. An HQC-256 public key is
// 7237 bytes and travels as hex — 14474 characters — so the original Postgres
// schema's `pk text PRIMARY KEY` did not merely index badly, it rejected every
// write that carried a genuine key:
//
//   ERROR: index row requires 14488 bytes, maximum size is 8191
//
// Nothing caught that for a full release cycle. The only tests that used
// key-shaped values were the e2e ones, and CI's `changes` job was failing on
// every pull request, which skipped them; the unit suite used short stand-ins
// like "aa".repeat(32), which fit comfortably and proved nothing. So this file
// pushed a key of the true size through every pk-keyed write.
//
// ── What it is now ───────────────────────────────────────────────────────────
//
// Those tables are keyed by a 64-character CLIENT ID (004_identity_by_hash.sql),
// so the size question is settled for all of them at once — the schema simply
// cannot be handed a 14 kB identifier any more, and `users.id` has a CHECK that
// says so.
//
// Two things still need asserting, and they are not the same thing:
//
//   1. The tables that legitimately hold a full-size key still accept one.
//      `prekeys_medium.prekey`, `prekeys_onetime.prekey` and
//      `users.identity_pk` are key MATERIAL, not names, and none of them is a
//      btree key. That is the original assertion, narrowed to where it applies.
//   2. Nothing else does. An identifier that is not 64 hex characters is
//      REFUSED, which is what stops the old shape quietly coming back through
//      one forgotten call site.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";
import { DB } from "../services/db/api";
import { peerId } from "../lib/identity";
import { q } from "../services/db/pg";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

// HQC_CONSTANTS.PUBLIC_KEY_BYTES from lib/hqc.ts, as a literal: importing that
// module loads the native library, which this test has no need of and which is
// built for one platform only.
const PUBLIC_KEY_BYTES = 7237;

/** A key of exactly the size the wire carries. Random, so it cannot compress
 *  down under the limit the way a repeated character would. */
const bigPk = () => crypto.randomBytes(PUBLIC_KEY_BYTES).toString("hex");

const tag = () => crypto.randomBytes(4).toString("hex");

test("a full-size key survives every table that legitimately holds one", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const pk = bigPk();
  const id = peerId(pk);
  const name = `bigkey_${tag()}`;

  // users.identity_pk — the ONLY durable copy of an account's identity key, and
  // the largest single thing 004 added. Its CHECK ties it to the id, so this
  // also asserts that the two halves agree.
  await DB.createUser(id, pk, name);
  assert.equal(await DB.identityKey(id), pk, "the key is served back intact");
  assert.equal(await DB.getUsername(id), name);

  // prekeys_*.prekey — key material by definition.
  const medium = bigPk();
  const oneTime = [{ id: 0, prekey: bigPk() }, { id: 1, prekey: bigPk() }];
  await DB.putPrekeyBundle(id, medium, oneTime);
  const claimed = await DB.claimPrekey(id);
  assert.equal(claimed?.medium, medium, "a full-size medium-term key round-trips");
  assert.equal(claimed?.oneTime?.prekey, oneTime[0]!.prekey, "and a one-time one");
  assert.equal(claimed?.oneTime?.id, 0, "with the client's own index for it");
  assert.equal(await DB.countOneTimePrekeys(id), 1, "the claimed key is consumed");

  await DB.deleteUser(id);
  assert.equal(await DB.identityKey(id), null, "and the key goes with the account");
});

test("users refuses a row whose key does not hash to its id", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The invariant that lets `GET /peer/{id}/key` be answered from a server the
  // protocol does not trust: a row whose `identity_pk` is not the key its `id`
  // commits to cannot exist, so a mismatch is a deliberate write rather than
  // something that could drift into place.
  const id = peerId(bigPk());
  await assert.rejects(
    () => q(`INSERT INTO users (id, identity_pk) VALUES ($1, $2)`, [id, bigPk()]),
    /users_check|violates check constraint/,
    "a key that does not hash to the id must be refused"
  );
});

test("users refuses an id that is not 64 hex characters", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The old shape, refused at the schema. This is what stops a forgotten call
  // site quietly reintroducing a 14474-character identifier — the failure is at
  // the write, not fifteen minutes later in the broker's authorizer cache.
  const pk = bigPk();
  for (const bad of [pk, pk.slice(0, 63), peerId(pk).toUpperCase(), "g".repeat(64)]) {
    await assert.rejects(
      () => q(`INSERT INTO users (id, identity_pk) VALUES ($1, $2)`, [bad, pk]),
      /violates check constraint/,
      `${bad.slice(0, 16)}… (${bad.length} chars) must be refused as an id`
    );
  }
});

test("the identity, graph and ACL tables are keyed by a 64-character id", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [pkA, pkB] = [bigPk(), bigPk()];
  const [a, b] = [peerId(pkA), peerId(pkB)];
  const id = tag();
  const [na, nb] = [`big_a_${id}`, `big_b_${id}`];

  await DB.createUser(a, pkA, na);
  await DB.createUser(b, pkB, nb);

  // The upsert path, which is where the index is written a second time.
  await DB.setUsername(a, `big_a2_${id}`);
  assert.equal(await DB.getUsername(a), `big_a2_${id}`);

  await DB.addAdmissionExempt(a);
  assert.ok(await DB.isAdmissionExempt(a));

  await DB.invite(a, nb);
  assert.equal((await DB.getMyInvites(b)).length, 1);
  assert.ok(await DB.acceptInvite(`big_a2_${id}`, b));
  assert.ok(await DB.checkFriendship(a, b), "friendship pair key");

  await DB.grantSelfTopics(a);
  await DB.grantFriendTopic(a, b);
  const topics = await DB.getAclTopics(a);
  assert.ok(topics.length >= 3);

  // The row size that made every per-client EMQX admin call answer 414. A
  // presence topic embedded a whole public key, beside a `pk` column holding
  // another one: ~29 kB to record one membership bit.
  // `u/` + 64 + `/presence` is the longest topic the scheme can produce.
  const widest = Math.max(...topics.map((tp) => tp.length));
  assert.equal(widest, 2 + 64 + "/presence".length, `the widest topic is ${widest} characters`);
  const { rows } = await q<{ bytes: string }>(
    `SELECT sum(octet_length(id) + octet_length(topic) + octet_length(action))::text AS bytes
       FROM mqtt_acl WHERE id = $1`, [a]
  );
  const bytes = Number(rows[0]!.bytes);
  assert.ok(bytes < 1000, `${topics.length} ACL rows total ${bytes} bytes, not ~29 kB each`);

  await DB.deleteUser(a);
  await DB.deleteUser(b);
});

test("the ephemeral tier is keyed by id too", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const pk = bigPk();
  const a = peerId(pk);
  await DB.ensureUser(a, pk);

  await DB.setPushToken(a, "ios", "tok-1");
  await DB.setPushToken(a, "ios", "tok-2");
  assert.equal((await DB.getPushToken(a))?.token, "tok-2");

  await DB.mintMqttToken(a);
  const live = await DB.mintMqttToken(a);
  assert.ok((await DB.verifyMqttToken(a, live)).ok);

  await DB.startAuthChallenge(a, "proof-1");
  await DB.startAuthChallenge(a, "proof-2");
  assert.equal(await DB.takeAuthChallenge(a), "proof-2");

  const token = await DB.mintSessionToken(a, "free", 60);
  assert.equal((await DB.resolveSessionToken(token))?.id, a);

  // auth/main.ts counts per identity, so `rate_counters.key` carries an id —
  // which is why that table's `key` is a plain PRIMARY KEY now rather than an
  // expression index over a digest of a 14 kB string.
  assert.equal(await DB.bumpCounter(`init:pk:${a}`, 60), 1);
  assert.equal(await DB.bumpCounter(`init:pk:${a}`, 60), 2);
  await DB.clearCounter(`init:pk:${a}`);

  await DB.deleteUser(a);
});

// A subscription claim used to be recorded here, pinning that it was keyed by
// the 64-character id rather than the 14 kB public key — because revoking one
// meant `DELETE /clients/{clientid}`, and EMQX answered 414 to the key. The
// claim tables are dropped in migrations/005_donations.sql; the id-length
// property they demonstrated is still pinned, on the path that still needs it,
// by test/emqx-revocation.test.ts.

test.after(closePg);
