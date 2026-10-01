// Prekey storage (003_prekeys.sql) — the ephemeral half of the initial key
// agreement. See the migration for why it exists; these tests pin the three
// properties the protocol actually depends on:
//
//   1. a one-time key is claimed EXACTLY once, even when two initiators race —
//      two peers deriving roots from the same "one-time" secret is the whole
//      failure this tier exists to prevent;
//   2. an exhausted pool falls back to the medium-term key rather than failing,
//      so a popular account never becomes unreachable;
//   3. deleting an account leaves no prekey row behind (the account-delete e2e
//      asserts a total purge, and that assertion is App Store evidence).

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { DB } from "../services/db/api";
import { peerId } from "../lib/identity";
import { q } from "../services/db/pg";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

// As in db-full-size-key.test.ts: the literal rather than an import, because
// lib/hqc.ts loads a native library built for one platform.
const PUBLIC_KEY_BYTES = 7237;

/** A key of exactly the size the wire carries, random so it cannot compress. */
const bigPk = () => crypto.randomBytes(PUBLIC_KEY_BYTES).toString("hex");
const tag = () => crypto.randomBytes(4).toString("hex");

/** An account: a real key, and the id it commits to. Prekeys are the one tier
 *  that still stores full keys — they ARE key material — but the account they
 *  belong to is named by its id like everything else. */
function account() {
  const pk = bigPk();
  return { pk, id: peerId(pk) };
}

test("a bundle round-trips and one-time keys drain before the medium-term one", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { pk, id } = account();
  await DB.createUser(id, pk, `pre_a_${tag()}`);

  const medium = bigPk();
  const oneTime = [0, 1, 2].map((keyId) => ({ id: keyId, prekey: bigPk() }));
  await DB.putPrekeyBundle(id, medium, oneTime);

  assert.equal(await DB.countOneTimePrekeys(id), 3, "all three one-time keys stored");
  assert.equal(await DB.maxOneTimePrekeyId(id), 2, "highest id is reported for replenishment");

  // Every claim carries the medium-term key AND a one-time key while the pool
  // has one. Both, not one or the other: the initial root mixes identity,
  // medium-term and (when available) one-time, so serving only one would
  // silently change which root the two sides derive.
  for (const expected of oneTime) {
    const claimed = await DB.claimPrekey(id);
    assert.equal(claimed?.medium, medium, "the medium-term key comes with every claim");
    assert.equal(claimed?.oneTime?.id, expected.id, "drained in id order");
    assert.equal(claimed?.oneTime?.prekey, expected.prekey,
      "a full-size key survives the round-trip");
  }
  assert.equal(await DB.countOneTimePrekeys(id), 0, "the pool is empty");

  // Property 2: exhaustion degrades to the medium-term key alone, it does not fail.
  const fallback = await DB.claimPrekey(id);
  assert.equal(fallback?.oneTime, null, "no one-time key is left to give");
  assert.equal(fallback?.medium, medium, "…but the bundle is still usable");

  // And the medium-term key is reusable — that is the point of the tier.
  assert.equal((await DB.claimPrekey(id))?.medium, medium, "medium-term key is not consumed");

  await DB.deleteUser(id);
});

test("a one-time prekey cannot be claimed twice, even by concurrent initiators", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { pk, id } = account();
  await DB.createUser(id, pk, `pre_race_${tag()}`);

  // No medium-term fallback would muddy the result, so publish one that is
  // obviously distinguishable from every one-time key.
  const medium = bigPk();
  const POOL = 8;
  const oneTime = Array.from({ length: POOL }, (_, id) => ({ id, prekey: bigPk() }));
  await DB.putPrekeyBundle(id, medium, oneTime);

  // More claimants than keys: the surplus must land on the medium-term key, and
  // no one-time key may be handed out twice. `FOR UPDATE SKIP LOCKED` is what
  // makes the losers of a race take the NEXT row instead of blocking on the
  // same one and then re-reading a deleted tuple.
  const claims = await Promise.all(
    Array.from({ length: POOL + 4 }, () => DB.claimPrekey(id))
  );

  assert.ok(claims.every((c) => c?.medium === medium), "every claim carried the bundle");
  const served = claims.map((c) => c?.oneTime).filter(Boolean) as Array<{ id: number; prekey: string }>;
  assert.equal(served.length, POOL, "exactly the pool size was served as one-time");
  assert.equal(claims.length - served.length, 4, "the surplus got the medium-term key alone");

  assert.equal(new Set(served.map((s) => s.id)).size, POOL, "no one-time id was served twice");
  assert.equal(new Set(served.map((s) => s.prekey)).size, POOL,
    "no one-time key material was served twice");
  assert.equal(await DB.countOneTimePrekeys(id), 0);

  await DB.deleteUser(id);
});

test("replenishment is additive and idempotent, never clobbering unclaimed keys", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { pk, id } = account();
  await DB.createUser(id, pk, `pre_top_${tag()}`);

  const first = [0, 1].map((keyId) => ({ id: keyId, prekey: bigPk() }));
  await DB.putPrekeyBundle(id, bigPk(), first);

  // A second upload tops the pool up rather than replacing it. Replacing would
  // strand a peer that had already claimed a key whose secret got dropped.
  const second = [2, 3].map((keyId) => ({ id: keyId, prekey: bigPk() }));
  await DB.putPrekeyBundle(id, bigPk(), second);
  assert.equal(await DB.countOneTimePrekeys(id), 4, "both batches are present");

  // A retried upload (same ids) must not duplicate or overwrite.
  await DB.putPrekeyBundle(id, bigPk(), second);
  assert.equal(await DB.countOneTimePrekeys(id), 4, "a repeated upload is a no-op");
  const claimed = await DB.claimPrekey(id);
  assert.equal(claimed?.oneTime?.prekey, first[0]!.prekey, "the original key material is intact");

  // The medium-term key IS replaced by each upload — it is a rotation, not a pool.
  const latestMedium = bigPk();
  await DB.putPrekeyBundle(id, latestMedium, []);
  for (let i = 0; i < 3; i++) await DB.claimPrekey(id); // drain the rest
  assert.equal((await DB.claimPrekey(id))?.medium, latestMedium, "medium-term key rotated");

  await DB.deleteUser(id);
});

test("an account with no published bundle yields nothing rather than throwing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { pk, id } = account();
  await DB.createUser(id, pk, `pre_none_${tag()}`);
  assert.equal(await DB.claimPrekey(id), null, "no bundle is a null, not an error");
  assert.equal(await DB.countOneTimePrekeys(id), 0);
  assert.equal(await DB.maxOneTimePrekeyId(id), null);
  // A one-time key without a medium-term one is NOT a usable bundle — the
  // initiator could not derive the same root as the responder from it.
  // `key_id`, not `id`: the account's identifier took the name `id` in 004, so
  // the client's own index for the prekey was renamed out of the way.
  await q(`INSERT INTO prekeys_onetime (id, key_id, prekey) VALUES ($1, 0, $2)`, [id, bigPk()]);
  assert.equal(await DB.claimPrekey(id), null, "a one-time key alone is not a bundle");
  // And the refusal did not CONSUME it. The medium-term check comes before the
  // DELETE precisely so an account that cannot serve a bundle does not burn its
  // pool answering claims it can never satisfy.
  assert.equal(await DB.countOneTimePrekeys(id), 1, "the one-time key was not consumed");
  await DB.deleteUser(id);
});

test("deleting an account purges both prekey tiers", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { pk, id } = account();
  await DB.createUser(id, pk, `pre_del_${tag()}`);
  await DB.putPrekeyBundle(id, bigPk(), [0, 1, 2].map((keyId) => ({ id: keyId, prekey: bigPk() })));

  await DB.deleteUser(id);

  // Asserted against the tables directly, not through the read path: the point
  // is that no ROW survives, and a bug in a getter would otherwise hide a bug in
  // the delete.
  for (const table of ["prekeys_medium", "prekeys_onetime"]) {
    const { rows } = await q<{ n: number }>(
      `SELECT count(*)::int AS n FROM ${table} WHERE id = $1`, [id]
    );
    assert.equal(rows[0]?.n, 0, `${table} has no row for the deleted account`);
  }
});

test.after(closePg);
