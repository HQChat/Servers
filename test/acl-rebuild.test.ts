// The MQTT topic ACL, and the three hand-written copies of the rule that fills it.
//
// `mqtt_acl` is what EMQX consults to decide whether a client may touch a topic.
// It is MATERIALISED rather than a view over `friendships` — a view would join on
// every authz cache miss — and the cost of materialising is that it can drift.
// So the rule that produces it is written out three times:
//
//   services/db/api.ts        grantSelfTopics / grantFriendTopic   — the writers
//   scripts/rebuild-mqtt-acl  one SQL statement                    — the repair
//   scripts/check-mqtt-acl    expected()                           — the report
//
// Each file says it must mirror the others. Nothing checked, and they had already
// drifted: the rebuild's self-grant wrote presence and inbox but NOT the graph
// topic. An account whose graph grant was lost — precisely the drift the repair
// exists to fix — did not get it back, and silently stopped being told its friend
// graph had changed: invites stop appearing until the next poll, and a greeting
// that arrives before the inviter knows who sent it is dropped as an unknown
// sender. Fixed here, and this file is what holds it.
//
// The test is a differential, not a restatement: it grants through the writers,
// wipes the table, rebuilds, and demands the same rows back. A fourth copy of the
// rule written out here would drift too.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { DB } from "../services/db/api";
import { q } from "../services/db/pg";
import { rebuildAcl } from "../scripts/rebuild-mqtt-acl";
import { expected } from "../scripts/check-mqtt-acl";
import { peerId } from "../lib/identity";
import { friendshipHash } from "../lib/crypto-utils";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";

setLogLevel("silent");

const created: string[] = [];

async function account(): Promise<string> {
  const pkHex = crypto.randomBytes(64).toString("hex");
  const id = peerId(pkHex);
  await DB.ensureUser(id, pkHex);
  created.push(id);
  return id;
}

/** Every ACL row these ids hold, ordered so two snapshots compare directly. */
async function aclFor(ids: string[]): Promise<Array<{ id: string; topic: string; action: string }>> {
  const res = await q<{ id: string; topic: string; action: string }>(
    `SELECT id, topic, action FROM mqtt_acl WHERE id = ANY($1::text[]) ORDER BY id, topic`,
    [ids],
  );
  return res.rows;
}

async function cleanup(): Promise<void> {
  if (!created.length) return;
  const ids = [...new Set(created)];
  for (const sql of [
    `DELETE FROM mqtt_acl WHERE id = ANY($1::text[])`,
    `DELETE FROM friendships WHERE id_lo = ANY($1::text[]) OR id_hi = ANY($1::text[])`,
    `DELETE FROM users WHERE id = ANY($1::text[])`,
  ]) {
    try { await q(sql, [ids]); } catch { /* not this schema */ }
  }
  created.length = 0;
}

test.afterEach(async () => { await cleanup(); });
test.after(async () => { await cleanup(); await closePg(); });

// --- the differential ----------------------------------------------------------------

test("a rebuild reproduces exactly what the writers wrote", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The claim in rebuild-mqtt-acl.ts's own header, asserted: `friendships` is
  // the source of truth, so deriving the whole table from it must land on the
  // same rows normal operation produces. A grant the writers make and the
  // rebuild does not is one an operator loses by running the repair.
  const [a, b, c] = [await account(), await account(), await account()];
  await DB.grantSelfTopics(a);
  await DB.grantSelfTopics(b);
  await DB.grantSelfTopics(c);
  await DB.createFriendship(a, b);
  await DB.grantFriendTopic(a, b);
  await DB.createFriendship(a, c);
  await DB.grantFriendTopic(a, c);

  const written = await aclFor([a, b, c]);
  assert.ok(written.length >= 12, `expected a populated ACL, got ${written.length} rows`);

  // The drift this guards against is silent, so simulate it completely: wipe
  // every row these accounts hold and repair from the friend graph alone.
  await q(`DELETE FROM mqtt_acl WHERE id = ANY($1::text[])`, [[a, b, c]]);
  assert.deepEqual(await aclFor([a, b, c]), [], "the wipe did not take");

  await rebuildAcl();

  assert.deepEqual(await aclFor([a, b, c]), written,
    "a rebuild does not reproduce what normal operation writes");
});

test("an account with no friends still gets its own topics back", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The self grants are derived from `users`, not from friendships, precisely so
  // that a friendless account still has somewhere to be woken. A rebuild that
  // derived everything from the friend graph would strand every new signup.
  const solo = await account();
  await DB.grantSelfTopics(solo);
  const written = await aclFor([solo]);

  await q(`DELETE FROM mqtt_acl WHERE id = $1`, [solo]);
  await rebuildAcl();

  assert.deepEqual(await aclFor([solo]), written);
  assert.equal(written.length, 3, `self grants are presence, inbox and graph — got ${written.length}`);
});

test("the graph grant is subscribe-only, and it is there", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The specific row that was missing from the rebuild. Subscribe only: the
  // server is the only publisher and it publishes through the admin API, which
  // the authorizer never consults — so no row grants publish here, not even to
  // the owner, who has no reason to tell themselves anything.
  const solo = await account();
  await q(`DELETE FROM mqtt_acl WHERE id = $1`, [solo]);
  await rebuildAcl();

  const rows = await aclFor([solo]);
  const graph = rows.find((r) => r.topic === `u/${solo}/graph`);
  assert.ok(graph, `no graph grant after a rebuild; got ${rows.map((r) => r.topic).join(", ")}`);
  assert.equal(graph!.action, "subscribe", "the owner must not be able to publish to their own graph");
});

test("the reporter's expectation matches what a rebuild produces", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The third copy. `check-mqtt-acl` is what an operator reads during an
  // outage — if its idea of "should have" disagrees with what the repair writes,
  // it reports a permanent phantom gap and the operator chases it.
  const [a, b] = [await account(), await account()];
  await DB.createFriendship(a, b);
  await q(`DELETE FROM mqtt_acl WHERE id = ANY($1::text[])`, [[a, b]]);
  await rebuildAcl();

  for (const id of [a, b]) {
    const want = (await expected(id)).map((r) => `${r.topic} ${r.action}`).sort();
    const have = (await aclFor([id])).map((r) => `${r.topic} ${r.action}`).sort();
    assert.deepEqual(have, want,
      `check-mqtt-acl and rebuild-mqtt-acl disagree about ${id.slice(0, 8)}…`);
  }
});

test("the reporter's expectation matches what the writers write", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [a, b] = [await account(), await account()];
  await DB.grantSelfTopics(a);
  await DB.grantSelfTopics(b);
  await DB.createFriendship(a, b);
  await DB.grantFriendTopic(a, b);

  for (const id of [a, b]) {
    const want = (await expected(id)).map((r) => `${r.topic} ${r.action}`).sort();
    const have = (await aclFor([id])).map((r) => `${r.topic} ${r.action}`).sort();
    assert.deepEqual(have, want, `check-mqtt-acl disagrees with the writers about ${id.slice(0, 8)}…`);
  }
});

// --- what a rebuild must not do ---------------------------------------------------------

test("a rebuild only ever widens access", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Idempotent by construction and additive by default. An operator running the
  // repair during an incident must not be able to make it worse — and this is
  // the reason `--prune` is opt-in.
  const [a, b] = [await account(), await account()];
  await DB.grantSelfTopics(a);
  await DB.grantSelfTopics(b);
  await DB.createFriendship(a, b);
  await DB.grantFriendTopic(a, b);
  const before = await aclFor([a, b]);

  await rebuildAcl();
  await rebuildAcl();
  const after = await aclFor([a, b]);

  assert.deepEqual(after, before, "a second rebuild changed the table");
});

test("pruning removes an orphaned conversation grant and nothing else", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The only destructive thing here, and a bug in its WHERE clause would cut
  // people off from conversations that are perfectly valid — which is exactly
  // why it is opt-in. Both halves are asserted: the orphan goes, the live
  // grant stays.
  const [a, b] = [await account(), await account()];
  await DB.grantSelfTopics(a);
  await DB.createFriendship(a, b);
  await DB.grantFriendTopic(a, b);
  const live = `c/${friendshipHash(a, b)}`;

  // A conversation grant with no friendship behind it — the drift a prune exists
  // to clear.
  const orphan = `c/${crypto.randomBytes(32).toString("hex")}`;
  await q(`INSERT INTO mqtt_acl (id, topic, action) VALUES ($1, $2, 'all')`, [a, orphan]);

  await rebuildAcl({ prune: true });

  const topics = (await aclFor([a, b])).map((r) => r.topic);
  assert.ok(!topics.includes(orphan), "the orphaned grant survived a prune");
  assert.ok(topics.includes(live), "a prune removed a conversation that a friendship justifies");
  assert.ok(topics.includes(`u/${a}/graph`), "a prune removed a self grant");
  assert.ok(topics.includes(`u/${b}/presence`), "a prune removed a presence grant");
});

test("a rebuild without --prune leaves the orphan alone", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Additive by default means additive. An operator who runs the plain command
  // during an incident has not quietly revoked anything.
  const a = await account();
  const orphan = `c/${crypto.randomBytes(32).toString("hex")}`;
  await q(`INSERT INTO mqtt_acl (id, topic, action) VALUES ($1, $2, 'all')`, [a, orphan]);

  await rebuildAcl();
  assert.ok((await aclFor([a])).some((r) => r.topic === orphan),
    "the default path removed a grant");
});

test("importing the repair script does not run it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // It rewrites an authorization table. `require.main === module` is what stops
  // a tool that merely wants `rebuildAcl` from rebuilding the whole ACL as a
  // side effect of the import — and this file is such a tool.
  const a = await account();
  await q(`DELETE FROM mqtt_acl WHERE id = $1`, [a]);
  // The module is already imported at the top of this file. If the import had
  // run main(), this account would hold rows.
  delete require.cache[require.resolve("../scripts/rebuild-mqtt-acl")];
  require("../scripts/rebuild-mqtt-acl");
  assert.deepEqual(await aclFor([a]), [], "importing the script rebuilt the ACL");
});
