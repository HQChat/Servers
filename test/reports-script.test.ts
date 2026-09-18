// The moderation queue an operator actually reads.
//
// `/eula` commits this deployment to acting on a reported message within 24
// hours, and there is no mail path in this stack — so the commitment rests on a
// Sentry event and on this script. That makes it the same class of thing as
// `check-push`: a diagnostic that lies is worse than none, because it ends the
// investigation.
//
// Two properties here are not cosmetic, and neither is obvious from reading the
// output:
//
//   * READING THE QUEUE DELETES LAPSED REPORTS. Every other expiring table in
//     this schema is filtered on read, so its sweep is about reclaiming space.
//     For `reports` the deletion IS the published promise, so the read path does
//     it itself rather than trusting an ops process to be running.
//   * THE UNVERIFIED CAVEAT IS PART OF THE TOOL. An excerpt is the reporter's
//     own copy and nothing can tell a real one from an invented one. An operator
//     who forgets that acts on a fabrication; the output says so on every row
//     that carries one rather than relying on them to remember.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { DB } from "../services/db/api";
import { q } from "../services/db/pg";
import { peerId } from "../lib/identity";
import { friendshipHash } from "../lib/crypto-utils";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";
import { queue, resolve, DISPOSITIONS } from "../scripts/reports";

setLogLevel("silent");

/** Everything the script printed, as one string. */
function captured(fn: () => Promise<unknown>): Promise<string> {
  const real = { log: console.log, error: console.error };
  const lines: string[] = [];
  const grab = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  console.log = grab; console.error = grab;
  return fn().then(
    () => { Object.assign(console, real); return lines.join("\n"); },
    (e) => { Object.assign(console, real); throw e; },
  );
}

const created: string[] = [];

/** A registered account. The id is DERIVED — `users` carries a CHECK that the
 *  id is the digest of its key, so the two cannot be invented separately. */
async function account(): Promise<string> {
  const pkHex = crypto.randomBytes(64).toString("hex");
  const id = peerId(pkHex);
  await DB.ensureUser(id, pkHex);
  created.push(id);
  return id;
}

async function wipe(): Promise<void> {
  if (!created.length) return;
  const ids = [...new Set(created)];
  await q(`DELETE FROM reports WHERE reporter_id = ANY($1::text[]) OR reported_id = ANY($1::text[])`, [ids]);
  await q(`DELETE FROM users WHERE id = ANY($1::text[])`, [ids]);
  created.length = 0;
}

test.afterEach(async () => { await wipe(); });
test.after(async () => { await wipe(); await closePg(); });

test("an empty queue says so rather than printing a header over nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await q(`DELETE FROM reports`);
  const out = await captured(() => queue());
  assert.match(out, /no open reports/i);
});

test("the queue prints what decides the outcome, and the caveat that qualifies it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await q(`DELETE FROM reports`);
  const [a, b] = [await account(), await account()];
  const id = await DB.createReport({
    reporterId: a, reportedId: b, conversationHash: friendshipHash(a, b),
    category: "harassment", note: "they would not stop",
    excerpt: "the thing they said",
  });

  const out = await captured(() => queue());
  assert.match(out, new RegExp(id), "the id an operator has to quote is not printed");
  assert.match(out, /harassment/);
  assert.match(out, /they would not stop/, "the reporter's note is what says what happened");
  assert.match(out, /the thing they said/, "…and the excerpt is what there is to look at");

  // The caveat has to sit WITH the excerpt. A note at the top of the output is a
  // note somebody scrolls past on the fortieth report.
  const atExcerpt = out.slice(0, out.indexOf("the thing they said"));
  assert.match(atExcerpt.slice(-300), /UNVERIFIED/,
    "the excerpt is printed without the line saying it cannot be verified");

  // No full ids. An operator quoting a log line into a ticket should not be
  // pasting the accounts in full.
  assert.ok(!out.includes(a) && !out.includes(b), "full account ids are printed");
});

test("a repeat subject is counted, because one report is not a pattern", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await q(`DELETE FROM reports`);
  const subject = await account();
  for (let i = 0; i < 3; i++) {
    const reporter = await account();
    await DB.createReport({
      reporterId: reporter, reportedId: subject,
      conversationHash: friendshipHash(reporter, subject), category: "spam",
    });
  }
  const out = await captured(() => queue());
  assert.match(out, /3 reports against this account/,
    "the count is the only question the table answers that one report cannot");
});

test("reading the queue deletes reports whose 90 days are up", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The published promise, not a space optimisation. An operator must not be
  // shown an expired report because the ops sweep happened not to be running.
  await q(`DELETE FROM reports`);
  const [a, b] = [await account(), await account()];
  const lapsed = await DB.createReport({
    reporterId: a, reportedId: b, conversationHash: friendshipHash(a, b),
    category: "spam", excerpt: "should not be readable any more",
  });
  await q(`UPDATE reports SET expires_at = now() - interval '1 day' WHERE id = $1::uuid`, [lapsed]);

  const out = await captured(() => queue());
  assert.doesNotMatch(out, /should not be readable any more/,
    "an expired report was shown to an operator");
  assert.equal((await q(`SELECT 1 FROM reports WHERE id = $1::uuid`, [lapsed])).rows.length, 0,
    "…and it is still in the table, so the deletion is not happening at all");
});

test("a decision is recorded once, and a second operator cannot quietly overwrite it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await q(`DELETE FROM reports`);
  const [a, b] = [await account(), await account()];
  const id = await DB.createReport({
    reporterId: a, reportedId: b, conversationHash: friendshipHash(a, b), category: "spam",
  });

  assert.equal(await captured(() => resolve(id, "warned")).then(() => true), true);
  const row = await q<{ disposition: string; handled_at: string | null }>(
    `SELECT disposition, handled_at::text FROM reports WHERE id = $1::uuid`, [id]);
  assert.equal(row.rows[0]!.disposition, "warned");
  assert.ok(row.rows[0]!.handled_at, "handled_at is what takes it out of the queue");

  const second = await captured(() => resolve(id, "banned"));
  assert.match(second, /already handled|not an open report/i);
  const after = await q<{ disposition: string }>(
    `SELECT disposition FROM reports WHERE id = $1::uuid`, [id]);
  assert.equal(after.rows[0]!.disposition, "warned", "the first decision was overwritten");

  // …and it leaves the queue.
  assert.match(await captured(() => queue()), /no open reports/i);
});

test("a disposition the column would refuse is refused here first", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Two lists that can drift would fail at the CHECK constraint, as a 500-shaped
  // crash, after the operator was told the decision was recorded.
  const [a, b] = [await account(), await account()];
  const id = await DB.createReport({
    reporterId: a, reportedId: b, conversationHash: friendshipHash(a, b), category: "spam",
  });
  const out = await captured(() => resolve(id, "deleted-them"));
  assert.match(out, /unknown disposition/i);
  assert.equal((await q(`SELECT 1 FROM reports WHERE id = $1::uuid AND handled_at IS NOT NULL`,
    [id])).rows.length, 0, "a refused disposition still marked the report handled");

  for (const d of DISPOSITIONS) {
    const fresh = await DB.createReport({
      reporterId: a, reportedId: b, conversationHash: friendshipHash(a, b), category: "spam",
    });
    await captured(() => resolve(fresh, d));
    assert.equal((await q<{ disposition: string }>(
      `SELECT disposition FROM reports WHERE id = $1::uuid`, [fresh])).rows[0]!.disposition, d,
      `the column refused "${d}", which this script offers`);
  }
});
