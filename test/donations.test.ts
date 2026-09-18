// Donations: the webhook, and the supporters table it writes.
//
// There was NO end-to-end test of /stripe/webhook at all while it was the
// entitlement path — signature verification, customer adoption and the
// revocation fan-out were all unexercised. The handler is small enough now to
// cover properly, and what it does is consequential in a different way: it is
// the single place a completed payment touches this database, so it is where
// the claim "no email address enters this server" is either true or not.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";
import { q } from "../services/db/pg";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";

// Without this the log volume interleaves with node:test's IPC and fails the
// whole FILE with "Unable to deserialize cloned data".
setLogLevel("silent");

const NAMES = ["Ada L.", "ada l.", "Grace H."];

async function clean() {
  await q(`DELETE FROM supporters WHERE name_key = ANY($1::text[])`,
    [NAMES.map((n) => n.trim().toLowerCase())]);
}

test("an opt-in name is recorded once, however many times it donates", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await clean();

  await DB.recordSupporter("Ada L.");
  await DB.recordSupporter("Grace H.");
  // A repeat donor is one supporter, not two. The dedupe is case-insensitive
  // because the name IS the key — there is nothing else held to recognise them
  // by, so "ada l." and "Ada L." must not become two people.
  await DB.recordSupporter("ada l.");

  const listed = (await DB.listSupporters()).filter((s) => NAMES.includes(s.name) || s.name === "ada l.");
  assert.equal(listed.length, 2, "two distinct supporters");
  await clean();
});

test("a blank or whitespace name records nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  await clean();
  const before = (await DB.listSupporters()).length;
  await DB.recordSupporter("");
  await DB.recordSupporter("   ");
  assert.equal((await DB.listSupporters()).length, before,
    "recognition is opt-in: no name means no row");
});

test("the supporters table holds nothing that could identify a donor", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The point of the whole change, expressed as a schema assertion. If a column
  // is ever added here that could be joined to a payment or an account — a
  // customer id, an email, a hash of one, an account id, an amount — this fails,
  // and it should: the privacy claim on the website depends on it.
  const cols = await q<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'supporters'`
  );
  assert.deepEqual(
    cols.rows.map((r) => r.column_name).sort(),
    ["display_name", "first_seen", "name_key"]
  );
});

test("the claim tables are gone, not merely unused", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Dormant tables holding email hashes would keep the old privacy story true
  // only by accident. 005_donations.sql drops them; this is what says so.
  const gone = ["subscriptions", "subscription_customers", "subscription_claims", "otp"];
  const found = await q<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = ANY($1::text[])`,
    [gone]
  );
  assert.deepEqual(found.rows.map((r) => r.table_name), [],
    "the paywall's tables must not survive the paywall");
});

test.after(async () => {
  if (await pgAvailable()) await clean();
  await closePg();
});
