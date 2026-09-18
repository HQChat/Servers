// ASVS-3 / ASVS-4: the counters behind `/auth/init`'s limits and the
// failed-proof alarm. Both are one row with a window, and both are easy to get
// wrong in the same way — a window re-armed on every hit turns a fixed window
// into an unbounded one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

test("a counter increments and reports the count after the hit", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const key = `test:${Date.now()}:${Math.random()}`;
  assert.equal(await DB.bumpCounter(key, 60), 1);
  assert.equal(await DB.bumpCounter(key, 60), 2);
  assert.equal(await DB.bumpCounter(key, 60), 3);
  await DB.clearCounter(key);
});

test("the window is set once, not re-armed by later hits", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // A window re-armed on every hit never closes, so a slow attacker never trips
  // the limit and never falls out of it either.
  const key = `test:${Date.now()}:${Math.random()}`;
  await DB.bumpCounter(key, 100);
  const first = await DB.counterTtl(key);
  await DB.bumpCounter(key, 5);          // a shorter window must not shrink it
  const second = await DB.counterTtl(key);
  assert.ok(second > 5, `expected the original window to stand, got ttl ${second}`);
  assert.ok(Math.abs(second - first) <= 1, "the window moved when it should not have");
  await DB.clearCounter(key);
});

test("clearing a counter starts the run again", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const key = `test:${Date.now()}:${Math.random()}`;
  await DB.bumpCounter(key, 60);
  await DB.bumpCounter(key, 60);
  await DB.clearCounter(key);
  assert.equal(await DB.bumpCounter(key, 60), 1, "a success must reset the failure run");
  await DB.clearCounter(key);
});

test.after(closePg);
