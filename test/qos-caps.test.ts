// The caps that replaced the paywall.
//
// A subscription used to bound the friend graph: without one, /friends/invite
// answered 402 and the graph could not grow at all. Nothing bounded it for a
// subscriber, because paying was assumed to be the deterrent. Both halves of
// that are gone, so these ceilings are the only thing standing between one
// signup and unbounded server work.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";
import { peerId } from "../lib/identity";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";

setLogLevel("silent");

const PK = (b: string) => b.repeat(64);
const ME = peerId(PK("1a"));
const A = peerId(PK("2b"));
const B = peerId(PK("3c"));

test("countFriends is what the cap reads, and it counts both sides", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  for (const id of [ME, A, B]) await DB.deleteUser(id).catch(() => {});
  await DB.ensureUser(ME, PK("1a"));
  await DB.ensureUser(A, PK("2b"));
  await DB.ensureUser(B, PK("3c"));

  assert.equal(await DB.countFriends(ME), 0);

  // A friendship is one row naming both members, so it must count for each of
  // them — a cap that only saw the rows a user created would let an account be
  // pushed past its ceiling by other people accepting.
  await DB.createFriendship(ME, A);
  assert.equal(await DB.countFriends(ME), 1);
  assert.equal(await DB.countFriends(A), 1);

  await DB.createFriendship(B, ME);
  assert.equal(await DB.countFriends(ME), 2, "counted regardless of who initiated");

  for (const id of [ME, A, B]) await DB.deleteUser(id);
  assert.equal(await DB.countFriends(ME), 0);
});

test("the daily invite counter windows and resets", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Reuses `rate_counters`, the table already behind /auth/init — no new
  // storage, and the same expiry semantics.
  const key = `invite:day:${ME}`;
  await DB.clearCounter(key);
  assert.equal(await DB.bumpCounter(key, 86400), 1);
  assert.equal(await DB.bumpCounter(key, 86400), 2);
  await DB.clearCounter(key);
  assert.equal(await DB.bumpCounter(key, 86400), 1, "a cleared window starts over");
  await DB.clearCounter(key);
});

test("the refusal codes are not 402", async (t) => {
  // Not a database test — a statement about the contract, kept next to the caps
  // it constrains. The app treats 402 as "fall back to the free door" and
  // re-authenticates; a user who merely hit a daily invite limit would lose
  // every friend topic for the trouble. api/main.ts must answer 409 and 429.
  const source = require("fs").readFileSync(
    require("path").join(__dirname, "..", "api", "main.ts"), "utf8"
  ) as string;
  assert.match(source, /FRIEND_LIMIT/);
  assert.match(source, /"RATE_LIMITED"/);

  // Comments stripped first — the code here explains at length why it is NOT
  // 402, and a naive scan matches its own rationale.
  const code = source.split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join("\n");
  const from = code.indexOf('url === "/friends/invite"');
  const to = code.indexOf('url === "/friends/cancel"');
  assert.ok(from > 0 && to > from, "found the invite and accept routes");
  assert.doesNotMatch(code.slice(from, to), /\b402\b/,
    "no 402 may be produced on the friend paths");
});

test.after(async () => {
  if (await pgAvailable()) {
    for (const id of [ME, A, B]) await DB.deleteUser(id).catch(() => {});
  }
  await closePg();
});
