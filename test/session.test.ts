// The session model that LAT-1 and ASVS-1 turned on.
//
// Sliding sessions are easy to get subtly wrong in the two directions that
// matter: a session that never slides costs the user a biometric prompt on a
// timer, and one that slides without a cap never dies. Both are asserted here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

// A client id, which is what a session is keyed on: 64 lowercase hex. The old
// `"aa".repeat(32)` happened to be the same width, which is why this file needs
// no other change — and why it would not have caught the switch on its own. It
// is spelled out as an id deliberately.
const ID = "aa".repeat(32);

// These need a real database — see test/pg-helper.ts for why the probe skips
// rather than fails.

test("a fresh session resolves to its client id and scope", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const token = await DB.mintSessionToken(ID, "free", 60);
  assert.deepEqual(await DB.resolveSessionToken(token), { id: ID, scope: "free" });
});

test("the scope a session was minted with is the scope it keeps", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Nothing re-derives an entitlement per request, so this IS the paywall: if
  // the value did not survive a round trip, /friends/invite would read wrong.
  const token = await DB.mintSessionToken(ID, "premium", 60);
  assert.equal((await DB.resolveSessionToken(token))?.scope, "premium");
});

test("using a session slides its idle timeout forward", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Mint with a deliberately short idle window, then use it: the slide should
  // push the TTL back up to the default, not leave it at 2 seconds.
  const token = await DB.mintSessionToken(ID, "free", 2);
  assert.equal((await DB.resolveSessionToken(token))?.id, ID);
  const ttl = await DB.sessionTtl(token);
  assert.ok(ttl > 2, `expected the TTL to slide past its original 2s, got ${ttl}`);
});

test("an unknown or revoked token resolves to nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const token = await DB.mintSessionToken(ID, "free", 60);
  await DB.revokeSessionToken(token);
  assert.equal(await DB.resolveSessionToken(token), null);
  assert.equal(await DB.resolveSessionToken("not-a-token"), null);
});

test("revoking an identity ends every live session it holds", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // What makes a cancelled subscription bite now rather than in thirty days.
  // An id of its own, because the other tests in this file mint against ID and
  // revokeAllSessions ends every session that identity holds.
  const loneId = "ee".repeat(32);
  const a = await DB.mintSessionToken(loneId, "premium", 60);
  const b = await DB.mintSessionToken(loneId, "premium", 60);
  assert.equal(await DB.revokeAllSessions(loneId), 2);
  assert.equal(await DB.resolveSessionToken(a), null);
  assert.equal(await DB.resolveSessionToken(b), null);
});

test("a session past its absolute cap is refused and deleted", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Backdate `iat` beyond the cap: sliding must not resurrect it.
  const token = await DB.mintSessionTokenAt(ID, 60, 1);
  assert.equal(await DB.resolveSessionToken(token), null);
  assert.equal(await DB.sessionTtl(token), -2, "the row should be gone, not merely refused");
});

test.after(closePg);
