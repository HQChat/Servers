// The friend graph, the prekey pool and account deletion — the routes that
// decide who may read what.
//
// `api/main.ts` sat at 78.8% line and 68.8% function, and the uncovered part was
// not the edges: it was every route's SUCCESS path. The existing api-routes.test
// file could only exercise refusals, because the moment a friend route succeeds
// it calls out to EMQX — `notifyGraphChanged`, `revokeTopic`, `kick` — and there
// is no broker in a unit run. So the half that maintains the topic ACL, the
// single mechanism separating one conversation from another, was untested.
//
// EMQX is stubbed here and its calls are RECORDED, because on these routes the
// call to the broker is not a side effect of the behaviour — it IS the
// behaviour. `/friends/remove` that updates the database and fails to revoke the
// topic leaves the removed peer's open subscription delivering, which is exactly
// what happened on this deployment: both arguments used to be 14 kB public keys,
// the admin URL came to ~29 kB, and EMQX answered 414 every single time.
//
// The database is real.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as crypto from "node:crypto";
import Module from "node:module";
import { q } from "../services/db/pg";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";

setLogLevel("silent");

// --- the broker double ------------------------------------------------------------

interface EmqxCall { fn: string; args: unknown[] }

const emqxCalls: EmqxCall[] = [];
let emqxThrows: Error | null = null;

const emqxPath = require.resolve("../lib/emqx");
const REAL_EMQX = require(emqxPath);            // captured before the stub displaces it

const record = (fn: string) => async (...args: unknown[]) => {
  emqxCalls.push({ fn, args });
  if (emqxThrows) throw emqxThrows;
  return undefined as any;
};

const emqxStub = {
  EMQX: {
    get enabled() { return true; },
    kick: record("kick"),
    unsubscribe: record("unsubscribe"),
    revokeTopic: record("revokeTopic"),
    notifyGraphChanged: record("notifyGraphChanged"),
  },
};
{
  const m = new Module(emqxPath, module);
  m.filename = emqxPath; m.loaded = true; m.exports = emqxStub;
  require.cache[emqxPath] = m;
}

// Required AFTER the stub, so the handler closes over it.
const { createApiHandler } = require("../api/main") as typeof import("../api/main");
const { DB } = require("../services/db/api") as typeof import("../services/db/api");
const { friendshipHash } = require("../lib/crypto-utils") as typeof import("../lib/crypto-utils");
const { peerId } = require("../lib/identity") as typeof import("../lib/identity");

// --- harness -----------------------------------------------------------------------

interface Reply { status: number; body: any; text: string }

const handler = createApiHandler();

async function call(
  method: string, path: string, body?: unknown, token?: string,
): Promise<Reply> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as any).port;
  try {
    return await new Promise<Reply>((resolve, reject) => {
      const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
      const req = http.request(
        { port, host: "127.0.0.1", method, path, agent: false, headers: {
          ...(payload ? { "content-type": "application/json" } : {}),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        } },
        (res) => {
          const parts: Buffer[] = [];
          res.on("data", (d: Buffer) => parts.push(d));
          res.on("end", () => {
            const text = Buffer.concat(parts).toString("utf8");
            let parsed: any;
            try { parsed = JSON.parse(text); } catch { /* `text` carries it */ }
            resolve({ status: res.statusCode!, body: parsed, text });
          });
        },
      );
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  } finally {
    server.close();
  }
}

const created: string[] = [];

interface Account { id: string; token: string; username: string }

/** A registered account with a session, made directly rather than through the
 *  handshake — this file is about what happens after login, and the handshake
 *  has its own file. */
async function account(): Promise<Account> {
  // The id is DERIVED, not chosen: `users` carries
  // CHECK (encode(pk_digest(identity_pk), 'hex') = id), so the database itself
  // refuses a row whose id does not name its key. Inventing the two
  // independently — which is what I tried first — fails at the constraint.
  const pkHex = crypto.randomBytes(64).toString("hex");
  const id = peerId(pkHex);
  const username = `t${crypto.randomBytes(6).toString("hex")}`;
  await DB.ensureUser(id, pkHex);
  await DB.setUsername(id, username);
  await DB.grantSelfTopics(id);
  created.push(id);
  return { id, token: await DB.mintSessionToken(id, "free"), username };
}

/** Two accounts that are already friends, with the ACL granted. */
async function friends(): Promise<[Account, Account]> {
  const a = await account();
  const b = await account();
  await DB.createFriendship(a.id, b.id);
  await DB.grantFriendTopic(a.id, b.id);
  return [a, b];
}

async function cleanup(): Promise<void> {
  emqxCalls.length = 0;
  emqxThrows = null;
  if (!created.length) return;
  const ids = [...new Set(created)];
  for (const sql of [
    `DELETE FROM mqtt_acl WHERE id = ANY($1::text[])`,
    `DELETE FROM mqtt_tokens WHERE id = ANY($1::text[])`,
    `DELETE FROM sessions WHERE id = ANY($1::text[])`,
    `DELETE FROM invites WHERE from_id = ANY($1::text[]) OR to_id = ANY($1::text[])`,
    `DELETE FROM friendships WHERE id_a = ANY($1::text[]) OR id_b = ANY($1::text[])`,
    `DELETE FROM prekeys_onetime WHERE id = ANY($1::text[])`,
    `DELETE FROM prekeys_medium WHERE id = ANY($1::text[])`,
    `DELETE FROM push_tokens WHERE id = ANY($1::text[])`,
    `DELETE FROM blocks WHERE blocker_id = ANY($1::text[]) OR blocked_id = ANY($1::text[])`,
    `DELETE FROM reports WHERE reporter_id = ANY($1::text[]) OR reported_id = ANY($1::text[])`,
    `DELETE FROM users WHERE id = ANY($1::text[])`,
  ]) {
    try { await q(sql, [ids]); } catch { /* a column this schema does not have */ }
  }
  await q(`DELETE FROM rate_counters WHERE key LIKE 'invite:day:%' OR key LIKE 'report:day:%'`);
  created.length = 0;
}

test.afterEach(async () => { await cleanup(); });
test.after(async () => { await cleanup(); await closePg(); });

const called = (fn: string) => emqxCalls.filter((c) => c.fn === fn);

// --- the stub is not a fiction -----------------------------------------------------------

test("the stubbed broker client still matches the real one", () => {
  for (const fn of ["kick", "unsubscribe", "revokeTopic", "notifyGraphChanged"] as const) {
    assert.equal(typeof REAL_EMQX.EMQX[fn], "function", `EMQX.${fn} is gone`);
    assert.equal(REAL_EMQX.EMQX[fn].length, (emqxStub.EMQX as any)[fn].length === 0 ? REAL_EMQX.EMQX[fn].length : 0,
      "arity is not comparable through a rest-args stub; presence is what is checked");
  }
  assert.equal(typeof REAL_EMQX.EMQX.enabled, "boolean");
});

// --- inviting -----------------------------------------------------------------------------

test("an invite reaches the recipient, and they are told it happened", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  const b = await account();

  const res = await call("POST", "/friends/invite", { to: b.username }, a.token);
  assert.equal(res.status, 200, res.text);

  const invites = await call("GET", "/friends/invites", undefined, b.token);
  assert.equal(invites.status, 200, invites.text);
  assert.equal(invites.body.invites.length, 1, JSON.stringify(invites.body));

  // The recipient has no other way to learn an invite exists — nothing pushed
  // graph changes, so one sat unseen until their next poll. This nudge is what
  // makes it appear without a manual refresh.
  const nudges = called("notifyGraphChanged");
  assert.equal(nudges.length, 1, "the recipient was not notified");
  assert.deepEqual(nudges[0]!.args[0], [b.id]);
});

test("an invite to a handle nobody holds notifies nobody", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  await call("POST", "/friends/invite", { to: "nobody-holds-this-handle" }, a.token);
  assert.deepEqual(called("notifyGraphChanged"), [],
    "a nudge for an unresolvable handle would be a request per junk invite");
});

test("the daily invite ceiling refuses with 429, not 402", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Deliberately not 402: the app reads 402 as "fall back to the free door" and
  // re-authenticates, so a user who hit a daily limit would silently lose their
  // friend topics for the trouble.
  const a = await account();
  const statuses: number[] = [];
  for (let i = 0; i < 22; i++) {
    const b = await account();
    statuses.push((await call("POST", "/friends/invite", { to: b.username }, a.token)).status);
  }
  assert.equal(statuses.filter((s) => s === 200).length, 20, statuses.join(","));
  const refused = statuses.slice(20);
  assert.deepEqual(refused, [429, 429], statuses.join(","));
});

test("the ceiling is counted before the body is read", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `bumpCounter` runs before `readJson`, so a rate-limited caller is refused
  // without the server parsing anything it sent. A limiter behind the body
  // parser still pays for every request it refuses.
  const a = await account();
  for (let i = 0; i < 20; i++) {
    const b = await account();
    await call("POST", "/friends/invite", { to: b.username }, a.token);
  }
  const res = await call("POST", "/friends/invite", { nonsense: true }, a.token);
  assert.equal(res.status, 429, `a missing "to" would be 400 if the body were read first: ${res.text}`);
});

// --- accepting, which is where the ACL is granted ---------------------------------------------

test("accepting an invite grants the conversation topic to BOTH members", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The friend rows alone are invisible to MQTT. The ACL entry is what lets
  // either side use the shared topic — without it both clients authenticate and
  // then cannot subscribe to the conversation they just created.
  const a = await account();
  const b = await account();
  await call("POST", "/friends/invite", { to: b.username }, a.token);
  emqxCalls.length = 0;

  const res = await call("POST", "/friends/accept", { from: a.username }, b.token);
  assert.equal(res.status, 200, res.text);
  assert.equal(res.body.ok, true);

  const topic = `c/${friendshipHash(a.id, b.id)}`;
  const acl = await q<{ id: string; topic: string }>(
    `SELECT id, topic FROM mqtt_acl WHERE topic = $1`, [topic],
  );
  const holders = acl.rows.map((r) => r.id).sort();
  assert.deepEqual(holders, [a.id, b.id].sort(), `only ${holders.length} member holds the topic`);

  // Both sides are nudged, and AFTER the grant. The inviter is the one that
  // matters: they invited a HANDLE, so their contact row holds no client id
  // until a directory sync fills it in — and the accepter greets immediately, so
  // that greeting used to reach the inviter before they knew who sent it.
  const nudged = called("notifyGraphChanged");
  assert.equal(nudged.length, 1);
  assert.deepEqual([...(nudged[0]!.args[0] as string[])].sort(), [a.id, b.id].sort());
});

test("accepting an invite that was never sent creates nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  const b = await account();
  const res = await call("POST", "/friends/accept", { from: a.username }, b.token);
  assert.equal(res.status, 400);
  assert.equal(res.body.ok, false);
  assert.equal((await q(`SELECT 1 FROM mqtt_acl WHERE topic = $1`, [`c/${friendshipHash(a.id, b.id)}`])).rows.length, 0);
  assert.deepEqual(called("notifyGraphChanged"), [], "nothing happened, so nobody is told");
});

// --- removing, which is where the ACL must come back -------------------------------------------

test("removing a friend revokes the topic in the database AND at the broker", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Two separate revocations, and both are needed. The database row blocks the
  // NEXT authorization check; authorization is checked at SUBSCRIBE, so a
  // subscription that is already open keeps delivering until the client
  // disconnects for its own reasons. The broker call is what ends it now.
  const [a, b] = await friends();
  const topic = `c/${friendshipHash(a.id, b.id)}`;
  assert.ok((await q(`SELECT 1 FROM mqtt_acl WHERE topic = $1`, [topic])).rows.length > 0, "setup");
  emqxCalls.length = 0;

  const res = await call("POST", "/friends/remove", { peer: b.username }, a.token);
  assert.equal(res.status, 200, res.text);

  assert.equal((await q(`SELECT 1 FROM mqtt_acl WHERE topic = $1`, [topic])).rows.length, 0,
    "the ACL rows survive the unfriend");

  const revokes = called("revokeTopic");
  assert.equal(revokes.length, 1, "the open subscription was never dropped");
  assert.deepEqual(revokes[0]!.args, [a.id, b.id, topic]);
  // The URL this builds used to be ~29 kB of public keys and EMQX answered 414
  // every single time. Ids are 64 characters now, and this is what keeps them so.
  for (const arg of revokes[0]!.args.slice(0, 2) as string[]) {
    assert.equal(arg.length, 64, `a ${arg.length}-character argument would rebuild the 414`);
  }
  assert.deepEqual([...(called("notifyGraphChanged")[0]!.args[0] as string[])].sort(), [a.id, b.id].sort());
});

test("removing someone you are not friends with revokes nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  const b = await account();
  const res = await call("POST", "/friends/remove", { peer: b.username }, a.token);
  assert.equal(res.status, 400);
  assert.deepEqual(called("revokeTopic"), [], "a non-friendship must not touch the ACL");
});

test("a broker that refuses does not undo the unfriend", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Best effort by design: the unfriend has already succeeded in the database
  // and must not be rolled back because the broker is unwell. Today that surfaces
  // as a 500 to the caller — the database change stands, so a retry is safe, and
  // pinning it means a future change to swallow the error is deliberate.
  const [a, b] = await friends();
  const topic = `c/${friendshipHash(a.id, b.id)}`;
  emqxThrows = new Error("emqx unreachable");
  const res = await call("POST", "/friends/remove", { peer: b.username }, a.token);
  assert.equal(res.status, 500, res.text);
  assert.equal(res.body.error, "INTERNAL", "the broker's message must not reach the caller");
  assert.equal((await q(`SELECT 1 FROM mqtt_acl WHERE topic = $1`, [topic])).rows.length, 0,
    "the database revocation must stand even when the broker call fails");
});

// --- cancelling ----------------------------------------------------------------------------------

test("an invite can be withdrawn by the sender and declined by the recipient", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // One route serves both, and only one of the two can match a real pending
  // invite — so the same call means "withdraw" to a sender and "decline" to a
  // recipient without either being able to act on the other's behalf.
  const a = await account();
  const b = await account();

  await call("POST", "/friends/invite", { to: b.username }, a.token);
  const withdrawn = await call("POST", "/friends/cancel", { peer: b.username }, a.token);
  assert.equal(withdrawn.status, 200, withdrawn.text);
  assert.equal((await call("GET", "/friends/invites", undefined, b.token)).body.invites.length, 0);

  await call("POST", "/friends/invite", { to: b.username }, a.token);
  const declined = await call("POST", "/friends/cancel", { peer: a.username }, b.token);
  assert.equal(declined.status, 200, declined.text);
  assert.equal((await call("GET", "/friends/invites", undefined, b.token)).body.invites.length, 0);
});

test("cancelling nothing is a 400 and notifies nobody", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  const b = await account();
  const res = await call("POST", "/friends/cancel", { peer: b.username }, a.token);
  assert.equal(res.status, 400);
  assert.deepEqual(called("notifyGraphChanged"), []);
});

// --- prekeys ---------------------------------------------------------------------------------------

const KEY = (seed: number) => seed.toString(16).padStart(2, "0").repeat(7237);

test("a one-time prekey is handed out once and never again", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The whole point of the one-time pool. A key served twice means two
  // conversations derive from the same ephemeral secret, which is the property
  // the pool exists to avoid.
  const [a, b] = await friends();
  const upload = await call("POST", "/prekeys", {
    medium: KEY(0xaa),
    oneTime: [{ id: 1, prekey: KEY(0xb1) }, { id: 2, prekey: KEY(0xb2) }],
  }, b.token);
  assert.equal(upload.status, 200, upload.text);
  assert.equal(upload.body.accepted, 2);

  const seen = new Set<number>();
  for (let i = 0; i < 2; i++) {
    const res = await call("POST", "/prekeys/claim", { peer: b.username }, a.token);
    assert.equal(res.status, 200, res.text);
    assert.equal(res.body.medium, KEY(0xaa), "the medium-term key comes with every claim");
    assert.ok(res.body.oneTime, `claim ${i} returned no one-time key`);
    assert.ok(!seen.has(res.body.oneTime.id), `one-time key ${res.body.oneTime.id} was served twice`);
    seen.add(res.body.oneTime.id);
  }
  assert.equal(seen.size, 2);
});

test("an exhausted pool falls back to the medium-term key rather than failing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The server is untrusted here by design: it can withhold one-time keys to
  // force the weaker fallback, but it cannot read anything, because the
  // initiator also encapsulates to the peer's PINNED identity key. So an empty
  // pool is a degraded handshake, not a refused one.
  const [a, b] = await friends();
  await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: [] }, b.token);

  const res = await call("POST", "/prekeys/claim", { peer: b.username }, a.token);
  assert.equal(res.status, 200, res.text);
  assert.equal(res.body.medium, KEY(0xaa));
  assert.equal(res.body.oneTime, null, "an empty pool must not invent a key");
});

test("a peer with no bundle at all is a 404", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // No medium-term key means no bundle. A one-time key is an addition to it,
  // never a substitute — an initiator with only a one-time key could not derive
  // the same root as the responder.
  const [a, b] = await friends();
  const res = await call("POST", "/prekeys/claim", { peer: b.username }, a.token);
  assert.equal(res.status, 404);
  assert.equal(res.body.error, "NO_PREKEYS");
});

test("a stranger cannot drain a pool, however many sessions they hold", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Friendship is the authorization. Without it anyone with a session could
  // empty a stranger's one-time pool — a cheap way to force every one of their
  // future conversations onto the reusable medium-term key.
  const victim = await account();
  const stranger = await account();
  await call("POST", "/prekeys", {
    medium: KEY(0xaa), oneTime: [{ id: 1, prekey: KEY(0xb1) }],
  }, victim.token);

  const res = await call("POST", "/prekeys/claim", { peer: victim.username }, stranger.token);
  assert.equal(res.status, 403);
  assert.equal(res.body.error, "NOT_FRIENDS");
  assert.equal((await call("GET", "/prekeys/count", undefined, victim.token)).body.remaining, 1,
    "the refused claim consumed a key anyway");
});

test("an upload larger than the cap is refused whole", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Eight keeps the body near 130 kB, half of MAX_BODY_BYTES. A key travels as
  // hex, so it costs 2 x 7237 characters on the wire — the byte count is not the
  // wire cost, which is the easy way to size this wrong.
  const a = await account();
  const nine = Array.from({ length: 9 }, (_, i) => ({ id: i, prekey: KEY(0xb0 + i) }));
  const res = await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: nine }, a.token);
  assert.equal(res.status, 400, res.text);
  assert.equal(res.body.error, "TOO_MANY_PREKEYS");
  assert.equal((await call("GET", "/prekeys/count", undefined, a.token)).body.remaining, 0,
    "a refused upload must not store the first eight");
});

test("a malformed prekey entry names the index that is wrong", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  for (const bad of [
    { id: -1, prekey: KEY(0xb1) },
    { id: 1.5, prekey: KEY(0xb1) },
    { id: "1", prekey: KEY(0xb1) },
    { id: 1, prekey: "not hex" },
    { id: 1 },
  ]) {
    const res = await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: [bad] }, a.token);
    assert.equal(res.status, 400, `${JSON.stringify(bad).slice(0, 40)} -> ${res.status}`);
    assert.ok(/oneTime\[0\]|prekey/.test(res.body.message ?? res.body.error), res.text);
  }
});

test("/prekeys/count reports the caller's own pool and the target", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  await call("POST", "/prekeys", {
    medium: KEY(0xaa),
    oneTime: [{ id: 5, prekey: KEY(0xb1) }, { id: 9, prekey: KEY(0xb2) }],
  }, a.token);
  const res = await call("GET", "/prekeys/count", undefined, a.token);
  assert.equal(res.body.remaining, 2);
  assert.equal(res.body.maxId, 9, "so a client knows where to continue numbering");
  assert.equal(res.body.target, 8);
});

// --- account deletion ---------------------------------------------------------------------------------

test("deleting an account leaves no row anywhere, and ends the live connection", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Everything in the database stops the NEXT connect. The kick is what ends the
  // current one — otherwise a deleted account keeps a live session, and its
  // queued backlog, for as long as the connection happens to last.
  //
  // TWO sessions on purpose. The route also calls `revokeSessionToken(bearer)`,
  // which would kill only the one that made the request; `deleteUser` deletes
  // every table by hand in a transaction — there are no FK cascades in this
  // schema — so the second session must die too. That is the property worth
  // asserting, and it is also what makes the route's explicit
  // `revokeSessionToken`/`revokeMqttAuth` calls redundant: verified by removing
  // each, which changes nothing observable. They are cheap belt-and-braces, not
  // load-bearing, and this test says so rather than appearing to cover them.
  const [a, b] = await friends();
  await DB.setPushToken(a.id, "ios", "a".repeat(64));
  await DB.mintMqttToken(a.id);
  await call("POST", "/prekeys", { medium: KEY(0xaa), oneTime: [{ id: 1, prekey: KEY(0xb1) }] }, a.token);
  const otherSession = await DB.mintSessionToken(a.id, "free");

  // Moderation state on both sides, so the exception below is asserted against
  // rows that actually exist rather than against an empty table.
  await DB.block(a.id, b.id);
  await DB.block(b.id, a.id);
  const hash = friendshipHash(a.id, b.id);
  const filedByA = await DB.createReport({
    reporterId: a.id, reportedId: b.id, conversationHash: hash,
    category: "spam", excerpt: "a message a reported",
  });
  const filedAboutA = await DB.createReport({
    reporterId: b.id, reportedId: a.id, conversationHash: hash,
    category: "harassment", excerpt: "a message b reported",
  });
  emqxCalls.length = 0;

  const res = await call("POST", "/account/delete", {}, a.token);
  assert.equal(res.status, 200, res.text);

  // A new table that forgets to appear in `deleteUser` is the silent regression
  // this guards — and the App Store evidence for account deletion rests on it.
  //
  // `reports` is NOT in this list, and that is the one deliberate hole in "no
  // row anywhere". It is spelled out rather than omitted, because a reader who
  // finds a table missing from this loop should be able to tell a decision from
  // an oversight — an oversight here is exactly the regression the loop exists
  // to catch. The two assertions under it pin both halves of the rule.
  for (const [table, col] of [
    ["users", "id"], ["sessions", "id"], ["mqtt_tokens", "id"], ["mqtt_acl", "id"],
    ["push_tokens", "id"], ["prekeys_medium", "id"], ["prekeys_onetime", "id"],
    ["friendships", "id_lo"],
    // Both directions: a block this user placed and a block placed on them.
    ["blocks", "blocker_id"], ["blocks", "blocked_id"],
  ] as const) {
    const rows = await q(`SELECT 1 FROM ${table} WHERE ${col} = $1`, [a.id]);
    assert.equal(rows.rows.length, 0,
      `${table}.${col} still holds a row for the deleted account`);
  }

  // The exception, and its limit. A report ABOUT the deleted user survives —
  // otherwise deleting an account erases the complaints against it, which makes
  // deletion the abuse-evasion button. A report BY them keeps its content and
  // loses its filer, because who complained is this user's own footprint and the
  // message they handed in is not. Neither row's clock moves: both still expire
  // 90 days after they were filed. See migrations/006_reports.sql §1.
  const about = await q<{ reporter_id: string | null; message_excerpt: string | null }>(
    `SELECT reporter_id, message_excerpt FROM reports WHERE id = $1::uuid`, [filedAboutA]);
  assert.equal(about.rows.length, 1,
    "a report ABOUT the deleted account vanished with it — deletion is now an abuse-evasion tool");
  assert.equal(about.rows[0]!.reporter_id, b.id, "…and it still names who filed it");

  const by = await q<{ reporter_id: string | null; message_excerpt: string | null }>(
    `SELECT reporter_id, message_excerpt FROM reports WHERE id = $1::uuid`, [filedByA]);
  assert.equal(by.rows.length, 1, "a report FILED by the deleted account was purged with it");
  assert.equal(by.rows[0]!.reporter_id, null,
    "…but it must no longer say who filed it: that half IS their footprint");
  assert.equal(by.rows[0]!.message_excerpt, "a message a reported",
    "…and its content stands, because it is about somebody else");

  const kicks = called("kick");
  assert.equal(kicks.length, 1, "the live connection was left open");
  assert.deepEqual(kicks[0]!.args, [a.id]);

  // BOTH sessions, not just the one that asked.
  assert.equal((await call("GET", "/friends", undefined, a.token)).status, 401, "the deleting session");
  assert.equal((await call("GET", "/friends", undefined, otherSession)).status, 401,
    "a second device's session outlived the account");

  // The friend is untouched — their account is not ours to delete — and their
  // dangling grant on this conversation is gone.
  assert.equal((await q(`SELECT 1 FROM users WHERE id = $1`, [b.id])).rows.length, 1);
  assert.equal(
    (await q(`SELECT 1 FROM mqtt_acl WHERE id = $1 AND topic = $2`,
      [b.id, `c/${friendshipHash(a.id, b.id)}`])).rows.length, 0,
    "the remaining friend keeps a grant on a topic whose other member is gone",
  );
});

test("deletion needs a session, like everything else", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const res = await call("POST", "/account/delete", {});
  assert.equal(res.status, 401);
  assert.deepEqual(called("kick"), [], "an unauthenticated call must not reach the broker");
});

// --- the friend ceiling ---------------------------------------------------------------------------------

test("the friend ceiling is checked on both sides of an accept", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The inviter was under the cap when they sent it; accepting is what would
  // push them over, and only the accepting side can see that. Without the
  // second check a capped account grows without limit through invites it sent
  // earlier — and the cap bounds real fan-out: `regrantAllFriendTopics` runs on
  // every full-door login and is O(friends).
  const src = require("node:fs").readFileSync(
    require("node:path").join(__dirname, "..", "api", "main.ts"), "utf8");
  const accept = src.slice(src.indexOf('url === "/friends/accept"'));
  const body = accept.slice(0, accept.indexOf('url === "/friends/cancel"'));
  const caps = body.match(/FRIEND_LIMIT/g) ?? [];
  assert.equal(caps.length, 2, "accept must refuse when EITHER side is at the ceiling");
  assert.match(body, /peer: true/, "…and say which side, or the client cannot explain it");
});

// --- moderation: report + block -------------------------------------------------------------------------
//
// Guideline 1.2. The refusals are the emphasis here for the same reason they are
// everywhere else in this file — a report route that files whatever it is sent
// is a way to write message content into someone else's moderation record, and
// a block that a re-invite walks through is not a block.

/** A filed report, straight from the table. */
async function reportRow(id: string) {
  const r = await q<{
    reporter_id: string | null; reported_id: string; conversation_hash: string;
    category: string; reporter_note: string | null; message_excerpt: string | null;
    message_id: string | null; message_frame: Buffer | null; expires_at: string;
    handled_at: string | null;
  }>(`SELECT * FROM reports WHERE id = $1::uuid`, [id]);
  return r.rows[0] ?? null;
}

test("a report names a conversation the reporter is in, and the server derives the subject", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [a, b] = await friends();
  const hash = friendshipHash(a.id, b.id);

  const res = await call("POST", "/report", {
    conversation: hash, peer: b.id, category: "harassment",
    note: "kept messaging after I asked them to stop",
    excerpt: "the message text",
    // The shape the iOS client actually mints: `UUID().uuidString`, uppercase
    // and hyphenated. 006 constrained this column to lowercase hex, so every
    // report carrying a real message id failed the CHECK and came back 500 —
    // and the test that should have caught it passed "deadbeef", the one shape
    // no client sends. 007 widens the column to the envelope's own contract.
    messageId: "9F3A1C2E-4B6D-4E8A-9C1F-2D7B5A0E3C84",
  }, a.token);
  assert.equal(res.status, 200, res.text);
  assert.ok(res.body.id, "the response must carry the id an operator quotes");

  const row = await reportRow(res.body.id);
  assert.ok(row, "nothing was written");
  assert.equal(row!.reporter_id, a.id);
  assert.equal(row!.reported_id, b.id, "the subject is derived from the conversation, not from `peer`");
  assert.equal(row!.category, "harassment");
  assert.equal(row!.message_excerpt, "the message text");
  assert.equal(row!.message_id, "9F3A1C2E-4B6D-4E8A-9C1F-2D7B5A0E3C84",
    "stored verbatim: this value is compared against what the broker delivered, " +
    "so a normalized copy matches nothing");
  assert.equal(row!.message_frame, null, "no frame was sent, and none was invented");
  assert.equal(row!.handled_at, null, "a fresh report is unhandled, which is what puts it in the queue");
});

test("a report takes any message id the wire format allows, and refuses what it does not", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `message_id` is a copy of the envelope's `msgId`: 1..128 bytes of UTF-8,
  // opaque, chosen by the sending client. The column must not have opinions the
  // wire format does not — 006 did, and refused every real report.
  const [a, b] = await friends();
  const hash = friendshipHash(a.id, b.id);

  for (const messageId of [
    "01JBQ7X4M9K2ZC8V5N3T6PW0RY",                      // a ULID: uppercase Crockford
    "aGVsbG8td29ybGQtbWVzc2FnZS1pZA",                  // base64url, mixed case
    "m".repeat(128),                                   // exactly the envelope's ceiling
  ]) {
    const res = await call("POST", "/report", {
      conversation: hash, peer: b.id, category: "spam", messageId,
    }, a.token);
    assert.equal(res.status, 200, `${messageId.slice(0, 16)}…: ${res.text}`);
    assert.equal((await reportRow(res.body.id))!.message_id, messageId);
  }

  // Over the ceiling in BYTES, which is the only unit the envelope counts: 40 of
  // these are 80 UTF-16 units and 160 bytes, so a `.length` bound of 128 waves
  // them through and the column then refuses them.
  const tooLong = await call("POST", "/report", {
    conversation: hash, peer: b.id, category: "spam", messageId: "🙂".repeat(40),
  }, a.token);
  assert.equal(tooLong.status, 400, tooLong.text);
  assert.equal(tooLong.body.error, "INVALID_FIELD");

  // Control characters are refused at the route, because `npm run reports`
  // prints this value into an operator's terminal.
  const escape = await call("POST", "/report", {
    conversation: hash, peer: b.id, category: "spam", messageId: "abc\u001b[2Jdef",
  }, a.token);
  assert.equal(escape.status, 400, escape.text);
  assert.equal(escape.body.error, "INVALID_FIELD");

  assert.equal(
    (await q(`SELECT 1 FROM reports WHERE reporter_id = $1`, [a.id])).rows.length, 3,
    "the two refusals must not have written rows"
  );
});

test("a report is refused for a conversation the caller is not in", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The whole point of deriving the subject from the friendship: an outsider
  // holding the hash — which is derivable by anyone who knows both ids — must
  // not be able to file against a pair they are not part of.
  const [a, b] = await friends();
  const outsider = await account();
  const res = await call("POST", "/report", {
    conversation: friendshipHash(a.id, b.id), peer: b.id, category: "spam",
  }, outsider.token);
  assert.equal(res.status, 403, res.text);
  assert.equal(res.body.error, "NOT_A_MEMBER");
});

test("a report for a conversation that does not exist is a 404, not a row", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const me = await account();
  const res = await call("POST", "/report", {
    conversation: crypto.randomBytes(32).toString("hex"), peer: me.id, category: "spam",
  }, me.token);
  assert.equal(res.status, 404, res.text);
  assert.equal((await q(`SELECT 1 FROM reports WHERE reporter_id = $1`, [me.id])).rows.length, 0);
});

test("a `peer` that is not the other member is refused rather than ignored", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `peer` is redundant — the subject is already derived — and that is why it is
  // required. A client that disagrees with the server about whose conversation
  // this is has a bug, and filing against the wrong person is the worst possible
  // moment to find out.
  const [a, b] = await friends();
  const someoneElse = await account();
  const res = await call("POST", "/report", {
    conversation: friendshipHash(a.id, b.id), peer: someoneElse.id, category: "spam",
  }, a.token);
  assert.equal(res.status, 400, res.text);
  assert.equal(res.body.error, "PEER_MISMATCH");
  assert.equal((await q(`SELECT 1 FROM reports WHERE reported_id = $1`, [someoneElse.id])).rows.length, 0,
    "…and nothing was filed against the person the client named");
});

test("a report refuses a category the runbook has no procedure for", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [a, b] = await friends();
  const hash = friendshipHash(a.id, b.id);
  for (const category of ["", "abuse", "DROP TABLE", "spam!"]) {
    const res = await call("POST", "/report", { conversation: hash, peer: b.id, category }, a.token);
    assert.equal(res.status, 400, `category=${JSON.stringify(category)} -> ${res.status}`);
  }
  // …and the vocabulary the route accepts is the one the column accepts. Two
  // lists that can drift would fail at the constraint, as a 500, after the
  // client was told the field was fine.
  for (const category of DB.reportCategories) {
    const res = await call("POST", "/report", { conversation: hash, peer: b.id, category }, a.token);
    assert.equal(res.status, 200, `category=${category} -> ${res.text}`);
  }
});

test("a malformed conversation hash never reaches the database", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [a, b] = await friends();
  for (const conversation of ["nothex", "ab", "zz".repeat(32), friendshipHash(a.id, b.id) + "00"]) {
    const res = await call("POST", "/report", { conversation, peer: b.id, category: "spam" }, a.token);
    assert.equal(res.status, 400, `${conversation.slice(0, 12)} -> ${res.status}`);
    assert.equal(res.body.error, "INVALID_FIELD");
  }
});

test("an attached frame must be base64 and must fit", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [a, b] = await friends();
  const hash = friendshipHash(a.id, b.id);
  const base = { conversation: hash, peer: b.id, category: "spam" };

  const notB64 = await call("POST", "/report", { ...base, frame: "this is not base64!!" }, a.token);
  assert.equal(notB64.status, 400, notB64.text);

  // Bounded in BYTES after decoding, because base64 is 4/3 the size of what it
  // carries and a cap on the string is a cap on the wrong number.
  const tooBig = await call("POST", "/report",
    { ...base, frame: Buffer.alloc(97 * 1024).toString("base64") }, a.token);
  assert.equal(tooBig.status, 400, tooBig.text);
  assert.match(tooBig.body.message ?? "", /bytes/);

  const ok = await call("POST", "/report",
    { ...base, frame: Buffer.from("a sealed frame would go here").toString("base64") }, a.token);
  assert.equal(ok.status, 200, ok.text);
  const row = await reportRow(ok.body.id);
  assert.equal(row!.message_frame?.toString("utf8"), "a sealed frame would go here",
    "the bytes stored must be the bytes sent, not their base64");
});

test("the daily report cap bites, and it bites before the body is read", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [a, b] = await friends();
  const hash = friendshipHash(a.id, b.id);
  // The limit comes from the environment, so this drives the counter directly
  // rather than sending twenty requests to discover a number a deployment can
  // change.
  const limit = Number(process.env.REPORTS_PER_DAY || 20);
  for (let i = 0; i < limit; i++) await DB.bumpCounter(`report:day:${a.id}`, 86400);

  const res = await call("POST", "/report", { conversation: hash, peer: b.id, category: "spam" }, a.token);
  assert.equal(res.status, 429, res.text);
  assert.equal(res.body.limit, limit);
  assert.equal((await q(`SELECT 1 FROM reports WHERE reporter_id = $1`, [a.id])).rows.length, 0,
    "a rate-limited report must not still write its row");
});

test("blocking ends the friendship, revokes the topic, and survives a re-invite", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [a, b] = await friends();
  emqxCalls.length = 0;

  const res = await call("POST", "/friends/block", { peer: b.id }, a.token);
  assert.equal(res.status, 200, res.text);

  assert.equal(await DB.areFriends(a.id, b.id), false, "the friendship survived the block");
  assert.equal(
    (await q(`SELECT 1 FROM mqtt_acl WHERE id = $1 AND topic = $2`,
      [b.id, `c/${friendshipHash(a.id, b.id)}`])).rows.length, 0,
    "the blocked peer keeps a grant on the conversation topic",
  );
  // The row edit stops the NEXT authorization check; an open subscription keeps
  // delivering until this call lands (ASVS-1).
  assert.equal(called("revokeTopic").length, 1, "the live subscription was left in place");
  assert.equal(called("notifyGraphChanged").length, 1, "neither side was told the graph changed");

  // The durable half. Without it the blocked party re-invites and the block has
  // evaporated — which is the ordinary way this feature is got wrong.
  const reinvite = await call("POST", "/friends/invite", { to: a.id }, b.token);
  assert.equal(reinvite.status, 404, reinvite.text);
  assert.equal((await q(`SELECT 1 FROM invites WHERE to_id = $1 AND from_id = $2`, [a.id, b.id])).rows.length, 0);

  // …and the blocker cannot walk through it either, by accident or otherwise.
  assert.equal((await call("POST", "/friends/invite", { to: b.id }, a.token)).status, 404);
});

test("a block refuses the invite with the SAME 404 an unknown handle gets", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Telling a blocked invite apart from an invite to nobody tells the blocked
  // party they were blocked, which is the one thing a block should not announce.
  const [a, b] = await friends();
  await call("POST", "/friends/block", { peer: b.id }, a.token);

  const blocked = await call("POST", "/friends/invite", { to: a.id }, b.token);
  const stranger = await call("POST", "/friends/invite",
    { to: crypto.randomBytes(32).toString("hex") }, b.token);
  assert.equal(blocked.status, stranger.status, "the status distinguishes a block from a stranger");
  assert.deepEqual(blocked.body, stranger.body, "…and so does the body");
});

test("a pending invite does not survive a block, in either direction", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  const b = await account();
  await call("POST", "/friends/invite", { to: b.id }, a.token);
  assert.equal((await q(`SELECT 1 FROM invites WHERE to_id = $1 AND from_id = $2`, [b.id, a.id])).rows.length, 1,
    "the fixture did not create the invite it is about to test");

  const res = await call("POST", "/friends/block", { peer: a.id }, b.token);
  assert.equal(res.status, 200, res.text);
  assert.equal((await q(`SELECT 1 FROM invites WHERE to_id = $1 OR from_id = $1`, [a.id])).rows.length, 0,
    "a pending invite is a live route back in and must go with the friendship");

  // And accepting it afterwards — from a device that was offline when the block
  // landed and still holds the invite in its UI — rebuilds nothing.
  const accept = await call("POST", "/friends/accept", { from: a.id }, b.token);
  assert.notEqual(accept.status, 200, accept.text);
  assert.equal(await DB.areFriends(a.id, b.id), false);
});

test("unblocking lifts the block without restoring the friendship", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const [a, b] = await friends();
  await call("POST", "/friends/block", { peer: b.id }, a.token);

  const res = await call("POST", "/friends/unblock", { peer: b.id }, a.token);
  assert.equal(res.status, 200, res.text);
  assert.equal(await DB.areFriends(a.id, b.id), false,
    "unblocking handed back a conversation topic the user deliberately tore down");

  // What it DOES restore is the ability to ask again.
  assert.equal((await call("POST", "/friends/invite", { to: a.id }, b.token)).status, 200);
});

test("GET /friends/blocked is what stops the client deleting a blocked contact", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // DirectorySync treats absence from /friends as "delete this row and its
  // history". A blocked peer is absent from /friends by construction, so without
  // this list a block silently destroys the conversation it was placed over.
  const [a, b] = await friends();
  assert.deepEqual((await call("GET", "/friends/blocked", undefined, a.token)).body.blocked, []);

  await call("POST", "/friends/block", { peer: b.id }, a.token);
  const mine = await call("GET", "/friends/blocked", undefined, a.token);
  assert.deepEqual(mine.body.blocked, [b.id]);

  // One direction only. A blocked peer must not be handed a list that tells them
  // who blocked them.
  assert.deepEqual((await call("GET", "/friends/blocked", undefined, b.token)).body.blocked, [],
    "the blocked party can read who blocked them");
});

test("report, THEN block — the order the client must use, and what happens if it does not", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // /report requires membership of the conversation it names and /friends/block
  // tears that conversation down, so the two routes cannot enforce their own
  // ordering between themselves. This pins the consequence so a client that gets
  // it backwards fails here rather than in the field, silently filing nothing.
  const [a, b] = await friends();
  const hash = friendshipHash(a.id, b.id);

  const filed = await call("POST", "/report",
    { conversation: hash, peer: b.id, category: "harassment", excerpt: "…" }, a.token);
  assert.equal(filed.status, 200, filed.text);
  assert.equal((await call("POST", "/friends/block", { peer: b.id }, a.token)).status, 200);

  const after = await call("POST", "/report",
    { conversation: hash, peer: b.id, category: "harassment" }, a.token);
  assert.equal(after.status, 404, "blocking first must fail loudly, not file a report about nobody");

  // The report filed BEFORE the block stands, with its content, which is the
  // property that makes the ordering workable at all.
  const row = await reportRow(filed.body.id);
  assert.equal(row!.reported_id, b.id);
  assert.equal(row!.message_excerpt, "…");
});
