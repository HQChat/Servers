// The report an operator reads when a phone does not buzz.
//
// Both of this repo's diagnostics were untested, and the previous round showed
// what that costs: `check-mqtt-acl` called an ACL complete while the one topic
// first contact needs was missing — during the outage it was written to
// diagnose. A diagnostic that lies is worse than none, because it ends the
// investigation.
//
// So this asserts the VERDICT, not the prose. Every step of the push path exits
// silently when it cannot proceed — no APNs config, no registered token, no
// bundle id — so a stack that has never sent a single push looks exactly like
// one that works. Which step stops is the only thing this tool is for.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { DB } from "../services/db/api";
import { q } from "../services/db/pg";
import { peerId } from "../lib/identity";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";

setLogLevel("silent");

const ENV_KEYS = [
  "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_KEY_P8",
  "APNS_TOPIC_IOS", "APNS_TOPIC_MACOS", "APNS_ENV",
] as const;

const EC_KEY = crypto.generateKeyPairSync("ec", {
  namedCurve: "P-256",
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
}).privateKey;

const CONFIGURED: Record<string, string> = {
  APNS_KEY_ID: "ABC123DEF4",
  APNS_TEAM_ID: "TEAM123456",
  APNS_KEY_P8: EC_KEY,
  APNS_TOPIC_IOS: "app.hqchat.ios",
  APNS_TOPIC_MACOS: "app.hqchat.macos",
};

const checkPushPath = require.resolve("../scripts/check-push");
const apnsPath = require.resolve("../services/apns/api");

/** Run the report under a given environment and return everything it printed. */
async function reportUnder(
  env: Record<string, string | undefined>,
  arg?: string,
): Promise<string> {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) {
    const v = env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  const out: string[] = [];
  const savedConsole = { log: console.log, error: console.error };
  console.log = (...a: unknown[]) => out.push(a.map(String).join(" "));
  console.error = (...a: unknown[]) => out.push(a.map(String).join(" "));

  // The APNs module caches the parsed key, and this report asks it whether the
  // key is usable — so both are reloaded, or every case after the first sees
  // the first case's verdict.
  delete require.cache[checkPushPath];
  delete require.cache[apnsPath];
  try {
    const { report } = require(checkPushPath) as typeof import("../scripts/check-push");
    await report(arg);
    return out.join("\n");
  } finally {
    Object.assign(console, savedConsole);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const created: string[] = [];

async function account(username?: string): Promise<{ id: string; username: string }> {
  const pkHex = crypto.randomBytes(64).toString("hex");
  const id = peerId(pkHex);
  const name = username ?? `p${crypto.randomBytes(6).toString("hex")}`;
  await DB.ensureUser(id, pkHex);
  await DB.setUsername(id, name);
  created.push(id);
  return { id, username: name };
}

async function cleanup(): Promise<void> {
  if (!created.length) return;
  const ids = [...new Set(created)];
  for (const sql of [
    `DELETE FROM push_tokens WHERE id = ANY($1::text[])`,
    `DELETE FROM friendships WHERE id_lo = ANY($1::text[]) OR id_hi = ANY($1::text[])`,
    `DELETE FROM users WHERE id = ANY($1::text[])`,
  ]) {
    try { await q(sql, [ids]); } catch { /* not this schema */ }
  }
  created.length = 0;
}

test.afterEach(async () => { await cleanup(); });
test.after(async () => { await cleanup(); await closePg(); });

// --- the config verdict, which decides whether anything else matters -------------------

test("an incomplete APNs config stops the report at the top", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // With APNs incomplete, `send()` returns before it builds a request: no device
  // is woken and no error is logged, for any account. Everything further down is
  // therefore irrelevant, and a report that buried that under an account's
  // details would send an operator looking at the wrong thing.
  const out = await reportUnder({ APNS_KEY_P8: EC_KEY });
  assert.match(out, /Nothing below matters until this is fixed/);
  // And it names where each half belongs — the distinction that made the
  // original outage invisible: the secret is a compose secret, the rest is not.
  assert.match(out, /server\.env/);
  assert.match(out, /apns_key_p8/);
});

test("a complete config does not raise that alarm", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // A report that cried "nothing matters" on a healthy stack would be ignored on
  // the day it was right.
  const out = await reportUnder(CONFIGURED);
  assert.doesNotMatch(out, /Nothing below matters/);
  assert.match(out, /APNs ready/);
});

test("a key that is present but unloadable is called out with its remedy", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // "Set" and "usable" are different questions: a .p8 OpenSSL will not load
  // passes every presence check and fails every push. The usual cause is a
  // truncated paste, so the fix named is scp rather than "paste it again".
  const rsa = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  }).privateKey;
  const out = await reportUnder({ ...CONFIGURED, APNS_KEY_P8: rsa });
  assert.match(out, /⛔️/);
  assert.match(out, /EC key/);
  assert.match(out, /scp /, "the remedy must be a command, not advice");
  assert.match(out, /takes one line/, "…and name the mistake that causes it");
});

test("no key at all is not reported as an unloadable key", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Two different problems with two different fixes. Conflating them sends an
  // operator to re-copy a file that was never there.
  const out = await reportUnder({ APNS_KEY_P8: undefined });
  assert.doesNotMatch(out, /Re-install it from the file Apple gave you/);
});

// --- the whole-table view ------------------------------------------------------------------

test("with no argument it reports the shape of the table", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // A stack where NOBODY has a token is a different problem from one person's
  // device, and the two look identical from a single account's report.
  const a = await account();
  await DB.setPushToken(a.id, "ios", "t".repeat(64));
  const out = await reportUnder(CONFIGURED);
  assert.match(out, /registered devices/);
  assert.match(out, /ios: \d+/, out);
  assert.match(out, /Pass a username or client id/);
});

// --- one account ---------------------------------------------------------------------------

test("an account nobody has ever registered is named as such", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Not "no push token": the account does not exist, which means it never
  // completed the handshake, which is a different investigation entirely.
  const out = await reportUnder(CONFIGURED, "definitely-not-a-real-handle");
  assert.match(out, /no account "definitely-not-a-real-handle"/);
  assert.match(out, /never completed \/auth/);
});

test("an account with no device says so, and says why that happens", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await account();
  const out = await reportUnder(CONFIGURED, a.username);
  assert.match(out, /push token: NONE/);
  // The two real causes, because "no token" on its own is not actionable.
  assert.match(out, /permission denied|aps-environment/);
  assert.match(out, /this account has no device to send to/);
});

test("an account with a device reports the topic that will be used", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // One bundle id per platform. A macOS device sent to the iOS topic
  // authenticates and delivers nothing — the silent failure this whole tool is
  // about.
  const a = await account();
  await DB.setPushToken(a.id, "macos", "m".repeat(64));
  const out = await reportUnder(CONFIGURED, a.username);
  assert.match(out, /\(macos\)/);
  // Scoped to the per-account line. The summary at the top names every
  // CONFIGURED topic, quite correctly — asserting over the whole report would
  // fail on a healthy stack, which is what my first version of this did.
  const line = out.split("\n").find((l) => /topic for macos:/.test(l));
  assert.ok(line, `no per-platform topic line:\n${out}`);
  assert.ok(line!.includes(CONFIGURED.APNS_TOPIC_MACOS!), line);
  assert.ok(!line!.includes(CONFIGURED.APNS_TOPIC_IOS!),
    `the iOS topic is not the one that will be used: ${line}`);
});

test("a missing topic for that platform is named at the point of use", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `apnsGaps` now reports the missing topic at the top of the report too, so
  // this is no longer the only thing that catches the half-configured case. It
  // is still the one that names it at the point of USE, for one device, which is
  // what an operator chasing "why did THIS phone not buzz" is reading.
  const a = await account();
  await DB.setPushToken(a.id, "ios", "t".repeat(64));
  const out = await reportUnder({ ...CONFIGURED, APNS_TOPIC_IOS: undefined }, a.username);
  assert.match(out, /UNSET — send\(\) returns silently/);
});

test("the full device token is never printed", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // It identifies one person's phone, and this runs in a terminal an operator
  // may well paste into an issue.
  const a = await account();
  const token = crypto.randomBytes(32).toString("hex");
  await DB.setPushToken(a.id, "ios", token);
  const out = await reportUnder(CONFIGURED, a.username);
  assert.ok(out.includes(token.slice(0, 12)), "a prefix should be shown, to correlate");
  assert.ok(!out.includes(token), "the whole device token was printed");
});

test("it counts the conversations that could wake an account", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // A friendship whose hash is not in the ACL is one the bridge would see a
  // message on and find no members for — the count is what makes "nobody can
  // wake them" visible.
  const [a, b, c] = [await account(), await account(), await account()];
  await DB.setPushToken(a.id, "ios", "t".repeat(64));
  await DB.createFriendship(a.id, b.id);
  await DB.createFriendship(a.id, c.id);

  const out = await reportUnder(CONFIGURED, a.username);
  assert.match(out, /conversations that could wake them: 2/);
  assert.match(out, /Nothing in the server's state blocks a wake/);
});

test("a lookup works by client id as well as by handle", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // An operator reading a log has an id, not a handle.
  const a = await account();
  const { resolve } = require("../scripts/check-push") as typeof import("../scripts/check-push");
  assert.deepEqual(await resolve(a.id), { id: a.id, username: a.username });
  assert.deepEqual(await resolve(a.username), { id: a.id, username: a.username });
  assert.equal(await resolve(peerId("nothing")), null, "an id nobody holds resolves to nothing");

  const out = await reportUnder(CONFIGURED, a.id);
  assert.match(out, new RegExp(`@${a.username} = ${a.id}`));
});

test("importing the script reports nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `require.main === module`: a test that wants `resolve` should not print a
  // whole diagnostic and close the connection pool as a side effect.
  const out: string[] = [];
  const savedLog = console.log;
  console.log = (...a: unknown[]) => out.push(a.map(String).join(" "));
  try {
    delete require.cache[checkPushPath];
    require(checkPushPath);
  } finally {
    console.log = savedLog;
  }
  assert.deepEqual(out, [], `importing printed:\n${out.join("\n")}`);
});
