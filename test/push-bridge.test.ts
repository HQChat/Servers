// The push bridge's two decisions: who is online, and who gets woken.
//
// Both fail SILENTLY when they are wrong. A presence entry under the wrong name
// means a device is simply never woken, with no error anywhere; a wake sent to
// someone who is online is a buzz in their pocket while they are looking at the
// conversation. Neither shows up in a log you would think to read.
//
// `push/main.ts` connected to EMQX and opened a port at import time, so none of
// this could be tested. It exports `createPushBridge` now, with the database and
// APNs injected — so these run with no broker, no database and no Apple.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import { createPushBridge, createHealthHandler, type PushDeps } from "../push/main";
import type { SendOutcome } from "../services/apns/api";

const ID_A = "a".repeat(64);
const ID_B = "b".repeat(64);
const HASH = "c".repeat(64);

/** Records every wake, so a test can assert on who was NOT woken too. */
function spy(members: Record<string, string[]> = {}, outcome: SendOutcome = "sent") {
  const woke: string[] = [];
  const deps: PushDeps = {
    getHashMembers: async (hash) => members[hash] ?? [],
    send: async (id) => { woke.push(id); return outcome; },
  };
  return { deps, woke };
}

const presence = (state: string) => Buffer.from(JSON.stringify({ s: state }));

// --- presence ----------------------------------------------------------------

test("a presence message adds and removes the id it names", async () => {
  const { deps } = spy();
  const b = createPushBridge(deps);

  await b.handleMessage(`u/${ID_A}/presence`, presence("online"));
  assert.ok(b.presence.has(ID_A), "online must be recorded");

  await b.handleMessage(`u/${ID_A}/presence`, presence("offline"));
  assert.ok(!b.presence.has(ID_A), "offline must clear it");
});

test("an empty payload — a cleared retained message — reads as offline", async () => {
  const { deps } = spy();
  const b = createPushBridge(deps);
  await b.handleMessage(`u/${ID_A}/presence`, presence("online"));
  await b.handleMessage(`u/${ID_A}/presence`, Buffer.alloc(0));
  assert.ok(!b.presence.has(ID_A), "a cleared retained message means gone, not unchanged");
});

test("a bare-string payload is understood, and anything else is offline", async () => {
  const { deps } = spy();
  const b = createPushBridge(deps);
  await b.handleMessage(`u/${ID_A}/presence`, Buffer.from("online"));
  assert.ok(b.presence.has(ID_A), "the non-JSON form still works");

  for (const junk of ["{", "null", "{}", '{"s":"maybe"}', "ONLINE"]) {
    await b.handleMessage(`u/${ID_A}/presence`, Buffer.from("online"));
    await b.handleMessage(`u/${ID_A}/presence`, Buffer.from(junk));
    assert.ok(!b.presence.has(ID_A), `"${junk}" must not read as online`);
  }
});

// The id pattern is spelled out in the route rather than left as `[^/]+`,
// precisely so a malformed topic cannot put a name into `online` that nothing
// else uses — the symptom of which is a device that quietly stops being woken.
test("a topic whose middle segment is not a client id is ignored", async () => {
  const { deps } = spy();
  const b = createPushBridge(deps);
  for (const topic of [
    "u/short/presence",
    `u/${ID_A.toUpperCase()}/presence`,   // ids are lowercase hex
    `u/${ID_A}x/presence`,
    `u/${ID_A}/presence/extra`,
    `u//presence`,
    `u/${ID_A}/typing`,
  ]) {
    await b.handleMessage(topic, presence("online"));
    assert.equal(b.presence.size, 0, topic);
  }
});

// --- waking ------------------------------------------------------------------

test("a conversation message wakes the members who are offline", async () => {
  const { deps, woke } = spy({ [HASH]: [ID_A, ID_B] });
  const b = createPushBridge(deps);
  await b.handleMessage(`c/${HASH}`, Buffer.from("ciphertext"));
  assert.deepEqual(woke.sort(), [ID_A, ID_B].sort());
});

test("…and never someone who is online", async () => {
  const { deps, woke } = spy({ [HASH]: [ID_A, ID_B] });
  const b = createPushBridge(deps);
  await b.handleMessage(`u/${ID_A}/presence`, presence("online"));

  await b.handleMessage(`c/${HASH}`, Buffer.from("ciphertext"));
  assert.deepEqual(woke, [ID_B], "the online member must not be woken");

  // The sender being skipped is not a special case — it is this same rule, and
  // it only holds while their presence is current.
  await b.handleMessage(`u/${ID_A}/presence`, presence("offline"));
  await b.handleMessage(`c/${HASH}`, Buffer.from("ciphertext"));
  assert.deepEqual(woke, [ID_B, ID_A, ID_B], "once offline again, they are woken");
});

test("an unknown conversation hash wakes nobody", async () => {
  // The bridge only ever parses a topic the broker authorized, so no members
  // means the friendship row and the topic scheme disagree. The wrong answer
  // here would be to wake everybody, or to throw.
  const { deps, woke } = spy({});
  const b = createPushBridge(deps);
  await b.handleMessage(`c/${HASH}`, Buffer.from("ciphertext"));
  assert.deepEqual(woke, []);
});

test("the payload is never inspected — a wake is content-free", async () => {
  const bodies: string[] = [];
  const b = createPushBridge({
    getHashMembers: async () => [ID_A],
    send: async (_id, title, body) => { bodies.push(`${title}|${body}`); return "sent"; },
  });
  await b.handleMessage(`c/${HASH}`, Buffer.from("this is ciphertext and must not leak"));
  assert.deepEqual(bodies, ["New message|You have a new message"],
    "the notification says nothing about the message");
});

test("a database failure does not take the bridge down", async () => {
  // One bad message must not stop the process: the next one still has to be
  // handled, or a single poisoned topic ends push for everybody.
  const woke: string[] = [];
  const b = createPushBridge({
    getHashMembers: async (hash) => { if (hash === HASH) throw new Error("pg is down"); return [ID_B]; },
    send: async (id) => { woke.push(id); return "sent"; },
  });
  await b.handleMessage(`c/${HASH}`, Buffer.from("x"));   // must not throw
  await b.handleMessage(`c/${"d".repeat(64)}`, Buffer.from("x"));
  assert.deepEqual(woke, [ID_B], "the bridge kept working after the failure");
});

test("a malformed conversation topic is ignored rather than guessed at", async () => {
  const { deps, woke } = spy({ [HASH]: [ID_A] });
  const b = createPushBridge(deps);
  for (const topic of [`c/${HASH}x`, "c/short", `c/${HASH.toUpperCase()}`, `c/${HASH}/extra`, "c/"]) {
    await b.handleMessage(topic, Buffer.from("x"));
  }
  assert.deepEqual(woke, []);
});

// --- health ------------------------------------------------------------------

test("the health endpoint reports how many clients are online", async () => {
  const seen = new Set<string>([ID_A, ID_B]);
  const server = http.createServer(createHealthHandler(seen));
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    const ok = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { ok: true, service: "push-bridge", online: 2 });

    const missing = await fetch(`http://127.0.0.1:${port}/nope`);
    assert.equal(missing.status, 404);
  } finally {
    server.close();
  }
});
