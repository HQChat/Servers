// End-to-end over the raw-TCP transport: a real client, through noise-gw
// (hqn/1, hybrid post-quantum Noise), into the real EMQX with the deployment's
// authn hook and authorizer, authenticated by the v1 signed CONNECT.
//
// What only a live stack can show:
//   - the whole chain works: handshake → CONNECT in msg1 → auth hook → CONNACK
//     as the first transport frame → pub/sub;
//   - the topic ACL still applies to a client arriving through the gateway;
//   - a captured opening, replayed on the wire, neither connects nor kicks the
//     live session it was copied from.
//
// Needs `bash test/e2e/run-local.sh` (which starts noise-gw) or equivalent env:
// TEST_HQN_HOST, TEST_HQN_PORT, TEST_HQN_KEYS_URL. Skips cleanly without them.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as net from "node:net";
import { MqttClient } from "mqtt";
import { TestClient, e2eAvailable, loadCrypto } from "../helpers/mqtt-client";
import { HqnStream } from "../helpers/hqn-stream";
import { newSigningKey, signConnect } from "../../lib/mqtt-proof";
import type { ServerStaticPublic } from "../../lib/noise";
import { disconnect } from "../../services/db/pg";

const HOST = process.env.TEST_HQN_HOST || "127.0.0.1";
const PORT = Number(process.env.TEST_HQN_PORT || 0);
const KEYS_URL = process.env.TEST_HQN_KEYS_URL || "";
const AUTH_BASE = (process.env.TEST_AUTH_URL || "http://127.0.0.1:8081").replace(/\/$/, "");
const SKIP = "needs the local stack with noise-gw (bash test/e2e/run-local.sh)";

after(() => disconnect().catch(() => {}));

async function available(): Promise<ServerStaticPublic | null> {
  if (!PORT || !KEYS_URL || !(await e2eAvailable())) return null;
  try {
    const r = await fetch(KEYS_URL);
    const k = (await r.json()).keys[0];
    return { keyId: k.keyId, x25519: Buffer.from(k.x25519, "base64"), hqc: Buffer.from(k.hqc, "base64") };
  } catch {
    return null;
  }
}

/** A signed-in client with a registered Ed25519 signing key (via /auth/refresh,
 *  so the refresh path is the one exercised here). */
async function signedIn() {
  const c = new TestClient(await loadCrypto());
  await c.register(`hqn${crypto.randomBytes(3).toString("hex")}`);
  const key = newSigningKey();
  const r = await fetch(`${AUTH_BASE}/auth/refresh`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${c.bearer}` },
    body: JSON.stringify({ mqttSigningKey: key.publicKeyB64 }),
  });
  const body = await r.json();
  assert.equal(r.status, 200);
  const offset = body.serverTime - Date.now() / 1000;
  const password = (clientid = c.id) =>
    signConnect({ clientid, keyId: body.mqttKeyId, privateKey: key.privateKey, nowSec: Date.now() / 1000 + offset });
  return { c, password };
}

/** mqtt.js over hqn/1. Resolves on CONNACK, rejects on refusal or timeout. */
function connectHqn(server: ServerStaticPublic, id: string, password: string, clientId = id) {
  const streams: HqnStream[] = [];
  const client = new MqttClient(() => {
    const s = new HqnStream(HOST, PORT, server);
    streams.push(s);
    return s as any;
  }, {
    clientId, username: id, password,
    protocolVersion: 4, clean: false, reconnectPeriod: 0, connectTimeout: 15000, keepalive: 60,
  } as any);
  const ready = new Promise<void>((resolve, reject) => {
    client.once("connect", () => resolve());
    client.once("error", reject);
    client.once("close", () => reject(new Error("closed before CONNACK")));
  });
  return { client, ready, stream: () => streams[0]! };
}

const endQuietly = (c: MqttClient) => new Promise<void>((r) => c.end(true, {}, () => r()));

test("a client connects over hqn/1 with a signed CONNECT, and pub/sub works", async (t) => {
  const server = await available();
  if (!server) return t.skip(SKIP);
  const { c, password } = await signedIn();
  const { client, ready } = connectHqn(server, c.id, password());
  await ready;
  try {
    const inbox = `u/${c.id}/inbox`;
    await client.subscribeAsync(inbox, { qos: 1 });
    const got = new Promise<Buffer>((r) => client.once("message", (_t, p) => r(p)));
    await client.publishAsync(inbox, Buffer.from("over raw tcp"), { qos: 1 });
    assert.equal((await got).toString(), "over raw tcp");
  } finally {
    await endQuietly(client);
  }
});

test("the topic ACL applies to a client arriving through the gateway", async (t) => {
  const server = await available();
  if (!server) return t.skip(SKIP);
  const { c, password } = await signedIn();
  const { client, ready } = connectHqn(server, c.id, password());
  await ready;
  const stranger = crypto.randomBytes(32).toString("hex");
  const outcome = await new Promise<string>((resolve) => {
    client.once("close", () => resolve("disconnected"));
    client.subscribe(`u/${stranger}/inbox`, { qos: 1 }, (err, granted) => {
      if (err) return resolve("refused");
      resolve(granted?.[0]?.qos === 128 ? "refused" : "granted");
    });
  });
  assert.notEqual(outcome, "granted", "a stranger's inbox must not be subscribable");
  await endQuietly(client);
});

test("a CONNECT for another client id is refused through the gateway too", async (t) => {
  const server = await available();
  if (!server) return t.skip(SKIP);
  const { c, password } = await signedIn();
  const victim = crypto.randomBytes(32).toString("hex");
  const { client, ready } = connectHqn(server, c.id, password(victim), victim);
  await assert.rejects(ready);
  await endQuietly(client);
});

test("a replayed opening neither connects nor kicks the live session", async (t) => {
  const server = await available();
  if (!server) return t.skip(SKIP);
  const { c, password } = await signedIn();
  const live = connectHqn(server, c.id, password());
  await live.ready;
  let kicked = false;
  live.client.on("close", () => { kicked = true; });

  // An on-path attacker's copy of the first bytes the client sent.
  const opening = live.stream().opening!;
  const replay = net.connect({ host: HOST, port: PORT });
  await new Promise<void>((r) => replay.on("connect", () => r()));
  replay.write(opening);
  const replayOutcome = await new Promise<string>((resolve) => {
    replay.on("data", () => resolve("answered"));
    replay.on("close", () => resolve("closed"));
    setTimeout(() => resolve("timeout"), 5000);
  });
  replay.destroy();
  assert.equal(replayOutcome, "closed", "the gateway closes a replayed opening without a reply");

  // The live session is untouched: still connected, still delivering.
  await new Promise((r) => setTimeout(r, 500));
  assert.equal(kicked, false, "the replay did not take over the session");
  const inbox = `u/${c.id}/inbox`;
  await live.client.subscribeAsync(inbox, { qos: 1 });
  const got = new Promise<Buffer>((r) => live.client.once("message", (_t, p) => r(p)));
  await live.client.publishAsync(inbox, Buffer.from("still here"), { qos: 1 });
  assert.equal((await got).toString(), "still here");
  await endQuietly(live.client);
});

test("GET /auth/transport advertises the gateway with the keys it actually holds", async (t) => {
  const server = await available();
  if (!server) return t.skip(SKIP);
  const r = await fetch(`${AUTH_BASE}/auth/transport`);
  const { hqn } = await r.json();
  if (!hqn) return t.skip("auth not started with HQN_ENABLED=1 (run-local.sh does this)");
  assert.equal(hqn.enabled, true);
  assert.equal(hqn.port, PORT);
  const k = hqn.keys.find((x: any) => x.keyId === server.keyId);
  assert.ok(k, "the gateway's key id is advertised");
  assert.ok(Buffer.from(k.x25519, "base64").equals(server.x25519), "…with its X25519 key");
  assert.ok(Buffer.from(k.hqc, "base64").equals(server.hqc), "…and its HQC-256 key");
});
