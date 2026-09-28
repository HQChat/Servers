// GET /auth/transport (lib/transport-config.ts): the raw-TCP transport's
// endpoint, its pinned keys, and the switch that turns it on.
//
// Two properties matter most. It is OPT-IN — nothing is advertised without
// HQN_ENABLED=1, whatever else is configured. And any missing, malformed or
// unreachable setting yields "no hqn" (clients stay on WSS), never an error
// that breaks sign-in.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import * as http from "node:http";
import { transportInfo, resolveTransportInfo, __resetGatewayKeyCache } from "../lib/transport-config";
import { createAuthHandler } from "../auth/main";

const key = (keyId = 1) => ({
  keyId,
  x25519: crypto.randomBytes(32).toString("base64"),
  hqc: crypto.randomBytes(7237).toString("base64"),
});

function keysFile(body: unknown): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hqn-pub-"));
  const f = path.join(dir, "pub.json");
  fs.writeFileSync(f, typeof body === "string" ? body : JSON.stringify(body));
  return f;
}

const EP = { HQN_PUBLIC_HOST: "mqtt.example.org", HQN_PUBLIC_PORT: "443" };

beforeEach(() => __resetGatewayKeyCache());

test("it is opt-in: a complete config advertises nothing without HQN_ENABLED=1", () => {
  const k = key();
  const env = { ...EP, NOISE_PUBLIC_KEYS: JSON.stringify({ keys: [k] }) };
  for (const off of [undefined, "", "0", "true", "yes", " 1"]) {
    assert.deepEqual(transportInfo({ ...env, HQN_ENABLED: off }), { hqn: null }, `HQN_ENABLED=${JSON.stringify(off)}`);
  }
  assert.deepEqual(transportInfo({ ...env, HQN_ENABLED: "1" }),
    { hqn: { enabled: true, host: "mqtt.example.org", port: 443, keys: [k] } });
});

test("keys from a file work the same as inline", () => {
  const k = key();
  const info = transportInfo({ ...EP, HQN_ENABLED: "1", NOISE_PUBLIC_KEYS_FILE: keysFile({ keys: [k] }) });
  assert.deepEqual(info.hqn?.keys, [k]);
});

test("anything missing or malformed means no hqn, never a throw", () => {
  const good = keysFile({ keys: [key()] });
  const on = { HQN_ENABLED: "1" };
  for (const env of [
    { ...on },
    { ...on, ...EP },
    { ...on, HQN_PUBLIC_HOST: "h", NOISE_PUBLIC_KEYS_FILE: good },
    { ...on, HQN_PUBLIC_HOST: "h", HQN_PUBLIC_PORT: "0", NOISE_PUBLIC_KEYS_FILE: good },
    { ...on, HQN_PUBLIC_HOST: "h", HQN_PUBLIC_PORT: "70000", NOISE_PUBLIC_KEYS_FILE: good },
    { ...on, HQN_PUBLIC_HOST: "h/evil", HQN_PUBLIC_PORT: "443", NOISE_PUBLIC_KEYS_FILE: good },
    { ...on, ...EP, NOISE_PUBLIC_KEYS_FILE: "/nonexistent" },
    { ...on, ...EP, NOISE_PUBLIC_KEYS_FILE: keysFile("not json") },
    { ...on, ...EP, NOISE_PUBLIC_KEYS: "{" },
    { ...on, ...EP, NOISE_PUBLIC_KEYS: JSON.stringify({ keys: [{ ...key(), hqc: "short" }] }) },
    { ...on, ...EP, NOISE_PUBLIC_KEYS: JSON.stringify({ keys: [{ ...key(), keyId: 300 }] }) },
  ]) {
    assert.deepEqual(transportInfo(env as NodeJS.ProcessEnv), { hqn: null }, JSON.stringify(Object.keys(env)));
  }
});

// --- keys straight from the gateway ---------------------------------------------

function fakeFetch(reply: () => unknown, calls: { n: number }): typeof fetch {
  return (async () => {
    calls.n++;
    const body = reply();
    if (body instanceof Error) throw body;
    return new Response(JSON.stringify(body), { status: 200 });
  }) as typeof fetch;
}

test("with a gateway URL, the gateway's own keys are advertised — and cached", async () => {
  const k = key();
  const calls = { n: 0 };
  const env = { ...EP, HQN_ENABLED: "1", HQN_GATEWAY_KEYS_URL: "http://noise-gw:8081/keys",
    NOISE_PUBLIC_KEYS: JSON.stringify({ keys: [key(9)] }) };
  const f = fakeFetch(() => ({ keys: [k] }), calls);
  const a = await resolveTransportInfo(env, { now: 1_000, fetchImpl: f });
  assert.deepEqual(a.hqn?.keys, [k], "the gateway's keys win over static ones");
  await resolveTransportInfo(env, { now: 30_000, fetchImpl: f });
  assert.equal(calls.n, 1, "cached for a minute");
  await resolveTransportInfo(env, { now: 62_000, fetchImpl: f });
  assert.equal(calls.n, 2, "then asked again");
});

test("an unreachable or broken gateway is not advertised, and is retried soon", async () => {
  const calls = { n: 0 };
  const env = { ...EP, HQN_ENABLED: "1", HQN_GATEWAY_KEYS_URL: "http://noise-gw:8081/keys" };
  const down = fakeFetch(() => new Error("ECONNREFUSED"), calls);
  assert.deepEqual(await resolveTransportInfo(env, { now: 0, fetchImpl: down }), { hqn: null });
  assert.deepEqual(await resolveTransportInfo(env, { now: 5_000, fetchImpl: down }), { hqn: null });
  assert.equal(calls.n, 1, "a failure is cached briefly, not hammered");
  const k = key();
  const up = fakeFetch(() => ({ keys: [k] }), calls);
  assert.deepEqual((await resolveTransportInfo(env, { now: 11_000, fetchImpl: up })).hqn?.keys, [k],
    "and a recovered gateway is advertised within seconds");
  __resetGatewayKeyCache();
  const junk = fakeFetch(() => ({ keys: [{ keyId: 1, x25519: "AA", hqc: "AA" }] }), calls);
  assert.deepEqual(await resolveTransportInfo(env, { now: 0, fetchImpl: junk }), { hqn: null });
});

test("without HQN_ENABLED=1 the gateway is not even asked", async () => {
  const calls = { n: 0 };
  const r = await resolveTransportInfo({ ...EP, HQN_GATEWAY_KEYS_URL: "http://noise-gw:8081/keys" },
    { fetchImpl: fakeFetch(() => ({ keys: [key()] }), calls) });
  assert.deepEqual(r, { hqn: null });
  assert.equal(calls.n, 0);
});

test("GET /auth/transport answers without a session", async () => {
  const server = http.createServer(createAuthHandler());
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    const r = await fetch(`http://127.0.0.1:${port}/auth/transport`);
    assert.equal(r.status, 200);
    assert.ok("hqn" in (await r.json()));
  } finally {
    server.close();
  }
});
