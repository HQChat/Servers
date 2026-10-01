// The EMQX admin transport's credential choice (lib/emqx-api.ts).
//
// The dashboard-login path (token reuse, the single 401 retry, login failures)
// is covered through broker-watch in broker-watch-checks.test.ts. This file
// covers the API key: when it is configured it wins, it is sent as HTTP Basic,
// and it never touches /login — a key has no session to refresh, so a 401 is an
// answer, not a cue to retry.

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { emqxApi, emqxApiConfigured, resetEmqxApiToken } from "../lib/emqx-api";

interface Call { url: string; init: any }
let calls: Call[] = [];
let status = 200;
const savedFetch = globalThis.fetch;
const savedEnv = { ...process.env };

beforeEach(() => {
  calls = [];
  status = 200;
  resetEmqxApiToken();
  for (const k of ["EMQX_API_KEY", "EMQX_API_SECRET", "EMQX_DASHBOARD_USER", "EMQX_DASHBOARD_PASSWORD"]) delete process.env[k];
  process.env.EMQX_API_URL = "http://emqx.test:18083";
  (globalThis as any).fetch = async (url: any, init: any) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith("/login")) return { ok: true, status: 200, json: async () => ({ token: "tok" }) };
    return { ok: status < 300, status, json: async () => ({}) };
  };
});

afterEach(() => {
  globalThis.fetch = savedFetch;
  process.env = { ...savedEnv };
});

test("no credential at all is reported as not configured", () => {
  assert.equal(emqxApiConfigured(), false);
  process.env.EMQX_API_KEY = "hqcat-svc";                 // half a key is no key
  assert.equal(emqxApiConfigured(), false);
});

test("an API key is sent as Basic auth and never logs in", async () => {
  process.env.EMQX_API_KEY = "hqcat-svc";
  process.env.EMQX_API_SECRET = "k3y-s3cret";
  process.env.EMQX_DASHBOARD_PASSWORD = "also-set";      // the key must still win
  assert.equal(emqxApiConfigured(), true);

  await emqxApi("DELETE", "clients/abc");
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, "http://emqx.test:18083/api/v5/clients/abc");
  assert.equal(calls[0]!.init.method, "DELETE");
  assert.equal(calls[0]!.init.headers.authorization, `Basic ${Buffer.from("hqcat-svc:k3y-s3cret").toString("base64")}`);
  assert.ok(calls[0]!.init.signal, "bounded by a timeout");
  assert.ok(!calls.some((c) => c.url.includes("k3y-s3cret")), "the secret never goes in a URL");
});

test("a 401 with an API key is returned as-is, not retried", async () => {
  process.env.EMQX_API_KEY = "hqcat-svc";
  process.env.EMQX_API_SECRET = "wrong";
  status = 401;
  const res = await emqxApi("GET", "nodes");
  assert.equal(res.status, 401);
  assert.equal(calls.length, 1, "one request, no login, no retry");
});

test("without a key it falls back to the dashboard login", async () => {
  process.env.EMQX_DASHBOARD_PASSWORD = "dash";
  assert.equal(emqxApiConfigured(), true);
  await emqxApi("POST", "clients/abc/unsubscribe", { topic: "cv/x" });
  assert.equal(calls[0]!.url, "http://emqx.test:18083/api/v5/login");
  assert.equal(JSON.parse(calls[0]!.init.body).username, "admin");
  assert.equal(calls[1]!.init.headers.authorization, "Bearer tok");
  assert.equal(calls[1]!.init.headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(calls[1]!.init.body), { topic: "cv/x" });
});
