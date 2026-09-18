// The auth server's routes, driven through the real handler.
//
// `/mqtt/authn` leads because it is the barrier between one conversation and
// another: EMQX calls it synchronously on every CONNECT, and what it answers
// decides whether a client reaches the broker at all. It had no test of any
// kind, and could not have had one — `auth/main.ts` built its server and called
// `listen()` at import time, so loading the module opened a socket.
//
// These drive `createAuthHandler()` over a real loopback server, so the routing,
// the JSON body handling and the status codes are all the production path. The
// database is the real one (see pg-helper.ts); the tests that need it skip
// loudly when it is absent rather than passing on a mock that agrees with
// whatever the code does.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as crypto from "node:crypto";
import { createAuthHandler } from "../auth/main";
import { DB } from "../services/db/api";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

// --- harness ---------------------------------------------------------------

interface Reply { status: number; body: any; text: string }

async function call(
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<Reply> {
  const server = http.createServer(createAuthHandler());
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    return await new Promise<Reply>((resolve, reject) => {
      const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
      const req = http.request(
        { port, method, path, agent: false, headers: { ...(payload ? { "content-type": "application/json" } : {}), ...headers } },
        (res) => {
          const parts: Buffer[] = [];
          res.on("data", (d: Buffer) => parts.push(d));
          res.on("end", () => {
            const text = Buffer.concat(parts).toString("utf8");
            let parsed: any = undefined;
            try { parsed = JSON.parse(text); } catch { /* not JSON; `text` carries it */ }
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

/** A client id: 64 lowercase hex, which is what everything downstream keys on. */
const someId = () => crypto.randomBytes(32).toString("hex");

// --- the shape of the service ----------------------------------------------

test("GET /health names the service", async () => {
  const r = await call("GET", "/health");
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, service: "auth" });
});

test("an unknown route is a 404, not a 200", async () => {
  for (const [m, p] of [["GET", "/"], ["POST", "/auth"], ["GET", "/mqtt/authn"], ["POST", "/nope"]] as const) {
    const r = await call(m, p);
    assert.equal(r.status, 404, `${m} ${p}`);
  }
});

// --- /mqtt/authn ------------------------------------------------------------
//
// EMQX expects HTTP 200 with { result: "allow" | "deny" } — a non-200 is a
// broker-side error, not a refusal, so EVERY outcome here is a 200 and the
// verdict rides in the body. A route that started returning 401 for a bad
// credential would read to EMQX as the auth service being broken rather than as
// the client being unwelcome.

test("/mqtt/authn denies a caller with no credentials at all", async () => {
  for (const body of [{}, { username: "" }, { password: "" }, { username: "", password: "" }]) {
    const r = await call("POST", "/mqtt/authn", body);
    assert.equal(r.status, 200, "EMQX needs a 200 even to be told no");
    assert.equal(r.body.result, "deny", JSON.stringify(body));
    assert.notEqual(r.body.is_superuser, true);
  }
});

test("/mqtt/authn denies an unknown id with a made-up token", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const r = await call("POST", "/mqtt/authn", {
    username: someId(),
    password: crypto.randomBytes(32).toString("hex"),
  });
  assert.equal(r.status, 200);
  assert.equal(r.body.result, "deny");
});

test("/mqtt/authn allows a real token and tells EMQX when it expires", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const id = someId();
  const session = await DB.mintSessionToken(id, "free", 300);
  const resolved = await DB.resolveSessionToken(session);
  assert.equal(resolved?.id, id, "the session must resolve before the token means anything");
  const mqttToken = await DB.mintMqttToken(id);

  const r = await call("POST", "/mqtt/authn", { username: id, password: mqttToken });
  assert.equal(r.status, 200);
  assert.equal(r.body.result, "allow");
  // expire_at is what makes rotation work: EMQX force-disconnects at this time
  // and the client refreshes. Without it a token would be valid for as long as
  // the connection lasted.
  assert.equal(typeof r.body.expire_at, "number");
  assert.ok(r.body.expire_at > Math.floor(Date.now() / 1000), "expire_at must be in the future");
  assert.notEqual(r.body.is_superuser, true, "an ordinary client is not a superuser");
});

test("/mqtt/authn matches the id case-insensitively but not the token", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const id = someId();
  await DB.mintSessionToken(id, "free", 300);
  const mqttToken = await DB.mintMqttToken(id);

  // The route lowercases the username, because EMQX carries whatever the client
  // put in the CONNECT packet.
  const upper = await call("POST", "/mqtt/authn", { username: id.toUpperCase(), password: mqttToken });
  assert.equal(upper.body.result, "allow", "an upper-cased id is the same id");

  // The token is a secret, not an identifier.
  const wrongCase = await call("POST", "/mqtt/authn", { username: id, password: mqttToken.toUpperCase() });
  assert.equal(wrongCase.body.result, "deny", "a token is compared exactly");
});

test("/mqtt/authn refuses a replayed CONNECT nonce", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const id = someId();
  await DB.mintSessionToken(id, "free", 300);
  const mqttToken = await DB.mintMqttToken(id);
  const nonce = crypto.randomBytes(16).toString("hex");

  const first = await call("POST", "/mqtt/authn", { username: id, password: mqttToken, nonce });
  assert.equal(first.body.result, "allow", "the first use of a nonce is fine");

  // A captured CONNECT packet, resent verbatim. Same credentials, same nonce.
  const replay = await call("POST", "/mqtt/authn", { username: id, password: mqttToken, nonce });
  assert.equal(replay.body.result, "deny", "the same nonce must not work twice");

  // …and the credential itself is still good, so the refusal was the nonce and
  // not the token being consumed.
  const fresh = await call("POST", "/mqtt/authn", {
    username: id, password: mqttToken, nonce: crypto.randomBytes(16).toString("hex"),
  });
  assert.equal(fresh.body.result, "allow", "a fresh nonce still works");
});

test("/mqtt/authn does not grant superuser without the internal secret", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The superuser arm is what push-bridge and the ops tools use, and it bypasses
  // the topic ACL entirely. Nothing that merely looks like the internal user may
  // reach it.
  const r = await call("POST", "/mqtt/authn", { username: "internal", password: "internal" });
  assert.equal(r.status, 200);
  assert.notEqual(r.body.is_superuser, true);
});

// --- /auth/refresh ----------------------------------------------------------

test("/auth/refresh needs a session bearer", async () => {
  for (const headers of [{}, { authorization: "Bearer " }, { authorization: "Bearer nonsense" }]) {
    const r = await call("POST", "/auth/refresh", {}, headers as Record<string, string>);
    assert.equal(r.status, 401, JSON.stringify(headers));
    assert.equal(r.body.error, "unauthenticated");
  }
});

test("/auth/refresh rotates the MQTT token and keeps the scope", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const id = someId();
  const session = await DB.mintSessionToken(id, "premium", 300);

  const r = await call("POST", "/auth/refresh", {}, { authorization: `Bearer ${session}` });
  assert.equal(r.status, 200);
  assert.equal(typeof r.body.mqttToken, "string");
  assert.ok(r.body.mqttToken.length > 0);
  // A refresh rotates a credential; it does not re-decide an entitlement.
  assert.equal(r.body.scope, "premium");
  assert.equal(typeof r.body.mqttTtl, "number");
  assert.ok(r.body.mqttExpiresAt > Math.floor(Date.now() / 1000));

  // The rotated token is usable, which is the point of rotating it.
  const authn = await call("POST", "/mqtt/authn", { username: id, password: r.body.mqttToken });
  assert.equal(authn.body.result, "allow");
});

test("a malformed body is a 400, not a 500", async () => {
  // Sent as raw text rather than through the JSON helper, so the body really is
  // broken on the wire.
  const server = http.createServer(createAuthHandler());
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request({ port, method: "POST", path: "/mqtt/authn", agent: false }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode!));
      });
      req.on("error", reject);
      req.end("{not json");
    });
    assert.equal(status, 400);
  } finally {
    server.close();
  }
});

test.after(async () => { await closePg(); });
