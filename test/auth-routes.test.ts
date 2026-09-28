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
import { formatProofPassword, proofMessage } from "../lib/mqtt-proof";

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

  const r = await call("POST", "/mqtt/authn", { username: id, password: mqttToken, clientid: id });
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
  const upper = await call("POST", "/mqtt/authn", { username: id.toUpperCase(), password: mqttToken, clientid: id });
  assert.equal(upper.body.result, "allow", "an upper-cased id is the same id");

  // The token is a secret, not an identifier.
  const wrongCase = await call("POST", "/mqtt/authn", { username: id, password: mqttToken.toUpperCase(), clientid: id });
  assert.equal(wrongCase.body.result, "deny", "a token is compared exactly");
});

test("/mqtt/authn refuses a clientid that is not the authenticated id", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // EMQX authorizes by CLIENTID but this route authenticates the USERNAME. A
  // valid token of one's own, presented under someone else's clientid, would
  // otherwise inherit that client's topic grants and kick its live session.
  const id = someId();
  const victim = someId();
  await DB.mintSessionToken(id, "free", 300);
  const mqttToken = await DB.mintMqttToken(id);

  for (const clientid of [victim, "", undefined, id.toUpperCase(), ` ${id}`, `${id}x`]) {
    const r = await call("POST", "/mqtt/authn", { username: id, password: mqttToken, clientid });
    assert.equal(r.status, 200);
    assert.equal(r.body.result, "deny", `clientid=${JSON.stringify(clientid)}`);
  }

  const own = await call("POST", "/mqtt/authn", { username: id, password: mqttToken, clientid: id });
  assert.equal(own.body.result, "allow", "the same id as clientid is the normal case");
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

// --- /mqtt/authn: the v1 signed CONNECT proof --------------------------------
//
// lib/mqtt-proof.ts. The client registers the public half of a per-session
// Ed25519 key at sign-in or refresh, then signs every CONNECT. These drive the
// whole path: registration over /auth/refresh, then the hook.

function signingKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { raw: spki.subarray(spki.length - 32), privateKey };
}

function v1Password(
  signer: crypto.KeyObject,
  keyId: string,
  signedClientid: string,
  opts: { ts?: number; nonce?: Buffer } = {},
): string {
  const ts = opts.ts ?? Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? crypto.randomBytes(16);
  const sig = crypto.sign(null, proofMessage(signedClientid, keyId, ts, nonce), signer);
  return formatProofPassword({ keyId, ts, nonce, sig });
}

/** A signed-in client with a registered signing key, via the real route. */
async function v1Client() {
  const id = someId();
  const session = await DB.mintSessionToken(id, "premium", 300);
  const key = signingKey();
  const r = await call("POST", "/auth/refresh", { mqttSigningKey: key.raw.toString("base64") },
    { authorization: `Bearer ${session}` });
  assert.equal(r.status, 200);
  return { id, session, key, keyId: r.body.mqttKeyId as string, refresh: r.body };
}

const authn = (id: string, password: string, clientid = id) =>
  call("POST", "/mqtt/authn", { username: id, password, clientid });

test("/auth/refresh registers a signing key and tells the client the server's time", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { refresh } = await v1Client();
  assert.match(refresh.mqttKeyId, /^[0-9a-f]{32}$/);
  const now = Math.floor(Date.now() / 1000);
  assert.ok(Math.abs(refresh.serverTime - now) <= 2, "serverTime is this clock");
  assert.ok(refresh.mqttKeyExpiresAt > now);
  // The legacy token is still minted, for a client that does not sign yet.
  assert.equal(typeof refresh.mqttToken, "string");
});

test("/auth/refresh without a key still works and registers nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const id = someId();
  const session = await DB.mintSessionToken(id, "premium", 300);
  const r = await call("POST", "/auth/refresh", {}, { authorization: `Bearer ${session}` });
  assert.equal(r.status, 200);
  assert.equal(r.body.mqttKeyId, undefined);
  assert.equal(typeof r.body.serverTime, "number");
});

test("/auth/refresh refuses a malformed signing key with a 400", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const id = someId();
  const session = await DB.mintSessionToken(id, "premium", 300);
  for (const mqttSigningKey of ["", "not base64!", crypto.randomBytes(31).toString("base64"),
    crypto.randomBytes(33).toString("base64"), 42]) {
    const r = await call("POST", "/auth/refresh", { mqttSigningKey }, { authorization: `Bearer ${session}` });
    assert.equal(r.status, 400, JSON.stringify(mqttSigningKey));
    assert.equal(r.body.error, "INVALID_MQTT_SIGNING_KEY");
  }
});

test("/mqtt/authn allows a v1 proof and expires the session with the key", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { id, key, keyId, refresh } = await v1Client();
  const r = await authn(id, v1Password(key.privateKey, keyId, id));
  assert.equal(r.body.result, "allow");
  assert.equal(r.body.expire_at, refresh.mqttKeyExpiresAt, "EMQX disconnects when the key expires");
  assert.notEqual(r.body.is_superuser, true);
});

test("/mqtt/authn refuses a replayed v1 CONNECT", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { id, key, keyId } = await v1Client();
  const password = v1Password(key.privateKey, keyId, id);
  assert.equal((await authn(id, password)).body.result, "allow");
  // The captured packet, resent verbatim — the attack the proof exists to stop.
  assert.equal((await authn(id, password)).body.result, "deny");
  // A fresh proof from the same key still works.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, id))).body.result, "allow");
});

test("/mqtt/authn holds a v1 timestamp to ±60 s", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { id, key, keyId } = await v1Client();
  const now = Math.floor(Date.now() / 1000);
  // ±58 rather than ±59: a second can tick between signing and checking.
  for (const ts of [now - 58, now + 58]) {
    assert.equal((await authn(id, v1Password(key.privateKey, keyId, id, { ts }))).body.result, "allow", `ts ${ts - now}`);
  }
  for (const ts of [now - 62, now + 62, 0]) {
    assert.equal((await authn(id, v1Password(key.privateKey, keyId, id, { ts }))).body.result, "deny", `ts ${ts - now}`);
  }
});

test("/mqtt/authn binds a v1 proof to the clientid it was signed for", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { id, key, keyId } = await v1Client();
  const victim = someId();
  // Our own proof, presented under a victim's clientid.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, id), victim)).body.result, "deny");
  // A proof SIGNED for the victim's clientid, presented as the victim.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, victim), victim)).body.result, "deny");
  // …and as ourselves: the signature no longer covers what is presented.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, victim), id)).body.result, "deny");
});

test("/mqtt/authn refuses a signature made with a different key", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const a = await v1Client();
  const stranger = signingKey();
  assert.equal((await authn(a.id, v1Password(stranger.privateKey, a.keyId, a.id))).body.result, "deny");
  // Another client's registered key, under our key id.
  const b = await v1Client();
  assert.equal((await authn(a.id, v1Password(b.key.privateKey, a.keyId, a.id))).body.result, "deny");
  // Our key, under the other client's key id.
  assert.equal((await authn(a.id, v1Password(a.key.privateKey, b.keyId, a.id))).body.result, "deny");
});

test("/mqtt/authn does not spend a nonce on a proof that fails", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { id, key, keyId } = await v1Client();
  const nonce = crypto.randomBytes(16);
  const forged = v1Password(signingKey().privateKey, keyId, id, { nonce });
  assert.equal((await authn(id, forged)).body.result, "deny");
  // Had the forgery spent it, this — the genuine CONNECT — would be refused.
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, id, { nonce }))).body.result, "allow");
});

test("/mqtt/authn refuses a revoked or expired signing key", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const revoked = await v1Client();
  await DB.revokeMqttAuth(revoked.id);
  assert.equal((await authn(revoked.id, v1Password(revoked.key.privateKey, revoked.keyId, revoked.id))).body.result, "deny");

  const id = someId();
  const key = signingKey();
  const { keyId } = await DB.registerMqttKey(id, key.raw, 0);
  assert.equal((await authn(id, v1Password(key.privateKey, keyId, id))).body.result, "deny");
});

test("a client keeps its two newest signing keys and no more", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const id = someId();
  const keys = [signingKey(), signingKey(), signingKey()];
  const ids: string[] = [];
  for (const k of keys) ids.push((await DB.registerMqttKey(id, k.raw)).keyId);
  assert.equal((await authn(id, v1Password(keys[0]!.privateKey, ids[0]!, id))).body.result, "deny", "the oldest is gone");
  assert.equal((await authn(id, v1Password(keys[1]!.privateKey, ids[1]!, id))).body.result, "allow", "the previous survives a refresh");
  assert.equal((await authn(id, v1Password(keys[2]!.privateKey, ids[2]!, id))).body.result, "allow");
});

test("/mqtt/authn refuses the legacy token once MQTT_LEGACY_TOKEN=0", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const id = someId();
  await DB.mintSessionToken(id, "free", 300);
  const mqttToken = await DB.mintMqttToken(id);
  const before = process.env.MQTT_LEGACY_TOKEN;
  try {
    process.env.MQTT_LEGACY_TOKEN = "0";
    assert.equal((await authn(id, mqttToken)).body.result, "deny");
    delete process.env.MQTT_LEGACY_TOKEN;
    assert.equal((await authn(id, mqttToken)).body.result, "allow", "on by default");
  } finally {
    if (before === undefined) delete process.env.MQTT_LEGACY_TOKEN;
    else process.env.MQTT_LEGACY_TOKEN = before;
  }
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
  const authn = await call("POST", "/mqtt/authn", { username: id, password: r.body.mqttToken, clientid: id });
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
