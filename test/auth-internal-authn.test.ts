// The two MQTT authentication hooks, and the one line between them.
//
// The broker's internal listener allows WILDCARD subscriptions — the
// push-bridge needs `u/+/presence` and `$share/…/cv/+` — and every other
// listener refuses them, which is what keeps anybody from subscribing to `cv/+`
// and reading every conversation. So the hooks must never cross:
//
//   /mqtt/authn/internal   the internal identity, and NOTHING else
//   /mqtt/authn            everybody else, and NEVER a superuser
//
// A superuser also bypasses the static ACL, so the internal secret presented on
// a public listener must be refused, not merely demoted.

import { INTERNAL_USER, INTERNAL_SECRET } from "./helpers/internal-mqtt-env";

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as crypto from "node:crypto";
import { createAuthHandler } from "../auth/main";
import { DB } from "../services/db/api";
import { peerId } from "../lib/identity";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

async function authn(path: string, body: unknown): Promise<{ status: number; body: any }> {
  const server = http.createServer(createAuthHandler());
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  } finally {
    server.close();
  }
}

test("the internal hook admits the internal identity as a superuser", async () => {
  const r = await authn("/mqtt/authn/internal", { username: INTERNAL_USER, password: INTERNAL_SECRET });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { result: "allow", is_superuser: true });
});

test("the internal hook refuses everything else, including a wrong secret", async () => {
  for (const body of [
    {},
    { username: INTERNAL_USER, password: "" },
    { username: INTERNAL_USER, password: INTERNAL_SECRET + "x" },
    { username: "someone-else", password: INTERNAL_SECRET },
  ]) {
    const r = await authn("/mqtt/authn/internal", body);
    assert.equal(r.status, 200, "EMQX needs a 200 even to be told no");
    assert.equal(r.body.result, "deny", JSON.stringify(body));
    assert.notEqual(r.body.is_superuser, true);
  }
});

test("an ordinary client with a valid token is refused on the internal hook", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The case that matters: a real account, reaching the wildcard listener.
  const id = peerId(crypto.randomBytes(64).toString("hex"));
  await DB.mintSessionToken(id, "free", 300);
  const token = await DB.mintMqttToken(id);
  const pub = await authn("/mqtt/authn", { username: id, password: token, clientid: id });
  assert.equal(pub.body.result, "allow", "setup: the token is good on the public hook");
  const internal = await authn("/mqtt/authn/internal", { username: id, password: token, clientid: id });
  assert.equal(internal.body.result, "deny", "an account was admitted to the wildcard listener");
});

test("the public hook never grants superuser — not even to the internal secret", async () => {
  const r = await authn("/mqtt/authn", { username: INTERNAL_USER, password: INTERNAL_SECRET, clientid: "x" });
  assert.equal(r.status, 200);
  assert.equal(r.body.result, "deny", "the internal secret opened a public-listener session");
  assert.notEqual(r.body.is_superuser, true);
});

test.after(closePg);
