// The key-possession handshake, end to end, with the real KEM and a real database.
//
// This is how every client — every app, and the helper bot — proves it holds the
// secret key for the identity it claims. Nothing else on this server establishes
// identity: `/mqtt/authn` only checks a token that this exchange minted.
//
// It had no test. `auth/main.ts` called `listen()` at import so nothing could
// load it, and even after that seam was opened the handshake itself stayed
// uncovered, because `handleInit` requires `lib/hqc` and that threw on every
// platform but Linux/x86. Both are fixed, so for the first time these run on the
// machine the code is written on.
//
// WHAT IS REAL HERE. The HQC keypair, the encapsulation, the decapsulation, the
// HKDF proof, the loopback HTTP, and the database. Nothing is stubbed, because
// the failure modes worth catching — a proof accepted for the wrong key, a
// challenge that can be replayed, a length comparison that throws — all live in
// the seams between those pieces.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as crypto from "node:crypto";
import { createAuthHandler } from "../auth/main";
import { authProof } from "../lib/auth-proof";
import { peerId } from "../lib/identity";
import { q } from "../services/db/pg";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";
import { readFileSync } from "node:fs";
import { join } from "node:path";

setLogLevel("silent");   // the failure path logs per attempt; see the alert test

// --- harness -----------------------------------------------------------------------

interface Reply { status: number; body: any; text: string }

const handler = createAuthHandler();

async function call(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Reply> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as any).port;
  try {
    return await new Promise<Reply>((resolve, reject) => {
      const payload = Buffer.from(JSON.stringify(body));
      const req = http.request(
        { port, host: "127.0.0.1", method: "POST", path, agent: false,
          headers: { "content-type": "application/json", ...headers } },
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
      req.write(payload);
      req.end();
    });
  } finally {
    server.close();
  }
}

/** A real HQC identity. Deterministic from a seed so a failure is reproducible. */
function identity(seed?: Buffer) {
  const { HqcWrapper } = require("../lib/hqc") as typeof import("../lib/hqc");
  const { pk, sk } = HqcWrapper.keypairFromSeed(seed ?? crypto.randomBytes(32));
  return { pk, sk, pkHex: pk.toString("hex"), id: peerId(pk.toString("hex")) };
}

/** What a client does with the server's challenge: decapsulate, then HKDF. */
function solve(sk: Buffer, ctB64: string): string {
  const { HqcWrapper } = require("../lib/hqc") as typeof import("../lib/hqc");
  const ss = HqcWrapper.decapsulate(sk, Buffer.from(ctB64, "base64"));
  // The PROOF, never the secret — the handshake must not be a decryption oracle.
  return authProof(ss).toString("base64");
}

const created: string[] = [];

/** Everything this file wrote, by id. */
async function cleanup(): Promise<void> {
  if (!created.length) return;
  const ids = [...new Set(created)];
  for (const sql of [
    `DELETE FROM mqtt_tokens WHERE id = ANY($1::text[])`,
    `DELETE FROM sessions WHERE id = ANY($1::text[])`,
    `DELETE FROM friendships WHERE id_a = ANY($1::text[]) OR id_b = ANY($1::text[])`,
    `DELETE FROM auth_challenges WHERE id = ANY($1::text[])`,
    `DELETE FROM users WHERE id = ANY($1::text[])`,
  ]) {
    try { await q(sql, [ids]); } catch { /* a column this schema does not have */ }
  }
  // `init:ip:%` too. Every request in this file comes from 127.0.0.1, so the
  // per-IP ceiling (20/min) is shared by the WHOLE file — without this, the
  // first few tests spend the budget and every one after them reads 429, which
  // surfaces as a confusing assertion about ciphertexts rather than as a limit.
  await q(
    `DELETE FROM rate_counters WHERE key LIKE 'init:ip:%' OR key LIKE 'init:pk:%' OR key LIKE 'verify:fail:%'`,
  );
  created.length = 0;
}

/** A full init → verify, as a client performs it. */
async function handshake(door: "free" | "paid" = "free", seed?: Buffer) {
  const me = identity(seed);
  created.push(me.id);
  const init = await call(`/auth/${door}/init`, { pk: me.pkHex });
  assert.equal(init.status, 200, `init failed: ${init.text}`);
  const verify = await call(`/auth/${door}/verify`, {
    pk: me.pkHex,
    solution: solve(me.sk, init.body.ct),
  });
  return { me, init, verify };
}

test.afterEach(async () => { await cleanup(); });
test.after(async () => { await cleanup(); await closePg(); });

// --- the exchange ---------------------------------------------------------------------

test("a client that holds the key gets a session", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { me, init, verify } = await handshake();

  assert.ok(init.body.ct, "init must answer with a KEM ciphertext");
  const ct = Buffer.from(init.body.ct, "base64");
  assert.equal(ct.length, 14421, "an HQC-256 KEM ciphertext");

  assert.equal(verify.status, 200, verify.text);
  assert.equal(verify.body.id, me.id, "the id is derived from the key, not chosen by the caller");
  assert.equal(verify.body.pk, me.pkHex, "the key is echoed so a client can confirm what was read");
  assert.equal(verify.body.scope, "free");
  assert.ok(verify.body.sessionToken, "a session token");
  assert.ok(verify.body.mqttToken, "and an MQTT token — without it the client cannot reach the broker");
  assert.ok(verify.body.mqttTtl > 0);
  // Absolute expiry, so a client can refresh before EMQX force-disconnects it.
  const now = Math.floor(Date.now() / 1000);
  assert.ok(verify.body.mqttExpiresAt > now, "expiry must be in the future");
  assert.ok(verify.body.mqttExpiresAt <= now + verify.body.mqttTtl + 5);
});

test("the challenge never carries the secret, only something derived from it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The handshake must not be a decryption oracle. What crosses the wire is the
  // KEM ciphertext one way and HKDF(ss, "auth") the other; the shared secret
  // itself appears in neither.
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/free/init", { pk: me.pkHex });
  const { HqcWrapper } = require("../lib/hqc") as typeof import("../lib/hqc");
  const ss = HqcWrapper.decapsulate(me.sk, Buffer.from(init.body.ct, "base64"));

  assert.ok(!init.text.includes(ss.toString("base64")), "the shared secret was returned");
  assert.ok(!init.text.includes(ss.toString("hex")));

  const solution = authProof(ss);
  assert.notDeepEqual(solution, ss, "the proof must not simply be the secret");
  const verify = await call("/auth/free/verify", { pk: me.pkHex, solution: solution.toString("base64") });
  assert.equal(verify.status, 200, verify.text);
  assert.ok(!verify.text.includes(ss.toString("base64")), "…and neither does the session response");
});

test("the stored challenge is the proof, not the secret", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // A database dump must not hand anybody a working solution for a challenge
  // that is still open. What is stored is what the client will send, which is
  // already one HKDF away from the secret.
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/free/init", { pk: me.pkHex });
  const { HqcWrapper } = require("../lib/hqc") as typeof import("../lib/hqc");
  const ss = HqcWrapper.decapsulate(me.sk, Buffer.from(init.body.ct, "base64"));

  const rows = await q<{ c: string }>(
    `SELECT * FROM auth_challenges WHERE id = $1`, [me.id],
  );
  assert.equal(rows.rows.length, 1, "one open challenge");
  const stored = JSON.stringify(rows.rows[0]);
  assert.ok(!stored.includes(ss.toString("hex")), "the shared secret is in the database");
  assert.ok(stored.includes(authProof(ss).toString("hex")), "the expected proof should be");
});

// --- refusals ---------------------------------------------------------------------------

test("a wrong proof is refused, and mints nothing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const me = identity();
  created.push(me.id);
  await call("/auth/free/init", { pk: me.pkHex });

  const bad = await call("/auth/free/verify", {
    pk: me.pkHex, solution: crypto.randomBytes(32).toString("base64"),
  });
  assert.equal(bad.status, 401);
  assert.equal(bad.body.error, "auth failed");
  assert.ok(!bad.body.sessionToken && !bad.body.mqttToken, bad.text);
  const sessions = await q(`SELECT 1 FROM sessions WHERE id = $1`, [me.id]);
  assert.equal(sessions.rows.length, 0, "a refused proof must not leave a session behind");
});

test("a proof of the WRONG LENGTH is refused rather than throwing", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `crypto.timingSafeEqual` THROWS on buffers of different length. That is the
  // whole reason `safeEqualStr` compares lengths first — without it a one-byte
  // solution is a 500 from inside the comparison, and a 500 where a 401 belongs
  // is an oracle: it distinguishes "wrong length" from "wrong value".
  const me = identity();
  created.push(me.id);
  await call("/auth/free/init", { pk: me.pkHex });

  for (const wrong of [
    Buffer.alloc(1).toString("base64"),
    Buffer.alloc(31).toString("base64"),
    Buffer.alloc(33).toString("base64"),
    Buffer.alloc(4096).toString("base64"),
    "",
    "not-base64-at-all!!",
  ]) {
    // Each attempt consumes the challenge, so re-open it.
    await call("/auth/free/init", { pk: me.pkHex });
    const res = await call("/auth/free/verify", { pk: me.pkHex, solution: wrong });
    assert.equal(res.status, 401, `length ${wrong.length} produced ${res.status}: ${res.text}`);
  }
});

test("a challenge is single-use, so a captured proof cannot be replayed", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `takeAuthChallenge` consumes atomically. Without that, anyone who observed
  // one successful exchange could repeat it forever — the proof is a fixed
  // function of the ciphertext, so it does not change on its own.
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/free/init", { pk: me.pkHex });
  const solution = solve(me.sk, init.body.ct);

  const first = await call("/auth/free/verify", { pk: me.pkHex, solution });
  assert.equal(first.status, 200, first.text);

  const replay = await call("/auth/free/verify", { pk: me.pkHex, solution });
  assert.equal(replay.status, 401, "the same proof was accepted twice");
});

test("a second init replaces the first challenge, it does not add one", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `startAuthChallenge` upserts, so one key has at most one open challenge.
  // The consequence worth pinning: the LATEST ciphertext is the one that works,
  // and an attacker who makes the server issue a second challenge does not keep
  // the first one alive alongside it.
  const me = identity();
  created.push(me.id);
  const a = await call("/auth/free/init", { pk: me.pkHex });
  const b = await call("/auth/free/init", { pk: me.pkHex });
  assert.equal(a.status, 200, a.text);
  assert.equal(b.status, 200, b.text);
  assert.notEqual(a.body.ct, b.body.ct, "each init must encapsulate afresh");

  const rows = await q(`SELECT 1 FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.equal(rows.rows.length, 1, "two inits must not leave two open challenges");

  const current = await call("/auth/free/verify", { pk: me.pkHex, solution: solve(me.sk, b.body.ct) });
  assert.equal(current.status, 200, `the latest challenge should verify: ${current.text}`);
});

test("a superseded ciphertext no longer verifies", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const me = identity();
  created.push(me.id);
  const a = await call("/auth/free/init", { pk: me.pkHex });
  await call("/auth/free/init", { pk: me.pkHex });        // supersedes it
  const stale = await call("/auth/free/verify", { pk: me.pkHex, solution: solve(me.sk, a.body.ct) });
  assert.equal(stale.status, 401, "a superseded challenge was still accepted");
});

test("a wrong proof BURNS the challenge — one guess per init", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `takeAuthChallenge` deletes unconditionally and then compares, so a failed
  // attempt consumes the challenge along with a successful one. That is the
  // right way round — it caps an attacker at one guess per challenge, and
  // `/auth/*/init` is itself rate-limited per key — but it is not obvious, and a
  // client that retries a failed verify without re-initing simply cannot log in.
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/free/init", { pk: me.pkHex });
  const good = solve(me.sk, init.body.ct);

  const wrong = await call("/auth/free/verify", {
    pk: me.pkHex, solution: crypto.randomBytes(32).toString("base64"),
  });
  assert.equal(wrong.status, 401);

  const retry = await call("/auth/free/verify", { pk: me.pkHex, solution: good });
  assert.equal(retry.status, 401, "the CORRECT proof after a wrong one — the challenge is gone");

  const rows = await q(`SELECT 1 FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.equal(rows.rows.length, 0, "…and nothing is left behind for a later attempt");
});

test("a proof solved with another key does not authenticate", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The whole point: holding SOME key is not holding THIS key.
  const victim = identity();
  const attacker = identity();
  created.push(victim.id, attacker.id);

  const victimInit = await call("/auth/free/init", { pk: victim.pkHex });
  // The attacker decapsulates the victim's ciphertext with their own secret key.
  // HQC is IND-CCA2, so this yields a pseudo-random secret rather than an error
  // — there is no oracle here, only a proof that will not match.
  const res = await call("/auth/free/verify", {
    pk: victim.pkHex, solution: solve(attacker.sk, victimInit.body.ct),
  });
  assert.equal(res.status, 401, "a proof from the wrong secret key was accepted");
});

test("verifying without an open challenge is refused", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const me = identity();
  created.push(me.id);
  const res = await call("/auth/free/verify", {
    pk: me.pkHex, solution: crypto.randomBytes(32).toString("base64"),
  });
  assert.equal(res.status, 401, "no challenge was ever opened for this key");
});

// --- what counts as a public key ------------------------------------------------------------

test("a malformed public key is refused before anything expensive runs", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The order in `handleInit` is deliberate and stated there: cheap shape check,
  // then the counters, then admission, and only then `dlopen` and a KEM-sized
  // CPU burn. These never reach the native library at all.
  for (const pk of ["", "zz", "0x1234", "ABCDEF".repeat(10), "12 34", null, 12345, {}]) {
    const res = await call("/auth/free/init", { pk });
    assert.equal(res.status, 400, `${JSON.stringify(pk)} produced ${res.status}`);
    assert.match(res.body.error, /public key/);
  }
});

test("hex of the right shape but the wrong length is still refused", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // This one passes the charset check and IS measured against
  // HQC_CONSTANTS.PUBLIC_KEY_BYTES — after the rate-limit counters and the
  // admission lookup have already run. Pinned because the ordering is what the
  // comment in `handleInit` promises, and a shorter path would be a change to
  // what an unauthenticated caller can make this server do.
  for (const pk of ["ab", "00".repeat(100), "ff".repeat(7236), "ab".repeat(7238)]) {
    const res = await call("/auth/free/init", { pk });
    assert.equal(res.status, 400, `${pk.length / 2} bytes produced ${res.status}: ${res.text}`);
  }
});

test("an uppercase key is the same identity as its lowercase form", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The id is a digest of the hex, so a client that sends uppercase must not
  // become a second account.
  const me = identity();
  created.push(me.id);
  const init = await call("/auth/free/init", { pk: me.pkHex.toUpperCase() });
  assert.equal(init.status, 200, init.text);
  const verify = await call("/auth/free/verify", {
    pk: me.pkHex.toUpperCase(), solution: solve(me.sk, init.body.ct),
  });
  assert.equal(verify.status, 200, verify.text);
  assert.equal(verify.body.id, me.id);
  assert.equal(verify.body.pk, me.pkHex, "normalised to lowercase on the way back");
});

// --- what a successful login leaves behind ------------------------------------------------

test("a login records the identity key", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `users.identity_pk` is written HERE and nowhere else — this is the moment
  // the caller has proved it holds the secret key, and it is what makes
  // `GET /peer/{id}/key` answerable at all.
  const { me, verify } = await handshake();
  assert.equal(verify.status, 200, verify.text);

  const user = await q<{ identity_pk: string }>(
    `SELECT identity_pk FROM users WHERE id = $1`, [me.id],
  );
  assert.equal(user.rows.length, 1, "the login did not record the user");
  assert.equal(user.rows[0]!.identity_pk, me.pkHex);

  // No topic rows either: the broker's ACL is static and keys the client's own
  // topics on its authenticated clientid (infra/deploy/emqx/acl.conf), so a
  // login has nothing to open.
});

test("the paid door mints a premium scope", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Admission is `open` by default — there is nothing to pay for now — so the
  // paid door is a pass. What it still decides is the scope stamped on the
  // session, which outlives the request.
  const { verify } = await handshake("paid");
  assert.equal(verify.status, 200, verify.text);
  assert.equal(verify.body.scope, "premium");
});

test("a login is idempotent — the same key twice is one account", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const seed = crypto.randomBytes(32);
  const first = await handshake("free", seed);
  assert.equal(first.verify.status, 200, first.verify.text);
  const second = await handshake("free", seed);
  assert.equal(second.verify.status, 200, second.verify.text);

  assert.equal(first.verify.body.id, second.verify.body.id);
  assert.notEqual(first.verify.body.sessionToken, second.verify.body.sessionToken,
    "each login mints a fresh session token");
  const users = await q(`SELECT 1 FROM users WHERE id = $1`, [first.me.id]);
  assert.equal(users.rows.length, 1, "one row per identity");
});

// --- the alert on repeated failures ------------------------------------------------------------

test("a run of failed proofs raises exactly one alert, and a success clears it", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Repeated failed proofs against one key are the signature of someone trying
  // to sign in as a key they do not hold. Nothing counted them before, so the
  // attempt was invisible however long it ran.
  //
  // `failures === VERIFY_FAILURE_ALERT` is an equality, deliberately: it fires
  // once per run rather than on every attempt past the threshold. Asserted both
  // ways, because "alerts every time" and "never alerts again" are the two ways
  // this stops being useful.
  const alerts: string[] = [];
  const savedError = console.error;
  setLogLevel("error");
  console.error = (...a: unknown[]) => alerts.push(a.map(String).join(" "));

  const me = identity();
  created.push(me.id);
  try {
    // No init. A verify with no open challenge takes the same failure branch and
    // bumps the same counter — which is right, since that is exactly what a
    // blind attacker does. It also keeps this test under the per-key init
    // ceiling of 6/min, which eight rounds of init would otherwise trip.
    for (let i = 0; i < 8; i++) {
      const res = await call("/auth/free/verify", {
        pk: me.pkHex, solution: crypto.randomBytes(32).toString("base64"),
      });
      assert.equal(res.status, 401);
    }
  } finally {
    console.error = savedError;
    setLogLevel("silent");
  }

  const raised = alerts.filter((l) => /failed key-possession proofs/.test(l));
  assert.equal(raised.length, 1, `eight failures raised ${raised.length} alerts:\n${alerts.join("\n")}`);
  assert.match(raised[0]!, /5 failed key-possession proofs in 15m/);

  // A success clears the run, so the next burst can alert again rather than
  // being swallowed by a counter that never resets.
  const init = await call("/auth/free/init", { pk: me.pkHex });
  const ok = await call("/auth/free/verify", { pk: me.pkHex, solution: solve(me.sk, init.body.ct) });
  assert.equal(ok.status, 200, ok.text);
  const counter = await q(`SELECT 1 FROM rate_counters WHERE key = $1`, [`verify:fail:${me.id}`]);
  assert.equal(counter.rows.length, 0, "a success must clear the failure run");
});

// --- the two counters in front of the encapsulation --------------------------------------

test("one key cannot open unlimited challenges", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `/auth/*/init` cannot require authentication — proving who you are is what
  // it is FOR — and every call runs an HQC encapsulation plus a database write.
  // Since the paywall was removed these two counters are the only thing standing
  // in front of that: an unclaimed key used to be turned away at the full door
  // for the cost of one primary-key lookup, so the CPU sat behind a
  // subscription. Nothing is behind a subscription now.
  //
  // A real client runs one init per login, so six is generous.
  const me = identity();
  created.push(me.id);
  const statuses: number[] = [];
  for (let i = 0; i < 8; i++) {
    statuses.push((await call("/auth/free/init", { pk: me.pkHex })).status);
  }
  assert.deepEqual(statuses.slice(0, 6), [200, 200, 200, 200, 200, 200],
    `the first six must be served: ${statuses.join(", ")}`);
  assert.deepEqual(statuses.slice(6), [429, 429], `the rest must be refused: ${statuses.join(", ")}`);
});

test("the rate-limit key is the id, not the 14 kB public key", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `init:pk:{id}`. It used to carry a whole HQC public key into `rate_counters`
  // as a primary key, which is why that table needed the same digest treatment
  // as the identity tables.
  const me = identity();
  created.push(me.id);
  await call("/auth/free/init", { pk: me.pkHex });

  const rows = await q<{ key: string }>(
    `SELECT key FROM rate_counters WHERE key LIKE 'init:pk:%'`,
  );
  assert.ok(rows.rows.length >= 1, "no per-key counter was written");
  for (const r of rows.rows) {
    assert.ok(r.key.length < 100, `a ${r.key.length}-character counter key`);
    assert.ok(!r.key.includes(me.pkHex), "the public key itself is the counter key");
  }
  assert.ok(rows.rows.some((r) => r.key === `init:pk:${me.id}`), rows.rows.map((r) => r.key).join(", "));
});

test("a refused init does not open a challenge", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The counters sit BEFORE the encapsulation and before the database write, so
  // a rate-limited caller costs two counter bumps and nothing else. If the
  // challenge were written first, the limit would still burn a KEM operation per
  // request and would be worth very little.
  const me = identity();
  created.push(me.id);
  for (let i = 0; i < 6; i++) await call("/auth/free/init", { pk: me.pkHex });
  await q(`DELETE FROM auth_challenges WHERE id = $1`, [me.id]);

  const refused = await call("/auth/free/init", { pk: me.pkHex });
  assert.equal(refused.status, 429, refused.text);
  const rows = await q(`SELECT 1 FROM auth_challenges WHERE id = $1`, [me.id]);
  assert.equal(rows.rows.length, 0, "a refused init wrote a challenge anyway");
});

test("a malformed key costs nothing — not even a counter row", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The charset check is the FIRST thing `handleInit` does, before the two
  // counters and before the database is touched at all. Removing it is
  // invisible in the status code — the length check downstream still answers
  // 400 — so the only thing that shows it is what was written on the way.
  //
  // It matters because those counters are a shared, finite resource: a caller
  // sending junk that reached them would consume the per-IP budget for everyone
  // behind the same NAT.
  await q(`DELETE FROM rate_counters WHERE key LIKE 'init:ip:%' OR key LIKE 'init:pk:%'`);
  for (const pk of ["zz", "0x1234", "not a key", "12 34"]) {
    const res = await call("/auth/free/init", { pk });
    assert.equal(res.status, 400, `${pk} -> ${res.status}`);
  }
  const rows = await q<{ key: string }>(
    `SELECT key FROM rate_counters WHERE key LIKE 'init:ip:%' OR key LIKE 'init:pk:%'`,
  );
  assert.deepEqual(rows.rows, [],
    `a malformed key reached the rate counters: ${rows.rows.map((r) => r.key).join(", ")}`);
});

test("the proof comparison is constant-time, structurally", async () => {
  // The one property in this file that an assertion cannot observe. Replacing
  // `safeEqualStr(a, b)` with `a !== b` changes no status code, no body and no
  // row — it changes only how long a mismatch takes, and a timing oracle over
  // loopback in a test process would measure the scheduler, not the compare.
  // Verified: that exact substitution passes every other test here.
  //
  // So this asserts the shape instead, which is the honest thing a test can do.
  const src = readFileSync(join(__dirname, "..", "auth", "main.ts"), "utf8");

  assert.match(src, /!safeEqualStr\(solutionHex, expectedHex\)/,
    "the key-possession proof must be compared with safeEqualStr, not with === or !==");

  const fn = src.slice(src.indexOf("function safeEqualStr"));
  const body = fn.slice(0, fn.indexOf("\n}"));
  assert.match(body, /crypto\.timingSafeEqual/, "safeEqualStr must use timingSafeEqual");
  // timingSafeEqual THROWS on differing lengths, so the guard is not optional —
  // without it a wrong-length solution is a 500 where a 401 belongs, which is
  // itself an oracle distinguishing "wrong length" from "wrong value".
  assert.match(body, /ab\.length !== bb\.length/, "…and must compare lengths before it");
});
