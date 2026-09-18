// Surgical revocation, and the reason it never once worked on this deployment.
//
// ── The failure ──────────────────────────────────────────────────────────────
//
// `lib/emqx.ts` exists so that revocation ACTS instead of waiting: deleting an
// ACL row stops the NEXT authorization check, but EMQX checks authorization at
// SUBSCRIBE, not per message, so an unfriended peer's already-open subscription
// keeps delivering until they disconnect for their own reasons. The admin API
// is what closes that window — `DELETE /clients/{id}/subscriptions/{topic}`.
//
// Both path segments were public keys. A client id was 14474 characters and a
// conversation topic embedded a hash of two more, so the request line ran to
// roughly 14.5 kB and EMQX answered `414 URI Too Long`. Every time. The code
// treats a failed kick as best-effort and logs it, so the unfriend still
// succeeded and nothing surfaced — the only visible symptom was that revoked
// peers kept receiving, which looks like a protocol bug rather than a URL one.
//
// ── What is asserted here ────────────────────────────────────────────────────
//
// Not "the URL is short". That is a consequence. What matters is the request
// the client actually PUTS ON THE WIRE, so this runs the real `EMQX` against a
// real HTTP server standing in for the broker and inspects what arrives:
//
//   1. an unsubscribe names ONE client and ONE topic, so the peer's other
//      conversations are untouched (the reason this is not a kick);
//   2. the request line fits comfortably inside any sane limit;
//   3. a kick — account deletion, a revoked device — is a single client too.
//
// The size assertions use the OLD sizes as the counter-example, so a change that
// puts a key back into an identifier fails here rather than in production
// fifteen minutes after a deploy.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as crypto from "node:crypto";
import { peerId } from "../lib/identity";
import { friendshipHash } from "../lib/crypto-utils";
import { setLogLevel } from "../lib/logger";

setLogLevel("silent");

const HQC_PUBLIC_KEY_BYTES = 7237;

/**
 * The bound this is really about.
 *
 * EMQX's HTTP listener refuses a request line past its limit with 414, and
 * anything in front of it (nginx defaults to 8 kB of request line + headers)
 * would too. 2048 is the conservative figure every HTTP client and proxy is
 * safe under; the point is not the exact number but that we are two orders of
 * magnitude below it rather than two above.
 */
const SAFE_URL_LENGTH = 2048;

/** Requests the fake broker saw, in order. */
const seen: string[] = [];

const bodies: string[] = [];
let server: http.Server;
let EMQX: typeof import("../lib/emqx").EMQX;

test("start a stand-in broker", async () => {
  server = http.createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    // Bodies matter for `publish`, which is the only admin call that carries
    // one — the rest say everything in the URL.
    let raw = "";
    req.on("data", (chunk) => { raw += chunk; });
    req.on("end", () => {
      if (raw) bodies.push(raw);
      res.writeHead(200, { "content-type": "application/json" });
      // Every admin call goes through `login` first, so the token has to be real
      // enough for the client to carry on.
      res.end(JSON.stringify({ token: "stub-token" }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;

  // Read at module scope in lib/emqx.ts, so both must be set before the require.
  process.env.EMQX_API_URL = `http://127.0.0.1:${port}`;
  process.env.EMQX_DASHBOARD_PASSWORD = "stub";
  EMQX = (require("../lib/emqx") as typeof import("../lib/emqx")).EMQX;
  assert.ok(EMQX.enabled, "an admin credential is configured");
});

test("unfriending drops ONE subscription, and the request fits in a URL", async () => {
  const [pkA, pkB] = [
    crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex"),
    crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex"),
  ];
  const [a, b] = [peerId(pkA), peerId(pkB)];
  const topic = `c/${friendshipHash(a, b)}`;

  seen.length = 0;
  await EMQX.revokeTopic(a, b, topic);

  const unsubscribes = seen.filter((line) => line.startsWith("DELETE"));
  assert.equal(unsubscribes.length, 2, "one call per member of the friendship");

  for (const line of unsubscribes) {
    const url = line.slice("DELETE ".length);
    // A SUBSCRIPTION endpoint, not a client one. Dropping the connection would
    // also drop the peer's other conversations, which are none of our business —
    // that trade was only ever forced by the URL not fitting.
    assert.match(url, /^\/api\/v5\/clients\/[0-9a-f]{64}\/subscriptions\/.+$/,
      "names one client and one topic");
    assert.ok(url.length < SAFE_URL_LENGTH,
      `the admin URL is ${url.length} characters, against a ${SAFE_URL_LENGTH} bound`);
    assert.ok(url.includes(encodeURIComponent(topic)), "the topic is the one being revoked");
  }

  // Both members, and only those two.
  assert.ok(unsubscribes.some((l) => l.includes(a)), "A's subscription is dropped");
  assert.ok(unsubscribes.some((l) => l.includes(b)), "B's subscription is dropped");
});

test("the same call built from public keys would NOT have fit", async () => {
  // The counter-example, computed rather than remembered. This is the request
  // this deployment was making every time somebody unfriended anybody.
  const pk = crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex");
  const oldTopic = `c/${friendshipHash(pk, pk)}`;
  const oldUrl =
    `/api/v5/clients/${encodeURIComponent(pk)}/subscriptions/${encodeURIComponent(oldTopic)}`;
  assert.ok(oldUrl.length > 14000, `the old URL was ${oldUrl.length} characters`);
  assert.ok(oldUrl.length > SAFE_URL_LENGTH * 7, "…which is why EMQX answered 414");

  // And the same request today, for scale.
  const id = peerId(pk);
  const newUrl =
    `/api/v5/clients/${id}/subscriptions/${encodeURIComponent(`c/${friendshipHash(id, id)}`)}`;
  assert.ok(newUrl.length < 200, `the same call is now ${newUrl.length} characters`);
});

test("a kick names one client, and also fits", async () => {
  // Account deletion and a revoked device, where ending the whole session IS the
  // intent — its queued QoS-1 backlog goes with it.
  const id = peerId(crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex"));
  seen.length = 0;
  assert.equal(await EMQX.kick(id), true);

  const kicks = seen.filter((l) => l.startsWith("DELETE"));
  assert.equal(kicks.length, 1);
  const url = kicks[0]!.slice("DELETE ".length);
  assert.equal(url, `/api/v5/clients/${id}`);
  assert.ok(url.length < SAFE_URL_LENGTH, `${url.length} characters`);
});

test("a graph nudge is one publish per account, on that account's own topic", async () => {
  // The whole reason this exists: the friend graph was the one piece of state
  // the server owned and the client could only learn by ASKING, on a 60-second
  // poll. So an invite sat unseen until the next tick, and an `init` from a
  // freshly accepted contact could reach the inviter before their directory had
  // the sender's client id in it at all — a frame naming nobody they knew, which
  // the client dropped.
  const [a, b] = [peerId(crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex")),
                  peerId(crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex"))];

  seen.length = 0;
  bodies.length = 0;
  await EMQX.notifyGraphChanged([a, b]);

  const publishes = seen.filter((line) => line === "POST /api/v5/publish");
  assert.equal(publishes.length, 2, "one publish per account, not one broadcast");
  assert.equal(bodies.length, 2);

  const topics = bodies.map((raw) => JSON.parse(raw).topic).sort();
  assert.deepEqual(topics, [`u/${a}/graph`, `u/${b}/graph`].sort(),
    "each account is told on its OWN topic — the one only it may subscribe to");

  for (const raw of bodies) {
    const body = JSON.parse(raw);
    assert.equal(body.qos, 1, "at least once: a missed nudge is a minute of staleness");
    assert.equal(body.retain, false,
      "not retained — a client pulls the directory on connect anyway, so a " +
      "retained nudge would only make every reconnect do it twice");
    // The fact of the message is the message. Anything else would be graph
    // CONTENT on a topic the client answers by calling authenticated /friends.
    assert.deepEqual(JSON.parse(body.payload), { t: "graph" });
  }
});

test("a nudge carries no graph content — only that something changed", async () => {
  const id = peerId(crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex"));
  const other = peerId(crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex"));

  bodies.length = 0;
  await EMQX.notifyGraphChanged([id]);

  const raw = bodies[0]!;
  // Neither the account being told, nor anyone else, appears in the payload.
  // The client answers a nudge by asking `/friends`, which is authenticated, so
  // a spoofed one costs its sender one directory fetch and reveals nothing.
  assert.ok(!raw.includes(other), "no other account is named");
  assert.equal(JSON.parse(JSON.parse(raw).payload).t, "graph");
});

test("an empty or blank list publishes nothing", async () => {
  seen.length = 0;
  await EMQX.notifyGraphChanged([]);
  await EMQX.notifyGraphChanged(["", ""]);
  assert.equal(seen.filter((l) => l.includes("publish")).length, 0);
});

test("a broker that refuses does not fail the operation that called it", async () => {
  // The property that hid the 414 for as long as it did, and which is still
  // correct: you unfriended someone, and that must succeed even if the broker is
  // unreachable. The ACL row is deleted regardless, so the next authorization
  // check refuses them anyway.
  await new Promise<void>((r) => server.close(() => r()));
  const id = peerId(crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex"));
  assert.equal(await EMQX.kick(id), false, "reports failure rather than throwing");
  await EMQX.revokeTopic(id, id, "c/x");  // must not throw
});
