// What the bridge SAYS when a wake fails, and what it says at boot.
//
// push-bridge.test.ts covers the two decisions — presence tracking and the wake
// rule. This covers the third thing this service does, which is the only reason
// anybody ever learns why a phone did not buzz.
//
// It has the watchdog's failure modes one layer down, and they are opposite:
//
//   say it every time    a deploy mistake is the SAME for all ten thousand
//                        users, so the one line worth reading is buried under
//                        ten thousand copies of itself
//   say it once, ever    a token Apple refuses belongs to ONE install, so
//                        deduplicating that globally means the second broken
//                        device is never mentioned at all
//
// The split between those two is the whole design of `report`, and nothing
// checked which side of it each outcome fell on.
//
// The module is reloaded per test because the dedupe set — and the APNs key
// cache it reports on — are module state with no reset, which is correct for a
// long-running bridge and means one process would otherwise see one verdict.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import type { SendOutcome } from "../services/apns/api";
import { setLogLevel } from "../lib/logger";

setLogLevel("debug");

const pushPath = require.resolve("../push/main");
const apnsPath = require.resolve("../services/apns/api");

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

interface Harness {
  push: typeof import("../push/main");
  /** Everything the logger wrote during this load, including at import. */
  log: string[];
  warns: string[];
}

/** A fresh push/main (and a fresh APNs key cache) under a given environment. */
async function withPush(
  env: Record<string, string | undefined>,
  fn: (h: Harness) => Promise<void> | void,
): Promise<void> {
  const saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) {
    const v = env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }

  const log: string[] = [];
  const warns: string[] = [];
  const savedConsole = { log: console.log, warn: console.warn, error: console.error };
  console.log = (...a: unknown[]) => log.push(a.map(String).join(" "));
  console.error = (...a: unknown[]) => log.push(a.map(String).join(" "));
  console.warn = (...a: unknown[]) => { const s = a.map(String).join(" "); log.push(s); warns.push(s); };

  // Both: `keyProblem()` caches the parsed key, and push/main asks it at import.
  delete require.cache[pushPath];
  delete require.cache[apnsPath];

  try {
    await fn({ push: require(pushPath), log, warns });
  } finally {
    Object.assign(console, savedConsole);
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const id = () => crypto.randomBytes(32).toString("hex");
const hash = () => crypto.randomBytes(32).toString("hex");

/** Drive one conversation message at a bridge whose `send` always answers
 *  `outcome`, for the given members. */
function bridgeThatAnswers(
  push: typeof import("../push/main"),
  outcome: SendOutcome | ((id: string) => SendOutcome),
  members: string[],
) {
  const sent: string[] = [];
  const bridge = push.createPushBridge({
    getTopicMembers: async () => members,
    send: async (to) => {
      sent.push(to);
      return typeof outcome === "function" ? outcome(to) : outcome;
    },
  }, new Set());
  return { bridge, sent };
}

// --- a deploy mistake is one fact, not ten thousand ----------------------------------------

const GLOBAL: SendOutcome[] = ["no-config", "bad-key", "no-topic-ios", "no-topic-macos"];

for (const outcome of GLOBAL) {
  test(`${outcome} is reported once however many devices it affects`, async () => {
    await withPush(CONFIGURED, async ({ push, warns }) => {
      const members = Array.from({ length: 50 }, () => id());
      const { bridge, sent } = bridgeThatAnswers(push, outcome, members);
      warns.length = 0;

      await bridge.handleMessage(`cv/${hash()}`, Buffer.from("x"));
      assert.equal(sent.length, 50, "every offline member is still attempted");

      const said = warns.filter((l) => l.includes(outcome));
      assert.equal(said.length, 1,
        `50 devices produced ${said.length} copies of the same deploy mistake`);
      // The line has to be actionable: which fault, what the config looks like,
      // and where to get the whole picture.
      assert.match(said[0]!, /waking NOBODY/);
      assert.match(said[0]!, /check-push/);

      // And a SECOND conversation does not re-say it.
      await bridge.handleMessage(`cv/${hash()}`, Buffer.from("x"));
      assert.equal(warns.filter((l) => l.includes(outcome)).length, 1,
        "the next conversation repeated it");
    });
  });
}

// --- a broken device is one device -----------------------------------------------------------

test("a rejected token is reported per install, not once for everybody", async () => {
  // Deduplicating this globally would mean the second person whose token Apple
  // refuses is never mentioned — the failure is about one install, and the fix
  // is per install.
  await withPush(CONFIGURED, async ({ push, warns }) => {
    const [a, b, c] = [id(), id(), id()];
    const { bridge } = bridgeThatAnswers(push, "rejected", [a, b, c]);
    warns.length = 0;

    await bridge.handleMessage(`cv/${hash()}`, Buffer.from("x"));
    const said = warns.filter((l) => /could not wake/.test(l));
    assert.equal(said.length, 3, `three broken devices produced ${said.length} lines`);
  });
});

test("…but the same device is not reported on every message", async () => {
  await withPush(CONFIGURED, async ({ push, warns }) => {
    const only = id();
    const { bridge } = bridgeThatAnswers(push, "error", [only]);
    warns.length = 0;

    for (let i = 0; i < 20; i++) await bridge.handleMessage(`cv/${hash()}`, Buffer.from("x"));
    const said = warns.filter((l) => /could not wake/.test(l));
    assert.equal(said.length, 1, `20 messages to one broken device produced ${said.length} lines`);
  });
});

test("rejected and error are different reasons for the same device", async () => {
  // The key is `${id}:${outcome}`. A device that starts failing differently has
  // changed its story, and that is worth one more line.
  await withPush(CONFIGURED, async ({ push, warns }) => {
    const only = id();
    let outcome: SendOutcome = "rejected";
    const bridge = push.createPushBridge({
      getTopicMembers: async () => [only],
      send: async () => outcome,
    }, new Set());
    warns.length = 0;

    await bridge.handleMessage(`cv/${hash()}`, Buffer.from("x"));
    outcome = "error";
    await bridge.handleMessage(`cv/${hash()}`, Buffer.from("x"));
    assert.equal(warns.filter((l) => /could not wake/.test(l)).length, 2, warns.join("\n"));
  });
});

// --- what is NOT worth a warning ------------------------------------------------------------------

test("a successful wake and a peer with no token are not warnings", async () => {
  // `no-token` is ordinary: a peer who has never opened the app on a device that
  // registered, or a macOS-only account. Nothing to fix, so nothing to report —
  // and per lib/logger's note, an expected condition is not an error.
  await withPush(CONFIGURED, async ({ push, warns, log }) => {
    const [a, b] = [id(), id()];
    const { bridge } = bridgeThatAnswers(push, (to) => (to === a ? "sent" : "no-token"), [a, b]);
    warns.length = 0;

    await bridge.handleMessage(`cv/${hash()}`, Buffer.from("x"));
    assert.deepEqual(warns, [], `an ordinary outcome was warned about:\n${warns.join("\n")}`);
    // They are still visible at debug, which is where "why did my phone not
    // buzz" is actually answered.
    assert.ok(log.some((l) => /woke/.test(l)), log.join("\n"));
    assert.ok(log.some((l) => /no push token/.test(l)), log.join("\n"));
  });
});

// --- what reaches the log -------------------------------------------------------------------------

test("a client id is truncated everywhere it is logged", async () => {
  // Eight characters is enough to correlate a line with check-push output
  // without putting a whole identifier in a log file — and these logs leave the
  // box, via the Sentry breadcrumb trail.
  await withPush(CONFIGURED, async ({ push, log }) => {
    const full = id();
    const { bridge } = bridgeThatAnswers(push, "rejected", [full]);
    log.length = 0;
    await bridge.handleMessage(`cv/${hash()}`, Buffer.from("x"));

    const all = log.join("\n");
    assert.ok(all.includes(`${full.slice(0, 8)}…`), `expected a short id; got:\n${all}`);
    assert.ok(!all.includes(full), "a full 64-character client id reached the log");
  });
});

test("an unknown conversation id is reported once per id", async () => {
  // Either a retired topic an ex-friend still publishes to, or the client and
  // friendships.convo_id disagreeing. Once per id: it would otherwise repeat for
  // every message on a topic that is going to keep having them — but a second
  // unknown id is a second fact.
  await withPush(CONFIGURED, async ({ push, warns }) => {
    const bridge = push.createPushBridge({
      getTopicMembers: async () => [],
      send: async () => "sent" as SendOutcome,
    }, new Set());
    warns.length = 0;

    const [h1, h2] = [hash(), hash()];
    for (let i = 0; i < 5; i++) await bridge.handleMessage(`cv/${h1}`, Buffer.from("x"));
    assert.equal(warns.filter((l) => /no friendship holds/.test(l)).length, 1,
      "five messages on one unknown id produced more than one line");

    await bridge.handleMessage(`cv/${h2}`, Buffer.from("x"));
    assert.equal(warns.filter((l) => /no friendship holds/.test(l)).length, 2,
      "a second unknown id is a second fact and was swallowed");
    // The id is truncated here too — it is a capability, and the log is not
    // somewhere to publish one.
    const said = warns.find((l) => /no friendship holds/.test(l))!;
    assert.ok(!said.includes(h1), "a full topic id reached the log");
  });
});

// --- what it says at boot ----------------------------------------------------------------------------

test("a present but unusable APNs key is escalated at import", async () => {
  // This is the one service mounted the .p8, so it is the only one that can tell
  // the difference between a missing key and a broken one. An INTENDED but
  // broken setup is a deploy mistake somebody is waiting on, so it goes to
  // logger.error — and therefore to Sentry — once, at boot.
  const rsa = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  }).privateKey;

  await withPush({ ...CONFIGURED, APNS_KEY_P8: rsa }, async ({ log }) => {
    const said = log.filter((l) => /APNs key is unusable/.test(l));
    assert.equal(said.length, 1, `expected one escalation; got:\n${log.join("\n")}`);
    assert.match(said[0]!, /No device will be woken/);
  });
});

test("a key with the rest of the config missing is escalated too", async () => {
  // The half-configured host: a key is present, so somebody meant to turn push
  // on, and every wake will be dropped in silence. The line names the variables
  // that are NOT secrets and belong in server.env, because that distinction is
  // what made the original outage invisible.
  await withPush(
    { APNS_KEY_P8: EC_KEY, APNS_KEY_ID: undefined, APNS_TEAM_ID: undefined,
      APNS_TOPIC_IOS: undefined, APNS_TOPIC_MACOS: undefined },
    async ({ log }) => {
      const said = log.filter((l) => /every wake will be dropped in silence/.test(l));
      assert.equal(said.length, 1, `expected one escalation; got:\n${log.join("\n")}`);
      assert.match(said[0]!, /server\.env/);
      assert.match(said[0]!, /check-push/);
    });
});

test("a host that never intended APNs is not escalated", async () => {
  // No key at all is not a deploy mistake — it is a deployment that does not do
  // push. Reporting it as an error would spend a Sentry event, at boot, on every
  // such host forever.
  await withPush(
    { APNS_KEY_P8: undefined, APNS_KEY_ID: undefined, APNS_TEAM_ID: undefined,
      APNS_TOPIC_IOS: undefined, APNS_TOPIC_MACOS: undefined },
    async ({ log }) => {
      assert.deepEqual(log.filter((l) => /every wake will be dropped|APNs key is unusable/.test(l)), [],
        `an unconfigured host was escalated:\n${log.join("\n")}`);
    });
});

test("a fully configured host says nothing at import", async () => {
  await withPush(CONFIGURED, async ({ log }) => {
    assert.deepEqual(log.filter((l) => /\[push-bridge\].*(unusable|dropped in silence)/.test(l)), [],
      `a healthy configuration was escalated:\n${log.join("\n")}`);
  });
});

// --- the health endpoint ------------------------------------------------------------------------------

test("the health endpoint 404s anything but /health", async () => {
  await withPush(CONFIGURED, async ({ push }) => {
    const presence = new Set<string>(["a", "b"]);
    const handler = push.createHealthHandler(presence);
    const run = (method: string, url: string) =>
      new Promise<{ status: number; body: string }>((resolve) => {
        let status = 0;
        handler(
          { method, url } as any,
          { writeHead(s: number) { status = s; return this; },
            end(b?: string) { resolve({ status, body: b ?? "" }); } } as any,
        );
      });

    const ok = await run("GET", "/health");
    assert.equal(ok.status, 200);
    assert.equal(JSON.parse(ok.body).online, 2);
    assert.equal(JSON.parse(ok.body).service, "push-bridge");

    for (const [m, u] of [["POST", "/health"], ["GET", "/"], ["GET", "/metrics"]] as const) {
      assert.equal((await run(m, u)).status, 404, `${m} ${u}`);
    }
  });
});

// --- what it subscribes to ---------------------------------------------------------------------------

test("presence is unshared and conversations are shared", async () => {
  // The asymmetry is the whole design, and breaking it either way is silent.
  //
  // Sharing presence would give each update to exactly ONE replica; the others
  // then hold a stale `online` set and either buzz a phone whose owner is
  // already reading the conversation, or never buzz it at all.
  //
  // Not sharing conversations would give every message to EVERY replica, so a
  // two-replica deployment sends each device two identical pushes.
  await withPush(CONFIGURED, async ({ push }) => {
    const subs = push.pushSubscriptions("pushbridge");
    const presence = subs.find((s) => s.topic.includes("presence"))!;
    const convo = subs.find((s) => s.topic.includes("cv/+"))!;

    assert.ok(presence, `no presence subscription: ${JSON.stringify(subs)}`);
    assert.ok(!presence.topic.startsWith("$share/"),
      "presence is in a shared group — each replica would see only some updates");
    assert.equal(presence.topic, "u/+/presence");

    assert.ok(convo, `no conversation subscription: ${JSON.stringify(subs)}`);
    assert.ok(convo.topic.startsWith("$share/pushbridge/"),
      "conversations are not shared — every replica would wake the same device");
    assert.equal(convo.qos, 1, "a dropped conversation message is a wake that never happens");

    assert.equal(subs.length, 2, "an extra subscription is extra fan-out per replica");
  });
});

test("the share group is configurable, and only the conversation topic uses it", async () => {
  // Two deployments sharing one broker must not share a group, or they split
  // each other's messages and each wakes half its own users.
  await withPush(CONFIGURED, async ({ push }) => {
    const subs = push.pushSubscriptions("staging-bridge");
    assert.ok(subs.some((s) => s.topic === "$share/staging-bridge/cv/+"), JSON.stringify(subs));
    assert.ok(subs.every((s) => s.topic === "u/+/presence" || s.topic.includes("staging-bridge")),
      JSON.stringify(subs));
  });
});
