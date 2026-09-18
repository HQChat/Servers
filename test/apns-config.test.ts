// Whether APNs can send, as a function of the environment.
//
// This is the check that decides if a phone ever buzzes, and it had two faults
// that together guaranteed silence on a correctly-configured host:
//
//  1. It ran in EVERY service. `APNS_KEY_P8` is a compose secret mounted into
//     push-bridge alone, so auth and app-api saw `APNS_KEY_ID` + `APNS_TEAM_ID`
//     from the shared server.env, called that partial, and exited. Setting APNs
//     up the documented way made the stack refuse to boot, so the only working
//     configuration was no APNs at all.
//
//  2. It did not look at the topics. `ApnsService.send` returns silently when
//     the platform's topic is unset, so a valid key with no `APNS_TOPIC_IOS`
//     passes every check, authenticates against Apple, and delivers nowhere.
//
// Pure and env-injected on purpose: the real `process.env` is global, and a test
// that mutated it would leak into whichever file ran next.

import { test } from "node:test";
import assert from "node:assert/strict";
import { apnsGaps, apnsIntended, apnsSummary } from "../lib/apns-config";

const FULL = {
  APNS_KEY_ID: "ABC123DEF4",
  APNS_TEAM_ID: "TEAM123456",
  APNS_KEY_P8: "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----",
  APNS_TOPIC_IOS: "martin.rougeron.DissQus-iOS",
  APNS_TOPIC_MACOS: "martin.rougeron.DissQus",
  APNS_ENV: "production",
};

test("a complete configuration has no gaps", () => {
  assert.deepEqual(apnsGaps(FULL), []);
  assert.ok(apnsIntended(FULL));
});

test("nothing set at all is not a gap-free config, but it IS unintended", () => {
  // The distinction the old check could not draw. CI and local dev run with no
  // APNs and are correct; a host with half of one is broken. Only the second
  // should refuse to boot.
  assert.ok(apnsGaps({}).length > 0);
  assert.equal(apnsIntended({}), false);
});

test("credentials without a topic is the silent misconfiguration", () => {
  // Passes the old three-key check, authenticates fine, and delivers to nobody:
  // send() reads APNS_TOPIC_IOS and returns without a word when it is unset.
  const noTopic = { ...FULL, APNS_TOPIC_IOS: "", APNS_TOPIC_MACOS: "" };
  const gaps = apnsGaps(noTopic);
  assert.equal(gaps.length, 1);
  assert.match(gaps[0]!, /APNS_TOPIC_IOS/);
  assert.ok(apnsIntended(noTopic), "a key is set, so this host meant to have push");
});

test("one topic is NOT enough — the missing one is a gap that names its platform", () => {
  // The inverse of what this asserted until now, and the reason is in
  // apns-send.test.ts: `send` picks the topic by the device's platform, so a
  // host with only one of them authenticates, reports ready, and drops every
  // push to the other platform without a word. Both, or say which is missing.
  const noMac = apnsGaps({ ...FULL, APNS_TOPIC_MACOS: "" });
  assert.equal(noMac.length, 1, noMac.join(" | "));
  assert.match(noMac[0]!, /APNS_TOPIC_MACOS/);
  assert.match(noMac[0]!, /Mac/, "a gap should name the devices it costs");

  const noIos = apnsGaps({ ...FULL, APNS_TOPIC_IOS: "" });
  assert.equal(noIos.length, 1, noIos.join(" | "));
  assert.match(noIos[0]!, /APNS_TOPIC_IOS/);
  assert.match(noIos[0]!, /iPhone/);

  assert.deepEqual(apnsGaps(FULL), [], "both set is still the ready state");
});

test("the shared-server.env case is reported as intended-but-incomplete", () => {
  // Exactly what auth and app-api see on a real host: everything non-secret from
  // server.env, and no .p8 because only push-bridge is mounted it. The service
  // that owns APNs must call this an error; nobody else may even ask.
  //
  // Both topics, because server.env carries both — the fixture named only the
  // iOS one, which stopped being a faithful copy of a host the moment a missing
  // topic became a gap in its own right. The point of the test is the .p8, and
  // it is sharper when that is the only thing missing.
  const partial = {
    APNS_KEY_ID: FULL.APNS_KEY_ID,
    APNS_TEAM_ID: FULL.APNS_TEAM_ID,
    APNS_TOPIC_IOS: FULL.APNS_TOPIC_IOS,
    APNS_TOPIC_MACOS: FULL.APNS_TOPIC_MACOS,
  };
  assert.ok(apnsIntended(partial));
  assert.deepEqual(apnsGaps(partial), ["APNS_KEY_P8"]);
});

test("the summary states the outcome, not the inputs", () => {
  // This string is the whole diagnostic: it is printed on every connect so the
  // answer to "why did my phone not buzz" is already in the log.
  assert.match(apnsSummary(FULL), /ready/);
  assert.match(apnsSummary(FULL), /production/);
  assert.match(apnsSummary({}), /not configured/);
  assert.match(apnsSummary({}), /no device will be woken/);

  const incomplete = apnsSummary({ APNS_KEY_ID: "x" });
  assert.match(incomplete, /INCOMPLETE/);
  assert.match(incomplete, /APNS_TEAM_ID/);
  assert.match(incomplete, /no device will be woken/);
});

test("sandbox is the default the summary reports", () => {
  // It matters which one it says: a token is bound to exactly one APNs
  // environment, and the two hosts reject each other's.
  assert.match(apnsSummary({ ...FULL, APNS_ENV: "" }), /sandbox/);
  assert.match(apnsSummary({ ...FULL, APNS_ENV: "sandbox" }), /sandbox/);
});

test("whitespace is not configuration", () => {
  assert.deepEqual(apnsGaps({ ...FULL, APNS_KEY_ID: "   " }), ["APNS_KEY_ID"]);
  assert.equal(apnsIntended({ APNS_KEY_ID: "  ", APNS_TEAM_ID: "\n" }), false);
});

// ── assertConfig must not take a service down over push ─────────────────────
//
// These spawn a real process because the regression IS the exit: `assertConfig`
// calls `process.exit(1)`, which an in-process assertion cannot observe without
// stubbing the thing under test. A box that deployed the first version of this
// change had push-bridge crash-looping on `❌ Invalid configuration — refusing
// to start`, holding an APNs key it could not use and no way to fix it without
// values from the Apple Developer portal.

import { spawnSync } from "node:child_process";
import * as path from "node:path";

// `__dirname`, not `import.meta.dirname`: tsconfig sets "module": "CommonJS",
// under which import.meta is a hard error. double-ratchet.test.ts and
// envelope.test.ts resolve their vector files the same way.
const BOOT = path.join(__dirname, "helpers", "assert-config-boot.ts");

/** Boot `assertConfig(needs)` in a fresh process with exactly this env. */
function boot(env: Record<string, string>, needs: string[]): { code: number; out: string } {
  const r = spawnSync(process.execPath, ["--import", "tsx", BOOT], {
    encoding: "utf8",
    // A clean env, minus anything the developer's own shell exports. Two things
    // are supplied because assertConfig requires them of every service, and this
    // file is about APNs: a DATABASE_URL, and ENV_FILE pointed at nothing so
    // dotenv cannot pick up a local .env and quietly fill in the gaps under test.
    env: {
      PATH: process.env.PATH ?? "",
      DATABASE_URL: "postgres://x@localhost/x",
      ENV_FILE: "/nonexistent/.env",
      __NEEDS__: JSON.stringify(needs),
      ...env,
    },
  });
  return { code: r.status ?? -1, out: `${r.stdout}${r.stderr}` };
}

test("a half-configured APNs warns — it does not stop the service", () => {
  // The exact shape of the box that hit this: the .p8 secret is mounted and has
  // content, and the non-secret ids never made it into server.env.
  const r = boot({ APNS_KEY_P8: FULL.APNS_KEY_P8 }, ["apns"]);
  assert.equal(r.code, 0, `refused to start:\n${r.out}`);
  assert.match(r.out, /partially configured/);
  assert.match(r.out, /APNS_KEY_ID/);
  assert.doesNotMatch(r.out, /refusing to start/);
});

test("no APNs at all still starts, and still says so", () => {
  const r = boot({}, ["apns"]);
  assert.equal(r.code, 0, `refused to start:\n${r.out}`);
  assert.match(r.out, /not configured/);
});

test("a service that does not send never mentions APNs", () => {
  // auth and app-api read the same server.env and are not mounted the key.
  // Before the scope fix they exited on it; now they have no opinion at all.
  const r = boot({ APNS_KEY_ID: FULL.APNS_KEY_ID, APNS_TEAM_ID: FULL.APNS_TEAM_ID }, []);
  assert.equal(r.code, 0, `refused to start:\n${r.out}`);
  assert.doesNotMatch(r.out, /APNS/);
});

test("a host serving one platform on purpose still boots", () => {
  // The scenario that kept `apnsGaps` on `some` for one release: tightening it
  // was believed to stop a macOS-only deployment from booting. It does not, and
  // this is the proof — a real process, one topic, exit 0.
  //
  // What protects that host is WHERE the gap is reported, not whether it is:
  // assertConfig files APNs under warnings and only errors exit. So it boots,
  // and it is told which platform it is not serving, which is the right outcome
  // for a deliberate choice and the only useful one for an accident.
  const r = boot({ ...FULL, APNS_TOPIC_IOS: "" }, ["apns"]);
  assert.equal(r.code, 0, `refused to start:\n${r.out}`);
  assert.match(r.out, /partially configured/);
  assert.match(r.out, /APNS_TOPIC_IOS/, r.out);
  assert.doesNotMatch(r.out, /refusing to start/);
});

test("a complete configuration is silent about APNs", () => {
  const r = boot(FULL, ["apns"]);
  assert.equal(r.code, 0, `refused to start:\n${r.out}`);
  assert.doesNotMatch(r.out, /partially configured|not configured/);
});

// ── The .p8, whatever shape it arrived in ───────────────────────────────────
//
// Production had a configured key and every push died on
// `error:1E08010C:DECODER routines::unsupported`, thrown per message from
// inside `crypto.sign`. That error names nothing an operator can act on, and
// the value can legitimately arrive in five different shapes depending on
// whether it came through a mounted file, a one-line .env, a form, or a paste.
//
// A REAL key is generated here rather than pasted: a fixture would have to be a
// live-looking APNs signing key committed to the repo, and the property under
// test is "OpenSSL loads what we hand it", which only a real key can prove.

import * as crypto from "node:crypto";
import { normalizeP8 } from "../lib/apns-config";

const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const REAL_P8 = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

/** What OpenSSL does with it is the only question that matters. */
function loads(pem: string | null): boolean {
  if (!pem) return false;
  try {
    return crypto.createPrivateKey(pem).asymmetricKeyType === "ec";
  } catch {
    return false;
  }
}

test("a canonical .p8 survives normalisation untouched in meaning", () => {
  assert.ok(loads(normalizeP8(REAL_P8)));
});

test("every shape the value can arrive in loads", () => {
  const body = REAL_P8
    .replace(/-----[A-Z ]+-----/g, "")
    .replace(/\s+/g, "");

  const shapes: Record<string, string> = {
    "literal \\n escapes (the one-line .env form)": REAL_P8.replace(/\n/g, "\\n"),
    "CRLF line endings": REAL_P8.replace(/\n/g, "\r\n"),
    "body unwrapped onto one line":
      `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`,
    // The production shape. The whole PEM on ONE line with no separators at
    // all — header, body and footer touching. On the box this measured 252
    // bytes with `wc -l` reporting 0, and every push died on
    // `DECODER routines::unsupported`. The key was never damaged; only its
    // newlines were.
    "every newline removed (what was on the prod host)":
      REAL_P8.replace(/\n/g, ""),
    "no armour at all, just the base64": body,
    "leading and trailing whitespace": `\n\n  ${REAL_P8}  \n\n`,
  };

  for (const [name, raw] of Object.entries(shapes)) {
    assert.ok(loads(normalizeP8(raw)), `${name} did not load`);
  }
});

test("the flattened production key is the SAME key, not just a parseable one", () => {
  // The check that matters for recovering a host without touching the file:
  // sign with the key recovered from the flattened form, verify with the public
  // half of the original.
  const pem = normalizeP8(REAL_P8.replace(/\n/g, ""));
  assert.ok(pem, "the flattened form must normalise");
  const data = Buffer.from("header.payload");
  const sig = crypto.sign("SHA256", data, {
    key: crypto.createPrivateKey(pem!),
    dsaEncoding: "ieee-p1363",
  });
  assert.ok(crypto.verify("SHA256", data, {
    key: crypto.createPublicKey(privateKey),
    dsaEncoding: "ieee-p1363",
  }, sig), "recovering the key changed it");
});

test("a signature made from a re-armoured key verifies", () => {
  // Normalising must not merely produce something that PARSES — it has to be
  // the same key. ES256 = ECDSA/P-256 with ieee-p1363 output, exactly as getJwt
  // signs an APNs provider token.
  const pem = normalizeP8(REAL_P8.replace(/\n/g, "\\n"))!;
  const data = Buffer.from("header.payload");
  const sig = crypto.sign("SHA256", data, {
    key: crypto.createPrivateKey(pem),
    dsaEncoding: "ieee-p1363",
  });
  const ok = crypto.verify("SHA256", data, {
    key: crypto.createPublicKey(privateKey),
    dsaEncoding: "ieee-p1363",
  }, sig);
  assert.ok(ok, "the re-armoured key is not the key we started with");
});

test("a key in the WRONG container is refused, not relabelled", () => {
  // SEC1 ("EC PRIVATE KEY") and PKCS#1 ("RSA PRIVATE KEY") are real keys in a
  // container APNs does not use. Restamping the header would yield a file that
  // parses and signs incorrectly, which is worse than refusing it.
  const sec1 = privateKey.export({ type: "sec1", format: "pem" }).toString();
  assert.equal(normalizeP8(sec1), null, "SEC1 must not be silently relabelled");

  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    .privateKey.export({ type: "pkcs1", format: "pem" }).toString();
  assert.equal(normalizeP8(rsa), null, "PKCS#1 must not be silently relabelled");
});

test("nothing usable yields null rather than something that throws later", () => {
  // Every one of these reached crypto.sign before and came back as the same
  // opaque DECODER error.
  for (const raw of [
    undefined, "", "   ", "\\n", "not a key at all",
    "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",                       // a truncated paste
    "-----BEGIN PRIVATE KEY-----\n!!!not base64!!!\n-----END PRIVATE KEY-----",
  ]) {
    assert.equal(normalizeP8(raw), null, `${JSON.stringify(raw)} should be null`);
  }
});

test("an RSA PKCS#8 key is PEM-valid but not an ES256 signing key", () => {
  // This one DOES normalise — it is genuine PKCS#8 — so the guard that catches
  // it is the asymmetricKeyType check in privateKey(), not the re-armouring.
  const rsaPkcs8 = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    .privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const pem = normalizeP8(rsaPkcs8);
  assert.ok(pem, "PKCS#8 RSA is well-formed PEM");
  assert.equal(crypto.createPrivateKey(pem!).asymmetricKeyType, "rsa");
  assert.notEqual(crypto.createPrivateKey(pem!).asymmetricKeyType, "ec");
});
