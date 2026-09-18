// Admission, per door.
//
// The interesting property used to be that the two doors disagreed: the free
// door never refused for want of payment, and the paid door never admitted an
// unclaimed key. There is no payment now, so what is left to pin is narrower and
// more important — that NOTHING refuses anybody on the default policy, and that
// `allowlist` still refuses at BOTH doors so a private server has no way in.
//
// ADMISSION_POLICY is read once, at module load, so each case reloads the
// module with the policy it wants. `require` rather than a static import for
// exactly that reason: an import would be hoisted above the env assignment.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";
import { peerId } from "../lib/identity";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";
import { setLogLevel } from "../lib/logger";

setLogLevel("silent");

type Admission = typeof import("../lib/admission");

function admissionUnder(policy: string, allowlist = ""): Admission {
  process.env.ADMISSION_POLICY = policy;
  process.env.ADMISSION_ALLOWLIST = allowlist;
  delete require.cache[require.resolve("../lib/admission")];
  return require("../lib/admission") as Admission;
}

// `checkAdmission` takes a PUBLIC KEY, because it runs on the auth path — the
// one place a key is in hand. Everything it looks up is keyed by the ID that key
// commits to, and the conversion happens inside lib/admission.ts so that neither
// an operator (who has keys) nor the schema (which has ids) has to know about
// the other's form.
const PK = "cc".repeat(64);
const OTHER = "dd".repeat(64);
const OTHER_ID = peerId(OTHER);

test("an open server admits both doors", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  const { checkAdmission } = admissionUnder("open");
  assert.deepEqual(await checkAdmission(PK, "free"), { ok: true });
  assert.deepEqual(await checkAdmission(PK, "paid"), { ok: true });
});

test("the full door admits a key that has never paid anything", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The regression this exists to catch is a paywall coming back by accident —
  // a policy value, a leftover lookup, an entitlement check reintroduced on the
  // auth path. A brand-new key with no history anywhere must reach the full
  // door, because that door is now the whole product.
  const { checkAdmission } = admissionUnder("open");
  const stranger = "ab".repeat(64);
  assert.deepEqual(await checkAdmission(stranger, "paid"), { ok: true });
});

test("a host still set to the retired stripe policy refuses to boot", () => {
  // "stripe" was a valid policy until the paywall was removed, and lib/admission
  // now treats anything unrecognised as `open` — which is the right runtime
  // behaviour and a terrible way to discover that the policy you configured no
  // longer exists. assertConfig is what makes it loud, and it does so by exiting
  // the process, so this has to be a child rather than an assert.throws.
  const { spawnSync } = require("child_process") as typeof import("child_process");
  const path = require("path") as typeof import("path");
  const run = spawnSync(
    process.execPath,
    ["--import", "tsx", "-e", 'require("./lib/config").assertConfig([])'],
    {
      cwd: path.join(__dirname, ".."),
      encoding: "utf8",
      env: { ...process.env, ADMISSION_POLICY: "stripe", DATABASE_URL: "postgres://x/y" },
    }
  );
  assert.equal(run.status, 1, "a retired policy must stop the boot, not be ignored");
  assert.match(run.stderr, /ADMISSION_POLICY="stripe" is invalid/);
  assert.match(run.stderr, /DONATIONS_ENABLED/, "and it must say what to do instead");
});

test("an allowlist server refuses an unlisted key at BOTH doors", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // A private server has no free tier to fall back to: being turned away is the
  // whole answer, and the client must not retry the other door hoping for less.
  // The allowlist is spelled in KEYS — that is what an operator copies out of a
  // client — and compared as ids, so an entry differing only in case still
  // matches.
  const { checkAdmission } = admissionUnder("allowlist", PK);
  assert.deepEqual(await checkAdmission(PK, "free"), { ok: true });
  assert.deepEqual(await checkAdmission(PK, "paid"), { ok: true });
  assert.deepEqual(await checkAdmission(PK.toUpperCase(), "paid"), { ok: true },
    "the same key in a different case is the same identity");
  assert.deepEqual(await checkAdmission(OTHER, "free"), { ok: false, reason: "denied" });
  assert.deepEqual(await checkAdmission(OTHER, "paid"), { ok: false, reason: "denied" });
});

test("an exempt key passes either door under any policy", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The helper bot registers itself. Every new account is auto-friended to it,
  // so a policy that shut it out would empty the first screen every user sees.
  // The bot writes its own ID here, not its key — see bot/bot.ts.
  await DB.addAdmissionExempt(OTHER_ID);

  const allow = admissionUnder("allowlist", PK);
  assert.deepEqual(await allow.checkAdmission(OTHER, "paid"), { ok: true });
});

test.after(async () => {
  if (await pgAvailable()) {
    // `admission_exempt` outlives the process, so leaving OTHER in it would
    // make the allowlist case above pass for the wrong reason on the next run.
    await DB.removeAdmissionExempt(OTHER_ID);
  }
  await closePg();
});
