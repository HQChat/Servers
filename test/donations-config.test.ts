// What the donate buttons will charge, and whether the server says so.
//
// The gap this closes: prod ran with DONATIONS_ENABLED=1 and NEITHER price id in
// server.env. Every button on the donate page — three monthly tiers and
// give-once, rendered unconditionally by a static Worker that cannot ask this
// server what is priced — answered "That option is not available. Go back and
// pick one of the amounts shown", to a donor looking straight at the amounts.
//
// The one line of evidence anywhere was a boot warning that named ONE of the two
// variables and called the outcome "only one-time donations will be offered".
// Both halves were wrong: the one-time id was unset too, so nothing was offered,
// and no tier was ever "not offered" — the buttons were all still there.
//
// The prices are compiled in now, which is what makes the first test below the
// important one: an unconfigured host charges correctly instead of going dark.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  resolvePrices,
  donationGaps,
  donationsDead,
  donationSummary,
  DEFAULT_DONATION_PRICE_IDS,
  DEFAULT_DONATION_ONCE_PRICE_ID,
  DONATION_TIERS_VAR,
  DONATION_ONCE_VAR,
} from "../lib/donations-config";

const REPO = join(__dirname, "..", "..", "..");
const NOTHING = { tiers: [], once: "" };

test("an unconfigured host charges correctly", () => {
  // The exact production environment: DONATIONS_ENABLED=1 from compose, nothing
  // in server.env. It used to mean four dead buttons.
  const p = resolvePrices({});
  assert.deepEqual(p.tiers, [...DEFAULT_DONATION_PRICE_IDS]);
  assert.equal(p.once, DEFAULT_DONATION_ONCE_PRICE_ID);
  assert.deepEqual(donationGaps(p), []);
  assert.match(donationSummary(p), /donations ready \(3 monthly tier\(s\) \+ one-time\)/);
});

test("an env var overrides, but an empty one falls back rather than going dark", () => {
  // A fork points at its own Stripe account by setting the variable. Nobody
  // points at nothing by leaving a line blank — that is an unconfigured host,
  // and treating it as "charge nothing" is what broke.
  const overridden = resolvePrices({
    [DONATION_TIERS_VAR]: "price_fork_a, price_fork_b",
    [DONATION_ONCE_VAR]: "price_fork_once",
  });
  assert.deepEqual(overridden.tiers, ["price_fork_a", "price_fork_b"]);
  assert.equal(overridden.once, "price_fork_once");

  // Blank, and mangled. server.env is hand-edited over ssh: a half-pasted value
  // or a stray comma is a realistic way for a line to arrive, and it must not
  // replace working prices with something Stripe will reject at checkout.
  for (const junk of ["", "   ", ",,,", " , ", "price", "# price_x", "TODO"]) {
    const p = resolvePrices({ [DONATION_TIERS_VAR]: junk, [DONATION_ONCE_VAR]: junk });
    assert.deepEqual(p.tiers, [...DEFAULT_DONATION_PRICE_IDS], `"${junk}" must fall back`);
    assert.equal(p.once, DEFAULT_DONATION_ONCE_PRICE_ID, `"${junk}" must fall back`);
  }

  // A partly-mangled list keeps the ids that are ids. The alternative — reject
  // the whole line — silently drops a tier the operator can see they wrote.
  const partial = resolvePrices({ [DONATION_TIERS_VAR]: "price_fork_a, ,oops, price_fork_b" });
  assert.deepEqual(partial.tiers, ["price_fork_a", "price_fork_b"]);

  // Half an override is honoured on that half only.
  const half = resolvePrices({ [DONATION_ONCE_VAR]: "price_fork_once" });
  assert.deepEqual(half.tiers, [...DEFAULT_DONATION_PRICE_IDS]);
  assert.equal(half.once, "price_fork_once");
});

test("the compiled-in prices are well formed and distinct", () => {
  // Not a check that they are LIVE — only Stripe knows that, and an archived
  // price now fails inside checkout.sessions.create rather than here. This is
  // the shape check: a truncated paste or a duplicated line is catchable.
  assert.equal(DEFAULT_DONATION_PRICE_IDS.length, 3);
  const all = [...DEFAULT_DONATION_PRICE_IDS, DEFAULT_DONATION_ONCE_PRICE_ID];
  for (const id of all) assert.match(id, /^price_[A-Za-z0-9]{20,}$/, `${id} is not a price id`);
  assert.equal(new Set(all).size, all.length, "a duplicated id charges the wrong tier");
});

test("the site renders exactly as many tier buttons as there are prices", () => {
  // The coupling the index scheme creates, and the one drift that silently
  // charges the wrong amount. The site posts tier0..tierN-1 and carries only
  // labels; a fourth label with no fourth price is a button that refuses, and a
  // fourth price with three labels is money nobody can give.
  const site = readFileSync(join(REPO, "apps/site/src/index.js"), "utf8");
  const tiers = /const TIERS = \[([\s\S]*?)\];/.exec(site);
  assert.ok(tiers, "apps/site/src/index.js must still declare TIERS");
  const labels = (tiers[1] ?? "").match(/label:/g) ?? [];
  assert.equal(labels.length, DEFAULT_DONATION_PRICE_IDS.length,
    "TIERS in the site and DEFAULT_DONATION_PRICE_IDS must stay the same length");
});

test("no price id appears in a message that may reach a log or Sentry", () => {
  // Price ids are not secret — they are in this repo twice over — but there is
  // no reason for them to travel into an error tracker. The summary names
  // variables and counts.
  for (const p of [resolvePrices({}), NOTHING, { tiers: ["price_x"], once: "" }]) {
    assert.doesNotMatch(donationSummary(p), /price_[A-Za-z0-9]/);
  }
});

// ── The state only a fork can reach ─────────────────────────────────────────
//
// With prices compiled in, "nothing is priced" is no longer reachable through
// configuration — which is the point. It stays reachable in a test, because it
// is exactly what a fork that empties those constants gets, and the reporting
// below is the only thing that would tell them.

test("nothing priced is reported as a dead page, not as a variable", () => {
  assert.equal(donationsDead(NOTHING), true);
  assert.deepEqual(donationGaps(NOTHING), [DONATION_TIERS_VAR, DONATION_ONCE_VAR]);

  const dead = donationSummary(NOTHING);
  assert.match(dead, new RegExp(DONATION_TIERS_VAR));
  assert.match(dead, new RegExp(DONATION_ONCE_VAR));
  assert.match(dead, /that option is not available/i,
    "the summary must quote what the donor is told, so the log matches the report");
});

test("one working path is not dead, and still warns about the other's buttons", () => {
  // Offering only monthly, or only one-time, is a legitimate deployment. It
  // still warns, because the site shows the other button regardless.
  const onceOnly = { tiers: [], once: "price_x" };
  const monthlyOnly = { tiers: ["price_a", "price_b"], once: "" };
  assert.equal(donationsDead(onceOnly), false);
  assert.equal(donationsDead(monthlyOnly), false);

  assert.match(donationSummary(onceOnly), /one-time giving only/);
  assert.match(donationSummary(onceOnly), /still shows monthly tier buttons/,
    "an unset price leaves the buttons up — it does not un-offer them");
  assert.match(donationSummary(monthlyOnly), /2 monthly tier\(s\) only/);
  assert.match(donationSummary(monthlyOnly), /still shows a give-once button/);
});
