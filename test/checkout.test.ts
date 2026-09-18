// The website's donate buttons, checked without spending a Stripe API call.
//
// This file exists because of a bug that a live call was the only way to find:
// the session carried `customer_creation: 'always'`, which Stripe accepts only
// in payment mode. In subscription mode it is a 400, so every click of the only
// place this product was sold died at the API and rendered "Something went
// wrong". The parameters are exported precisely so that class of mistake — a
// field that is valid Stripe, and valid TypeScript, but not valid for THIS mode
// — is caught here instead of in production.
//
// That guard matters MORE now than it did, because this builder emits both
// modes. A one-time donation is `mode: 'payment'` and a monthly one is
// `mode: 'subscription'`, and the two accept different parameter sets in
// opposite directions: whatever is payment-only breaks the tier buttons, and
// whatever is subscription-only breaks the give-once button.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const REPO = join(__dirname, "..", "..", "..");

const TIER_A = "price_test_tier_a";
const TIER_B = "price_test_tier_b";
const ONCE = "price_test_once";

// Read at module load inside services/stripe/api, so set before requiring it.
process.env.STRIPE_DONATION_PRICE_IDS = `${TIER_A},${TIER_B}`;
process.env.STRIPE_DONATION_ONCE_PRICE_ID = ONCE;

const {
  checkoutSessionParams,
  donationPriceIds,
  tierCount,
  monthlyTiersAvailable,
  oneTimeAvailable,
  displayNameFromSession,
  DISPLAY_NAME_FIELD_KEY,
} = require("../services/stripe/api") as typeof import("../services/stripe/api");
const { CSP, CHECKOUT_ORIGIN } = require("../services/web/donate") as typeof import("../services/web/donate");

const BASE = "https://chat.example.com";

test("a monthly donation is a subscription, and the redirects come back to us", () => {
  const p = checkoutSessionParams(BASE, { kind: "monthly", index: 0 });
  assert.equal(p.mode, "subscription");
  assert.equal(p.success_url, `${BASE}/donate/thanks`);
  assert.equal(p.cancel_url, `${BASE}/donate/cancelled`);
  const items = p.line_items ?? [];
  assert.equal(items.length, 1);
  assert.equal(items[0]?.quantity, 1);
  assert.equal(items[0]?.price, TIER_A);
});

test("a one-time donation is a payment, priced by Stripe not by us", () => {
  const p = checkoutSessionParams(BASE, { kind: "once" });
  assert.equal(p.mode, "payment");
  assert.equal(p.success_url, `${BASE}/donate/thanks`);
  const items = p.line_items ?? [];
  assert.equal(items.length, 1);
  assert.equal(items[0]?.price, ONCE);
  // A Price id, never an inline amount. Whether the donor names the figure is a
  // property of that Price in Stripe (`custom_unit_amount`), not of this code —
  // which is exactly why no amount, floor or currency may appear in the server
  // source. The website carries display labels, and says so.
  assert.equal((items[0] as Record<string, unknown>)?.price_data, undefined,
    "an inline price_data would mean an amount lives in our source");
});

test("no mode-only parameter rides along on the wrong mode", () => {
  // Exactly the fields the pinned SDK's own type docs scope to one mode
  // (types/Checkout/SessionsResource.d.ts) — not a guess at which ones feel
  // payment-ish. `customer_creation` ("Can only be set in `payment` and `setup`
  // mode") is the one that actually shipped and took checkout down.
  const paymentModeOnly = ["customer_creation", "payment_intent_data", "submit_type"];
  const subscriptionModeOnly = ["subscription_data"];

  const monthly = checkoutSessionParams(BASE, { kind: "monthly", index: 0 }) as Record<string, unknown>;
  for (const key of paymentModeOnly) {
    assert.ok(!(key in monthly), `${key} is payment-mode only — Stripe 400s the subscription checkout`);
  }
  const once = checkoutSessionParams(BASE, { kind: "once" }) as Record<string, unknown>;
  for (const key of subscriptionModeOnly) {
    assert.ok(!(key in once), `${key} is subscription-mode only — Stripe 400s the payment checkout`);
  }
});

test("a tier the operator did not configure cannot be put in a cart", () => {
  // The choice reaches this builder from a public form, so it is
  // attacker-controlled. It is an INDEX into the operator's configured list,
  // never a price id — so a visitor cannot name a price at all, which is
  // stronger than validating a submitted id against the same list.
  for (const bad of [2, -1, 99, 1.5, NaN]) {
    assert.throws(
      () => checkoutSessionParams(BASE, { kind: "monthly", index: bad }),
      /no donation tier at index/,
      `index ${bad} must be refused`
    );
  }
  assert.equal(checkoutSessionParams(BASE, { kind: "monthly", index: 1 }).line_items?.[0]?.price, TIER_B);
  assert.deepEqual([...donationPriceIds()], [TIER_A, TIER_B]);
  assert.equal(tierCount(), 2);
  assert.equal(monthlyTiersAvailable(), true);
  assert.equal(oneTimeAvailable(), true);
});

test("no page needs a Stripe price id to render a donate button", () => {
  // The whole point of the index. `apps/site/src/index.js` is a static Worker
  // that cannot ask Stripe anything at render time; if the buttons carried
  // price ids, this deployment's Stripe account would be baked into the site's
  // source and a fork would ship buttons pointed at someone else's prices.
  const site = readFileSync(join(REPO, "apps/site/src/index.js"), "utf8");
  assert.doesNotMatch(site, /price_[A-Za-z0-9]{6,}/,
    "no Stripe price id may appear in the marketing site");
});

// --- the supporters field ---------------------------------------------------

test("every checkout offers the optional supporters-page name", () => {
  for (const p of [
    checkoutSessionParams(BASE, { kind: "monthly", index: 0 }),
    checkoutSessionParams(BASE, { kind: "once" }),
  ]) {
    const fields = p.custom_fields ?? [];
    assert.equal(fields.length, 1, "one field, and only one");
    assert.equal(fields[0]?.key, DISPLAY_NAME_FIELD_KEY);
    assert.equal(fields[0]?.optional, true, "recognition is opt-in — blank is the expected answer");
  }
});

test("a blank name records no supporter", () => {
  // The webhook must leave no row for a donation with no name, so that the
  // supporters table stays a list of people who asked to be on it.
  const field = (value: string) => ({ custom_fields: [{ key: DISPLAY_NAME_FIELD_KEY, text: { value } }] });
  assert.equal(displayNameFromSession(field("")), null);
  assert.equal(displayNameFromSession(field("   ")), null);
  assert.equal(displayNameFromSession({}), null, "no custom_fields at all");
  assert.equal(displayNameFromSession({ custom_fields: [] }), null);
  assert.equal(displayNameFromSession(field("  Ada  ")), "Ada");
});

test("nothing but the name is read off a completed session", () => {
  // The strongest privacy claim in the stack is that no email address enters
  // this server. It holds only because this is the one function that reads a
  // checkout session, and it reads one field.
  const session = {
    customer_details: { email: "someone@example.com" },
    customer: "cus_123",
    amount_total: 2500,
    custom_fields: [{ key: DISPLAY_NAME_FIELD_KEY, text: { value: "Ada" } }],
  };
  assert.equal(displayNameFromSession(session), "Ada");
});

// --- the CSP half of the same outage ----------------------------------------
//
// With the Stripe 400 fixed the server started issuing a clean 302 to
// checkout.stripe.com — and the browser threw it away, because `form-action` is
// enforced across REDIRECTS and the page said `'self'`. Nothing surfaced: a
// healthy 302 in the log, a page that did not move, and one console line nobody
// was looking at.

test("the page's CSP lets the browser follow the redirect to Stripe", () => {
  const formAction = CSP.split(";").map((d) => d.trim())
    .find((d) => d.startsWith("form-action"));
  assert.ok(formAction, "form-action must be stated, not left to default-src");
  assert.match(
    formAction,
    new RegExp(CHECKOUT_ORIGIN.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    "form-action must permit the checkout origin or the POST redirect is silently dropped"
  );
});

test("widening form-action did not loosen anything else", () => {
  assert.match(CSP, /default-src 'none'/);
  assert.match(CSP, /base-uri 'none'/);
  assert.doesNotMatch(CSP, /script-src/, "these pages run no scripts");
  assert.doesNotMatch(CSP, /unsafe-eval/);
  // 'unsafe-inline' is for styles only — the pages are inline-styled by design.
  assert.match(CSP, /style-src 'unsafe-inline'/);
});
