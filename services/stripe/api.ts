// Stripe — the only place money is handled.
//
// It used to be the entitlement system: it held the buyer's email, the webhook
// hashed it, and the app claimed a subscription with a code mailed to that
// address. None of that is left. The product is free for everyone and funded by
// donations, so a payment here grants nothing, unlocks nothing, and is never
// looked up again.
//
// What that removes is worth stating plainly, because it is the strongest
// privacy property in the stack: NO EMAIL ADDRESS ENTERS THIS SERVER AT ALL,
// not in the clear and not as a hash. Stripe holds what it needs to take a
// payment. This side keeps one optional string — a display name, for the
// supporters page — and that string is stored with nothing to join it to.

import { logger } from '../../lib/logger';
import { resolvePrices } from '../../lib/donations-config';
import Stripe from 'stripe';

// Lazily constructed so a self-hosted server with no donations configured can
// boot WITHOUT a Stripe key. Throws a clear error only if Stripe is actually used.
let _stripe: Stripe | null = null;
function stripeClient(): Stripe {
  if (_stripe) return _stripe;
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error("STRIPE_SECRET_KEY is required when DONATIONS_ENABLED=1");
  }
  _stripe = new Stripe(key, { apiVersion: '2025-02-24.acacia' });
  return _stripe;
}

/**
 * The recurring donation tiers, low to high, as Stripe price ids.
 *
 * Compiled in, with `STRIPE_DONATION_PRICE_IDS` as an override — the constants
 * and the reasoning are in `lib/donations-config.ts`.
 *
 * They were env-only, and the comment here argued for it: "no default and no
 * hard-coded fallback ... an unset variable means the monthly tiers are simply
 * not offered, and the one-time path still works. Failing quiet is the right
 * failure here." Every clause of that was wrong. Nothing in this process can
 * un-offer a tier — the donate page is a static Worker that renders all three
 * buttons regardless — so an unset variable left the buttons up and made them
 * refuse; the one-time path did not still work, because that variable was unset
 * too; and the failure was not quiet, it was loud in the one place nobody could
 * see it, which is a donor's browser.
 *
 * A Price id is not a secret, and these four have been published in
 * docs/runbooks/deploy.md all along. What the env indirection bought was a
 * donate page depending on two lines of host config invisible from the repo.
 */
const PRICES = resolvePrices(process.env);
const DONATION_PRICE_IDS = PRICES.tiers;

/** Whether recurring tiers can be offered at all. */
export function monthlyTiersAvailable(): boolean {
  return DONATION_PRICE_IDS.length > 0;
}

/** The configured tier price ids, in the order they should be displayed. */
export function donationPriceIds(): readonly string[] {
  return DONATION_PRICE_IDS;
}

/** How many monthly tiers are offered. The site's `TIERS` labels must be this
 *  long and in the same order — it renders its own buttons and cannot ask. */
export function tierCount(): number {
  return DONATION_PRICE_IDS.length;
}

/**
 * The one-time donation price.
 *
 * A Price id rather than an amount built here, for the same reason the tiers
 * are: Stripe decides what is charged. Whether the donor picks the amount is a
 * property of the Price — set `custom_unit_amount` on it and Checkout asks;
 * leave it fixed and Checkout charges it. Either works through this code path
 * unchanged, because all it does is name the price.
 *
 * The configured one is currently FIXED (€10). If that is ever switched to
 * `custom_unit_amount`, the website copy has to change with it: several
 * sentences on `/donate` name the number.
 *
 * Note that `custom_unit_amount` cannot be inlined on `price_data` in Checkout
 * — it only exists on a Price — which is why this is an id and not an object.
 *
 * Compiled in with `STRIPE_DONATION_ONCE_PRICE_ID` as an override, same as the
 * tiers. The line that stood here — "unset means one-time giving is simply not
 * offered" — described a button disappearing. It never did.
 */
const ONCE_PRICE_ID = PRICES.once;

/** Whether the donor-chooses-the-amount path can be offered. */
export function oneTimeAvailable(): boolean {
  return ONCE_PRICE_ID.length > 0;
}

/**
 * The optional name a donor may put on the supporters page.
 *
 * Collected by Stripe rather than by a form on this site, which is what keeps
 * the donation path free of any input of our own: the browser posts a tier
 * choice and nothing else. Optional, and blank is the expected answer — the
 * webhook records a supporter only when it is filled in.
 */
export const DISPLAY_NAME_FIELD_KEY = 'display_name';

const displayNameField: Stripe.Checkout.SessionCreateParams.CustomField = {
  key: DISPLAY_NAME_FIELD_KEY,
  type: 'text',
  optional: true,
  label: { type: 'custom', custom: 'Name for the supporters page (optional)' },
  text: { maximum_length: 60 },
};

/**
 * Which donation the visitor picked.
 *
 * A monthly tier is an INDEX into `STRIPE_DONATION_PRICE_IDS`, not a price id.
 * The website posts `tier0`/`tier1`/… and the id is resolved here, which is the
 * same shape the one-time button has always had (`once` →
 * `STRIPE_DONATION_ONCE_PRICE_ID`). It means no Stripe price id appears in the
 * site's source at all, which still matters now that the ids are compiled into
 * the SERVER: the site is a Cloudflare Worker deployed separately, so an index
 * keeps the two from having to be redeployed together, and a fork changes its
 * prices in one file (`lib/donations-config.ts`) or one env var rather than in
 * two codebases.
 */
export type DonationChoice =
  | { kind: 'monthly'; index: number }
  | { kind: 'once' };

/**
 * Parameters for the checkout session, separated from the call that sends them
 * so they can be asserted without a Stripe account (test/checkout.test.ts).
 *
 * They were not always assertable, and the cost of that showed: this object
 * carried `customer_creation: 'always'`, which Stripe accepts ONLY in payment
 * mode. In subscription mode it is a hard 400 — "`customer_creation` can only be
 * used in `payment` mode" — so every click of the website's one buy button died
 * at the API and rendered the generic error page. Nothing caught it, because
 * nothing could see this object without spending a live API call.
 *
 * That trap is now live in BOTH directions, which is why the guard test matters
 * more than it did: this function builds `payment` sessions as well, and the
 * two modes accept different parameter sets. Neither branch may carry a
 * parameter the other's mode rejects.
 *
 * A monthly tier is an index, bounds-checked here. The caller is a public HTTP
 * route, so the value is attacker-controlled — but an index into a list the
 * operator configured cannot name a price that is not on it, which is a
 * stronger guarantee than validating a submitted id against the same list, and
 * it needs no id in the request at all.
 */
export function checkoutSessionParams(
  baseUrl: string,
  choice: DonationChoice
): Stripe.Checkout.SessionCreateParams {
  const common = {
    success_url: `${baseUrl}/donate/thanks`,
    cancel_url: `${baseUrl}/donate/cancelled`,
    custom_fields: [displayNameField],
  };

  if (choice.kind === 'monthly') {
    const priceId = DONATION_PRICE_IDS[choice.index];
    if (!Number.isInteger(choice.index) || !priceId) {
      throw new Error(`no donation tier at index ${choice.index}`);
    }
    return {
      ...common,
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
    };
  }

  // One-time. Whether the donor names the amount is decided on the Price in
  // Stripe, not here.
  if (!ONCE_PRICE_ID) throw new Error('one-time donations are not configured');
  return {
    ...common,
    mode: 'payment',
    line_items: [{ price: ONCE_PRICE_ID, quantity: 1 }],
  };
}

/**
 * The display name a donor typed at checkout, or null.
 *
 * Reads the completed session's `custom_fields`. Anything else on that object —
 * the address, the customer id, the amount — is deliberately not read: there is
 * no feature that needs it, and not reading it is what makes the claim in this
 * file's header true.
 */
export function displayNameFromSession(session: any): string | null {
  const fields = (session?.custom_fields ?? []) as Array<any>;
  const field = fields.find((f) => f?.key === DISPLAY_NAME_FIELD_KEY);
  const value = typeof field?.text?.value === 'string' ? field.text.value.trim() : '';
  return value.length > 0 ? value.slice(0, 60) : null;
}

export const StripeService = {

  /**
   * A Checkout session for the website's donate button. Stripe collects the
   * email itself, and keeps it: it needs an address to send a receipt, and it
   * is the only party here entitled to see one.
   */
  async createCheckout(baseUrl: string, choice: DonationChoice): Promise<string> {
    const session = await stripeClient().checkout.sessions.create(
      checkoutSessionParams(baseUrl, choice)
    );
    if (!session.url) throw new Error("Stripe returned a checkout session with no URL");
    return session.url;
  },

  /** Verify and parse a raw webhook payload using the signing secret. */
  constructEvent(rawBody: Buffer, signature: string) {
    return stripeClient().webhooks.constructEvent(
      rawBody,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  },

  /**
   * Human-readable labels for the configured tiers, for the donate page.
   *
   * Asks Stripe rather than carrying the amounts in this repo or on the site.
   * The price of a thing lives in the system that charges for it — that was
   * true when there was one price to sell and it is still true now. Best-effort:
   * a page that cannot reach Stripe should still render its ask.
   */
  async tierLabels(): Promise<Array<{ priceId: string; label: string }>> {
    const out: Array<{ priceId: string; label: string }> = [];
    for (const priceId of DONATION_PRICE_IDS) {
      try {
        const price = await stripeClient().prices.retrieve(priceId);
        const amount = typeof price.unit_amount === 'number' ? price.unit_amount / 100 : null;
        const symbols: Record<string, string> = { eur: '€', usd: '$' };
        const symbol = symbols[price.currency] ?? '';
        out.push({
          priceId,
          label: amount === null ? 'choose' : `${symbol}${amount.toFixed(0)} / month`,
        });
      } catch (e: any) {
        logger.warn(`[stripe] could not read price ${priceId}: ${e?.message || e}`);
        out.push({ priceId, label: 'monthly' });
      }
    }
    return out;
  },
};
