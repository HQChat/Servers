// What the donate buttons will actually charge, as a pure function of the
// environment and the prices compiled in below.
//
// Own module, with no imports, for the same two reasons as `apns-config.ts`:
// `lib/config.ts` runs at import time and must not pull `services/stripe/api`
// (and through it the Stripe SDK) into the boot path, and the point of
// extracting it is that it can be asserted in a unit test.
//
// ── Why an unset price id was never a quiet "tier not offered" ──────────────
//
// It reads like one from inside the server: no ids, no tiers, `/donate` renders
// a form with no buttons in it, nothing breaks. That is not what a visitor sees.
// The donate page people actually reach is the marketing Worker
// (`apps/site/src/index.js`), a STATIC page that cannot ask this server
// anything — it renders three monthly tiers and a give-once button
// unconditionally, always. So an unset variable did not remove a button; it
// left the button on the page and made it answer
//
//     400 "That option is not available — go back and pick one of the amounts shown"
//
// to a donor looking straight at the amounts. That is what shipped: prod ran for
// days with `DONATIONS_ENABLED=1` and neither price id in
// `/etc/hqcat/prod/server.env`, and the only clue anywhere was one boot warning
// that named just one of the two variables and described the outcome ("only
// one-time donations will be offered") as something other than a dead page —
// which it also got wrong, because the one-time id was unset too.
//
// The prices are compiled in now, so that host cannot recur: a box with an empty
// server.env charges correctly. The reporting below is kept and still tested,
// because it is what a fork that edits these constants gets told.

/** The two settings that override the compiled-in prices. Neither is required. */
export const DONATION_TIERS_VAR = "STRIPE_DONATION_PRICE_IDS";
export const DONATION_ONCE_VAR = "STRIPE_DONATION_ONCE_PRICE_ID";

/**
 * The Prices this deployment charges.
 *
 * These lived only in `server.env`, on the reasoning that the deployment's
 * Stripe account should stay in its own configuration. What that bought was a
 * donate page whose every button depended on two lines nobody could see from the
 * repo — and the buttons spent days refusing every click, because those two
 * lines were never written to the host.
 *
 * A Stripe **Price id is not a secret**. It names a public thing to buy, it is
 * safe in a client, and these four have been committed in
 * `docs/runbooks/deploy.md` since the donations switch. Moving them here
 * discloses nothing the repo did not already publish — and unlike the runbook,
 * this copy is the one the code reads.
 *
 * Order is LOW TO HIGH and load-bearing: the site's buttons post an index into
 * this list (`tier0`, `tier1`, …) and carry only display labels, so `TIERS` in
 * `apps/site/src/index.js` must stay the same length and the same order.
 * Reorder one and not the other and a button charges the wrong amount.
 * `test/donations-config.test.ts` reads that file and fails on a length drift;
 * the amounts themselves it cannot check, because only Stripe knows them.
 *
 * What compiling them in does NOT protect against: a Price archived or deleted
 * in the Stripe dashboard. That stops being a config gap anything here can
 * report — it fails inside `checkout.sessions.create`, and the donor gets
 * "Something went wrong". Prices cost nothing to leave active; leave them.
 */
export const DEFAULT_DONATION_PRICE_IDS: readonly string[] = [
  "price_1UA7SiKdAg16VdMqEwh5d0di", // €2 / month
  "price_1UA7SiKdAg16VdMq6SgO0npz", // €5 / month
  "price_1UA7SiKdAg16VdMqFzizTrQV", // €15 / month
];

/** €10, a FIXED amount — no `custom_unit_amount` on this Price. Several
 *  sentences on the site name that number; change both or neither. */
export const DEFAULT_DONATION_ONCE_PRICE_ID = "price_1UA7SiKdAg16VdMqlxdkR2Ib";

export type DonationEnv = Record<string, string | undefined>;

/** What this process will charge: monthly tiers low to high, and the one-time
 *  price. Either may be empty, which is what "cannot charge" looks like. */
export interface DonationPrices {
  tiers: string[];
  once: string;
}

/**
 * Every Stripe Price id starts with `price_`. That prefix is the whole
 * validation, and it is worth having: an override reaches this from a
 * hand-edited `server.env` over ssh, and a mangled line ("`,,,`", a stray
 * comment, half a paste) is otherwise indistinguishable from a real id here and
 * only fails much later, inside `checkout.sessions.create`, as a 500 and
 * "Something went wrong" for the donor.
 *
 * Deliberately no stricter than the prefix: test-mode and fixture ids are
 * shaped differently from live ones, and this must not become a second place
 * that decides which of the operator's Prices are real.
 */
const isPriceId = (v: string) => v.startsWith("price_");

const list = (v: string | undefined) =>
  (v || "").split(",").map((s) => s.trim()).filter(isPriceId);

/**
 * Env override first, compiled-in default second.
 *
 * An EMPTY or absent variable is not a request to sell nothing — it is a host
 * that was never configured, and it falls back rather than going dark. That
 * distinction is the entire fix: the previous behaviour treated "nobody wrote
 * this line" as "charge nothing", on a page that goes on showing prices.
 *
 * `defaults` is a parameter, not a closed-over constant, so the no-prices state
 * stays reachable in a test. It is the state a fork reaches by emptying the
 * constants above, and the reporting below exists only to describe it.
 */
export function resolvePrices(
  env: DonationEnv,
  defaults: DonationPrices = {
    tiers: [...DEFAULT_DONATION_PRICE_IDS],
    once: DEFAULT_DONATION_ONCE_PRICE_ID,
  }
): DonationPrices {
  const tiers = list(env[DONATION_TIERS_VAR]);
  const once = env[DONATION_ONCE_VAR]?.trim() || "";
  return {
    tiers: tiers.length ? tiers : defaults.tiers,
    once: isPriceId(once) ? once : defaults.once,
  };
}

/** Which prices resolve to nothing. Empty means every button on the marketing
 *  page can be honoured. */
export function donationGaps(p: DonationPrices): string[] {
  const gaps: string[] = [];
  if (p.tiers.length === 0) gaps.push(DONATION_TIERS_VAR);
  if (!p.once) gaps.push(DONATION_ONCE_VAR);
  return gaps;
}

/** True when NOTHING can be charged — every donate button is dead. */
export function donationsDead(p: DonationPrices): boolean {
  return donationGaps(p).length === 2;
}

/** One line describing what the donate buttons will do. Names variables and
 *  counts, never price ids: this goes to a log and to Sentry. */
export function donationSummary(p: DonationPrices): string {
  const gaps = donationGaps(p);
  if (gaps.length === 2) {
    return `donations are ENABLED but nothing is priced (${DONATION_TIERS_VAR} and ` +
      `${DONATION_ONCE_VAR} resolve to nothing) — every donate button on the site ` +
      `refuses with "that option is not available"`;
  }
  if (gaps.includes(DONATION_TIERS_VAR)) {
    return `donations are enabled for one-time giving only (no monthly tiers resolved) ` +
      `— the site still shows monthly tier buttons, and each of them refuses`;
  }
  if (gaps.includes(DONATION_ONCE_VAR)) {
    return `donations are enabled for ${p.tiers.length} monthly tier(s) only (no ` +
      `one-time price resolved) — the site still shows a give-once button, and it refuses`;
  }
  return `donations ready (${p.tiers.length} monthly tier(s) + one-time)`;
}
