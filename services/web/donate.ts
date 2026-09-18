import { logger } from "../../lib/logger";
import { IncomingMessage, ServerResponse } from "node:http";
import { StripeService, monthlyTiersAvailable, oneTimeAvailable, tierCount } from "../stripe/api";
import { DB } from "../db/api";

// The website's donation surface, and the only place money changes hands.
//
// It used to be the checkout for a subscription that unlocked contacts. Nothing
// is unlocked here now and nothing is bound to anything: the whole app is free,
// a donation grants no feature, and the only thing this flow can leave behind is
// an optional name on the supporters page.
//
// These pages live on the ORIGIN rather than in the marketing Worker because two
// of them need the database or a Stripe call. The Worker serves exact paths only
// (infra/cloudflare/variables.tf), so `/donate` reaches the Worker and
// `/donate/checkout`, `/donate/thanks`, `/donate/cancelled` and `/supporters`
// fall through to here. That split is load-bearing — a `*` in `worker_paths`
// routes the whole API to the marketing site.

function baseUrl(req: IncomingMessage): string {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;
  const host = req.headers.host || "localhost";
  const proto = (req.headers["x-forwarded-proto"] as string) || "https";
  return `${proto}://${host}`;
}

/** Escape anything a donor typed. Supporter names are user-supplied text on a
 *  public page, and the CSP below is a mitigation, not a substitute. */
function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

function page(title: string, inner: string): string {
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · hqchat</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:linear-gradient(160deg,#5b6cff 0%,#8b5cf6 100%); min-height:100vh;
         display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { background:#fff; color:#111; max-width:440px; width:100%; border-radius:20px;
          padding:32px; box-shadow:0 20px 60px rgba(0,0,0,.25); }
  h1 { font-size:1.5rem; margin:0 0 8px; }
  p { color:#555; line-height:1.5; }
  ol, ul { color:#555; line-height:1.6; padding-left:20px; }
  button { width:100%; padding:14px; font:inherit; font-weight:600; color:#fff;
           background:#5b6cff; border:0; border-radius:12px; cursor:pointer; margin-top:12px; }
  .logo { width:64px; height:64px; border-radius:18px; margin:0 auto 16px;
          background:linear-gradient(135deg,#5b6cff,#8b5cf6); display:flex; align-items:center;
          justify-content:center; font-size:30px; }
  .names { list-style:none; padding:0; }
  .names li { padding:8px 0; border-bottom:1px solid #eee; color:#111; }
  .muted { color:#777; font-size:.9rem; }
</style></head>
<body><div class="card"><div class="logo">✦</div>${inner}</div></body></html>`;
}

/**
 * Where Stripe Checkout is served from, and therefore where the POST below
 * redirects the browser.
 *
 * This is in the CSP, and it has to be. `form-action` is enforced across
 * REDIRECTS, not just on the initial submission target: with `form-action
 * 'self'` the browser blocks the 302 out to Stripe, and blocks it *silently* —
 * the server logs a clean 302, the page simply does not move, and the only
 * evidence is a console line the user never sees. That is what "no error, just
 * nothing" looked like.
 *
 * If Stripe Checkout is ever moved to a custom domain, this constant moves with
 * it, or the button goes dead again in exactly the same invisible way.
 */
export const CHECKOUT_ORIGIN = "https://checkout.stripe.com";

/**
 * No scripts on these pages; only inline styles. Locked down apart from the one
 * hole the flow genuinely needs — see `CHECKOUT_ORIGIN`.
 */
export const CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  `form-action 'self' ${CHECKOUT_ORIGIN}`,
  "base-uri 'none'",
].join("; ");

/**
 * The server cannot charge anything. 503, not 400: nothing is wrong with the
 * request, the service is unavailable — and a 4xx here tells a donor they did
 * something wrong when they did not.
 */
function unconfigured(res: ServerResponse) {
  return send(res, 503, page("Donations unavailable", `<h1>Donations are off right now</h1>
    <p>This server has no payment configured, so none of the buttons can take
       anything. That is our end, not yours — nothing was charged and there is
       nothing to retry.</p>
    <p class="muted">The app is free and entirely unaffected; a donation never
       changed anything about it.</p>`));
}

function send(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  res.end(body);
}

/** Read a urlencoded form body. Small and bounded: the only field is a choice. */
async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 4096) throw new Error("form body too large");
    chunks.push(c as Buffer);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

/** Handle /donate* and /supporters. */
export async function handleDonate(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = new URL(req.url || "/", "http://localhost").pathname;

  // Every route below, not just the checkout. `/supporters` reaches the
  // database, and a throw there used to leave this handler entirely: the
  // caller in api/main.ts turned it into a bare `500 error` with none of the
  // headers every other response here carries.
  try {
    if (path === "/supporters") {
      const supporters = await DB.listSupporters();
      const list = supporters.length === 0
        ? `<p class="muted">Nobody yet. This page is written by the people who
             choose to be on it — donating does not put you here unless you type a
             name at checkout.</p>`
        : `<ul class="names">${supporters.map((s) => "<li>" + esc(s.name) + "</li>").join("")}</ul>`;
      return send(res, 200, page("Supporters", `<h1>Supporters</h1>
        <p>People who funded the servers, and asked to be named.</p>
        ${list}
        <p class="muted">No account, email or payment is linked to any name here —
           the name is all this server keeps.</p>`));
    }

    if (path === "/donate/thanks") {
      return send(res, 200, page("Thank you", `<h1>Thank you 🙏</h1>
        <p>That goes straight to the bill — servers, a database and a developer
           account.</p>
        <p>There is nothing to do next. You already had the whole app, and you
           still do; a donation does not change your account in any way.</p>
        <p class="muted">Stripe has emailed you a receipt. If you asked to be
           named, you will appear on the <a href="/supporters">supporters</a>
           page.</p>`));
    }

    if (path === "/donate/cancelled") {
      return send(res, 200, page("Cancelled", `<h1>Nothing was charged</h1>
        <p>No payment was taken. The app is free either way — come back whenever,
           or don't.</p>`));
    }

    // POST starts checkout; anything else here is the origin's fallback offer
    // page. The marketing `/donate` page lives in the Worker and never reaches
    // this handler.
    if (req.method !== "POST") {
      // Nothing priced means no button on this page can charge, so this page does
      // not pretend otherwise. It used to render an empty <form> and a 200: the
      // one surface that can see the server is misconfigured, saying nothing.
      if (!monthlyTiersAvailable() && !oneTimeAvailable()) return unconfigured(res);

      // Buttons post `tier0`/`tier1`/… — an index, never a price id. Same shape as
      // the one-time button's `once`, and the reason no Stripe id needs to appear
      // in any page's markup.
      const tiers = monthlyTiersAvailable()
        ? (await StripeService.tierLabels())
            .map((t, i) => `<button type="submit" name="choice" value="tier${i}">${esc(t.label)}</button>`)
            .join("")
        : "";
      return send(res, 200, page("Donate", `<h1>Support hqchat</h1>
        <p>The app is free and always will be. This pays for the servers it runs
           on — it buys you nothing, and everyone has every feature either way.</p>
        <form method="POST" action="/donate/checkout">
          ${tiers}
          ${oneTimeAvailable() ? `<button type="submit" name="choice" value="once">give once</button>` : ""}
        </form>
        <p class="muted">Not a registered charity and not tax-deductible. This is
           one person's project and one person's server bill.</p>`));
    }

    const form = await readForm(req);
    const choice = (form.get("choice") || "once").trim();
    // Bounded and stripped before it is ever logged below. It is form input, so
    // a 4KB value with newlines in it is a log-injection payload, not a choice.
    const shown = choice.replace(/[^\x20-\x7e]/g, "").slice(0, 32);
    // `once`, or `tierN` where N indexes STRIPE_DONATION_PRICE_IDS. Never a
    // price id: the website does not know them and does not need to.
    const tier = /^tier(\d{1,2})$/.exec(choice);
    const donation = tier
      ? ({ kind: "monthly", index: Number(tier[1]) } as const)
      : ({ kind: "once" } as const);
    // Bounds-checked again inside checkoutSessionParams, which throws — this
    // branch exists so a visitor gets a page instead of a 500.
    const known = donation.kind === "once"
      ? oneTimeAvailable()
      : donation.index < tierCount();
    if (!known) {
      // WHY it is unknown decides both the status and who needs to hear about
      // it, and conflating the two is what made this take days to spot.
      //
      // The donate page visitors reach is the static marketing Worker. It
      // renders every tier and the give-once button unconditionally, because it
      // cannot ask this server what is priced. So when the server has no price
      // ids, a donor is looking at four live buttons and gets told to "pick one
      // of the amounts shown" — advice that cannot be followed, describing the
      // donor's mistake, for a mistake that is entirely the operator's. Prod
      // shipped exactly that: DONATIONS_ENABLED=1 with neither price id in
      // server.env, four dead buttons, and not one log line saying so.
      if (!monthlyTiersAvailable() && !oneTimeAvailable()) {
        // Not error(): app-api already spends one Sentry event on this at boot
        // (api/main.ts), and this line would fire per click. It is worth saying
        // once per donor, in the log, because it is the only evidence that
        // somebody actually tried to give money and could not.
        logger.warn(`[donate] refused "${shown}" — nothing is priced on this server. ` +
          `Set STRIPE_DONATION_PRICE_IDS / STRIPE_DONATION_ONCE_PRICE_ID in server.env.`);
        return unconfigured(res);
      }
      // A choice outside the configured range. Ordinary junk from a crawler or
      // a stale page, and genuinely the caller's problem — the page below is
      // both true and actionable here.
      logger.debug(`[donate] unknown choice "${shown}"`);
      return send(res, 400, page("Unknown option", `<h1>That option is not available</h1>
        <p>Go back and pick one of the amounts shown.</p>`));
    }

    const checkoutUrl = await StripeService.createCheckout(baseUrl(req), donation);
    // Say so if Stripe ever hands back a host the page's CSP will not let the
    // browser follow. Without this the redirect is issued, the browser drops it
    // on the floor, and the server log shows a perfectly healthy 302 — the exact
    // failure that made this bug invisible the first time.
    if (!checkoutUrl.startsWith(`${CHECKOUT_ORIGIN}/`)) {
      logger.error(
        `[donate] checkout URL origin is not ${CHECKOUT_ORIGIN} — the CSP form-action ` +
        `will block this redirect and the button will do nothing. Got: ${new URL(checkoutUrl).origin}`
      );
    }
    res.writeHead(302, { Location: checkoutUrl });
    res.end();
  } catch (e: any) {
    logger.error("[donate] error:", e?.message || e);
    // A throw after the response has started cannot be turned into a page —
    // writeHead would throw again, inside the catch.
    if (res.headersSent) { res.end(); return; }
    return send(res, 500, page("Error", `<h1>Something went wrong</h1>
      <p>Please try again in a moment.</p>`));
  }
}