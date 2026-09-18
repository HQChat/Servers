// The donation pages: the only surface on this server where money changes hands,
// and the only one that renders text a stranger typed.
//
// 48% covered before this file. What was uncovered was the whole handler — every
// page, every refusal, and both of the log lines that exist because a previous
// version of this flow failed *invisibly* in production for days.
//
// ── Why this file stubs its two collaborators ──────────────────────────────────
//
// `handleDonate` reaches Stripe and Postgres. Neither is available in a unit run,
// but that is not the interesting reason. The interesting one is that
// `monthlyTiersAvailable()` / `oneTimeAvailable()` CANNOT be made false from the
// environment: `resolvePrices` (lib/donations-config.ts) falls back to prices
// compiled into the repo whenever the env is empty — deliberately, because a host
// with an unconfigured server.env going dark is the exact outage that module
// documents. So the `unconfigured` branches here are unreachable except by a fork
// that empties those constants, and the only honest way to exercise them is to
// stand in for the pricing module.
//
// A stub can lie, so the first test below checks the real modules still have the
// shape this file pretends they have.
//
// ── Why require.cache and not assignment ──────────────────────────────────────
//
// The obvious `api.monthlyTiersAvailable = () => false` does not work and does
// not say so. tsx compiles `export function` to a non-configurable GETTER, and
// assigning to a getter-only property in sloppy mode is a SILENT no-op — the
// patch appears to succeed, the real function keeps running, and the test passes
// while testing something other than what it claims. Replacing the cached module
// wholesale is the technique that actually holds.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import Module from "node:module";
import type { IncomingMessage, ServerResponse } from "node:http";
import { setLogLevel } from "../lib/logger";

setLogLevel("debug");   // the refusal paths log at debug; this file asserts on them

// --- the real modules, captured before the stubs displace them ----------------

const REAL_STRIPE = require("../services/stripe/api");
const REAL_DB = require("../services/db/api");

// --- the stubs ----------------------------------------------------------------

/** What the stubbed pricing module currently offers. Mutable: `handleDonate`
 *  calls through the module object on every request, so a test can change what
 *  this deployment can charge between one request and the next. */
const priced = {
  tiers: [] as Array<{ priceId: string; label: string }>,
  once: true,
  checkoutUrl: "https://checkout.stripe.com/c/pay/cs_test_123",
  createCheckout: null as null | ((baseUrl: string, choice: any) => Promise<string>),
};

/** Every createCheckout call, so the tests can assert what Stripe was asked for. */
const checkouts: Array<{ baseUrl: string; choice: any }> = [];

const stripeStub = {
  monthlyTiersAvailable: () => priced.tiers.length > 0,
  oneTimeAvailable: () => priced.once,
  tierCount: () => priced.tiers.length,
  StripeService: {
    async tierLabels() { return priced.tiers; },
    async createCheckout(baseUrl: string, choice: any) {
      checkouts.push({ baseUrl, choice });
      if (priced.createCheckout) return priced.createCheckout(baseUrl, choice);
      return priced.checkoutUrl;
    },
  },
};

let supporters: Array<{ name: string; since: string }> = [];
let supportersError: Error | null = null;

const dbStub = {
  DB: {
    async listSupporters() {
      if (supportersError) throw supportersError;
      return supporters;
    },
  },
};

function stubModule(request: string, exports: unknown) {
  const resolved = require.resolve(request);
  const m = new Module(resolved, module);
  m.filename = resolved;
  m.loaded = true;
  m.exports = exports;
  require.cache[resolved] = m;
}

stubModule("../services/stripe/api", stripeStub);
stubModule("../services/db/api", dbStub);

const { handleDonate, CSP, CHECKOUT_ORIGIN } =
  require("../services/web/donate") as typeof import("../services/web/donate");

// --- request / response doubles ------------------------------------------------

function makeReq(opts: {
  url: string; method?: string; headers?: Record<string, string>; body?: string | Buffer[];
}): IncomingMessage {
  const chunks = typeof opts.body === "string" ? [Buffer.from(opts.body, "utf8")] : (opts.body ?? []);
  const r = Readable.from(chunks) as any;
  r.url = opts.url;
  r.method = opts.method ?? "GET";
  r.headers = opts.headers ?? {};
  return r as IncomingMessage;
}

interface Captured {
  status: number;
  headers: Record<string, string>;
  body: string;
  ended: boolean;
  writeHeads: number;
}

/** `headersSent` is modelled, because the handler's catch branches on it — a
 *  double that leaves it undefined would report the guard as covered while
 *  never taking it. */
function makeRes(opts: { endThrowsOnce?: Error } = {}): { res: ServerResponse; out: Captured } {
  const out: Captured = { status: 0, headers: {}, body: "", ended: false, writeHeads: 0 };
  let toThrow = opts.endThrowsOnce;
  const res: any = {
    headersSent: false,
    writeHead(status: number, headers?: Record<string, string>) {
      if (res.headersSent) throw new Error("Cannot render headers after they are sent");
      res.headersSent = true;
      out.writeHeads++;
      out.status = status;
      for (const [k, v] of Object.entries(headers ?? {})) out.headers[k.toLowerCase()] = String(v);
      return res;
    },
    end(body?: string) {
      if (toThrow) { const e = toThrow; toThrow = undefined; throw e; }
      if (body) out.body += body;
      out.ended = true;
    },
  };
  return { res: res as ServerResponse, out };
}

/** One request through the handler. */
async function call(opts: Parameters<typeof makeReq>[0]): Promise<Captured> {
  const { res, out } = makeRes();
  await handleDonate(makeReq(opts), res);
  assert.ok(out.ended, "the handler must always end the response");
  return out;
}

/** Capture what the logger writes while `fn` runs. */
async function withLog<T>(fn: () => Promise<T>): Promise<{ result: T; lines: string[] }> {
  const lines: string[] = [];
  const saved = { log: console.log, warn: console.warn, error: console.error };
  for (const k of ["log", "warn", "error"] as const) {
    (console as any)[k] = (...a: unknown[]) => lines.push(a.map(String).join(" "));
  }
  try {
    return { result: await fn(), lines };
  } finally {
    Object.assign(console, saved);
  }
}

/** The default state: three tiers and a one-time price, which is what every
 *  real deployment has (see the contract test). */
function configured() {
  priced.tiers = [
    { priceId: "price_a", label: "€2 / month" },
    { priceId: "price_b", label: "€5 / month" },
    { priceId: "price_c", label: "€15 / month" },
  ];
  priced.once = true;
  priced.checkoutUrl = "https://checkout.stripe.com/c/pay/cs_test_123";
  priced.createCheckout = null;
  checkouts.length = 0;
  supporters = [];
  supportersError = null;
}

test.beforeEach(() => configured());

// --- the stubs are not a fiction -----------------------------------------------

test("the stubbed modules still match the real ones", () => {
  // Everything below this line is only as true as this test. If `tierLabels` is
  // renamed or `createCheckout` grows an argument, the stub goes on answering the
  // old shape and every other test in this file keeps passing against a module
  // that no longer exists.
  for (const name of ["monthlyTiersAvailable", "oneTimeAvailable", "tierCount"] as const) {
    assert.equal(typeof REAL_STRIPE[name], "function", `services/stripe/api no longer exports ${name}`);
    assert.equal(typeof (stripeStub as any)[name], "function");
  }
  for (const name of ["tierLabels", "createCheckout"] as const) {
    assert.equal(typeof REAL_STRIPE.StripeService[name], "function", `StripeService.${name} is gone`);
    assert.equal(
      REAL_STRIPE.StripeService[name].length, (stripeStub.StripeService as any)[name].length,
      `StripeService.${name} takes a different number of arguments than the stub`,
    );
  }
  assert.equal(typeof REAL_DB.DB.listSupporters, "function", "DB.listSupporters is gone");

  // And the claim in this file's header: the real pricing module cannot report
  // "nothing priced", because the prices are compiled in. That is why the 503
  // paths below are reached through a stub rather than through the environment.
  assert.equal(REAL_STRIPE.monthlyTiersAvailable(), true,
    "compiled-in tiers were expected — if this fails, lib/donations-config's defaults were emptied");
  assert.equal(REAL_STRIPE.oneTimeAvailable(), true);
});

// --- the headers every page carries ---------------------------------------------

const PAGES: Array<{ what: string; req: Parameters<typeof makeReq>[0]; status: number }> = [
  { what: "supporters", req: { url: "/supporters" }, status: 200 },
  { what: "thanks", req: { url: "/donate/thanks" }, status: 200 },
  { what: "cancelled", req: { url: "/donate/cancelled" }, status: 200 },
  { what: "the offer page", req: { url: "/donate" }, status: 200 },
];

test("every page is served with the same locked-down headers", async () => {
  for (const { what, req, status } of PAGES) {
    const out = await call(req);
    assert.equal(out.status, status, what);
    assert.equal(out.headers["content-security-policy"], CSP, what);
    assert.equal(out.headers["x-content-type-options"], "nosniff", what);
    assert.equal(out.headers["x-frame-options"], "DENY", what);
    // These pages carry no session and link to nothing of ours, but the
    // supporters page carries other people's names — the referrer must not
    // follow a donor off it.
    assert.equal(out.headers["referrer-policy"], "no-referrer", what);
    assert.match(out.headers["content-type"]!, /^text\/html; charset=utf-8$/, what);
  }
});

test("the error and refusal pages carry them too", async () => {
  // The easy mistake is to lock down the happy path and hand-roll the failures.
  priced.tiers = [];
  priced.once = false;
  const off = await call({ url: "/donate" });
  assert.equal(off.status, 503);
  assert.equal(off.headers["content-security-policy"], CSP);

  configured();
  priced.createCheckout = async () => { throw new Error("stripe is down"); };
  const boom = await withLog(() => call({ url: "/donate/checkout", method: "POST", body: "choice=once" }));
  assert.equal(boom.result.status, 500);
  assert.equal(boom.result.headers["content-security-policy"], CSP);
  assert.equal(boom.result.headers["x-frame-options"], "DENY");
});

// --- the supporters page, which renders text a stranger typed --------------------

test("a supporter name is escaped, not rendered", async () => {
  // The one place on this server where user-supplied text reaches a public page.
  // The CSP is `default-src 'none'` with no script-src, so an injected <script>
  // would not run in a modern browser — but that is a mitigation, and the comment
  // above `esc` says so. This is the guarantee.
  supporters = [
    { name: `<script>alert(1)</script>`, since: "2026-01-01" },
    { name: `" onmouseover="steal()`, since: "2026-01-02" },
    { name: `Ben & Jerry's`, since: "2026-01-03" },
  ];
  const out = await call({ url: "/supporters" });
  assert.equal(out.status, 200);
  assert.ok(!out.body.includes("<script>alert(1)</script>"), "a script tag was rendered raw");
  assert.ok(!out.body.includes(`onmouseover="steal()`), "an attribute breakout was rendered raw");
  assert.ok(out.body.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "…and the escaped form should be there");
  assert.ok(out.body.includes("&quot; onmouseover=&quot;steal()"));
  // The ampersand must be escaped FIRST or `&lt;` becomes `&amp;lt;` — the
  // classic double-escape ordering bug, and the reason this case is here.
  assert.ok(out.body.includes("Ben &amp; Jerry&#39;s"), out.body.slice(out.body.indexOf("Ben")));
  assert.ok(!out.body.includes("&amp;lt;"), "double-escaped");
});

test("the supporters page publishes the name and nothing else", async () => {
  // Its own copy promises "no account, email or payment is linked to any name
  // here — the name is all this server keeps". `listSupporters` returns a
  // `since` date as well, and rendering it would turn the page into a record of
  // when each person paid.
  supporters = [{ name: "Ada L.", since: "2026-03-04" }];
  const out = await call({ url: "/supporters" });
  assert.ok(out.body.includes("<li>Ada L.</li>"));
  assert.ok(!out.body.includes("2026-03-04"), "the donation date must not be published");
});

test("an empty supporters page explains itself rather than looking broken", async () => {
  supporters = [];
  const out = await call({ url: "/supporters" });
  assert.equal(out.status, 200);
  assert.match(out.body, /Nobody yet/);
  assert.ok(!out.body.includes("<ul"), "no empty list");
});

test("a database failure is a 500 page, not a stack trace", async () => {
  supportersError = new Error("connection refused to postgres://user:hunter2@db");
  const out = await withLog(() => call({ url: "/supporters" }));
  assert.equal(out.result.status, 500);
  assert.match(out.result.body, /Something went wrong/);
  assert.ok(!out.result.body.includes("hunter2"), "the failure detail must not reach the page");
  assert.ok(!out.result.body.includes("postgres://"), out.result.body);
});

// --- the fixed pages -------------------------------------------------------------

test("thanks says there is nothing to do next, and points at supporters", async () => {
  const out = await call({ url: "/donate/thanks" });
  assert.equal(out.status, 200);
  // A donation buys nothing. The page has to say so, or a donor reasonably
  // waits for something to unlock.
  assert.match(out.body, /does not change your account/);
  assert.match(out.body, /href="\/supporters"/);
});

test("cancelled states plainly that nothing was charged", async () => {
  const out = await call({ url: "/donate/cancelled" });
  assert.equal(out.status, 200);
  assert.match(out.body, /Nothing was charged/);
});

// --- the offer page ---------------------------------------------------------------

test("the offer page posts an index, never a price id", async () => {
  const out = await call({ url: "/donate" });
  assert.equal(out.status, 200);
  assert.match(out.body, /<form method="POST" action="\/donate\/checkout">/);
  for (let i = 0; i < 3; i++) {
    assert.ok(out.body.includes(`name="choice" value="tier${i}"`), `tier${i} button missing`);
  }
  assert.ok(out.body.includes(`name="choice" value="once"`));
  // The whole reason the buttons carry an index: a page that named price ids
  // would bake this deployment's Stripe account into its markup.
  assert.doesNotMatch(out.body, /price_/, "a price id reached the page");
});

test("a label from Stripe is escaped before it is rendered", async () => {
  // `tierLabels` is remote data. It is our own Stripe account, so this is not an
  // attack path — it is the assertion that the page has no unescaped hole, which
  // is worth holding whatever the source.
  priced.tiers = [{ priceId: "price_a", label: `<img src=x onerror=alert(1)>` }];
  const out = await call({ url: "/donate" });
  assert.ok(!out.body.includes("<img src=x"), "a Stripe label was rendered raw");
  assert.ok(out.body.includes("&lt;img src=x onerror=alert(1)&gt;"));
});

test("only the buttons that can actually charge are rendered", async () => {
  priced.once = false;
  const noOnce = await call({ url: "/donate" });
  assert.ok(noOnce.body.includes(`value="tier0"`));
  assert.ok(!noOnce.body.includes(`value="once"`), "a dead give-once button");

  configured();
  priced.tiers = [];
  const noTiers = await call({ url: "/donate" });
  assert.equal(noTiers.status, 200);
  assert.ok(!noTiers.body.includes(`value="tier`), "a dead tier button");
  assert.ok(noTiers.body.includes(`value="once"`));
});

test("nothing priced is a 503 that blames the operator, not an empty form", async () => {
  // The documented regression: this page used to render a <form> with no buttons
  // in it and return 200 — the one surface that can see the server is
  // misconfigured, saying nothing.
  priced.tiers = [];
  priced.once = false;
  const out = await call({ url: "/donate" });
  assert.equal(out.status, 503, "503, not 400 — the request was fine, the service is not");
  assert.match(out.body, /Donations are off right now/);
  assert.match(out.body, /That is our end, not yours/);
  assert.ok(!out.body.includes("<form"), "no form when nothing can be charged");
});

// --- starting a checkout ------------------------------------------------------------

test("a tier button starts a monthly checkout at that index", async () => {
  const out = await call({
    url: "/donate/checkout", method: "POST",
    headers: { host: "hqchat.app" }, body: "choice=tier2",
  });
  assert.equal(out.status, 302);
  assert.equal(out.headers["location"], priced.checkoutUrl);
  assert.deepEqual(checkouts, [{ baseUrl: "https://hqchat.app", choice: { kind: "monthly", index: 2 } }]);
});

test("the give-once button starts a one-time checkout", async () => {
  const out = await call({ url: "/donate/checkout", method: "POST", body: "choice=once" });
  assert.equal(out.status, 302);
  assert.deepEqual(checkouts[0]!.choice, { kind: "once" });
});

test("an unrecognised choice becomes a one-time donation rather than a refusal", async () => {
  // Recording what the code DOES, which is not what the 400 page below suggests.
  // `choice` defaults to "once" and only `tier0`..`tier99` parse as a tier, so
  // every other string — a crawler's junk, a three-digit index, an empty field —
  // starts a one-time checkout. Nothing is charged without the donor confirming
  // the amount on Stripe's own page, so this is a surprise rather than a defect;
  // it is here so that a future change to it is a deliberate one.
  for (const choice of ["", "chess", "tier100", "tier-1", "TIER0", "tier 0"]) {
    checkouts.length = 0;
    const out = await call({ url: "/donate/checkout", method: "POST", body: `choice=${encodeURIComponent(choice)}` });
    assert.equal(out.status, 302, `"${choice}" did not start a checkout`);
    assert.deepEqual(checkouts[0]!.choice, { kind: "once" }, `"${choice}"`);
  }
  // …and a missing field entirely.
  checkouts.length = 0;
  await call({ url: "/donate/checkout", method: "POST", body: "" });
  assert.deepEqual(checkouts[0]!.choice, { kind: "once" });
});

test("a tier index past the end is refused with a page, not a 500", async () => {
  // `checkoutSessionParams` throws on an out-of-range index. This branch exists
  // so a visitor gets a sentence instead of "Something went wrong".
  const out = await withLog(() =>
    call({ url: "/donate/checkout", method: "POST", body: "choice=tier7" }));
  assert.equal(out.result.status, 400);
  assert.match(out.result.body, /That option is not available/);
  assert.equal(checkouts.length, 0, "Stripe must not be called for an index we know is bad");
  assert.ok(out.lines.some((l) => /unknown choice "tier7"/.test(l)), out.lines.join("\n"));
});

test("a refusal because nothing is priced names the variables to set", async () => {
  // The distinction that took days to spot: the donor's mistake and the
  // operator's produce the same click. Only one of them can be acted on by the
  // person reading the page, and this is the other one.
  priced.tiers = [];
  priced.once = false;
  const out = await withLog(() =>
    call({ url: "/donate/checkout", method: "POST", body: "choice=tier0" }));
  assert.equal(out.result.status, 503, "not 400 — the donor did nothing wrong");
  assert.match(out.result.body, /Donations are off right now/);
  const warn = out.lines.find((l) => /\[donate\] refused/.test(l));
  assert.ok(warn, `expected a warning naming the config; got:\n${out.lines.join("\n")}`);
  assert.match(warn!, /STRIPE_DONATION_PRICE_IDS/);
  assert.match(warn!, /STRIPE_DONATION_ONCE_PRICE_ID/);
  assert.match(warn!, /server\.env/);
});

// --- the log line is built from form input ---------------------------------------

test("a hostile choice cannot forge log lines", async () => {
  // `choice` is form input and is echoed into a log line. Newlines in it would
  // let a crawler write whatever it liked into the log — including a fake line
  // from another subsystem. The handler strips to printable ASCII and caps at 32.
  priced.tiers = [];
  priced.once = false;
  const payload = `tier0\n2026-01-01 [auth] admin login succeeded\r\n\x1b[31m` + "A".repeat(4000);
  const out = await withLog(() =>
    call({ url: "/donate/checkout", method: "POST", body: `choice=${encodeURIComponent(payload)}` }));

  const warn = out.lines.find((l) => /\[donate\] refused/.test(l))!;
  assert.ok(warn, out.lines.join("\n"));
  const echoed = /refused "([^"]*)"/.exec(warn)?.[1] ?? "";
  assert.ok(!echoed.includes("\n") && !echoed.includes("\r"), `newline survived: ${JSON.stringify(echoed)}`);
  assert.ok(!echoed.includes("\x1b"), "an escape sequence reached the log");
  assert.ok(echoed.length <= 32, `echoed ${echoed.length} characters`);
  // The whole 4 KB must not be in the line anywhere, not merely outside the quotes.
  assert.ok(!warn.includes("A".repeat(33)), "the log line carries the unbounded input");
});

// --- limits and failures ------------------------------------------------------------

test("an oversized form body is refused rather than buffered", async () => {
  // The cap is 4096 and the only real field is a word. Without it a POST here is
  // an unbounded allocation on an unauthenticated endpoint.
  const big = Buffer.alloc(5000, 0x61);
  const out = await withLog(() => call({
    url: "/donate/checkout", method: "POST",
    body: [Buffer.from("choice="), big],
  }));
  assert.equal(out.result.status, 500);
  assert.equal(checkouts.length, 0, "an over-cap body must never reach Stripe");
  assert.ok(out.lines.some((l) => /form body too large/.test(l)), out.lines.join("\n"));
});

test("a body that is exactly at the cap is still accepted", async () => {
  // The other half of the bound, so a future tightening cannot pass by refusing
  // everything. 4096 is the limit and the check is `> 4096`.
  const field = "choice=once&pad=";
  const out = await call({
    url: "/donate/checkout", method: "POST",
    body: [Buffer.from(field), Buffer.alloc(4096 - field.length, 0x62)],
  });
  assert.equal(out.status, 302, "a body at exactly the cap must be accepted");
});

test("a Stripe failure is a page, and the reason stays in the log", async () => {
  priced.createCheckout = async () => { throw new Error("No such price: price_deleted"); };
  const out = await withLog(() =>
    call({ url: "/donate/checkout", method: "POST", body: "choice=once" }));
  assert.equal(out.result.status, 500);
  assert.match(out.result.body, /Something went wrong/);
  assert.ok(!out.result.body.includes("price_deleted"), "the Stripe error reached the donor's page");
  assert.ok(out.lines.some((l) => /price_deleted/.test(l)), "…and it should be in the log");
});

// --- the invisible failure this handler was rebuilt around --------------------------

test("a checkout URL the CSP would block is reported loudly", async () => {
  // The failure that made the original bug take days: the browser drops a
  // redirect that `form-action` does not allow, silently. The server logs a
  // clean 302 and the page simply does not move. This line is the only evidence
  // that would have existed.
  priced.createCheckout = async () => "https://pay.example.com/c/pay/cs_1";
  const out = await withLog(() =>
    call({ url: "/donate/checkout", method: "POST", body: "choice=once" }));

  const err = out.lines.find((l) => /checkout URL origin is not/.test(l));
  assert.ok(err, `expected a loud error; got:\n${out.lines.join("\n")}`);
  assert.match(err!, new RegExp(CHECKOUT_ORIGIN.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(err!, /form-action/, "the message must name the mechanism, or it is unactionable");
  assert.match(err!, /https:\/\/pay\.example\.com/, "…and what it actually got");
  // Still redirects. Refusing here would break a live donation flow on the
  // strength of a hostname check; the log line is the right severity.
  assert.equal(out.result.status, 302);
  assert.equal(out.result.headers["location"], "https://pay.example.com/c/pay/cs_1");
});

test("the expected Stripe origin passes without a word", async () => {
  // The check must not fire on the normal case, or the line is noise and gets
  // muted — which is how it would stop working.
  const out = await withLog(() =>
    call({ url: "/donate/checkout", method: "POST", body: "choice=once" }));
  assert.equal(out.result.status, 302);
  assert.ok(!out.lines.some((l) => /checkout URL origin/.test(l)), out.lines.join("\n"));
});

test("a prefix of the checkout origin does not pass for it", async () => {
  // `startsWith(CHECKOUT_ORIGIN)` without the trailing slash would accept
  // `https://checkout.stripe.com.evil.test/` — a real and well-worn trick. The
  // slash is why it does not, and nothing was holding it there.
  priced.createCheckout = async () => "https://checkout.stripe.com.evil.test/c/pay/x";
  const out = await withLog(() =>
    call({ url: "/donate/checkout", method: "POST", body: "choice=once" }));
  assert.ok(out.lines.some((l) => /checkout URL origin is not/.test(l)),
    "a lookalike host must not satisfy the origin check");
});

// --- where Stripe is told to send the donor back ------------------------------------

test("PUBLIC_BASE_URL pins the return URL, whatever the Host header says", async () => {
  // `baseUrl` builds the success/cancel URLs Stripe redirects to after payment,
  // and `Host` is set by the caller. A deployment sets PUBLIC_BASE_URL and the
  // header stops mattering — which is the configuration that ships.
  const saved = process.env.PUBLIC_BASE_URL;
  process.env.PUBLIC_BASE_URL = "https://hqchat.app";
  try {
    await call({
      url: "/donate/checkout", method: "POST",
      headers: { host: "attacker.test", "x-forwarded-proto": "http" },
      body: "choice=once",
    });
    assert.equal(checkouts[0]!.baseUrl, "https://hqchat.app");
  } finally {
    if (saved === undefined) delete process.env.PUBLIC_BASE_URL;
    else process.env.PUBLIC_BASE_URL = saved;
  }
});

test("without it the URL is built from the request, and defaults to https", async () => {
  const saved = process.env.PUBLIC_BASE_URL;
  delete process.env.PUBLIC_BASE_URL;
  try {
    for (const [headers, expected] of [
      [{ host: "hqchat.app" }, "https://hqchat.app"],
      [{ host: "hqchat.app", "x-forwarded-proto": "http" }, "http://hqchat.app"],
      [{}, "https://localhost"],
    ] as Array<[Record<string, string>, string]>) {
      checkouts.length = 0;
      await call({ url: "/donate/checkout", method: "POST", headers, body: "choice=once" });
      assert.equal(checkouts[0]!.baseUrl, expected, JSON.stringify(headers));
    }
  } finally {
    if (saved !== undefined) process.env.PUBLIC_BASE_URL = saved;
  }
});

// --- routing --------------------------------------------------------------------------

test("a query string does not change which page is served", async () => {
  // The path is taken from a parsed URL rather than compared as a raw string —
  // `/supporters?utm_source=x` is the supporters page, and `/supporters/../donate`
  // is not reachable by a path that only ever matches exactly.
  const out = await call({ url: "/supporters?utm_source=newsletter&x=%2Fdonate" });
  assert.equal(out.status, 200);
  assert.match(out.body, /<h1>Supporters<\/h1>/);
});

test("an unmatched path under /donate falls through to the offer page", async () => {
  // api/main.ts routes everything under /donate here, so this handler is the end
  // of the line: an unknown one must render something rather than hang.
  for (const url of ["/donate/", "/donate/anything", "/donate"]) {
    const out = await call({ url });
    assert.equal(out.status, 200, url);
    assert.match(out.body, /Support hqchat/, url);
  }
});

test("GET on the checkout path shows the offer instead of charging", async () => {
  // Only POST starts a checkout. A donor who reloads /donate/checkout, or a
  // crawler that follows it, must not reach Stripe.
  const out = await call({ url: "/donate/checkout", method: "GET" });
  assert.equal(out.status, 200);
  assert.equal(checkouts.length, 0, "a GET must never create a checkout session");
  assert.match(out.body, /Support hqchat/);
});

test("a client that vanishes mid-redirect does not throw a second time", async () => {
  // The guard in the catch. Once `writeHead` has run, the error page cannot be
  // rendered — attempting it throws again, inside the catch, and the rejection
  // escapes to api/main.ts. A donor closing the tab on the 302 is the ordinary
  // way to reach this.
  const { res, out } = makeRes({ endThrowsOnce: new Error("EPIPE: socket closed") });
  await withLog(() => handleDonate(makeReq({ url: "/donate/checkout", method: "POST", body: "choice=once" }), res));
  assert.equal(out.status, 302, "the redirect was already written");
  assert.equal(out.writeHeads, 1, "the catch must not try to write a second set of headers");
});
