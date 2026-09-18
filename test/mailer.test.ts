// The mailer, which is exported, importable, and had no tests.
//
// Its two guarantees are both about what does NOT happen, which is why nothing
// noticed they were unchecked:
//
//   IT NEVER THROWS. A claim endpoint that 500s on a mail outage leaks, by its
//   status code alone, that the address it was handed is one the server would
//   have written to. The caller has to be able to answer identically either way.
//
//   IT NEVER LOGS THE BODY. `lib/scrub.ts` redacts addresses on the way to
//   Sentry, but that is a net, not a guarantee. The guarantee is that this module
//   does not hand the recipient or the text to the logger in the first place.
//
// `fetch` is stubbed, so nothing here reaches Resend.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mailConfigured, sendMail } from "../lib/mailer";

const ENV_KEYS = ["RESEND_API_KEY", "MAIL_FROM", "MAIL_REPLY_TO"] as const;

/** Run `fn` with a given env and a stubbed fetch; restore both afterwards. */
async function withMailer(
  env: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>>,
  fetchImpl: (url: any, init: any) => Promise<any>,
  fn: (sent: Array<{ url: any; init: any }>) => Promise<void>,
): Promise<void> {
  const savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  const savedFetch = globalThis.fetch;
  const sent: Array<{ url: any; init: any }> = [];
  for (const k of ENV_KEYS) {
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  (globalThis as any).fetch = async (url: any, init: any) => {
    sent.push({ url, init });
    return fetchImpl(url, init);
  };
  try {
    await fn(sent);
  } finally {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k as string];
      else process.env[k as string] = v;
    }
    (globalThis as any).fetch = savedFetch;
  }
}

const ok = async () => ({ ok: true, status: 200, text: async () => "" });
const MAIL = { to: "someone@example.com", subject: "Your code", text: "123456" };

// --- configuration -----------------------------------------------------------

test("mailConfigured needs BOTH the key and the from address", async () => {
  await withMailer({ RESEND_API_KEY: "k", MAIL_FROM: "a@b.co" }, ok, async () => {
    assert.equal(mailConfigured(), true);
  });
  await withMailer({ RESEND_API_KEY: "k", MAIL_FROM: undefined }, ok, async () => {
    assert.equal(mailConfigured(), false, "a key with nowhere to send from is not configured");
  });
  await withMailer({ RESEND_API_KEY: undefined, MAIL_FROM: "a@b.co" }, ok, async () => {
    assert.equal(mailConfigured(), false);
  });
  // Whitespace-only is unset, not set — the config is read from env files where
  // an empty value is easy to leave behind.
  await withMailer({ RESEND_API_KEY: "   ", MAIL_FROM: "a@b.co" }, ok, async () => {
    assert.equal(mailConfigured(), false);
  });
});

test("an unconfigured mailer reports failure without calling out", async () => {
  await withMailer({ RESEND_API_KEY: undefined, MAIL_FROM: undefined }, ok, async (sent) => {
    assert.equal(await sendMail(MAIL), false);
    assert.equal(sent.length, 0, "nothing may be sent when there is nowhere to send it");
  });
});

// --- the request -------------------------------------------------------------

test("a configured send posts the mail and reports success", async () => {
  await withMailer({ RESEND_API_KEY: "key-abc", MAIL_FROM: "HQChat <no-reply@example.com>" }, ok,
    async (sent) => {
      assert.equal(await sendMail(MAIL), true);
      assert.equal(sent.length, 1);
      const body = JSON.parse(sent[0]!.init.body);
      assert.deepEqual(body.to, [MAIL.to], "the recipient travels as a list");
      assert.equal(body.from, "HQChat <no-reply@example.com>");
      assert.equal(body.subject, MAIL.subject);
      assert.equal(body.text, MAIL.text);
      assert.equal(body.html, undefined, "html is omitted rather than sent empty");
      assert.equal(body.reply_to, undefined, "…and so is reply_to");
      assert.match(sent[0]!.init.headers.authorization, /^Bearer key-abc$/);
      // Without a deadline a hung provider holds the request open, and the caller
      // is a user-facing endpoint.
      assert.ok(sent[0]!.init.signal, "the request carries a timeout");
    });
});

test("html and reply_to are included only when set", async () => {
  await withMailer(
    { RESEND_API_KEY: "k", MAIL_FROM: "a@b.co", MAIL_REPLY_TO: "help@example.com" }, ok,
    async (sent) => {
      await sendMail({ ...MAIL, html: "<p>123456</p>" });
      const body = JSON.parse(sent[0]!.init.body);
      assert.equal(body.html, "<p>123456</p>");
      assert.equal(body.reply_to, "help@example.com");
    });
});

// --- failure, which must stay quiet --------------------------------------------

test("a provider rejection is reported as false, not thrown", async () => {
  const rejects = async () => ({ ok: false, status: 422, text: async () => "domain not verified" });
  await withMailer({ RESEND_API_KEY: "k", MAIL_FROM: "a@b.co" }, rejects, async () => {
    assert.equal(await sendMail(MAIL), false);
  });
});

test("a network failure is reported as false, not thrown", async () => {
  const explodes = async () => { throw new Error("ECONNREFUSED"); };
  await withMailer({ RESEND_API_KEY: "k", MAIL_FROM: "a@b.co" }, explodes, async () => {
    // If this throws, the test fails — which is the assertion. A claim endpoint
    // that 500s on a mail outage tells the caller their address is one we have.
    assert.equal(await sendMail(MAIL), false);
  });
});

test("a timeout is reported as false, not thrown", async () => {
  const aborts = async () => { const e = new Error("The operation was aborted"); e.name = "TimeoutError"; throw e; };
  await withMailer({ RESEND_API_KEY: "k", MAIL_FROM: "a@b.co" }, aborts, async () => {
    assert.equal(await sendMail(MAIL), false);
  });
});

// --- the secret --------------------------------------------------------------

test("neither the recipient nor the body reaches the logger", async () => {
  // The code in a claim mail IS the secret. Nothing about a failure is worth
  // logging it — and the provider's own error text is safe, which is why it is
  // the one thing that does get logged.
  const written: string[] = [];
  const saved = { log: console.log, error: console.error, warn: console.warn };
  for (const k of ["log", "error", "warn"] as const) {
    (console as any)[k] = (...args: unknown[]) => written.push(args.map(String).join(" "));
  }
  try {
    const rejects = async () => ({ ok: false, status: 500, text: async () => "upstream is unwell" });
    await withMailer({ RESEND_API_KEY: "super-secret-key", MAIL_FROM: "a@b.co" }, rejects, async () => {
      await sendMail({ to: "victim@example.com", subject: "Your code", text: "TOPSECRET123" });
    });
  } finally {
    Object.assign(console, saved);
  }
  const all = written.join("\n");
  assert.ok(!all.includes("victim@example.com"), `recipient leaked: ${all}`);
  assert.ok(!all.includes("TOPSECRET123"), `body leaked: ${all}`);
  assert.ok(!all.includes("super-secret-key"), `api key leaked: ${all}`);
  // …and the provider's reason, which carries no user content, IS kept, because
  // it is usually the whole diagnosis.
  assert.ok(all.includes("upstream is unwell"), "the provider's reason should survive");
});
