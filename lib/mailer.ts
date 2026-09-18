// Transactional mail — today that is one message: the OTP that binds a web
// subscription to a device key (services/subscription/api.ts).
//
// Resend over plain `fetch` rather than the SDK. It is one POST with one auth
// header, and a messaging server that ships its own crypto has no business
// adding a dependency tree for that. The provider is reachable only through
// sendMail(), so swapping to SMTP or Postmark is a change to this file alone.
//
// Unconfigured is a SUPPORTED state, not an error. A self-hosted server runs
// ADMISSION_POLICY=open, never sells anything and never sends mail; it must
// still boot. sendMail() warns once and no-ops there, the same way
// services/stripe/api.ts only demands a key at the moment Stripe is used.

import { logger } from "./logger";

const RESEND_ENDPOINT = "https://api.resend.com/emails";

// A provider outage must not hold an HTTP handler open. Resend's own timeout is
// far longer than anything a user will wait for a six-digit code.
const SEND_TIMEOUT_MS = 10_000;

export interface Mail {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

function config() {
  return {
    apiKey: process.env.RESEND_API_KEY?.trim() || "",
    from: process.env.MAIL_FROM?.trim() || "",
  };
}

/** Whether this deployment can send at all. Callers use it to skip work, never
 *  to shape a response — /claim/start answers identically either way. */
export function mailConfigured(): boolean {
  const { apiKey, from } = config();
  return Boolean(apiKey && from);
}

let warnedUnconfigured = false;

/**
 * Send one transactional mail. Returns whether the provider accepted it.
 *
 * Never throws: a claim endpoint that 500s on a mail outage would leak, by its
 * status code, that the address it was given is one we would have written to.
 * The caller logs the failure (which reaches Sentry) and still answers neutrally.
 *
 * NOTHING here logs the body. The code is the whole secret; `lib/scrub.ts`
 * redacts addresses on the way to Sentry, but the only real guarantee is that
 * this module never hands either to the logger in the first place.
 */
export async function sendMail(mail: Mail): Promise<boolean> {
  const { apiKey, from } = config();

  if (!apiKey || !from) {
    if (!warnedUnconfigured) {
      warnedUnconfigured = true;
      logger.warn(
        "[mailer] RESEND_API_KEY/MAIL_FROM unset — transactional mail is disabled. " +
        "Expected on a self-hosted server; a fault on one that sells subscriptions."
      );
    }
    return false;
  }

  try {
    const res = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [mail.to],
        subject: mail.subject,
        text: mail.text,
        ...(mail.html ? { html: mail.html } : {}),
        ...(process.env.MAIL_REPLY_TO ? { reply_to: process.env.MAIL_REPLY_TO } : {}),
      }),
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });

    if (!res.ok) {
      // The body carries Resend's reason (bad domain, suppressed recipient) and
      // no user content, so it is safe to log and is usually the whole diagnosis.
      const detail = await res.text().catch(() => "");
      logger.error(`[mailer] send failed: ${res.status} ${detail.slice(0, 200)}`);
      return false;
    }
    return true;
  } catch (e: any) {
    logger.error(`[mailer] send failed: ${e?.message || e}`);
    return false;
  }
}
