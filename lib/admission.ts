// Shared admission policy — decides whether an authenticated public key may use
// this server, and at which door. Extracted from server.ts so every entrypoint
// enforces identical rules with no drift.
//
//   open      — anyone who passes HQC auth (default; the official server)
//   allowlist — only public keys in ADMISSION_ALLOWLIST (private/family servers)
//
// This function used to answer "has this person paid?" — first by calling Stripe
// on every login, later by reading a subscription claim. It answers neither now.
// The product is free and funded by donations, so there is no entitlement to
// look up and the question is the one the name always implied: is this key
// allowed on this server at all.
//
// `allowlist` is what remains of the gate, and it is the lever to reach for if
// the open server is ever abused: it is a policy switch, not a rebuild.

import { DB } from "../services/db/api";
import { peerId } from "./identity";
import { logger } from "./logger";

export const ADMISSION_POLICY = (process.env.ADMISSION_POLICY || "open").toLowerCase();
export const ADMISSION_ALLOWLIST = (process.env.ADMISSION_ALLOWLIST || "")
  .split(",").map((s) => s.trim()).filter(Boolean);

/**
 * Which door a client knocked on. The free door grants a bot-only session; the
 * full door grants everything.
 *
 * They stayed separate endpoints after the paywall was removed because the
 * distinction still earns its keep: the free door is what a client falls back to
 * when the full door refuses it, which is how the app keeps working against an
 * `allowlist` deployment instead of failing shut.
 *
 * The wire name of the full door is still "paid" — the app, the bot and the
 * deployed servers all speak it, and renaming a live path buys nothing but a
 * migration. Nothing behind it costs money.
 */
export type Door = "free" | "paid";

export type Admission =
  | { ok: true }
  | { ok: false; reason: "denied" };

/** Whether a public key is exempt from every gate (the helper bot). Exemption
 *  waives policy, never the proof of key possession.
 *
 *  The ENV lists hold public keys, because that is what an operator has in front
 *  of them and what every other document about this deployment refers to. The
 *  DATABASE holds ids, because that is what names a client everywhere else. The
 *  conversion happens here rather than at either end, so neither an operator nor
 *  the schema has to know about the other's form. */
async function isExempt(pkHex: string, id: string): Promise<boolean> {
  const configured = (process.env.EXEMPT_PUBLIC_KEYS || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  if (configured.some((k) => peerId(k) === id)) return true;

  // Self-registered exemptions (the helper bot writes its own id on startup;
  // see bot/bot.ts). Survives the bot's identity changing without an operator
  // editing EXEMPT_PUBLIC_KEYS. Best-effort: a database blip here must not
  // hard-fail admission, so a failure falls through to the policy check.
  try {
    return await DB.isAdmissionExempt(id);
  } catch (e: any) {
    logger.error(`[admission] exempt-set lookup failed: ${e.message}`);
    return false;
  }
}

/**
 * `pkHex` is the full public key, because this runs on the auth path — the one
 * place a key is in hand. Everything it looks up is keyed by `peerId(pkHex)`.
 */
export async function checkAdmission(pkHex: string, door: Door): Promise<Admission> {
  const id = peerId(pkHex);
  if (await isExempt(pkHex, id)) return { ok: true };

  switch (ADMISSION_POLICY) {
    case "allowlist":
      // A private server has no free tier to speak of: an unlisted key is not
      // welcome through either door. Compared as ids so a list entry that
      // differs only in case still matches.
      return ADMISSION_ALLOWLIST.some((k) => peerId(k) === id)
        ? { ok: true }
        : { ok: false, reason: "denied" };

    case "open":
    default:
      // Everyone gets the whole product. There is nothing to pay for anywhere,
      // so the full door is a pass rather than a gate.
      return { ok: true };
  }
}
