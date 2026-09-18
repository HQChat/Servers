// Centralized config loading, Docker-secret resolution, and fail-fast
// validation. This module is intentionally side-effecting at import time so it
// can run BEFORE any service module reads process.env. Import it FIRST in
// server.ts / bot.ts (`import "./lib/config"`).
//
// Load order matters:
//   1. dotenv  — fills process.env from a .env file (ENV_FILE overrides path).
//   2. _FILE   — resolves the Docker/compose "secrets" pattern: any FOO_FILE
//                env var is read from disk and its contents become FOO. This
//                lets compose mount secrets at /run/secrets/* without ever
//                putting the plaintext value in the environment or an image.
//   3. assertConfig(needs) — called explicitly by the entrypoint to fail fast.
//
// `needs` exists because the services no longer want the same things. Only
// app-api talks to Stripe; only push-bridge holds the APNs key. Demanding all of
// all would force every service to hold every secret, which is the opposite of
// what splitting them was for.

import * as fs from "fs";
import { apnsGaps, apnsIntended, apnsSummary } from "./apns-config";
import { donationGaps, donationSummary, resolvePrices } from "./donations-config";

// 1. dotenv (best-effort: in Docker the env comes from compose, not a file).
try {
  const dotenv = require("dotenv");
  dotenv.config({ quiet: true, ...(process.env.ENV_FILE ? { path: process.env.ENV_FILE } : {}) });
} catch {
  // dotenv not installed / no file — fine when env is injected by the runtime.
}

// 2. Resolve the *_FILE secrets convention (Docker secrets / compose `secrets:`).
//    For every FOO_FILE that points at a readable file, set FOO to its trimmed
//    contents unless FOO is already explicitly set (explicit env wins).
for (const key of Object.keys(process.env)) {
  if (!key.endsWith("_FILE")) continue;
  const base = key.slice(0, -"_FILE".length);
  if (process.env[base]) continue; // explicit value takes precedence
  const path = process.env[key];
  if (!path) continue;
  try {
    process.env[base] = fs.readFileSync(path, "utf8").trim();
  } catch (err: any) {
    // Loud, because a missing secret file is almost always a deploy mistake.
    console.error(`⚠️  config: ${key}=${path} could not be read: ${err.message}`);
  }
}

const isProd = process.env.NODE_ENV === "production";

/** What the calling service actually uses. Checks for a capability nobody
 *  declared are skipped — an auth server with no Stripe key is correct, not
 *  broken. */
/**
 * Whether this deployment takes donations. Independent of ADMISSION_POLICY:
 * money buys nothing here, so it has no say in who is admitted.
 */
export const DONATIONS_ENABLED = /^(1|true|yes)$/i.test(process.env.DONATIONS_ENABLED || "");

// `WIRE_V3_EMIT` stood here. It let a deployment choose which wire format it
// EMITTED while acceptance stayed dual, which is what made the v2 → v3 rollout
// separable into two releases: every build learned to READ v3 first, and only
// then did anyone start writing it. Both halves are done, so the flag is a
// choice between one option and nothing. Its Apple twin, `Deployment.wireVersion`,
// went the same way.

/**
 * A note to show every client, or empty for none.
 *
 * It was written for the wire-version flip, and that is the shape of the job it
 * is for: a change every client has to have taken before the server can rely on
 * it. A peer on a build that cannot read what the server now sends drops the
 * frames silently, so the change is made in a window, and this is what tells
 * people the window is open.
 *
 * DELIBERATELY ADVISORY. It shows a message and blocks nothing. A hard gate
 * during a maintenance window is the wrong instinct here for a security reason:
 * the window is exactly when a client most needs to reach the server — to
 * receive the build that closes whatever the window is for. A banner that
 * everybody can ignore is worth more than a door that locks the fix out.
 */
export const MAINTENANCE_MESSAGE = (process.env.MAINTENANCE_MESSAGE || "").trim();

export type ConfigNeed = "stripe" | "apns";

/** Exit with a combined message listing every missing/invalid setting, so a
 *  misconfigured box fails immediately at boot instead of at first request. */
export function assertConfig(needs: ConfigNeed[] = []): void {
  const errors: string[] = [];
  const warnings: string[] = [];
  const require = (name: string, why: string) => {
    if (!process.env[name]?.trim()) errors.push(`${name} is required (${why}).`);
  };

  const policy = (process.env.ADMISSION_POLICY || "open").toLowerCase();

  // Donations are configured INDEPENDENTLY of admission now. They used to be the
  // same switch — `ADMISSION_POLICY=stripe` meant both "take payments" and
  // "payment decides who gets in" — and separating them is the whole point of
  // the change: money no longer has anything to do with who is admitted. A
  // self-hoster runs the same image with donations off and no Stripe key.
  if (DONATIONS_ENABLED && needs.includes("stripe")) {
    require("STRIPE_SECRET_KEY", "DONATIONS_ENABLED=1");
    require("STRIPE_WEBHOOK_SECRET", "DONATIONS_ENABLED=1; verifies webhook signatures");
    require("PUBLIC_BASE_URL", "DONATIONS_ENABLED=1; used to build Stripe redirect URLs");
    // Both price settings, not just the tiers. The warning this replaces named
    // only STRIPE_DONATION_PRICE_IDS and concluded "only one-time donations will
    // be offered" — reassuring, and false on a host where the one-time id was
    // unset as well, which is exactly the host it ran on. Nothing could be
    // charged at all, and the site went on showing four buttons that each
    // answered "that option is not available". See lib/donations-config.ts.
    const prices = resolvePrices(process.env);
    const gaps = donationGaps(prices);
    if (gaps.length) warnings.push(donationSummary(prices) + `. Set ${gaps.join(" and ")} in server.env.`);
  }

  if (policy === "allowlist") {
    if (!process.env.ADMISSION_ALLOWLIST?.trim())
      warnings.push("ADMISSION_POLICY=allowlist but ADMISSION_ALLOWLIST is empty — nobody can join.");
  } else if (policy !== "open") {
    // "stripe" was a valid value until the paywall was removed. Naming it here
    // matters: a host still carrying it in its env would otherwise silently
    // fall through to `open`, which is the right behaviour but a terrible way
    // to learn that the policy you configured no longer exists.
    const hint = policy === "stripe"
      ? ` ADMISSION_POLICY=stripe was removed with the paywall — use "open" and set DONATIONS_ENABLED=1.`
      : "";
    errors.push(`ADMISSION_POLICY="${policy}" is invalid (expected open | allowlist).${hint}`);
  }

  // APNs: all-or-nothing, and ONLY for the service that actually sends.
  //
  // This check used to run in every service, and that made a correctly
  // configured host unbootable. `APNS_KEY_ID`/`APNS_TEAM_ID` belong in the
  // shared `server.env` (they are not secrets); `APNS_KEY_P8` is a compose
  // secret mounted into push-bridge ALONE. So auth and app-api saw two thirds of
  // a config, called it partial, and exited — on a box where push was set up
  // exactly as `.env.example` and `collect-apple-env.sh` say to set it up.
  //
  // The only way to keep the stack booting was to leave APNs unset, which is
  // why a deployment can look healthy and have never sent a single push. The
  // check was right; the SCOPE was wrong. Nothing that cannot send has an
  // opinion about whether push is configured.
  //
  // It does NOT refuse to boot. Push is documented as optional and a stack with
  // no APNs at all is allowed to run, so exiting on HALF a config while
  // tolerating none of one is incoherent — and it is the worse outcome besides:
  // a crash-looping push-bridge takes out the health endpoint and buries its own
  // explanation in restart spam, on a box whose operator may need values from
  // the Apple Developer portal before they can fix it. Waking nobody is what
  // both states do; only one of them also drops the container.
  //
  // Saying so is the fix. `push/main.ts` escalates a half-config to logger.error
  // (and therefore Sentry) at boot, repeats the verdict on every broker connect,
  // and names the reason on the first wake it cannot perform.
  if (needs.includes("apns")) {
    const gaps = apnsGaps(process.env);
    if (gaps.length && apnsIntended(process.env)) {
      warnings.push(
        `APNs is partially configured — missing ${gaps.join(", ")}. ` +
        `Nothing will be woken until all of them are set. ` +
        `The credentials are secrets; the ids and topics are not and belong in server.env.`
      );
    } else if (gaps.length) {
      // No APNs at all is how CI and local dev run. Still said out loud: it is
      // the single most likely answer to "why did my phone not buzz".
      warnings.push(apnsSummary(process.env));
    }
  }

  // The database is not optional for any service in this stack — it IS the
  // state. A missing URL used to be survivable because ioredis defaulted to
  // localhost; nothing defaults now, so say so at boot rather than at the first
  // request.
  const databaseUrl = process.env.DATABASE_URL || "";
  require("DATABASE_URL", "every service reads and writes Postgres");
  if (isProd && databaseUrl) {
    // `sslmode=require` encrypts but does not authenticate the server, which is
    // DigitalOcean's default and not enough on its own: the CA is on the host
    // (PGSSLROOTCERT), so there is no reason to accept anything weaker.
    if (!/sslmode=verify-full/.test(databaseUrl)) {
      warnings.push(
        "DATABASE_URL does not request sslmode=verify-full — the connection is encrypted but the server is not authenticated."
      );
    }
    if (!process.env.PGSSLROOTCERT?.trim()) {
      warnings.push("PGSSLROOTCERT is unset — verify-full cannot be honoured without the cluster CA.");
    }
    if (/CHANGE_ME/i.test(databaseUrl)) {
      errors.push("DATABASE_URL still contains the placeholder CHANGE_ME password.");
    }
  }

  for (const w of warnings) console.warn(`⚠️  config: ${w}`);
  if (errors.length) {
    console.error("\n❌ Invalid configuration — refusing to start:\n  - " + errors.join("\n  - ") + "\n");
    process.exit(1);
  }
}
