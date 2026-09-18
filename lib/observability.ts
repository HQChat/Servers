// Sentry wiring + process-level crash capture for the relay server and the bot.
//
// WHY THIS EXISTS (the stress-test crash): the server had NO
// process.on("uncaughtException") / ("unhandledRejection") handlers and NO
// per-socket "error" listener. In `ws`, an unhandled socket "error" event (an
// ECONNRESET storm during a flood is the classic trigger) is re-emitted on the
// process and, with no listener, terminates Node. CPU/mem sat at ~40% because it
// was never a resource ceiling — it was an unhandled error killing the process.
//
// This module:
//   1. Initialises Sentry (send-only DSN; safe to ship a default, override via env).
//   2. Registers the logger's Sentry sink so logger.error()/warn() reach Sentry.
//   3. Installs global handlers for uncaughtException / unhandledRejection /
//      process "warning" and a couple of fatal signals, each of which captures to
//      Sentry, FLUSHES, and (for genuinely fatal cases) exits so Docker's
//      restart:unless-stopped brings the process back cleanly.
//
// Import this FIRST in an entrypoint, right after ./lib/config.

import * as Sentry from "@sentry/node";
import { logger, registerSentrySink } from "./logger";
import { scrubEvent, scrubBreadcrumb, redact } from "./scrub";

// Sentry DSNs can only SEND, so one is not a secret — but shipping ours in a
// public repo means every fork and every local run reports into our project.
// There is no default: set SENTRY_DSN (deployment config, see deploy/server.env)
// or run without it, which logs "Sentry disabled" instead of failing quietly.
const DEFAULT_DSN = "";

let started = false;
let sentryOn = false;

export function sentryEnabled(): boolean {
  return sentryOn;
}

/**
 * Initialise Sentry + global crash capture. Idempotent. `component` tags every
 * event ("server" | "bot") so the two processes are distinguishable in Sentry.
 */
/** Which process is reporting — tags every Sentry event so processes are
 *  distinguishable. Extended for the MQTT extraction services. */
export type Component = "server" | "bot" | "auth" | "api" | "push-bridge" | "broker-watch";

export function initObservability(component: Component): void {
  if (started) return;
  started = true;

  const isProd = process.env.NODE_ENV === "production";
  // In dev, stay silent unless a DSN is explicitly provided (no dev spam).
  const dsn =
    process.env.SENTRY_DSN !== undefined
      ? process.env.SENTRY_DSN
      : isProd
      ? DEFAULT_DSN
      : "";

  sentryOn = !!dsn && process.env.SENTRY_ENABLED !== "false";

  if (sentryOn) {
    const release = process.env.SENTRY_RELEASE || process.env.SERVER_VERSION;
    Sentry.init({
      dsn,
      environment: process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "development",
      ...(release ? { release } : {}),
      // Modest perf sampling — enough to catch event-loop stalls / slow handlers
      // without shipping every frame. Tune with SENTRY_TRACES_SAMPLE_RATE.
      tracesSampleRate: Number(process.env.SENTRY_TRACES_SAMPLE_RATE ?? (isProd ? 0.05 : 0)),
      // --- Privacy hardening -------------------------------------------------
      // Never let the SDK attach IPs, headers, cookies or request bodies. This
      // is the default in v8, but for an E2EE relay we set it explicitly so a
      // future upgrade / config drift can't silently start shipping PII.
      sendDefaultPii: false,
      // Bound how much free text a single value can carry off-box (default is
      // 250; we allow more for stacks but still cap the blast radius).
      maxValueLength: 2048,
      // Fewer breadcrumbs = less incidental context leaving with each event.
      maxBreadcrumbs: 50,
      // We install our OWN uncaught/unhandled handlers below (so we control
      // flush + exit + logging). Drop Sentry's so they don't double-fire / exit
      // out from under us. Also drop request-data/local-variable integrations so
      // no incoming HTTP payload or captured local ever reaches an event.
      integrations: (defaults) =>
        defaults.filter(
          (i) =>
            i.name !== "OnUncaughtException" &&
            i.name !== "OnUnhandledRejection" &&
            i.name !== "RequestData" &&
            i.name !== "LocalVariables"
        ),
      // Last line of defence: scrub every event + breadcrumb (see lib/scrub.ts).
      // Drops request/user-ip/hostname and redacts pubkeys, usernames, IPs,
      // tokens, emails, Stripe secrets and ciphertext from all free text.
      beforeSend: (event) => scrubEvent(event),
      beforeSendTransaction: (event) => scrubEvent(event),
      beforeBreadcrumb: (crumb) => scrubBreadcrumb(crumb),
      initialScope: { tags: { component } },
    });
    logger.startup(`🛰️  Sentry enabled (${component}, env=${process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "development"})`);
  } else {
    logger.startup(`🛰️  Sentry disabled (no DSN) — crash handlers still active (${component})`);
  }

  // Route logger.error()/warn()/info() into Sentry (breadcrumbs + events).
  registerSentrySink({
    breadcrumb: (level, message) => {
      if (!sentryOn) return;
      Sentry.addBreadcrumb({ category: "log", level, message: truncate(message) });
    },
    captureError: (err, message) => {
      if (!sentryOn) return;
      if (message) Sentry.addBreadcrumb({ category: "log", level: "error", message: truncate(message) });
      Sentry.captureException(err);
    },
    captureMessage: (message, level) => {
      if (!sentryOn) return;
      Sentry.captureMessage(truncate(message), level);
    },
  });

  installGlobalHandlers(component);
}

function truncate(s: string, n = 1000): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

/**
 * Flush pending Sentry events (best-effort, bounded) then run `after`. Used on
 * fatal paths so the crash event actually leaves the box before we exit.
 */
async function flushThen(after: () => void): Promise<void> {
  try {
    if (sentryOn) await Sentry.flush(2000);
  } catch {
    /* ignore */
  } finally {
    after();
  }
}

function installGlobalHandlers(component: Component): void {
  // The bug that took the server down. An uncaught exception leaves the process
  // in an undefined state — capture it, flush, and exit so the orchestrator
  // restarts us clean (restart:unless-stopped). Do NOT try to keep running.
  process.on("uncaughtException", (err, origin) => {
    logger.error(`💥 uncaughtException (${origin})`, err);
    Sentry.captureException(err, { tags: { fatal: "uncaughtException", origin } });
    void flushThen(() => process.exit(1));
  });

  // Unhandled promise rejections. Node's default is to crash on these too; we
  // capture + log but keep the process alive — a single dropped await in a
  // handler shouldn't take the whole relay down. If this proves too lenient,
  // flip to exit(1) like above.
  process.on("unhandledRejection", (reason) => {
    logger.error("💥 unhandledRejection", reason as any);
    if (sentryOn)
      Sentry.captureException(reason, { tags: { fatal: "unhandledRejection" } });
  });

  // Node process warnings (e.g. MaxListenersExceededWarning — an early sign of a
  // listener leak that precedes an OOM/crash). Surfaced to Sentry as a warning.
  process.on("warning", (w) => {
    logger.warn(`⚠️  process warning: ${w.name}: ${w.message}`);
    if (sentryOn)
      Sentry.captureMessage(`process warning: ${w.name}: ${w.message}`, "warning");
  });

  // Graceful-ish shutdown: flush the buffer so in-flight events aren't lost.
  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => {
      logger.startup(`↩️  ${sig} received — flushing Sentry and exiting (${component})`);
      void flushThen(() => process.exit(0));
    });
  }
}

export { Sentry };
