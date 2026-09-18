// Sentry flood control.
//
// This exists because a month's Sentry quota was spent in production on ONE
// condition: the bot's `openSession` reported "could not open a session" for
// every peer that had not published prekeys yet, once per 15-second poll. That
// is 240 events an hour per affected user, for something expected and
// self-resolving.
//
// The call site is fixed (NO_PREKEYS is now a debug line), but these tests are
// about the backstop rather than that bug: no call site, present or future,
// should be able to spend the quota by looping.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  logger,
  registerSentrySink,
  resetSentryThrottle,
  setLoggerClock,
  fingerprint,
  setLogLevel,
} from "../lib/logger";

setLogLevel("silent"); // keep the console out of node:test's IPC

/** Collects what would have been billed. */
function collector() {
  const events: string[] = [];
  registerSentrySink({
    breadcrumb: () => {},
    captureError: (_e, m) => { events.push(m ?? ""); },
    captureMessage: (m) => { events.push(m); },
  });
  return events;
}

test("the first occurrence is never delayed", () => {
  resetSentryThrottle();
  const events = collector();
  logger.error("🤖 [bot] the broker is unreachable");
  assert.equal(events.length, 1, "a new failure must reach Sentry immediately");
});

test("a loop cannot spend the quota", () => {
  resetSentryThrottle();
  const events = collector();
  // The real shape: one poll every 15s, forever.
  for (let i = 0; i < 240; i++) logger.error("🤖 [bot] friend poll: connect ECONNREFUSED");
  assert.equal(events.length, 1, "240 identical errors must bill exactly one event");
});

test("per-peer detail collapses to one fingerprint", () => {
  resetSentryThrottle();
  const events = collector();
  // The property that actually saved the quota. Without it, 200 users with no
  // prekeys are 200 distinct messages and the throttle buys nothing.
  for (const id of ["135652ce", "a91f0b27", "77c3de04", "0f0f0f0f"]) {
    logger.error(`🤖 [bot] could not open a session with @user…${id}: POST /prekeys/claim → 404`);
  }
  assert.equal(events.length, 1, "the same failure about different peers is one failure");
});

test("an unrelated error is never held back by another's window", () => {
  resetSentryThrottle();
  const events = collector();
  logger.error("🤖 [bot] friend poll: connect ECONNREFUSED");
  logger.error("🔒 [auth] 5 failed key-possession proofs in 15m for one public key");
  assert.equal(events.length, 2, "throttling is per fingerprint, not global");
});

test("a suppressed run is reported, not silently dropped", () => {
  resetSentryThrottle();
  const events = collector();
  // Time is driven, not waited on. The earlier version of this test used a 1 ms
  // window and a busy-wait; it passed here and failed on CI, because two
  // synchronous calls can straddle a millisecond on a loaded runner.
  let t = 1_000_000;
  setLoggerClock(() => t);
  try {
    logger.error("boom");           // 1st: sent
    logger.error("boom");           // suppressed
    logger.error("boom");           // suppressed
    assert.equal(events.length, 1, "the run in between must be suppressed");

    t += 10 * 60 * 1000 + 1;        // the default window, plus a tick
    logger.error("boom");           // window rolled: sent, carrying the count
    assert.equal(events.length, 2, "the next event after the window must go through");
    assert.match(events[1] ?? "", /\[\+2 identical suppressed/,
      "a persistent problem must say how much of it was hidden");
  } finally {
    setLoggerClock();
  }
});

test("the window is read per call, so it can be widened without a restart", () => {
  // An operator watching a host flood should be able to turn this up in
  // server.env and have it apply. Read once into a const, it could not be.
  resetSentryThrottle();
  const events = collector();
  let t = 2_000_000;
  setLoggerClock(() => t);
  process.env.SENTRY_THROTTLE_MS = String(60 * 60 * 1000); // one hour
  try {
    logger.error("widened");
    t += 30 * 60 * 1000;            // half an hour later: still inside the window
    logger.error("widened");
    assert.equal(events.length, 1, "the widened window must be honoured");
  } finally {
    delete process.env.SENTRY_THROTTLE_MS;
    setLoggerClock();
  }
});

test("fingerprinting collapses ids, counts and handles", () => {
  // Deliberately explicit: this function decides what shares a budget, so its
  // behaviour should be readable without running it.
  assert.equal(
    fingerprint("could not open a session with @user…135652ce: POST /x → 404"),
    fingerprint("could not open a session with @other…a91f0b27: POST /x → 500"),
    "peer and status vary; the failure does not"
  );
  assert.notEqual(
    fingerprint("could not open a session"),
    fingerprint("could not publish prekeys"),
    "different failures must stay different"
  );
});

test("the console is not throttled", () => {
  // stderr is not metered, and an operator tailing logs must see every
  // occurrence — the throttle is a Sentry-billing concern only.
  resetSentryThrottle();
  collector();
  setLogLevel("error");
  const seen: string[] = [];
  const original = console.error;
  console.error = (...a: unknown[]) => { seen.push(a.join(" ")); };
  try {
    for (let i = 0; i < 5; i++) logger.error("🤖 [bot] repeated and identical");
  } finally {
    console.error = original;
    setLogLevel("silent");
  }
  assert.equal(seen.length, 5, "every occurrence must still print");
});
