// The early-warning monitor: what it decides is wrong, and how often it says so.
//
// Every service starts this, and it is the thing that turns a stalling process
// into a Sentry event somebody sees. Its failure modes are the watchdog's, one
// layer down — alert on every sample and the channel is noise; alert once and a
// process that has been degraded for an hour looks fine.
//
// The thresholds are read from the environment AT IMPORT, so this file sets them
// before importing the module. node --test runs each file in its own process, so
// that is contained here and cannot disturb another suite.

// MUST be first: this sets the thresholds, and lib/health-monitor reads them at
// import. Assigning process.env in this file's body would be too late — `import`
// is hoisted, so the module would already have read the defaults.
import "./helpers/health-env";

import { test } from "node:test";
import assert from "node:assert/strict";
import { healthMonitor } from "../lib/health-monitor";

/**
 * An ALERT line, not just any line carrying the stethoscope.
 *
 * `start()` logs "🩺 health monitor on — sampling every …", so filtering on the
 * emoji alone counts the startup banner as an alert and every one of these
 * assertions reads the wrong list.
 */
const ALERT = /🩺 health (WARN|CRIT)/;

/** Capture what the logger writes, since alerting is the observable behaviour. */
function captureConsole() {
  const lines: string[] = [];
  const saved = { log: console.log, error: console.error, warn: console.warn };
  for (const k of ["log", "error", "warn"] as const) {
    (console as any)[k] = (...a: unknown[]) => lines.push(a.map(String).join(" "));
  }
  return { lines, restore: () => Object.assign(console, saved) };
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Exactly ONE sample window (HEALTH_SAMPLE_MS = 150).
 *
 * Deliberately not "comfortably more than one". The counters reset on every
 * sample, so a wait long enough for two windows sees the second — an error storm
 * asserted after three windows reads as `ok`, because it was, by then. That cost
 * me four failing tests before I noticed the tests were wrong and the monitor
 * was right.
 */
const aSample = () => wait(200);

test.afterEach(() => healthMonitor.stop());

test("thresholds come from the environment", () => {
  const t = healthMonitor.getThresholds();
  assert.equal(t.errWarn, 3, "HEALTH_ERR_WARN was not read");
  assert.equal(t.errCrit, 6);
  assert.equal(t.sampleMs, 150);
  // An unset one keeps its default, which is what makes the overrides safe to
  // ship: a deployment tunes one number without inheriting zeros for the rest.
  assert.ok(t.loopWarnMs > 0);
  assert.ok(t.rssWarnMB > 0);
});

test("a snapshot only exists once sampling has started", async () => {
  healthMonitor.stop();
  healthMonitor.start();
  await aSample();
  const snap = healthMonitor.getSnapshot();
  assert.ok(snap, "expected a snapshot after a sample window");
  assert.ok(["ok", "warn", "crit"].includes(snap!.status));
  assert.ok(Array.isArray(snap!.tripped));
  assert.ok(snap!.rssMB > 0, "rss should be a real measurement");
});

test("a quiet process reports ok and says nothing", async () => {
  const cap = captureConsole();
  try {
    healthMonitor.start();
    await aSample();
    await aSample();
  } finally { cap.restore(); healthMonitor.stop(); }
  assert.equal(healthMonitor.getSnapshot()?.status, "ok");
  assert.deepEqual(cap.lines.filter((l) => ALERT.test(l)), [],
    "a healthy process must not be reported at all");
});

test("an error storm trips, and names what tripped", async () => {
  const cap = captureConsole();
  try {
    healthMonitor.start();
    for (let i = 0; i < 8; i++) healthMonitor.noteError();   // over errCrit = 6
    await aSample();
  } finally { cap.restore(); healthMonitor.stop(); }

  const snap = healthMonitor.getSnapshot()!;
  assert.equal(snap.status, "crit", `expected crit, got ${snap.status}: ${snap.tripped.join("; ")}`);
  assert.ok(snap.tripped.some((t) => /error/i.test(t)), snap.tripped.join("; "));
  // The alert has to carry WHAT tripped — "health CRIT" on its own tells an
  // operator to go looking, which is the state they were already in.
  const alerts = cap.lines.filter((l) => ALERT.test(l));
  assert.ok(alerts.length >= 1, "a crit must be reported");
  assert.match(alerts[0]!, /CRIT/);
  assert.match(alerts[0]!, /error/i);
});

test("the counters reset each window, so a burst does not trip forever", async () => {
  healthMonitor.start();
  for (let i = 0; i < 8; i++) healthMonitor.noteError();
  await aSample();
  assert.equal(healthMonitor.getSnapshot()?.status, "crit");

  // Nothing further goes wrong. The next window must come back clean rather than
  // carrying the previous one's count — a monitor that never recovers is one
  // nobody believes.
  await aSample();
  await aSample();
  assert.equal(healthMonitor.getSnapshot()?.status, "ok",
    "the error count is per-window, not cumulative");
});

// `healthMonitor` is a module SINGLETON, so its cooldown state survives from one
// test to the next: an alert in an earlier test can leave a later one inside the
// window. These two assert on bounds rather than exact counts for that reason —
// the property is "suppressed", not "exactly one", and an exact count makes the
// test depend on what ran before it.
test("a sustained warning is not re-reported on every sample", async () => {
  const cap = captureConsole();
  const windows = 5;
  try {
    healthMonitor.start();
    // Stay in `warn` (over errWarn=3, under errCrit=6) across several windows.
    for (let w = 0; w < windows; w++) {
      for (let i = 0; i < 4; i++) healthMonitor.noteError();
      await aSample();
    }
  } finally { cap.restore(); healthMonitor.stop(); }

  const alerts = cap.lines.filter((l) => ALERT.test(l));
  assert.ok(alerts.length <= 1,
    `${windows} windows at warn must not produce ${alerts.length} alerts — the cooldown is not holding`);
  for (const a of alerts) assert.match(a, /WARN/, "a warn must not be reported as crit");
});

test("warn escalating to crit is reported immediately, cooldown or not", async () => {
  const cap = captureConsole();
  try {
    healthMonitor.start();
    for (let i = 0; i < 4; i++) healthMonitor.noteError();   // warn
    await aSample();
    for (let i = 0; i < 9; i++) healthMonitor.noteError();   // crit, well inside the cooldown
    await aSample();
  } finally { cap.restore(); healthMonitor.stop(); }

  const alerts = cap.lines.filter((l) => ALERT.test(l));
  // The claim is that reaching crit reports EVEN THOUGH the cooldown is running —
  // the warn that preceded it may itself have been suppressed by an earlier
  // test's alert, so only the crit is asserted.
  assert.ok(alerts.some((l) => /CRIT/.test(l)),
    `an escalation to crit must not be suppressed by the cooldown; saw: ${JSON.stringify(alerts)}`);
});

test("backpressured sockets are counted and tripped on", async () => {
  // A slow consumer is invisible in every other measurement: the process is
  // fine, memory is fine, and messages simply stop arriving at one client.
  const socket = (buffered: number) => ({ bufferedAmount: buffered, readyState: 1 });
  const wss = {
    clients: {
      size: 4,
      forEach: (cb: (c: any) => void) => [
        socket(0), socket(0), socket(50 * 1024 * 1024), socket(50 * 1024 * 1024),
      ].forEach(cb),
    },
  };
  healthMonitor.start(wss, 1024);        // cap of 1 KiB, so two are over it
  await aSample();
  const snap = healthMonitor.getSnapshot()!;
  assert.equal(snap.wsClients, 4, "client count comes from the server, not a guess");
  assert.ok(snap.wsBackpressured >= 2, `expected backpressured sockets, got ${snap.wsBackpressured}`);
  assert.ok(snap.tripped.some((t) => /backpressure/i.test(t)), snap.tripped.join("; "));
});

test("start is idempotent and stop actually stops", async () => {
  healthMonitor.start();
  healthMonitor.start();                 // must not leave two timers behind
  healthMonitor.stop();
  const after = healthMonitor.getSnapshot();
  await wait(80);
  assert.deepEqual(healthMonitor.getSnapshot(), after,
    "no sample may land after stop — a second timer would keep sampling");
});

test("noteMessage and noteError do not throw before start", () => {
  healthMonitor.stop();
  // Both are called from hot paths that may run before the monitor is up. A
  // throw there would take down the thing being measured.
  healthMonitor.noteError();
  healthMonitor.noteMessage();
});
