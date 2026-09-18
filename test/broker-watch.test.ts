// The watchdog's alert state machine.
//
// Its contract is one sentence — "only transitions (and stuck failures) reach
// Sentry; steady state is silent" — and both ways of breaking it are invisible
// from inside the process:
//
//   alert on every tick   the channel becomes noise, and the one line worth
//                         reading is buried under thousands of copies of itself
//   alert only once       a fault that persists for a day looks like it was
//                         handled, because nothing said otherwise
//
// Neither shows up as an error. The only symptom of the second is an outage
// nobody was told about.
//
// The clock and the sink are injected, so these run in no time at all and assert
// on exactly what would have been sent.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createEscalator, type Check } from "../ops/broker-watch";

const REALERT = 30 * 60_000;

/** A frozen clock the test moves by hand, and a recorder for what was sent. */
function harness(realertMs = REALERT) {
  let now = 1_000_000;
  const alerts: string[] = [];
  const recoveries: string[] = [];
  const e = createEscalator({
    realertMs,
    now: () => now,
    sink: { alert: (m) => alerts.push(m), recovered: (m) => recoveries.push(m) },
  });
  return {
    alerts, recoveries,
    advance: (ms: number) => { now += ms; },
    fail: (detail = "down") => e.escalate({ name: "emqx", ok: false, detail }),
    pass: (detail = "up") => e.escalate({ name: "emqx", ok: true, detail }),
    check: (c: Check) => e.escalate(c),
    state: e.state,
  };
}

test("a healthy check that stays healthy says nothing at all", () => {
  const h = harness();
  for (let i = 0; i < 20; i++) { h.pass(); h.advance(30_000); }
  assert.deepEqual(h.alerts, []);
  assert.deepEqual(h.recoveries, [], "there was nothing to recover from");
});

test("the first failure alerts", () => {
  const h = harness();
  h.pass();
  h.fail("connection refused");
  assert.equal(h.alerts.length, 1);
  assert.match(h.alerts[0]!, /emqx unhealthy: connection refused/);
});

test("a failure on the very first check alerts too", () => {
  // No previous state at all — a watchdog that only reported TRANSITIONS would
  // stay silent through a dependency that was already down when it started.
  const h = harness();
  h.fail("down at boot");
  assert.equal(h.alerts.length, 1);
});

test("a failure that persists does not alert again until the re-alert window", () => {
  const h = harness();
  h.fail();
  assert.equal(h.alerts.length, 1);

  // Every tick for just under the window: still one alert.
  for (let i = 0; i < 50; i++) { h.advance(30_000); h.fail(); }
  assert.equal(h.alerts.length, 1,
    `expected the watchdog to stay quiet, got ${h.alerts.length} alerts`);
});

test("…and does alert again once the window passes, saying how long", () => {
  const h = harness();
  h.fail();
  h.advance(REALERT);
  h.fail();
  assert.equal(h.alerts.length, 2, "a stuck failure is re-reported");
  assert.match(h.alerts[1]!, /unhealthy for 30m/,
    "the re-alert says how long it has been broken, which is the point of sending it");
});

test("recovery is reported once, with the duration", () => {
  const h = harness();
  h.fail();
  h.advance(5 * 60_000);
  h.pass("200 OK");
  assert.equal(h.recoveries.length, 1);
  assert.match(h.recoveries[0]!, /recovered after 5m/);

  // …and staying healthy afterwards is silent again.
  for (let i = 0; i < 10; i++) { h.advance(60_000); h.pass(); }
  assert.equal(h.recoveries.length, 1);
  assert.equal(h.alerts.length, 1);
});

test("a flap alerts once per outage, not once per tick", () => {
  const h = harness();
  for (let i = 0; i < 5; i++) {
    h.fail();
    h.advance(30_000);
    h.pass();
    h.advance(30_000);
  }
  assert.equal(h.alerts.length, 5, "five distinct outages, five alerts");
  assert.equal(h.recoveries.length, 5);
});

test("the 'unhealthy for' duration measures the outage, not the last alert", () => {
  const h = harness();
  h.fail();                        // t0: alert 1
  h.advance(REALERT);
  h.fail();                        // alert 2, "for 30m"
  h.advance(REALERT);
  h.fail();                        // alert 3 — must say 60m, not 30m
  assert.equal(h.alerts.length, 3);
  assert.match(h.alerts[2]!, /unhealthy for 60m/,
    "`since` must survive a re-alert, or a long outage always reads as one window old");
});

test("each check is tracked independently", () => {
  const h = harness();
  h.check({ name: "emqx", ok: false, detail: "down" });
  h.check({ name: "postgres", ok: false, detail: "down" });
  h.check({ name: "emqx", ok: true, detail: "up" });
  assert.equal(h.alerts.length, 2, "two different checks, two alerts");
  assert.equal(h.recoveries.length, 1, "…and only the one that recovered");
  assert.equal(h.state.get("postgres")?.ok, false, "postgres is still down");
  assert.equal(h.state.get("emqx")?.ok, true);
});

test("a recovery with no prior failure is not announced", () => {
  const h = harness();
  h.pass();
  assert.deepEqual(h.recoveries, [],
    "announcing a recovery that never happened would make the log lie");
});
