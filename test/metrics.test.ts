import { describe, it } from "node:test";
import assert from "node:assert";
import { queryMetrics } from "../lib/metrics";

describe("queryMetrics", () => {
  it("records durations and computes percentiles + per-op breakdown", async () => {
    queryMetrics.drain(); // clear any prior state

    // Record a spread of latencies across two ops.
    for (let i = 0; i < 100; i++) queryMetrics.record("getUser", i, true);
    queryMetrics.record("getUser", 999, false); // an error + the max
    queryMetrics.record("areFriends", 5, true);

    const snap = queryMetrics.drain();
    assert.strictEqual(snap.count, 102);
    assert.strictEqual(snap.errors, 1);
    assert.strictEqual(snap.maxMs, 999);
    assert.ok(snap.p50Ms > 0 && snap.p50Ms < snap.p99Ms, "p50 < p99");
    // getUser had the largest max, so it leads the slowest-ops list.
    assert.strictEqual(snap.slowestOps[0]?.op, "getUser");
    const areFriends = snap.slowestOps.find((o) => o.op === "areFriends");
    assert.ok(areFriends && areFriends.count === 1);
  });

  it("counts slow queries at/over the threshold", () => {
    queryMetrics.drain();
    const slow = queryMetrics.getSlowThresholdMs();
    queryMetrics.record("flushPending", slow, true); // exactly at threshold = slow
    queryMetrics.record("flushPending", slow - 1, true); // under = fast
    const snap = queryMetrics.drain();
    assert.strictEqual(snap.slow, 1);
  });

  it("drain() resets the window", () => {
    queryMetrics.drain();
    queryMetrics.record("getUser", 10, true);
    assert.strictEqual(queryMetrics.drain().count, 1);
    assert.strictEqual(queryMetrics.drain().count, 0);
  });

  it("time() records even when the op throws", async () => {
    queryMetrics.drain();
    await assert.rejects(
      queryMetrics.time("boom", async () => {
        throw new Error("nope");
      })
    );
    const snap = queryMetrics.drain();
    assert.strictEqual(snap.count, 1);
    assert.strictEqual(snap.errors, 1);
  });
});
