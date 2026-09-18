// Query/operation timing — the "vitals" for I/O the relay does on behalf of a
// request. The health monitor already tracks *process* vitals (event-loop lag,
// rss, handles); this adds the missing half: how long the backing store (Postgres)
// actually takes, which is the usual hidden cause of event-loop stalls and slow
// message delivery.
//
// WHAT IT GIVES YOU:
//   - per-window counts + p50/p99/max latency across all DB ops, surfaced in the
//     health snapshot and /metrics next to the process vitals;
//   - a per-op breakdown (slowest operations) so a regression points at the
//     specific call, not just "the DB is slow";
//   - a Sentry breadcrumb for every slow query, so an error event carries a
//     replay of the slow I/O that led up to it. Op names are static method names
//     (getUser, areFriends, …) — never arguments — so no key/username/pk leaks.
//
// Wired in two places: services/db/api.ts wraps every DB method through
// `queryMetrics.time()` via a Proxy; lib/health-monitor.ts drains a window each
// sample and folds the numbers into its snapshot + Sentry "vitals" context.

import { performance } from "perf_hooks";
import { Sentry, sentryEnabled } from "./observability";

function envNum(name: string, def: number): number {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : def;
}

// A query at/over this many ms is "slow" — counted and breadcrumbed.
const SLOW_MS = envNum("DB_SLOW_QUERY_MS", 100);

interface OpAgg {
  count: number;
  totalMs: number;
  maxMs: number;
  slow: number;
  errors: number;
}

export interface QuerySnapshot {
  count: number; // ops in the window
  errors: number; // ops that threw
  slow: number; // ops ≥ SLOW_MS
  p50Ms: number;
  p99Ms: number;
  maxMs: number;
  slowestOps: Array<{ op: string; count: number; avgMs: number; maxMs: number; slow: number }>;
}

class QueryMetrics {
  // Reservoir of per-op durations for the current window, bounded so a burst
  // can't grow this without limit. Percentiles are computed off this on drain.
  private durations: number[] = [];
  private readonly cap = 4000;
  private byOp = new Map<string, OpAgg>();
  private count = 0;
  private errors = 0;
  private slow = 0;

  /** Record one completed op. `ok=false` means it threw. */
  record(op: string, ms: number, ok: boolean): void {
    this.count++;
    if (!ok) this.errors++;
    if (this.durations.length < this.cap) this.durations.push(ms);

    let a = this.byOp.get(op);
    if (!a) {
      a = { count: 0, totalMs: 0, maxMs: 0, slow: 0, errors: 0 };
      this.byOp.set(op, a);
    }
    a.count++;
    a.totalMs += ms;
    if (ms > a.maxMs) a.maxMs = ms;
    if (!ok) a.errors++;

    if (ms >= SLOW_MS) {
      a.slow++;
      this.slow++;
      // Replay trail: a slow query is a leading indicator, so leave a crumb.
      if (sentryEnabled()) {
        Sentry.addBreadcrumb({
          category: "db",
          level: ok ? "warning" : "error",
          message: `slow query ${op} ${ms.toFixed(0)}ms${ok ? "" : " (failed)"}`,
          data: { op, ms: Math.round(ms), ok },
        });
      }
    }
  }

  /** Time an async op and record its duration (even if it throws). */
  async time<T>(op: string, fn: () => Promise<T>): Promise<T> {
    const start = performance.now();
    let ok = true;
    try {
      return await fn();
    } catch (e) {
      ok = false;
      throw e;
    } finally {
      this.record(op, performance.now() - start, ok);
    }
  }

  /** Snapshot the current window and reset it (windowed, like the other vitals). */
  drain(): QuerySnapshot {
    const d = this.durations;
    const sorted = d.length ? [...d].sort((a, b) => a - b) : [];
    const pct = (p: number): number => {
      if (!sorted.length) return 0;
      const i = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
      return sorted[i] ?? 0;
    };

    const slowestOps = [...this.byOp.entries()]
      .map(([op, a]) => ({
        op,
        count: a.count,
        avgMs: round1(a.totalMs / a.count),
        maxMs: round1(a.maxMs),
        slow: a.slow,
      }))
      .sort((x, y) => y.maxMs - x.maxMs)
      .slice(0, 5);

    const snap: QuerySnapshot = {
      count: this.count,
      errors: this.errors,
      slow: this.slow,
      p50Ms: round1(pct(50)),
      p99Ms: round1(pct(99)),
      maxMs: round1(sorted.length ? (sorted[sorted.length - 1] ?? 0) : 0),
      slowestOps,
    };

    this.durations = [];
    this.byOp.clear();
    this.count = 0;
    this.errors = 0;
    this.slow = 0;
    return snap;
  }

  getSlowThresholdMs(): number {
    return SLOW_MS;
  }
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

export const queryMetrics = new QueryMetrics();
