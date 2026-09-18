// Crash early-warning monitor.
//
// The stress-test crash was NOT a hardware ceiling (CPU/mem peaked ~40%). It was
// an unhandled error killing the process. But the class of failures a relay hits
// under load — event-loop starvation, socket/FD leaks, unbounded backpressure,
// listener leaks — all show up as *leading indicators* seconds before the process
// dies or goes unresponsive. This module samples those indicators on a timer,
// compares them to thresholds, and escalates to Sentry BEFORE the crash so you
// get an alert ("coming crash") instead of just a postmortem.
//
// Indicators sampled:
//   - eventLoopLagMs   : perf_hooks event-loop delay (mean + p99). The #1
//                        predictor of a Node process about to stall.
//   - rssMB / heapMB   : process memory vs. the container mem_limit.
//   - wsClients        : live WebSocket connections (socket/FD pressure).
//   - activeHandles    : libuv active resources (leak detection — sockets/timers
//                        that never close climb monotonically before an FD-exhaust
//                        crash).
//   - errorRate/rejRate: errors + unhandled rejections per sample window.
//   - backpressure     : sockets currently over the buffered-bytes soft cap.
//
// Snapshot is exposed via getSnapshot() for the /metrics endpoint and the stress
// test, so the load test can read the SAME numbers the alerting uses and help you
// tune the thresholds.

import { monitorEventLoopDelay, type IntervalHistogram } from "perf_hooks";
import { logger } from "./logger";
import { Sentry, sentryEnabled } from "./observability";
import { queryMetrics, type QuerySnapshot } from "./metrics";

type Status = "ok" | "warn" | "crit";

export interface HealthSnapshot {
  ts: number;
  uptimeSec: number;
  status: Status;
  tripped: string[]; // human-readable rules currently breached
  eventLoopLagMeanMs: number;
  eventLoopLagP99Ms: number;
  rssMB: number;
  heapUsedMB: number;
  heapTotalMB: number;
  wsClients: number;
  wsBackpressured: number; // sockets over the soft buffered-bytes cap
  activeHandles: number;
  messagesPerSec: number;
  errorsPerWindow: number;
  rejectionsPerWindow: number;
  // Backing-store (Postgres) query vitals for the window — see lib/metrics.ts.
  dbQueriesPerSec: number;
  dbP50Ms: number;
  dbP99Ms: number;
  dbMaxMs: number;
  dbSlowPerWindow: number; // queries ≥ DB_SLOW_QUERY_MS
  dbErrorsPerWindow: number;
  dbSlowestOps: QuerySnapshot["slowestOps"]; // top offenders by max latency
}

function envNum(name: string, def: number): number {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : def;
}

// Thresholds (all overridable via env so you can tune from stress-test output).
const T = {
  loopWarnMs: envNum("HEALTH_LOOP_WARN_MS", 100),
  loopCritMs: envNum("HEALTH_LOOP_CRIT_MS", 500),
  rssWarnMB: envNum("HEALTH_RSS_WARN_MB", 700), // container mem_limit is 1g
  rssCritMB: envNum("HEALTH_RSS_CRIT_MB", 900),
  clientsWarn: envNum("HEALTH_CLIENTS_WARN", 4000),
  clientsCrit: envNum("HEALTH_CLIENTS_CRIT", 8000),
  handlesWarn: envNum("HEALTH_HANDLES_WARN", 6000),
  handlesCrit: envNum("HEALTH_HANDLES_CRIT", 12000),
  errWarn: envNum("HEALTH_ERR_WARN", 20), // errors per sample window
  errCrit: envNum("HEALTH_ERR_CRIT", 100),
  backpressureWarn: envNum("HEALTH_BACKPRESSURE_WARN", 10), // sockets over cap
  dbP99WarnMs: envNum("HEALTH_DB_P99_WARN_MS", 150), // query p99 latency
  dbP99CritMs: envNum("HEALTH_DB_P99_CRIT_MS", 500),
  dbSlowWarn: envNum("HEALTH_DB_SLOW_WARN", 20), // slow queries per window
  sampleMs: envNum("HEALTH_SAMPLE_MS", 5000),
  // How long to suppress a repeat Sentry alert for the same status (ms).
  alertCooldownMs: envNum("HEALTH_ALERT_COOLDOWN_MS", 60_000),
};

const BYTES_PER_MB = 1024 * 1024;

interface Wsish {
  clients: { size: number; forEach: (cb: (c: any) => void) => void };
}

class HealthMonitor {
  private hist: IntervalHistogram | null = null;
  private timer: NodeJS.Timeout | null = null;
  private wss: Wsish | null = null;
  private bufferedCap = 1 * BYTES_PER_MB;
  private startedAt = Date.now();

  // Rolling counters, reset each window.
  private errors = 0;
  private rejections = 0;
  private messages = 0;

  private last: HealthSnapshot | null = null;
  private lastAlertAt = 0;
  private lastAlertStatus: Status = "ok";

  /** Call once, from the entrypoint. `bufferedCapBytes` = per-socket soft cap. */
  start(wss?: Wsish, bufferedCapBytes?: number) {
    if (this.timer) return;
    this.wss = wss ?? null;
    if (bufferedCapBytes) this.bufferedCap = bufferedCapBytes;

    // resolution sets the histogram's noise floor: an idle loop reads ~resolution
    // ms, so keep it small for a clean baseline well under the warn threshold.
    this.hist = monitorEventLoopDelay({ resolution: 10 });
    this.hist.enable();

    // Count unhandled rejections toward the rejection-rate indicator (the
    // handler in observability.ts still captures each one to Sentry).
    process.on("unhandledRejection", () => {
      this.rejections++;
    });

    this.timer = setInterval(() => this.sample(), T.sampleMs);
    this.timer.unref?.();
    logger.startup(
      `🩺 health monitor on — sampling every ${T.sampleMs}ms (loop warn ${T.loopWarnMs}/crit ${T.loopCritMs}ms, rss warn ${T.rssWarnMB}/crit ${T.rssCritMB}MB)`
    );
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.hist?.disable();
  }

  noteError() {
    this.errors++;
  }
  noteMessage() {
    this.messages++;
  }

  getSnapshot(): HealthSnapshot | null {
    return this.last;
  }

  getThresholds() {
    return { ...T };
  }

  private countBackpressure(): number {
    if (!this.wss) return 0;
    let n = 0;
    this.wss.clients.forEach((c) => {
      if ((c.bufferedAmount ?? 0) > this.bufferedCap) n++;
    });
    return n;
  }

  private sample() {
    const h = this.hist!;
    const loopMean = h.mean / 1e6; // ns → ms
    const loopP99 = h.percentile(99) / 1e6;
    h.reset();

    const mem = process.memoryUsage();
    const rssMB = mem.rss / BYTES_PER_MB;
    const heapUsedMB = mem.heapUsed / BYTES_PER_MB;
    const heapTotalMB = mem.heapTotal / BYTES_PER_MB;

    const wsClients = this.wss?.clients.size ?? 0;
    const wsBackpressured = this.countBackpressure();
    // getActiveResourcesInfo() (Node 17+) lists live libuv resources — a proxy
    // for FD/handle leaks that precede an "EMFILE / too many open files" crash.
    const activeHandles =
      (process as any).getActiveResourcesInfo?.().length ?? 0;

    const windowSec = T.sampleMs / 1000;
    const messagesPerSec = this.messages / windowSec;
    const errorsPerWindow = this.errors;
    const rejectionsPerWindow = this.rejections;
    this.messages = 0;
    this.errors = 0;
    this.rejections = 0;

    // Backing-store latency for this window (drains + resets the query metrics).
    const db = queryMetrics.drain();
    const dbQueriesPerSec = Math.round(db.count / windowSec);

    // --- Evaluate rules -------------------------------------------------------
    const tripped: string[] = [];
    let status: Status = "ok";
    const bump = (s: Status) => {
      if (s === "crit") status = "crit";
      else if (s === "warn" && status !== "crit") status = "warn";
    };

    if (loopP99 >= T.loopCritMs) {
      tripped.push(`event-loop p99 ${loopP99.toFixed(0)}ms ≥ ${T.loopCritMs}ms (stalling)`);
      bump("crit");
    } else if (loopP99 >= T.loopWarnMs) {
      tripped.push(`event-loop p99 ${loopP99.toFixed(0)}ms ≥ ${T.loopWarnMs}ms`);
      bump("warn");
    }
    if (rssMB >= T.rssCritMB) {
      tripped.push(`rss ${rssMB.toFixed(0)}MB ≥ ${T.rssCritMB}MB (OOM risk)`);
      bump("crit");
    } else if (rssMB >= T.rssWarnMB) {
      tripped.push(`rss ${rssMB.toFixed(0)}MB ≥ ${T.rssWarnMB}MB`);
      bump("warn");
    }
    if (wsClients >= T.clientsCrit) {
      tripped.push(`ws clients ${wsClients} ≥ ${T.clientsCrit}`);
      bump("crit");
    } else if (wsClients >= T.clientsWarn) {
      tripped.push(`ws clients ${wsClients} ≥ ${T.clientsWarn}`);
      bump("warn");
    }
    if (activeHandles >= T.handlesCrit) {
      tripped.push(`active handles ${activeHandles} ≥ ${T.handlesCrit} (leak/FD risk)`);
      bump("crit");
    } else if (activeHandles >= T.handlesWarn) {
      tripped.push(`active handles ${activeHandles} ≥ ${T.handlesWarn}`);
      bump("warn");
    }
    if (errorsPerWindow >= T.errCrit) {
      tripped.push(`errors ${errorsPerWindow}/window ≥ ${T.errCrit} (error storm)`);
      bump("crit");
    } else if (errorsPerWindow >= T.errWarn) {
      tripped.push(`errors ${errorsPerWindow}/window ≥ ${T.errWarn}`);
      bump("warn");
    }
    if (wsBackpressured >= T.backpressureWarn) {
      tripped.push(`${wsBackpressured} sockets backpressured (slow consumers)`);
      bump("warn");
    }
    if (db.p99Ms >= T.dbP99CritMs) {
      tripped.push(`db p99 ${db.p99Ms.toFixed(0)}ms ≥ ${T.dbP99CritMs}ms (store stalling)`);
      bump("crit");
    } else if (db.p99Ms >= T.dbP99WarnMs) {
      tripped.push(`db p99 ${db.p99Ms.toFixed(0)}ms ≥ ${T.dbP99WarnMs}ms`);
      bump("warn");
    }
    if (db.slow >= T.dbSlowWarn) {
      tripped.push(`${db.slow} slow db queries this window`);
      bump("warn");
    }

    const snap: HealthSnapshot = {
      ts: Date.now(),
      uptimeSec: Math.round((Date.now() - this.startedAt) / 1000),
      status,
      tripped,
      eventLoopLagMeanMs: round1(loopMean),
      eventLoopLagP99Ms: round1(loopP99),
      rssMB: Math.round(rssMB),
      heapUsedMB: Math.round(heapUsedMB),
      heapTotalMB: Math.round(heapTotalMB),
      wsClients,
      wsBackpressured,
      activeHandles,
      messagesPerSec: Math.round(messagesPerSec),
      errorsPerWindow,
      rejectionsPerWindow,
      dbQueriesPerSec,
      dbP50Ms: db.p50Ms,
      dbP99Ms: db.p99Ms,
      dbMaxMs: db.maxMs,
      dbSlowPerWindow: db.slow,
      dbErrorsPerWindow: db.errors,
      dbSlowestOps: db.slowestOps,
    };
    this.last = snap;

    // Make vitals explicit on EVERY Sentry event: attach the freshest snapshot
    // as context each sample, so any error/crash carries the process + store
    // vitals from the moment it happened (not just at alert time).
    if (sentryEnabled()) Sentry.setContext("vitals", snap as any);

    this.maybeAlert(snap);
  }

  private maybeAlert(snap: HealthSnapshot) {
    if (snap.status === "ok") {
      this.lastAlertStatus = "ok";
      return;
    }
    const now = Date.now();
    const escalated =
      snap.status === "crit" && this.lastAlertStatus !== "crit";
    const cooledDown = now - this.lastAlertAt >= T.alertCooldownMs;
    if (!escalated && !cooledDown) return;

    this.lastAlertAt = now;
    this.lastAlertStatus = snap.status;

    const line = `🩺 health ${snap.status.toUpperCase()} — ${snap.tripped.join("; ")}`;
    if (snap.status === "crit") logger.error(line);
    else logger.warn(line);

    if (sentryEnabled()) {
      // The "vitals" context is already set fresh each sample (see sample()),
      // so the captured event carries this snapshot without setting it again.
      Sentry.captureMessage(
        `[early-warning] ${line}`,
        snap.status === "crit" ? "error" : "warning"
      );
    }
  }
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

export const healthMonitor = new HealthMonitor();
