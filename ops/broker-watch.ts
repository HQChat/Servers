// Broker/infra watchdog (see deploy/EXTRACTION_PLAN.md, deploy/emqx/acl-notes.md).
//
// WHY THIS EXISTS. Every Node service reports itself to Sentry (lib/observability
// .ts) — but two things in the stack are NOT Node and reported NOTHING:
//
//   1. EMQX's own state. The broker keeps its own HTTP link to the auth server,
//      which can be flat on its back while every app service is healthy — and
//      then NOBODY connects. And its authorization is a static file plus one
//      setting, `mqtt.wildcard_subscription = false`, that the whole ACL rests
//      on: acl.conf allows `cv/+` to everyone because a conversation id is a
//      secret, so a broker that booted with wildcards ON — a config edit, a
//      lost mount, the image's stock defaults — lets any client subscribe to
//      `cv/#` and read every conversation. Nothing else would ever notice.
//   2. Postgres itself. Services log their own client errors, but a database
//      that is up yet not answering (a maintenance restart, a saturated
//      connection pool, credentials that drifted) shows up as scattered noise
//      across five services rather than as one alert.
//
// So: poll, hold the last state, and escalate TRANSITIONS to Sentry via
// logger.error (which the Sentry sink turns into an event). Steady-state healthy
// is silent; a stuck failure re-alerts every BROKER_WATCH_REALERT_MS so it can't
// be forgotten.

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import "../lib/config";
import { initObservability } from "../lib/observability";
import { logger } from "../lib/logger";
import { healthMonitor } from "../lib/health-monitor";
import * as http from "http";
import { ping, sweepExpired } from "../services/db/pg";
import { emqxApi, emqxApiConfigured, resetEmqxApiToken } from "../lib/emqx-api";
import { listenOn, parseHosts } from "../lib/listen";

const PORT = Number(process.env.PORT || 8080);
const INTERVAL_MS = Number(process.env.BROKER_WATCH_INTERVAL_MS || 30_000);
const REALERT_MS = Number(process.env.BROKER_WATCH_REALERT_MS || 30 * 60_000);
export interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

// --- EMQX admin API ------------------------------------------------------------
// API key when configured, else the dashboard login (lib/emqx-api.ts).

/** Drop the cached dashboard token. Exported for tests. */
export function resetApiToken(): void {
  resetEmqxApiToken();
}

/** GET an API path. */
async function api<T>(path: string): Promise<T> {
  const res = await emqxApi("GET", path);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return (await res.json()) as T;
}

/**
 * Healthy = enabled, and (for the sources that hold a CONNECTION) connected.
 * EMQX only reports `status` for connector-backed sources; the built-in file
 * authorizer and the built-in authn mechanisms have none, and a missing status
 * must not read as an outage.
 */
export function linkOk(x: { enable?: boolean; status?: string }): boolean {
  if (x.enable === false) return false;
  return x.status === undefined || x.status === "connected";
}

/** EMQX reports per-node errors on a source; flatten them into one line. */
export function nodeErrors(x: { node_error?: unknown[] }): string {
  const errs = x.node_error || [];
  if (!errs.length) return "";
  return ` — ${errs.map((e) => (typeof e === "string" ? e : JSON.stringify(e))).join("; ").slice(0, 300)}`;
}

/** One check that cannot take the others down with it: an API path this EMQX
 *  version does not serve is a failing check, not an exception out of the poll. */
async function probe(name: string, fn: () => Promise<{ ok: boolean; detail: string }>): Promise<Check> {
  try {
    return { name, ...(await fn()) };
  } catch (e) {
    return { name, ok: false, detail: (e as Error).message };
  }
}

export async function checkEmqx(): Promise<Check[]> {
  const out: Check[] = [];

  type Node = { node: string; node_status: string; connections: number };
  const nodes = await api<Node[]>("nodes");
  for (const n of nodes) {
    out.push({
      name: `emqx.node.${n.node}`,
      ok: n.node_status === "running",
      detail: `${n.node_status}, ${n.connections} connections`,
    });
  }

  // Authentication chain — if this breaks, NOBODY can connect.
  type Authn = { mechanism?: string; backend?: string; enable?: boolean; status?: string; node_error?: unknown[] };
  const authn = await api<Authn[]>("authentication");
  if (!authn.length) {
    // No authenticator at all = EMQX admits every CONNECT. Never intended here.
    out.push({ name: "emqx.authn", ok: false, detail: "no authenticator configured — the broker is admitting everyone" });
  }
  for (const a of authn) {
    const id = [a.mechanism, a.backend].filter(Boolean).join(":") || "authn";
    out.push({
      name: `emqx.authn.${id}`,
      ok: linkOk(a),
      detail: `status=${a.status ?? "n/a"} enable=${a.enable}${nodeErrors(a)}`,
    });
  }

  // Authorization sources — the static file ACL (infra/deploy/emqx/acl.conf).
  //
  // This one is NOT shaped like /authentication above, which really does answer
  // with a bare array. `GET /authorization/sources` wraps it:
  //
  //   sources(get, _) -> ... {200, #{sources => Sources}};
  //     -- emqx_authz_api_sources.erl, v5.8.6, the version this stack pins
  //
  // Reading it as an array threw `authz is not iterable` on every poll, so the
  // one check that exists to notice a broken topic ACL never once reported on
  // it -- it failed before it could look.
  type Authz = { type?: string; enable?: boolean; status?: string; node_error?: unknown[] };
  const { sources: authz = [] } = await api<{ sources?: Authz[] }>("authorization/sources");
  if (!authz.length) {
    out.push({ name: "emqx.authz", ok: false, detail: "no authorization source configured — the topic ACL is not enforced" });
  } else if (!authz.some((s) => s.type === "file" && s.enable !== false)) {
    out.push({ name: "emqx.authz", ok: false, detail: "the static file ACL is not loaded — acl.conf is not what is being enforced" });
  }
  for (const s of authz) {
    out.push({
      name: `emqx.authz.${s.type || "source"}`,
      ok: linkOk(s),
      detail: `status=${s.status ?? "n/a"} enable=${s.enable}${nodeErrors(s)}`,
    });
  }

  // What happens to a topic nothing allows. `allow` would make every rule in
  // acl.conf moot.
  out.push(await probe("emqx.authz.no_match", async () => {
    const { no_match } = await api<{ no_match?: string }>("authorization/settings");
    return { ok: no_match === "deny", detail: `no_match=${no_match ?? "n/a"}` };
  }));

  // The setting the ACL rests on. See this file's header.
  out.push(await probe("emqx.wildcard_subscription", async () => {
    const zone = await api<{ mqtt?: { wildcard_subscription?: boolean } }>("configs/global_zone");
    const on = zone.mqtt?.wildcard_subscription;
    return {
      ok: on === false,
      detail: on === false
        ? "off for clients"
        : `wildcard_subscription=${on} — any client can subscribe to cv/# and read every conversation`,
    };
  }));

  return out;
}

// --- Postgres ----------------------------------------------------------------
export async function checkPostgres(): Promise<Check> {
  const t0 = Date.now();
  try {
    const ok = await ping();
    return { name: "postgres.ping", ok, detail: `SELECT 1 in ${Date.now() - t0}ms` };
  } catch (e) {
    return { name: "postgres.ping", ok: false, detail: (e as Error).message };
  }
}

// --- Expiry sweeper ----------------------------------------------------------
// Redis expired its own keys; Postgres does not, so somebody has to delete the
// lapsed sessions, nonces, codes and counters. It lives here rather than in a
// container of its own because this is already the always-on ops process, and
// because the work is unrelated to any request: every read filters on
// `expires_at` regardless, so a late sweep costs disk, never correctness.
const SWEEP_MS = Number(process.env.PG_SWEEP_INTERVAL_MS || 5 * 60_000);

export async function sweep(): Promise<void> {
  try {
    const removed = await sweepExpired();
    const total = Object.values(removed).reduce((a, b) => a + b, 0);
    if (total) logger.debug(`[broker-watch] swept ${total} expired rows: ${JSON.stringify(removed)}`);
  } catch (e) {
    logger.warn(`[broker-watch] sweep failed: ${(e as Error).message}`);
  }
}

// --- Alerting ----------------------------------------------------------------
//
// Only transitions (and stuck failures) reach Sentry; steady state is silent.
//
// SEPARATED SO IT CAN BE TESTED, with the clock and the sink injected. This is a
// state machine whose two failure modes are both invisible from inside the
// process: alert on every tick and the channel becomes noise nobody reads, alert
// only once and a fault that persists for a day looks like it was handled. It
// ran on `Date.now()` and the module-scope logger inside a file that connected
// to EMQX at import, so neither could be reached.
export interface Escalator {
  escalate(c: Check): void;
  /** Exposed for the health endpoint and for assertions. */
  state: Map<string, { ok: boolean; since: number; lastAlertAt: number }>;
}

export interface EscalatorSink {
  /** logger.error → a Sentry event (lib/logger.ts sink). */
  alert(message: string): void;
  recovered(message: string): void;
}

export function createEscalator(
  opts: { realertMs: number; now?: () => number; sink?: EscalatorSink },
): Escalator {
  const now = opts.now ?? (() => Date.now());
  const sink = opts.sink ?? {
    alert: (m) => logger.error(m),
    recovered: (m) => logger.startup(m),
  };
  const state = new Map<string, { ok: boolean; since: number; lastAlertAt: number }>();

  function escalate(c: Check): void {
    const t = now();
    const prev = state.get(c.name);

    if (!c.ok) {
      const firstFailure = !prev || prev.ok;
      const stale = prev && !prev.ok && t - prev.lastAlertAt >= opts.realertMs;
      if (firstFailure || stale) {
        const forMs = prev && !prev.ok ? t - prev.since : 0;
        const forStr = forMs ? ` (unhealthy for ${Math.round(forMs / 60_000)}m)` : "";
        sink.alert(`🚨 [broker-watch] ${c.name} unhealthy${forStr}: ${c.detail}`);
        state.set(c.name, { ok: false, since: prev && !prev.ok ? prev.since : t, lastAlertAt: t });
        return;
      }
      state.set(c.name, { ok: false, since: prev?.since ?? t, lastAlertAt: prev?.lastAlertAt ?? t });
      return;
    }

    if (prev && !prev.ok) {
      sink.recovered(`✅ [broker-watch] ${c.name} recovered after ${Math.round((t - prev.since) / 60_000)}m: ${c.detail}`);
    }
    state.set(c.name, { ok: true, since: prev?.ok ? prev.since : t, lastAlertAt: 0 });
  }

  return { escalate, state };
}

const escalator = createEscalator({ realertMs: REALERT_MS });
const escalate = (c: Check) => escalator.escalate(c);

let lastRun: { ts: number; checks: Check[] } = { ts: 0, checks: [] };

/** What the last poll found. Exported so a test can assert that the status
 *  endpoint reports the tick's result rather than a shape of its own. */
export function lastChecks(): Check[] {
  return lastRun.checks;
}

export async function tick(): Promise<void> {
  const checks: Check[] = [await checkPostgres()];
  try {
    checks.push(...(await checkEmqx()));
  } catch (e) {
    // The API itself is unreachable/unauthorised — that IS the alert.
    resetEmqxApiToken();
    checks.push({ name: "emqx.api", ok: false, detail: (e as Error).message });
  }
  for (const c of checks) escalate(c);
  lastRun = { ts: Date.now(), checks };
}

// --- Health endpoint (compose healthcheck + a human-readable status) ----------
export function createStatusHandler(): http.RequestListener {
  return (req, res) => {
    if (req.method === "GET" && (req.url === "/health" || req.url === "/status")) {
      const unhealthy = lastRun.checks.filter((c) => !c.ok);
      res.writeHead(200, { "content-type": "application/json" });
      // 200 even when a dependency is down: this process is fine, and flapping
      // its own container on a broker blip would take the watchdog off the air.
      return res.end(
        JSON.stringify({
          ok: true,
          service: "broker-watch",
          lastRunAgoMs: lastRun.ts ? Date.now() - lastRun.ts : null,
          unhealthy: unhealthy.map((c) => `${c.name}: ${c.detail}`),
          checks: lastRun.checks,
        })
      );
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  };
}

// --- Boot -------------------------------------------------------------------
//
// Only when this file is the process entry point. Imported, it opens no port,
// starts no timers and talks to no broker.
if (require.main === module) {
  initObservability("broker-watch");

  listenOn(() => http.createServer(createStatusHandler()), PORT, parseHosts(process.env.LISTEN_HOST),
    (host) => logger.startup(`🛎️  broker-watch health on ${host}:${PORT} — polling every ${INTERVAL_MS}ms`));

  if (!emqxApiConfigured()) {
    logger.error("[broker-watch] no EMQX API credential (EMQX_API_KEY/SECRET or EMQX_DASHBOARD_PASSWORD) — cannot query the broker API");
  }

  // Event-loop/memory early warning for this process too.
  healthMonitor.start();

  void tick();
  setInterval(() => void tick(), INTERVAL_MS).unref?.();

  void sweep();
  setInterval(() => void sweep(), SWEEP_MS).unref?.();
}
