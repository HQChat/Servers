// The Postgres connection, and the two things every caller needs from it: a
// query helper and a sweeper for the expiring tables.
//
// One pool per process, `max` deliberately small. The managed cluster allows 22
// backend connections (db-s-1vcpu-1gb), which is why the services connect through
// a transaction-mode PgBouncer pool — see infra/database/README.md for the
// budget. A transaction-mode pooler hands a backend to a statement rather than to
// a connection, so a small `max` here is not a throughput ceiling; it is what
// keeps five services inside the budget.
//
// Two consequences of the pooler worth knowing before adding a query:
//   - Session state does not survive between statements. No SET, no LISTEN/
//     NOTIFY, no session-level advisory locks. A multi-statement unit of work
//     must be an explicit transaction on ONE client (see `tx` below).
//   - node-postgres does not use named prepared statements by default, so
//     ordinary parameterised queries are fine. Do not add `name:` to a query.

import { Pool, PoolClient, QueryResult, QueryResultRow } from "pg";
import { logger } from "../../lib/logger";
import { tls, withoutSslMode } from "./ssl";

// `max: 3` × five services = 15 client connections, which the 15-backend pool
// absorbs because a transaction-mode pooler hands a backend to a statement
// rather than to a connection. Raise it only alongside `pool_size` in
// infra/database/variables.tf.
const POOL_MAX = Number(process.env.PG_POOL_MAX) || 3;

export const pool = new Pool({
  // See ./ssl.ts for why the URI's own sslmode has to come off before the
  // driver sees it.
  connectionString: withoutSslMode(process.env.DATABASE_URL),
  max: POOL_MAX,
  // A pooled backend that has been idle this long is given back. Keeps a quiet
  // service from holding a scarce connection all night.
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  ssl: tls(),
});

// An idle client erroring (the cluster restarted, the pooler dropped us) emits
// on the pool. Without a listener that is an unhandled 'error' event, which
// takes the process down — exactly the wrong response to a database that is
// coming back in twenty seconds.
pool.on("error", (err) => logger.error(`[pg] idle client: ${err.message}`));

/** Errors that mean "the connection went away", as opposed to "your SQL is
 *  wrong". The cluster is single-node, so its maintenance window IS a restart:
 *  these are expected a few times a year and must not surface as 500s. */
function isTransient(e: unknown): boolean {
  const err = e as { code?: string; message?: string };
  const code = err?.code || "";
  // 57P01 admin_shutdown, 57P02 crash_shutdown, 57P03 cannot_connect_now,
  // 08006 connection_failure, 08003 connection_does_not_exist, 08001, 53300.
  if (/^(57P0[123]|080(01|03|06)|53300)$/.test(code)) return true;
  return /ECONNRESET|ECONNREFUSED|ETIMEDOUT|EPIPE|Connection terminated/i.test(
    err?.message || ""
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * One query. Retries ONCE on a connection-level failure, which turns a failover
 * or a maintenance restart into a slow request instead of an error — the pool
 * will have dialled a fresh backend by the second attempt.
 *
 * Deliberately not a general retry loop: a query that fails twice is either a
 * real outage (where failing fast is honest) or a bug, and retrying a write
 * whose outcome is unknown is worse than reporting it.
 */
export async function q<R extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<QueryResult<R>> {
  try {
    return await pool.query<R>(text, params);
  } catch (e) {
    if (!isTransient(e)) throw e;
    logger.warn(`[pg] transient: ${(e as Error).message} — retrying once`);
    await sleep(250);
    return await pool.query<R>(text, params);
  }
}

/** First row, or null. The shape most of db/api.ts wants. */
export async function one<R extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<R | null> {
  const res = await q<R>(text, params);
  return res.rows[0] ?? null;
}

/**
 * Several statements as one unit, on one client. Needed wherever Redis used a
 * Lua script or a pipeline it was pretending was atomic — and required rather
 * than optional under a transaction-mode pooler, where consecutive `q()` calls
 * may land on different backends.
 *
 * No retry: re-running a half-applied transaction is not obviously safe, and
 * the callers here are all user-facing operations that can be repeated by the
 * user instead.
 */
export async function tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const out = await fn(client);
    await client.query("COMMIT");
    return out;
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* the connection is already gone; the transaction died with it */
    }
    throw e;
  } finally {
    client.release();
  }
}

/** Tables whose rows carry their own lifetime. Redis expired these itself. */
const EXPIRING: Array<[table: string, column: string]> = [
  ["sessions", "expires_at"],
  ["otp", "expires_at"],
  ["auth_challenges", "expires_at"],
  ["mqtt_tokens", "expires_at"],
  ["mqtt_nonces", "expires_at"],
  ["rate_counters", "window_ends_at"],
  // ⚠️ NOT like the others. See the second paragraph below.
  ["reports", "expires_at"],
];

/**
 * Delete what has lapsed.
 *
 * For every table above but the last, this is about reclaiming SPACE rather than
 * correctness: each is read with a filter on its expiry column, so a lapsed row
 * is already invisible and deleting it only returns disk. That is why this can
 * run on a lazy interval from an ops process (ops/broker-watch.ts) instead of
 * needing a job scheduler.
 *
 * ⚠️ `reports` breaks that, and the distinction is worth keeping straight
 * because the comment above used to cover it by accident. A report holds message
 * content, and /privacy and /eula both promise it is deleted after 90 days — so
 * here the DELETE *is* the published commitment, not a space optimisation, and
 * "it is filtered on read anyway" is not true of it either. The operator read
 * path (`DB.listOpenReports`) therefore sweeps lapsed rows ITSELF before
 * reading, so a human cannot be shown an expired report because an ops process
 * was not running. This line is the routine half, not the guarantee.
 *
 * Returns rows removed per table, so the caller can log a number that means
 * something when bloat is the question.
 */
export async function sweepExpired(): Promise<Record<string, number>> {
  const removed: Record<string, number> = {};
  for (const [table, column] of EXPIRING) {
    try {
      // Table and column names are from the literal list above, never from a
      // caller — the only reason interpolation is acceptable here.
      const res = await q(`DELETE FROM ${table} WHERE ${column} <= now()`);
      if (res.rowCount) removed[table] = res.rowCount;
    } catch (e) {
      logger.warn(`[pg] sweep ${table} failed: ${(e as Error).message}`);
    }
  }
  return removed;
}

/** Cheap liveness probe for /health and the diagnostics script. */
export async function ping(): Promise<boolean> {
  const res = await q<{ ok: number }>("SELECT 1 AS ok");
  return res.rows[0]?.ok === 1;
}

export async function disconnect(): Promise<void> {
  await pool.end();
}
