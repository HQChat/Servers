// Schema migrations. Deliberately about sixty lines and no dependency.
//
//   docker compose run --rm db-migrate
//   DATABASE_URL_DIRECT=... node --import tsx services/db/migrate.ts
//
// Files in ./migrations are applied in filename order, each in its own
// transaction, and recorded in `schema_migrations`. Applying twice is a no-op.
// Editing a file that has already been applied does nothing — add a new one.
//
// It connects to DATABASE_URL_DIRECT, not DATABASE_URL: DDL belongs on the
// direct endpoint rather than through a transaction-mode pooler, and the
// application role is deliberately not allowed to create tables (000_roles.sql).

import "../../lib/config";
import { Client } from "pg";
import * as fs from "fs";
import * as path from "path";
import { logger } from "../../lib/logger";
import { tls, withoutSslMode } from "./ssl";

const DIR = path.join(__dirname, "migrations");

// The role names differ per environment — `app_prod` / `emqx_prod` on the managed
// cluster, whatever the local container uses elsewhere — so they cannot be
// hardcoded in a .sql file. These two are the only substitutions the runner
// performs, and both default to the connecting user, which is what makes a
// single-superuser container need no setup at all.
function roles(fallback: string) {
  const named = (name: string) => {
    const v = (process.env[name] || fallback).trim();
    // Substituted into a GRANT, where a parameter is not allowed. Everything
    // that reaches this point comes from our own Terraform outputs, but an
    // identifier built by string interpolation gets checked anyway.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) {
      throw new Error(`${name}="${v}" is not a plain SQL identifier`);
    }
    return v;
  };
  return { APP_ROLE: named("APP_ROLE"), EMQX_ROLE: named("EMQX_ROLE") };
}

async function main() {
  const url = process.env.DATABASE_URL_DIRECT || process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL_DIRECT (or DATABASE_URL) is required");

  // TLS policy and the sslmode strip both live in ./ssl.ts, shared with pg.ts
  // so the two cannot disagree about how this stack reaches its database.
  const client = new Client({
    connectionString: withoutSslMode(url),
    ssl: tls(),
  });

  await client.connect();

  // Whoever we connected as is the fallback for both roles, so a local
  // `postgres:17` container with a single superuser needs no extra setup: the
  // grants become no-ops it already has.
  const who = (await client.query<{ u: string }>("SELECT current_user AS u")).rows[0]?.u;
  if (!who) throw new Error("could not resolve current_user");
  const subs = roles(who);

  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name       text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  const applied = new Set(
    (await client.query<{ name: string }>("SELECT name FROM schema_migrations")).rows.map(
      (r) => r.name
    )
  );

  const files = fs.readdirSync(DIR).filter((f) => f.endsWith(".sql")).sort();
  let ran = 0;

  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = fs
      .readFileSync(path.join(DIR, file), "utf8")
      .replace(/\$\{(APP_ROLE|EMQX_ROLE)\}/g, (_, k: keyof typeof subs) => subs[k]);

    logger.startup(`[migrate] applying ${file}`);
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [file]);
      await client.query("COMMIT");
      ran++;
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      throw new Error(`${file}: ${(e as Error).message}`);
    }
  }

  logger.startup(
    ran === 0
      ? `[migrate] up to date (${files.length} migrations)`
      : `[migrate] applied ${ran} of ${files.length}`
  );
  await client.end();
}

main().catch((e) => {
  logger.error(`[migrate] failed: ${(e as Error).message}`);
  process.exit(1);
});
