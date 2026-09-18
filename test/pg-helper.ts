// Shared probe for the tests that need a real database.
//
// Most of the unit suite deliberately does not — the crypto, the ratchet, the
// scrubber and the username charset guard are all pure — so a developer running
// `npm test` with nothing else installed should get a pass with a few skips,
// not a wall of connection errors or a hang.
//
//   docker compose -f infra/deploy/docker-compose.yml \
//                  -f infra/deploy/docker-compose.local.yml up -d postgres
//   npm run migrate && npm test

import { q, disconnect } from "../services/db/pg";

let checked = false;
let available = false;

/** True when DATABASE_URL points at something that answers, AND the schema has
 *  been migrated into it. An empty database is not "available" for these tests:
 *  it would fail every assertion with a relation-does-not-exist that says
 *  nothing about the code under test. */
export async function pgAvailable(): Promise<boolean> {
  if (checked) return available;
  checked = true;
  try {
    await q("SELECT 1 FROM users LIMIT 1");
    available = true;
  } catch {
    available = false;
  }
  return available;
}

/** Skip reason, so every test spells it the same way. */
export const NEEDS_PG = "needs Postgres (see test/pg-helper.ts)";

/** Close the pool once a file is done, so the test process can exit. */
export async function closePg(): Promise<void> {
  if (available) await disconnect();
}
