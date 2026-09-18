// DB-2 guard (security audit 2026-08): `setUsername` must reject any username
// outside `^[a-zA-Z0-9_]+$`.
//
// The original reason was Redis key namespaces — a username containing ':'
// could collide with or escape `user:`, `friends:`, `admission:exempt`. That
// class of bug died with the store: every value now reaches Postgres as a bound
// parameter, so a ':' is just a character. The rule stays because the OTHER
// reason it existed did not go away: a handle carrying whitespace, control
// characters or homoglyphs is an impersonation tool wherever it is displayed.
//
// These cases still need no database. The charset and length checks run BEFORE
// any query, so they throw synchronously.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DB } from "../services/db/api";

const ID = "a".repeat(64); // shape irrelevant — validation trips before any lookup

// Every one of these contains a character outside [A-Za-z0-9_] or violates the
// length bound, so the charset/length guard rejects it before any query runs.
const REJECTED = [
  "evil:user", // ':' — separator in the old key namespaces
  "user:friends:x", // multiple ':' segments
  "admission:exempt", // tries to name an internal namespace
  "has space", // whitespace
  "tab\tuser", // control char
  "new\nline", // control char / injection
  "dash-name", // '-' not permitted
  "dot.name", // '.' not permitted
  "emoji😀", // non-ASCII
  "ab", // too short (< 3)
  "x".repeat(33), // too long (> 32)
  "", // empty
];

for (const name of REJECTED) {
  test(`setUsername rejects ${JSON.stringify(name)}`, async () => {
    await assert.rejects(
      () => DB.setUsername(ID, name),
      /between 3 and 32|letters, numbers, and underscores/,
      `expected ${JSON.stringify(name)} to be rejected by the charset/length guard`
    );
  });
}
