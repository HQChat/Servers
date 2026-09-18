-- 007 — `reports.message_id` accepts the ids clients actually mint.
--
-- The bug, in one line: 006 wrote
--
--   message_id text CHECK (message_id IS NULL OR message_id ~ '^[0-9a-f]{1,128}$')
--
-- and the iOS client mints its ids with `UUID().uuidString`, which is uppercase
-- and contains hyphens. Every report filed with a message id — which is every
-- report filed about a message the reporter can still see — failed with
--
--   new row for relation "reports" violates check constraint "reports_message_id_check"
--
-- and surfaced as a 500 on POST /report. Metadata-only reports were unaffected,
-- which is why this survived review: the test in api-graph.test.ts passed
-- "deadbeef", and a hand-written hex string is the one shape no client sends.
--
-- ============================================================
-- WHY HEX WAS THE WRONG BOUND, NOT JUST A TOO-NARROW ONE
-- ============================================================
-- `message_id` is not ours to describe. It is a copy of the frame's `msgId`,
-- and that field's contract is set by the wire format
-- (apps/apple/DissQus/Services/ConversationEnvelopeV3.swift):
--
--     95  msgIdLen  u8        1..128
--     96  msgId     msgIdLen bytes, UTF-8
--
-- Opaque bytes, bounded at 128, chosen by the sending client. 006 invented a
-- narrower vocabulary for a column whose only job is to equal something another
-- component already defined — so the fix is to mirror that contract rather than
-- to widen the regex to fit today's UUIDs. A client that switches from UUIDs to
-- base64url or ULIDs tomorrow is within the wire format, and must not be a
-- second constraint violation.
--
-- The bound that remains is the bound the envelope itself enforces:
--
--   * 1..128 BYTES, via octet_length — the envelope counts `msgId.utf8.count`,
--     and length() would count characters, which is a different (larger) number
--     for anything outside ASCII and therefore a bound that does not match.
--   * No control characters. Not from the envelope — it permits any UTF-8 — but
--     because this value is printed into an operator's terminal by
--     `npm run reports`, and a msgId carrying an escape sequence is an attacker
--     writing to that terminal. The value is still not TRUSTED after this check
--     (see 006 §0: nothing in a report is verifiable); it is merely no longer
--     able to move a cursor.
--
-- Normalizing instead — lowercasing, stripping hyphens — was the other option
-- and is worse: `message_id` exists to be compared against broker delivery
-- metadata for the same topic, and a value we rewrote on the way in no longer
-- matches the one that crossed the wire. That would turn a 500 into a silently
-- useless column, which is the more expensive bug.
--
-- api/main.ts gains the same bound, so a malformed id is a 400 naming the field
-- rather than a 500 from Postgres. This constraint stays because a route is not
-- the only thing that can write a row — 006 §2's reasoning, unchanged.
--
-- Existing rows: none can violate the new constraint, since every row that
-- exists passed the stricter one. No backfill, and no data is rewritten.
--
-- No BEGIN/COMMIT: migrate.ts wraps each file in its own transaction, and
-- committing early would leave the schema_migrations row outside it.

-- The name is Postgres's own for an unnamed column CHECK (`<table>_<column>_check`),
-- which is why the error message quoted it. IF EXISTS so that a database built
-- after this file is folded into a future squash is not a failure.
ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_message_id_check;

ALTER TABLE reports ADD CONSTRAINT reports_message_id_check
  CHECK (message_id IS NULL
         OR (octet_length(message_id) BETWEEN 1 AND 128
             AND message_id !~ '[[:cntrl:]]'));
