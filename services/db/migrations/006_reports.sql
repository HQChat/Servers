-- 006 — the first server-side moderation state: reports, and blocks.
--
-- App Store Guideline 1.2 asks a user-generated-content app for four things at
-- once: a EULA the user accepts, a way to report content, a way to block a
-- person, and a contact point that answers. Two of the four are server state,
-- and this file is both of them.
--
-- ============================================================
-- 0. WHY `reports` IS THE FIRST TABLE HERE THAT HOLDS A MESSAGE
-- ============================================================
-- Everything else in this schema is a name, a grant, or a public key. Message
-- content has never been on this server in any form, and /privacy says so in
-- those words. A report is the deliberate, consented exception: the reporter
-- asks us to look at something, and a report with nothing to look at is a
-- complaint, not a report.
--
-- So `message_excerpt` is the REPORTER'S OWN COPY, uploaded because they chose
-- to upload it, and it is worth being exact about what that is and is not:
--
--   * It is NOT verifiable. The excerpt is plaintext the reporting client typed
--     into the request. A reporter can fabricate it perfectly, and nothing in
--     this schema or anywhere else can tell a real excerpt from an invented one.
--   * `message_frame` does not fix that. The AEAD tag on a conversation frame is
--     computed under a ratchet key the REPORTER holds, so a reporter can mint a
--     well-formed frame saying anything they like. What the frame buys is a
--     CONSISTENCY CHECK, not an attestation: its header (`v`, `sender`, `to`,
--     `msgId`, `cid`) can be pinned against what the broker actually delivered on
--     `c/{conversation_hash}`. A fabrication that never crossed the wire fails
--     that check. A fabrication swapped for a message that did is not detectable.
--
-- Every sentence the product says about this has to match those two bullets.
-- Implying verification would be the single dishonest sentence in the feature.
--
-- ============================================================
-- 1. RETENTION — TIME-BOUNDED, NOT IDENTITY-BOUNDED
-- ============================================================
-- The obvious rule is that a report dies with the account it names, and it is
-- wrong: it makes "delete my account" the abuse-evasion button. Delete, the
-- reports against you vanish, re-register.
--
-- The opposite rule — reports are forever — contradicts /privacy, which promises
-- that deleting an account purges its server-side footprint, and which is the
-- App Store's 5.1.1(v) evidence.
--
-- The rule here is neither. A report expires 90 days after it is filed, and
-- account deletion neither shortens nor extends that. What deletion does do is
-- `UPDATE reports SET reporter_id = NULL` — the person who FILED it is server
-- footprint and goes — while the report itself stands, because a message you
-- chose to send to someone else, who then handed it in, is on the far side of
-- "your footprint". `blocks` rows go with the account entirely; they are one
-- person's preference about their own inbox and nobody else's record.
--
-- ⚠️ `reported_id` is deliberately NOT nulled and NOT hashed. A moderation
-- record whose subject is unreadable is a row, not a record. It expires in 90
-- days like everything else here.
--
-- ⚠️ The honest limit, which belongs in the runbook and not only in a comment:
-- an id is sha256(public key), so a reinstall mints a new one. A ban cannot
-- follow a person across re-creation on this architecture AT ALL. What these
-- rows support is seeing a pattern and acting on a live identity, which is what
-- `admission_exempt` + ADMISSION_POLICY and the eject path are for.
--
-- ⚠️ The expiry sweep in services/db/pg.ts describes itself as being about
-- reclaiming space rather than correctness, because every other expiring table
-- is filtered on read. That is FALSE for this one: here the deletion IS the
-- published promise. pg.ts's comment is amended alongside this migration, and
-- the operator read path deletes lapsed rows itself rather than trusting an ops
-- process to have run.
--
-- No BEGIN/COMMIT: migrate.ts wraps each file in its own transaction, and
-- committing early would leave the schema_migrations row outside it.

-- ============================================================
-- 2. REPORTS
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

  -- NULL once the reporter deletes their account (section 1). The column stays
  -- because "who filed this" is worth having for the 90 days it exists: a queue
  -- where one id filed forty reports in an hour is a different queue.
  reporter_id     text,
  -- The account the report is ABOUT. Not null, not nulled, not hashed.
  reported_id     text        NOT NULL CHECK (reported_id ~ '^[0-9a-f]{64}$'),

  -- friendships.hash — sha256(id_lo || id_hi). Deliberately not a foreign key:
  -- the friendship is routinely gone by the time an operator reads the row,
  -- because reporting someone and blocking them is one gesture, and blocking
  -- tears the friendship down. It is here to name the topic (`c/{hash}`) the
  -- frame should have crossed.
  conversation_hash text      NOT NULL CHECK (conversation_hash ~ '^[0-9a-f]{64}$'),

  -- A fixed vocabulary rather than free text, so the queue can be sorted by it
  -- and so the client cannot invent a category the runbook has no procedure for.
  category        text        NOT NULL
                              CHECK (category IN ('spam', 'harassment', 'sexual',
                                                  'violence', 'csae', 'other')),
  -- What the reporter typed. Bounded here as well as at the API, because a
  -- CHECK is the one bound that holds no matter which caller writes the row.
  reporter_note   text        CHECK (reporter_note IS NULL OR length(reporter_note) <= 2000),

  -- The reporter's own plaintext copy, by consent. Unverifiable — see section 0.
  message_excerpt text        CHECK (message_excerpt IS NULL OR length(message_excerpt) <= 4000),
  -- The sealed frame, when the reporting client still holds it. Nullable on
  -- purpose and from day one: the iOS client does not retain wire frames today
  -- (ConversationRouter decrypts and drops them), so the first shipped version
  -- of this feature files metadata-only reports. The column exists now so that
  -- retention can land later without a migration.
  message_frame   bytea       CHECK (message_frame IS NULL OR length(message_frame) <= 262144),
  -- The frame's message id, which is what pins a report to broker delivery
  -- metadata for the same topic. Present even when `message_frame` is not.
  message_id      text        CHECK (message_id IS NULL OR message_id ~ '^[0-9a-f]{1,128}$'),

  created_at      timestamptz NOT NULL DEFAULT now(),
  -- 90 days, set by the default rather than by the caller so that no code path
  -- can file a report that outlives the promise.
  expires_at      timestamptz NOT NULL DEFAULT now() + interval '90 days',

  -- The operator side. `handled_at` is the 24h clock the runbook commits to.
  handled_at      timestamptz,
  disposition     text        CHECK (disposition IS NULL OR
                                     disposition IN ('no-action', 'warned', 'ejected', 'banned')),
  CHECK (reporter_id IS NULL OR reporter_id ~ '^[0-9a-f]{64}$'),
  -- Reporting yourself is refused at the API too; this is the bound that holds
  -- regardless of caller.
  CHECK (reporter_id IS NULL OR reporter_id <> reported_id)
);

-- The operator queue: oldest unhandled first.
CREATE INDEX IF NOT EXISTS reports_open_idx ON reports (created_at) WHERE handled_at IS NULL;
-- "how many times has this account been reported" — the only question these rows
-- answer that one report cannot.
CREATE INDEX IF NOT EXISTS reports_reported_id_idx ON reports (reported_id);
-- The sweep.
CREATE INDEX IF NOT EXISTS reports_expires_at_idx ON reports (expires_at);

-- ============================================================
-- 3. BLOCKS
-- ============================================================
-- A block is `/friends/remove` PLUS a row that survives the friendship being
-- deleted. Without the row the blocked party re-invites and the block has
-- evaporated, which is the ordinary way this feature is got wrong.
--
-- Its own table rather than a column on `friendships` for exactly that reason:
-- the friendship row is deleted by the block itself, so a column on it would be
-- deleted by the operation it is meant to outlive.
CREATE TABLE IF NOT EXISTS blocks (
  blocker_id text        NOT NULL CHECK (blocker_id ~ '^[0-9a-f]{64}$'),
  blocked_id text        NOT NULL CHECK (blocked_id ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (blocker_id <> blocked_id),
  PRIMARY KEY (blocker_id, blocked_id)
);
-- The primary key answers "who have I blocked". This answers the question the
-- invite path actually asks, which is the other direction: "has this person
-- blocked me". Both directions refuse an invite — a block is not a one-way
-- filter that the blocked party can talk through.
CREATE INDEX IF NOT EXISTS blocks_blocked_id_idx ON blocks (blocked_id);

-- The app role is granted per-table, not per-schema-default, so a new table is
-- invisible to it until this runs. 004 and 005 end with the same line for the
-- same reason.
GRANT SELECT, INSERT, UPDATE, DELETE ON reports TO ${APP_ROLE};
GRANT SELECT, INSERT, UPDATE, DELETE ON blocks  TO ${APP_ROLE};
