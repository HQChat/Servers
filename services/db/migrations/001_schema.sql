-- Durable tier: what the system would be wrong without. Replicated to any read
-- replica a later region gets; backed up by DigitalOcean's PITR.

-- Case-insensitive text, so `Helper` and `helper` cannot both be claimed.
CREATE EXTENSION IF NOT EXISTS citext;

-- ============================================================
-- 0. WHY NO PUBLIC KEY IS EVER A BTREE KEY
-- ============================================================
-- ⚠️ SUPERSEDED BY 004_identity_by_hash.sql. Migrations are applied in filename
-- order and never edited in place, so everything below still describes what THIS
-- file created — but almost none of those tables exist in that shape any more.
--
-- The essay is worth reading anyway, because 004 is its conclusion. This file
-- worked out that a public key cannot be a btree key and indexed every identity
-- as `pk_digest(pk)` instead, while leaving the 14 kB string as the column, the
-- value the application passes around, and the thing every topic name embeds.
-- That held inside the database and nowhere else: `DELETE /clients/{clientid}`
-- on the broker's admin API built a ~14.5 kB URL and was answered
-- `414 URI Too Long` every single time, so revocation never dropped a live
-- subscription; `/prekeys/claim` capped its `peer` parameter at 128 and refused
-- both real clients; an mqtt_acl row carried a key in `pk` and another inside
-- `topic`, ~29 kB to record one membership bit.
--
-- 004 makes `encode(pk_digest(pk),'hex')` — the value this file was already
-- forced to index on — the identifier everywhere. `pk_digest` itself survives
-- unchanged, and services/server/test/identity.test.ts asserts that it equals
-- the TypeScript and Swift implementations of the same construction.

-- An HQC-256 public key is 7237 bytes (lib/hqc.ts), and it travels as hex: a
-- 14474-character string. A btree index entry may not exceed a third of a page,
-- ~2704 bytes, so `pk text PRIMARY KEY` is not a slow schema -- it is a schema
-- that cannot accept a single real user:
--
--   ERROR: index row requires 14488 bytes, maximum size is 8191
--
-- (The literal error from the first end-to-end run against Postgres. Nothing
-- caught it earlier because CI's `changes` job was failing on every pull
-- request -- paths-filter could not read the file list without
-- `pull-requests: read` -- so e2e was skipped and the PR went green having run
-- nothing. Fixed in .github/workflows/ci.yml alongside this.)
--
-- So keys are indexed two ways, and neither is a btree over the key itself:
--
--   * uniqueness -- a UNIQUE index over pk_digest(pk). Constraints still cannot
--     be raced, which was the whole point of moving off Redis; they are simply
--     enforced over a 32-byte digest instead of a 14 kB string.
--   * lookup -- a HASH index on the raw column. Hash indexes store only the hash
--     code, so they have no size limit, and they serve exactly the `=` that
--     every query here uses. That is what keeps `WHERE pk = $1` untouched in
--     both the application AND in EMQX's authorizer query, which is configured
--     on the broker and does not live in this repo.
--
-- The digest is a function rather than a stored column so that no INSERT has to
-- remember it. `convert_to` is formally STABLE (it reads the server encoding),
-- which an index expression may not be; a database's encoding is fixed when it
-- is created and this one is UTF8, so IMMUTABLE is the truth here.
CREATE OR REPLACE FUNCTION pk_digest(t text) RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
  AS $$ SELECT sha256(convert_to(t, 'UTF8')) $$;

-- ============================================================
-- 1. IDENTITY
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  pk         text NOT NULL,
  -- UNIQUE is the whole point: the Redis version did SISMEMBER then a
  -- non-atomic pipeline, so two simultaneous registrations could both pass the
  -- check and both write. A constraint cannot be raced.
  --
  -- citext also closes a gap the Redis shape had: `username:{u}` was a
  -- case-SENSITIVE key while the reserved-handle blacklist lowercased, so
  -- `Helper` was claimable while `helper` was not.
  username   citext UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  tier       text NOT NULL DEFAULT 'free'
);
CREATE UNIQUE INDEX IF NOT EXISTS users_pk_key      ON users (pk_digest(pk));
CREATE INDEX        IF NOT EXISTS users_pk_hash_idx ON users USING hash (pk);

-- ============================================================
-- 2. SOCIAL GRAPH
-- ============================================================
-- One row per friendship, not two sets plus a blind hash plus a members set.
-- The pair is normalised (pk_lo < pk_hi) so "are these two friends" is a primary
-- key lookup from either direction.
--
-- COLLATE "C" on the CHECK is load-bearing: JavaScript's Array.sort() compares
-- UTF-16 code units, and lib/crypto-utils.ts sorts the pair that way before
-- hashing it. Any other collation and Postgres would disagree with the hash.
CREATE TABLE IF NOT EXISTS friendships (
  pk_lo      text NOT NULL,
  pk_hi      text NOT NULL,
  -- sha256(pk_lo || pk_hi), written by the application. Deliberately NOT a
  -- generated column: friendshipHash() has a Swift counterpart and — as of
  -- 004, and only as of 004 — an actual cross-implementation test vector
  -- (test/helpers/identity-vectors.json). It should keep one definition.
  hash       text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (pk_lo COLLATE "C" < pk_hi COLLATE "C")
);
-- Was PRIMARY KEY (pk_lo, pk_hi) -- see section 0. Still one row per pair, and
-- still answerable from either direction.
CREATE UNIQUE INDEX IF NOT EXISTS friendships_pair_key
  ON friendships (pk_digest(pk_lo), pk_digest(pk_hi));
CREATE INDEX IF NOT EXISTS friendships_pk_lo_idx ON friendships USING hash (pk_lo);
CREATE INDEX IF NOT EXISTS friendships_pk_hi_idx ON friendships USING hash (pk_hi);

-- An invite lives in the recipient's inbox, keyed by the sender — same shape as
-- `invites:{to}` was. The index on from_pk is what replaces deleteUser's SCAN
-- over every inbox in the system.
CREATE TABLE IF NOT EXISTS invites (
  to_pk      text NOT NULL,
  from_pk    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS invites_pair_key
  ON invites (pk_digest(to_pk), pk_digest(from_pk));
CREATE INDEX IF NOT EXISTS invites_to_pk_idx   ON invites USING hash (to_pk);
CREATE INDEX IF NOT EXISTS invites_from_pk_idx ON invites USING hash (from_pk);

-- ============================================================
-- 3. PUSH
-- ============================================================
CREATE TABLE IF NOT EXISTS push_tokens (
  pk         text NOT NULL,
  platform   text NOT NULL DEFAULT 'ios',
  token      text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS push_tokens_pk_key      ON push_tokens (pk_digest(pk));
CREATE INDEX        IF NOT EXISTS push_tokens_pk_hash_idx ON push_tokens USING hash (pk);

-- ============================================================
-- 4. SUBSCRIPTIONS
-- ============================================================
-- A subscription is bought on the website and claimed from the app, joined by an
-- email address this server never stores: it exists here only as
-- H = sha256(lowercased email). A dump of this database says which subscriptions
-- exist, not whose.
CREATE TABLE IF NOT EXISTS subscriptions (
  email_hash  text PRIMARY KEY,
  state       text NOT NULL CHECK (state IN ('waiting', 'active', 'cancelled')),
  customer_id text,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Reverse index, so a Stripe webhook carrying only a customer id resolves
-- without an API call back to Stripe.
CREATE TABLE IF NOT EXISTS subscription_customers (
  customer_id text PRIMARY KEY,
  email_hash  text NOT NULL
);

-- Which device keys have claimed a subscription. Devices are recorded by RAW
-- public key: revoking a lapsed subscriber means editing mqtt_acl and kicking
-- {pk} off the broker, and a blinded key can address neither.
CREATE TABLE IF NOT EXISTS subscription_claims (
  pk         text NOT NULL,
  email_hash text NOT NULL,
  claimed_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS subscription_claims_pk_key
  ON subscription_claims (pk_digest(pk));
CREATE INDEX IF NOT EXISTS subscription_claims_pk_hash_idx
  ON subscription_claims USING hash (pk);
CREATE INDEX IF NOT EXISTS subscription_claims_email_hash_idx
  ON subscription_claims (email_hash);

-- ============================================================
-- 5. ADMISSION
-- ============================================================
-- Self-registered exemptions. The helper bot writes its own pk here at startup,
-- so it is admitted under any policy without an operator hand-copying a key that
-- goes stale whenever the bot's identity changes.
CREATE TABLE IF NOT EXISTS admission_exempt (
  pk text NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS admission_exempt_pk_key
  ON admission_exempt (pk_digest(pk));
CREATE INDEX IF NOT EXISTS admission_exempt_pk_hash_idx
  ON admission_exempt USING hash (pk);

-- ============================================================
-- 6. MQTT AUTHORIZATION
-- ============================================================
-- EMQX reads this directly, once per client-topic per authz-cache window. Kept
-- materialised rather than a view over `friendships` because a view would join
-- on every cache miss.
--
-- The topic name is derivable by anyone who knows both public keys, so
-- authorization rests ENTIRELY on this table — never on topic-name secrecy.
-- `topic` embeds a public key too (`u/{pk}/presence`), so it is no more usable as
-- a btree key than `pk` is: both halves of the pair go through pk_digest. The
-- hash index on `pk` is the one the broker's authorizer uses -- its query is
-- `WHERE pk = $1`, it is configured on EMQX rather than here, and it keeps
-- working unchanged.
CREATE TABLE IF NOT EXISTS mqtt_acl (
  pk     text NOT NULL,
  topic  text NOT NULL,
  action text NOT NULL CHECK (action IN ('publish', 'subscribe', 'all'))
);
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_acl_pk_topic_key
  ON mqtt_acl (pk_digest(pk), pk_digest(topic));
CREATE INDEX IF NOT EXISTS mqtt_acl_pk_hash_idx ON mqtt_acl USING hash (pk);

-- The one table the broker's role may read (see 000_roles.sql).
GRANT SELECT ON mqtt_acl TO ${EMQX_ROLE};

-- Tables created above predate the ALTER DEFAULT PRIVILEGES only when this
-- migration is re-run against an older database; granting explicitly is
-- idempotent and covers both orders.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE};
