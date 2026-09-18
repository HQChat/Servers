-- Identify clients by sha256(pk), not by the public key itself.
--
-- ============================================================
-- 0. WHY THIS EXISTS
-- ============================================================
-- §0 of 001_schema.sql explains at length why no public key may be a btree key:
-- an HQC-256 key is 7237 bytes and travels as 14474 hex characters, past the
-- ~2704-byte limit on a btree entry. Its answer was to index a DIGEST —
-- `pk_digest(pk)` — while leaving the 14 kB string as the column, the value the
-- application passes around, and the thing every topic name embeds.
--
-- That answer held inside the database and nowhere else:
--
--   * `DELETE /clients/{clientid}` built a ~14.5 kB URL, so EMQX answered
--     `414 URI Too Long` to EVERY kick this deployment ever attempted.
--     Authorization is checked at SUBSCRIBE, not per message, so an unfriended
--     peer's open subscription kept delivering after its ACL row was gone —
--     surgical revocation has never once worked here.
--   * `/prekeys/claim` capped `peer` at 128 characters and refused both real
--     clients.
--   * An `mqtt_acl` row carried a key in `pk` AND another inside `topic`:
--     ~29 kB to record one membership bit.
--   * `/friends` shipped 14 kB per friend, every 60 seconds, per client.
--
-- So the identifier becomes the digest that was already there:
--
--     id = sha256( lowercase-hex(pk) )        -- 64 hex characters
--
-- which is EXACTLY `encode(pk_digest(pk), 'hex')`. `pk_digest` is kept, both
-- because it is that definition and because test/identity.test.ts asserts
-- `peerId(pk) = encode(pk_digest(pk),'hex')` against a live database — the
-- three-way check (TypeScript, Swift, SQL) on the one construction every name
-- in the system now depends on.
--
-- Every `USING hash` index goes with the columns it served: at 64 characters an
-- id is a perfectly ordinary btree key, and several tables get a REAL primary
-- key for the first time.
--
-- ============================================================
-- 1. WHY THIS DROPS RATHER THAN BACKFILLS
-- ============================================================
-- A backfill is expressible — `id = encode(pk_digest(pk),'hex')` is a single
-- UPDATE per table — but it would preserve a graph whose members cannot reach
-- each other anyway. The identifier is the MQTT client id and the envelope's
-- `sender`; every shipped client sends the old form, and no version of either
-- side interoperates across the change. Sessions, tokens and challenges are
-- ephemeral by construction; friendships and usernames are the only durable
-- casualties, and both are one screen to recreate.
--
-- Keeping the rows would mean carrying `pk` alongside `id` on every table
-- forever to support a migration nobody can exercise. Users re-register.
--
-- What SURVIVES: `subscriptions`, `subscription_customers` and `otp` are keyed
-- by an email hash and know nothing about keys — a paid subscription outlives
-- this. `subscription_claims` is dropped, so a subscriber re-links their device
-- with the code flow they already know.
--
-- ============================================================
-- 2. WHAT STILL HOLDS A FULL KEY
-- ============================================================
--   users.identity_pk    NEW. The auth challenge encapsulates to it, and
--                        friend-add serves it so an initiator can encapsulate
--                        to a peer. No table stored an account's identity key
--                        before: `users.pk` was identity and key material at
--                        once, and dropping it would have left nothing able to
--                        answer "what key does this id name?".
--   prekeys_*.prekey     key material, by definition.
--
-- Nothing else. An id is a NAME, and a name is 64 characters.

-- ============================================================
-- 3. IDENTITY
-- ============================================================
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
  -- A real btree primary key at last. §0 of 001 could not have one.
  id          text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{64}$'),
  -- The key the id names. Served by GET /peer/{id}/key at friend-add, and used
  -- by the auth server to encapsulate a challenge.
  --
  -- It is NOT a credential and NOT a secret: it is public, and the id is
  -- derivable from it by anyone who holds it. What the CHECK buys is that a
  -- row cannot exist whose `identity_pk` is not the key its `id` commits to —
  -- so a client that verifies a served key against the id it already held
  -- (which every client does) can never be handed a mismatch by accident, only
  -- by a deliberate write.
  --
  -- `pk_digest` deliberately, rather than an inlined sha256: it is the function
  -- 001_schema.sql defined for this exact purpose, and writing the invariant in
  -- terms of it is what keeps "the id is the digest" one definition instead of
  -- two that could drift.
  identity_pk text NOT NULL CHECK (encode(pk_digest(identity_pk), 'hex') = id),
  -- citext, so `Helper` and `helper` cannot both be claimed — the gap the
  -- Redis version had, where the reserved-handle blacklist lowercased and the
  -- key did not.
  username    citext UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  tier        text NOT NULL DEFAULT 'free'
);

-- ============================================================
-- 4. SOCIAL GRAPH
-- ============================================================
DROP TABLE IF EXISTS friendships CASCADE;

CREATE TABLE friendships (
  id_lo      text NOT NULL,
  id_hi      text NOT NULL,
  -- sha256(id_lo || id_hi), written by the application. Deliberately NOT a
  -- generated column: friendshipHash() has a Swift counterpart and — as of this
  -- change, and only as of this change — an actual cross-implementation vector
  -- (test/helpers/identity-vectors.json). It should keep one definition.
  hash       text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- COLLATE "C" is load-bearing: JavaScript's Array.sort() compares UTF-16 code
  -- units and lib/crypto-utils.ts sorts the pair that way before hashing it.
  -- Asserted from both sides in test/identity.test.ts.
  CHECK (id_lo COLLATE "C" < id_hi COLLATE "C"),
  PRIMARY KEY (id_lo, id_hi)
);
-- The pair is normalised, so the primary key answers "are these two friends"
-- from the lo side. This is the index for the hi side, and for "who are my
-- friends" asked by the higher id.
CREATE INDEX friendships_id_hi_idx ON friendships (id_hi);

DROP TABLE IF EXISTS invites CASCADE;

CREATE TABLE invites (
  to_id      text NOT NULL,
  from_id    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (to_id, from_id)
);
-- What replaces deleteUser's SCAN over every inbox: invites this user SENT live
-- in other people's rows, with nothing else pointing back at them.
CREATE INDEX invites_from_id_idx ON invites (from_id);

-- ============================================================
-- 5. PUSH
-- ============================================================
DROP TABLE IF EXISTS push_tokens CASCADE;

CREATE TABLE push_tokens (
  id         text PRIMARY KEY,
  platform   text NOT NULL DEFAULT 'ios',
  token      text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- ============================================================
-- 6. SUBSCRIPTION CLAIMS
-- ============================================================
-- Which device identities have claimed a subscription. Recorded by id, which is
-- what revocation needs: editing `mqtt_acl` and kicking a client off the broker
-- both address an id, and — now that the id fits in a URL — the kick works.
DROP TABLE IF EXISTS subscription_claims CASCADE;

CREATE TABLE subscription_claims (
  id         text PRIMARY KEY,
  email_hash text NOT NULL,
  claimed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX subscription_claims_email_hash_idx ON subscription_claims (email_hash);

-- ============================================================
-- 7. ADMISSION
-- ============================================================
DROP TABLE IF EXISTS admission_exempt CASCADE;

CREATE TABLE admission_exempt (
  id text PRIMARY KEY
);

-- ============================================================
-- 8. MQTT AUTHORIZATION
-- ============================================================
-- EMQX reads this directly, once per client-topic per authz-cache window.
--
-- The column is named `id` because the broker's query is configured on EMQX and
-- names it: `WHERE id = ${clientid}` (infra/deploy/emqx/emqx.conf). Renaming it
-- here without renaming it there produces an authorizer that errors on every
-- lookup, which under `deny_action = disconnect` is every client in a
-- connect/drop loop.
--
-- ⚠️ The authz cache is 15 minutes, so grants cached against the OLD clientids
-- outlive the rollover. Restart EMQX as part of deploying this.
--
-- A row is now ~140 bytes rather than ~29 kB: `id` is 64 characters and `topic`
-- is at most 68 (`u/{64}/presence`).
DROP TABLE IF EXISTS mqtt_acl CASCADE;

CREATE TABLE mqtt_acl (
  id     text NOT NULL,
  topic  text NOT NULL,
  action text NOT NULL CHECK (action IN ('publish', 'subscribe', 'all')),
  -- Was a UNIQUE index over (pk_digest(pk), pk_digest(topic)) because neither
  -- column could be indexed directly. Both fit now.
  PRIMARY KEY (id, topic)
);

-- The one table the broker's role may read (see 000_roles.sql).
GRANT SELECT ON mqtt_acl TO ${EMQX_ROLE};

-- ============================================================
-- 9. PREKEYS
-- ============================================================
-- Still the only tables besides users.identity_pk that hold a full key —
-- `prekey` IS key material. What changes is only who they belong to.
DROP TABLE IF EXISTS prekeys_medium CASCADE;

CREATE TABLE prekeys_medium (
  id         text PRIMARY KEY,
  prekey     text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

DROP TABLE IF EXISTS prekeys_onetime CASCADE;

CREATE TABLE prekeys_onetime (
  -- The account.
  id         text NOT NULL,
  -- The client's own index for the key, echoed back in the `init` frame as
  -- `otId` so the responder knows which secret to decapsulate with. Unique per
  -- account, not globally. Renamed from `id` — that name is the account's now,
  -- and two different things called `id` in one table is how a WHERE clause
  -- ends up matching the wrong one.
  key_id     integer NOT NULL,
  prekey     text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id, key_id)
);

-- ============================================================
-- 10. EPHEMERAL TIER (see 002_ephemeral.sql for why UNLOGGED)
-- ============================================================
DROP TABLE IF EXISTS sessions CASCADE;

CREATE UNLOGGED TABLE sessions (
  token_hash text PRIMARY KEY,
  id         text NOT NULL,
  scope      text NOT NULL CHECK (scope IN ('free', 'premium')),
  -- `iat` enforces the absolute cap; `expires_at` is the sliding idle timeout.
  iat        timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_id_idx ON sessions (id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

DROP TABLE IF EXISTS rate_counters CASCADE;

-- `key` used to be unindexable: auth/main.ts counts per identity, so
-- `init:pk:{hex}` carried a whole 14 kB key. It carries an id now, so the key
-- IS the primary key.
CREATE UNLOGGED TABLE rate_counters (
  key            text PRIMARY KEY,
  n              integer NOT NULL DEFAULT 0,
  window_ends_at timestamptz NOT NULL
);
CREATE INDEX rate_counters_window_ends_at_idx ON rate_counters (window_ends_at);

DROP TABLE IF EXISTS auth_challenges CASCADE;

CREATE UNLOGGED TABLE auth_challenges (
  id         text PRIMARY KEY,
  proof      text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX auth_challenges_expires_at_idx ON auth_challenges (expires_at);

DROP TABLE IF EXISTS mqtt_tokens CASCADE;

CREATE UNLOGGED TABLE mqtt_tokens (
  id         text PRIMARY KEY,
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX mqtt_tokens_expires_at_idx ON mqtt_tokens (expires_at);

-- `otp` and `mqtt_nonces` are untouched: neither has ever been keyed by an
-- identity, and neither needs to be.

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE};
