-- Ephemeral tier: state that is safe to lose.
--
-- Every table here is UNLOGGED. That means no WAL — which is what keeps the
-- hottest writes in the system (session sliding, rate counters) from costing
-- what a durable write costs — and it means Postgres TRUNCATES them on crash
-- recovery. That is exactly the durability these want: a rate counter or an idle
-- timeout that survives a crash is not more correct, just staler. The worst case
-- is that everyone re-handshakes.
--
-- Redis expressed lifetime as a TTL on the key. Here it is an `expires_at`
-- column: every read filters on it, and sweepExpired() (db/pg.ts, called from
-- ops/broker-watch.ts) deletes what has lapsed. If these ever accumulate enough
-- dead tuples to bother autovacuum, the escape hatch is hourly partitioning and
-- DROP PARTITION instead of DELETE — not needed at this size.

-- ============================================================
-- REST session bearers
-- ============================================================
-- Stored by sha256(token), NOT by the token itself as `session:{token}` was.
-- A dump of this table no longer hands over live bearers.
CREATE UNLOGGED TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  pk         text NOT NULL,
  scope      text NOT NULL CHECK (scope IN ('free', 'premium')),
  -- `iat` enforces the absolute cap; `expires_at` is the sliding idle timeout.
  iat        timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
-- revokeAllSessions(pk) — logout, account deletion, a lapsed subscription.
CREATE INDEX IF NOT EXISTS sessions_pk_idx ON sessions USING hash (pk);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

-- ============================================================
-- Fixed-window rate counters
-- ============================================================
-- `key` is not always short: auth/main.ts counts per public key, so
-- `init:pk:{hex}` and `verify:fail:{hex}` carry a whole 14 kB key. Same
-- treatment as the identity tables (001, section 0).
CREATE UNLOGGED TABLE IF NOT EXISTS rate_counters (
  key             text NOT NULL,
  n               integer NOT NULL DEFAULT 0,
  window_ends_at  timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS rate_counters_key_key
  ON rate_counters (pk_digest(key));
CREATE INDEX IF NOT EXISTS rate_counters_key_hash_idx
  ON rate_counters USING hash (key);
CREATE INDEX IF NOT EXISTS rate_counters_window_ends_at_idx
  ON rate_counters (window_ends_at);

-- ============================================================
-- Subscription claim codes
-- ============================================================
-- The HASH of a pending OTP, peppered. One live code per address: a resend
-- replaces the previous one rather than leaving two valid at once.
CREATE UNLOGGED TABLE IF NOT EXISTS otp (
  email_hash text PRIMARY KEY,
  code_hash  text NOT NULL,
  attempts   integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS otp_expires_at_idx ON otp (expires_at);

-- ============================================================
-- HQC-KEM handshake challenges
-- ============================================================
CREATE UNLOGGED TABLE IF NOT EXISTS auth_challenges (
  pk         text NOT NULL,
  proof      text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS auth_challenges_pk_key
  ON auth_challenges (pk_digest(pk));
CREATE INDEX IF NOT EXISTS auth_challenges_pk_hash_idx
  ON auth_challenges USING hash (pk);
CREATE INDEX IF NOT EXISTS auth_challenges_expires_at_idx
  ON auth_challenges (expires_at);

-- ============================================================
-- MQTT connect credentials
-- ============================================================
-- The opaque connect token, again by hash only.
CREATE UNLOGGED TABLE IF NOT EXISTS mqtt_tokens (
  pk         text NOT NULL,
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS mqtt_tokens_pk_key
  ON mqtt_tokens (pk_digest(pk));
CREATE INDEX IF NOT EXISTS mqtt_tokens_pk_hash_idx
  ON mqtt_tokens USING hash (pk);
CREATE INDEX IF NOT EXISTS mqtt_tokens_expires_at_idx ON mqtt_tokens (expires_at);

-- Single-use CONNECT nonces. `SET NX EX` becomes an INSERT that either takes the
-- row or does not — strictly more correct than the Redis version, because the
-- primary key decides rather than a round trip.
CREATE UNLOGGED TABLE IF NOT EXISTS mqtt_nonces (
  nonce      text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS mqtt_nonces_expires_at_idx ON mqtt_nonces (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE};
