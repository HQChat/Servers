-- 008 — per-session MQTT signing keys (the v1 CONNECT proof).
--
-- The MQTT CONNECT password has been an opaque bearer token: 32 random bytes,
-- valid for 12 hours, reusable on every reconnect in that window. Anyone who
-- saw one CONNECT could connect as that client until it expired — and on the
-- raw-TCP transport the CONNECT is exactly what an on-path observer sees first.
--
-- v1 replaces it with a proof. At sign-in and at every refresh, over HTTPS, the
-- client registers the PUBLIC half of a fresh Ed25519 key; each CONNECT then
-- carries a signature over (clientid, key id, timestamp, single-use nonce). The
-- server stores no secret at all — a copy of this table lets nobody connect —
-- and a captured CONNECT is dead once its nonce is spent or its timestamp ages
-- out of the 60-second window.
--
-- UNLOGGED like mqtt_tokens: losing the table on a crash costs every client one
-- refresh, and nothing else.
--
-- At most two live rows per id (the current key and the one before it), so a
-- CONNECT signed a moment before a refresh still verifies. registerMqttKey
-- prunes the rest on every insert, so the table cannot grow per id.

CREATE UNLOGGED TABLE IF NOT EXISTS mqtt_session_keys (
  id         text        NOT NULL,
  key_id     text        NOT NULL CHECK (key_id ~ '^[0-9a-f]{32}$'),
  pubkey     bytea       NOT NULL CHECK (octet_length(pubkey) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (id, key_id)
);
CREATE INDEX IF NOT EXISTS mqtt_session_keys_expires_at_idx ON mqtt_session_keys (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE};
