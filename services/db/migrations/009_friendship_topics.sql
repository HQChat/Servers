-- 009 — unguessable conversation topics.
--
-- A conversation topic was `c/{friendshipHash}`: sha256 over the two client ids,
-- and a client id is sha256 over a public key. Anyone could therefore derive the
-- topic of any pair, and the ONLY thing between a stranger and a conversation's
-- ciphertext and metadata was the broker's Postgres authorizer over `mqtt_acl`.
--
-- The topic becomes a capability instead. Each friendship carries two random
-- 256-bit ids, handed to its two members over authenticated REST (/friends):
--
--   cv/{convo_id}       the conversation      (was c/{hash})
--   hs/{handshake_id}   the init challenge    (was h/{hash})
--
-- The broker then needs only a static ACL (infra/deploy/emqx/acl.conf) plus
-- `wildcard_subscription = false`: it allows `cv/+` and `hs/+` to anyone, and
-- knowing an id is the permission. Unfriending deletes the row, and with it the
-- ids; re-friending mints fresh ones, so an ex-friend is left holding a topic
-- nobody publishes to any more.
--
-- Random ids rather than an HMAC of a per-friendship key: the managed cluster has
-- no pgcrypto, so SQL could not derive an HMAC to backfill existing rows, and a
-- client that is handed the topic has no use for the key it came from. It also
-- leaves nothing for two implementations to agree on.
--
-- The DEFAULT is the minting: two gen_random_uuid() (122 random bits each, from
-- pg_strong_random) with the dashes stripped — 64 hex characters, 244 bits. A
-- volatile default is evaluated per row, so ADD COLUMN backfills every existing
-- friendship with its own values, and INSERTs that do not name the columns get
-- fresh ones without the application doing anything.
--
-- `hash` stays: /report and getHashMembers still name a friendship by it. It is
-- just no longer a topic.

ALTER TABLE friendships
  ADD COLUMN IF NOT EXISTS convo_id text NOT NULL
    DEFAULT (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''))
    CHECK (convo_id ~ '^[0-9a-f]{64}$'),
  ADD COLUMN IF NOT EXISTS handshake_id text NOT NULL
    DEFAULT (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''))
    CHECK (handshake_id ~ '^[0-9a-f]{64}$');

-- UNIQUE because the push-bridge maps an arriving `cv/{id}` back to its two
-- members through this column, and a collision would push the wrong people.
CREATE UNIQUE INDEX IF NOT EXISTS friendships_convo_id_key ON friendships (convo_id);
CREATE UNIQUE INDEX IF NOT EXISTS friendships_handshake_id_key ON friendships (handshake_id);
