-- Prekeys: the ephemeral half of the initial key agreement.
--
-- Until now every shared secret in a conversation — the channel setup AND every
-- rotation — was a KEM encapsulation to the peer's long-term identity key. HQC
-- decapsulation is deterministic, so one leaked identity secret plus a recorded
-- transcript recomputes every root, every chain key and every message key ever
-- used with that peer. Deleting message keys after use bought nothing against
-- that adversary, because they are recomputable from the ciphertexts.
--
-- These tables hold the fix. A client publishes short-lived KEM public keys; an
-- initiator claims one and encapsulates to BOTH it and the pinned identity key,
-- mixing the two secrets into the initial root. The identity half authenticates
-- the peer; the prekey half is destroyed after use, so the transcript stops
-- being decryptable once it is gone. This is PQXDH's argument, and it is why the
-- prekeys need no signature — a substituted prekey yields nothing to an attacker
-- who cannot also produce the identity secret. HQC is a KEM, not a signature
-- scheme, so that property is load-bearing rather than a convenience.
--
-- DURABLE, not ephemeral (002): a lost one-time prekey is not a lost session —
-- the initiator falls back to the medium-term key — but a truncated table would
-- silently drop every conversation to the fallback, which is exactly the
-- degradation nobody would notice. Durability here is what makes the one-time
-- tier real rather than decorative.

-- ============================================================
-- Medium-term prekey — one per account, replaced on rotation
-- ============================================================
-- The fallback when a peer's one-time prekeys are exhausted (a popular account
-- claimed faster than its client replenishes, or a client that has not been
-- online to top up). Reused across handshakes until rotated, so it gives weaker
-- forward secrecy than a one-time key and better than none: an identity leak no
-- longer suffices, but the window is the key's lifetime rather than one session.
--
-- `prekey` is a 7237-byte HQC public key as hex (14474 chars) — see §0 of
-- 001_schema.sql for why neither it nor `pk` may be a btree key.
CREATE TABLE IF NOT EXISTS prekeys_medium (
  pk         text NOT NULL,
  prekey     text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS prekeys_medium_pk_key
  ON prekeys_medium (pk_digest(pk));
CREATE INDEX IF NOT EXISTS prekeys_medium_pk_hash_idx
  ON prekeys_medium USING hash (pk);

-- ============================================================
-- One-time prekeys — claimed exactly once, then gone
-- ============================================================
-- `id` is the client's own index for the key, echoed back in the `init` frame so
-- the responder knows which secret to decapsulate with. It is unique per account,
-- not globally: two accounts may both hold id 0.
--
-- Claiming is a `DELETE ... RETURNING` (see claimPrekey in db/api.ts), which is
-- what makes "exactly once" a property of the row rather than of a read-then-
-- write the way the Redis shape would have had it. Two initiators racing for the
-- same peer cannot both take the same key: one DELETE wins and the other returns
-- no row and moves to the next one.
CREATE TABLE IF NOT EXISTS prekeys_onetime (
  pk         text NOT NULL,
  id         integer NOT NULL,
  prekey     text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS prekeys_onetime_pk_id_key
  ON prekeys_onetime (pk_digest(pk), id);
CREATE INDEX IF NOT EXISTS prekeys_onetime_pk_hash_idx
  ON prekeys_onetime USING hash (pk);

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE};
