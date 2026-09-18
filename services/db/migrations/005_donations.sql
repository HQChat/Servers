-- 005 — the paywall becomes donations.
--
-- Everything dropped here existed to answer one question: "has the holder of
-- this key paid?" The product is free now and funded by donations, so nothing
-- asks it, and the tables that answered it are not dormant — they are wrong to
-- keep. `subscriptions` and `otp` in particular held the only email-derived
-- material on the server; dropping them is the point, not a side effect.
--
-- Irreversible by design. There is no down-migration because there is no state
-- worth restoring: no subscription was ever sold (the app has not shipped), and
-- a rollback would want the paywall code back, not its rows.
--
-- No BEGIN/COMMIT here: migrate.ts wraps each file in its own transaction, and
-- committing early would leave the schema_migrations row outside it.

-- The claim flow, in full.
DROP TABLE IF EXISTS subscription_claims;     -- id -> email_hash (device binding)
DROP TABLE IF EXISTS subscription_customers;  -- stripe customer id -> email_hash
DROP TABLE IF EXISTS subscriptions;           -- email_hash -> active | cancelled
DROP TABLE IF EXISTS otp;                     -- pending 6-digit claim codes

-- Recognition for people who donate. Opt-in, and deliberately joinable to
-- NOTHING: no customer id, no email, no hash of one, no account id, no amount,
-- no timestamp finer than the day it arrived. A donation and an identity cannot
-- be connected from this database, by anyone, including whoever runs it.
--
-- `name_key` rather than a surrogate id because the dedupe IS the identity here:
-- a repeat donor should appear once, and the only thing we hold to recognise
-- them by is the name they typed.
CREATE TABLE IF NOT EXISTS supporters (
  name_key      text        PRIMARY KEY,
  display_name  text        NOT NULL,
  first_seen    date        NOT NULL DEFAULT current_date
);

-- The app role is granted per-table, not per-schema-default, so a new table is
-- invisible to it until this runs. 004 ends with the same line for the same
-- reason.
GRANT SELECT, INSERT, UPDATE, DELETE ON supporters TO ${APP_ROLE};
