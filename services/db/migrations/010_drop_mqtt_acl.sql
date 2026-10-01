-- 010 — drop the broker's topic ACL table.
--
-- EMQX authorized from `mqtt_acl` through a PostgreSQL source. It now reads a
-- static file (infra/deploy/emqx/acl.conf) and holds no database connection:
-- per-user topics are keyed on the authenticated clientid, and conversations
-- are addressed by the random per-friendship ids of 009, which only the two
-- members are handed. Nothing writes this table and nothing reads it.
--
-- ⚠️ Ordering. A broker still configured with the PostgreSQL source would, once
-- this runs, find no table: every lookup errors, no_match = deny. That is why
-- this ships in the SAME release as the static-ACL emqx.conf, and why
-- db-migrate runs before the broker restarts.
--
-- The EMQX role keeps USAGE on the schema (000_roles.sql) and nothing else. It
-- is vestigial; see infra/database/README.md.

DROP TABLE IF EXISTS mqtt_acl;
