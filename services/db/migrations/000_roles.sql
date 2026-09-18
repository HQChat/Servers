-- Privileges for the two roles Terraform created (infra/database/main.tf).
--
-- DigitalOcean's API has no grant primitive, so this is where least privilege
-- actually happens. The role NAMES differ per stack (managed-database users are
-- cluster-wide, so they carry their stack), which is why they arrive as
-- ${APP_ROLE} / ${EMQX_ROLE} — see migrate.ts.
--
-- Runs FIRST, before any table exists, so the grants below are DEFAULT
-- privileges: they apply to whatever the later migrations create. Re-running is
-- harmless; GRANT is idempotent.

-- Both roles may reach the schema at all.
GRANT USAGE ON SCHEMA public TO ${APP_ROLE};
GRANT USAGE ON SCHEMA public TO ${EMQX_ROLE};

-- The services: read and write every table, but no DDL. Migrations run as the
-- cluster admin, so an application compromise cannot drop a table or add one.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${APP_ROLE};

-- The broker: SELECT on the topic ACL and nothing else. EMQX has never had a
-- credential this narrow — its Redis authorizer held the password to the whole
-- keyspace, i.e. read/write on every user, session and subscription in the
-- system, to answer one lookup.
--
-- Default privileges cannot express "one table", so the grant on mqtt_acl
-- itself is at the end of 001_schema.sql, where the table exists.
