-- Privileges for the application role Terraform created (infra/database/main.tf).
--
-- There were two. The broker's (`emqx_prod`, SELECT on mqtt_acl) went with the
-- Postgres authorizer: EMQX's ACL is a static file now and it holds no database
-- credential at all. Its grants are removed from this file for FRESH installs;
-- a database that already ran it has them revoked by 011_drop_emqx_role.sql.
-- Migrations are tracked by name, so editing an applied one never re-runs it.
--
-- DigitalOcean's API has no grant primitive, so this is where least privilege
-- actually happens. The role NAMES differ per stack (managed-database users are
-- cluster-wide, so they carry their stack), which is why it arrives as
-- ${APP_ROLE} — see migrate.ts.
--
-- Runs FIRST, before any table exists, so the grants below are DEFAULT
-- privileges: they apply to whatever the later migrations create. Re-running is
-- harmless; GRANT is idempotent.

-- The role may reach the schema at all.
GRANT USAGE ON SCHEMA public TO ${APP_ROLE};

-- The services: read and write every table, but no DDL. Migrations run as the
-- cluster admin, so an application compromise cannot drop a table or add one.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${APP_ROLE};
