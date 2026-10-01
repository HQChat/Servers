-- 011 — strip the broker's database role, so Terraform can delete it.
--
-- `emqx_prod` existed for EMQX's PostgreSQL authorizer: USAGE on the schema
-- (000_roles.sql) and SELECT on mqtt_acl (001/004; the table went in 010). The
-- broker's ACL is a static file now and it holds no database credential.
--
-- Postgres refuses to drop a role that still holds privileges, and DigitalOcean
-- deletes a database user with a DROP ROLE — so the Terraform removal of
-- `digitalocean_database_user.emqx_prod` fails until this has run. Order:
-- deploy this, THEN `terraform apply` in infra/database.
--
-- The name is LITERAL, not ${...}: the runner's substitutions fall back to the
-- CONNECTING user when unset, and a REVOKE aimed at whoever runs migrations is
-- the one mistake this file must not be able to make. Only the managed cluster
-- ever had this role (pre-prod and local run a single Postgres user), so
-- everywhere else this is a no-op — guarded, not assumed.

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'emqx_prod')
     AND current_user <> 'emqx_prod' THEN
    REVOKE ALL ON SCHEMA public FROM emqx_prod;
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM emqx_prod;
    -- 000 never set default privileges for this role, but a database that grew
    -- them by hand would keep the role undroppable; clearing them is harmless.
    ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM emqx_prod;
  END IF;
END
$$;
