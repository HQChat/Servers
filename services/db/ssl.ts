// How this stack speaks TLS to Postgres. One definition, because pg.ts and
// migrate.ts have already drifted once on exactly this question (`existsSync`
// against non-empty) and the failure mode both times was a service that could
// not reach the database at all.
import * as fs from "fs";

/**
 * The cluster CA, or "" when there is none to use.
 *
 * The file must be non-EMPTY, not merely present: the local and CI overlays
 * mount an empty placeholder, because compose has no way to omit a secret that
 * one service in the stack does need. An empty CA with `rejectUnauthorized`
 * fails every handshake instead of falling back to the plaintext connection
 * those overlays intend.
 */
export function clusterCa(): string {
  const path = process.env.PGSSLROOTCERT;
  return path && fs.existsSync(path) ? fs.readFileSync(path, "utf8").trim() : "";
}

/**
 * TLS settings for a client. With the CA on disk we verify the certificate AND
 * the hostname, which is what DigitalOcean's own `sslmode=verify-full` means; a
 * redirected host fails the handshake rather than quietly serving. Without one,
 * plaintext — local development against a `postgres:17` container that speaks no
 * TLS. config.ts warns about that combination in production.
 */
export function tls(): { ca: string; rejectUnauthorized: true } | false {
  const ca = clusterCa();
  return ca ? { ca, rejectUnauthorized: true } : (false as const);
}

/**
 * The connection URI with `sslmode` removed — NOT a downgrade, and not optional.
 *
 * node-postgres re-parses `connectionString` OVER the explicit config, so a URI
 * carrying `sslmode=verify-full` replaces the `ssl` object above -- CA and all --
 * with a bare `rejectUnauthorized: true` checked against the system trust store.
 * DigitalOcean signs each cluster with its own self-signed project CA, which is
 * not in that store, so every connection died with
 *
 *   [migrate] failed: self-signed certificate in certificate chain
 *
 * while the same URI minus `sslmode` connected on the first try. Proven against
 * the live cluster before this was written.
 *
 * The URI keeps `sslmode=verify-full` where it is written and read by people:
 * terraform emits it, and lib/config.ts warns when production lacks it. This
 * strips it only at the point a driver would misuse it, and `tls()` then asks
 * for strictly what that mode promises.
 */
export function withoutSslMode(uri: string | undefined): string | undefined {
  if (!uri) return uri;
  return uri.replace(/([?&])sslmode=[^&]*&?/, (_m, sep: string) => (sep === "?" ? "?" : "&"))
    .replace(/[?&]$/, "");
}
