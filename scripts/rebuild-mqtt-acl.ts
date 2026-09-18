// Rebuild the MQTT topic ACL from the friend graph.
//
//   docker compose run --rm app-api node --import tsx scripts/rebuild-mqtt-acl.ts
//
// The grants here MUST mirror DB.grantFriendTopic / DB.grantSelfTopics exactly.
// They did not: the handshake topic and the graph topic were both absent, so a
// repair silently left first contact and graph updates broken. Held to it now by
// test/acl-rebuild.test.ts, which grants through the writers, wipes the table,
// rebuilds, and demands the same rows back.
//
// `mqtt_acl` is materialised rather than a view over `friendships`, because EMQX
// queries it directly and a view would join on every authz cache miss. The cost
// of materialising is that it can drift — a grant that failed halfway, a row
// deleted by hand. This is the repair: `friendships` is the source of truth, so
// derive the whole table from it and let ON CONFLICT settle the difference.
//
// Idempotent by construction. It ADDS what is missing and does not remove
// anything, so running it can only widen access — pass --prune to also drop
// conversation grants that no friendship justifies.
//
// (This was `backfill-mqtt-acl.ts`, a one-time Redis SCAN written for the MQTT
// cutover. The derivation it performed is a single statement now.)

// Must be first: loads .env + resolves *_FILE secrets so DATABASE_URL is set.
import "../lib/config";
import { logger } from "../lib/logger";
import { q, disconnect } from "../services/db/pg";

/**
 * Derive the whole ACL from `friendships` and `users`.
 *
 * Exported so `test/acl-rebuild.test.ts` can assert the thing this file's header
 * asks for and nothing enforced: that what a rebuild produces is what
 * `DB.grantFriendTopic` / `DB.grantSelfTopics` produce. It had already drifted —
 * the self-grant here wrote presence and inbox but not the graph topic, so an
 * account that lost its graph grant did not get it back from the repair, and
 * silently stopped being told its friend graph had changed.
 *
 * Does not disconnect: the caller owns the pool.
 */
export async function rebuildAcl(opts: { prune?: boolean } = {}): Promise<{
  granted: number; selfGranted: number; pruned: number;
}> {
  const prune = opts.prune ?? false;

  // Both members of every friendship get: `all` on the shared conversation
  // topic, `subscribe` on the other's presence, and `publish` on the other's
  // inbox (where the `init` frame lands so first contact survives the peer being
  // offline — see DB.grantFriendTopic). This must stay a mirror of that function;
  // a grant that exists there and not here is one a rebuild silently removes.
  const granted = await q(
    `WITH grants AS (
       SELECT id_lo AS id, 'c/' || hash AS topic, 'all' AS action FROM friendships
       UNION ALL
       SELECT id_hi,       'c/' || hash,          'all'            FROM friendships
       UNION ALL
       SELECT id_lo, 'u/' || id_hi || '/presence', 'subscribe'     FROM friendships
       UNION ALL
       SELECT id_hi, 'u/' || id_lo || '/presence', 'subscribe'     FROM friendships
       UNION ALL
       SELECT id_lo, 'u/' || id_hi || '/inbox',    'publish'       FROM friendships
       UNION ALL
       SELECT id_hi, 'u/' || id_lo || '/inbox',    'publish'       FROM friendships
       UNION ALL
       -- The handshake topic, and it was missing entirely. h/{hash} carries the
       -- challenge/proof exchange that authenticates an init frame; both members
       -- hold 'all' and nobody else is granted it at all. Without these two rows
       -- a repair leaves every affected conversation answering 0x87 NOT
       -- AUTHORIZED on the one topic first contact needs — which is the outage
       -- check-mqtt-acl.ts was written during.
       -- (No backticks in here: this is inside a template literal.)
       SELECT id_lo, 'h/' || hash, 'all' FROM friendships
       UNION ALL
       SELECT id_hi, 'h/' || hash, 'all' FROM friendships
     )
     INSERT INTO mqtt_acl (id, topic, action)
     SELECT id, topic, action FROM grants
     ON CONFLICT (id, topic) DO UPDATE SET action = EXCLUDED.action
     RETURNING id`
  );

  // Everyone keeps their own topics: publish on their presence, all on their
  // inbox. Derived from `users` rather than from friendships, so an account with
  // no friends still has somewhere to be woken.
  const selfGranted = await q(
    `INSERT INTO mqtt_acl (id, topic, action)
     SELECT id, 'u/' || id || '/presence', 'publish' FROM users
     UNION ALL
     SELECT id, 'u/' || id || '/inbox', 'all' FROM users
     UNION ALL
     -- SUBSCRIBE only, and it was missing entirely. The account listens for
     -- "your graph changed"; the server is the only publisher and it publishes
     -- through the admin API, which the authorizer does not consult. Without
     -- this row a repaired account stops learning about invites until its next
     -- poll, and a greeting that arrives before the inviter knows who sent it is
     -- dropped as an unknown sender.
     SELECT id, 'u/' || id || '/graph', 'subscribe' FROM users
     ON CONFLICT (id, topic) DO UPDATE SET action = EXCLUDED.action
     RETURNING id`
  );

  logger.startup(
    `[rebuild-mqtt-acl] ${granted.rowCount} friendship grants, ${selfGranted.rowCount} self grants written`
  );

  let prunedCount = 0;
  if (prune) {
    // A conversation grant whose friendship is gone. Deliberately opt-in: this
    // is the only destructive thing here, and a bug in the WHERE clause would
    // silently cut people off from conversations that are perfectly valid.
    const pruned = await q(
      `DELETE FROM mqtt_acl a
        WHERE a.topic LIKE 'c/%'
          AND NOT EXISTS (
            SELECT 1 FROM friendships f
             WHERE 'c/' || f.hash = a.topic
               AND (f.id_lo = a.id OR f.id_hi = a.id)
          )`
    );
    prunedCount = pruned.rowCount ?? 0;
    logger.startup(`[rebuild-mqtt-acl] pruned ${prunedCount} orphaned conversation grants`);
  }

  return {
    granted: granted.rowCount ?? 0,
    selfGranted: selfGranted.rowCount ?? 0,
    pruned: prunedCount,
  };
}

async function main() {
  await rebuildAcl({ prune: process.argv.includes("--prune") });
  await disconnect();
}

// Only when this file is the process entry point — importing it must not
// rewrite an authorization table.
if (require.main === module) {
  main().catch((e) => {
    logger.error(`[rebuild-mqtt-acl] failed: ${(e as Error).message}`);
    process.exit(1);
  });
}
