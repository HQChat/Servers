// What ACL rows a pk HAS, against the rows it SHOULD have.
//
//   docker compose exec app-api node --import tsx scripts/check-mqtt-acl.ts helper
//
// Written during a bot outage that presented as a connect/drop loop with
// `0x87 NOT AUTHORIZED`. The reason code says why, and the bot now names the
// operation — but neither says whether the grant is missing or the topic string
// is wrong, and there is no `postgres` container to query by hand: the database
// is managed and its URL is a Docker secret this service already holds.
//
// So the check runs where the credentials are, and DERIVES what should be
// there rather than asking someone to eyeball a list. A missing row and a row
// that merely looks unfamiliar are very different problems.
//
// Read-only. `rebuild-mqtt-acl.ts` is the thing that fixes what this reports.

import "../lib/config";
import { q, disconnect } from "../services/db/pg";
import { DB } from "../services/db/api";
import { friendshipHash } from "../lib/crypto-utils";
import { isPeerId, peerId } from "../lib/identity";

type Row = { topic: string; action: string };

/**
 * Every grant this client is entitled to, derived the same way the writers do.
 *
 * Exported so it can be held to that claim. This is the THIRD hand-written copy
 * of one rule — `DB.grantSelfTopics`/`grantFriendTopic` write it,
 * `rebuild-mqtt-acl.ts` repairs from it, and this reports against it — and the
 * three had already drifted: the rebuild was missing the graph grant that both
 * of the others knew about.
 */
export async function expected(id: string): Promise<Row[]> {
  const rows: Row[] = [
    // grantSelfTopics
    { topic: DB.presenceTopic(id), action: "publish" },
    { topic: DB.inboxTopic(id), action: "all" },
    { topic: DB.graphTopic(id), action: "subscribe" },
  ];
  const peers = await DB.friendIds(id);
  for (const peer of peers) {
    // grantFriendTopic — both directions, from this client's side
    rows.push({ topic: `c/${friendshipHash(id, peer)}`, action: "all" });
    rows.push({ topic: DB.presenceTopic(peer), action: "subscribe" });
    rows.push({ topic: DB.inboxTopic(peer), action: "publish" });
    // Both members hold `all` on the handshake topic and nobody else is granted
    // it. It was absent from this list, so this check reported a complete ACL
    // while the one topic first contact needs was missing — during the outage
    // it was written to diagnose.
    rows.push({ topic: DB.handshakeTopic(id, peer), action: "all" });
  }
  return rows;
}

/** Shorten a topic for display. Topics are 64-hex-keyed now rather than
 *  14474-hex-keyed, so this elides far less than it used to — but a screen of
 *  eleven full ids is still a screen nobody reads. */
function short(topic: string): string {
  return topic.replace(/[0-9a-f]{32,}/g, (m) => `${m.slice(0, 8)}…${m.slice(-6)}`);
}

export type { Row };

async function main() {
  const who = process.argv[2] || process.env.BOT_USERNAME || "helper";

  // A client id (64 hex), a full public key (14474 hex — accepted because that
  // is what an operator is likely to have copied out of a log), or a username.
  const argument = who.toLowerCase();
  const id = isPeerId(argument)
    ? argument
    : /^[0-9a-f]{100,}$/.test(argument)
      ? peerId(argument)
      : await DB.getIdByUsername(who);
  if (!id) {
    console.error(`no user '${who}'`);
    process.exitCode = 1;
    return;
  }
  console.log(`id       ${id}`);
  console.log(`username ${(await DB.getUsername(id)) ?? "(none)"}`);

  const actual = (await q<Row>(`SELECT topic, action FROM mqtt_acl WHERE id = $1`, [id])).rows;
  const want = await expected(id);

  const key = (r: Row) => `${r.action} ${r.topic}`;
  const have = new Map(actual.map((r) => [r.topic, r.action]));
  const wanted = new Map(want.map((r) => [r.topic, r.action]));

  console.log(`\n${actual.length} row(s) present, ${want.length} expected\n`);

  const missing = want.filter((r) => have.get(r.topic) !== r.action);
  const extra = actual.filter((r) => !wanted.has(r.topic));

  for (const r of want) {
    const got = have.get(r.topic);
    const ok = got === r.action;
    const note = got === undefined ? "MISSING" : ok ? "" : `has '${got}', wants '${r.action}'`;
    console.log(`  ${ok ? "✓" : "✗"} ${r.action.padEnd(9)} ${short(r.topic)}${note ? `   ← ${note}` : ""}`);
  }
  for (const r of extra) {
    // Not an error on its own: an unfriended peer's rows linger until a prune.
    console.log(`  · ${r.action.padEnd(9)} ${short(r.topic)}   ← not expected (stale?)`);
  }

  if (missing.length) {
    console.log(
      `\n❌ ${missing.length} grant(s) missing or wrong.\n` +
      `   With authorization.deny_action = disconnect, touching any of these\n` +
      `   DROPS THE CONNECTION — which is what a connect/reconnect loop is.\n` +
      `   Fix: npm run rebuild-mqtt-acl  (then wait out the 15m authorizer cache,\n` +
      `   or restart emqx to clear it immediately).`
    );
    process.exitCode = 1;
  } else {
    console.log(`\n✅ every expected grant is present.`);
    console.log(`   If the client is still being refused, the topic it actually`);
    console.log(`   touches differs from the ones above — the bot logs the culprit.`);
  }
}

// Only when this file is the process entry point.
if (require.main === module) {
  main()
    .catch((e) => { console.error(e); process.exitCode = 1; })
    .finally(() => disconnect());
}
