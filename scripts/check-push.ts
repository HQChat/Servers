// Why a phone would or would not be woken, from the server's own state.
//
//   docker compose exec push-bridge node --import tsx scripts/check-push.ts helper
//
// Written after "notifications only arrive while the app is open". Every step of
// the push path exits silently when it cannot proceed — no APNs config, no
// registered token, no bundle id — so a stack that has never sent a single push
// looks exactly like one that is working. This states which step stops.
//
// It must run in `push-bridge`: that is the only service mounted the APNs key,
// which is the whole reason the old all-or-nothing check in `lib/config.ts` had
// to be moved behind `needs.includes("apns")`.
//
// Read-only, and deliberately blind to one thing: whether the DEVICE is
// currently marked online. That lives in the bridge's memory, not the database
// — `GET /health` reports the size of that set. A token that exists here and a
// notification that never arrives, with APNs ready, means the bridge believed
// the device was reachable.

import "../lib/config";
import { q, disconnect } from "../services/db/pg";
import { DB } from "../services/db/api";
import { apnsGaps, apnsSummary } from "../lib/apns-config";
import { keyProblem } from "../services/apns/api";
import { isPeerId } from "../lib/identity";

/** Resolve a username or an id to an id. Exported so the resolution half can be
 *  asserted without driving the whole report. */
export async function resolve(who: string): Promise<{ id: string; username: string } | null> {
  if (isPeerId(who)) {
    const row = await q<{ id: string; username: string | null }>(
      `SELECT id, username FROM users WHERE id = $1`, [who]
    );
    const r = row.rows[0];
    return r ? { id: r.id, username: r.username ?? "(no handle)" } : null;
  }
  const row = await q<{ id: string; username: string | null }>(
    `SELECT id, username FROM users WHERE username = $1`, [who]
  );
  const r = row.rows[0];
  return r ? { id: r.id, username: r.username ?? "(no handle)" } : null;
}

/**
 * The report, with the account to check passed in rather than read from argv.
 *
 * Exported because this is what an operator READS during an outage, and the
 * round that found the ACL scripts drifting showed what a diagnostic that lies
 * costs: `check-mqtt-acl` called an ACL complete while the one topic first
 * contact needs was missing. A report is only worth having if its verdict is
 * held to something.
 */
export async function report(arg?: string): Promise<void> {
  console.log("");
  console.log(`APNs: ${apnsSummary(process.env)}`);
  // "Set" and "usable" are different questions. A .p8 that OpenSSL will not load
  // passes every presence check and fails every push.
  const keyIssue = keyProblem();
  if (keyIssue && process.env.APNS_KEY_P8?.trim()) {
    console.log(`  ⛔️ ${keyIssue}`);
    console.log("     Re-install it from the file Apple gave you:");
    console.log("       scp AuthKey_XXXXXXXXXX.p8 root@host:/etc/hqcat/prod/secrets/apns_key_p8");
    console.log("     Pasting it at a prompt is what usually truncates it: `read` takes one line.");
  }

  const gaps = apnsGaps(process.env);
  if (gaps.length) {
    console.log("");
    console.log("  ⛔️ Nothing below matters until this is fixed: with APNs incomplete,");
    console.log("     ApnsService.send() returns before it builds a request. No device");
    console.log("     is woken, and no error is logged, for any account.");
    console.log("");
    console.log("     APNS_KEY_ID / APNS_TEAM_ID / APNS_TOPIC_IOS / APNS_TOPIC_MACOS / APNS_ENV");
    console.log("     belong in deploy/server.env; APNS_KEY_P8 is the compose secret");
    console.log("     deploy/secrets/apns_key_p8, mounted into push-bridge only.");
  }

  if (!arg) {
    // Without a name, report the shape of the whole table. A stack where NOBODY
    // has a token is a different problem from one person's device.
    const all = await q<{ platform: string; n: string }>(
      `SELECT platform, count(*)::text AS n FROM push_tokens GROUP BY platform ORDER BY platform`
    );
    const users = await q<{ n: string }>(`SELECT count(*)::text AS n FROM users`);
    console.log("");
    console.log(`registered devices (of ${users.rows[0]?.n ?? "?"} accounts)`);
    if (all.rows.length === 0) {
      console.log("  none — no device has ever POSTed /push/token.");
      console.log("  The client does that on every successful auth, so zero rows means");
      console.log("  either no build with push has ever signed in, or the entitlement is");
      console.log("  missing and registerForRemoteNotifications never returned a token.");
    } else {
      for (const r of all.rows) console.log(`  ${r.platform}: ${r.n}`);
    }
    console.log("");
    console.log("Pass a username or client id to check one account.");
    console.log("");
    return;
  }

  const who = await resolve(arg);
  if (!who) {
    console.log(`\nno account "${arg}" — it has never completed /auth/*/verify.\n`);
    return;
  }

  console.log("");
  console.log(`@${who.username} = ${who.id}`);

  const token = await DB.getPushToken(who.id);
  if (!token) {
    console.log("  push token: NONE");
    console.log("    → this device cannot be woken at all. The app registers on every");
    console.log("      auth success (AppState.onAuthSuccess), so a missing row means the");
    console.log("      OS never handed it a token: notification permission denied, or the");
    console.log("      build has no aps-environment entitlement.");
  } else {
    const topic = token.platform === "macos"
      ? process.env.APNS_TOPIC_MACOS
      : process.env.APNS_TOPIC_IOS;
    console.log(`  push token: ${token.token.slice(0, 12)}… (${token.platform})`);
    console.log(`  topic for ${token.platform}: ${topic || "UNSET — send() returns silently"}`);
  }

  // Who could wake them, and on which topic. A friendship whose hash is not in
  // the table is one the bridge would see a message on and find no members for.
  const friends = await q<{ peer: string; hash: string }>(
    `SELECT CASE WHEN id_lo = $1 THEN id_hi ELSE id_lo END AS peer, hash
       FROM friendships WHERE id_lo = $1 OR id_hi = $1`,
    [who.id]
  );
  console.log(`  conversations that could wake them: ${friends.rows.length}`);
  for (const f of friends.rows) {
    console.log(`    c/${f.hash.slice(0, 8)}… with ${f.peer.slice(0, 8)}…`);
  }

  console.log("");
  console.log("──");
  if (gaps.length) {
    console.log("APNs is not ready — see the top of this report.");
  } else if (!token) {
    console.log("APNs is ready, but this account has no device to send to.");
  } else {
    console.log("Nothing in the server's state blocks a wake for this account.");
    console.log("If it still does not buzz: the bridge only wakes a member it believes is");
    console.log("OFFLINE. Check `curl localhost:8080/health` for the size of that set, and");
    console.log("the bridge log for a `could not wake` line naming the reason.");
  }
  console.log("");
}

// Only when this file is the process entry point. Imported, it reports nothing
// and closes no pool — the caller owns both.
if (require.main === module) {
  report(process.argv[2])
    .catch((e) => { console.error(e instanceof Error ? e.message : String(e)); process.exitCode = 1; })
    .finally(() => disconnect());
}
