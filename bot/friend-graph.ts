/**
 * The two decisions that keep the bot's local friend list in step with the
 * server's — pure, so they can be tested without loading the native HQC library
 * or booting an MQTT client.
 *
 * They live here rather than inside `bot.ts` because getting either wrong is
 * destructive in a way the bot cannot recover from on its own: one of them
 * decides which conversations to FORGET, sessions included.
 */

import { PEER_ID_RE } from "../lib/identity";

/**
 * The peers the server says we still have, or null if it did not say.
 *
 * The distinction is the whole point. `api()` throws on a non-2xx, so a caller
 * reaching here got an answer — but an answer whose `friends` is not an array is
 * not "you have no friends", and treating it as one would prune every peer the
 * bot knows and destroy every ratchet session with them. Null means "learned
 * nothing, change nothing".
 *
 * Rows are CLIENT IDS now — `/friends` used to ship a 14474-character public key
 * per friend, which is about 160 kB a minute for eleven friends on a poll that
 * exists only because nothing pushes graph changes.
 */
export function liveFriendIds(body: unknown, selfId: string): Set<string> | null {
  const rows = (body as { friends?: unknown } | null | undefined)?.friends;
  if (!Array.isArray(rows)) return null;

  const live = new Set<string>();
  for (const row of rows) {
    const id = String((row as { id?: unknown })?.id ?? "").toLowerCase();
    // Exactly a client id. This was `[0-9a-f]{16,}` — an open-ended bound that
    // could not tell a well-formed identifier from a truncated one, which is
    // the difference between skipping a bad row and tracking a peer whose topic
    // nobody has a grant on. A malformed entry is skipped rather than failing
    // the whole sync: one bad row must not cost the other peers their sessions,
    // and it must not look like they were unfriended either.
    if (!PEER_ID_RE.test(id) || id === selfId) continue;
    live.add(id);
  }
  return live;
}

/**
 * Tracked peers the server no longer lists.
 *
 * These are what put the bot in a permanent reconnect loop: their conversation
 * grant is revoked when the friendship ends, and re-subscribing to a revoked
 * topic makes the broker close the link (`deny_action = disconnect`).
 */
export function staleFriendIds(tracked: Iterable<string>, live: Set<string>): string[] {
  return [...tracked].filter((id) => !live.has(id));
}
