import { logger } from '../../lib/logger';
import * as crypto from 'crypto';
import { friendshipHash } from '../../lib/crypto-utils';
import { isPeerId, peerId } from '../../lib/identity';
import { queryMetrics } from '../../lib/metrics';
import { performance } from 'perf_hooks';
import { q, one, tx, disconnect as pgDisconnect } from './pg';
require('dotenv').config();

// The whole backing store is Postgres — see docs/architecture/postgres-migration.md
// for why, and services/db/migrations/ for the schema. Two properties of that
// move show up all through this file:
//
//   - Anything that used to need a Lua script or a pipeline pretending to be
//     atomic is now a constraint, a single statement, or an explicit
//     transaction. Check-then-set races (username claim, seat cap, invite
//     accept) are gone rather than narrowed.
//   - TTLs are `expires_at` columns. Every read filters on them; sweepExpired()
//     in pg.ts reclaims the space, called on an interval from ops/broker-watch.
//     ⚠️ One table is not like that: `reports` (006) holds message content and
//     its 90-day deletion is a PUBLISHED promise rather than a space
//     optimisation, so its read path sweeps before reading instead of trusting
//     the interval. pg.ts says the same beside the sweep.
//
// MQTT connect token lifetime.
//
// This used to be 5 minutes, and the reason was revocation: with no way to end a
// live session, expiry WAS the revocation mechanism, so it had to be short. The
// cost was that every connected client was disconnected and made to reconnect
// twelve times an hour whether or not it sent anything — a TLS handshake, an
// authn hook call, a store read and a full re-subscribe each time, for every
// client, forever (LAT-1).
//
// `lib/emqx.ts` can now kick a session and drop a single subscription on demand,
// so revocation no longer waits for a clock. The TTL goes back to meaning what a
// credential lifetime should mean: a bound on how long a STOLEN token is useful,
// not a polling interval. Twelve hours keeps a leaked token from being
// indefinite while making the disconnect a daily event rather than a constant one.
const MQTT_TOKEN_TTL_SECONDS = 12 * 60 * 60;

// REST bearer session (app-api + /auth/refresh). SLIDING: every use extends it,
// up to an absolute cap.
//
// Fixed at one hour, this quietly cost a biometric prompt every hour of use. A
// client whose MQTT token expired called /auth/refresh with its session; once the
// session itself lapsed, that 401'd and the app fell back to a full KEM
// handshake, which needs the private key, which prompts. An idle timeout is what
// was wanted; a hard cap on an ACTIVE session was not.
const REST_SESSION_TTL_SECONDS = 60 * 60;
// However long it stays active, a session cannot outlive this. A stolen bearer
// that is used continuously would otherwise never expire.
const REST_SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;

// Don't rewrite `expires_at` on every authenticated request. Resolving a session
// is the single hottest operation in the system and the old implementation made
// it a WRITE — one `EXPIRE` per request, per user, forever. Sliding only once
// the session is within this much of lapsing keeps the behaviour identical from
// the client's side (it never sees a session die while in use) and turns almost
// every resolve into a pure read.
const SESSION_SLIDE_AFTER_SECONDS = 5 * 60;

// How long an auth challenge (the KEM proof the client must return) stays open.
const AUTH_CHALLENGE_TTL_SECONDS = 60;

/**
 * Which door minted a REST session. `premium` is granted only by
 * /auth/paid/verify against a claimed subscription; `free` is what the open
 * door hands out. It is STORED in the session rather than recomputed per
 * request, so a route reads one column instead of re-deciding an entitlement -
 * which is only honest because revocation acts (revokeAllSessions) instead of
 * waiting for a TTL.
 */
export type SessionScope = 'free' | 'premium';

export interface SessionInfo {
  /** The caller's client id — sha256(hex(pk)), 64 hex characters. Not the key:
   *  nothing a session-authenticated route does needs one. */
  id: string;
  scope: SessionScope;
}

const usernamesBlacklist = new Set([
  'admin', 'administrator', 'root', 'system', 'support', 'help', 'contact',
  'info', 'security', 'test', 'tester', 'bot', 'moderator', 'mod',
  'staff', 'team', 'owner', 'founder',
  // The helper bot's handle — the server auto-friends it to every user, so it
  // must not be reclaimable by a normal account (would hijack that routing).
  'helper', 'dissqus'
]);

/** A session bearer is stored by its HASH, never in the clear. `session:{token}`
 *  used the token itself as the key, so anyone who could read the store held
 *  every live bearer in it. */
function tokenHash(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** The friendship pair, normalised. Must sort exactly the way friendshipHash
 *  does (JS default lexicographic), which is also why the CHECK constraint in
 *  004_identity_by_hash.sql carries COLLATE "C". Asserted from both sides in
 *  test/identity.test.ts. */
function pair(id1: string, id2: string): [string, string] {
  const [lo, hi] = [id1, id2].sort();
  return [lo!, hi!];
}

/** Seconds → a Postgres interval parameter. */
const secs = (n: number) => `${Math.max(0, Math.floor(n))} seconds`;

const DBImpl = {
  // ============================================================
  // 1. IDENTITY & USER MANAGEMENT
  // ============================================================

  /**
   * Record an identity: its id AND the key that id names.
   *
   * This is the ONE write that needs both. `users.identity_pk` is the only
   * durable copy of an account's identity key in the system — nothing else
   * stores one — so it is what `GET /peer/{id}/key` serves and what the auth
   * server encapsulates a challenge to. The pair is checked by the database
   * (`encode(pk_digest(identity_pk),'hex') = id`), which means a row whose key
   * does not match its id cannot exist.
   *
   * Called from the auth server's verify path, where key possession has just
   * been proved, so an identity is recorded only by whoever holds its secret.
   * Idempotent: re-authenticating is the ordinary case.
   */
  async ensureUser(id: string, identityPk: string): Promise<void> {
    await q(
      `INSERT INTO users (id, identity_pk, created_at, tier)
       VALUES ($1, $2, now(), 'free')
       ON CONFLICT (id) DO NOTHING`,
      [id, identityPk.toLowerCase()]
    );
  },

  /** Record an identity AND claim a username in one go. Used by tests and
   *  fixtures; the live path is ensureUser + setUsername, because a client
   *  authenticates before it ever picks a name. */
  async createUser(id: string, identityPk: string, username: string) {
    // One statement, and the UNIQUE index decides. The Redis version read
    // `usernames:taken`, then wrote a pipeline — two clients could both pass the
    // read and both write, and the loser silently overwrote the winner's binding.
    try {
      await q(
        `INSERT INTO users (id, identity_pk, username, created_at, tier)
         VALUES ($1, $2, $3, now(), 'free')`,
        [id, identityPk.toLowerCase(), username]
      );
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === '23505') {
        // 23505 is unique_violation; which constraint tripped says which of the
        // two callers' errors to raise.
        const detail = String((e as { constraint?: string }).constraint || '');
        if (detail.includes('username')) throw new Error(`Username '${username}' is already taken.`);
        throw new Error(`Public Key already registered.`);
      }
      throw e;
    }
  },

  async getUser(id: string) {
    const row = await one<{ id: string; username: string | null; created_at: Date; tier: string }>(
      `SELECT id, username, created_at, tier FROM users WHERE id = $1`,
      [id]
    );
    // `{}` for an unknown id, as HGETALL gave.
    if (!row) return {} as Record<string, string>;
    return {
      id: row.id,
      username: row.username || '',
      created_at: String(row.created_at.getTime()),
      tier: row.tier,
    } as Record<string, string>;
  },

  async getUsername(id: string): Promise<string | null> {
    const row = await one<{ username: string | null }>(
      `SELECT username FROM users WHERE id = $1`, [id]
    );
    return row?.username ?? null;
  },

  /**
   * The public key an id names.
   *
   * Served at friend-add (GET /peer/{id}/key) and used by the auth server. The
   * caller MUST check it against the id it asked for — `keyMatchesId` in
   * lib/identity.ts — which is what makes a substituted key impossible rather
   * than merely unlikely. This server cannot be trusted to answer honestly, and
   * with the commitment it does not have to be.
   */
  async identityKey(id: string): Promise<string | null> {
    const row = await one<{ identity_pk: string }>(
      `SELECT identity_pk FROM users WHERE id = $1`, [id]
    );
    return row?.identity_pk ?? null;
  },

  async getIdByUsername(username: string): Promise<string | null> {
    // `username` is citext, so this is case-insensitive — which is the point.
    // `username:{u}` was a case-SENSITIVE key while the reserved-handle list
    // lowercased, so `Helper` was claimable while `helper` was not.
    const row = await one<{ id: string }>(`SELECT id FROM users WHERE username = $1`, [username]);
    return row?.id ?? null;
  },

  // NOTE: the bulk user directory (getUserDirectory / getAllUsernames) was
  // removed. Returning every username + pk to any authenticated user was a
  // social-graph enumeration leak, and pk → SHA-256(pk) → billing/linking code
  // (M3). Discovery is now exact-username lookup only (getIdByUsername), used by
  // the GET_ALL_USERS handler in server.ts.

  /**
   * Read an identifier that may be either a client id or a username.
   *
   * The two forms cannot be confused: an id is exactly 64 lowercase hex
   * characters, and a username is 3–32 of `[A-Za-z0-9_]`. So this is a shape
   * test, not the `length > 50` heuristic it replaces — which worked only
   * because the other form was 14474 characters, and would have read a full
   * public key as an id the moment a caller sent one.
   *
   * Returning the id unchanged does NOT mean it names anybody. Callers check
   * that separately (friendship, or a `users` lookup); an id is a name, never a
   * claim.
   */
  async resolveToId(identifier: string): Promise<string | null> {
    if (!identifier) return null;
    // Lowercased first, so an uppercase id is read as the id it is rather than
    // as a username nobody could hold. A username is at most 32 characters, so
    // it can never take this branch.
    const lowered = identifier.toLowerCase();
    if (isPeerId(lowered)) return lowered;
    return await this.getIdByUsername(identifier);
  },

  async setUsername(id: string, newUsername: string) {
    // check new username 
    if (!newUsername || newUsername.length < 3 || newUsername.length > 32) {
      throw new Error("Username must be between 3 and 32 characters.");
    }
    if (!/^[a-zA-Z0-9_]+$/.test(newUsername)) {
      throw new Error("Username can only contain letters, numbers, and underscores.");
    }
    if (usernamesBlacklist.has(newUsername.toLowerCase())) {
      // Reserved handles (incl. the bot's 'helper'/'dissqus') are blocked for
      // normal users. A trusted service identity that self-registered in
      // `admission_exempt` — i.e. the helper bot — is allowed to claim its
      // reserved handle; that's the whole reason the handle is reserved.
      if (!(await this.isAdmissionExempt(id))) {
        throw new Error("This username is not allowed.");
      }
    }
    // Who currently owns this name (if anyone)?
    const currentOwner = await this.getIdByUsername(newUsername);

    // Idempotent: re-setting the name you already own is a no-op success
    // (previously this threw "Username taken." against your own identity).
    if (currentOwner === id) return;

    // A name owned by a *different* pk may NOT be transferred — blindly handing
    // it over let any authenticated user take over (impersonate) another user or
    // the helper bot (H3). The only exception is a trusted service identity: the
    // helper bot legitimately needs to reclaim its handle after a seed/keypair
    // regeneration (e.g. its state volume was lost). We recognise it by the same
    // self-registered `admission_exempt` row it writes on startup — so this needs
    // no manual, stale-prone BOT_PUBLIC_KEY list. The static env is still honoured
    // as an optional override. Everything else is refused.
    if (currentOwner && currentOwner !== id) {
      // BOT_PUBLIC_KEY is a KEY, as its name says and as an operator would set
      // it — so it is compared after being reduced to the id it names, not
      // against the id directly.
      const trustedIds = (process.env.BOT_PUBLIC_KEY || '')
        .split(',').map((s) => s.trim()).filter(Boolean).map((k) => peerId(k));
      const trusted = trustedIds.includes(id) || (await this.isAdmissionExempt(id));
      if (!trusted) {
        throw new Error('USERNAME_TAKEN');
      }
    }

    // Releasing the old owner's name and taking it must not be two round trips:
    // between them the name belongs to nobody, and a third caller could claim it.
    await tx(async (c) => {
      if (currentOwner && currentOwner !== id) {
        await c.query(`UPDATE users SET username = NULL WHERE id = $1`, [currentOwner]);
      }
      // An UPDATE, where this used to upsert. It cannot create the row any more:
      // `users.identity_pk` is NOT NULL and this function has no key to put in
      // it. Nothing is lost, because the row already exists by the time anyone
      // can call this — a username is set with a session bearer, and the auth
      // server writes the identity (ensureUser) before it mints one.
      const res = await c.query(
        `UPDATE users SET username = $2 WHERE id = $1`, [id, newUsername]
      );
      if (!res.rowCount) throw new Error('UNKNOWN_IDENTITY');
    });
  },

  /**
   * Permanently delete a user and everything we store about them — used by the
   * in-app "Delete Account" flow (App Store Guideline 5.1.1(v)). Removes the
   * identity record, frees the username, tears down both sides of every
   * friendship (and the MQTT grants that went with them), drops invites in both
   * directions, the push token, and every live session.
   *
   * ⚠️ It used to purge the user's entire server-side footprint, full stop, and
   * /privacy says so. There is now exactly one deliberate exception, and it is
   * worth stating here rather than only in the migration: a REPORT filed against
   * this user survives, because a purge that took it would make "delete my
   * account" the abuse-evasion button — delete, the reports against you vanish,
   * re-register. What goes is the half that is this user's own footprint: every
   * report they FILED has its `reporter_id` nulled, and their blocks go
   * entirely. The report itself expires 90 days after it was filed, unchanged by
   * this, which is how the promise on /privacy stays true in a form you can
   * actually write down. See migrations/006_reports.sql §1.
   *
   * It used to also release a subscription claim, freeing the device slot so a
   * user who deleted and re-created did not burn through their own cap. Nothing
   * is bound to an identity by payment any more, so there is no slot to give
   * back — and a supporter's name is not linked to an account, so deleting an
   * account cannot and should not remove it.
   *
   * One transaction. The Redis version could not be: it ran a pipeline, then
   * revoked sessions separately (because the session keys were only reachable
   * through an index it had to delete last), and then SCANned every `invites:*`
   * key in the database — on a user-facing request — because invites this user
   * SENT lived in other people's inboxes with nothing pointing back. An index on
   * `invites.from_id` makes that last part a single statement.
   */
  async deleteUser(id: string): Promise<void> {
    await tx(async (c) => {
      // Each friend also holds ACL rows naming this user: the shared
      // conversation topic and this user's presence topic. Without removing
      // them the deleted account's grants survive, and every friend keeps a
      // dangling entry for an id that no longer exists.
      const { rows: peers } = await c.query<{ peer: string; hash: string }>(
        `SELECT CASE WHEN id_lo = $1 THEN id_hi ELSE id_lo END AS peer, hash
           FROM friendships WHERE id_lo = $1 OR id_hi = $1`,
        [id]
      );
      for (const { peer, hash } of peers) {
        await c.query(`DELETE FROM mqtt_acl WHERE id = $1 AND topic = ANY($2::text[])`, [
          peer,
          // Every topic of THIS user that a peer holds a grant on — the shared
          // conversation, this user's presence, and (since 003) this user's
          // inbox. Missing one leaves the peer a dangling grant on an id that no
          // longer exists.
          [`c/${hash}`, this.presenceTopic(id), this.inboxTopic(id)],
        ]);
      }

      await c.query(`DELETE FROM friendships WHERE id_lo = $1 OR id_hi = $1`, [id]);
      await c.query(`DELETE FROM invites WHERE to_id = $1 OR from_id = $1`, [id]);
      await c.query(`DELETE FROM mqtt_acl WHERE id = $1`, [id]);
      // MQTT connect credential + every live REST bearer.
      await c.query(`DELETE FROM mqtt_tokens WHERE id = $1`, [id]);
      await c.query(`DELETE FROM sessions WHERE id = $1`, [id]);
      await c.query(`DELETE FROM push_tokens WHERE id = $1`, [id]);
      // Both prekey tiers. These are public keys, so leaving them would leak
      // nothing — but account-delete.e2e asserts that NO row anywhere survives,
      // and that assertion is the App Store evidence. A new table that forgets
      // to appear here is exactly the silent regression it exists to catch.
      await c.query(`DELETE FROM prekeys_medium WHERE id = $1`, [id]);
      await c.query(`DELETE FROM prekeys_onetime WHERE id = $1`, [id]);
      // Moderation state. Blocks are one person's preference about their own
      // inbox and nobody else's record, so they go with the account, in both
      // directions — a block naming this id can never bite again anyway, since
      // an id is sha256(public key) and a re-registration mints a new one.
      await c.query(`DELETE FROM blocks WHERE blocker_id = $1 OR blocked_id = $1`, [id]);
      // Reports this user FILED lose their filer and keep their content: the
      // message was handed in by someone about someone else. Reports ABOUT this
      // user are not touched at all — the one row in this schema that outlives
      // the account it names, on purpose, bounded by its own 90-day expiry.
      // test/api-graph.test.ts pins both halves; it is the App Store evidence
      // for 5.1.1(v) and the exception has to be visible in it.
      await c.query(`UPDATE reports SET reporter_id = NULL WHERE reporter_id = $1`, [id]);
      // Last: the identity — which frees the username AND is the only copy of
      // this account's public key the server held.
      await c.query(`DELETE FROM users WHERE id = $1`, [id]);
    });
  },

  // ============================================================
  // 2. SUPPORTERS (donations -> recognition, and nothing else)
  // ============================================================
  //
  // What stood here was the subscription claim: `subscriptions`, `otp`,
  // `subscription_customers` and `subscription_claims`, joining a web purchase
  // to a device key through sha256(email). All four are dropped in
  // migrations/005_donations.sql.
  //
  // One table replaces them, and it does far less on purpose. A donation grants
  // nothing, so there is no entitlement to record and no device to bind. The
  // only thing kept is the name a donor chose to be listed under — held with no
  // customer id, no email, no hash of one, no account id and no amount, so
  // there is nothing here to join a payment to a person.

  /** Record an opt-in supporter name. Idempotent: a repeat donor keeps their
   *  original `first_seen` rather than jumping to the top of the list. */
  async recordSupporter(displayName: string): Promise<void> {
    const name = displayName.trim().slice(0, 60);
    if (!name) return;
    await q(
      `INSERT INTO supporters (name_key, display_name) VALUES ($1, $2)
       ON CONFLICT (name_key) DO UPDATE SET display_name = EXCLUDED.display_name`,
      [name.toLowerCase(), name]
    );
  },

  /** The supporters page, oldest first. */
  async listSupporters(): Promise<Array<{ name: string; since: string }>> {
    const res = await q<{ display_name: string; first_seen: string }>(
      `SELECT display_name, first_seen::text FROM supporters
        ORDER BY first_seen, name_key`
    );
    return res.rows.map((r) => ({ name: r.display_name, since: r.first_seen }));
  },

  /**
   * Self-registered admission exemptions. The helper bot writes its own id here
   * on startup (see bot/bot.ts) so it's admitted under any policy without an
   * operator hand-copying its key into EXEMPT_PUBLIC_KEYS — which would go stale
   * whenever the bot's seed/identity changes. Being exempt only waives the
   * payment/allowlist gate; the caller still had to pass HQC auth, so only the
   * holder of that private key benefits.
   *
   * An id is derivable by anyone holding the public key, so this table is not a
   * secret and being IN it proves nothing on its own — it is read only after
   * the KEM proof has already established who is asking.
   */
  async addAdmissionExempt(id: string) {
    await q(
      `INSERT INTO admission_exempt (id) VALUES ($1) ON CONFLICT DO NOTHING`,
      [id.toLowerCase()]
    );
  },

  /** Whether this identity self-registered an admission exemption. */
  async isAdmissionExempt(id: string): Promise<boolean> {
    const row = await one(`SELECT 1 FROM admission_exempt WHERE id = $1`, [id.toLowerCase()]);
    return row !== null;
  },

  /** Withdraw an exemption. The bot re-registers its own on every startup, so
   *  this is for an operator retiring a key - or a test cleaning up after one. */
  async removeAdmissionExempt(id: string): Promise<void> {
    await q(`DELETE FROM admission_exempt WHERE id = $1`, [id.toLowerCase()]);
  },

  // ============================================================
  // 3. INVITES & SOCIAL
  // ============================================================

  async invite(fromId: string, toIdentifier: string) {
    const toId = await this.resolveToId(toIdentifier);
    if (!toId) throw new Error("User not found");
    if (fromId === toId) throw new Error("Self-invite not allowed");
    // The `users` lookup is what stops an id being a way to address a stranger:
    // resolveToId hands back any well-formed id unchecked, deliberately, and
    // this is where "does anyone hold that name" is decided.
    if (!(await one(`SELECT 1 FROM users WHERE id = $1`, [toId]))) throw new Error("User not found");

    if (await this.areFriends(fromId, toId)) throw new Error("Already friends");

    // We store the invite in the recipient's "inbox"
    await q(
      `INSERT INTO invites (to_id, from_id, created_at) VALUES ($1, $2, now())
       ON CONFLICT (to_id, from_id) DO UPDATE SET created_at = now()`,
      [toId, fromId]
    );
  },

  /**
   * Withdraw an invite this user sent, or decline one they received.
   * `removeFriend` cannot do this: it requires an established friendship, so a
   * pending invite had no way to be taken back at all.
   * Returns true when an invite was actually removed.
   */
  async cancelInvite(fromId: string, toIdentifier: string): Promise<boolean> {
    const toId = await this.resolveToId(toIdentifier);
    if (!toId) return false;
    // The invite lives in the *recipient's* inbox, keyed by the sender.
    const res = await q(`DELETE FROM invites WHERE to_id = $1 AND from_id = $2`, [toId, fromId]);
    return (res.rowCount ?? 0) > 0;
  },

  /** Decline an invite addressed to this user. */
  async declineInvite(myId: string, fromIdentifier: string): Promise<boolean> {
    const fromId = await this.resolveToId(fromIdentifier);
    if (!fromId) return false;
    const res = await q(`DELETE FROM invites WHERE to_id = $1 AND from_id = $2`, [myId, fromId]);
    return (res.rowCount ?? 0) > 0;
  },

  async getMyInvites(myId: string) {
    // One join, where the Redis version did an HGETALL and then a round trip per
    // sender to look up a username.
    const res = await q<{ id: string; username: string | null; sent_at: string }>(
      `SELECT i.from_id AS id,
              u.username::text AS username,
              (EXTRACT(epoch FROM i.created_at) * 1000)::bigint::text AS sent_at
         FROM invites i
         LEFT JOIN users u ON u.id = i.from_id
        WHERE i.to_id = $1
        ORDER BY i.created_at`,
      [myId]
    );
    return res.rows.map((r) => ({
      id: r.id,
      // NULL, not "Unknown". A placeholder here is a display decision the server
      // has no business making, and it is actively harmful: the client detects a
      // changed identity by finding a DIFFERENT id under the same display name,
      // so two nameless accounts sharing a placeholder would read as one of them
      // having re-keyed. The client labels a nameless peer by its id.
      username: r.username || null,
      sent_at: Number(r.sent_at),
    }));
  },

  /**
   * Refined to support the server's need to notify the peer.
   * Returns true if the acceptance was successful.
   *
   * Consuming the invite and creating the friendship are one transaction, so
   * two simultaneous accepts cannot both succeed — the Redis version checked
   * HEXISTS and then wrote, with a window in between.
   */
  async acceptInvite(fromIdentifier: string, myId: string): Promise<boolean> {
    const fromId = await this.resolveToId(fromIdentifier);
    if (!fromId) return false;

    return await tx(async (c) => {
      const taken = await c.query(`DELETE FROM invites WHERE to_id = $1 AND from_id = $2`, [
        myId, fromId,
      ]);
      if (!taken.rowCount) return false;

      // One row IS the friendship. Accepting used to write only the friend sets
      // and not the blind hash, so `checkFriendship` — which reads the hash —
      // answered false for a friendship the friend LIST showed. There is nothing
      // left to keep in sync.
      const [lo, hi] = pair(myId, fromId);
      await c.query(
        `INSERT INTO friendships (id_lo, id_hi, hash) VALUES ($1, $2, $3)
         ON CONFLICT (id_lo, id_hi) DO NOTHING`,
        [lo, hi, friendshipHash(myId, fromId)]
      );
      return true;
    });
  },

  /**
   * The friend graph as the client sees it: an id and a display name per peer.
   *
   * This used to ship a 14474-character public key per friend — about 160 kB
   * every sixty seconds for eleven friends, on a poll that exists only because
   * nothing pushes graph changes. It ships 64 characters now, and the client
   * fetches the KEY separately (GET /peer/{id}/key), once, at friend-add — and
   * verifies it against the id before pinning it.
   */
  async getFriendsList(myId: string) {
    const res = await q<{ id: string; username: string | null }>(
      `SELECT peer.id, u.username::text AS username
         FROM friendships f
         CROSS JOIN LATERAL (
           SELECT CASE WHEN f.id_lo = $1 THEN f.id_hi ELSE f.id_lo END AS id
         ) peer
         LEFT JOIN users u ON u.id = peer.id
        WHERE f.id_lo = $1 OR f.id_hi = $1`,
      [myId]
    );
    // NULL rather than 'Anonymous', for the same reason getMyInvites returns
    // null: a shared placeholder name is indistinguishable from a re-keyed
    // contact to the client's username-fallback detection.
    return res.rows.map((r) => ({ id: r.id, username: r.username ?? null }));
  },

  /**
   * How many contacts an account has.
   *
   * A COUNT rather than `getFriendsList().length`: this runs on the invite and
   * accept paths to enforce FRIEND_CAP, and those should not pay to marshal
   * every row and its username just to compare a number.
   */
  async countFriends(myId: string): Promise<number> {
    const row = await one<{ n: string }>(
      `SELECT count(*)::text AS n FROM friendships WHERE id_lo = $1 OR id_hi = $1`,
      [myId]
    );
    return Number(row?.n ?? 0);
  },

  /** Just the peers, for the ACL walks below. */
  async friendIds(myId: string): Promise<string[]> {
    const res = await q<{ id: string }>(
      `SELECT CASE WHEN id_lo = $1 THEN id_hi ELSE id_lo END AS id
         FROM friendships WHERE id_lo = $1 OR id_hi = $1`,
      [myId]
    );
    return res.rows.map((r) => r.id);
  },

  async areFriends(idA: string, idB: string): Promise<boolean> {
    const [lo, hi] = pair(idA, idB);
    const row = await one(`SELECT 1 FROM friendships WHERE id_lo = $1 AND id_hi = $2`, [lo, hi]);
    return row !== null;
  },

  async removeFriend(fromId: string, toIdentifier: string): Promise<boolean> {
    const toId = await this.resolveToId(toIdentifier);
    if (!toId) return false;

    // Deleting the one row is both directions and the blind hash at once; the
    // "are they actually friends" check is its rowcount.
    const [lo, hi] = pair(fromId, toId);
    const res = await q(`DELETE FROM friendships WHERE id_lo = $1 AND id_hi = $2`, [lo, hi]);
    return (res.rowCount ?? 0) > 0;
  },

  async createFriendship(id1: string, id2: string) {
    const [lo, hi] = pair(id1, id2);
    await q(
      `INSERT INTO friendships (id_lo, id_hi, hash) VALUES ($1, $2, $3)
       ON CONFLICT (id_lo, id_hi) DO NOTHING`,
      [lo, hi, friendshipHash(id1, id2)]
    );
  },

  /** Idempotently ensure the friendship exists. It used to heal older
   *  friendships that were stored only as a blind hash with no friend-set link;
   *  one row cannot drift from itself, so this is now exactly
   *  `createFriendship` and is kept only for its callers. */
  async ensureFriendLink(id1: string, id2: string) {
    await this.createFriendship(id1, id2);
  },

  /**
   * Checks if friendship exists based on blind hash
   */
  async checkFriendship(id1: string, id2: string): Promise<boolean> {
    const row = await one(`SELECT 1 FROM friendships WHERE hash = $1`, [
      friendshipHash(id1, id2),
    ]);
    return row !== null;
  },

  getFriendshipHash(id1: string, id2: string): string {
    return friendshipHash(id1, id2);
  },

  // ============================================================
  // 3c. MODERATION (reports & blocks)
  // ============================================================
  //
  // See migrations/006_reports.sql for the retention argument and for the exact
  // sense in which a report's excerpt is NOT verifiable. Two rules from it are
  // enforced here rather than only described there:
  //
  //   * A report expires 90 days after it is filed. `expires_at` is set by the
  //     column default, so nothing in this file can file one that outlives the
  //     promise — and the operator read path sweeps lapsed rows itself rather
  //     than trusting an ops process to have run.
  //   * A block is symmetric. It is not a filter the blocked party can talk
  //     through: `isBlocked` answers for a PAIR, in either direction, and both
  //     the invite and the accept path consult it.

  /** The fixed vocabulary, mirrored by the CHECK constraint in 006. Kept here as
   *  a const so the API layer validates against one list rather than a second
   *  copy that can drift from the column. */
  reportCategories: ['spam', 'harassment', 'sexual', 'violence', 'csae', 'other'] as const,

  /**
   * File a report. Returns its id, which is what an operator quotes.
   *
   * Membership of the conversation is the CALLER'S check, not this one — the API
   * route holds the session and refuses a hash the reporter is not part of. What
   * is enforced here is what a constraint can enforce: the shape of every id, the
   * bounds on the two free-text fields, and that nobody reports themselves.
   */
  async createReport(r: {
    reporterId: string;
    reportedId: string;
    conversationHash: string;
    category: string;
    note?: string | null;
    excerpt?: string | null;
    frame?: Buffer | null;
    messageId?: string | null;
  }): Promise<string> {
    const row = await one<{ id: string }>(
      `INSERT INTO reports (reporter_id, reported_id, conversation_hash, category,
                            reporter_note, message_excerpt, message_frame, message_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id::text AS id`,
      [
        r.reporterId, r.reportedId, r.conversationHash, r.category,
        r.note ?? null, r.excerpt ?? null, r.frame ?? null, r.messageId ?? null,
      ]
    );
    if (!row) throw new Error("report insert returned no id");
    return row.id;
  },

  /**
   * The operator queue: unhandled reports, oldest first, each carrying how many
   * times its subject has been reported at all. That count is the only question
   * the table answers that a single report cannot, and it is the one that
   * decides between a warning and an ejection.
   *
   * ⚠️ It DELETES lapsed rows before reading. Everywhere else in this schema an
   * expiry sweep is about reclaiming space, because every read filters on the
   * column anyway (pg.ts). Here the deletion is the published promise, so it
   * happens on the path a human actually uses rather than only on an ops timer
   * that may not be running.
   */
  async listOpenReports(limit = 100): Promise<Array<{
    id: string; reporterId: string | null; reportedId: string; conversationHash: string;
    category: string; note: string | null; excerpt: string | null;
    hasFrame: boolean; messageId: string | null; createdAt: string; againstSubject: number;
  }>> {
    await q(`DELETE FROM reports WHERE expires_at <= now()`);
    const res = await q<{
      id: string; reporter_id: string | null; reported_id: string; conversation_hash: string;
      category: string; reporter_note: string | null; message_excerpt: string | null;
      has_frame: boolean; message_id: string | null; created_at: string; against_subject: string;
    }>(
      `SELECT r.id::text AS id, r.reporter_id, r.reported_id, r.conversation_hash,
              r.category, r.reporter_note, r.message_excerpt,
              (r.message_frame IS NOT NULL) AS has_frame, r.message_id,
              r.created_at::text AS created_at,
              (SELECT count(*) FROM reports a WHERE a.reported_id = r.reported_id)::text
                AS against_subject
         FROM reports r
        WHERE r.handled_at IS NULL
        ORDER BY r.created_at ASC
        LIMIT $1`,
      [Math.max(1, Math.min(1000, Math.floor(limit)))]
    );
    return res.rows.map((x) => ({
      id: x.id, reporterId: x.reporter_id, reportedId: x.reported_id,
      conversationHash: x.conversation_hash, category: x.category,
      note: x.reporter_note, excerpt: x.message_excerpt, hasFrame: x.has_frame,
      messageId: x.message_id, createdAt: x.created_at,
      againstSubject: Number(x.against_subject),
    }));
  },

  /** Record what was done about a report. Returns false when the id is unknown
   *  or the report has already been handled, so a second operator cannot quietly
   *  overwrite the first one's decision. */
  async resolveReport(id: string, disposition: string): Promise<boolean> {
    const res = await q(
      `UPDATE reports SET handled_at = now(), disposition = $2
        WHERE id = $1::uuid AND handled_at IS NULL`,
      [id, disposition]
    );
    return (res.rowCount ?? 0) > 0;
  },

  /** The sealed frame, when one was attached. Separate from `listOpenReports`
   *  so the queue does not carry up to 256 kB per row for a field an operator
   *  opens one at a time. */
  async reportFrame(id: string): Promise<Buffer | null> {
    const row = await one<{ message_frame: Buffer | null }>(
      `SELECT message_frame FROM reports WHERE id = $1::uuid`, [id]
    );
    return row?.message_frame ?? null;
  },

  /**
   * Block a peer. Idempotent — re-blocking someone already blocked is a no-op
   * rather than an error, because the client has no reason to know the
   * difference and a failure there would look like the block not working.
   *
   * This writes the ROW only. Tearing down the friendship and its MQTT grants is
   * the caller's job (removeFriend → revokeFriendTopic → EMQX.revokeTopic +
   * kick), exactly as unfriending does it — the row is what makes the block
   * survive that teardown, which is the whole reason it is its own table.
   */
  async block(blockerId: string, blockedId: string): Promise<void> {
    if (blockerId === blockedId) throw new Error("Self-block not allowed");
    await q(
      `INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2)
       ON CONFLICT (blocker_id, blocked_id) DO NOTHING`,
      [blockerId, blockedId]
    );
  },

  /** Lift a block. Returns true when one was actually lifted. Does NOT restore
   *  the friendship: the pair re-invite like strangers, which is the same path
   *  an ordinary unfriend leaves behind. */
  async unblock(blockerId: string, blockedId: string): Promise<boolean> {
    const res = await q(
      `DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2`,
      [blockerId, blockedId]
    );
    return (res.rowCount ?? 0) > 0;
  },

  /** Is there a block between these two, in EITHER direction? That is the
   *  question every gate asks: a block that only stopped the blocker from
   *  inviting would be a mute, and one that only stopped the blocked party would
   *  leave the blocker able to re-open a conversation they ended. */
  async isBlocked(idA: string, idB: string): Promise<boolean> {
    const row = await one(
      `SELECT 1 FROM blocks
        WHERE (blocker_id = $1 AND blocked_id = $2)
           OR (blocker_id = $2 AND blocked_id = $1)`,
      [idA, idB]
    );
    return row !== null;
  },

  /** Who this user has blocked. The client needs it to keep a blocked contact
   *  visible-but-inert rather than deleting them when they vanish from /friends
   *  — see apps/apple/DissQus/Services/DirectorySync.swift, where absence from
   *  the directory otherwise means "delete this row and its history". */
  async blockedIds(myId: string): Promise<string[]> {
    const res = await q<{ blocked_id: string }>(
      `SELECT blocked_id FROM blocks WHERE blocker_id = $1 ORDER BY created_at`,
      [myId]
    );
    return res.rows.map((r) => r.blocked_id);
  },

  // ============================================================
  // 3b. PREKEYS (ephemeral half of the initial key agreement)
  // ============================================================
  //
  // See migrations/003_prekeys.sql for why these exist at all. In short: without
  // an ephemeral contribution, one leaked identity secret plus a recorded
  // transcript decrypts a conversation's entire history, because every shared
  // secret was a deterministic encapsulation to a long-term key.
  //
  // The server is untrusted here and does not need to be trusted. It can hand an
  // initiator the wrong prekey, or none — the initiator ALSO encapsulates to the
  // pinned identity key, so a substituted prekey yields the server nothing. What
  // the server can do is withhold one-time keys to force the weaker medium-term
  // fallback, which is a downgrade in the forward-secrecy window, not in
  // confidentiality.

  /** Replace an account's published bundle: one medium-term key, N one-time keys.
   *  One transaction, because a client that uploads is replacing its whole set —
   *  a partial write would leave peers claiming keys whose secrets were dropped. */
  async putPrekeyBundle(
    ownerId: string,
    mediumPrekey: string,
    oneTime: Array<{ id: number; prekey: string }>
  ): Promise<void> {
    await tx(async (c) => {
      await c.query(
        `INSERT INTO prekeys_medium (id, prekey, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (id) DO UPDATE SET prekey = EXCLUDED.prekey, updated_at = now()`,
        [ownerId, mediumPrekey]
      );
      if (oneTime.length === 0) return;
      // Additive, not a replace: replenishment tops up the pool without
      // invalidating keys a peer may already have claimed but not yet used.
      // DO NOTHING on a repeated key_id keeps a retried upload idempotent.
      await c.query(
        `INSERT INTO prekeys_onetime (id, key_id, prekey)
         SELECT $1, * FROM unnest($2::int[], $3::text[])
         ON CONFLICT (id, key_id) DO NOTHING`,
        [ownerId, oneTime.map((k) => k.id), oneTime.map((k) => k.prekey)]
      );
    });
  },

  /**
   * The bundle an initiator needs: the medium-term key ALWAYS, plus a one-time
   * key when the pool has one.
   *
   * Both, not one or the other. The initial root mixes three secrets — identity,
   * medium-term and (when available) one-time — and each does a different job:
   * identity authenticates, medium-term gives a rotation-length forward-secrecy
   * window, one-time ends that window the moment it is consumed. Serving only
   * one would silently change which root the two sides derive.
   *
   * The one-time branch is `DELETE ... RETURNING`, so "claimed exactly once" is
   * a property of the row rather than of a read-then-delete two initiators could
   * interleave. Returns null only when the account has published nothing at all.
   */
  async claimPrekey(
    ownerId: string
  ): Promise<{ medium: string; oneTime: { id: number; prekey: string } | null } | null> {
    const medium = await one<{ prekey: string }>(
      `SELECT prekey FROM prekeys_medium WHERE id = $1`, [ownerId]
    );
    // No medium-term key means no bundle. The one-time pool is an addition to
    // it, never a substitute — an initiator with only a one-time key could not
    // derive the same root as the responder.
    if (!medium?.prekey) return null;

    const oneTime = await one<{ key_id: number; prekey: string }>(
      `DELETE FROM prekeys_onetime
        WHERE ctid = (
          SELECT ctid FROM prekeys_onetime WHERE id = $1 ORDER BY key_id LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        RETURNING key_id, prekey`,
      [ownerId]
    );

    return {
      medium: medium.prekey,
      // `id` on the wire — it is the client's own index for the key, echoed
      // back as the envelope's `otId`. The column is `key_id` because the
      // account's identifier took the name `id` in 004.
      oneTime: oneTime ? { id: oneTime.key_id, prekey: oneTime.prekey } : null,
    };
  },

  /** How many one-time keys this account has left, so a client knows when to
   *  replenish. */
  async countOneTimePrekeys(ownerId: string): Promise<number> {
    const row = await one<{ n: number }>(
      `SELECT count(*)::int AS n FROM prekeys_onetime WHERE id = $1`, [ownerId]
    );
    return row?.n ?? 0;
  },

  /** The highest one-time id on file, so replenishment never reuses one. Null
   *  when the pool is empty — the client starts from 0 again, which is safe
   *  because the ids it would collide with have all been claimed and deleted. */
  async maxOneTimePrekeyId(ownerId: string): Promise<number | null> {
    const row = await one<{ key_id: number | null }>(
      `SELECT max(key_id) AS key_id FROM prekeys_onetime WHERE id = $1`, [ownerId]
    );
    return row?.key_id ?? null;
  },

  // ============================================================
  // 4. PUSH TOKENS
  // ============================================================

  async setPushToken(id: string, platform: string, token: string) {
    // The client re-registers its APNs token on every app launch
    // (apps/apple/DissQus/AppState.swift), so this is one of the few writes that
    // scales with usage rather than with events. `IS DISTINCT FROM` makes the
    // unchanged case a no-op instead of a new row version to vacuum.
    await q(
      `INSERT INTO push_tokens (id, platform, token, updated_at) VALUES ($1, $2, $3, now())
       ON CONFLICT (id) DO UPDATE SET
         platform = EXCLUDED.platform, token = EXCLUDED.token, updated_at = now()
       WHERE push_tokens.token IS DISTINCT FROM EXCLUDED.token
          OR push_tokens.platform IS DISTINCT FROM EXCLUDED.platform`,
      [id, platform, token]
    );
  },

  async getPushToken(id: string): Promise<{ platform: string; token: string } | null> {
    const row = await one<{ platform: string; token: string }>(
      `SELECT platform, token FROM push_tokens WHERE id = $1`, [id]
    );
    if (!row?.token) return null;
    return { platform: row.platform || "ios", token: row.token };
  },

  // ============================================================
  // 5. MQTT AUTHORIZATION (RLS) — friend-hash topic ACL
  // ============================================================
  //
  // Each conversation is a topic `c/{friendshipHash}`. EMQX's PostgreSQL
  // authorizer reads `mqtt_acl` for the connecting clientid (see
  // infra/deploy/emqx/emqx.conf) — with a 15m cache in front, so this is not a
  // per-message lookup. We grant the topic to BOTH members when a friendship
  // forms and revoke it when it ends, and revocation ALSO acts on the live
  // connection through lib/emqx.ts rather than waiting for the cache.
  //
  // The topic name is derivable by anyone who knows both identifiers, so
  // security rests ENTIRELY on this table — never on topic-name secrecy.
  //
  // Every topic here names CLIENT IDS, not public keys. A presence topic was
  // `u/{14474 hex}/presence`, so an ACL row carried a key in `pk` and another
  // inside `topic`: ~29 kB to record one membership bit. It is ~140 bytes now,
  // and — the part that actually failed — a topic short enough that
  // `DELETE /clients/{id}/subscriptions/{topic}` fits in a URL, which is what
  // makes unfriending stop a LIVE subscription instead of only the next one.

  /** Conversation topic between two client ids. */
  mqttTopicFor(id1: string, id2: string): string {
    return `c/${friendshipHash(id1, id2)}`;
  },

  /** A client's own presence + inbox topics. Presence: owner publishes (retained
   *  + LWT), friends subscribe. Inbox: owner subscribes (offline wake target). */
  presenceTopic(id: string): string { return `u/${id}/presence`; },
  inboxTopic(id: string): string { return `u/${id}/inbox`; },
  /** Where the server tells this account its friend graph moved. Owner-only:
   *  nobody else is ever granted anything on it, and the server publishes
   *  through the admin API rather than as a client. */
  graphTopic(id: string): string { return `u/${id}/graph`; },

  /**
   * Where two friends prove to each other that an `init` came from the peer it
   * names. Derived from the friendship, exactly like the conversation topic, so
   * there is nothing to create, expire or clean up.
   *
   * It is a SEPARATE topic rather than the inbox because the inbox is the one
   * place every friend may publish: a challenge sitting there would be visible
   * to — and forgeable by — precisely the attacker this exchange exists to stop.
   * Only the two members are granted here, which is what keeps a third party
   * from ever seeing the challenge it would need to relay.
   */
  handshakeTopic(idA: string, idB: string): string {
    return `h/${friendshipHash(idA, idB)}`;
  },

  /** Grant a client the topics it owns: publish on its presence, all on its
   *  inbox. Idempotent; call on user creation and (harmlessly) on each token
   *  mint. */
  async grantSelfTopics(id: string): Promise<void> {
    await this.grant([
      [id, this.presenceTopic(id), 'publish'],
      [id, this.inboxTopic(id), 'all'],
      // SUBSCRIBE only. The account listens for "your graph changed"; the server
      // is the only publisher, and it publishes through the admin API, which the
      // authorizer does not consult. So no row grants anyone `publish` here —
      // not even the owner, who has no reason to tell themselves anything.
      [id, this.graphTopic(id), 'subscribe'],
    ]);
  },

  /** Grant both members everything they need for a friendship: pub/sub on the
   *  shared conversation topic, subscribe on each other's presence, and PUBLISH
   *  on each other's inbox. Idempotent. (The topic's membership no longer needs
   *  recording separately — `friendships.hash` already answers it; see
   *  getHashMembers.)
   *
   *  The inbox grant is what makes first contact work while the peer is offline.
   *  MQTT drops a publish to a topic nobody has subscribed to yet, so the old
   *  key-agreement offer — sent on the conversation topic — vanished whenever the
   *  peer had not connected since the friendship formed, and the client papered
   *  over it with a 15s directory poll. The inbox is subscribed on every connect
   *  with `cleanSession = false`, so the broker QUEUES for an offline peer
   *  instead. The `init` frame goes there; everything after it stays on the
   *  conversation topic.
   *
   *  This does not widen the trust boundary: a friend can already publish to the
   *  shared conversation topic, and the inbox carries the same ciphertext. It is
   *  scoped to friends — `grantSelfTopics` gives the owner 'all' on their own
   *  inbox, and nobody else gets a row without a friendship. */
  async grantFriendTopic(idA: string, idB: string): Promise<void> {
    const convo = `c/${friendshipHash(idA, idB)}`;
    const handshake = this.handshakeTopic(idA, idB);
    await this.grant([
      [idA, convo, 'all'],
      [idA, this.presenceTopic(idB), 'subscribe'],
      [idA, this.inboxTopic(idB), 'publish'],
      // Both members read and write the handshake topic, and nobody else is
      // granted it at all — see `handshakeTopic`.
      [idA, handshake, 'all'],
      [idB, convo, 'all'],
      [idB, this.presenceTopic(idA), 'subscribe'],
      [idB, this.inboxTopic(idA), 'publish'],
      [idB, handshake, 'all'],
    ]);
  },

  /** Write a batch of (id, topic, action) grants in one statement. */
  async grant(rows: Array<[string, string, string]>): Promise<void> {
    await q(
      `INSERT INTO mqtt_acl (id, topic, action)
       SELECT * FROM unnest($1::text[], $2::text[], $3::text[])
       ON CONFLICT (id, topic) DO UPDATE SET action = EXCLUDED.action`,
      [rows.map((r) => r[0]), rows.map((r) => r[1]), rows.map((r) => r[2])]
    );
  },

  /** Revoke both members' friendship topics (conversation + each other's
   *  presence). Idempotent. Callers should ALSO kick any live subscription via
   *  the EMQX API — the row edit only affects the NEXT authorization check that
   *  misses the cache, not an already-open subscription. */
  async revokeFriendTopic(idA: string, idB: string): Promise<void> {
    const convo = `c/${friendshipHash(idA, idB)}`;
    const handshake = this.handshakeTopic(idA, idB);
    await q(
      `DELETE FROM mqtt_acl
        WHERE (id = $1 AND topic = ANY($3::text[]))
           OR (id = $2 AND topic = ANY($4::text[]))`,
      [
        idA,
        idB,
        // Mirror of grantFriendTopic — the inbox publish grant must come back out
        // with the friendship, or an unfriended peer keeps a channel to wake this
        // device with `init` frames it will no longer answer. Same for the
        // handshake topic, which is the channel that would let them try again.
        [convo, this.presenceTopic(idB), this.inboxTopic(idB), handshake],
        [convo, this.presenceTopic(idA), this.inboxTopic(idA), handshake],
      ]
    );
  },

  /** Re-grant every friend topic this pk is entitled to. A lapsed subscription
   *  revokes them - a paywall has to bite on the live session, not only on the
   *  next one - and resubscribing has to put them back. The friend list was
   *  never deleted, so it is the record of what to restore. */
  async regrantAllFriendTopics(id: string): Promise<number> {
    const friends = await this.friendIds(id);
    for (const peer of friends) await this.grantFriendTopic(id, peer);
    return friends.length;
  },

  /** Revoke every friend topic except `keepId` (the helper bot, which the free
   *  tier keeps). Returns the peers revoked so the caller can ALSO drop their
   *  live subscriptions via the EMQX API. */
  async revokeAllFriendTopics(id: string, keepId?: string): Promise<string[]> {
    const friends = (await this.friendIds(id)).filter((p) => p !== keepId);
    for (const peer of friends) await this.revokeFriendTopic(id, peer);
    return friends;
  },

  /** The two client ids that share a conversation hash (for push-bridge).
   *  Answered from the friendship itself — `hashmembers:{h}` was a third copy of
   *  a fact the edge already carried, and one more thing to keep in sync. */
  async getHashMembers(hash: string): Promise<string[]> {
    const row = await one<{ id_lo: string; id_hi: string }>(
      `SELECT id_lo, id_hi FROM friendships WHERE hash = $1`, [hash]
    );
    return row ? [row.id_lo, row.id_hi] : [];
  },

  /** All topics a client may access (for repair/debugging). */
  async getAclTopics(id: string): Promise<string[]> {
    const res = await q<{ topic: string }>(`SELECT topic FROM mqtt_acl WHERE id = $1`, [id]);
    return res.rows.map((r) => r.topic);
  },

  // ============================================================
  // 6. MQTT AUTHENTICATION — opaque connect token (password)
  // ============================================================
  //
  // No JWT. The auth server, after the HQC-KEM handshake proves key ownership,
  // mints a random 32-byte token, stores only its SHA-256, and returns the raw
  // token to the client. The client presents it as the MQTT CONNECT password —
  // with its client id as the username — and EMQX's authn hook verifies it and
  // is handed the token's `expire_at` so EMQX disconnects the client at expiry
  // (expiration-based rotation). Grant = mintMqttToken; revoke = revokeMqttAuth.

  /** Seconds a freshly-minted MQTT token stays valid before refresh is required. */
  MQTT_TOKEN_TTL_SECONDS,

  /** Mint (and store the hash of) a fresh opaque MQTT connect token for `pk`.
   *  Returns the RAW token — the only time it is ever available. */
  async mintMqttToken(id: string, ttlSeconds = MQTT_TOKEN_TTL_SECONDS): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    await q(
      `INSERT INTO mqtt_tokens (id, token_hash, expires_at)
       VALUES ($1, $2, now() + $3::interval)
       ON CONFLICT (id) DO UPDATE SET
         token_hash = EXCLUDED.token_hash, expires_at = EXCLUDED.expires_at`,
      [id, tokenHash(token), secs(ttlSeconds)]
    );
    return token;
  },

  /** Verify a presented token against the stored hash (constant-time) WITHOUT
   *  consuming it — the token is reusable across reconnects until it expires.
   *  Returns whether it is valid and, if so, its absolute `expireAt` (unix
   *  seconds) so the auth hook can tell EMQX when to force a re-auth. Revocation
   *  is immediate via revokeMqttAuth, and the expiry bounds a stale token. */
  async verifyMqttToken(id: string, token: string): Promise<{ ok: boolean; expireAt: number }> {
    const row = await one<{ token_hash: string; expire_at: string }>(
      `SELECT token_hash, EXTRACT(epoch FROM expires_at)::bigint::text AS expire_at
         FROM mqtt_tokens WHERE id = $1 AND expires_at > now()`,
      [id]
    );
    if (!row) return { ok: false, expireAt: 0 };
    const a = Buffer.from(tokenHash(token));
    const b = Buffer.from(row.token_hash);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, expireAt: 0 };
    return { ok: true, expireAt: Number(row.expire_at) };
  },

  /** Revoke a client's current MQTT token immediately (account deletion /
   *  forced logout). The next reconnect fails until a new token is minted; to
   *  drop an already-open connection before its token expires, ALSO kick it via
   *  the EMQX API (the "server can revoke" half of grant/revoke). */
  async revokeMqttAuth(id: string): Promise<void> {
    await q(`DELETE FROM mqtt_tokens WHERE id = $1`, [id]);
  },

  /** Single-use nonce guard for a CONNECT. Returns true the FIRST time a nonce is
   *  seen (and reserves it for `ttlSeconds`), false on any replay.
   *
   *  `SET NX EX` became an INSERT whose primary key decides — strictly more
   *  correct, because the decision is the write rather than a round trip before
   *  it. The DO UPDATE re-takes a nonce whose reservation has lapsed, which is
   *  what the Redis TTL did by deleting the key. */
  async useNonce(nonce: string, ttlSeconds = MQTT_TOKEN_TTL_SECONDS): Promise<boolean> {
    const res = await q(
      `INSERT INTO mqtt_nonces (nonce, expires_at) VALUES ($1, now() + $2::interval)
       ON CONFLICT (nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at
       WHERE mqtt_nonces.expires_at <= now()
       RETURNING nonce`,
      [nonce, secs(ttlSeconds)]
    );
    return (res.rowCount ?? 0) === 1;
  },

  // ============================================================
  // 7. AUTH HANDSHAKE + REST SESSION (used by the auth server)
  // ============================================================
  //
  // The HQC-KEM handshake proves a client owns its public key: the auth server
  // encapsulates to the KEY and stores the expected proof under the client's ID;
  // the client decapsulates, returns the proof, and the server compares +
  // consumes it. On success it issues a multi-use REST session bearer (app-api
  // auth + token refresh) alongside the MQTT connect token.
  //
  // Keyed by id rather than by the key it names, because a challenge row is
  // pure bookkeeping — the encapsulation already happened, against a key the
  // caller supplied, and nothing here needs to re-derive it. An id being
  // derivable by anyone is irrelevant: what an attacker would have to produce
  // is the PROOF, which requires the secret key.

  /** Store the expected KEM proof for an open challenge (hex). */
  async startAuthChallenge(id: string, proofHex: string, ttlSeconds = AUTH_CHALLENGE_TTL_SECONDS): Promise<void> {
    await q(
      `INSERT INTO auth_challenges (id, proof, expires_at)
       VALUES ($1, $2, now() + $3::interval)
       ON CONFLICT (id) DO UPDATE SET proof = EXCLUDED.proof, expires_at = EXCLUDED.expires_at`,
      [id, proofHex, secs(ttlSeconds)]
    );
  },

  /** Atomically read AND delete the open challenge proof for `id` (so it can't
   *  be replayed). Returns the stored proof hex, or null if none. The caller
   *  does a constant-time compare against the client's solution. */
  async takeAuthChallenge(id: string): Promise<string | null> {
    const row = await one<{ proof: string }>(
      `DELETE FROM auth_challenges WHERE id = $1 AND expires_at > now() RETURNING proof`,
      [id]
    );
    return row?.proof ?? null;
  },

  /** Mint a multi-use REST session bearer for `id` at `scope`. Returns the raw
   *  token — the only time it exists outside the caller. */
  async mintSessionToken(
    id: string,
    scope: SessionScope = 'free',
    ttlSeconds = REST_SESSION_TTL_SECONDS
  ): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    // `iat` enforces the absolute cap; `expires_at` is the idle timeout. There
    // is no separate per-identity index to maintain — revokeAllSessions is a
    // WHERE clause, so the set of live bearers cannot drift from the bearers.
    await q(
      `INSERT INTO sessions (token_hash, id, scope, iat, expires_at)
       VALUES ($1, $2, $3, now(), now() + $4::interval)`,
      [tokenHash(token), id, scope, secs(ttlSeconds)]
    );
    return token;
  },

  /**
   * Resolve a REST session bearer to its client id AND scope, sliding its idle
   * timeout forward. Returns null when unknown, idle-expired, or past the cap.
   *
   * One statement, and usually a pure read: the slide only writes once the
   * session is within SESSION_SLIDE_AFTER_SECONDS of lapsing. Sliding on every
   * request made the hottest path in the system a write, for no behaviour a
   * client can observe.
   */
  async resolveSessionToken(token: string): Promise<SessionInfo | null> {
    if (!token) return null;
    const row = await one<{ id: string; scope: SessionScope }>(
      `WITH found AS (
         SELECT token_hash, id, scope, iat
           FROM sessions
          WHERE token_hash = $1 AND expires_at > now()
       ),
       -- Past the absolute cap: refused AND removed, so a bearer that is used
       -- continuously cannot live forever by sliding.
       capped AS (
         DELETE FROM sessions
          WHERE token_hash IN (SELECT token_hash FROM found WHERE iat <= now() - $2::interval)
       ),
       slid AS (
         UPDATE sessions SET expires_at = now() + $3::interval
          WHERE token_hash IN (SELECT token_hash FROM found WHERE iat > now() - $2::interval)
            AND expires_at < now() + $4::interval
       )
       SELECT id, scope FROM found WHERE iat > now() - $2::interval`,
      [
        tokenHash(token),
        secs(REST_SESSION_MAX_AGE_SECONDS),
        secs(REST_SESSION_TTL_SECONDS),
        secs(REST_SESSION_TTL_SECONDS - SESSION_SLIDE_AFTER_SECONDS),
      ]
    );
    return row ? { id: row.id, scope: row.scope } : null;
  },

  /** Revoke a REST session bearer (logout / account deletion). */
  async revokeSessionToken(token: string): Promise<void> {
    if (!token) return;
    await q(`DELETE FROM sessions WHERE token_hash = $1`, [tokenHash(token)]);
  },

  /** End EVERY live REST session for `pk`. This is what makes a cancelled
   *  subscription take effect now instead of whenever the last bearer happens
   *  to lapse - the same reason revocation reaches into EMQX rather than
   *  trusting a token lifetime (see lib/emqx.ts). Returns how many were ended. */
  async revokeAllSessions(id: string): Promise<number> {
    const res = await q(`DELETE FROM sessions WHERE id = $1`, [id]);
    return res.rowCount ?? 0;
  },

  /**
   * Fixed-window counter. Returns the count AFTER incrementing, so a caller can
   * compare it against a limit. One statement; the window is set only on the
   * first hit of each window, so the limit is per-window, not sliding — and a
   * later hit asking for a SHORTER window cannot shrink the one in progress.
   */
  async bumpCounter(key: string, windowSeconds: number): Promise<number> {
    const row = await one<{ n: number }>(
      `INSERT INTO rate_counters (key, n, window_ends_at)
       VALUES ($1, 1, now() + $2::interval)
       ON CONFLICT (key) DO UPDATE SET
         n = CASE WHEN rate_counters.window_ends_at <= now() THEN 1 ELSE rate_counters.n + 1 END,
         window_ends_at = CASE WHEN rate_counters.window_ends_at <= now()
                               THEN now() + $2::interval
                               ELSE rate_counters.window_ends_at END
       RETURNING n`,
      [key, secs(windowSeconds)]
    );
    return row?.n ?? 1;
  },

  /** Remaining seconds in a counter's window (-2 when absent, as Redis TTL
   *  reported it). Tests + ops. */
  async counterTtl(key: string): Promise<number> {
    const row = await one<{ ttl: string }>(
      `SELECT CEIL(EXTRACT(epoch FROM window_ends_at - now()))::bigint::text AS ttl
         FROM rate_counters WHERE key = $1 AND window_ends_at > now()`,
      [key]
    );
    return row ? Number(row.ttl) : -2;
  },

  /** Reset a counter (a success ends a run of failures). */
  async clearCounter(key: string): Promise<void> {
    await q(`DELETE FROM rate_counters WHERE key = $1`, [key]);
  },

  /** Remaining idle seconds on a session (-2 when it is gone). Tests + ops. */
  async sessionTtl(token: string): Promise<number> {
    const row = await one<{ ttl: string }>(
      `SELECT CEIL(EXTRACT(epoch FROM expires_at - now()))::bigint::text AS ttl
         FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
      [tokenHash(token)]
    );
    return row ? Number(row.ttl) : -2;
  },

  /** Mint a session with a chosen issue time. Exists so a test can prove the
   *  absolute cap is enforced without waiting thirty days for it. */
  async mintSessionTokenAt(
    id: string,
    ttlSeconds: number,
    issuedAtUnix: number,
    scope: SessionScope = 'free'
  ): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    await q(
      `INSERT INTO sessions (token_hash, id, scope, iat, expires_at)
       VALUES ($1, $2, $3, to_timestamp($4), now() + $5::interval)`,
      [tokenHash(token), id, scope, issuedAtUnix, secs(ttlSeconds)]
    );
    return token;
  },

  disconnect() { return pgDisconnect().catch((e) => logger.warn(`[pg] close: ${e.message}`)); }
};

// Wrap every DB method so its wall-clock time is recorded (see lib/metrics.ts).
// Only async methods (the ones that hit the database) are timed; sync helpers and
// plain value members pass straight through. `this` is bound to the raw impl so a
// method that calls a sibling (e.g. resolveToId → getIdByUsername) records only
// the top-level operation, not a double-counted nested one.
function instrument<T extends object>(impl: T): T {
  return new Proxy(impl, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== 'function') return value;
      const op = String(prop);
      return (...args: unknown[]) => {
        const start = performance.now();
        let out: unknown;
        try {
          out = (value as (...a: unknown[]) => unknown).apply(target, args);
        } catch (e) {
          queryMetrics.record(op, performance.now() - start, false);
          throw e;
        }
        // Only time genuine promises; sync helpers keep their return value.
        if (out && typeof (out as any).then === 'function') {
          return (out as Promise<unknown>).then(
            (r) => {
              queryMetrics.record(op, performance.now() - start, true);
              return r;
            },
            (e) => {
              queryMetrics.record(op, performance.now() - start, false);
              throw e;
            }
          );
        }
        return out;
      };
    },
  });
}

export const DB = instrument(DBImpl);
