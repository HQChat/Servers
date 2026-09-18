// App-API entrypoint (Phase 1 — see deploy/EXTRACTION_PLAN.md).
//
// "The monolith minus auth and messages": the HTTP/REST control plane for
// directory, the friend graph, payments, push-token registration, and account
// deletion. It NEVER sees message content. Friend-graph mutations here maintain
// the MQTT topic ACL (DB.grantFriendTopic / DB.revokeFriendTopic) that EMQX
// enforces as RLS.
//
// Auth: every mutating route requires a REST session bearer (Authorization:
// Bearer <sessionToken>) minted by the auth server after the HQC handshake and
// resolved here via DB.resolveSessionToken. Runs the SAME image as the monolith.
//
// The bearer also carries its SCOPE — which door minted it. Adding friends is
// the paid feature, so those two routes read one field off the resolved session
// instead of asking the database (or Stripe) whether this person has paid. The
// entitlement was decided once, at the door.

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import { assertConfig, DONATIONS_ENABLED, MAINTENANCE_MESSAGE } from "../lib/config";
import { donationsDead, donationSummary, resolvePrices } from "../lib/donations-config";
import { initObservability } from "../lib/observability";
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import * as http from "http";
import {
  readJson, send, bearer, requireString, requireHex, optionalString, optionalBase64,
  HttpError, MAX_BODY_BYTES,
} from "../lib/http";
import { DB } from "../services/db/api";
import { EMQX } from "../lib/emqx";
import { friendshipHash } from "../lib/crypto-utils";
import { isPeerId, PEER_ID_LENGTH } from "../lib/identity";
import { StripeService, displayNameFromSession } from "../services/stripe/api";
import { handleDonate } from "../services/web/donate";
import { ADMISSION_POLICY } from "../lib/admission";

const PORT = Number(process.env.PORT || 8080);

/** HQC-256 public key size (lib/hqc.ts). Prekeys are HQC public keys too. */
const HQC_PUBLIC_KEY_BYTES = 7237;

/**
 * One-time prekeys accepted per upload.
 *
 * A key travels as hex, so it costs 2 x 7237 = 14474 characters on the wire —
 * the byte count is NOT the wire cost, which is the easy way to size this wrong.
 * A bundle is the medium-term key plus N one-time keys, so the body is roughly
 * (N + 1) x 14474 bytes: at N = 16 that is ~246 kB against a 256 kB
 * MAX_BODY_BYTES, close enough that a couple of extra fields would start
 * returning 413 in production and nowhere else.
 *
 * Eight keeps the body near 130 kB, half the cap. The pool is not limited to
 * eight: putPrekeyBundle is additive (ON CONFLICT DO NOTHING), so a client that
 * wants a deeper pool uploads more than one batch.
 */
const MAX_ONETIME_PER_UPLOAD = 8;

/**
 * Longest `peer` identifier a route will accept.
 *
 * One number again, for every route. It was two: the friend routes capped at
 * 128 because you invite people by HANDLE, while `/prekeys/claim` had to fit a
 * peer's IDENTITY — and an identity was a 14474-character public key, so the
 * cap was raised to exactly that (#105, after 128 refused every real client
 * with `peer must be 1–128 characters`).
 *
 * An identity is 64 characters now, which is comfortably inside the handle-sized
 * bound, so the two forms stop needing different limits and the widest thing
 * this route accepts stops being "a public key's worth of anything".
 */
const MAX_PEER_IDENTIFIER = 128;

// --- QoS caps ---------------------------------------------------------------
// These replace the paywall. The infrastructure bill is fixed monthly — droplets,
// one managed Postgres — so users do not cost money; they cost capacity. What
// actually threatens the deployment is a script, not a popular account, and
// these are set where no real person will ever meet them.
//
// The friend cap also bounds a real fan-out: `endPremiumAccess`-style ACL walks
// and `notifyGraphChanged` are O(friends), and `regrantAllFriendTopics` runs on
// every full-door login.
const FRIEND_CAP = Number(process.env.FRIEND_CAP || 150);
// Per calendar-ish day, on the existing `rate_counters` table — no new storage.
const INVITES_PER_DAY = Number(process.env.INVITES_PER_DAY || 20);

// --- Report bounds ----------------------------------------------------------
// A report is the one route on this service that stores message content, so its
// bounds are the bound on how much of that a single account can put here. Each
// of the three is mirrored by a CHECK constraint in 006_reports.sql, because a
// route is not the only thing that can write a row.
//
// Twenty a day is generous for a person and useless as a channel: the daily
// ceiling on what one account can deposit is REPORTS_PER_DAY x (excerpt + note
// + frame), which is what to reason about rather than any single number.
const REPORTS_PER_DAY = Number(process.env.REPORTS_PER_DAY || 20);
const MAX_REPORT_NOTE = 2000;
const MAX_REPORT_EXCERPT = 4000;
// The sealed frame, when a client has one. An init frame is ~82 kB and travels
// as base64, so 96 kB of frame is ~128 kB of body — half of MAX_BODY_BYTES, with
// the note, the excerpt and the JSON scaffolding fitting comfortably in the
// rest. The boot invariant below refuses to start if that stops being true.
const MAX_REPORT_FRAME_BYTES = 96 * 1024;
// The frame's own id, copied from the envelope header. NOT our vocabulary to
// choose: ConversationEnvelopeV3 defines `msgId` as 1..128 bytes of UTF-8
// chosen by the sending client, so this is that bound and nothing narrower.
// 006 guessed lowercase hex here, which refused every id `UUID().uuidString`
// produces; 007_report_message_id.sql has the full account.
const MAX_REPORT_MESSAGE_ID_BYTES = 128;

// Refuse to boot rather than 413 in production if either constant drifts into
// the body cap. At startup, where an operator sees it — a type-level assertion
// cannot express this (comparing two number literals yields `boolean`, and the
// cast that would silence it would also stop it ever failing).
//
// The same reasoning applies to the peer bound: an identifier must fit, and the
// only reason it does is that identities are digests now.
{
  if (MAX_PEER_IDENTIFIER < PEER_ID_LENGTH) {
    throw new Error(
      `MAX_PEER_IDENTIFIER (${MAX_PEER_IDENTIFIER}) is shorter than a client id ` +
      `(${PEER_ID_LENGTH}) — every peer-addressed route would refuse every real caller`
    );
  }
}
{
  const worstCaseBody = (MAX_ONETIME_PER_UPLOAD + 1) * HQC_PUBLIC_KEY_BYTES * 2;
  if (worstCaseBody > MAX_BODY_BYTES / 2) {
    throw new Error(
      `prekey bundle upload can reach ${worstCaseBody}B against MAX_BODY_BYTES ${MAX_BODY_BYTES}B — ` +
      `lower MAX_ONETIME_PER_UPLOAD (${MAX_ONETIME_PER_UPLOAD}) or raise the cap`
    );
  }

  // The same arithmetic for /report, and for the same reason: a bound that only
  // fails in production is not a bound. base64 costs 4 bytes per 3, and the two
  // text fields and the JSON around them ride along in the same body.
  const worstCaseReport =
    Math.ceil(MAX_REPORT_FRAME_BYTES / 3) * 4 + MAX_REPORT_NOTE + MAX_REPORT_EXCERPT + 512;
  if (worstCaseReport > MAX_BODY_BYTES) {
    throw new Error(
      `a report can reach ${worstCaseReport}B against MAX_BODY_BYTES ${MAX_BODY_BYTES}B — ` +
      `lower MAX_REPORT_FRAME_BYTES (${MAX_REPORT_FRAME_BYTES}) or raise the cap`
    );
  }
}

/**
 * `messageId` on a report: the frame's own id, or null.
 *
 * Its bound is the ENVELOPE'S bound (MAX_REPORT_MESSAGE_ID_BYTES above), which
 * is why this is not a plain `optionalString`:
 *
 *   * BYTES, not characters. optionalString measures `.length`, and a UTF-16
 *     length is not the number the wire format counts — the same mistake
 *     optionalBase64's comment describes. An id of 128 emoji is 512 bytes on
 *     the wire and would pass a character check, then fail the CHECK
 *     constraint, which is exactly the class of bug this replaces.
 *   * No control characters, because `npm run reports` prints this value to an
 *     operator's terminal. That is a display concern, not a trust one: nothing
 *     in a report is verifiable (006_reports.sql §0), and this check only stops
 *     the value from moving a cursor.
 *
 * Mirrors reports_message_id_check in 007 so a malformed id is a 400 naming the
 * field instead of a 500 from Postgres. Deliberately NOT normalized — see 007:
 * this value is compared against what the broker delivered, so lowercasing or
 * stripping hyphens would trade a loud failure for a useless column.
 */
function reportMessageId(body: any): string | null {
  const value = optionalString(body, "messageId", { max: MAX_REPORT_MESSAGE_ID_BYTES });
  if (value === null) return null;
  if (Buffer.byteLength(value, "utf8") > MAX_REPORT_MESSAGE_ID_BYTES) {
    throw new HttpError(400, "INVALID_FIELD",
      `messageId must be at most ${MAX_REPORT_MESSAGE_ID_BYTES} bytes`);
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    throw new HttpError(400, "INVALID_FIELD", "messageId must not contain control characters");
  }
  return value;
}

/** Resolve the caller's client id + scope from its REST session bearer, or
 *  null. No route below needs the caller's KEY — the id is the name for
 *  everything the control plane does. */
async function authSession(req: http.IncomingMessage) {
  return DB.resolveSessionToken(bearer(req));
}

/**
 * Every route this service answers, as a plain request listener.
 *
 * SEPARATED FROM THE LISTENER so it can be tested. This module used to build the
 * server and call `listen()` at import time, so no test could load it — importing
 * it opened a socket — and all twenty routes went untested: the friend graph
 * that maintains the MQTT topic ACL, prekey claim, account deletion.
 *
 * Nothing about the behaviour changes: the same closure, now reachable.
 */
export function createApiHandler(): http.RequestListener {
  return async (req, res) => {
  const url = req.url || "";
  const method = req.method || "GET";
  try {
    if (method === "GET" && url === "/health") {
      return send(res, 200, { ok: true, service: "api" });
    }

    // --- /info + /metrics -----------------------------------------------------
    // Both lived on the retired monolith and, for a while, nowhere at all: the
    // apps' server-info screen and any uptime monitor pointed at a 404. app-api
    // is the natural host — it is the only public HTTP service left.
    if (method === "GET" && url === "/info") {
      return send(res, 200, {
        name: process.env.SERVER_NAME || "hqchat",
        version: process.env.SERVER_VERSION || "dev",
        admission: ADMISSION_POLICY,
        // What a client needs to decide whether it can talk to this deployment
        // at all, without a round trip per capability.
        transport: "mqtt",
        endpoints: { auth: "/auth", mqtt: "/mqtt", api: "/" },
        // Advisory, and advisory on purpose — it blocks nothing. A wire-version
        // flip switches every contact at once, so it is done in a window, and
        // this is what tells people the window is open. Gating during it would
        // be the wrong instinct for a security reason: the window is exactly
        // when a client most needs to reach the server, to receive the build the
        // window exists for.
        maintenance: {
          active: MAINTENANCE_MESSAGE.length > 0,
          message: MAINTENANCE_MESSAGE,
        },
      });
    }
    if (method === "GET" && url === "/metrics") {
      // Fail closed in production: no token configured means no metrics, not
      // open metrics (SRV-2). Localhost-only at the nginx layer as well.
      const token = process.env.METRICS_TOKEN || "";
      if (!token || bearer(req) !== token) return send(res, 404, { error: "not found" });
      return send(res, 200, {
        service: "api",
        uptimeSec: Math.round(process.uptime()),
        health: healthMonitor.getSnapshot(),
      });
    }

    // --- Donations (Stripe) — raw body needed for signature verification ----
    //
    // ONE event matters, and it carries almost nothing we want:
    //
    //   checkout.session.completed   a donation went through. The only field
    //                                read is the optional display name for the
    //                                supporters page. Not the email, not the
    //                                customer id, not the amount.
    //
    // `customer.subscription.*` is deliberately NOT handled. A recurring
    // donation that lapses removes no access, because it granted none — there is
    // nothing to revoke, so subscribing to those events would only invite a
    // handler that did something.
    if (DONATIONS_ENABLED && method === "POST" && url === "/stripe/webhook") {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c as Buffer));
      req.on("end", async () => {
        try {
          const event = StripeService.constructEvent(
            Buffer.concat(chunks),
            req.headers["stripe-signature"] as string
          );

          if (event.type === "checkout.session.completed") {
            const name = displayNameFromSession(event.data.object);
            // Blank is the expected answer: recognition is opt-in, and a
            // donation with no name must leave no row at all.
            if (name) await DB.recordSupporter(name);
          }

          res.writeHead(200); res.end("ok");
        } catch (e: any) {
          logger.error(`❌ [stripe-webhook] ${e.message}`);
          res.writeHead(400); res.end(`Webhook Error: ${e.message}`);
        }
      });
      return;
    }
    if (DONATIONS_ENABLED && (url.startsWith("/donate") || url.startsWith("/supporters"))) {
      handleDonate(req, res).catch((e: unknown) => {
        logger.error("[donate] handler error", e);
        if (!res.headersSent) { res.writeHead(500); res.end("error"); }
      });
      return;
    }

    // --- Directory --------------------------------------------------------
    if (method === "GET" && url.startsWith("/users")) {
      // Exact-username lookup only (?username=…) — no bulk enumeration (M3).
      const q = new URL(url, "http://x").searchParams.get("username") || "";
      const id = q ? await DB.getIdByUsername(q) : null;
      return send(res, 200, { username: q, id });
    }

    // The public key an id names.
    //
    // The directory ships IDS — 64 characters per friend rather than 14474 —
    // so a client that has just learned about someone, or that lost its local
    // store, needs one place to fetch the key itself. This is that place.
    //
    // Unauthenticated, and that is deliberate: the response is a public key,
    // the id that addresses it is derivable from that same key by anyone who
    // holds it, and requiring a session would buy nothing an attacker does not
    // already have. What makes it SAFE is not access control but the
    // commitment — the caller checks `sha256(hex(key)) == id` before pinning
    // anything, so this server cannot substitute a key even for itself.
    //
    // ⚠️ A client that skips that check has re-created the MITM this design
    // exists to close. Both clients do it (lib/identity.keyMatchesId,
    // PeerID.matches).
    if (method === "GET" && url.startsWith("/peer/")) {
      const m = url.match(/^\/peer\/([^/?]+)\/key$/);
      if (!m) return send(res, 404, { error: "not found" });
      const id = decodeURIComponent(m[1]!).toLowerCase();
      // Shape-checked before it reaches the database: an id is a fixed-width
      // hex string, and anything else is a caller error rather than a lookup.
      if (!isPeerId(id)) {
        throw new HttpError(400, "INVALID_FIELD", `id must be ${PEER_ID_LENGTH} lowercase hex characters`);
      }
      const identityPk = await DB.identityKey(id);
      if (!identityPk) return send(res, 404, { error: "UNKNOWN_PEER" });
      return send(res, 200, { id, publicKey: identityPk });
    }

    if (method === "POST" && url === "/username") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const body = await readJson(req);
      const username = requireString(body, "username", { min: 3, max: 32 });
      // The client distinguishes "someone else owns that handle" from a
      // transient failure and shows a banner with a way out (AppState
      // .isUsernameTaken), so this code has to survive the round trip as a code
      // — not collapse into a generic 500 with the rest.
      try {
        await DB.setUsername(id, username);
      } catch (e) {
        const msg = (e as Error).message;
        if (msg === "USERNAME_TAKEN") throw new HttpError(409, "USERNAME_TAKEN", "That username is taken");
        throw new HttpError(400, "INVALID_USERNAME", msg);
      }
      return send(res, 200, { ok: true, username });
    }

    // --- Friend graph (also maintains the MQTT ACL) -----------------------
    if (method === "GET" && url === "/friends") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      return send(res, 200, { friends: await DB.getFriendsList(id) });
    }
    if (method === "GET" && url === "/friends/invites") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      return send(res, 200, { invites: await DB.getMyInvites(id) });
    }
    if (method === "POST" && url === "/friends/invite") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      // What used to be the paywall. A subscription bought the right to grow
      // the friend graph at all; now everyone has it, and what stands here
      // instead are ceilings — high enough that no real account meets them,
      // low enough that a script cannot turn one signup into unbounded work.
      //
      // Deliberately NOT 402. The app reads 402 as "fall back to the free
      // door" and re-authenticates; a user who hit a daily invite limit would
      // silently lose their friend topics for the trouble.
      if (await DB.countFriends(id) >= FRIEND_CAP) {
        return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP });
      }
      const sent = await DB.bumpCounter(`invite:day:${id}`, 24 * 60 * 60);
      if (sent > INVITES_PER_DAY) {
        logger.warn(`[friends] invite rate-limited for ${id.slice(0, 12)}… (${sent}/${INVITES_PER_DAY} today)`);
        return send(res, 429, { error: "RATE_LIMITED", limit: INVITES_PER_DAY });
      }
      const to = requireString(await readJson(req), "to", { max: MAX_PEER_IDENTIFIER });
      // A block that a re-invite can walk through is not a block. Checked in
      // EITHER direction: the blocked party must not be able to re-open the
      // conversation, and the blocker must not be able to do it by accident
      // either — their client should be hiding this person, and if it is asking,
      // it is out of date rather than right.
      //
      // 404, deliberately, and the same 404 an unknown handle gets. Telling an
      // invite apart from a block tells the blocked party they were blocked,
      // which is the one thing a block should not announce.
      const blockTarget = await DB.resolveToId(to);
      if (blockTarget && (await DB.isBlocked(id, blockTarget))) {
        logger.debug(`[friends] invite refused: ${id.slice(0, 12)}… and ${blockTarget.slice(0, 12)}… are blocked`);
        return send(res, 404, { error: "NOT_FOUND" });
      }
      try {
        await DB.invite(id, to);
      } catch (e) {
        // `DB.invite` refuses three ordinary things by throwing a plain Error,
        // and until the block landed every one of them came back as a 500: a
        // user typing a handle that does not exist produced a Sentry event and
        // an "internal error" in the app. That was invisible because the two
        // tests covering it sent the field name `peer`, which this route does
        // not read, so both were refused at validation and never reached here
        // (test/api-routes.test.ts — fixed alongside this).
        //
        // It stopped being only a quality problem when blocking arrived: a block
        // answers 404, so a 500 for a stranger is the difference that tells the
        // blocked party which of the two they are. The statuses have to agree.
        const msg = (e as Error).message;
        if (msg === "User not found") return send(res, 404, { error: "NOT_FOUND" });
        if (msg === "Self-invite not allowed") {
          throw new HttpError(400, "SELF_INVITE", "You cannot invite yourself");
        }
        if (msg === "Already friends") {
          throw new HttpError(409, "ALREADY_FRIENDS", "You are already friends");
        }
        throw e;
      }
      // The recipient has no other way to learn an invite exists: nothing pushed
      // graph changes, so an invite sat unseen until their next poll — which is
      // why one needed a manual refresh to appear at all.
      const toId = await DB.resolveToId(to);
      if (toId) await EMQX.notifyGraphChanged([toId]);
      return send(res, 200, { ok: true });
    }
    if (method === "POST" && url === "/friends/accept") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      if (await DB.countFriends(id) >= FRIEND_CAP) {
        return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP });
      }
      const from = requireString(await readJson(req), "from", { max: MAX_PEER_IDENTIFIER });
      const fromId = await DB.resolveToId(from);
      // BOTH sides, because a friendship adds a contact to each. The inviter
      // was under the cap when they sent it; accepting is what would push them
      // over, and only this side can see that.
      if (fromId && (await DB.countFriends(fromId)) >= FRIEND_CAP) {
        return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP, peer: true });
      }
      // The invite may predate the block — blocking cancels pending invites in
      // both directions, but an invite can also arrive at a device that is
      // offline, and the accept is what would rebuild the friendship.
      if (fromId && (await DB.isBlocked(id, fromId))) {
        return send(res, 404, { error: "NOT_FOUND" });
      }
      const ok = fromId ? await DB.acceptInvite(fromId, id) : false;
      // Grant the conversation + presence topics to BOTH members.
      if (ok && fromId) await DB.grantFriendTopic(id, fromId);
      // AFTER the grant, and both sides.
      //
      // The inviter is the one that matters. They invited a HANDLE, so their
      // contact row holds no client id until a directory sync fills it in — and
      // the accepter now greets immediately, so that greeting reached the
      // inviter BEFORE they knew who the sender was. The frame named an id their
      // directory did not contain, and it was dropped. Nudging here closes the
      // window instead of leaving it to a 60-second timer.
      if (ok && fromId) await EMQX.notifyGraphChanged([fromId, id]);
      return send(res, ok ? 200 : 400, { ok });
    }
    if (method === "POST" && url === "/friends/cancel") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const peer = requireString(await readJson(req), "peer", { max: MAX_PEER_IDENTIFIER });
      // Withdraw an invite we sent, or decline one addressed to us. Only one of
      // the two can match a real pending invite.
      const withdrew = await DB.cancelInvite(id, peer);
      const declined = withdrew ? false : await DB.declineInvite(id, peer);
      const ok = withdrew || declined;
      if (ok) {
        const peerId = await DB.resolveToId(peer);
        if (peerId) await EMQX.notifyGraphChanged([peerId, id]);
      }
      return send(res, ok ? 200 : 400, { ok });
    }
    if (method === "POST" && url === "/friends/remove") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const peer = requireString(await readJson(req), "peer", { max: MAX_PEER_IDENTIFIER });
      const peerId = await DB.resolveToId(peer);
      const ok = await DB.removeFriend(id, peer);
      if (ok && peerId) {
        await DB.revokeFriendTopic(id, peerId);
        // The ACL edit blocks the NEXT authorization check; a subscription that
        // is already open keeps delivering until the client disconnects for its
        // own reasons (ASVS-1). Drop it now. Best effort by design — the
        // unfriend has already succeeded and must not fail on the broker.
        //
        // This is the line that has never once worked on this deployment. Both
        // arguments used to be 14474-character public keys, so the admin URL it
        // built was ~29 kB and EMQX answered 414 every single time — and because
        // authorization is checked at SUBSCRIBE, the unfriended peer's open
        // subscription kept delivering. At 64 characters the request fits.
        await EMQX.revokeTopic(id, peerId, `c/${friendshipHash(id, peerId)}`);
        // Both sides: the removed peer should stop showing a contact they can no
        // longer reach, and the remover's other devices need the same news.
        await EMQX.notifyGraphChanged([peerId, id]);
      }
      return send(res, ok ? 200 : 400, { ok });
    }

    // --- Moderation: report + block ---------------------------------------
    //
    // App Store Guideline 1.2 asks a UGC app for a way to report content AND a
    // way to block a person. Shipping one without the other is a routine
    // rejection, and they are here together for that reason as much as any
    // other: a report is a request to someone else, and a block is the thing
    // the user can do about it themselves, immediately, without waiting for us.
    //
    // ORDER MATTERS AND THE CLIENT MUST GET IT RIGHT. /report requires the
    // reporter to be a member of the conversation it names, and /friends/block
    // tears the friendship down — so a client that blocks first can no longer
    // report. Report, then block. The UI does both from one gesture and in that
    // order; this comment is here because the two routes cannot enforce it
    // between themselves.
    if (method === "POST" && url === "/report") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;

      // Before anything else is read. A report costs a row holding message
      // content, so the cap is what stops one account turning the moderation
      // queue into a place to publish — and it is counted on the existing
      // rate_counters table, like invites, rather than on new storage.
      const filed = await DB.bumpCounter(`report:day:${id}`, 24 * 60 * 60);
      if (filed > REPORTS_PER_DAY) {
        logger.warn(`[report] rate-limited for ${id.slice(0, 12)}… (${filed}/${REPORTS_PER_DAY} today)`);
        return send(res, 429, { error: "RATE_LIMITED", limit: REPORTS_PER_DAY });
      }

      const body = await readJson(req);
      const conversation = requireHex(body, "conversation", 32).toLowerCase();

      // Membership decides who may be reported, and it decides it from the
      // SERVER'S copy of the friend graph rather than from anything the client
      // sent. That is what makes "report a stranger" unrepresentable instead of
      // merely refused: there is no field to put a stranger's id in.
      const members = await DB.getHashMembers(conversation);
      if (members.length !== 2) {
        return send(res, 404, { error: "NO_CONVERSATION" });
      }
      if (!members.includes(id)) {
        logger.warn(`[report] ${id.slice(0, 12)}… named a conversation it is not a member of`);
        return send(res, 403, { error: "NOT_A_MEMBER" });
      }
      const reportedId = members[0] === id ? members[1]! : members[0]!;

      // `peer` is redundant — the line above already derived it — and that is
      // exactly why it is required. A client that disagrees with the server
      // about whose conversation this is has a bug, and filing a report against
      // the wrong person is the worst possible moment to discover it.
      const peer = requireString(body, "peer", { max: MAX_PEER_IDENTIFIER });
      if (peer.toLowerCase() !== reportedId) {
        return send(res, 400, { error: "PEER_MISMATCH",
          message: "peer is not the other member of that conversation" });
      }

      const category = requireString(body, "category", { max: 32 }).toLowerCase();
      if (!(DB.reportCategories as readonly string[]).includes(category)) {
        throw new HttpError(400, "INVALID_FIELD",
          `category must be one of: ${DB.reportCategories.join(", ")}`);
      }

      const reportId = await DB.createReport({
        reporterId: id,
        reportedId,
        conversationHash: conversation,
        category,
        note: optionalString(body, "note", { max: MAX_REPORT_NOTE }),
        // The reporter's own plaintext copy, by consent, and NOT verifiable —
        // see migrations/006_reports.sql §0. Nothing downstream may present it
        // as evidence of what was said, only as what was handed in.
        excerpt: optionalString(body, "excerpt", { max: MAX_REPORT_EXCERPT }),
        frame: optionalBase64(body, "frame", MAX_REPORT_FRAME_BYTES),
        messageId: reportMessageId(body),
      });

      // The operator signal, and the reason `logger.event` exists at all.
      //
      // There is no mail path in this stack — docs/product/publishing.md records
      // resend_api_key as no longer used — so the 24-hour commitment on /eula
      // rests on this line and on `npm run reports`, both of which are in
      // docs/runbooks/moderation.md.
      //
      // NOT `warn`: warn only drops a Sentry breadcrumb, so the line would be
      // invisible until something else crashed and carried it along. NOT
      // `error` either: a report is not a failure, and error is throttled per
      // fingerprint — a mechanism for suppressing repetition, which is the
      // opposite of what a second report in an hour deserves.
      //
      // No message content in it. The excerpt is in the row for an operator who
      // opens it, not in a log line that fans out to Sentry, Docker and whatever
      // reads either.
      logger.event(
        `[report] filed ${reportId} — ${category} against ${reportedId.slice(0, 12)}… ` +
        `by ${id.slice(0, 12)}… (see docs/runbooks/moderation.md)`
      );
      return send(res, 200, { ok: true, id: reportId });
    }

    // A block is an unfriend PLUS a row that outlives it. Without the row the
    // blocked party re-invites and the block has evaporated — which is the
    // ordinary way this feature is got wrong, and why `blocks` is its own table
    // rather than a column on the friendship the block itself deletes.
    if (method === "POST" && url === "/friends/block") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const peer = requireString(await readJson(req), "peer", { max: MAX_PEER_IDENTIFIER });
      const peerId = await DB.resolveToId(peer);
      if (!peerId) return send(res, 404, { error: "NOT_FOUND" });
      if (peerId === id) return send(res, 400, { error: "SELF_BLOCK" });

      // The row FIRST. Every line below it is best-effort teardown, and a block
      // that recorded nothing because the broker was unreachable would be a
      // block the user was told they had.
      await DB.block(id, peerId);

      // A pending invite in either direction is a live route back in, so it
      // goes with the friendship. Both calls are no-ops when there is nothing
      // pending, which is the common case.
      await DB.cancelInvite(id, peerId);
      await DB.declineInvite(id, peerId);

      const wasFriend = await DB.removeFriend(id, peerId);
      if (wasFriend) {
        await DB.revokeFriendTopic(id, peerId);
        // As in /friends/remove: the ACL edit stops the NEXT authorization
        // check, and a subscription that is already open keeps delivering until
        // the client disconnects for its own reasons (ASVS-1). Drop it now.
        await EMQX.revokeTopic(id, peerId, `c/${friendshipHash(id, peerId)}`);
      }
      // Both sides either way — the blocked peer should stop showing a contact
      // they can no longer reach even if the friendship row was already gone,
      // and the blocker's other devices need the same news.
      await EMQX.notifyGraphChanged([peerId, id]);
      return send(res, 200, { ok: true });
    }

    if (method === "POST" && url === "/friends/unblock") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const peer = requireString(await readJson(req), "peer", { max: MAX_PEER_IDENTIFIER });
      const peerId = await DB.resolveToId(peer);
      if (!peerId) return send(res, 404, { error: "NOT_FOUND" });
      // Lifting a block does NOT restore the friendship. The pair re-invite like
      // strangers, which is exactly what an ordinary unfriend leaves behind —
      // restoring it silently would hand back a conversation topic the user
      // deliberately tore down.
      const ok = await DB.unblock(id, peerId);
      if (ok) await EMQX.notifyGraphChanged([peerId, id]);
      return send(res, ok ? 200 : 400, { ok });
    }

    // The client needs this to keep a blocked contact visible-but-inert. Absence
    // from /friends otherwise means "delete this row and its history" to
    // DirectorySync, so without this list a block silently destroys the very
    // conversation the user blocked someone over.
    if (method === "GET" && url === "/friends/blocked") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      return send(res, 200, { blocked: await DB.blockedIds(session.id) });
    }

    // --- Prekeys ----------------------------------------------------------
    // The ephemeral half of the initial key agreement (003_prekeys.sql). The
    // server is untrusted here by design: it can withhold one-time keys to force
    // the weaker medium-term fallback, but it cannot read anything, because the
    // initiator also encapsulates to the peer's PINNED identity key and mixes
    // both secrets into the root.
    if (method === "POST" && url === "/prekeys") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const body = await readJson(req);
      const medium = requireHex(body, "medium", HQC_PUBLIC_KEY_BYTES);

      const raw = Array.isArray(body?.oneTime) ? body.oneTime : [];
      if (raw.length > MAX_ONETIME_PER_UPLOAD) {
        throw new HttpError(400, "TOO_MANY_PREKEYS",
          `at most ${MAX_ONETIME_PER_UPLOAD} one-time prekeys per upload`);
      }
      const oneTime = raw.map((entry: unknown, i: number) => {
        const item = entry as Record<string, unknown>;
        const id = item?.id;
        if (!Number.isInteger(id) || (id as number) < 0) {
          throw new HttpError(400, "INVALID_FIELD", `oneTime[${i}].id must be a non-negative integer`);
        }
        return { id: id as number, prekey: requireHex(item, "prekey", HQC_PUBLIC_KEY_BYTES) };
      });

      await DB.putPrekeyBundle(id, medium, oneTime);
      return send(res, 200, { ok: true, accepted: oneTime.length });
    }

    // Claim one prekey for a peer. POST rather than GET with the peer in the
    // path — kept that way now that an id would fit in a URL, because the
    // RESPONSE is key material and has no business in an access log or a proxy
    // cache, and because a claim mutates (it consumes a one-time key).
    if (method === "POST" && url === "/prekeys/claim") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const peer = requireString(await readJson(req), "peer", { max: MAX_PEER_IDENTIFIER });
      const peerId = await DB.resolveToId(peer);
      // Friendship is the authorization. Without it, anyone with a session could
      // drain a stranger's one-time pool — a cheap way to force every one of
      // their future conversations onto the reusable medium-term key.
      if (!peerId || !(await DB.areFriends(id, peerId))) {
        return send(res, 403, { error: "NOT_FRIENDS" });
      }
      const claimed = await DB.claimPrekey(peerId);
      if (!claimed) return send(res, 404, { error: "NO_PREKEYS" });
      return send(res, 200, claimed);
    }

    // How many one-time keys this account has left, so the client knows when to
    // replenish. Only ever about the caller's own pool.
    if (method === "GET" && url === "/prekeys/count") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      return send(res, 200, {
        remaining: await DB.countOneTimePrekeys(id),
        maxId: await DB.maxOneTimePrekeyId(id),
        target: MAX_ONETIME_PER_UPLOAD,
      });
    }

    // --- Push token -------------------------------------------------------
    if (method === "POST" && url === "/push/token") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      const pushBody = await readJson(req);
      const platform = requireString({ platform: pushBody.platform ?? "ios" }, "platform", { max: 16 });
      const token = requireString(pushBody, "token", { min: 8, max: 512 });
      await DB.setPushToken(id, platform, token);
      return send(res, 200, { ok: true });
    }

    // --- Account deletion (purge + revoke MQTT + session tokens) ----------
    if (method === "POST" && url === "/account/delete") {
      const session = await authSession(req);
      if (!session) return send(res, 401, { error: "unauthenticated" });
      const id = session.id;
      await DB.deleteUser(id);
      await DB.revokeMqttAuth(id);
      await DB.revokeSessionToken(bearer(req));
      // Everything above stops the NEXT connect. This ends the current one —
      // otherwise a deleted account keeps a live session, and its queued backlog,
      // for as long as the connection happens to last. It also only started
      // working when the client id stopped being a 14 kB URL path segment.
      await EMQX.kick(id);
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: "not found" });
  } catch (e) {
    // A validation failure is the caller's problem and says which field; anything
    // else is ours, and its detail goes to the log and Sentry rather than to the
    // client. Previously every error came back as a 400 carrying its raw message,
    // which leaked internals (database errors included) to whoever asked.
    if (e instanceof HttpError) {
      return send(res, e.status, { error: e.code, message: e.message });
    }
    logger.error(`[api] ${method} ${url} — ${(e as Error).message}`, e as Error);
    return send(res, 500, { error: "INTERNAL" });
  }
  };
}

// --- Boot -------------------------------------------------------------------
//
// Only when this file is the process entry point. Imported — by a test, or by a
// tool that wants the handler — it defines routes and opens nothing: no socket,
// no Sentry transport, no health-monitor timer keeping the event loop alive, and
// no `process.exit` from assertConfig.
//
// The boot-time INVARIANTS above (MAX_PEER_IDENTIFIER vs PEER_ID_LENGTH, and the
// prekey body against MAX_BODY_BYTES) deliberately stay at module scope. They
// compare two constants in this file and throw; a test that imports this module
// should get the same refusal a deploy would, because a violated one means every
// peer-addressed route refuses every real caller.
if (require.main === module) {
  initObservability("api");

  // Fail fast, before the port opens: this process owns /stripe/webhook and
  // /donate. (Beside the import it would be hoisted over; here it is not.)
  assertConfig(["stripe"]);

  // A donate button that cannot charge is worth a Sentry event, not just a line
  // in a boot log nobody reads after the first rollout. Same escalation
  // push-bridge makes for a half-configured APNs (push/main.ts): the process is
  // fine, the feature is dead, and the only person who can tell is looking
  // somewhere else.
  //
  // It does NOT refuse to boot, deliberately. This process is the whole REST
  // API — directory, friends, push registration, account deletion — and taking
  // all of it down over a broken donate button would be a far worse outage than
  // the one it reports.
  const prices = resolvePrices(process.env);
  if (DONATIONS_ENABLED && donationsDead(prices)) {
    logger.error(`[api] ${donationSummary(prices)}`);
  }

  http.createServer(createApiHandler()).listen(PORT, () => {
    logger.startup(
      `📇 app-api on :${PORT} — REST directory/friends/push/account` +
      (DONATIONS_ENABLED ? ` + ${donationSummary(prices)}` : "")
    );
  });

  // Event-loop / memory / query-latency early warning → Sentry. Same monitor the
  // monolith runs: every service in the stack now reports its own vitals, so a
  // stall or leak in an extracted service is as visible as one in server.ts.
  healthMonitor.start();
}
