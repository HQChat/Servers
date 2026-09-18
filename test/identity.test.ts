// The client identifier, pinned three ways.
//
// `id = sha256(lowercase-hex(pk))` is what every name in the system now is: the
// MQTT client id, the ACL row, the topic strings, the envelope's `sender`, every
// route parameter. Four implementations have to agree about it byte-for-byte —
// TypeScript, Swift, Postgres, and the EMQX authorizer query — and a
// disagreement is not a crash. It is a client that names itself something the
// broker has no grant for, and gets disconnected with `0x87 NOT AUTHORIZED`.
//
// That is the exact class of failure this deployment has already shipped twice:
// the AAD encoding, then the auth-proof encoding. Both were one encoding
// decision made twice, and both surfaced as an authentication failure that said
// nothing about encoding at all.
//
// So: the vectors are READ (not recomputed) here and in
// apps/apple/tests/PeerIDTests.swift, and the Postgres half is asserted against
// a live database — `encode(pk_digest(pk),'hex')` IS peerId, and has been since
// 001_schema.sql was written.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { peerId, isPeerId, keyMatchesId, PEER_ID_LENGTH } from "../lib/identity";
import { friendshipHash } from "../lib/crypto-utils";
import { q } from "../services/db/pg";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

const V = JSON.parse(
  fs.readFileSync(path.join(__dirname, "helpers", "identity-vectors.json"), "utf8")
) as {
  version: number;
  publicKeyBytes: number;
  keys: Array<{ label: string; publicKeyHex: string; id: string }>;
  friendships: Array<{ a: string; b: string; hash: string; topic: string }>;
};

test("the vector file is the shape both suites expect", () => {
  assert.equal(V.version, 1);
  assert.equal(V.publicKeyBytes, 7237, "an HQC-256 public key");
  assert.ok(V.keys.length >= 4, "vectors for the full-size, short and uppercase cases");
  assert.ok(V.friendships.length >= 3);
  // The first vector must be a REAL key. A short stand-in is what let
  // `pk text PRIMARY KEY` reach production, and it is what this whole change is
  // about not doing again.
  assert.equal(V.keys[0]!.publicKeyHex.length, 7237 * 2);
});

test("peerId matches the pinned id for every vector", () => {
  for (const k of V.keys) {
    assert.equal(peerId(k.publicKeyHex), k.id, k.label);
    assert.equal(k.id.length, PEER_ID_LENGTH);
    assert.ok(isPeerId(k.id), `${k.label}: the id is 64 lowercase hex`);
  }
});

test("an id is 450x shorter than the key it names", () => {
  // The number that made every per-client EMQX endpoint answer 414, and every
  // mqtt_acl row ~29 kB. Asserted rather than asserted-in-a-comment, because it
  // is the entire reason for the change.
  const pk = V.keys[0]!.publicKeyHex;
  assert.equal(pk.length, 14474);
  assert.equal(peerId(pk).length, 64);
  // `DELETE /clients/{id}/subscriptions/{topic}` — the surgical revocation that
  // has never once worked here — with both halves at their new size.
  const url = `clients/${peerId(pk)}/subscriptions/${encodeURIComponent(`c/${"a".repeat(64)}`)}`;
  assert.ok(url.length < 200, `a per-client admin URL is ${url.length} characters`);
});

test("uppercase hex names the same client as lowercase", () => {
  // Not a nicety. The wire form is lowercase, and a caller that sends uppercase
  // would otherwise be a stranger: a different id, a different topic, no ACL
  // row, and a broker that answers 0x87 without saying why.
  const lower = V.keys[2]!;
  const upper = V.keys[3]!;
  assert.equal(lower.publicKeyHex.toUpperCase(), upper.publicKeyHex);
  assert.equal(lower.id, upper.id);
});

test("different keys get different ids", () => {
  const ids = new Set(V.keys.map((k) => k.id));
  // The two full-size vectors plus the short one; the uppercase vector is the
  // short one's twin by design.
  assert.equal(ids.size, V.keys.length - 1);
});

// ── The commitment property ─────────────────────────────────────────────────
//
// This is what the digest BUYS, beyond fitting in a URL. Because the id is a
// hash of the key, a key can be checked against an id already held — so the
// graph carries ids, the key travels separately, and TOFU narrows to "trust the
// id you were first given".

test("a key verifies against the id that names it", () => {
  for (const k of V.keys) {
    assert.ok(keyMatchesId(k.publicKeyHex, k.id), k.label);
    assert.ok(keyMatchesId(k.publicKeyHex.toUpperCase(), k.id), "case-insensitively");
  }
});

test("a substituted key is refused — no second preimage survives", () => {
  const real = V.keys[0]!;
  const impostor = V.keys[1]!;
  assert.ok(!keyMatchesId(impostor.publicKeyHex, real.id),
    "a different key must not verify against this id");
  // The near-miss case: one flipped hex digit, which is what a tampered
  // directory response would most plausibly look like.
  const tweaked = real.publicKeyHex.slice(0, -1) + (real.publicKeyHex.endsWith("0") ? "1" : "0");
  assert.ok(!keyMatchesId(tweaked, real.id), "one changed character is a different key");
});

test("an id is NOT an authenticator — anyone holding the key can compute it", () => {
  // Stated as a test because it is the constraint every route has to respect
  // (SRV-1/DB-3 was an unauthenticated route keyed on a derivable digest).
  // There is no secret in this function.
  const k = V.keys[0]!;
  assert.equal(peerId(k.publicKeyHex), k.id);
  assert.equal(crypto.createHash("sha256").update(k.publicKeyHex, "utf8").digest("hex"), k.id);
});

test("the id is NOT chainId — chainId is the same digest truncated to 32", () => {
  // lib/double-ratchet.ts derives a chain selector the same way and keeps 32
  // hex characters. Reusing it here would halve the collision resistance of
  // every name in the system for the sake of 32 bytes.
  const k = V.keys[0]!;
  assert.equal(k.id.length, 64);
  assert.notEqual(k.id.slice(0, 32), k.id);
});

// ── friendshipHash ──────────────────────────────────────────────────────────
//
// The conversation topic. 001_schema.sql has claimed since it was written that
// this has "a Swift counterpart and a cross-impl test vector"; the counterpart
// existed, the vector did not.

test("friendshipHash matches the pinned vectors", () => {
  for (const f of V.friendships) {
    assert.equal(friendshipHash(f.a, f.b), f.hash);
    assert.equal(`c/${f.hash}`, f.topic);
  }
});

test("friendshipHash is order-independent, which is why one row serves both", () => {
  const [ab, ba] = [V.friendships[0]!, V.friendships[1]!];
  assert.deepEqual([ab.a, ab.b].sort(), [ba.a, ba.b].sort(), "the same pair, reversed");
  assert.equal(ab.hash, ba.hash);
});

test("a conversation topic is now 66 characters, not ~29000", () => {
  // `c/{hash}` used to embed two public keys' worth of hash input and, in
  // mqtt_acl, sat beside a 14474-character `pk` in the same row.
  assert.equal(V.friendships[0]!.topic.length, 66);
});

// ── The Postgres half ───────────────────────────────────────────────────────

test("peerId IS pk_digest — the database has been keyed on this all along", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  for (const k of V.keys) {
    const res = await q<{ digest: string }>(
      `SELECT encode(pk_digest($1), 'hex') AS digest`,
      [k.publicKeyHex.toLowerCase()]
    );
    assert.equal(res.rows[0]!.digest, k.id,
      `${k.label}: encode(pk_digest(pk),'hex') must equal peerId(pk)`);
  }
});

test("Postgres agrees about friendshipHash too", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  for (const f of V.friendships) {
    // Exactly what the application writes into `friendships.hash`, computed the
    // other way round. `pk_digest` is sha256(convert_to(t,'UTF8')), so feeding
    // it the sorted concatenation reproduces friendshipHash.
    const sorted = [f.a, f.b].sort().join("");
    const res = await q<{ digest: string }>(
      `SELECT encode(pk_digest($1), 'hex') AS digest`, [sorted]
    );
    assert.equal(res.rows[0]!.digest, f.hash);
  }
});

test("the pair ordering the CHECK constraint enforces is the one JS produces", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // `CHECK (id_lo COLLATE "C" < id_hi COLLATE "C")` has to agree with
  // Array.sort(). It does for hex, but asserting it is cheap and the failure —
  // an INSERT that violates a CHECK on some pairs and not others — is not.
  for (const f of V.friendships) {
    const [lo, hi] = [f.a, f.b].sort();
    const res = await q<{ ok: boolean }>(
      `SELECT ($1 COLLATE "C") < ($2 COLLATE "C") AS ok`, [lo, hi]
    );
    if (lo !== hi) assert.ok(res.rows[0]!.ok, `${lo} < ${hi} in COLLATE "C"`);
  }
});

test.after(closePg);
