// What a `peer` identifier is allowed to be — and why there is now ONE answer.
//
// This file exists because of a bug that reached production with a green suite.
// The bot and the app both identify a peer by its PUBLIC KEY — 14474 hex
// characters — while `/prekeys/claim` capped `peer` at 128, so both were
// refused:
//
//     POST /prekeys/claim → 400 {"error":"INVALID_FIELD",
//                                "message":"peer must be 1–128 characters"}
//
// The e2e suite did not catch it because the test client sent a USERNAME. It
// was exercising an input shape nothing in production uses, so it proved the
// route worked for a caller that does not exist.
//
// The fix at the time was to raise the number to 14474 (#105). The fix now is
// that a peer's identity is 64 characters, so the two forms — id and handle —
// fit under the SAME bound, and the widest thing a peer-addressed route accepts
// stops being "a public key's worth of anything".
//
// The lesson from #105 survives the change and is asserted below: a test that
// picks the convenient identifier form tests nothing.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { requireString, HttpError } from "../lib/http";
import { peerId, isPeerId, PEER_ID_LENGTH } from "../lib/identity";
import { DB } from "../services/db/api";
import { pgAvailable, closePg, NEEDS_PG } from "./pg-helper";

const HQC_PUBLIC_KEY_BYTES = 7237;
const PK_HEX_LENGTH = HQC_PUBLIC_KEY_BYTES * 2;
/** Must match MAX_PEER_IDENTIFIER in api/main.ts. */
const MAX_PEER_IDENTIFIER = 128;
/** The longest handle `setUsername` will accept. */
const MAX_HANDLE = 32;

const pkHex = () => crypto.randomBytes(HQC_PUBLIC_KEY_BYTES).toString("hex");

test("a peer identifier is 64 characters, whatever it names", () => {
  const id = peerId(pkHex());
  assert.equal(id.length, PEER_ID_LENGTH);
  assert.equal(id.length, 64);
  // The number that made this a two-bound problem in the first place.
  assert.equal(PK_HEX_LENGTH, 14474);
  assert.ok(id.length * 226 < PK_HEX_LENGTH, "an id is over two hundred times shorter");
});

test("one bound now serves both forms", () => {
  // #105 raised the claim route to 14474 because an identity WAS a public key.
  // Both a handle and an id fit inside a handle-sized bound now, so the wide one
  // is gone — and with it the route that would accept 14 kB of arbitrary text.
  assert.ok(MAX_PEER_IDENTIFIER >= PEER_ID_LENGTH, "an id fits");
  assert.ok(MAX_PEER_IDENTIFIER >= MAX_HANDLE, "a handle fits");
  assert.ok(MAX_PEER_IDENTIFIER < PK_HEX_LENGTH, "a public key does NOT fit, and need not");
});

test("both real identifier forms pass the bound", () => {
  const id = peerId(pkHex());
  assert.equal(requireString({ peer: id }, "peer", { max: MAX_PEER_IDENTIFIER }), id);
  assert.equal(requireString({ peer: "helper" }, "peer", { max: MAX_PEER_IDENTIFIER }), "helper");
});

test("a full public key is refused — it is no longer an identifier", () => {
  // The exact input both real clients used to send. It is not merely too long:
  // it does not name anybody any more, and a route that accepted it would be
  // accepting 14 kB it cannot do anything with.
  assert.throws(
    () => requireString({ peer: pkHex() }, "peer", { max: MAX_PEER_IDENTIFIER }),
    (e: unknown) => e instanceof HttpError && /1–128 characters/.test((e as Error).message)
  );
});

test("one character past the bound is still refused", () => {
  // The bound is a bound, not an invitation.
  assert.throws(
    () => requireString({ peer: "a".repeat(MAX_PEER_IDENTIFIER + 1) }, "peer", {
      max: MAX_PEER_IDENTIFIER,
    }),
    HttpError
  );
});

test("resolveToId reads an id as an id, without asking the database", async () => {
  // A shape test, not the `length > 50` heuristic it replaces — which worked
  // only because the other form was 14474 characters, and would have read a full
  // public key as an identifier the moment a caller sent one.
  //
  // No Postgres needed for these: an id resolves to itself, and an empty string
  // resolves to nobody, before any query runs.
  const id = peerId(pkHex());
  assert.equal(await DB.resolveToId(id), id, "an id is taken as an id");
  assert.equal(await DB.resolveToId(id.toUpperCase()), id, "…case-insensitively");
  assert.equal(await DB.resolveToId(""), null, "empty is nobody");
});

test("a public key is NOT read as an identifier", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // The regression this shape test exists to prevent: under `length > 50` a
  // 14474-character key came straight back as if it named someone, and every
  // check downstream then ran against a value no row can hold. It falls through
  // to a username lookup now, which finds nothing — which is the truth.
  const key = pkHex();
  assert.ok(!isPeerId(key), "a key does not have the shape of an identifier");
  assert.equal(await DB.resolveToId(key), null, "…so it names nobody");
});

test("an identifier and a handle cannot be confused", async (t) => {
  if (!(await pgAvailable())) return t.skip(NEEDS_PG);
  // Usernames are 3–32 of [A-Za-z0-9_] (setUsername), so nothing a user can
  // claim is 64 hex characters. The two namespaces do not overlap, which is what
  // makes the shape test safe rather than merely convenient.
  assert.ok(MAX_HANDLE < PEER_ID_LENGTH);
  assert.equal(await DB.resolveToId("a".repeat(63)), null, "63 hex is not an id");
  assert.equal(await DB.resolveToId("a".repeat(65)), null, "65 hex is not an id");
  assert.equal(await DB.resolveToId("g".repeat(64)), null, "64 non-hex is not an id");
});

test.after(closePg);
