// The v1 MQTT CONNECT proof's pure half (lib/mqtt-proof.ts): the signed bytes,
// the password grammar, the timestamp window. The auth hook that uses them is
// driven end to end, against a real database, in auth-routes.test.ts.
//
// The vectors are READ from the file the Swift suite reads too
// (apps/apple/tests/MQTTProofTests.swift): one byte of disagreement about the
// signed message and every CONNECT is refused with nothing but "deny" to show
// for it.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  MQTT_PROOF_CONTEXT,
  MQTT_PROOF_SKEW_SECONDS,
  MQTT_PROOF_NONCE_TTL_SECONDS,
  proofMessage,
  formatProofPassword,
  parseProofPassword,
  isV1Password,
  isFreshTimestamp,
  verifyProofSignature,
  ed25519PublicKey,
} from "../lib/mqtt-proof";

const vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, "helpers", "mqtt-proof-vectors.json"), "utf8"),
);

test("the vector file describes this implementation", () => {
  assert.equal(vectors.context, MQTT_PROOF_CONTEXT);
  assert.equal(vectors.skewSeconds, MQTT_PROOF_SKEW_SECONDS);
  assert.ok(vectors.cases.length >= 3);
});

for (const v of vectors.cases) {
  test(`vector: ${v.label}`, () => {
    const nonce = Buffer.from(v.nonceHex, "hex");
    const message = proofMessage(v.clientid, v.keyId, v.ts, nonce);
    assert.equal(message.toString("hex"), v.messageHex, "signed bytes");

    const sig = Buffer.from(v.signatureHex, "hex");
    const pub = Buffer.from(v.publicKeyHex, "hex");
    assert.ok(verifyProofSignature(pub, message, sig), "pinned signature verifies");

    assert.equal(formatProofPassword({ keyId: v.keyId, ts: v.ts, nonce, sig }), v.connectField);
    const parsed = parseProofPassword(v.connectField);
    assert.ok(parsed);
    assert.equal(parsed.keyId, v.keyId);
    assert.equal(parsed.ts, v.ts);
    assert.ok(parsed.nonce.equals(nonce));
    assert.ok(parsed.sig.equals(sig));
  });
}

test("a signature does not transfer to another clientid, key id, timestamp or nonce", () => {
  const v = vectors.cases[0];
  const nonce = Buffer.from(v.nonceHex, "hex");
  const sig = Buffer.from(v.signatureHex, "hex");
  const pub = Buffer.from(v.publicKeyHex, "hex");
  const other = vectors.cases[2];
  for (const [label, msg] of [
    ["clientid", proofMessage(other.clientid, v.keyId, v.ts, nonce)],
    ["keyId", proofMessage(v.clientid, other.keyId, v.ts, nonce)],
    ["ts", proofMessage(v.clientid, v.keyId, v.ts + 1, nonce)],
    ["nonce", proofMessage(v.clientid, v.keyId, v.ts, Buffer.from(other.nonceHex, "hex"))],
  ] as const) {
    assert.equal(verifyProofSignature(pub, msg, sig), false, label);
  }
  assert.equal(verifyProofSignature(Buffer.from(other.publicKeyHex, "hex"),
    proofMessage(v.clientid, v.keyId, v.ts, nonce), sig), false, "another key");
});

test("the password grammar is exact", () => {
  const good = vectors.cases[0].connectField as string;
  assert.ok(isV1Password(good));
  assert.ok(parseProofPassword(good));
  // A legacy token is 64 hex characters; it can never be mistaken for v1.
  assert.equal(isV1Password(crypto.randomBytes(32).toString("hex")), false);

  const [, keyId, ts, nonce, sig] = good.split(".");
  const bad = [
    "",
    "v1.",
    good + ".",
    good + "=",
    `v2.${keyId}.${ts}.${nonce}.${sig}`,
    `v1.${keyId!.toUpperCase()}.${ts}.${nonce}.${sig}`,
    `v1.${keyId!.slice(1)}.${ts}.${nonce}.${sig}`,
    `v1.${keyId}.0${ts}.${nonce}.${sig}`,            // leading zero: two spellings of one time
    `v1.${keyId}.-${ts}.${nonce}.${sig}`,
    `v1.${keyId}.${ts}.${nonce}==.${sig}`,           // padding
    `v1.${keyId}.${ts}.${nonce!.replace(/-/g, "+").replace(/_/g, "/")}x.${sig}`,
    `v1.${keyId}.${ts}.${nonce}.${sig!.slice(0, -1)}`,
    ` ${good}`,
  ];
  for (const p of bad) assert.equal(parseProofPassword(p), null, JSON.stringify(p));
});

test("non-canonical base64url spellings are refused", () => {
  // 16 bytes is 22 base64url characters with 4 spare bits in the last one. A
  // last character that differs only in those bits decodes to the same bytes;
  // accepting it would give one proof several passwords.
  const v = vectors.cases[0];
  const [, keyId, ts, nonce, sig] = (v.connectField as string).split(".");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(nonce!.at(-1)!);
  const twin = alphabet[last ^ 1]!;   // flips a padding bit
  const alt = `v1.${keyId}.${ts}.${nonce!.slice(0, -1)}${twin}.${sig}`;
  assert.ok(Buffer.from(nonce!.slice(0, -1) + twin, "base64url").equals(Buffer.from(nonce!, "base64url")),
    "the twin really does decode to the same bytes");
  assert.equal(parseProofPassword(alt), null);
});

test("the timestamp window is ±skew, inclusive", () => {
  const now = 1_790_000_000;
  assert.ok(isFreshTimestamp(now, now));
  assert.ok(isFreshTimestamp(now - MQTT_PROOF_SKEW_SECONDS, now));
  assert.ok(isFreshTimestamp(now + MQTT_PROOF_SKEW_SECONDS, now));
  assert.equal(isFreshTimestamp(now - MQTT_PROOF_SKEW_SECONDS - 1, now), false);
  assert.equal(isFreshTimestamp(now + MQTT_PROOF_SKEW_SECONDS + 1, now), false);
  assert.equal(isFreshTimestamp(Number.NaN, now), false);
  assert.equal(isFreshTimestamp(now + 0.5, now), false, "not an integer");
});

test("a spent nonce outlives every timestamp that could still be accepted with it", () => {
  // A timestamp at the far edge of the window stays acceptable for 2×skew
  // after the earliest moment it could have been used.
  assert.ok(MQTT_PROOF_NONCE_TTL_SECONDS >= 2 * MQTT_PROOF_SKEW_SECONDS);
});

test("only a real 32-byte Ed25519 key is a key", () => {
  assert.equal(ed25519PublicKey(Buffer.alloc(31)), null);
  assert.equal(ed25519PublicKey(Buffer.alloc(33)), null);
  const v = vectors.cases[0];
  assert.ok(ed25519PublicKey(Buffer.from(v.publicKeyHex, "hex")));
  assert.equal(verifyProofSignature(Buffer.alloc(31), Buffer.alloc(1), Buffer.alloc(64)), false);
  assert.equal(verifyProofSignature(Buffer.from(v.publicKeyHex, "hex"), Buffer.alloc(1), Buffer.alloc(63)), false);
});

test("newSigningKey + signConnect produce passwords the verifier accepts, fresh each time", () => {
  const { newSigningKey, signConnect } = require("../lib/mqtt-proof") as typeof import("../lib/mqtt-proof");
  const k = newSigningKey();
  const pub = Buffer.from(k.publicKeyB64, "base64");
  assert.equal(pub.length, 32);
  const clientid = "ab".repeat(32), keyId = "0f".repeat(16);
  const a = signConnect({ clientid, keyId, privateKey: k.privateKey, nowSec: 1_790_000_000.9 });
  const b = signConnect({ clientid, keyId, privateKey: k.privateKey, nowSec: 1_790_000_000 });
  assert.notEqual(a, b, "a new nonce every CONNECT");
  for (const pw of [a, b]) {
    const p = parseProofPassword(pw);
    assert.ok(p);
    assert.equal(p.ts, 1_790_000_000, "whole seconds");
    assert.ok(verifyProofSignature(pub, proofMessage(clientid, keyId, p.ts, p.nonce), p.sig));
  }
});
