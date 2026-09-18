import { test } from "node:test";
import { strict as assert } from "node:assert";
import * as nodeCrypto from "node:crypto";

// Exercises the bot's KEM crypto against the real HQC library. The lib is
// These used to skip everywhere but Linux/x86, because lib/hqc.ts named that one
// library outright. It now picks by platform, so they run on a Mac too; the
// guard stays for a host with no library at all. See test/hqc.test.ts
// rather than crashing on import. In CI (ubuntu) they run for real.

test("bot HQC KEM + AES + HKDF round-trip", async (t) => {
  let botCrypto: typeof import("../bot/crypto");
  let hqc: typeof import("../lib/hqc");
  try {
    botCrypto = await import("../bot/crypto");
    hqc = await import("../lib/hqc");
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }

  const { hqcEncapsulate, hqcDecapsulate, aesEncrypt, aesDecrypt, deriveSharedKey, freshSeed } = botCrypto;
  const { HqcWrapper } = hqc;

  // Deterministic keypair from a seed; the public key is reproducible.
  const seed = nodeCrypto.randomBytes(32);
  const { pk, sk } = HqcWrapper.keypairFromSeed(seed);
  assert.ok(HqcWrapper.keypairFromSeed(seed).pk.equals(pk), "keygen is deterministic (stable pk)");

  // KEM: encapsulate → (ct, ss); decapsulate recovers the same 32-byte secret.
  const { ct, ss } = hqcEncapsulate(pk);
  assert.equal(ss.length, 32, "shared secret is 32 bytes");
  assert.ok(hqcDecapsulate(sk, ct).equals(ss), "KEM encapsulate/decapsulate agree");

  // A different encapsulation yields a different (fresh) shared secret.
  assert.ok(!hqcEncapsulate(pk).ss.equals(ss), "each encapsulation is fresh");

  // AES-GCM (the Swift [IV][tag][ct] layout) round-trips, incl. emoji.
  const key = nodeCrypto.randomBytes(32);
  const enc = aesEncrypt("hello, post-quantum 🔒", key);
  assert.equal(aesDecrypt(enc, key), "hello, post-quantum 🔒", "AES round-trip");

  // Shared-key derivation is order-independent (both peers get the same key).
  const a = freshSeed();
  const b = freshSeed();
  assert.ok(deriveSharedKey(a, b).equals(deriveSharedKey(b, a)), "HKDF symmetry");
  assert.equal(deriveSharedKey(a, b).length, 32, "AES-256 key length");
});

// A GCM verifier that will compare fewer bytes than it should is a forgery
// oracle: a 4-byte tag is guessable at 2^-32 instead of 2^-128. Node accepts a
// short tag unless `authTagLength` says otherwise, and `subarray` hands one over
// silently when the payload is truncated — so the length is both declared to the
// cipher and checked before `setAuthTag`. This pins the check.
test("aesDecrypt refuses a truncated GCM tag", async (t) => {
  let botCrypto: typeof import("../bot/crypto");
  try {
    botCrypto = await import("../bot/crypto");
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }
  const { aesEncrypt, aesDecrypt } = botCrypto;

  const key = nodeCrypto.randomBytes(32);
  const sealed = Buffer.from(aesEncrypt("hello", key), "base64");
  assert.equal(aesDecrypt(sealed.toString("base64"), key), "hello", "round-trip still works");

  // iv(12) + tag(16) + ct — chop the payload so the tag slice comes up short.
  for (const tagBytes of [0, 4, 8, 15]) {
    const truncated = sealed.subarray(0, 12 + tagBytes);
    assert.throws(
      () => aesDecrypt(truncated.toString("base64"), key),
      /truncated GCM tag/,
      `a ${tagBytes}-byte tag is rejected by length, before any verification`
    );
  }

  // A full-length but wrong tag must still fail — on authentication, not length.
  const forged = Buffer.from(sealed);
  forged.writeUInt8(forged.readUInt8(12) ^ 0xff, 12);
  assert.throws(() => aesDecrypt(forged.toString("base64"), key),
    (e: Error) => !/truncated GCM tag/.test(e.message),
    "a 16-byte forgery is refused by GCM itself");
});

// The AAD parameter exists so the v2 frame header can be bound to the payload it
// selects the key for. Three properties matter, and all three are load-bearing:
// it must round-trip, a changed header must break the tag, and omitting AAD must
// stay byte-compatible with a sealer that never passed any.
test("aesEncrypt/aesDecrypt bind additional authenticated data", async (t) => {
  let botCrypto: typeof import("../bot/crypto");
  try {
    botCrypto = await import("../bot/crypto");
  } catch {
    return t.skip("HQC native lib unavailable on this platform");
  }
  const { aesEncrypt, aesDecrypt } = botCrypto;

  const key = nodeCrypto.randomBytes(32);
  const header = Buffer.from(JSON.stringify({ n: 7, pn: 0, t: "msg" }), "utf8");

  const sealed = aesEncrypt("attack at dawn", key, header);
  assert.equal(aesDecrypt(sealed, key, header), "attack at dawn", "AAD round-trips");

  // A tampered header must not open, even though the ciphertext is untouched.
  // This is the TM-1 case: today `epoch`/`idx` ride outside the AEAD.
  const tampered = Buffer.from(JSON.stringify({ n: 8, pn: 0, t: "msg" }), "utf8");
  assert.throws(() => aesDecrypt(sealed, key, tampered),
    "a modified header fails the tag check");
  assert.throws(() => aesDecrypt(sealed, key),
    "dropping the header entirely fails too");

  // And a sealer that passes no AAD is unchanged — the parameter is additive, so
  // the epoch-0 path and every existing caller keep working untouched.
  const plain = aesEncrypt("no aad here", key);
  assert.equal(aesDecrypt(plain, key), "no aad here", "omitting AAD is the old behaviour");
  assert.throws(() => aesDecrypt(plain, key, header),
    "AAD cannot be added after the fact");
});
