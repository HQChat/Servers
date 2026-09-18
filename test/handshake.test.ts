// The initiator-authentication step, and the attack it exists to stop.
//
// The attack, reproduced in the second audit: C is any accepted friend of A. C
// fetches B's public key (GET /peer/{id}/key needs no session), claims A's
// prekey bundle, runs the ordinary initiator path, and writes B's id and B's
// real key into the frame. Every check passes, because every value C used was
// public. A stores a message attributed to B and can never talk to the real B
// again.
//
// Nothing in the frame could have caught it. A KEM cannot authenticate a sender
// in one flight — encapsulation demonstrates the RECIPIENT's secret, never the
// sender's — so the fix is a round trip, and it is an HQC round trip rather
// than a second primitive.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  handshakeNonce,
  handshakeProof,
  handshakeProofMatches,
  encodeHandshake,
  decodeHandshake,
  HANDSHAKE_NONCE_BYTES,
  HANDSHAKE_PROOF_BYTES,
} from "../lib/handshake";
import { peerId } from "../lib/identity";

/** A stub KEM with HQC's shape, implicit rejection included. */
function stubKem() {
  return {
    keypair() { const t = crypto.randomBytes(32); return { pk: t, sk: t }; },
    encapsulate(pk: Buffer) {
      const ss = crypto.randomBytes(32);
      const mask = crypto.createHash("sha256").update(pk).digest();
      const body = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) body[i] = ss[i]! ^ mask[i]!;
      return { ct: Buffer.concat([mask, body]), ss };
    },
    decapsulate(sk: Buffer, ct: Buffer) {
      const mask = crypto.createHash("sha256").update(sk).digest();
      // Implicit rejection: a ciphertext that was not encapsulated to this key
      // yields a pseudo-random secret, never an error. That is what makes the
      // proof — rather than the decapsulation — the thing that decides.
      if (ct.length !== 64 || !ct.subarray(0, 32).equals(mask)) {
        return crypto.createHash("sha256").update(Buffer.concat([sk, ct])).digest();
      }
      const ss = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) ss[i] = ct[32 + i]! ^ mask[i]!;
      return ss;
    },
  };
}

const kem = stubKem();
const idOf = (pk: Buffer) => peerId(Buffer.concat([pk, Buffer.alloc(7237 - pk.length)]).toString("hex"));

test("the real peer answers a challenge, and A accepts", () => {
  const b = kem.keypair();
  const aId = peerId(crypto.randomBytes(7237).toString("hex"));
  const bId = idOf(b.pk);

  // A challenges: an ordinary HQC encapsulation to B's IDENTITY key.
  const nonce = handshakeNonce();
  const { ct, ss } = kem.encapsulate(b.pk);
  const expected = handshakeProof(ss, nonce, aId, bId);

  // B decapsulates with the one secret only B holds, and returns HKDF of it —
  // never the secret, so this is not a decryption oracle.
  const bSs = kem.decapsulate(b.sk, ct);
  const offered = handshakeProof(bSs, nonce, aId, bId);

  assert.ok(handshakeProofMatches(expected, offered), "the real B proves it");
});

test("an impersonator cannot answer — this is finding 01, closed", () => {
  const b = kem.keypair();          // B, whose key C wants to speak under
  const c = kem.keypair();          // C, the attacker: a friend of A
  const aId = peerId(crypto.randomBytes(7237).toString("hex"));
  const bId = idOf(b.pk);

  // C has B's PUBLIC key and nothing else. A encapsulates to it.
  const nonce = handshakeNonce();
  const { ct, ss } = kem.encapsulate(b.pk);
  const expected = handshakeProof(ss, nonce, aId, bId);

  // C decapsulates with the only secret it has. HQC rejects implicitly, so this
  // SUCCEEDS and yields a pseudo-random secret — the failure has to surface at
  // the proof, and it does.
  const cSs = kem.decapsulate(c.sk, ct);
  const forged = handshakeProof(cSs, nonce, aId, bId);

  assert.ok(!handshakeProofMatches(expected, forged),
    "C holds B's public key and still cannot produce the proof");
});

test("a proof is bound to its nonce, so it cannot be replayed", () => {
  const b = kem.keypair();
  const aId = peerId(crypto.randomBytes(7237).toString("hex"));
  const bId = idOf(b.pk);
  const { ct, ss } = kem.encapsulate(b.pk);

  const first = handshakeNonce();
  const second = handshakeNonce();
  const answered = handshakeProof(kem.decapsulate(b.sk, ct), first, aId, bId);

  assert.ok(!handshakeProofMatches(handshakeProof(ss, second, aId, bId), answered),
    "yesterday's proof does not answer today's challenge");
});

test("a proof is bound to BOTH ids, in order", () => {
  const b = kem.keypair();
  const aId = peerId(crypto.randomBytes(7237).toString("hex"));
  const dId = peerId(crypto.randomBytes(7237).toString("hex"));
  const bId = idOf(b.pk);
  const nonce = handshakeNonce();
  const { ct, ss } = kem.encapsulate(b.pk);
  const answered = handshakeProof(kem.decapsulate(b.sk, ct), nonce, aId, bId);

  // The same proof presented as though it answered a different challenger…
  assert.ok(!handshakeProofMatches(handshakeProof(ss, nonce, dId, bId), answered),
    "a proof made for A does not satisfy D");
  // …or with the roles swapped, which is what a reflection would need.
  assert.ok(!handshakeProofMatches(handshakeProof(ss, nonce, bId, aId), answered),
    "the two ids are bound in order, so a proof cannot be reflected");
});

test("the challenge and proof frames round-trip, and refuse garbage", () => {
  const aId = peerId(crypto.randomBytes(7237).toString("hex"));
  const bId = peerId(crypto.randomBytes(7237).toString("hex"));
  const nonce = handshakeNonce();
  const ct = crypto.randomBytes(14421);
  const proof = crypto.randomBytes(HANDSHAKE_PROOF_BYTES);

  const chal = encodeHandshake({ kind: "chal", from: aId, to: bId, nonce, ct });
  const gotChal = decodeHandshake(chal);
  assert.ok(gotChal && gotChal.kind === "chal");
  assert.equal(gotChal!.from, aId);
  assert.equal(gotChal!.to, bId);
  assert.ok(gotChal!.nonce.equals(nonce));
  assert.ok(gotChal!.ct!.equals(ct));

  const pf = encodeHandshake({ kind: "proof", from: bId, to: aId, nonce, proof });
  const gotPf = decodeHandshake(pf);
  assert.ok(gotPf && gotPf.kind === "proof");
  assert.ok(gotPf!.proof!.equals(proof));

  for (const [name, bytes] of [
    ["empty", Buffer.alloc(0)],
    ["magic only", Buffer.from("HQCH", "ascii")],
    ["truncated challenge", chal.subarray(0, chal.length - 1)],
    ["trailing byte", Buffer.concat([pf, Buffer.from([0])])],
    ["bad magic", Buffer.concat([Buffer.from("XXXX"), chal.subarray(4)])],
    ["unknown kind", (() => { const b = Buffer.from(pf); b.writeUInt8(9, 5); return b; })()],
    ["wrong version", (() => { const b = Buffer.from(pf); b.writeUInt8(2, 4); return b; })()],
    ["huge ct length", (() => { const b = Buffer.from(chal); b.writeUInt32BE(0x0ffffff0, 102); return b; })()],
  ] as [string, Buffer][]) {
    let out: unknown;
    assert.doesNotThrow(() => { out = decodeHandshake(bytes); }, `${name} must not throw`);
    assert.equal(out, null, `${name} must be refused`);
  }
});

test("a malformed proof is refused rather than throwing", () => {
  // `timingSafeEqual` throws on a length mismatch, which on the receive path
  // would turn a short proof into an exception instead of a refusal.
  const expected = crypto.randomBytes(HANDSHAKE_PROOF_BYTES);
  assert.doesNotThrow(() => handshakeProofMatches(expected, Buffer.alloc(4)));
  assert.equal(handshakeProofMatches(expected, Buffer.alloc(4)), false);
  assert.equal(handshakeProofMatches(expected, Buffer.alloc(0)), false);
});

test("the nonce is the documented width, and fresh", () => {
  const a = handshakeNonce();
  const b = handshakeNonce();
  assert.equal(a.length, HANDSHAKE_NONCE_BYTES);
  assert.ok(!a.equals(b), "two challenges do not share a nonce");
});
