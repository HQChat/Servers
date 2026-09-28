// hqn/1 (lib/noise.ts): the hybrid Noise handshake the raw-TCP transport runs.
//
// Three layers of evidence, weakest first:
//   - it round-trips, with the real HQC-256 library;
//   - it refuses every tampered, truncated or replayed input it should;
//   - its bytes match test/helpers/noise-hqn-vectors.json, which the Swift
//     implementation (apps/apple/tests/NoiseHQNTests.swift) reads too — two
//     independent implementations agreeing on every byte of the transcript.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  HqnInitiator,
  HqnResponder,
  CipherState,
  FrameReader,
  NoiseError,
  x25519KeyPair,
  dh,
  hkdf2,
  frame,
  sealFrames,
  msg1Length,
  nkInitiatorMessage1,
  nkResponderMessage2,
  MAX_FRAME,
  MAX_FRAME_PLAINTEXT,
  HQC_CIPHERTEXT_BYTES,
  HQC_PUBLIC_KEY_BYTES,
  HQN_VERSION,
  type Kem,
  type ServerStatic,
} from "../lib/noise";

// --- Fixtures -------------------------------------------------------------------

/** A stand-in KEM with the real sizes: ss = sha256(ct), ct random. Lets the
 *  handshake be exercised without the native library; the real one is below. */
const fakeKem: Kem = {
  encapsulate: () => {
    const ct = crypto.randomBytes(HQC_CIPHERTEXT_BYTES);
    return { ct, ss: crypto.createHash("sha256").update(ct).digest() };
  },
  decapsulate: (_sk, ct) => crypto.createHash("sha256").update(ct).digest(),
};

function fakeServer(keyId = 1): ServerStatic {
  return {
    keyId,
    x25519: x25519KeyPair(),
    hqc: { pk: crypto.randomBytes(HQC_PUBLIC_KEY_BYTES), sk: crypto.randomBytes(7333) },
  };
}

const pub = (s: ServerStatic) => ({ keyId: s.keyId, x25519: s.x25519.pub, hqc: s.hqc.pk });

function handshake(server: ServerStatic, payload1: Buffer, payload2 = Buffer.alloc(0), kem: Kem = fakeKem) {
  const client = new HqnInitiator(pub(server), { kem });
  const msg1 = client.writeMessage1(payload1);
  const responder = new HqnResponder(server, { kem });
  const got1 = responder.readMessage1(msg1);
  const { message: msg2, transport: serverT } = responder.writeMessage2(payload2);
  const { payload: got2, transport: clientT } = client.readMessage2(msg2);
  return { msg1, msg2, got1, got2, clientT, serverT };
}

// --- Round trips ------------------------------------------------------------------

test("a handshake carries both payloads and yields matching transports", () => {
  const server = fakeServer();
  const connect = Buffer.from("MQTT CONNECT bytes");
  const { msg1, got1, got2, clientT, serverT } = handshake(server, connect, Buffer.from("ok"));
  assert.ok(got1.equals(connect), "the CONNECT arrives");
  assert.equal(got2.toString(), "ok");
  assert.equal(msg1.length, msg1Length(connect.length), "msg1 has exactly the advertised length");
  assert.ok(clientT.handshakeHash.equals(serverT.handshakeHash), "both ends agree on the transcript");

  for (let i = 0; i < 3; i++) {
    const up = Buffer.from(`up ${i}`);
    assert.ok(serverT.recv.decryptWithAd(Buffer.alloc(0), clientT.send.encryptWithAd(Buffer.alloc(0), up)).equals(up));
    const down = Buffer.from(`down ${i}`);
    assert.ok(clientT.recv.decryptWithAd(Buffer.alloc(0), serverT.send.encryptWithAd(Buffer.alloc(0), down)).equals(down));
  }
});

test("the payload in msg1 is not visible on the wire", () => {
  const marker = Buffer.from("clientid=0123456789abcdef-SECRET-MARKER");
  const { msg1 } = handshake(fakeServer(), marker);
  assert.equal(msg1.indexOf(marker), -1);
});

test("each direction has its own key", () => {
  const { clientT } = handshake(fakeServer(), Buffer.from("x"));
  const pt = Buffer.from("same plaintext");
  const up = clientT.send.encryptWithAd(Buffer.alloc(0), pt);
  // The client decrypting its OWN upstream frame with its downstream key fails:
  // a reflected frame is not accepted as the server's.
  assert.throws(() => clientT.recv.decryptWithAd(Buffer.alloc(0), up), NoiseError);
});

test("the real HQC-256 library completes a handshake", async (t) => {
  let HqcWrapper: typeof import("../lib/hqc").HqcWrapper;
  try {
    ({ HqcWrapper } = await import("../lib/hqc"));
  } catch (e) {
    return t.skip(`native HQC library unavailable: ${(e as Error).message}`);
  }
  const kp = HqcWrapper.keypairFromSeed(crypto.randomBytes(32));
  const server: ServerStatic = { keyId: 7, x25519: x25519KeyPair(), hqc: { pk: kp.pk, sk: kp.sk } };
  // No KEM passed: the production default, which loads the native library.
  const client = new HqnInitiator(pub(server));
  const responder = new HqnResponder(server);
  assert.equal(responder.readMessage1(client.writeMessage1(Buffer.from("real"))).toString(), "real");
  const { message, transport: serverT } = responder.writeMessage2(Buffer.alloc(0));
  const { transport: clientT } = client.readMessage2(message);
  assert.ok(clientT.handshakeHash.equals(serverT.handshakeHash));
});

// --- Refusals ---------------------------------------------------------------------

test("a pinned server key of the wrong size is refused up front", () => {
  const s = fakeServer();
  assert.throws(() => new HqnInitiator({ ...pub(s), x25519: Buffer.alloc(31) }), NoiseError);
  assert.throws(() => new HqnInitiator({ ...pub(s), hqc: Buffer.alloc(HQC_PUBLIC_KEY_BYTES - 1) }), NoiseError);
  assert.throws(() => x25519KeyPair(Buffer.alloc(31)), NoiseError);
  assert.throws(() => dh(x25519KeyPair().priv, Buffer.alloc(31)), NoiseError);
});

test("a KEM that returns the wrong sizes is refused", () => {
  const s = fakeServer();
  const short: Kem = { ...fakeKem, encapsulate: () => ({ ct: Buffer.alloc(10), ss: Buffer.alloc(32) }) };
  assert.throws(() => new HqnInitiator(pub(s), { kem: short }).writeMessage1(Buffer.alloc(0)), NoiseError);
});

test("a short msg2 is refused", () => {
  const s = fakeServer();
  const client = new HqnInitiator(pub(s), { kem: fakeKem });
  client.writeMessage1(Buffer.alloc(0));
  assert.throws(() => client.readMessage2(Buffer.alloc(47)), NoiseError);
  assert.throws(() => HqnResponder.ephemeralOf(Buffer.alloc(31)), NoiseError);
  assert.equal(HqnResponder.ephemeralOf(Buffer.alloc(40, 7)).length, 32);
});

test("a bit flip anywhere in msg1 is refused", () => {
  const server = fakeServer();
  const client = new HqnInitiator(pub(server), { kem: fakeKem });
  const msg1 = client.writeMessage1(Buffer.from("connect"));
  // Positions in each region: the ephemeral key, the encrypted KEM ciphertext,
  // its tag, and the encrypted payload.
  for (const pos of [0, 31, 32, 5000, 32 + HQC_CIPHERTEXT_BYTES + 3, msg1.length - 1]) {
    const bad = Buffer.from(msg1);
    bad[pos]! ^= 0x01;
    assert.throws(() => new HqnResponder(server, { kem: fakeKem }).readMessage1(bad), NoiseError, `byte ${pos}`);
  }
});

test("a bit flip in msg2 is refused", () => {
  const server = fakeServer();
  const client = new HqnInitiator(pub(server), { kem: fakeKem });
  const responder = new HqnResponder(server, { kem: fakeKem });
  responder.readMessage1(client.writeMessage1(Buffer.from("c")));
  const { message } = responder.writeMessage2(Buffer.from("ok"));
  const bad = Buffer.from(message);
  bad[bad.length - 1]! ^= 0x80;
  assert.throws(() => client.readMessage2(bad), NoiseError);
});

test("the wrong server key, key id or version cannot complete a handshake", () => {
  const server = fakeServer(1);
  const msg1 = new HqnInitiator(pub(server), { kem: fakeKem }).writeMessage1(Buffer.from("c"));

  const otherX = { ...server, x25519: x25519KeyPair() };
  assert.throws(() => new HqnResponder(otherX, { kem: fakeKem }).readMessage1(msg1), NoiseError, "X25519 key");

  const otherHqc = { ...server, hqc: { pk: crypto.randomBytes(HQC_PUBLIC_KEY_BYTES), sk: server.hqc.sk } };
  assert.throws(() => new HqnResponder(otherHqc, { kem: fakeKem }).readMessage1(msg1), NoiseError, "HQC public key");

  assert.throws(() => new HqnResponder({ ...server, keyId: 2 }, { kem: fakeKem }).readMessage1(msg1),
    NoiseError, "key id is in the prologue");
  assert.throws(() => new HqnResponder(server, { kem: fakeKem, version: HQN_VERSION + 1 }).readMessage1(msg1),
    NoiseError, "version is in the prologue");
});

test("a KEM that disagrees breaks the handshake — the HQC secret is load-bearing", () => {
  const server = fakeServer();
  const msg1 = new HqnInitiator(pub(server), { kem: fakeKem }).writeMessage1(Buffer.from("c"));
  const liar: Kem = { ...fakeKem, decapsulate: () => crypto.randomBytes(32) };
  assert.throws(() => new HqnResponder(server, { kem: liar }).readMessage1(msg1), NoiseError);
});

test("the two-phase read agrees with the one-step read, and orders its steps", () => {
  const server = fakeServer();
  const msg1 = new HqnInitiator(pub(server), { kem: fakeKem }).writeMessage1(Buffer.from("connect"));
  const r = new HqnResponder(server, { kem: fakeKem });
  const ct = r.openMessage1(msg1);
  assert.equal(ct.length, HQC_CIPHERTEXT_BYTES);
  assert.throws(() => r.writeMessage2(Buffer.alloc(0)), NoiseError, "no msg2 between the phases");
  assert.throws(() => r.finishMessage1(Buffer.alloc(31)), NoiseError, "a secret of the wrong size");
  assert.equal(r.finishMessage1(fakeKem.decapsulate(Buffer.alloc(0), ct)).toString(), "connect");
  assert.throws(() => r.finishMessage1(Buffer.alloc(32)), NoiseError, "finish runs once");
  assert.throws(() => new HqnResponder(server, { kem: fakeKem }).finishMessage1(Buffer.alloc(32)), NoiseError,
    "finish needs open");
});

test("random bytes fail phase 1, so they never cost a decapsulation", () => {
  const server = fakeServer();
  for (let i = 0; i < 50; i++) {
    const garbage = crypto.randomBytes(32 + HQC_CIPHERTEXT_BYTES + 16 + 16 + (i % 40));
    assert.throws(() => new HqnResponder(server).openMessage1(garbage), NoiseError);
  }
});

test("a short msg1 is refused before any cryptography", () => {
  const server = fakeServer();
  let decaps = 0;
  const counting: Kem = { ...fakeKem, decapsulate: (sk, ct) => { decaps++; return fakeKem.decapsulate(sk, ct); } };
  for (const n of [0, 31, 32, 32 + HQC_CIPHERTEXT_BYTES + 16]) {
    assert.throws(() => new HqnResponder(server, { kem: counting }).readMessage1(Buffer.alloc(n)), NoiseError, `${n} bytes`);
  }
  assert.equal(decaps, 0, "no decapsulation was spent on a message that could not be valid");
});

test("a low-order ephemeral key is refused", () => {
  const server = fakeServer();
  const msg1 = new HqnInitiator(pub(server), { kem: fakeKem }).writeMessage1(Buffer.from("c"));
  const zero = Buffer.from(msg1);
  zero.fill(0, 0, 32);   // the identity point: DH with it is all zeros
  assert.throws(() => new HqnResponder(server, { kem: fakeKem }).readMessage1(zero), NoiseError);
  assert.throws(() => dh(x25519KeyPair().priv, Buffer.alloc(32)), NoiseError);
});

test("a handshake object is single-use", () => {
  const server = fakeServer();
  const client = new HqnInitiator(pub(server), { kem: fakeKem });
  const msg1 = client.writeMessage1(Buffer.from("c"));
  assert.throws(() => client.writeMessage1(Buffer.from("c")), NoiseError);
  const r = new HqnResponder(server, { kem: fakeKem });
  r.readMessage1(msg1);
  assert.throws(() => r.readMessage1(msg1), NoiseError);
  assert.throws(() => new HqnResponder(server, { kem: fakeKem }).writeMessage2(Buffer.alloc(0)), NoiseError,
    "no msg2 before msg1");
  assert.throws(() => new HqnInitiator(pub(server), { kem: fakeKem }).readMessage2(Buffer.alloc(64)), NoiseError,
    "no reading msg2 before sending msg1");
});

test("a replayed msg1 yields a DIFFERENT session the replayer cannot read", () => {
  // The replay the gateway cannot prevent cryptographically: msg1 carries no
  // liveness. What it CAN'T give the replayer is the session — msg2 is keyed by
  // ee, which needs the original client's ephemeral secret.
  const server = fakeServer();
  const { msg1, clientT } = handshake(server, Buffer.from("c"));
  const replay = new HqnResponder(server, { kem: fakeKem });
  replay.readMessage1(msg1);
  const { transport: replayT } = replay.writeMessage2(Buffer.alloc(0));
  const frameFromReplayServer = replayT.send.encryptWithAd(Buffer.alloc(0), Buffer.from("secret"));
  assert.throws(() => clientT.recv.decryptWithAd(Buffer.alloc(0), frameFromReplayServer), NoiseError);
});

test("the nonce counter refuses to wrap", () => {
  const cs = new CipherState(crypto.randomBytes(32));
  cs.__setNonceForTesting((1n << 64n) - 1n);
  assert.throws(() => cs.encryptWithAd(Buffer.alloc(0), Buffer.from("x")), /nonce exhausted/);
});

// --- Framing ----------------------------------------------------------------------

test("frames reassemble from any split of the byte stream", () => {
  for (const piece of [1, 2, 3, 7, 1000]) {
    // A fresh session per split, so each run starts both counters at zero.
    const { clientT, serverT } = handshake(fakeServer(), Buffer.from("c"));
    const wire = Buffer.concat([
      sealFrames(clientT.send, Buffer.from("first")),
      sealFrames(clientT.send, Buffer.from("second, longer")),
    ]);
    const r = new FrameReader();
    const out: string[] = [];
    for (let i = 0; i < wire.length; i += piece) {
      r.push(wire.subarray(i, i + piece));
      for (let f = r.next(); f; f = r.next()) out.push(serverT.recv.decryptWithAd(Buffer.alloc(0), f).toString());
    }
    assert.deepEqual(out, ["first", "second, longer"], `split every ${piece} bytes`);
    assert.equal(r.pending, 0);
  }
});

test("a payload larger than one frame is split, and nothing is lost", () => {
  const { clientT, serverT } = handshake(fakeServer(), Buffer.from("c"));
  const big = crypto.randomBytes(MAX_FRAME_PLAINTEXT * 2 + 1234);
  const wire = sealFrames(clientT.send, big);
  const r = new FrameReader();
  r.push(wire);
  const parts: Buffer[] = [];
  for (let f = r.next(); f; f = r.next()) {
    assert.ok(f.length <= MAX_FRAME, "every frame fits a u16 length");
    parts.push(serverT.recv.decryptWithAd(Buffer.alloc(0), f));
  }
  assert.equal(parts.length, 3);
  assert.ok(Buffer.concat(parts).equals(big));
});

test("a frame cannot exceed the u16 length", () => {
  assert.throws(() => frame(Buffer.alloc(MAX_FRAME + 1)), NoiseError);
  assert.equal(frame(Buffer.alloc(MAX_FRAME)).readUInt16BE(0), MAX_FRAME);
});

test("frames delivered out of order, dropped or repeated are refused", () => {
  const { clientT, serverT } = handshake(fakeServer(), Buffer.from("c"));
  const f1 = clientT.send.encryptWithAd(Buffer.alloc(0), Buffer.from("1"));
  const f2 = clientT.send.encryptWithAd(Buffer.alloc(0), Buffer.from("2"));
  assert.throws(() => serverT.recv.decryptWithAd(Buffer.alloc(0), f2), NoiseError, "skipped frame");
  assert.equal(serverT.recv.decryptWithAd(Buffer.alloc(0), f1).toString(), "1");
  assert.throws(() => serverT.recv.decryptWithAd(Buffer.alloc(0), f1), NoiseError, "repeated frame");
});

// --- Plain NK through the same core ------------------------------------------------

test("plain Noise NK runs through the same core and agrees with itself", () => {
  const s = x25519KeyPair();
  const e1 = x25519KeyPair();
  const e2 = x25519KeyPair();
  const prologueBytes = Buffer.from("prologue");
  const { message: m1, state: is } = nkInitiatorMessage1(prologueBytes, s.pub, e1, Buffer.from("one"));
  const { payload1, message: m2, state: rs } = nkResponderMessage2(prologueBytes, s, m1, e2, Buffer.from("two"));
  assert.equal(payload1.toString(), "one");
  // The initiator finishes the pattern by hand: <- e, ee.
  is.mixHash(m2.subarray(0, 32));
  is.mixKey(dh(e1.priv, m2.subarray(0, 32)));
  assert.equal(is.decryptAndHash(m2.subarray(32)).toString(), "two");
  assert.ok(is.h.equals(rs.h), "same handshake hash");
});

test("the core matches the published Noise_NK_25519_ChaChaPoly_SHA256 vector", () => {
  const { vector: v } = JSON.parse(fs.readFileSync(path.join(__dirname, "helpers", "noise-nk-cacophony.json"), "utf8"));
  const h = (x: string) => Buffer.from(x, "hex");
  const prologueBytes = h(v.init_prologue);
  const initE = x25519KeyPair(h(v.init_ephemeral));
  const respE = x25519KeyPair(h(v.resp_ephemeral));
  const respS = x25519KeyPair(h(v.resp_static));
  assert.ok(respS.pub.equals(h(v.init_remote_static)), "the responder static matches what the initiator pins");

  const m = v.messages as { payload: string; ciphertext: string }[];
  const { message: m1, state: is } = nkInitiatorMessage1(prologueBytes, respS.pub, initE, h(m[0]!.payload));
  assert.equal(m1.toString("hex"), m[0]!.ciphertext, "message 1");
  const { payload1, message: m2, state: rs } = nkResponderMessage2(prologueBytes, respS, m1, respE, h(m[1]!.payload));
  assert.equal(payload1.toString("hex"), m[0]!.payload);
  assert.equal(m2.toString("hex"), m[1]!.ciphertext, "message 2");
  is.mixHash(m2.subarray(0, 32));
  is.mixKey(dh(initE.priv, m2.subarray(0, 32)));
  assert.equal(is.decryptAndHash(m2.subarray(32)).toString("hex"), m[1]!.payload);
  assert.equal(is.h.toString("hex"), v.handshake_hash, "handshake hash");
  assert.equal(rs.h.toString("hex"), v.handshake_hash);

  // Transport: initiator and responder alternate, starting with the initiator.
  const [iSend, iRecv] = is.split();
  const [rRecv, rSend] = rs.split();
  for (let i = 2; i < m.length; i++) {
    const fromInitiator = i % 2 === 0;
    const ct = (fromInitiator ? iSend : rSend).encryptWithAd(Buffer.alloc(0), h(m[i]!.payload));
    assert.equal(ct.toString("hex"), m[i]!.ciphertext, `transport message ${i}`);
    assert.equal((fromInitiator ? rRecv : iRecv).decryptWithAd(Buffer.alloc(0), ct).toString("hex"), m[i]!.payload);
  }
});

// --- The Noise HKDF, against its definition ---------------------------------------

test("hkdf2 is the Noise HKDF (HMAC-SHA256 chained)", () => {
  const ck = crypto.randomBytes(32);
  const ikm = crypto.randomBytes(32);
  const temp = crypto.createHmac("sha256", ck).update(ikm).digest();
  const o1 = crypto.createHmac("sha256", temp).update(Buffer.from([1])).digest();
  const o2 = crypto.createHmac("sha256", temp).update(Buffer.concat([o1, Buffer.from([2])])).digest();
  const [a, b] = hkdf2(ck, ikm);
  assert.ok(a.equals(o1) && b.equals(o2));
  // And it is RFC 5869 HKDF with the chaining key as salt, empty info — node's
  // own implementation must agree, or one of the two definitions is wrong.
  const rfc = Buffer.from(crypto.hkdfSync("sha256", ikm, ck, Buffer.alloc(0), 64));
  assert.ok(rfc.subarray(0, 32).equals(a) && rfc.subarray(32).equals(b));
});

test("X25519 matches RFC 7748 §6.1", () => {
  const alice = x25519KeyPair(Buffer.from("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "hex"));
  const bob = x25519KeyPair(Buffer.from("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", "hex"));
  assert.equal(alice.pub.toString("hex"), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  assert.equal(bob.pub.toString("hex"), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  assert.equal(dh(alice.priv, bob.pub).toString("hex"), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
});

// --- Cross-implementation vectors ---------------------------------------------------

const VECTORS = path.join(__dirname, "helpers", "noise-hqn-vectors.json");

test("the hqn/1 vectors reproduce byte for byte", (t) => {
  if (!fs.existsSync(VECTORS)) return t.skip("noise-hqn-vectors.json not generated yet");
  const v = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
  for (const c of v.cases) {
    const kem: Kem = {
      encapsulate: () => ({ ct: Buffer.from(c.kemCiphertextHex, "hex"), ss: Buffer.from(c.kemSharedSecretHex, "hex") }),
      decapsulate: () => Buffer.from(c.kemSharedSecretHex, "hex"),
    };
    const server: ServerStatic = {
      keyId: c.keyId,
      x25519: x25519KeyPair(Buffer.from(c.serverStaticPrivHex, "hex")),
      hqc: { pk: Buffer.from(c.serverHqcPublicHex, "hex"), sk: Buffer.alloc(7333) },
    };
    const client = new HqnInitiator(pub(server), { kem, ephemeral: x25519KeyPair(Buffer.from(c.clientEphemeralPrivHex, "hex")) });
    const msg1 = client.writeMessage1(Buffer.from(c.payload1Hex, "hex"));
    assert.equal(crypto.createHash("sha256").update(msg1).digest("hex"), c.msg1Sha256, `${c.label}: msg1`);
    const responder = new HqnResponder(server, { kem });
    assert.equal(responder.readMessage1(msg1).toString("hex"), c.payload1Hex);
    const { message: msg2, transport: st } = responder.writeMessage2(
      Buffer.from(c.payload2Hex, "hex"), x25519KeyPair(Buffer.from(c.serverEphemeralPrivHex, "hex")));
    assert.equal(msg2.toString("hex"), c.msg2Hex, `${c.label}: msg2`);
    const { transport: ct } = client.readMessage2(msg2);
    assert.equal(ct.handshakeHash.toString("hex"), c.handshakeHashHex, `${c.label}: handshake hash`);
    assert.equal(ct.send.encryptWithAd(Buffer.alloc(0), Buffer.from(c.transportPlainHex, "hex")).toString("hex"),
      c.transportUpHex, `${c.label}: first upstream frame`);
    assert.equal(st.send.encryptWithAd(Buffer.alloc(0), Buffer.from(c.transportPlainHex, "hex")).toString("hex"),
      c.transportDownHex, `${c.label}: first downstream frame`);
  }
});
