// Regenerates test/helpers/noise-hqn-vectors.json.
//
//   npx tsx scripts/gen-noise-hqn-vectors.ts > test/helpers/noise-hqn-vectors.json
//
// hqn/1 (lib/noise.ts) is implemented twice — here for the gateway, and in
// apps/apple/DissQus/Services/NoiseHQN.swift for the app — and one byte of
// disagreement anywhere in the transcript is a handshake that fails with
// nothing but "decryption failed" on both ends. Both suites READ this file:
// test/noise.test.ts and apps/apple/tests/NoiseHQNTests.swift.
//
// Every random input is pinned: both ephemerals, the server's static X25519
// key, and — because real HQC encapsulation draws fresh randomness — the KEM's
// (ciphertext, shared secret) pair itself. The HQC public key and ciphertext are
// deterministic stand-ins of the TRUE sizes: what is being pinned is the Noise
// transcript around the KEM, and the KEM is checked separately against its own
// known answers (test/hqc.test.ts). msg1 is ~14.5 kB, so it is pinned by hash;
// everything else is pinned in full.

import * as crypto from "crypto";
import {
  HqnInitiator,
  HqnResponder,
  x25519KeyPair,
  HQN_PROTOCOL_NAME,
  HQN_PROLOGUE_LABEL,
  HQN_VERSION,
  HQC_PUBLIC_KEY_BYTES,
  HQC_CIPHERTEXT_BYTES,
  type Kem,
} from "../lib/noise";

function bytes(label: string, n: number): Buffer {
  const out: Buffer[] = [];
  let block = crypto.createHash("sha256").update(label, "utf8").digest();
  while (Buffer.concat(out).length < n) {
    out.push(block);
    block = crypto.createHash("sha256").update(block).digest();
  }
  return Buffer.concat(out).subarray(0, n);
}

const specs = [
  { label: "a CONNECT-sized payload", keyId: 1, payload1: bytes("p1/connect", 180), payload2: Buffer.alloc(0) },
  { label: "an empty payload in both directions", keyId: 1, payload1: Buffer.alloc(0), payload2: Buffer.alloc(0) },
  { label: "a second server key id, and a payload in msg2", keyId: 2, payload1: bytes("p1/other", 64), payload2: Buffer.from("hqn/1 ok") },
];

const cases = specs.map((s, i) => {
  const serverStaticPriv = bytes(`hqn/server-static/${s.keyId}`, 32);
  const serverHqcPublic = bytes(`hqn/server-hqc/${s.keyId}`, HQC_PUBLIC_KEY_BYTES);
  const clientEphemeralPriv = bytes(`hqn/client-e/${i}`, 32);
  const serverEphemeralPriv = bytes(`hqn/server-e/${i}`, 32);
  const kemCiphertext = bytes(`hqn/kem-ct/${i}`, HQC_CIPHERTEXT_BYTES);
  const kemSharedSecret = bytes(`hqn/kem-ss/${i}`, 32);
  const kem: Kem = {
    encapsulate: () => ({ ct: kemCiphertext, ss: kemSharedSecret }),
    decapsulate: () => kemSharedSecret,
  };
  const staticKp = x25519KeyPair(serverStaticPriv);
  const client = new HqnInitiator(
    { keyId: s.keyId, x25519: staticKp.pub, hqc: serverHqcPublic },
    { kem, ephemeral: x25519KeyPair(clientEphemeralPriv) },
  );
  const msg1 = client.writeMessage1(s.payload1);
  const responder = new HqnResponder(
    { keyId: s.keyId, x25519: staticKp, hqc: { pk: serverHqcPublic, sk: Buffer.alloc(7333) } },
    { kem },
  );
  responder.readMessage1(msg1);
  const { message: msg2, transport: st } = responder.writeMessage2(s.payload2, x25519KeyPair(serverEphemeralPriv));
  const { transport: ct } = client.readMessage2(msg2);
  const transportPlain = bytes(`hqn/transport/${i}`, 40);
  return {
    label: s.label,
    keyId: s.keyId,
    serverStaticPrivHex: serverStaticPriv.toString("hex"),
    serverStaticPubHex: staticKp.pub.toString("hex"),
    serverHqcPublicHex: serverHqcPublic.toString("hex"),
    clientEphemeralPrivHex: clientEphemeralPriv.toString("hex"),
    serverEphemeralPrivHex: serverEphemeralPriv.toString("hex"),
    kemCiphertextHex: kemCiphertext.toString("hex"),
    kemSharedSecretHex: kemSharedSecret.toString("hex"),
    payload1Hex: s.payload1.toString("hex"),
    payload2Hex: s.payload2.toString("hex"),
    msg1Length: msg1.length,
    msg1Sha256: crypto.createHash("sha256").update(msg1).digest("hex"),
    msg1HeadHex: msg1.subarray(0, 96).toString("hex"),
    msg2Hex: msg2.toString("hex"),
    handshakeHashHex: ct.handshakeHash.toString("hex"),
    transportPlainHex: transportPlain.toString("hex"),
    transportUpHex: ct.send.encryptWithAd(Buffer.alloc(0), transportPlain).toString("hex"),
    transportDownHex: st.send.encryptWithAd(Buffer.alloc(0), transportPlain).toString("hex"),
  };
});

process.stdout.write(
  JSON.stringify(
    {
      _comment:
        "hqn/1 hybrid Noise handshake (lib/noise.ts). Every random input is pinned, including the KEM's " +
        "(ct, ss). Asserted by services/server/test/noise.test.ts and apps/apple/tests/NoiseHQNTests.swift, " +
        "both of which READ this file. Regenerate with scripts/gen-noise-hqn-vectors.ts.",
      version: 1,
      protocolName: HQN_PROTOCOL_NAME,
      prologueLabel: HQN_PROLOGUE_LABEL,
      hqnVersion: HQN_VERSION,
      cases,
    },
    null,
    2,
  ) + "\n",
);
