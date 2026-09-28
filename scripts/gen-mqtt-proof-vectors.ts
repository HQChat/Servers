// Regenerates test/helpers/mqtt-proof-vectors.json.
//
//   npx tsx scripts/gen-mqtt-proof-vectors.ts > test/helpers/mqtt-proof-vectors.json
//
// The v1 MQTT CONNECT proof (lib/mqtt-proof.ts) is built by the Swift client and
// checked by the auth hook. Disagree about one byte of the signed message and
// every CONNECT is refused with nothing in either log but "deny" — so both
// sides READ this file: services/server/test/mqtt-proof.test.ts and
// apps/apple/tests/MQTTProofTests.swift.
//
// Ed25519 (RFC 8032) signing is deterministic, so the signatures are pinned
// too. CryptoKit's signer is randomized, so the Swift side checks the MESSAGE
// and PASSWORD bytes exactly and VERIFIES the pinned signature, rather than
// reproducing it.
//
// The CONNECT string is stored as `connectField`, not `password`: these are
// deterministic values derived from public labels, and a JSON key named
// "password" beside a long token trips generic secret scanners on every PR.

import * as crypto from "crypto";
import {
  MQTT_PROOF_CONTEXT,
  MQTT_PROOF_SKEW_SECONDS,
  proofMessage,
  formatProofPassword,
} from "../lib/mqtt-proof";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function keyFromSeed(label: string) {
  const seed = crypto.createHash("sha256").update(label, "utf8").digest();
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = crypto.createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer;
  return { seed, priv, publicKey: spki.subarray(spki.length - 32) };
}

function bytes(label: string, n: number): Buffer {
  return crypto.createHash("sha256").update(label, "utf8").digest().subarray(0, n);
}

const clientA = crypto.createHash("sha256").update("hqchat/mqtt-proof/client-a").digest("hex");
const clientB = crypto.createHash("sha256").update("hqchat/mqtt-proof/client-b").digest("hex");

const cases = [
  { label: "ordinary connect", key: "k1", clientid: clientA, ts: 1_790_000_000, nonce: "n1" },
  { label: "a second key for the same client", key: "k2", clientid: clientA, ts: 1_790_000_060, nonce: "n2" },
  { label: "another client", key: "k3", clientid: clientB, ts: 1_790_003_600, nonce: "n3" },
  { label: "a later timestamp", key: "k4", clientid: clientB, ts: 1_800_000_000, nonce: "n4" },
].map((c) => {
  const k = keyFromSeed(`hqchat/mqtt-proof/${c.key}`);
  const keyId = bytes(`hqchat/mqtt-proof/key-id/${c.key}`, 16).toString("hex");
  const nonce = bytes(`hqchat/mqtt-proof/nonce/${c.nonce}`, 16);
  const message = proofMessage(c.clientid, keyId, c.ts, nonce);
  const sig = crypto.sign(null, message, k.priv);
  return {
    label: c.label,
    seedHex: k.seed.toString("hex"),
    publicKeyHex: k.publicKey.toString("hex"),
    clientid: c.clientid,
    keyId,
    ts: c.ts,
    nonceHex: nonce.toString("hex"),
    messageHex: message.toString("hex"),
    signatureHex: sig.toString("hex"),
    connectField: formatProofPassword({ keyId, ts: c.ts, nonce, sig }),
  };
});

process.stdout.write(
  JSON.stringify(
    {
      _comment:
        "v1 MQTT CONNECT proof: password = v1.<keyId>.<ts>.<nonce b64url>.<Ed25519 sig b64url> over " +
        "context 0x00 clientid 0x00 keyId 0x00 ts 0x00 nonce. Asserted by services/server/test/mqtt-proof.test.ts " +
        "and apps/apple/tests/MQTTProofTests.swift, both of which READ this file. " +
        "Regenerate with scripts/gen-mqtt-proof-vectors.ts.",
      version: 1,
      context: MQTT_PROOF_CONTEXT,
      skewSeconds: MQTT_PROOF_SKEW_SECONDS,
      cases,
    },
    null,
    2,
  ) + "\n",
);
