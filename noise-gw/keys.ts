import * as fs from "fs";
import { x25519KeyPair, type ServerStatic } from "../lib/noise";

/**
 * The gateway's static keys.
 *
 * The secret file holds SEEDS, not keys: a 32-byte X25519 private key and a
 * 32-byte HQC-256 seed per key id. The HQC key pair is derived from the seed
 * (`HqcWrapper.keypairFromSeed`), so the secret is 64 bytes a key rather than
 * 7 kB, and the public half the app pins is reproducible from it.
 *
 *   { "keys": [ { "keyId": 1, "x25519": "<64 hex>", "hqcSeed": "<64 hex>" } ] }
 *
 * Up to two key ids are expected at once — the current one and the next —
 * which is how rotation works: ship an app that pins both, then switch.
 */
export interface KeySeed { keyId: number; x25519: Buffer; hqcSeed: Buffer }

export function parseKeySeeds(json: string): KeySeed[] {
  const parsed = JSON.parse(json);
  if (!Array.isArray(parsed?.keys) || parsed.keys.length === 0) throw new Error("noise keys: no keys");
  const out: KeySeed[] = [];
  const seen = new Set<number>();
  for (const k of parsed.keys) {
    const keyId = Number(k.keyId);
    if (!Number.isInteger(keyId) || keyId < 0 || keyId > 255) throw new Error("noise keys: keyId must be 0..255");
    if (seen.has(keyId)) throw new Error(`noise keys: duplicate keyId ${keyId}`);
    seen.add(keyId);
    const x25519 = Buffer.from(String(k.x25519 ?? ""), "hex");
    const hqcSeed = Buffer.from(String(k.hqcSeed ?? ""), "hex");
    if (x25519.length !== 32 || hqcSeed.length !== 32) throw new Error(`noise keys: key ${keyId} needs 32-byte x25519 and hqcSeed`);
    out.push({ keyId, x25519, hqcSeed });
  }
  return out;
}

export function loadServerKeys(seeds: KeySeed[]): Map<number, ServerStatic> {
  // Lazy: the native library is only needed once keys are actually loaded.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { HqcWrapper } = require("../lib/hqc") as typeof import("../lib/hqc");
  return new Map(seeds.map((s) => [s.keyId, {
    keyId: s.keyId,
    x25519: x25519KeyPair(s.x25519),
    hqc: HqcWrapper.keypairFromSeed(s.hqcSeed),
  }]));
}

export function readKeySeeds(file: string): KeySeed[] {
  return parseKeySeeds(fs.readFileSync(file, "utf8"));
}

/** What the app pins, and what /auth/transport will publish. */
export function publicKeys(keys: Map<number, ServerStatic>) {
  return [...keys.values()].map((k) => ({
    keyId: k.keyId,
    x25519: k.x25519.pub.toString("base64"),
    hqc: k.hqc.pk.toString("base64"),
  }));
}
