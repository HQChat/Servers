// Generates a noise-gw key: the SECRET seed file the gateway loads, and the
// PUBLIC keys the app pins.
//
//   npx tsx scripts/noise-gw-keys.ts --key-id 1 --secret keys.json [--public pub.json]
//
// Appends to an existing secret file (rotation holds two key ids at once).
// Refuses to overwrite an existing key id.

import * as crypto from "crypto";
import * as fs from "fs";
import { parseKeySeeds, loadServerKeys, publicKeys } from "../noise-gw/keys";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const keyId = Number(arg("--key-id") ?? "1");
const secretFile = arg("--secret");
if (!secretFile) { console.error("--secret <file> is required"); process.exit(2); }

const existing = fs.existsSync(secretFile) ? JSON.parse(fs.readFileSync(secretFile, "utf8")) : { keys: [] };
if (existing.keys.some((k: { keyId: number }) => Number(k.keyId) === keyId)) {
  console.error(`key id ${keyId} already exists in ${secretFile}`);
  process.exit(1);
}
existing.keys.push({
  keyId,
  x25519: crypto.randomBytes(32).toString("hex"),
  hqcSeed: crypto.randomBytes(32).toString("hex"),
});
fs.writeFileSync(secretFile, JSON.stringify(existing, null, 2) + "\n", { mode: 0o600 });

const pub = { keys: publicKeys(loadServerKeys(parseKeySeeds(JSON.stringify(existing)))) };
const publicFile = arg("--public");
if (publicFile) fs.writeFileSync(publicFile, JSON.stringify(pub, null, 2) + "\n");
else process.stdout.write(JSON.stringify(pub, null, 2) + "\n");
