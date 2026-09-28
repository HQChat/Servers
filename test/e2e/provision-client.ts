// Provisions one signed-in client against the local e2e stack and prints what a
// NON-TypeScript client needs to connect as it: its id, a registered Ed25519
// signing key (the private half, raw), the server's clock, and the gateway's
// pinned keys. Used by apps/apple/e2e/hqn-live — the Swift client, through the
// real noise-gw, into the real broker. Test identities only; nothing here is
// a production credential.
//
//   TEST_AUTH_URL=… TEST_API_URL=… TEST_HQN_KEYS_URL=… npx tsx test/e2e/provision-client.ts

import * as crypto from "crypto";
import { TestClient, loadCrypto } from "../helpers/mqtt-client";
import { newSigningKey } from "../../lib/mqtt-proof";
import { disconnect } from "../../services/db/pg";

async function main() {
  const AUTH = (process.env.TEST_AUTH_URL || "").replace(/\/$/, "");
  const c = new TestClient(await loadCrypto());
  await c.register(`swift${crypto.randomBytes(3).toString("hex")}`);
  const key = newSigningKey();
  const pkcs8 = key.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const r = await fetch(`${AUTH}/auth/refresh`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${c.bearer}` },
    body: JSON.stringify({ mqttSigningKey: key.publicKeyB64 }),
  });
  const refresh = await r.json();
  const keys = (await (await fetch(process.env.TEST_HQN_KEYS_URL!)).json()).keys;
  process.stdout.write(JSON.stringify({
    id: c.id,
    keyId: refresh.mqttKeyId,
    signingSeedHex: pkcs8.subarray(pkcs8.length - 32).toString("hex"),
    serverTime: refresh.serverTime,
    gateway: { host: process.env.TEST_HQN_HOST, port: Number(process.env.TEST_HQN_PORT), keys },
    wss: process.env.TEST_EMQX_URL,
  }) + "\n");
  await disconnect().catch(() => {});
}

main().catch((e) => { console.error(e); process.exit(1); });
