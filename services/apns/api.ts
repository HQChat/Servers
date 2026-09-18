import { logger } from "../../lib/logger";
import * as http2 from "http2";
import * as crypto from "crypto";
import { DB } from "../db/api";
import { apnsGaps, normalizeP8 } from "../../lib/apns-config";

/** Why a push was or was not delivered. `no-config`/`no-topic-*`/`bad-key` are
 *  deploy mistakes, `no-token` is an ordinary state (a peer who has never run the app
 *  on a device that registered), and `rejected`/`error` came back from Apple. */
export type SendOutcome =
  | "sent"
  | "no-config"
  | "bad-key"
  | "no-token"
  | "no-topic-ios"
  | "no-topic-macos"
  | "rejected"
  | "error";

let cachedJwt: { token: string; iat: number } | null = null;
let cachedKey: crypto.KeyObject | null | undefined;   // undefined = not tried yet

/** Parse the .p8 once. `null` means it is not a usable APNs signing key, and
 *  `keyProblem()` says why in words that name a fix.
 *
 *  Parsed ONCE, not per token: a bad key produced an OpenSSL stack trace on
 *  every single message, and a good one was re-decoded on every refresh. */
function privateKey(): crypto.KeyObject | null {
  if (cachedKey !== undefined) return cachedKey;
  cachedKey = null;
  const pem = normalizeP8(process.env.APNS_KEY_P8);
  if (!pem) return cachedKey;
  try {
    const key = crypto.createPrivateKey(pem);
    // ES256 means ECDSA on P-256, and Apple issues nothing else. Checking it
    // here turns "InvalidProviderToken" — which arrives from Apple, hours later,
    // about a push nobody saw fail — into a sentence at boot.
    if (key.asymmetricKeyType !== "ec") return cachedKey;
    cachedKey = key;
  } catch {
    // Deliberately not logged: the failure is about private key material, and
    // OpenSSL's message can echo the input.
  }
  return cachedKey;
}

/** What is wrong with the configured .p8, in words, or null when it is fine.
 *  Says nothing about the key's CONTENT — only its shape. */
export function keyProblem(): string | null {
  if (!process.env.APNS_KEY_P8?.trim()) return "APNS_KEY_P8 is empty";
  if (!normalizeP8(process.env.APNS_KEY_P8)) {
    return "APNS_KEY_P8 is not a PKCS#8 private key — Apple's .p8 starts " +
           "'-----BEGIN PRIVATE KEY-----'. An 'EC PRIVATE KEY' or 'RSA PRIVATE KEY' " +
           "header is the wrong container, and a truncated paste (one line of a " +
           "multi-line file) looks the same from here";
  }
  if (!privateKey()) {
    return "APNS_KEY_P8 is PEM-shaped but OpenSSL will not load it as an EC key — " +
           "the base64 body is corrupt or it is not the P-256 key ES256 needs";
  }
  return null;
}

function getJwt(): string | null {
  const now = Math.floor(Date.now() / 1000);
  // APNs accepts a provider token for up to 1h; refresh well before that.
  if (cachedJwt && now - cachedJwt.iat < 3000) return cachedJwt.token;

  const key = privateKey();
  if (!key) return null;

  const b64 = (o: object) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  const header = { alg: "ES256", kid: process.env.APNS_KEY_ID };
  const payload = { iss: process.env.APNS_TEAM_ID, iat: now };
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const sig = crypto
    .sign("SHA256", Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" })
    .toString("base64url");

  const token = `${signingInput}.${sig}`;
  cachedJwt = { token, iat: now };
  return token;
}

/**
 * Minimal APNs (token-based) push sender using Node built-ins — no node-apn
 * dependency. Sends an alert push to a user's registered device.
 *
 * Configure via env (see deploy/.env.example):
 *   APNS_KEY_ID, APNS_TEAM_ID, APNS_KEY_P8 (the .p8 contents, \n-escaped),
 *   APNS_TOPIC_IOS, APNS_TOPIC_MACOS, APNS_ENV (sandbox|production)
 *
 * If the env isn't set, send() is a no-op so the rest of the server is
 * unaffected — push simply stays dormant until you add the key.
 *
 * ── Every exit is named ─────────────────────────────────────────────────────
 *
 * `send` used to return `void` through five different silent `return`s: no
 * config, no token, no topic, and two HTTP failures. A phone that never buzzed
 * therefore had five indistinguishable explanations and no evidence for any of
 * them. It returns an OUTCOME now, and the push-bridge logs it. Nothing here
 * throws or blocks a message either way — a push is best-effort by design.
 */
export const ApnsService = {
  enabled(): boolean {
    return !!(
      process.env.APNS_KEY_ID &&
      process.env.APNS_TEAM_ID &&
      process.env.APNS_KEY_P8
    );
  },

  /** Alert push to the device registered against a client id, with the reason
   *  when there isn't one. Never throws. */
  async send(id: string, title: string, body: string): Promise<SendOutcome> {
    try {
      if (!this.enabled()) return "no-config";
      // Before the token lookup: a key OpenSSL cannot load is a property of the
      // deployment, not of this recipient, and it used to surface as a stack
      // trace per message from inside the signer.
      const jwt = getJwt();
      if (!jwt) return "bad-key";
      const info = await DB.getPushToken(id);
      if (!info) return "no-token";

      const topic =
        info.platform === "macos"
          ? process.env.APNS_TOPIC_MACOS
          : process.env.APNS_TOPIC_IOS;
      // A key with no topic is the quietest misconfiguration in the stack: it
      // authenticates fine and delivers to nowhere.
      if (!topic) return info.platform === "macos" ? "no-topic-macos" : "no-topic-ios";

      // A device token is tied to exactly one APNs environment. A debug/dev
      // build (and App Review) yields a *sandbox* token; App Store/TestFlight a
      // *production* one. We can't tell which from the token, so try the
      // configured primary and, on BadDeviceToken, retry the other host once.
      const primary =
        process.env.APNS_ENV === "production"
          ? "api.push.apple.com"
          : "api.sandbox.push.apple.com";
      const other =
        primary === "api.push.apple.com"
          ? "api.sandbox.push.apple.com"
          : "api.push.apple.com";

      const res = await sendToHost(primary, info.token, topic, title, body, jwt);
      if (res.status === 400 && /BadDeviceToken/.test(res.data)) {
        const retry = await sendToHost(other, info.token, topic, title, body, jwt);
        if (retry.status !== 200) {
          logger.error(`[apns] ${retry.status} ${retry.data}`);
          return "rejected";
        }
        return "sent";
      }
      if (res.status !== 200) {
        logger.error(`[apns] ${res.status} ${res.data}`);
        return "rejected";
      }
      return "sent";
    } catch (e) {
      logger.error("[apns] send failed", e);
      return "error";
    }
  },

  /** What is missing before this service can send. Empty means ready.
   *  Includes a key that is present but unloadable — "set" and "usable" are
   *  different questions, and only the second one predicts a push. */
  gaps(): string[] {
    const gaps = apnsGaps(process.env);
    const problem = keyProblem();
    if (problem && !gaps.includes("APNS_KEY_P8")) gaps.push(problem);
    return gaps;
  },
};

/** POST a single alert to one APNs host; resolves with the HTTP status + body. */
function sendToHost(
  host: string,
  token: string,
  topic: string,
  title: string,
  body: string,
  jwt: string
): Promise<{ status: number; data: string }> {
  return new Promise((resolve) => {
    const client = http2.connect(`https://${host}`);
    client.on("error", (e) => {
      logger.error("[apns] connection error", e);
      resolve({ status: 0, data: String(e) });
    });

    const payload = JSON.stringify({ aps: { alert: { title, body }, sound: "default" } });
    const req = client.request({
      ":method": "POST",
      ":path": `/3/device/${token}`,
      authorization: `bearer ${jwt}`,
      "apns-topic": topic,
      "apns-push-type": "alert",
      "content-type": "application/json",
    });

    let status = 0;
    let data = "";
    req.setEncoding("utf8");
    req.on("response", (h) => { status = Number(h[":status"]); });
    req.on("data", (c) => (data += c));
    req.on("end", () => { client.close(); resolve({ status, data }); });
    req.on("error", (e) => { client.close(); resolve({ status: 0, data: String(e) }); });
    req.write(payload);
    req.end();
  });
}
