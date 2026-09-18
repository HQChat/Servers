// What APNs needs before it can send anything, as a pure function of the
// environment.
//
// It lives in its own module, with no imports, for two reasons. `lib/config.ts`
// runs at import time before anything else and must not pull in `services/db`
// through `services/apns/api.ts`. And the whole point of extracting it is that
// it can be asserted in a unit test — the failure this replaces was a stack
// where push had never once been sent and nothing, anywhere, said so.
//
// ── Why the topics are in the required set ──────────────────────────────────
//
// `ApnsService.send` reads `APNS_TOPIC_IOS`/`APNS_TOPIC_MACOS` and returns
// silently when the one it needs is unset. A deployment with a valid key, a
// valid team and no topic therefore looks completely healthy and wakes nobody.
// "Configured" has to mean "can actually send", or the check is decoration.

/** Every setting APNs cannot send without. The topics are per-platform and a
 *  host that means to have push needs BOTH — see `apnsGaps` for why one is not
 *  enough, which is the half-fix this used to describe. */
export const APNS_CREDENTIALS = ["APNS_KEY_ID", "APNS_TEAM_ID", "APNS_KEY_P8"] as const;
export const APNS_TOPICS = ["APNS_TOPIC_IOS", "APNS_TOPIC_MACOS"] as const;

/** The platform each topic delivers to, so a gap can name what stops working
 *  rather than only which variable is unset. */
const PLATFORM: Record<(typeof APNS_TOPICS)[number], string> = {
  APNS_TOPIC_IOS: "iPhone",
  APNS_TOPIC_MACOS: "Mac",
};

export type ApnsEnv = Record<string, string | undefined>;

const set = (env: ApnsEnv, k: string) => !!env[k]?.trim();

/** True when at least one APNs setting is present — i.e. somebody INTENDED to
 *  configure push here. Absent-everywhere is a valid state (CI, local dev), and
 *  is not an error; half-configured is. */
export function apnsIntended(env: ApnsEnv): boolean {
  return [...APNS_CREDENTIALS, ...APNS_TOPICS].some((k) => set(env, k));
}

/** What is missing before a push can be sent. Empty means ready.
 *
 *  The topic test used to be `some`, and that was wrong in the quietest way
 *  available: a host with only APNS_TOPIC_MACOS reported READY, and then `send`
 *  returned `no-topic-ios` for every iPhone on it. That is exactly the silent
 *  delivery failure the topics belong in this set to prevent — nobody
 *  complains, nothing is logged, phones simply never buzz — reintroduced one
 *  platform at a time.
 *
 *  So both are required once anything APNs-ish is set, and a missing one names
 *  the devices it costs. Absent-everywhere is still fine (`apnsIntended` is what
 *  separates those); half-configured is the error state, which is what this
 *  module said in prose before it said it in code.
 *
 *  Nothing exits on the result. `assertConfig` files APNs gaps under warnings
 *  and never under errors (lib/config.ts), deliberately, and push-bridge
 *  escalates them once at boot to logger.error and therefore Sentry. A
 *  deployment that genuinely serves one platform reads a warning naming the
 *  other and carries on; that is the cost, and it is much cheaper than the
 *  alternative of not finding out at all. */
export function apnsGaps(env: ApnsEnv): string[] {
  const gaps = APNS_CREDENTIALS.filter((k) => !set(env, k)) as string[];
  const missing = APNS_TOPICS.filter((k) => !set(env, k));
  if (missing.length === APNS_TOPICS.length) {
    gaps.push(`${APNS_TOPICS.join(" or ")} (the bundle id APNs delivers to)`);
  } else {
    for (const k of missing) gaps.push(`${k} (without it, no ${PLATFORM[k]} is ever woken)`);
  }
  return gaps;
}

/** One line describing what push will do, for the bridge's startup log. */
export function apnsSummary(env: ApnsEnv): string {
  const gaps = apnsGaps(env);
  if (gaps.length) {
    return apnsIntended(env)
      ? `APNs is INCOMPLETE (missing ${gaps.join(", ")}) — no device will be woken`
      : "APNs is not configured — no device will be woken";
  }
  const envName = env.APNS_ENV === "production" ? "production" : "sandbox";
  const topics = APNS_TOPICS.filter((k) => set(env, k)).map((k) => `${k}=${env[k]}`);
  return `APNs ready (${envName}; ${topics.join(", ")})`;
}

// ── The .p8, whatever shape it arrived in ───────────────────────────────────
//
// `crypto.sign` was handed `process.env.APNS_KEY_P8` with nothing but a
// `\n`-unescape, and OpenSSL answered `error:1E08010C:DECODER routines::
// unsupported` — per message, as a stack trace, from inside a fire-and-forget
// send. That error says only "this is not a key I can decode"; it does not say
// which of the several ways the value can arrive went wrong.
//
// It can arrive as:
//   - a real PEM with real newlines          (APNS_KEY_P8_FILE → the mounted .p8)
//   - a PEM with literal \n escapes          (the one-line .env form)
//   - either of those with CRLF              (edited on Windows, or via a form)
//   - a PEM whose body lost its wrapping     (whitespace collapsed in transit)
//   - the base64 body alone, no armour       (someone stripped the header)
//
// Only the first two worked. The rest are indistinguishable at the call site
// and all produce the same opaque OpenSSL error, so this normalises every one
// of them into the armour OpenSSL wants rather than asking an operator to guess
// which transformation their secret went through.

const P8_HEADER = "-----BEGIN PRIVATE KEY-----";
const P8_FOOTER = "-----END PRIVATE KEY-----";

/** Re-armour an APNs signing key into canonical PKCS#8 PEM, or null when the
 *  value holds nothing that could be one. Never throws, and never logs: the
 *  input is private key material. */
export function normalizeP8(raw: string | undefined): string | null {
  if (!raw) return null;
  // Literal \n first — an escaped one-liner has no real newlines to preserve.
  const text = raw.replace(/\\n/g, "\n").replace(/\r/g, "").trim();
  if (!text) return null;

  // Take the base64 body: everything between the armour, or the whole value
  // when there is none. Any PEM-ish header that is NOT PKCS#8 is refused rather
  // than re-labelled — an "EC PRIVATE KEY" (SEC1) or "RSA PRIVATE KEY" (PKCS#1)
  // is a real key in the wrong container, and silently restamping the header
  // would produce a file that parses and signs wrongly.
  let body: string;
  if (text.includes(P8_HEADER)) {
    const start = text.indexOf(P8_HEADER) + P8_HEADER.length;
    const end = text.indexOf(P8_FOOTER, start);
    body = text.slice(start, end === -1 ? undefined : end);
  } else if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(text)) {
    return null;
  } else {
    body = text;
  }

  body = body.replace(/\s+/g, "");
  if (!body || body.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return null;

  // The base64 ALPHABET is not much of a test — "notakeyatall" passes it. What
  // the value has to be is DER: an ASN.1 SEQUENCE (0x30) long enough to hold a
  // PKCS#8 P-256 key, which is ~138 bytes. This is still only a shape check;
  // `crypto.createPrivateKey` in services/apns is the real gate. It exists so
  // that "this was never a key" is distinguishable from "this is a key OpenSSL
  // will not load", which are different mistakes with different fixes.
  const der = Buffer.from(body, "base64");
  if (der.length < 48 || der[0] !== 0x30) return null;

  // 64-column wrapping. OpenSSL tolerates an unwrapped body, but emitting
  // canonical PEM means what we log about and what we sign with are the same
  // shape as the file Apple hands you.
  const lines = body.match(/.{1,64}/g) ?? [];
  return [P8_HEADER, ...lines, P8_FOOTER].join("\n") + "\n";
}
