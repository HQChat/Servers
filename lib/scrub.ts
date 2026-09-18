// PII / secret scrubbing for everything that leaves the box via Sentry.
//
// WHY THIS EXISTS: Sentry is a crash-reporting pipe, and a relay for an
// end-to-end-encrypted messenger is exactly the kind of process whose error
// strings, breadcrumbs and stack frames can incidentally carry things we never
// want off-box: public keys (stable user identifiers), usernames, client IPs,
// bearer tokens, Stripe signatures, ciphertext blobs, DSNs and the like. Sentry
// events are stored by a third party; treat every field as world-readable.
//
// STRATEGY — defence in depth, two layers:
//   1. Structural — drop whole fields Sentry attaches that we never need
//      (request headers/cookies/query/body, the user's IP, the machine's
//      hostname). Done in observability.ts against the event object.
//   2. Textual — run every free-text string that survives (messages, exception
//      values, breadcrumb text, stack-frame vars, tag/extra/context values)
//      through `redact()`, which pattern-matches known-sensitive shapes and
//      replaces them with typed placeholders like [pubkey] / [ip] / [token].
//
// The redactors are ordered most-specific → least-specific so a token isn't
// half-eaten by the generic hex rule. This is best-effort defence, not a proof:
// prefer NOT logging a secret over relying on this to catch it. But when a
// third-party stack frame or an unexpected error message does carry one, this
// is the net.
//
// Pure and dependency-free on purpose: it's unit-tested in isolation and safe to
// import from both the logger sink and the Sentry beforeSend/beforeBreadcrumb
// hooks without pulling Sentry in.

// Cap on how deep/wide we walk a structure — a runaway object shouldn't turn
// scrubbing into the thing that stalls the event loop.
const MAX_DEPTH = 6;
const MAX_STRING = 8192;

// --- Ordered textual redactors -------------------------------------------------
// Each entry replaces a sensitive shape with a typed placeholder. Order matters:
// specific, high-entropy shapes first so the broad hex/base64 rules can't chew a
// token in half.
// PORTABILITY: no \b and no \s anywhere below, deliberately.
//
// Both are engine-defined, and this rule set is mirrored in the Swift client
// (apps/apple/DissQus/Helpers/Redaction.swift) which runs on ICU, not on V8:
//
//   \b  JS defines word characters as [A-Za-z0-9_]; ICU uses the Unicode
//       property. So "𝔘t=1614556800,v1=…" has a boundary before `t` in JS and
//       none in ICU — the Stripe signature rule fired on one platform only.
//   \s  JS includes U+FEFF; ICU does not, so [^\s…] consumed a different span
//       on each side.
//
// Written out as explicit ASCII classes, the two engines agree by construction
// rather than by coincidence. Found by test/fuzz/scrub-differential.ts; the
// fuzzer is what keeps it true.
const WB0 = "(?<![A-Za-z0-9_])"; // start-of-word boundary, ASCII
const WB1 = "(?![A-Za-z0-9_])";  // end-of-word boundary, ASCII
const WS = " \\t\\n\\r\\f\\x0B"; // ASCII whitespace, for use inside a class

const REDACTORS: Array<{ re: RegExp; to: string }> = [
  // JWTs (three base64url segments) — before the generic base64 rule.
  { re: new RegExp(`${WB0}eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}${WB1}`, "g"), to: "[jwt]" },
  // Credentials embedded in a URL's userinfo, e.g. postgresql://user:pw@host —
  // the classic way a secret rides in a connection error, and the shape
  // DATABASE_URL actually has. Keep the scheme + host, drop the userinfo.
  {
    re: new RegExp(`${WB0}([a-z][a-z0-9+.-]*://)[^/${WS}:@]*:[^/${WS}@]+@`, "gi"),
    to: (_m: string, scheme: string) => `${scheme}[redacted]@`,
  } as any,
  // Authorization / bearer headers and "token=…", "secret=…", "password=…",
  // "apikey=…", "dsn=…" style key/value pairs (JSON, querystring or log form).
  // Group 3 captures an opening quote so the matching close is consumed too.
  {
    re: new RegExp(
      `${WB0}(authorization|auth|bearer|token|secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|dsn|cookie|session|stripe[_-]?signature|signature)${WB1}` +
      `([${WS}]*[:=][${WS}]*|[${WS}]+)("?)[^${WS},;"'}]+\\3`, "gi"),
    to: (_m: string, k: string) => `${k}=[redacted]`,
  } as any,
  // Stripe secrets / webhook signatures and whsec (bodies contain underscores,
  // e.g. sk_live_… / whsec_…).
  { re: new RegExp(`${WB0}(?:sk|rk|whsec|pk)_[A-Za-z0-9_]{10,}${WB1}`, "g"), to: "[stripe-key]" },
  // SYNC INVARIANT: this rule set is mirrored in the iOS scrubber
  // (apple/.../Helpers/Redaction.swift `redactors`). Keep both in step —
  // test/fuzz/scrub-differential.ts checks that they are.
  { re: new RegExp(`${WB0}t=\\d{10},v1=[a-f0-9]{16,}${WB1}`, "g"), to: "[stripe-sig]" },
  // Emails.
  { re: new RegExp(`${WB0}[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}${WB1}`, "g"), to: "[email]" },
  // IPv6 — both the "::"-compressed form and the full 8-group form. Client
  // addresses are PII for an E2EE messenger. (The 8-group rule needs ≥7 colons
  // so it can't eat a "12:34:56"-style timestamp.) Then IPv4.
  // ReDoS FIX. The previous compressed-IPv6 rule was
  //   (?:[A-Fa-f0-9]{1,4}:)*[A-Fa-f0-9]{0,4}::(?:[A-Fa-f0-9]{1,4}:?)*[A-Fa-f0-9]{0,4}
  // and the `:?` made the colon OPTIONAL, so a run of hex after `::` could be
  // partitioned exponentially many ways. "fe80::" + 64 hex chars + a letter (the
  // letter fails the closing boundary, forcing every partition to be tried) does
  // not terminate — measured at over ten minutes before being killed, on both
  // engines. Every Sentry message, breadcrumb and exception string goes through
  // here, so an attacker-influenced string reaching a log line hangs the process.
  // Each side of `::` is now a colon-separated list with exactly one colon
  // between groups: unambiguous, and linear. Found by scrub-differential.ts.
  { re: new RegExp(`${WB0}(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?::(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?${WB1}`, "g"), to: "[ip]" },
  { re: new RegExp(`${WB0}(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}${WB1}`, "g"), to: "[ip]" },
  { re: new RegExp(`${WB0}(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)${WB1}`, "g"), to: "[ip]" },
  // Public keys / secret keys / ciphertext: long hex (≥32) or long base64 (≥40).
  // These are the stable identifiers in this system, so redact aggressively.
  { re: new RegExp(`${WB0}[A-Fa-f0-9]{32,}${WB1}`, "g"), to: "[key]" },
  { re: new RegExp(`${WB0}[A-Za-z0-9+/]{40,}={0,2}${WB1}`, "g"), to: "[blob]" },
  // @usernames (handles) — a username maps 1:1 to a person here.
  { re: new RegExp(`(^|[${WS}([{:,'"])@[A-Za-z0-9_]{2,32}${WB1}`, "g"), to: (_m: string, pre: string) => `${pre}@[user]` } as any,
];

/**
 * Redact known-sensitive shapes from a single string. Idempotent-ish (running it
 * twice yields the same placeholders) and length-capped so a pathological input
 * can't blow up. Returns the input unchanged when it's not a non-empty string.
 */
export function redact(input: unknown): string {
  if (typeof input !== "string" || input.length === 0) return input as string;
  // Capped in UNICODE SCALARS, not in `.length`.
  //
  // `.length` counts UTF-16 code units, and the Swift twin's `.count` counts
  // GRAPHEME CLUSTERS — so "𝔘" is 2 to one and 1 to the other, and a long string
  // was cut in a different place on each platform. Neither unit is portable:
  // slicing UTF-16 can split a surrogate pair, which a Swift String cannot even
  // hold. Scalars are the unit both languages can count and cut identically.
  //
  // For ASCII — which is nearly all of it — this is the same number as before.
  const scalars = Array.from(input);
  let s = scalars.length > MAX_STRING
    ? scalars.slice(0, MAX_STRING).join("") + "…[truncated]"
    : input;
  for (const { re, to } of REDACTORS) {
    s = s.replace(re, to as any);
  }
  return s;
}

// Object keys whose *value* is sensitive regardless of what it looks like. We
// redact the whole value rather than trust the textual patterns to catch it.
//
// Matching is word-aware, NOT substring: "tripped" must not match "ip",
// "recipient"/"description" must not match "ip"/"sig". We split the key on
// camelCase and separators into words, then check whole words + a few glued
// multi-word phrases (so "publicKeyBytes" still trips on "publickey").
const SENSITIVE_WORDS = new Set([
  "authorization", "auth", "bearer", "cookie", "token", "secret", "password",
  "passwd", "pwd", "apikey", "dsn", "session", "signature", "sig", "credential",
  "credentials", "pubkey", "payload", "ciphertext", "nonce", "ip",
]);
const SENSITIVE_PHRASES = [
  "publickey", "privatekey", "apikey", "accesskey", "secretkey",
  "ipaddress", "remoteaddress", "xforwardedfor",
];

function keyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2") // split camelCase
    .split(/[^A-Za-z0-9]+/) // split snake/kebab/space
    .map((w) => w.toLowerCase())
    .filter(Boolean);
}

/**
 * Exported for the differential fuzzer (test/fuzz/scrub-differential.ts), which
 * compares this against `Redaction.isSensitive` in the Swift client. The two
 * split camelCase with different regex engines, and they only have to disagree
 * about one key name for a value to be dropped on one platform and sent on the
 * other. Not part of the module's intended surface otherwise — `scrubDeep` is.
 */
export function isSensitiveKey(key: string): boolean {
  const words = keyWords(key);
  if (words.some((w) => SENSITIVE_WORDS.has(w))) return true;
  const glued = words.join("");
  return SENSITIVE_PHRASES.some((p) => glued.includes(p));
}

/**
 * Recursively scrub an arbitrary JSON-ish value: redact strings, drop values of
 * sensitive-named keys, and bound depth. Mutates nothing — returns a new value.
 * Used for tags / extra / contexts and breadcrumb data.
 */
export function scrubDeep<T>(value: T, depth = 0): T {
  if (depth > MAX_DEPTH) return "[max-depth]" as unknown as T;
  if (value == null) return value;
  if (typeof value === "string") return redact(value) as unknown as T;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.map((v) => scrubDeep(v, depth + 1)) as unknown as T;
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k) ? "[redacted]" : scrubDeep(v, depth + 1);
    }
    return out as unknown as T;
  }
  return value;
}

// --- Sentry event/breadcrumb shaping ------------------------------------------
// Typed loosely (`any`) on purpose so this module stays free of a hard Sentry
// import and can be unit-tested against plain objects. observability.ts wires
// these into beforeSend / beforeBreadcrumb.

/**
 * Scrub a Sentry breadcrumb in place: redact its message and deep-scrub its
 * data bag. Returns the same object for convenience.
 */
export function scrubBreadcrumb(crumb: any): any {
  if (!crumb) return crumb;
  if (typeof crumb.message === "string") crumb.message = redact(crumb.message);
  if (crumb.data) crumb.data = scrubDeep(crumb.data);
  return crumb;
}

/**
 * Structurally + textually scrub a Sentry event before it's sent:
 *   - drop request (headers/cookies/query/body), user IP, and the machine
 *     hostname — fields we never need and that leak PII / topology;
 *   - redact the top-level message and every exception value + stack-frame vars;
 *   - deep-scrub breadcrumbs, tags, extra and contexts.
 * Returns the same event object.
 */
export function scrubEvent(event: any): any {
  if (!event) return event;

  // 1. Structural drops — cheaper and more reliable than pattern-matching.
  delete event.request; // headers, cookies, query_string, data, url params
  delete event.server_name; // container hostname → infra topology
  if (event.user) {
    // Keep an opaque id if one was set on purpose; never keep network identifiers.
    delete event.user.ip_address;
    delete event.user.email;
    delete event.user.username;
  }

  // 2. Top-level message.
  if (typeof event.message === "string") event.message = redact(event.message);
  if (event.logentry?.message) event.logentry.message = redact(event.logentry.message);

  // 3. Exceptions: type/value strings and any captured local variables.
  const values = event.exception?.values;
  if (Array.isArray(values)) {
    for (const ex of values) {
      if (typeof ex.value === "string") ex.value = redact(ex.value);
      const frames = ex.stacktrace?.frames;
      if (Array.isArray(frames)) {
        for (const f of frames) {
          if (f.vars) f.vars = scrubDeep(f.vars);
        }
      }
    }
  }

  // 4. Breadcrumbs.
  const crumbs = event.breadcrumbs?.values ?? event.breadcrumbs;
  if (Array.isArray(crumbs)) crumbs.forEach(scrubBreadcrumb);

  // 5. Structured bags.
  if (event.tags) event.tags = scrubDeep(event.tags);
  if (event.extra) event.extra = scrubDeep(event.extra);
  if (event.contexts) event.contexts = scrubDeep(event.contexts);

  return event;
}
