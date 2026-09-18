// Leveled logger — replaces the ~100 raw console.* calls scattered through the
// relay + bot so that (a) Docker stdout stops carrying the per-message emoji
// firehose, and (b) errors/warnings still reach Sentry with a trail of recent
// activity.
//
// Docker-noise policy (the ask: "remove logging to docker but ok for Sentry"):
//   - Per-message chatter was moved to logger.debug(), which is OFF by default
//     (LOG_LEVEL defaults to "info" in prod, "debug" in dev). So under normal
//     load Docker's json-file driver stays quiet.
//   - logger.error()/logger.warn() still print (to stderr/stdout) AND forward to
//     Sentry, so real problems are never silently swallowed.
//   - info/warn/error also drop a Sentry *breadcrumb*, so when something does
//     crash, the event carries the last N log lines as context — without those
//     lines ever hitting Docker's logs.
//
// This module must not import Sentry eagerly (observability.ts imports the
// logger during its own init). It looks Sentry up lazily via a registered sink.
//
// Stdout scrubbing (OBS-2): Docker's json-file driver captures whatever we print,
// so — as defence in depth on top of keeping LOG_LEVEL=info in prod — every arg
// is run through the same pure `redact`/`scrubDeep` used at the Sentry boundary
// before it reaches the console. `scrub.ts` is dependency-free (no Sentry), so
// importing it here is safe. The Sentry side redacts separately, in
// `beforeSend: scrubEvent` — this half is only about what reaches the console.
//
// ── Log injection ────────────────────────────────────────────────────────────
//
// `redact` removes SHAPES. It has never had an opinion about CONTROL characters,
// and a log line is newline-delimited, so a string carrying one is two lines by
// the time Docker sees it. Plenty of attacker-influenced values reach a log
// line — a handle, a topic, an APNs or EMQX error body echoed back — and any of
// them can spell:
//
//     bob\n[apns] 200 delivered to every device
//
// which lands in the same json-file the operator greps, indistinguishable from a
// line this process wrote. Forging log entries is the cheap half; the expensive
// half is that it makes every other line untrustworthy, including the ones an
// incident is being reconstructed from.
//
// So every control character is ESCAPED rather than dropped: the content of the
// field is preserved and visible, and it can no longer end a line. C0, DEL, C1,
// and U+2028/U+2029 — the last two because a JSON log consumer will happily
// treat them as line breaks even though a terminal will not.
//
// This is confined to the console path on purpose. The fuzzed, mirrored surface
// is `redact`/`isSensitiveKey` in scrub.ts (test/fuzz/scrub-differential.ts
// against Redaction.swift); `scrubArgs` is above it and server-only, so
// tightening here does not put the two implementations out of step.

import { redact, scrubDeep } from "./scrub";

/** C0, DEL, C1, and the two Unicode line separators a JSON log reader will
 *  break on. `\n` `\r` `\t` keep their familiar spelling; everything else
 *  becomes `\xNN` / `\uNNNN`, which is unambiguous and still greppable. */
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
const NAMED: Record<string, string> = { "\n": "\\n", "\r": "\\r", "\t": "\\t" };

export function escapeControl(s: string): string {
  return s.replace(CONTROL_RE, (c) => {
    const named = NAMED[c];
    if (named) return named;
    const code = c.codePointAt(0)!;
    return code <= 0xff
      ? `\\x${code.toString(16).padStart(2, "0")}`
      : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

/** `scrubDeep` output with every remaining string escaped. Keys too: an object
 *  logged with an attacker-chosen key prints that key. */
function escapeDeep(v: unknown, depth = 0): unknown {
  if (typeof v === "string") return escapeControl(v);
  if (depth > 8 || v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map((x) => escapeDeep(x, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v)) out[escapeControl(k)] = escapeDeep(val, depth + 1);
  return out;
}

/**
 * An Error whose message cannot forge a line, with its frames intact.
 *
 * Errors used to pass through untouched to keep the stack readable, and the
 * stack is genuinely worth keeping — but `err.stack` begins with the message,
 * so an attacker-supplied one (a parse failure quoting its input, an HTTP body
 * echoed into `new Error`) is inside the multi-line string being printed.
 *
 * Rebuilt rather than flattened: the message is escaped and the `    at …`
 * frames are carried over as they were, so a normal stack still reads like a
 * stack. An Error with nothing to escape is returned as-is, untouched, which is
 * every Error this process raises itself.
 *
 * The frames are found by LENGTH, not by shape. Picking out every line of the
 * stack matching /^\s+at\s/ is the obvious implementation and it is wrong: a
 * message can contain a line that looks exactly like a frame — which is the
 * whole point of the attack — and such a line would then be promoted out of the
 * message and into the frame list, forging a stack entry instead of a log entry.
 * V8 writes `name: message` and then the frames, so slicing that prefix off is
 * what separates what the attacker wrote from what the runtime did. If the stack
 * does not start with the prefix (a subclass that rewrote it, a non-V8 engine),
 * there is no way to tell the halves apart and the frames are dropped rather
 * than guessed at.
 */
function safeError(e: Error): Error {
  const message = escapeControl(e.message);
  if (message === e.message) return e;
  const head = e.message ? `${e.name}: ${e.message}` : e.name;
  const stack = e.stack ?? "";
  const rest = stack.startsWith(head) ? stack.slice(head.length) : "";
  const frames = rest.split("\n").filter((l) => /^\s+at\s/.test(l));
  const copy = new Error(message);
  copy.name = escapeControl(e.name);
  copy.stack = [`${copy.name}: ${message}`, ...frames].join("\n");
  return copy;
}

function scrubArg(a: unknown): unknown {
  if (typeof a === "string") return escapeControl(redact(a));
  if (a instanceof Error) return safeError(a);
  return escapeDeep(scrubDeep(a));
}
function scrubArgs(args: unknown[]): unknown[] {
  return args.map(scrubArg);
}

export type LogLevel = "silent" | "error" | "warn" | "info" | "debug";

const ORDER: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
};

function resolveLevel(): LogLevel {
  const raw = (process.env.LOG_LEVEL || "").toLowerCase();
  if (raw in ORDER) return raw as LogLevel;
  // Default: quiet in prod (info — no per-message debug), chatty in dev.
  return process.env.NODE_ENV === "production" ? "info" : "debug";
}

let currentLevel: LogLevel = resolveLevel();
export function setLogLevel(l: LogLevel) {
  currentLevel = l;
}
export function getLogLevel(): LogLevel {
  return currentLevel;
}
function enabled(l: Exclude<LogLevel, "silent">): boolean {
  return ORDER[currentLevel] >= ORDER[l];
}

// --- Sentry sink (registered by observability.ts once Sentry is initialised) ---
export interface SentrySink {
  breadcrumb: (level: "info" | "warning" | "error", message: string) => void;
  captureError: (err: unknown, message?: string) => void;
  captureMessage: (message: string, level: "warning" | "error") => void;
}
let sink: SentrySink | null = null;
export function registerSentrySink(s: SentrySink) {
  sink = s;
}

function fmt(args: unknown[]): string {
  return args
    .map((a) =>
      typeof a === "string"
        ? a
        : a instanceof Error
        ? a.stack || a.message
        : (() => {
            try {
              return JSON.stringify(a);
            } catch {
              return String(a);
            }
          })()
    )
    .join(" ");
}

// --- Sentry flood control (quota protection) --------------------------------
//
// Every logger.error() used to become one Sentry EVENT, unconditionally. That
// is what exhausted a month's quota in production: the bot's `openSession`
// catch-all fired once per peer per FRIEND_POLL_MS (15s) for any user who had
// not yet published prekeys — 240 events an hour, per user, for a condition
// that is expected and self-resolving.
//
// The call sites are being fixed, but a call site is the wrong place for the
// only defence: the next one is written by someone who has not read this
// comment, on a path that only floods in production, under a condition nobody
// reproduced locally. So the throttle lives HERE, where every current and
// future error passes.
//
// Shape: first occurrence of a fingerprint goes straight through, then at most
// one per THROTTLE_MS, and that one carries how many were suppressed. So a
// genuine new failure is never delayed, a persistent one stays visible at a
// readable cadence, and neither can spend the quota.
//
// NOTHING is throttled on the console — stderr is not metered and an operator
// tailing logs should see every occurrence. This only gates the Sentry sink.
// Resolved per call rather than at module load. Read once into a const, the
// knob could not actually be turned: an operator raising it on a flooding host
// would have had to restart the process to apply it, which is the worst moment
// to need a restart. It is one env lookup on an already-expensive path.
function throttleMs(): number {
  const raw = Number(process.env.SENTRY_THROTTLE_MS);
  return Number.isFinite(raw) && raw >= 0 ? raw : 10 * 60 * 1000;
}
// Bounded so a process with unbounded distinct fingerprints cannot grow this
// map forever; oldest-first eviction is fine because an evicted key simply gets
// one more event through.
const THROTTLE_MAX_KEYS = 500;

interface Seen { until: number; suppressed: number }
const seen = new Map<string, Seen>();

// Injectable so the throttle's own tests are deterministic. They used to drive
// it with a 1 ms window and a busy-wait, which passed locally and failed on a
// loaded CI runner: 1 ms elapsed between two synchronous calls, the window
// lapsed, and a "suppressed" event was sent. A test for time-based behaviour
// should not itself depend on how fast the machine is.
let clock: () => number = Date.now;
/** Test seam. Pass nothing to restore the real clock. */
export function setLoggerClock(fn?: () => number): void {
  clock = fn ?? Date.now;
}

/**
 * Collapse the volatile parts of a message so that the same FAILURE, about
 * different peers or at different offsets, shares one budget.
 *
 * Without this, "could not open a session with @alice…" and "…with @bob…" are
 * distinct fingerprints and 200 users still produce 200 events per cycle. The
 * per-peer detail is not lost — it is on the event that does get through, and
 * on every console line.
 */
export function fingerprint(message: string): string {
  // Truncate FIRST. Every pattern below then runs over at most 200 characters,
  // which bounds the work regardless of how long a log line gets.
  //
  // The handle pattern used to be `[^\s]*@[^\s]*`, which is quadratic: on a
  // long run of non-space characters with no `@`, the engine consumes to the
  // end and backtracks from every start position. A ReDoS on the ERROR path is
  // a bad place to have one — that path is reached exactly when something is
  // already going wrong, and often in a loop. Anchoring on the literal `@`
  // makes it linear, and `@` is where the volatile part starts anyway.
  return message
    .slice(0, 200)
    .replace(/\b[0-9a-f]{6,}\b/gi, "#")   // ids, hashes, key fragments
    .replace(/\b\d+\b/g, "#")             // counts, ports, status codes
    .replace(/@\S*/g, "@")                 // handles and addresses
    .replace(/\s+/g, " ")
    .trim();
}

/** Whether this message may spend a Sentry event now, and what to append. */
function admit(message: string): { send: boolean; note: string } {
  const now = clock();
  const key = fingerprint(message);
  const prev = seen.get(key);

  if (prev && now < prev.until) {
    prev.suppressed++;
    return { send: false, note: "" };
  }

  if (seen.size >= THROTTLE_MAX_KEYS && !prev) {
    const oldest = seen.keys().next();
    if (!oldest.done) seen.delete(oldest.value);
  }
  const window = throttleMs();
  seen.set(key, { until: now + window, suppressed: 0 });

  const n = prev?.suppressed ?? 0;
  return {
    send: true,
    note: n > 0 ? ` [+${n} identical suppressed in the last ${Math.round(window / 60000)}m]` : "",
  };
}

/** Test seam: forget every throttle window. */
export function resetSentryThrottle(): void {
  seen.clear();
}

export const logger = {
  /** High-volume per-message tracing. Off by default (LOG_LEVEL=debug to see). */
  debug(...args: unknown[]) {
    if (enabled("debug")) console.log(...scrubArgs(args));
    // Deliberately NOT breadcrumbed — this is the firehose we're keeping out of
    // both Docker and Sentry under normal load.
  },
  info(...args: unknown[]) {
    if (enabled("info")) console.log(...scrubArgs(args));
    sink?.breadcrumb("info", fmt(args));
  },
  warn(...args: unknown[]) {
    if (enabled("warn")) console.warn(...scrubArgs(args));
    const msg = fmt(args);
    sink?.breadcrumb("warning", msg);
  },
  /**
   * Real errors: always surfaced to stderr (unless LOG_LEVEL=silent) AND sent to
   * Sentry as an exception event. Pass an Error first for a proper stack.
   *
   * The Sentry half is throttled per fingerprint — see the note above. The
   * console half never is.
   *
   * If what you are reporting is EXPECTED and self-resolving (a peer with no
   * prekeys yet, a reconnect that will succeed), it is not an error: use warn
   * for the first occurrence, or debug. The throttle bounds the damage; it does
   * not make a non-error into one.
   */
  error(...args: unknown[]) {
    if (enabled("error")) console.error(...scrubArgs(args));
    const errArg = args.find((a) => a instanceof Error);
    const msg = fmt(args);
    if (!sink) return;
    const { send, note } = admit(msg);
    if (!send) return;
    if (errArg) sink.captureError(errArg, msg + note);
    else sink.captureMessage(msg + note, "error");
  },
  /**
   * An operational EVENT: something a human has to see, which is not a failure.
   *
   * `warn` only drops a breadcrumb, so a warned line is invisible until
   * something else crashes and carries it along as context. That is the right
   * shape for "this looked odd" and the wrong shape for "somebody filed an abuse
   * report", where the whole point is that a person acts within 24 hours. `error`
   * is the wrong shape too: a report is not a failure, and error is throttled per
   * fingerprint, which is a mechanism for suppressing repetition.
   *
   * Deliberately NOT throttled. Every call here is a distinct thing that needs
   * somebody, and suppressing the second one in an hour is precisely the case
   * that matters most.
   */
  event(...args: unknown[]) {
    if (currentLevel !== "silent") console.warn(...scrubArgs(args));
    const msg = fmt(args);
    sink?.breadcrumb("warning", msg);
    sink?.captureMessage(msg, "warning");
  },
  /** Startup/operational lines we always want visible even at LOG_LEVEL=info. */
  startup(...args: unknown[]) {
    if (currentLevel !== "silent") console.log(...scrubArgs(args));
    sink?.breadcrumb("info", fmt(args));
  },
};

export type Logger = typeof logger;
