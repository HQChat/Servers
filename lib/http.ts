// The small HTTP layer every service shares.
//
// `auth/main.ts` and `api/main.ts` each carried their own copy of readJson /
// send / bearer — same code, drifting body caps (64 KB vs 256 KB) and no shared
// error shape. Two services is where copy-paste stops being cheaper than a
// module, and a third (ops) is already here.
//
// It also carries the request id, which is the thing that makes a report like
// "it failed for me at 14:32" actionable: one id ties the client's error to a
// server log line to a Sentry event.

import * as http from "http";
import * as crypto from "crypto";
import { logger } from "./logger";

/** Max request body. Anything larger is refused before it is buffered. */
export const MAX_BODY_BYTES = 256 * 1024;

export class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message?: string) {
    super(message || code);
  }
}

/**
 * Parse a JSON body, refusing anything oversized or malformed.
 *
 * BUFFERS BYTES, NOT A STRING, and the distinction is the whole function.
 *
 * This used to accumulate `data += c`, which does two wrong things at once.
 *
 *   THE CAP WAS NOT IN BYTES. `data.length` counts UTF-16 code units while
 *   MAX_BODY_BYTES is named, documented and reasoned about in bytes. A character
 *   in U+0800–U+FFFF is three UTF-8 bytes and one code unit, so the real ceiling
 *   was 3x the stated one: a 786 kB body sailed through a 256 kB cap. That cap is
 *   the DoS bound for every route on both services, and api/main.ts sizes its
 *   prekey-upload limit against it at startup — arithmetic that only held because
 *   hex is ASCII.
 *
 *   MULTI-BYTE CHARACTERS WERE CORRUPTED. `data += c` calls Buffer.toString() on
 *   each chunk independently, so a character split across a TCP chunk boundary
 *   decoded as replacement characters on both sides of the seam. Any body large
 *   enough to be split and containing non-ASCII — a display name, a username —
 *   was silently mangled before it was ever parsed.
 *
 * Both were found by test/fuzz/http-body.ts.
 */
export function readJson(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      if (tooBig) return;
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        tooBig = true;
        // Reject NOW, and then DISCARD the rest rather than destroying the
        // socket.
        //
        // Destroying is the obvious move and it loses a race it cannot win. The
        // route still has to write the 413, and the caller is still pushing the
        // remaining body; tearing the connection down — even a tick later —
        // means the response sometimes never lands and the caller sees a bare
        // reset instead. It cannot then tell "too large" from "the server fell
        // over", and the obvious response to the latter is to retry the same
        // oversized body. Under parallel load that race flipped often enough to
        // make the test for it flaky, which is how it was found.
        //
        // Discarding keeps MEMORY bounded, which is what the cap is actually
        // defending: nothing further is retained. What it does not bound is how
        // long a client may keep sending, and that is deliberately left to the
        // layers that already own it — Node's requestTimeout, and the nginx and
        // Cloudflare body limits in front of this.
        reject(new HttpError(413, "BODY_TOO_LARGE"));
        chunks.length = 0;
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (tooBig) return;   // already rejected above
      // Decoded ONCE, over the whole body, so no character is split.
      const data = Buffer.concat(chunks).toString("utf8");
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(new HttpError(400, "INVALID_JSON"));
      }
    });
    req.on("error", reject);
  });
}

/** JSON response. Echoes the request id so a client can quote it in a report. */
export function send(res: http.ServerResponse, status: number, body: unknown, requestId?: string): void {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (requestId) headers["x-request-id"] = requestId;
  res.writeHead(status, headers);
  res.end(JSON.stringify(body));
}

export function bearer(req: http.IncomingMessage): string {
  return (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
}

/**
 * The caller's request id, or a fresh one. Trusted only for correlation — it is
 * client-supplied, never an identity, and never used in a security decision.
 */
export function requestId(req: http.IncomingMessage): string {
  const given = String(req.headers["x-request-id"] || "").trim();
  if (/^[A-Za-z0-9_.:-]{1,64}$/.test(given)) return given;
  return crypto.randomUUID();
}

/**
 * The caller's IP, trusting only headers the EDGE sets.
 *
 * Carried over from the retired monolith with its reasoning intact (SRV-ip):
 * never take the leftmost `X-Forwarded-For`, which is attacker-controlled. Count
 * back from the right by the number of proxies we actually run, so a spoofed
 * prefix cannot move the value we rate-limit on.
 */
const TRUSTED_PROXY_HOPS = Number(process.env.TRUSTED_PROXY_HOPS || 1);

export function clientIp(req: http.IncomingMessage): string {
  if (process.env.TRUST_CF_CONNECTING_IP !== "false") {
    const cf = String(req.headers["cf-connecting-ip"] || "").trim();
    if (cf) return cf;
  }
  const realIp = String(req.headers["x-real-ip"] || "").trim();
  if (realIp) return realIp;

  const xff = String(req.headers["x-forwarded-for"] || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (xff.length) {
    const idx = Math.max(0, xff.length - TRUSTED_PROXY_HOPS);
    return xff[idx] ?? req.socket.remoteAddress ?? "unknown";
  }
  return req.socket.remoteAddress || "unknown";
}

// --- Body validation -------------------------------------------------------
// Routes used to do `String(body.username)`, which turns `undefined` into the
// string "undefined" and an object into "[object Object]" — both of which then
// travel into the database as if they were real values.

/** A required string field, trimmed and length-bounded. Throws HttpError(400). */
export function requireString(body: any, field: string, opts: { min?: number; max?: number } = {}): string {
  const { min = 1, max = 512 } = opts;
  const raw = body?.[field];
  if (typeof raw !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a string`);
  const value = raw.trim();
  if (value.length < min || value.length > max) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must be ${min}–${max} characters`);
  }
  return value;
}

/**
 * An OPTIONAL string field: absent, null and empty all mean "not given" and come
 * back as null, so a caller never has to distinguish three ways of saying
 * nothing. A present non-string is still a 400 — sending `note: 42` is a bug in
 * the client, not a way of omitting the field.
 */
export function optionalString(body: any, field: string, opts: { max?: number } = {}): string | null {
  const { max = 512 } = opts;
  const raw = body?.[field];
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a string`);
  const value = raw.trim();
  if (!value) return null;
  if (value.length > max) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must be at most ${max} characters`);
  }
  return value;
}

/**
 * An OPTIONAL base64 field, decoded and bounded in BYTES.
 *
 * Bounded after decoding rather than before, because base64 is 4/3 the size of
 * what it carries and a cap on the string is a cap on the wrong number — the
 * same class of mistake readJson's own comment describes for UTF-16 length.
 * Re-encoding and comparing is what rejects a string that is not really base64:
 * Buffer.from(s, "base64") silently drops anything outside the alphabet rather
 * than failing, so a decode alone accepts garbage and returns a short buffer.
 */
export function optionalBase64(body: any, field: string, maxBytes: number): Buffer | null {
  const raw = body?.[field];
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a base64 string`);
  if (!raw) return null;
  const buf = Buffer.from(raw, "base64");
  // Padding is the one difference that is not a difference, so both sides lose
  // it before they are compared.
  const unpadded = (s: string) => s.replace(/=+$/, "");
  if (unpadded(buf.toString("base64")) !== unpadded(raw)) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must be base64`);
  }
  if (buf.length === 0) return null;
  if (buf.length > maxBytes) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must decode to at most ${maxBytes} bytes`);
  }
  return buf;
}

/** A required lowercase-hex field of an exact byte length (public keys, hashes). */
export function requireHex(body: any, field: string, bytes: number): string {
  const value = requireString(body, field, { min: bytes * 2, max: bytes * 2 });
  if (!/^[0-9a-fA-F]+$/.test(value)) throw new HttpError(400, "INVALID_FIELD", `${field} must be hex`);
  return value;
}

/**
 * Wrap a request handler: assigns a request id, times the call, logs one line
 * per request at debug, and turns a thrown HttpError into its status + code.
 * Anything else is a 500 with no detail — the detail goes to the log and Sentry.
 */
export function handler(
  service: string,
  fn: (req: http.IncomingMessage, res: http.ServerResponse, ctx: { id: string }) => Promise<void>
): http.RequestListener {
  return async (req, res) => {
    const id = requestId(req);
    const started = Date.now();
    try {
      await fn(req, res, { id });
    } catch (e) {
      const err = e as Error;
      if (err instanceof HttpError) {
        send(res, err.status, { error: err.code, message: err.message }, id);
      } else {
        logger.error(`[${service}] ${req.method} ${req.url} [${id}] — ${err.message}`, err);
        send(res, 500, { error: "INTERNAL" }, id);
      }
    } finally {
      logger.debug(`[${service}] ${req.method} ${req.url} → ${res.statusCode} ${Date.now() - started}ms [${id}]`);
    }
  };
}
