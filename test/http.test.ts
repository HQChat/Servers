// The shared HTTP layer — body cap, client IP, field validation, error shaping.
//
// This module sat at 46% function coverage, which is a strange number for the
// file that holds the DoS bound for every route on both services, the defence
// against a spoofed X-Forwarded-For, and the validators standing between request
// JSON and the database.
//
// Two of the tests below are regressions for defects found while writing them;
// both are marked. The `clientIp` block is the one to read first: its rule is a
// carried-over finding (SRV-ip) whose whole point is that the LEFTMOST
// X-Forwarded-For is attacker-controlled, and nothing was checking that the code
// still counted from the right.

import { test, describe, it } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import {
  readJson, send, bearer, requestId, clientIp,
  requireString, requireHex, handler,
  HttpError, MAX_BODY_BYTES,
} from "../lib/http";

// --- helpers ---------------------------------------------------------------

/** A fake IncomingMessage carrying just headers and a socket address. */
function req(headers: Record<string, string | undefined>, remote = "203.0.113.9"): http.IncomingMessage {
  return { headers, socket: { remoteAddress: remote } } as unknown as http.IncomingMessage;
}

/** Run one request through a real server and return status + body. */
async function roundTrip(
  listener: http.RequestListener,
  body: Buffer | string,
  opts: { split?: boolean } = {},
): Promise<{ status: number | null; text: string; headers: http.IncomingHttpHeaders; netError?: string }> {
  const server = http.createServer(listener);
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);

  try {
    return await new Promise((resolve, reject) => {
      // Resolve only once BOTH the response has been read and the client socket
      // has closed.
      //
      // An oversize body is answered and then hung up on, so the client's
      // remaining unsent bytes fail with EPIPE — which is the behaviour under
      // test, not a defect. But it arrives asynchronously, and resolving on the
      // response alone let it land after the test had finished, where the runner
      // reports it as "activity after the test ended" rather than as the
      // expected consequence it is.
      let answer: { status: number | null; text: string; headers: http.IncomingHttpHeaders; netError?: string } | null = null;
      let closed = false;
      const done = () => { if (answer && closed) resolve(answer); };

      // `agent: false` — a connection of its own per request.
      //
      // Node 19+ turns keep-alive ON for the global agent, so a socket the server
      // destroyed while refusing an oversize body got handed straight back out to
      // the next request. That surfaced as EPIPE on bodies comfortably UNDER the
      // cap — a harness artifact that reads exactly like a server defect.
      const r = http.request({ port, method: "POST", path: "/", agent: false }, (res) => {
        // Bytes, decoded once — `text += chunk` is the same defect this file
        // tests for, and it would corrupt any response big enough to be split.
        const parts: Buffer[] = [];
        res.on("data", (d: Buffer) => parts.push(d));
        res.on("end", () => {
          answer = { status: res.statusCode!, text: Buffer.concat(parts).toString("utf8"), headers: res.headers };
          done();
        });
      });
      r.on("close", () => { closed = true; done(); });
      // A socket error before any response is REPORTED, not thrown.
      //
      // Refusing a body mid-upload means responding before the request has been
      // read, and Node closes the connection when that happens — so a client
      // still pushing the remainder can see ECONNRESET before it reads the 413.
      // That is a race no implementation can win, and asserting a status through
      // it made this suite flaky under the parallel load of the full run. The
      // property that actually holds is "not accepted", so the caller gets to
      // decide.
      r.on("error", (e: any) => {
        if (!answer) answer = { status: null, text: "", headers: {}, netError: e.code ?? e.message };
        closed = true;
        done();
      });
      if (opts.split) {
        // Land the split mid-character on purpose.
        const half = Math.floor(payload.length / 2) + 1;
        r.write(payload.subarray(0, half));
        setTimeout(() => r.end(payload.subarray(half)), 20);
      } else {
        r.end(payload);
      }
    });
  } finally {
    server.close();
  }
}

/** An oversize body must never be ACCEPTED. Whether the caller gets to read the
 *  413 depends on whether it is still writing when the server answers. */
function assertRefused(r: { status: number | null; text: string; netError?: string }) {
  assert.notEqual(r.status, 200, "an oversize body must not be accepted");
  if (r.status !== null) {
    assert.equal(r.status, 413);
    assert.equal(JSON.parse(r.text).error, "BODY_TOO_LARGE");
  }
}

const echo: http.RequestListener = async (rq, rs) => {
  try {
    const body = await readJson(rq);
    send(rs, 200, { ok: true, body });
  } catch (e: any) {
    send(rs, e.status ?? 500, { error: e.code ?? "ERR" });
  }
};

// --- readJson --------------------------------------------------------------

describe("readJson", () => {
  it("parses a JSON body", async () => {
    const r = await roundTrip(echo, JSON.stringify({ a: 1 }));
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(r.text).body, { a: 1 });
  });

  it("treats an empty body as an empty object", async () => {
    const r = await roundTrip(echo, "");
    assert.deepEqual(JSON.parse(r.text).body, {});
  });

  it("refuses malformed JSON with 400 INVALID_JSON", async () => {
    const r = await roundTrip(echo, "{not json");
    assert.equal(r.status, 400);
    assert.equal(JSON.parse(r.text).error, "INVALID_JSON");
  });

  // REGRESSION. The cap is named, documented and reasoned about in BYTES, and
  // api/main.ts sizes its prekey-upload limit against it at startup. It was
  // enforced on `data.length` — UTF-16 code units — so a character in
  // U+0800–U+FFFF (three UTF-8 bytes, one code unit) bought three times the
  // stated ceiling. A 786 kB body passed a 256 kB cap. Found by
  // test/fuzz/http-body.ts.
  it("counts the cap in bytes, not UTF-16 code units", async () => {
    const oversize = Buffer.from(`{"s":"${"ࠀ".repeat(262_000)}"}`, "utf8");
    assert.ok(oversize.length > MAX_BODY_BYTES * 2, "the fixture must be well over the cap");
    assertRefused(await roundTrip(echo, oversize));
  });

  it("accepts a body of exactly the cap and refuses one byte more", async () => {
    const at = Buffer.from(`{"s":"${"a".repeat(MAX_BODY_BYTES - 8)}"}`);
    assert.equal(at.length, MAX_BODY_BYTES);
    assert.equal((await roundTrip(echo, at)).status, 200);

    const over = Buffer.from(`{"s":"${"a".repeat(MAX_BODY_BYTES - 7)}"}`);
    assert.equal(over.length, MAX_BODY_BYTES + 1);
    assertRefused(await roundTrip(echo, over));
  });

  // REGRESSION. `data += chunk` calls Buffer.toString() on each chunk
  // independently, so a character split across a TCP chunk boundary decoded as
  // replacement characters on both sides of the seam. Any body big enough to be
  // split and carrying non-ASCII — a display name, a username — was silently
  // mangled before it was parsed.
  it("does not corrupt a character split across chunks", async () => {
    const payload = Buffer.from(`{"s":"${"ࠀ".repeat(4000)}"}`, "utf8");
    const r = await roundTrip(echo, payload, { split: true });
    assert.equal(r.status, 200);
    const s = JSON.parse(r.text).body.s as string;
    assert.ok(!s.includes("�"), "no replacement characters");
    assert.equal(s.length, 4000, "every character survived");
  });

  // A refusal the caller cannot read is indistinguishable from the server
  // falling over, and the obvious response to that is to retry the same body. So
  // the 413 should land whenever the client is not still mid-upload — which for
  // a body just over the cap, written in one go, is the ordinary case.
  it("answers a just-over-cap body with a readable 413", async () => {
    const r = await roundTrip(echo, Buffer.from(`{"s":"${"a".repeat(MAX_BODY_BYTES)}"}`));
    assert.equal(r.status, 413);
    assert.equal(JSON.parse(r.text).error, "BODY_TOO_LARGE");
  });
});

// --- clientIp --------------------------------------------------------------

describe("clientIp", () => {
  const CF = "cf-connecting-ip";

  it("prefers the edge's own header", () => {
    assert.equal(clientIp(req({ [CF]: "198.51.100.7", "x-forwarded-for": "1.2.3.4" })), "198.51.100.7");
  });

  it("falls back to x-real-ip, then the socket", () => {
    assert.equal(clientIp(req({ "x-real-ip": "198.51.100.8" })), "198.51.100.8");
    assert.equal(clientIp(req({})), "203.0.113.9");
  });

  // THE POINT OF THE WHOLE FUNCTION. Anyone can send X-Forwarded-For, so the
  // leftmost entry is attacker-chosen; only the rightmost entries were written
  // by proxies we run. Taking the left one lets a caller pick the identity every
  // per-IP rate limit and admission check keys on.
  it("ignores a spoofed X-Forwarded-For prefix", () => {
    const spoofed = clientIp(req({ "x-forwarded-for": "1.1.1.1, 2.2.2.2, 198.51.100.20" }));
    assert.notEqual(spoofed, "1.1.1.1", "must not take the leftmost, attacker-supplied entry");
    assert.equal(spoofed, "198.51.100.20", "counts back from the right by TRUSTED_PROXY_HOPS");
  });

  it("a longer spoofed prefix does not move the answer", () => {
    const a = clientIp(req({ "x-forwarded-for": "9.9.9.9, 198.51.100.20" }));
    const b = clientIp(req({ "x-forwarded-for": "8.8.8.8, 7.7.7.7, 6.6.6.6, 198.51.100.20" }));
    assert.equal(a, b, "the value depends on the right-hand end, not on length");
  });

  it("falls back to the socket when the header is empty or junk", () => {
    assert.equal(clientIp(req({ "x-forwarded-for": "" })), "203.0.113.9");
    assert.equal(clientIp(req({ "x-forwarded-for": " , , " })), "203.0.113.9");
  });

  it("reports 'unknown' rather than undefined with no socket address", () => {
    const r = { headers: {}, socket: {} } as unknown as http.IncomingMessage;
    assert.equal(clientIp(r), "unknown");
  });
});

// --- bearer / requestId ----------------------------------------------------

describe("bearer", () => {
  it("strips the scheme, case-insensitively, and trims", () => {
    assert.equal(bearer(req({ authorization: "Bearer abc123" })), "abc123");
    assert.equal(bearer(req({ authorization: "bearer   abc123  " })), "abc123");
    assert.equal(bearer(req({ authorization: "BEARER abc123" })), "abc123");
  });

  it("is empty when absent, and leaves an unknown scheme alone", () => {
    assert.equal(bearer(req({})), "");
    assert.equal(bearer(req({ authorization: "Basic abc123" })), "Basic abc123");
  });
});

describe("requestId", () => {
  it("echoes a well-formed client id", () => {
    assert.equal(requestId(req({ "x-request-id": "abc-123_DEF.4:5" })), "abc-123_DEF.4:5");
  });

  // It is client-supplied and only ever used for correlation, but it reaches log
  // lines — so the charset is a bound on what can be written into them.
  it("replaces anything outside the charset or over 64 chars", () => {
    for (const bad of ["a b", "a\nb", "<script>", "a".repeat(65), "", "  "]) {
      const id = requestId(req({ "x-request-id": bad }));
      assert.notEqual(id, bad);
      assert.match(id, /^[0-9a-f-]{36}$/, `expected a uuid, got ${id}`);
    }
  });
});

// --- field validation ------------------------------------------------------

describe("requireString", () => {
  it("returns a trimmed value", () => {
    assert.equal(requireString({ a: "  hi  " }, "a"), "hi");
  });

  // These exist because routes used to do String(body.x), which turns undefined
  // into "undefined" and an object into "[object Object]" — and both then travel
  // into the database as if they were real values.
  it("refuses a non-string rather than coercing it", () => {
    for (const v of [undefined, null, 1, true, {}, [], () => {}]) {
      assert.throws(() => requireString({ a: v }, "a"), (e: any) => e instanceof HttpError && e.status === 400);
    }
  });

  it("enforces min and max after trimming", () => {
    assert.throws(() => requireString({ a: "   " }, "a"), /1–512/);
    assert.throws(() => requireString({ a: "abc" }, "a", { min: 4 }), /4–512/);
    assert.throws(() => requireString({ a: "abcde" }, "a", { max: 4 }), /1–4/);
    assert.equal(requireString({ a: " abcd " }, "a", { min: 4, max: 4 }), "abcd");
  });

  it("survives a missing body", () => {
    assert.throws(() => requireString(undefined, "a"), (e: any) => e.status === 400);
    assert.throws(() => requireString(null, "a"), (e: any) => e.status === 400);
  });
});

describe("requireHex", () => {
  it("accepts exactly the right byte length, either case", () => {
    assert.equal(requireHex({ k: "abcdef01" }, "k", 4), "abcdef01");
    assert.equal(requireHex({ k: "ABCDEF01" }, "k", 4), "ABCDEF01");
  });

  it("refuses wrong lengths and non-hex", () => {
    assert.throws(() => requireHex({ k: "abcdef0" }, "k", 4), /must be 8–8/);
    assert.throws(() => requireHex({ k: "abcdef012" }, "k", 4), /must be 8–8/);
    assert.throws(() => requireHex({ k: "zzzzzzzz" }, "k", 4), /must be hex/);
    assert.throws(() => requireHex({ k: "abcd ef1" }, "k", 4), /must be hex/);
  });
});

// --- handler ---------------------------------------------------------------

describe("handler", () => {
  it("maps an HttpError to its status and code", async () => {
    const r = await roundTrip(handler("test", async () => {
      throw new HttpError(409, "CONFLICT", "already exists");
    }), "");
    assert.equal(r.status, 409);
    assert.deepEqual(JSON.parse(r.text), { error: "CONFLICT", message: "already exists" });
  });

  // The detail goes to the log and Sentry, never to the caller: an unexpected
  // error's message can carry anything the process knows.
  it("turns anything else into a bare 500", async () => {
    const r = await roundTrip(handler("test", async () => {
      throw new Error("connection string postgres://user:PLACEHOLDER@db/x failed");
    }), "");
    assert.equal(r.status, 500);
    assert.deepEqual(JSON.parse(r.text), { error: "INTERNAL" });
    assert.ok(!r.text.includes("PLACEHOLDER"), "no internal detail reaches the caller");
  });

  it("echoes the request id so a caller can quote it", async () => {
    const r = await roundTrip(handler("test", async (_q, rs, ctx) => {
      send(rs, 200, { ok: true }, ctx.id);
    }), "");
    assert.match(String(r.headers["x-request-id"]), /^[0-9a-f-]{36}$/);
  });
});

// --- send ------------------------------------------------------------------

test("send sets JSON content-type and omits the request id when absent", async () => {
  const r = await roundTrip((_q, rs) => send(rs, 201, { a: 1 }), "");
  assert.equal(r.status, 201);
  assert.equal(r.headers["content-type"], "application/json");
  assert.equal(r.headers["x-request-id"], undefined);
  assert.deepEqual(JSON.parse(r.text), { a: 1 });
});
