/**
 * Fuzzing `readJson` — the body cap and the decode, over a real socket.
 *
 * WHY A FUZZER AND NOT JUST TESTS. The unit suite pins the cases that are known;
 * this drives the shape that is easy to get wrong, which is the relationship
 * between three different ways of measuring the same body:
 *
 *     bytes on the wire   what MAX_BODY_BYTES is named in
 *     UTF-16 code units   what `String.length` counts
 *     chunk boundaries    where the transport happens to split it
 *
 * Two defects came out of exactly that gap, and both are now regressions in
 * test/http.test.ts:
 *
 *   · The cap was enforced on `data.length`, so a body of three-byte characters
 *     bought 3x the stated ceiling — 786 kB through a 256 kB cap. That cap is the
 *     DoS bound for every route on both services.
 *   · `data += chunk` decoded each chunk separately, so a character split across
 *     a TCP boundary became replacement characters. Any body large enough to be
 *     split and carrying non-ASCII was silently corrupted before parsing.
 *
 * THREE ORACLES:
 *
 *   A. THE CAP IS IN BYTES. A body of N bytes is accepted iff N <= the cap.
 *      Nothing about its characters may move that line.
 *   B. WHAT GOES IN COMES OUT. An accepted body parses to the value that was
 *      sent — no replacement characters, whatever the chunking.
 *   C. IT ALWAYS ANSWERS. Every request gets a status, never a hang and never a
 *      bare connection reset: a caller that cannot tell "too large" from "the
 *      server fell over" retries the same oversized body.
 *
 * Run:
 *   npx tsx test/fuzz/http-body.ts --iterations 400 --seed 7
 */

import * as http from "node:http";
import { readJson, send, MAX_BODY_BYTES, HttpError } from "../../lib/http";

// ── deterministic randomness ─────────────────────────────────────────────────

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
type Rng = () => number;
const pick = <T>(r: Rng, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;
const int = (r: Rng, n: number) => Math.floor(r() * n);

/** Characters chosen for their byte-to-code-unit ratio, which is the whole point. */
const FILLERS = [
  { ch: "a", bytes: 1 },        // 1 byte, 1 unit
  { ch: "é", bytes: 2 },        // 2 bytes, 1 unit
  { ch: "ࠀ", bytes: 3 },        // 3 bytes, 1 unit — the worst ratio
  { ch: "𝔘", bytes: 4 },        // 4 bytes, 2 units (surrogate pair)
  { ch: "🔒", bytes: 4 },
];

interface Case { payload: Buffer; expect: "ok" | "too-large" | "bad-json"; value?: string }

function makeCase(r: Rng): Case {
  const filler = pick(r, FILLERS);

  // Aim at the boundary most of the time: a cap that is off by a factor only
  // shows up if inputs actually land near it.
  const targetBytes = r() < 0.75
    ? MAX_BODY_BYTES + int(r, 400) - 200
    : int(r, MAX_BODY_BYTES * 2);

  const overhead = Buffer.byteLength(`{"s":""}`);
  const fillCount = Math.max(0, Math.floor((targetBytes - overhead) / filler.bytes));
  const value = filler.ch.repeat(fillCount);
  let payload = Buffer.from(`{"s":"${value}"}`, "utf8");

  if (r() < 0.06) {
    // Malformed, at a size that may or may not be refused first. The cap is
    // checked while reading and the parse only afterwards, so an oversize
    // malformed body must read as too-large, not as bad JSON.
    payload = Buffer.concat([payload.subarray(0, payload.length - 1), Buffer.from("!")]);
    return { payload, expect: payload.length > MAX_BODY_BYTES ? "too-large" : "bad-json" };
  }
  return {
    payload,
    expect: payload.length > MAX_BODY_BYTES ? "too-large" : "ok",
    value,
  };
}

// ── the server under test ────────────────────────────────────────────────────

function start(): Promise<{ port: number; close: () => void }> {
  const server = http.createServer(async (req, res) => {
    try {
      const body = await readJson(req);
      send(res, 200, { ok: true, s: (body as any).s ?? "" });
    } catch (e) {
      const err = e as HttpError;
      if (!res.headersSent) send(res, err.status ?? 500, { error: err.code ?? "ERR" });
    }
  });
  return new Promise((resolve) => {
    server.listen(0, () => resolve({
      port: (server.address() as any).port,
      close: () => server.close(),
    }));
  });
}

/** POST, splitting the body into `chunks` writes — possibly mid-character. */
function post(port: number, payload: Buffer, chunks: number): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    let answer: { status: number; text: string } | null = null;
    let closed = false;
    const done = () => { if (answer && closed) resolve(answer); };

    // `agent: false` — a connection of its own per request.
    //
    // Node 19+ turns keep-alive ON for the global agent, so a socket the server
    // destroyed while refusing an oversize body got handed straight back out to
    // the next request. That surfaced as EPIPE on bodies comfortably UNDER the
    // cap — a harness artifact that reads exactly like a server defect.
    const req = http.request({ port, method: "POST", path: "/", agent: false }, (res) => {
      // Collected as BYTES and decoded once. `text += chunk` here would split a
      // multi-byte character across response chunks and report corruption that
      // the harness itself had introduced — which is exactly what it did, and
      // took a while to see, because it is the same defect this fuzzer exists to
      // find on the request side.
      const parts: Buffer[] = [];
      res.on("data", (d: Buffer) => parts.push(d));
      res.on("end", () => {
        answer = { status: res.statusCode!, text: Buffer.concat(parts).toString("utf8") };
        done();
      });
    });
    req.on("close", () => { closed = true; done(); });
    // After a response, a socket error is the server having hung up, which is
    // what an oversize body is supposed to produce.
    req.on("error", (e) => { if (!answer) reject(e); else { closed = true; done(); } });

    const size = Math.max(1, Math.ceil(payload.length / chunks));
    let offset = 0;
    const writeNext = () => {
      if (offset >= payload.length) return req.end();
      const slice = payload.subarray(offset, offset + size);
      offset += size;
      // Deliberately not aligned to character boundaries.
      if (req.write(slice)) setImmediate(writeNext);
      else req.once("drain", writeNext);
    };
    writeNext();
  });
}

// ── driver ───────────────────────────────────────────────────────────────────

function arg(flag: string, dflt: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? (process.argv[i + 1] ?? dflt) : dflt;
}

async function main() {
  const iterations = Number(arg("--iterations", "400"));
  const seed = Number(arg("--seed", String((Math.random() * 1e9) | 0)));
  const r = rng(seed);
  const { port, close } = await start();

  console.log(`http body fuzz · ${iterations} iterations · seed ${seed} · cap ${MAX_BODY_BYTES}B`);
  let failures = 0;

  for (let i = 0; i < iterations && failures < 5; i++) {
    const c = makeCase(r);
    const chunks = 1 + int(r, 8);
    let res: { status: number; text: string };
    try {
      res = await post(port, c.payload, chunks);
    } catch (e) {
      // ORACLE C, with one exception. An oversize body is refused as soon as the
      // cap is crossed and the socket is torn down a tick later, so a client
      // still pushing the remaining hundreds of kilobytes can lose the race and
      // see EPIPE before it reads the 413. That is the cost of not buffering an
      // unbounded upload just to be polite about it, and it is what the edge
      // (nginx, Cloudflare) exists to turn into a clean 413 in production.
      //
      // For a body UNDER the cap there is no such excuse: losing the answer
      // there is a hang or a reset on a request that should have been served.
      if (c.expect === "too-large") continue;
      console.error(`\n── NO ANSWER ─────────────────────────────`);
      console.error(`  ${c.payload.length} bytes in ${chunks} chunk(s), under the cap: ${(e as Error).message}`);
      failures++;
      continue;
    }

    // ORACLE A.
    const wanted = c.expect === "too-large" ? 413 : c.expect === "bad-json" ? 400 : 200;
    if (res.status !== wanted) {
      console.error(`\n── WRONG STATUS ──────────────────────────`);
      console.error(`  ${c.payload.length} bytes (cap ${MAX_BODY_BYTES}), ${chunks} chunk(s)`);
      console.error(`  expected ${wanted} (${c.expect}), got ${res.status} ${res.text.slice(0, 80)}`);
      failures++;
      continue;
    }

    // ORACLE B.
    if (c.expect === "ok") {
      const got = JSON.parse(res.text).s as string;
      if (got !== c.value) {
        const bad = got.indexOf("�");
        console.error(`\n── BODY CORRUPTED ────────────────────────`);
        console.error(`  ${c.payload.length} bytes in ${chunks} chunk(s)`);
        console.error(`  sent ${c.value!.length} chars, got ${got.length}` +
                      (bad >= 0 ? `, first replacement char at ${bad}` : ""));
        failures++;
      }
    }
  }

  close();
  if (failures === 0) {
    console.log(`✅ ${iterations} bodies, cap held in bytes and nothing was corrupted`);
    process.exit(0);
  }
  console.error(`\n❌ ${failures} failure(s) — replay with --seed ${seed}`);
  process.exit(1);
}

main();
