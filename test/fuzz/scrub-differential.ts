/**
 * Differential fuzzing: `redact` / `isSensitiveKey` (TypeScript, lib/scrub.ts)
 * against `Redaction.redact` / `Redaction.isSensitive` (Swift), on identical
 * inputs.
 *
 * WHY THIS EXISTS. The two files are one rule set maintained twice. lib/scrub.ts
 * says "SYNC INVARIANT: this rule set is mirrored in the iOS scrubber … keep both
 * in step" and Redaction.swift says the same thing back. Neither statement was
 * ever checked.
 *
 * What a divergence costs is asymmetric and worth stating plainly. This is the
 * last code that runs before an event leaves for Sentry. The server is designed
 * never to hold plaintext; the client necessarily does. So a shape the server
 * redacts and the client does not is a leak of message content, handle graph or
 * key material from the one process that has all three — and it would look like
 * a perfectly healthy crash report.
 *
 * TWO MODES, run separately, because the halves drift independently:
 *
 *   redact  the textual redactors. Order-sensitive: the specific high-entropy
 *           shapes must run before the broad hex/base64 rules on both sides, or
 *           a token gets chewed in half and the placeholder misdescribes what it
 *           replaced.
 *
 *   key     isSensitive(key). Word-aware, not substring, so "recipient" does not
 *           trip on "ip". The camelCase split is hand-written twice — JS uses a
 *           regex replace, Swift uses a regex replace with different engine
 *           semantics — and the two only have to disagree about one key for a
 *           value to survive on one platform.
 *
 * KNOWN DIVERGENCE CANDIDATES, aimed at deliberately:
 *
 *   · TRUNCATION UNITS. TS caps on `input.length` (UTF-16 code units); Swift caps
 *     on `input.count` (GRAPHEME CLUSTERS). A string of 8192 family-emoji is
 *     8192 to Swift and ~90,000 to JavaScript. This is the same class of bug the
 *     envelope differential found in `msgId`.
 *   · THE QUOTE BACKREFERENCE. The TS key/value rule is `("?)[^\s,;"'}]+\3` — it
 *     captures an opening quote and requires the matching close. The Swift rule
 *     is `\"?[^\\s,;\"'}]+` with no backreference. On `token="abc"` they consume
 *     different spans.
 *   · ICU vs JS regex. NSRegularExpression is stricter about escapes inside
 *     character classes, and `\b` is defined over different word-character sets
 *     once non-ASCII is involved.
 *
 * Run:
 *   cd apps/apple/fuzz && ./run.sh scrub-verdict      # build the Swift half
 *   cd services/server && npx tsx test/fuzz/scrub-differential.ts --iterations 20000
 *   …                                                --mode key
 *   …                                                --seed 7
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execFileSync } from "node:child_process";
import { redact, isSensitiveKey } from "../../lib/scrub";

const SWIFT = path.join(__dirname, "../../../../apps/apple/fuzz/build/scrub-verdict");
const FINDINGS = path.join(__dirname, "findings");
const BATCH = 2000;

// ── deterministic randomness ─────────────────────────────────────────────────

/** mulberry32 — seedable, so a finding replays. `Math.random()` cannot. */
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

// ── the corpus of interesting fragments ──────────────────────────────────────
//
// Every entry is either a shape a redactor is meant to catch, or a shape that is
// deliberately just short of one. The near-misses matter as much: over-redaction
// destroys the diagnostic value the event was collected for, and the two sides
// must agree about where the line is, not merely that there is one.

const SECRETS = [
  "eyJQTEFDRUhPTERFUn0.eyJQTEFDRUhPTERFUn0.PLACEHOLDERsignature",
  "sk_test_PLACEHOLDER01", "whsec_PLACEHOLDER0001", "pk_test_PLACEHOLDER03",
  "t=1614556800,v1=5257a869e7ecebeda32affa62cdca3fa",
  "postgresql://user:PLACEHOLDER@db.internal:5432/db", "redis://:pw@cache:6379",
  "token=abc123def456", 'token="abc123def456"', "token: abc123def456",
  "Authorization: Bearer abcdef123456", "api_key=zzzz1111yyyy2222",
  "alice@example.com", "a@b.co",
  "192.168.1.254", "255.255.255.255", "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
  "fe80::1", "::1",
  "4f3c2b1a4f3c2b1a4f3c2b1a4f3c2b1a", "a".repeat(64),
  "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm8=",
  "@alice_k", "@bob",
];

/** Just short of a rule, so the two must agree on NOT redacting. */
const NEAR_MISSES = [
  "12:34:56",              // not IPv6
  "order 12345 failed",    // not a key
  "deadbeef",              // 8 hex, under the 32 floor
  "a".repeat(31),          // one under the hex rule
  "256.1.1.1",             // not a valid IPv4
  "@a",                    // one under the handle floor
  "recipient", "description", "tripped", "signal",
  "connection reset by peer",
];

const NOISE = [
  " ", "\n", "\t", "  ", ", ", ": ", "=", '"', "'", "}", ";", "(", "[", "{",
  "failed: ", "error ", "at ", "from ", "→", "…", "🔒", "é", "ß",
  "‍", "́", "﻿",
];

/** Grapheme clusters that are one `.count` to Swift and many `.length` to JS. */
const WIDE = ["👨‍👩‍👧‍👦", "🇫🇷", "é", "🏳️‍🌈", "𝔘"];

// ── generators ───────────────────────────────────────────────────────────────

function randomString(r: Rng): string {
  const parts: string[] = [];
  const n = 1 + int(r, 6);
  for (let i = 0; i < n; i++) {
    const roll = r();
    if (roll < 0.45) parts.push(pick(r, SECRETS));
    else if (roll < 0.7) parts.push(pick(r, NEAR_MISSES));
    else if (roll < 0.95) parts.push(pick(r, NOISE));
    else parts.push(pick(r, WIDE));
  }
  return parts.join(pick(r, ["", " ", "", " "]));
}

/**
 * Strings built to sit either side of the 8192 cap, where TS counts UTF-16 units
 * and Swift counts grapheme clusters. A run of family emoji makes the two
 * measurements differ by more than an order of magnitude.
 */
function truncationCandidate(r: Rng): string {
  const filler = pick(r, [...WIDE, "a", "ab"]);
  const target = pick(r, [8190, 8191, 8192, 8193, 8200, 4100]);
  const body = filler.repeat(Math.ceil(target / filler.length));
  // A secret at the end, so a difference in where the cut falls is a difference
  // in whether that secret survives.
  return body.slice(0, target) + " " + pick(r, SECRETS);
}

/** Key names for the `key` mode: camelCase, snake, kebab, unicode, near-misses. */
function randomKey(r: Rng): string {
  const words = ["public", "Key", "secret", "token", "ip", "Address", "recipient",
    "description", "sig", "signature", "nonce", "payload", "user", "id",
    "session", "Token", "x", "forwarded", "for", "credential", "tripped",
    "SIG", "IP", "Ip", "apiKey", "API_KEY", "a", "1", "é", "🔒"];
  const sep = pick(r, ["", "_", "-", " ", ".", ""]);
  const n = 1 + int(r, 4);
  const out: string[] = [];
  for (let i = 0; i < n; i++) out.push(pick(r, words));
  return out.join(sep);
}

// ── the oracles ──────────────────────────────────────────────────────────────

interface Verdict { kind: "R" | "K" | "X"; body: string }

function swiftVerdicts(mode: string, inputs: string[]): Verdict[] {
  // A private directory, not a predictable name in a shared /tmp: a pid is
  // guessable, so `scrub-batch-1234.jsonl` is a path somebody else on the
  // box can create as a symlink first and have this overwrite for them.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scrub-batch-"));
  const batchFile = path.join(dir, "batch.jsonl");
  fs.writeFileSync(batchFile, inputs.map((s) => JSON.stringify(s)).join("\n") + "\n");
  const stdout = execFileSync(SWIFT, [mode, batchFile], {
    maxBuffer: 256 * 1024 * 1024,
    encoding: "utf8",
  });
  fs.rmSync(dir, { recursive: true, force: true });
  return stdout.split("\n").filter(Boolean).map((line) => {
    if (line === "X") return { kind: "X" as const, body: "" };
    const sp = line.indexOf(" ");
    return { kind: line.slice(0, sp) as "R" | "K", body: line.slice(sp + 1) };
  });
}

function tsVerdict(mode: string, input: string): Verdict {
  if (mode === "key") return { kind: "K", body: isSensitiveKey(input) ? "S" : "-" };
  const out = redact(input);
  const bytes = Buffer.from(out, "utf8");
  const digest = require("node:crypto").createHash("sha256").update(bytes).digest("hex");
  return { kind: "R", body: `${digest} ${bytes.length} ${bytes.subarray(0, 120).toString("base64")}` };
}

// ── driver ───────────────────────────────────────────────────────────────────

function arg(flag: string, dflt: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? (process.argv[i + 1] ?? dflt) : dflt;
}

function main() {
  const iterations = Number(arg("--iterations", "20000"));
  const seed = Number(arg("--seed", String((Math.random() * 1e9) | 0)));
  const mode = arg("--mode", "redact");
  if (mode !== "redact" && mode !== "key") {
    console.error("--mode must be redact or key");
    process.exit(2);
  }

  if (!fs.existsSync(SWIFT)) {
    console.error(`❌ no Swift half at ${SWIFT}`);
    console.error("   build it:  cd apps/apple/fuzz && ./run.sh scrub-verdict");
    process.exit(2);
  }

  console.log(`scrub differential · mode ${mode} · ${iterations} iterations · seed ${seed}`);
  const r = rng(seed);
  let mismatches = 0;
  let undecodable = 0;
  let done = 0;

  while (done < iterations) {
    const n = Math.min(BATCH, iterations - done);
    const inputs: string[] = [];
    for (let i = 0; i < n; i++) {
      if (mode === "key") inputs.push(randomKey(r));
      else inputs.push(r() < 0.08 ? truncationCandidate(r) : randomString(r));
    }

    const swift = swiftVerdicts(mode, inputs);
    if (swift.length !== inputs.length) {
      console.error(`❌ Swift returned ${swift.length} verdicts for ${inputs.length} inputs`);
      process.exit(2);
    }

    for (let i = 0; i < n; i++) {
      const s = swift[i]!;
      // A line Swift's JSONDecoder refused is a JSON transport artifact (lone
      // surrogates, mostly), not a scrubber disagreement. Counted, not failed.
      if (s.kind === "X") { undecodable++; continue; }

      const t = tsVerdict(mode, inputs[i]!);
      if (s.body === t.body) continue;

      mismatches++;
      fs.mkdirSync(FINDINGS, { recursive: true });
      const file = path.join(FINDINGS, `scrub-${mode}-${seed}-${done + i}.json`);
      fs.writeFileSync(file, JSON.stringify({ mode, seed, input: inputs[i], swift: s.body, ts: t.body }, null, 2));

      console.error("");
      console.error(`── MISMATCH (${mode}) ──────────────────────────────`);
      console.error(`  input   ${JSON.stringify(inputs[i]).slice(0, 200)}`);
      if (mode === "redact") {
        const [, , sPrev] = s.body.split(" ");
        const [, , tPrev] = t.body.split(" ");
        console.error(`  swift   ${JSON.stringify(Buffer.from(sPrev ?? "", "base64").toString("utf8"))}`);
        console.error(`  ts      ${JSON.stringify(Buffer.from(tPrev ?? "", "base64").toString("utf8"))}`);
      } else {
        console.error(`  swift   ${s.body}   ts ${t.body}`);
      }
      console.error(`  saved   ${path.relative(process.cwd(), file)}`);
      if (mismatches >= 10) {
        console.error("\nstopping after 10 mismatches — fix these first");
        process.exit(1);
      }
    }
    done += n;
  }

  const skipped = undecodable ? ` · ${undecodable} undecodable (JSON transport, not a finding)` : "";
  if (mismatches === 0) {
    console.log(`✅ ${iterations} inputs, no divergence${skipped}`);
    process.exit(0);
  }
  console.error(`❌ ${mismatches} divergence(s)${skipped}`);
  process.exit(1);
}

main();
