/**
 * Differential fuzzing for the v3 binary framing: `decodeV3` (TypeScript)
 * against `ConversationEnvelopeV3.decodeReporting` (Swift), on identical bytes.
 *
 * WHY A SECOND DRIVER. The v2 harness mutates JSON TEXT, because that is where
 * v2's disagreements live — duplicate keys, escapes, number spellings. v3 has no
 * text. Its disagreements live in offsets, length prefixes and integer widths,
 * so the mutations are byte-level and the ORACLE is wider: two implementations
 * can now agree to accept a frame and still disagree about what `n` is, which is
 * a shape JSON could not produce.
 *
 * THREE ORACLES:
 *
 *   A. VERDICTS AGREE. accept <=> accept. A divergence is a frame one peer sends
 *      and the other silently drops.
 *
 *   B. AAD BYTES AGREE when both accept. Worse when it breaks: it surfaces as a
 *      GCM tag mismatch, indistinguishable from a wrong key.
 *
 *   C. DECODED FIELDS AGREE when both accept. New here. v3 reads integers out of
 *      byte offsets rather than out of a parsed object, so "both accepted, same
 *      AAD, different `pn`" is reachable and would be a frame-confusion bug.
 *
 * Run:
 *   cd apps/apple/fuzz && ./run.sh envelope-v3-verdict     # build the Swift half
 *   cd services/server && npx tsx test/fuzz/envelope-v3-differential.ts --iterations 100000
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { decodeV3 } from "../../lib/envelope-v3";
import { makeRng, Rng } from "./rng";

const VECTORS = path.join(__dirname, "..", "helpers", "envelope-v3-vectors.json");
const SWIFT = path.join(__dirname, "../../../../apps/apple/fuzz/build/envelope-v3-verdict");
const FINDINGS = path.join(__dirname, "findings");

// ── the mutator ──────────────────────────────────────────────────────────────
//
// Byte-level, and aimed at the things a length-prefixed binary format can get
// wrong. A frame is mostly incompressible KEM material, so blind bit-flipping
// spends almost all its time in payload bytes nobody parses; the strategies
// below deliberately concentrate on the header, where the offsets are.

/** The fixed header runs to byte 96; everything decisive lives in it. */
const HEADER_FIXED = 96;

function flipBitInHeader(buf: Buffer, rng: Rng): Buffer {
  const out = Buffer.from(buf);
  if (out.length === 0) return out;
  const i = rng.int(Math.min(out.length, HEADER_FIXED));
  out[i] = out[i]! ^ (1 << rng.int(8));
  return out;
}

function flipBitAnywhere(buf: Buffer, rng: Rng): Buffer {
  const out = Buffer.from(buf);
  if (out.length === 0) return out;
  const i = rng.int(out.length);
  out[i] = out[i]! ^ (1 << rng.int(8));
  return out;
}

/** Rewrite a u32 to a boundary value. Length prefixes are u32, and so are the
 *  counters — the interesting failures are at the edges, not in the range. */
function smashU32(buf: Buffer, rng: Rng): Buffer {
  const out = Buffer.from(buf);
  if (out.length < 4) return out;
  const at = rng.int(out.length - 4);
  const value = rng.pick([
    0, 1, 0xffffffff, 0x7fffffff, 0x80000000, 0xfffffff0, out.length, out.length + 1,
  ]);
  out.writeUInt32BE(value >>> 0, at);
  return out;
}

/** Truncate. Every length prefix then claims more than is there. */
function truncate(buf: Buffer, rng: Rng): Buffer {
  if (buf.length === 0) return buf;
  return Buffer.from(buf.subarray(0, rng.int(buf.length)));
}

/** Extend. Trailing bytes must be refused, and the payload prefix must not
 *  simply absorb them. */
function extend(buf: Buffer, rng: Rng): Buffer {
  return Buffer.concat([buf, crypto.randomBytes(1 + rng.int(8))]);
}

/** Rewrite the flags byte, including bits neither side defines. */
function smashFlags(buf: Buffer, rng: Rng): Buffer {
  const out = Buffer.from(buf);
  if (out.length <= 6) return out;
  out[6] = rng.int(256);
  return out;
}

/** Rewrite the kind or version byte — the two that decide how everything after
 *  them is read. */
function smashDiscriminator(buf: Buffer, rng: Rng): Buffer {
  const out = Buffer.from(buf);
  if (out.length <= 5) return out;
  out[rng.bool() ? 4 : 5] = rng.int(256);
  return out;
}

/** Rewrite the msgId length, and sometimes the bytes under it — the one
 *  variable-length field inside the fixed header. */
function smashMsgId(buf: Buffer, rng: Rng): Buffer {
  const out = Buffer.from(buf);
  if (out.length <= HEADER_FIXED) return out;
  out[95] = rng.pick([0, 1, 127, 128, 129, 255, rng.int(256)]);
  if (rng.bool()) {
    // Invalid UTF-8 under a valid length: a lone continuation byte.
    const at = HEADER_FIXED + rng.int(Math.min(8, out.length - HEADER_FIXED));
    out[at] = rng.pick([0x80, 0xc0, 0xf5, 0xff]);
  }
  return out;
}

const MUTATORS = [
  flipBitInHeader,
  flipBitAnywhere,
  smashU32,
  truncate,
  extend,
  smashFlags,
  smashDiscriminator,
  smashMsgId,
];

export function mutate(buf: Buffer, rng: Rng): Buffer {
  let out = buf;
  const edits = 1 + rng.int(3);
  for (let i = 0; i < edits; i++) out = MUTATORS[rng.int(MUTATORS.length)]!(out, rng);
  return out;
}

// ── the two verdicts ─────────────────────────────────────────────────────────

/** Must produce the same three forms as the Swift binary. */
function tsVerdict(frame: Buffer): string {
  let got: ReturnType<typeof decodeV3>;
  try {
    got = decodeV3(frame);
  } catch (e) {
    return `T decodeV3 threw: ${e instanceof Error ? e.message : String(e)}`;
  }
  if (!got) return "R rejected";
  const { env, aad } = got;
  const hex = (b: Buffer | undefined) => (b === undefined ? "" : b.toString("hex"));
  const h = crypto.createHash("sha256");
  // A NUL between fields, so "ab" + "c" and "a" + "bc" cannot digest alike.
  for (const part of [
    env.t,
    env.sender,
    env.to,
    env.msgId,
    env.cid,
    String(env.n),
    String(env.pn),
    env.otId === undefined ? "" : String(env.otId),
    hex(env.rk),
    hex(env.kemCt),
    hex(env.ctId),
    hex(env.ctMt),
    hex(env.ctOt),
    hex(env.senderPk),
    hex(env.payload),
  ]) {
    h.update(part, "utf8");
    h.update(Buffer.from([0]));
  }
  const aadDigest = crypto.createHash("sha256").update(aad).digest("hex");
  return `A ${aad.length}:${aadDigest}:${h.digest("hex")}`;
}

function agree(ts: string, swift: string): boolean {
  if (ts[0] === "T" || swift[0] === "T") return false;
  if (ts[0] !== swift[0]) return false;
  if (ts[0] === "A") return ts === swift; // verdict, AAD and fields all at once
  return true;
}

function swiftVerdicts(frames: Buffer[], batchFile: string): string[] {
  // NO trailing newline, and empty lines are meaningful: a truncation mutation
  // can produce a zero-length frame, whose hex is the empty string. Dropping
  // those silently is what made the two sides disagree about how many verdicts
  // they were even discussing.
  fs.writeFileSync(batchFile, frames.map((f) => f.toString("hex")).join("\n"));
  const out = execFileSync(SWIFT, [batchFile], { maxBuffer: 1 << 28 }).toString("utf8");
  const lines = out.split("\n");
  // The binary ends its output with a newline, so the final element is empty.
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

// ── driver ───────────────────────────────────────────────────────────────────

function loadSeeds(): Buffer[] {
  const v = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
  return Object.values(v.cases as Record<string, { frameHex: string }>)
    .map((c) => Buffer.from(c.frameHex, "hex"));
}

function main() {
  const args = process.argv.slice(2);
  const num = (flag: string, fallback: number) => {
    const i = args.indexOf(flag);
    return i === -1 ? fallback : Number(args[i + 1]);
  };
  const iterations = num("--iterations", 50_000);
  const seed = num("--seed", 1);
  const batchSize = num("--batch", 2000);

  if (!fs.existsSync(SWIFT)) {
    console.error(`✗ missing ${SWIFT}\n  build it: cd apps/apple/fuzz && ./run.sh envelope-v3-verdict`);
    process.exit(2);
  }

  const seeds = loadSeeds();
  const rng = makeRng(seed);
  const batchFile = path.join(os.tmpdir(), `hqchat-v3-fuzz-${process.pid}.hexlines`);
  let mismatches = 0;
  const started = Date.now();

  console.log(`seeds: ${seeds.length}  iterations: ${iterations}  seed: ${seed}  batch: ${batchSize}`);

  for (let done = 0; done < iterations; done += batchSize) {
    const n = Math.min(batchSize, iterations - done);
    const frames: Buffer[] = [];
    for (let i = 0; i < n; i++) frames.push(mutate(rng.pick(seeds), rng));

    const ts = frames.map(tsVerdict);
    const swift = swiftVerdicts(frames, batchFile);
    if (swift.length !== frames.length) {
      console.error(`✗ the Swift half returned ${swift.length} verdicts for ${frames.length} frames`);
      process.exit(1);
    }
    for (let i = 0; i < frames.length; i++) {
      if (agree(ts[i]!, swift[i]!)) continue;
      mismatches++;
      fs.mkdirSync(FINDINGS, { recursive: true });
      const file = path.join(FINDINGS, `v3-mismatch-${seed}-${done + i}.hex`);
      fs.writeFileSync(file, frames[i]!.toString("hex"));
      if (mismatches <= 10) {
        console.log(`\n✗ MISMATCH at iteration ${done + i}`);
        console.log(`  ts:    ${ts[i]}`);
        console.log(`  swift: ${swift[i]}`);
        console.log(`  input: ${file}`);
      }
    }
  }

  try { fs.unlinkSync(batchFile); } catch { /* the tmp file is not load-bearing */ }
  const secs = ((Date.now() - started) / 1000).toFixed(1);
  console.log(`done: ${iterations} frames in ${secs}s — ${mismatches} mismatch(es)`);
  process.exit(mismatches === 0 ? 0 : 1);
}

if (require.main === module) main();
