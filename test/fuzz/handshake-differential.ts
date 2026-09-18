/**
 * Differential fuzzing: `encodeHandshake` / `decodeHandshake` (TypeScript)
 * against `Handshake.encode` / `Handshake.decode` (Swift), on identical inputs.
 *
 * WHY THIS FRAME. `h/{friendshipHash}` carries the exchange that closes the gap
 * an `init` leaves open. An init is built entirely from public values and arrives
 * on an inbox that every friend may publish to, so it establishes nothing about
 * who sent it — Handshake.swift's own comment calls this "the door the
 * impersonation walked through". The challenge and proof on the handshake topic
 * are what shut it.
 *
 * Both ends parse that frame with hand-written offset arithmetic, written twice,
 * and until now the only thing comparing them was five pinned vectors that both
 * sides agree on by construction. A divergence is a first contact that stalls
 * from one side and completes from the other, or two peers with different
 * opinions about which nonce was proved.
 *
 * THREE MODES, because the halves fail differently:
 *
 *   decode  Bytes in. Both must refuse the same bytes and agree on every field
 *           of what they accept — kind, from, to, nonce, and the body.
 *
 *   encode  Frames in. Everything else here tests decoders, and the envelope
 *           work found the ENCODERS disagreeing on every malformed input while
 *           the decoders agreed: TypeScript writes into a sized buffer (a short
 *           field pads, a long one clips) where Swift appends (a wrong length
 *           shifts every field after it), and writeUInt32BE throws where
 *           truncatingIfNeeded wraps.
 *
 *   round   decode(encode(f)) == f, on each side independently. An encoder and a
 *           decoder can each be self-consistent and still not be inverses, and
 *           the pinned vectors cannot see it because they only travel one way.
 *
 * Run:
 *   cd apps/apple/fuzz && ./run.sh handshake-verdict
 *   cd services/server && npx tsx test/fuzz/handshake-differential.ts --iterations 20000
 *   …                                                                 --mode encode
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  encodeHandshake, decodeHandshake, HandshakeFrame,
  HANDSHAKE_NONCE_BYTES, HANDSHAKE_PROOF_BYTES, HANDSHAKE_VERSION,
} from "../../lib/handshake";

const SWIFT = path.join(__dirname, "../../../../apps/apple/fuzz/build/handshake-verdict");
const VECTORS = path.join(__dirname, "..", "helpers", "handshake-vectors.json");
const FINDINGS = path.join(__dirname, "findings");
const BATCH = 1000;

// Layout, restated here so a mutation can aim at a field rather than at a byte.
const OFF = { magic: 0, version: 4, kind: 5, from: 6, to: 38, nonce: 70, body: 102 };
const ID_BYTES = 32;
const MAX_CT = 1 << 20;

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
const bytes = (r: Rng, n: number) => Buffer.from(Array.from({ length: n }, () => int(r, 256)));
const hexId = (r: Rng) => bytes(r, ID_BYTES).toString("hex");

// ── seeds ────────────────────────────────────────────────────────────────────

/** Valid frames of both kinds, from the shared vectors where they exist. */
function seedFrames(r: Rng): Buffer[] {
  const out: Buffer[] = [];
  const chal = encodeHandshake({
    kind: "chal", from: hexId(r), to: hexId(r),
    nonce: bytes(r, HANDSHAKE_NONCE_BYTES), ct: bytes(r, 200),
  });
  const proof = encodeHandshake({
    kind: "proof", from: hexId(r), to: hexId(r),
    nonce: bytes(r, HANDSHAKE_NONCE_BYTES), proof: bytes(r, HANDSHAKE_PROOF_BYTES),
  });
  if (chal) out.push(chal);
  if (proof) out.push(proof);

  // The committed vectors carry frames both suites already assert on.
  try {
    const v = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
    for (const f of v.frames ?? []) {
      if (typeof f?.hex === "string") out.push(Buffer.from(f.hex, "hex"));
      else if (typeof f === "string") out.push(Buffer.from(f, "hex"));
    }
  } catch { /* vectors are a bonus, not a requirement */ }
  return out;
}

// ── mutation, aimed at the header ────────────────────────────────────────────
//
// Everything that decides acceptance lives in the first 106 bytes: magic,
// version, kind, and the length prefix. Spreading mutations evenly over a frame
// whose body can reach a megabyte would spend the whole run inside the payload,
// where nothing is parsed.

function mutate(seed: Buffer, r: Rng): Buffer {
  const b = Buffer.from(seed);
  const edits = 1 + int(r, 3);
  for (let i = 0; i < edits; i++) {
    switch (int(r, 8)) {
      case 0: // corrupt the magic
        b[int(r, 4)] = int(r, 256);
        break;
      case 1: // a version that is not 1
        b[OFF.version] = int(r, 256);
        break;
      case 2: // a kind outside {0, 1}
        b[OFF.kind] = int(r, 256);
        break;
      case 3: { // rewrite the ct length prefix at a boundary
        if (b.length < OFF.body + 4) break;
        const v = pick(r, [0, 1, MAX_CT - 1, MAX_CT, MAX_CT + 1, 0x7fffffff, 0xffffffff,
                           b.length - OFF.body - 4, b.length - OFF.body - 3]);
        b.writeUInt32BE(v >>> 0, OFF.body);
        break;
      }
      case 4: { // flip a bit anywhere in the header
        if (b.length > OFF.body) {
          const at = int(r, OFF.body);
          b[at] = (b[at] ?? 0) ^ (1 << int(r, 8));
        }
        break;
      }
      case 5: // truncate — including exactly at each field boundary
        return b.subarray(0, pick(r, [0, 1, 4, 5, 6, OFF.nonce, OFF.body - 1, OFF.body,
                                      OFF.body + 3, OFF.body + 4, int(r, b.length + 1)]));
      case 6: // extend, so an exact-length check has something to refuse
        return Buffer.concat([b, bytes(r, 1 + int(r, 8))]);
      default:
        b[int(r, b.length || 1)] = int(r, 256);
    }
  }
  return b;
}

/**
 * A well-formed challenge whose ct is exactly `len` bytes, so the frame is
 * SELF-CONSISTENT at the length bound.
 *
 * Without this the HS_MAX_CT_BYTES check was unreachable and the fuzzer could not
 * have seen an off-by-one in it: rewriting the length prefix on a 300-byte frame
 * makes `raw.length !== OFF.body + 4 + len` fail on both sides long before the
 * bound is consulted, so the two agree for the wrong reason. Verified by
 * injecting `len > HS_MAX_CT_BYTES + 1` into the TypeScript decoder and checking
 * that this driver now reports it.
 *
 * A megabyte a frame, so these are rare by design — enough to cover the boundary,
 * not enough to turn the run into an allocation benchmark.
 */
function boundaryChallenge(r: Rng, len: number): Buffer {
  const head = Buffer.alloc(OFF.body + 4);
  Buffer.from("HQCH", "ascii").copy(head, 0);
  head.writeUInt8(HANDSHAKE_VERSION, OFF.version);
  head.writeUInt8(0, OFF.kind);                       // challenge
  bytes(r, ID_BYTES).copy(head, OFF.from);
  bytes(r, ID_BYTES).copy(head, OFF.to);
  bytes(r, HANDSHAKE_NONCE_BYTES).copy(head, OFF.nonce);
  head.writeUInt32BE(len >>> 0, OFF.body);
  // The body is not parsed, so it need not be random — and allocating a
  // megabyte of random bytes per frame would dominate the run.
  return Buffer.concat([head, Buffer.alloc(len, 0x5a)]);
}

/** Frames for encode/round mode, including ones the encoder must refuse. */
function randomFrame(r: Rng): HandshakeFrame {
  const kind = r() < 0.5 ? "chal" : "proof";
  const wrong = r() < 0.35;
  const idLen = wrong ? pick(r, [0, 2, 31, 32, 33, 64]) : ID_BYTES;
  const nonceLen = wrong ? pick(r, [0, 1, 31, 32, 33]) : HANDSHAKE_NONCE_BYTES;
  const base = {
    from: wrong && r() < 0.3 ? pick(r, ["", "zz", "NOTHEX".repeat(6)]) : bytes(r, idLen).toString("hex"),
    to: bytes(r, idLen).toString("hex"),
    nonce: bytes(r, nonceLen),
  };
  if (kind === "chal") {
    const ctLen = wrong ? pick(r, [0, 1, MAX_CT, MAX_CT + 1]) : 1 + int(r, 400);
    // A megabyte-plus body is the point of the cap, but allocating many of them
    // makes the run about memory rather than about parsing.
    return { kind, ...base, ct: bytes(r, Math.min(ctLen, 2048)) };
  }
  const pLen = wrong ? pick(r, [0, 31, 32, 33]) : HANDSHAKE_PROOF_BYTES;
  return { kind, ...base, proof: bytes(r, pLen) };
}

// ── oracles ──────────────────────────────────────────────────────────────────

function tsDecode(b: Buffer): string {
  const f = decodeHandshake(b);
  if (!f) return "R";
  const body = f.ct ?? f.proof ?? Buffer.alloc(0);
  const sha = crypto.createHash("sha256").update(body).digest("hex");
  return `A ${f.kind} ${f.from} ${f.to} ${f.nonce.toString("hex")} ${sha} ${body.length}`;
}

function tsEncode(f: HandshakeFrame): string {
  let b: Buffer | null = null;
  try { b = encodeHandshake(f); } catch { return "R"; }
  if (!b) return "R";
  return `A ${crypto.createHash("sha256").update(b).digest("hex")} ${b.length}`;
}

function tsRound(f: HandshakeFrame): string {
  let b: Buffer | null = null;
  try { b = encodeHandshake(f); } catch { return "R"; }
  if (!b) return "R";
  const back = decodeHandshake(b);
  if (!back) return "F encode produced bytes its own decoder refuses";
  const why: string[] = [];
  if (back.kind !== f.kind) why.push("kind");
  if (back.from.toLowerCase() !== f.from.toLowerCase()) why.push("from");
  if (back.to.toLowerCase() !== f.to.toLowerCase()) why.push("to");
  if (!back.nonce.equals(f.nonce)) why.push("nonce");
  if (f.kind === "chal" && !(back.ct ?? Buffer.alloc(0)).equals(f.ct ?? Buffer.alloc(0))) why.push("ct");
  if (f.kind === "proof" && !(back.proof ?? Buffer.alloc(0)).equals(f.proof ?? Buffer.alloc(0))) why.push("proof");
  return why.length ? `F ${why.join(",")}` : "T";
}

function swiftVerdicts(mode: string, lines: string[]): string[] {
  // A private directory, not a predictable name in a shared /tmp: a pid is
  // guessable, so `handshake-batch-1234.jsonl` is a path somebody else on the
  // box can create as a symlink first and have this overwrite for them.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "handshake-batch-"));
  const file = path.join(dir, "batch.jsonl");
  fs.writeFileSync(file, lines.join("\n") + "\n");
  const stdout = execFileSync(SWIFT, [mode, file], { maxBuffer: 512 * 1024 * 1024, encoding: "utf8" });
  fs.rmSync(dir, { recursive: true, force: true });
  return stdout.split("\n").filter((l) => l.length > 0);
}

// ── driver ───────────────────────────────────────────────────────────────────

function arg(flag: string, dflt: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? (process.argv[i + 1] ?? dflt) : dflt;
}

function main() {
  const iterations = Number(arg("--iterations", "20000"));
  const seed = Number(arg("--seed", String((Math.random() * 1e9) | 0)));
  const mode = arg("--mode", "decode");
  if (!["decode", "encode", "round"].includes(mode)) {
    console.error("--mode must be decode, encode or round");
    process.exit(2);
  }
  if (!fs.existsSync(SWIFT)) {
    console.error(`❌ no Swift half at ${SWIFT}`);
    console.error("   build it:  cd apps/apple/fuzz && ./run.sh handshake-verdict");
    process.exit(2);
  }

  console.log(`handshake differential · mode ${mode} · ${iterations} iterations · seed ${seed} · v${HANDSHAKE_VERSION}`);
  const r = rng(seed);
  const seeds = seedFrames(r);
  let mismatches = 0;
  let done = 0;

  while (done < iterations) {
    const n = Math.min(BATCH, iterations - done);
    const lines: string[] = [];
    const inputs: any[] = [];

    for (let i = 0; i < n; i++) {
      if (mode === "decode") {
        // Rarely, a frame that is self-consistent AT the ct-length bound —
        // the only way that check is reachable at all.
        const b = r() < 0.004
          ? boundaryChallenge(r, pick(r, [MAX_CT - 1, MAX_CT, MAX_CT + 1]))
          : mutate(pick(r, seeds), r);
        inputs.push(b);
        lines.push(JSON.stringify(b.toString("base64")));
      } else {
        const f = randomFrame(r);
        inputs.push(f);
        lines.push(JSON.stringify({
          kind: f.kind, from: f.from, to: f.to,
          nonce: f.nonce.toString("base64"),
          ct: f.ct?.toString("base64"),
          proof: f.proof?.toString("base64"),
        }));
      }
    }

    const swift = swiftVerdicts(mode, lines);
    if (swift.length !== n) {
      console.error(`❌ Swift returned ${swift.length} verdicts for ${n} inputs`);
      process.exit(2);
    }

    for (let i = 0; i < n; i++) {
      const input = inputs[i];
      const ts = mode === "decode" ? tsDecode(input)
               : mode === "encode" ? tsEncode(input)
               : tsRound(input);
      const sw = swift[i]!;

      // In `round` mode each side checks ITSELF, so both must say T. A pair of
      // R's is agreement that the frame was unencodable, which is fine.
      const agree = mode === "round"
        ? (ts.startsWith("T") && sw.startsWith("T")) || (ts === "R" && sw === "R")
        : ts === sw;
      if (agree) continue;

      mismatches++;
      fs.mkdirSync(FINDINGS, { recursive: true });
      const file = path.join(FINDINGS, `handshake-${mode}-${seed}-${done + i}.json`);
      const payload = mode === "decode"
        ? { mode, seed, inputBase64: (input as Buffer).toString("base64"), swift: sw, ts }
        : { mode, seed, frame: lines[i], swift: sw, ts };
      fs.writeFileSync(file, JSON.stringify(payload, null, 2));

      console.error("");
      console.error(`── MISMATCH (${mode}) ─────────────────────────────`);
      if (mode === "decode") {
        const b = input as Buffer;
        console.error(`  ${b.length} bytes: ${b.subarray(0, 8).toString("hex")}…`);
      } else {
        console.error(`  ${lines[i]!.slice(0, 160)}`);
      }
      console.error(`  swift  ${sw.slice(0, 160)}`);
      console.error(`  ts     ${ts.slice(0, 160)}`);
      console.error(`  saved  ${path.relative(process.cwd(), file)}`);
      if (mismatches >= 10) {
        console.error("\nstopping after 10 mismatches — fix these first");
        process.exit(1);
      }
    }
    done += n;
  }

  if (mismatches === 0) {
    console.log(`✅ ${iterations} inputs, no divergence`);
    process.exit(0);
  }
  console.error(`❌ ${mismatches} divergence(s)`);
  process.exit(1);
}

main();
