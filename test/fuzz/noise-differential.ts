/**
 * Differential fuzzing of hqn/1 — the raw-TCP transport's Noise handshake and
 * framing — lib/noise.ts (TypeScript, the gateway) against NoiseHQN.swift (the
 * app), plus the gateway's own responder on hostile input.
 *
 * WHY. The pinned vectors (test/helpers/noise-hqn-vectors.json) show the two
 * implementations agree on VALID transcripts. What an attacker controls is the
 * invalid ones, and on this surface they arrive before any authentication:
 *
 *   frames     A byte stream cut at arbitrary points, with arbitrary lengths.
 *              Both frame readers must return the same frames and leave the
 *              same bytes pending. A disagreement here is a stream the two ends
 *              slice differently, which is every frame after it lost.
 *
 *   msg2       The server's reply, mutated, read by an initiator in a pinned
 *              state. Both must refuse the same bytes and agree on payload and
 *              handshake hash for anything they accept. (Only the unmodified
 *              msg2 should ever be accepted; that is asserted too.)
 *
 *   responder  TypeScript only — the app has no responder. The gateway reads
 *              msg1 from anyone on the internet: a mutated msg1 must be refused
 *              with a NoiseError, never an unexpected exception (a crash is a
 *              gateway restart, i.e. a denial of service for everyone on it),
 *              and nothing but the genuine msg1 may be accepted.
 *
 * Run:
 *   cd apps/apple/fuzz && ./run.sh noise-verdict
 *   cd services/server && npx tsx test/fuzz/noise-differential.ts --mode frames --iterations 20000
 *   …                                                            --mode msg2
 *   …                                                            --mode responder
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  HqnInitiator,
  HqnResponder,
  FrameReader,
  NoiseError,
  x25519KeyPair,
  type Kem,
  type ServerStatic,
} from "../../lib/noise";

const SWIFT = path.join(__dirname, "../../../../apps/apple/fuzz/build/noise-verdict");
const VECTORS = path.join(__dirname, "..", "helpers", "noise-hqn-vectors.json");
const FINDINGS = path.join(__dirname, "findings");
const BATCH = 500;

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
const int = (r: Rng, n: number) => Math.floor(r() * n);
const bytes = (r: Rng, n: number) => Buffer.from(Array.from({ length: n }, () => int(r, 256)));

// ── the pinned state both sides start from ────────────────────────────────────

const V = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
const C = V.cases[0];
const hex = (k: string) => Buffer.from(C[k], "hex");
const pinnedKem: Kem = {
  encapsulate: () => ({ ct: hex("kemCiphertextHex"), ss: hex("kemSharedSecretHex") }),
  decapsulate: () => hex("kemSharedSecretHex"),
};
const server: ServerStatic = {
  keyId: C.keyId,
  x25519: x25519KeyPair(hex("serverStaticPrivHex")),
  hqc: { pk: hex("serverHqcPublicHex"), sk: Buffer.alloc(7333) },
};
const serverPub = { keyId: server.keyId, x25519: server.x25519.pub, hqc: server.hqc.pk };

function initiatorAfterMsg1(): HqnInitiator {
  const i = new HqnInitiator(serverPub, { kem: pinnedKem, ephemeral: x25519KeyPair(hex("clientEphemeralPrivHex")) });
  i.writeMessage1(hex("payload1Hex"));
  return i;
}
const GENUINE_MSG1 = new HqnInitiator(serverPub, {
  kem: pinnedKem, ephemeral: x25519KeyPair(hex("clientEphemeralPrivHex")),
}).writeMessage1(hex("payload1Hex"));
const GENUINE_MSG2 = hex("msg2Hex");

// ── mutation ───────────────────────────────────────────────────────────────────

function mutate(seed: Buffer, r: Rng): Buffer {
  let b = Buffer.from(seed);
  const rounds = 1 + int(r, 3);
  for (let k = 0; k < rounds; k++) {
    switch (int(r, 7)) {
      case 0: if (b.length) { const i = int(r, b.length); b[i] = b[i]! ^ (1 << int(r, 8)); } break;
      case 1: if (b.length) b[int(r, b.length)] = int(r, 256); break;
      case 2: b = b.subarray(0, int(r, b.length + 1)); break;                       // truncate
      case 3: b = Buffer.concat([b, bytes(r, 1 + int(r, 64))]); break;             // extend
      case 4: if (b.length >= 32) b.fill(pickFill(r), 0, 32); break;               // ephemeral: 0, 1, 0xff…
      case 5: { const i = int(r, b.length + 1); b = Buffer.concat([b.subarray(0, i), b.subarray(i + 1 + int(r, 16))]); } break;
      case 6: /* keep as is — agreement on the genuine input matters too */ break;
    }
  }
  return b;
}
function pickFill(r: Rng): number { return [0, 1, 0xff, int(r, 256)][int(r, 4)]!; }

/** A stream of frames with honest and dishonest length prefixes, cut anywhere. */
function frameStream(r: Rng): Buffer[] {
  const parts: Buffer[] = [];
  const frames = int(r, 6);
  for (let f = 0; f < frames; f++) {
    const len = r() < 0.1 ? [0, 1, 65535][int(r, 3)]! : int(r, 300);
    const lie = r() < 0.15;
    const body = bytes(r, lie ? int(r, len + 1) : len);
    const prefix = Buffer.alloc(2);
    prefix.writeUInt16BE(len, 0);
    parts.push(prefix, body);
  }
  if (r() < 0.3) parts.push(bytes(r, int(r, 3)));   // a dangling partial prefix
  const stream = Buffer.concat(parts);
  const chunks: Buffer[] = [];
  for (let i = 0; i < stream.length;) {
    const n = 1 + int(r, 40);
    chunks.push(stream.subarray(i, i + n));
    i += n;
  }
  return chunks;
}

// ── the TypeScript verdicts ────────────────────────────────────────────────────

function tsFrames(chunks: Buffer[]): string {
  const reader = new FrameReader();
  const joined: Buffer[] = [];
  let n = 0;
  for (const c of chunks) {
    reader.push(c);
    for (let f = reader.next(); f; f = reader.next()) {
      n++;
      const len = Buffer.alloc(2);
      len.writeUInt16BE(f.length, 0);
      joined.push(len, f);
    }
  }
  const h = crypto.createHash("sha256").update(Buffer.concat(joined)).digest("hex");
  return `F ${n} ${h} ${reader.pending}`;
}

function tsMsg2(msg2: Buffer): string {
  try {
    const { payload, transport } = initiatorAfterMsg1().readMessage2(msg2);
    return `A ${payload.toString("hex")} ${transport.handshakeHash.toString("hex")}`;
  } catch (e) {
    if (!(e instanceof NoiseError)) throw e;
    return "R";
  }
}

// ── the Swift verdicts ─────────────────────────────────────────────────────────

function swiftVerdicts(mode: string, lines: string[]): string[] {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noise-batch-"));
  const file = path.join(dir, "batch.jsonl");
  fs.writeFileSync(file, lines.join("\n") + "\n");
  const stdout = execFileSync(SWIFT, [mode, file, VECTORS], { maxBuffer: 512 * 1024 * 1024, encoding: "utf8" });
  fs.rmSync(dir, { recursive: true, force: true });
  return stdout.split("\n").filter((l) => l.length > 0);
}

// ── driver ───────────────────────────────────────────────────────────────────

function arg(flag: string, dflt: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? (process.argv[i + 1] ?? dflt) : dflt;
}

function record(mode: string, seed: number, index: number, input: unknown, swift: string, ts: string): string {
  fs.mkdirSync(FINDINGS, { recursive: true });
  const file = path.join(FINDINGS, `noise-${mode}-${seed}-${index}.json`);
  fs.writeFileSync(file, JSON.stringify({ mode, seed, input, swift, ts }, null, 2));
  return file;
}

function responderRun(iterations: number, seed: number): number {
  // Every responder refusal must be a NoiseError; anything else is a crash the
  // gateway would take on attacker input. And only the genuine msg1 opens.
  const r = rng(seed);
  let problems = 0;
  // A KEM that returns a DIFFERENT secret for a different ciphertext, so a
  // mutation inside the encrypted ct region is a real failure, not a free pass.
  const kem: Kem = {
    encapsulate: pinnedKem.encapsulate,
    decapsulate: (_sk, ct) => ct.equals(hex("kemCiphertextHex"))
      ? hex("kemSharedSecretHex")
      : crypto.createHash("sha256").update(ct).digest(),
  };
  for (let i = 0; i < iterations; i++) {
    const input = mutate(GENUINE_MSG1, r);
    let verdict: string;
    try {
      new HqnResponder(server, { kem }).readMessage1(input);
      verdict = input.equals(GENUINE_MSG1) ? "ok" : "ACCEPTED A MUTATION";
    } catch (e) {
      verdict = e instanceof NoiseError ? "ok" : `THREW ${(e as Error).constructor.name}: ${(e as Error).message}`;
    }
    if (verdict === "ok") continue;
    problems++;
    const file = record("responder", seed, i, { inputSha256: crypto.createHash("sha256").update(input).digest("hex"),
      length: input.length, head: input.subarray(0, 48).toString("hex") }, "-", verdict);
    console.error(`── RESPONDER PROBLEM: ${verdict}  (${input.length} bytes, saved ${path.relative(process.cwd(), file)})`);
    if (problems >= 10) break;
  }
  return problems;
}

function main() {
  const iterations = Number(arg("--iterations", "20000"));
  const seed = Number(arg("--seed", String((Math.random() * 1e9) | 0)));
  const mode = arg("--mode", "frames");
  if (!["frames", "msg2", "responder"].includes(mode)) {
    console.error("--mode must be frames, msg2 or responder");
    process.exit(2);
  }
  console.log(`hqn/1 differential · mode ${mode} · ${iterations} iterations · seed ${seed}`);

  // Sanity: the genuine msg1 IS what the vectors pin, or every verdict below is
  // about some other transcript.
  if (crypto.createHash("sha256").update(GENUINE_MSG1).digest("hex") !== C.msg1Sha256
      || GENUINE_MSG1.length !== C.msg1Length) {
    console.error("❌ the pinned msg1 does not reproduce — regenerate the vectors");
    process.exit(2);
  }

  if (mode === "responder") {
    const problems = responderRun(iterations, seed);
    if (problems === 0) { console.log(`✅ ${iterations} hostile msg1s, every one refused cleanly`); process.exit(0); }
    console.error(`❌ ${problems} responder problem(s)`);
    process.exit(1);
  }

  if (!fs.existsSync(SWIFT)) {
    console.error(`❌ no Swift half at ${SWIFT}`);
    console.error("   build it:  cd apps/apple/fuzz && ./run.sh noise-verdict");
    process.exit(2);
  }

  const r = rng(seed);
  let mismatches = 0;
  let done = 0;
  while (done < iterations) {
    const n = Math.min(BATCH, iterations - done);
    const inputs: (Buffer | Buffer[])[] = [];
    const lines: string[] = [];
    for (let i = 0; i < n; i++) {
      if (mode === "frames") {
        const chunks = frameStream(r);
        inputs.push(chunks);
        lines.push(JSON.stringify(chunks.map((c) => c.toString("base64"))));
      } else {
        const m = mutate(GENUINE_MSG2, r);
        inputs.push(m);
        lines.push(JSON.stringify(m.toString("base64")));
      }
    }
    const swift = swiftVerdicts(mode, lines);
    if (swift.length !== n) {
      console.error(`❌ Swift returned ${swift.length} verdicts for ${n} inputs`);
      process.exit(2);
    }
    for (let i = 0; i < n; i++) {
      const input = inputs[i]!;
      const ts = mode === "frames" ? tsFrames(input as Buffer[]) : tsMsg2(input as Buffer);
      const sw = swift[i]!;
      // Beyond agreement: in msg2 mode only the genuine reply may be accepted.
      const onlyGenuine = mode !== "msg2" || ts === "R" || (input as Buffer).equals(GENUINE_MSG2);
      if (ts === sw && onlyGenuine) continue;
      mismatches++;
      const file = record(mode, seed, done + i, lines[i], sw, ts);
      console.error("");
      console.error(`── ${onlyGenuine ? "MISMATCH" : "A MUTATED msg2 WAS ACCEPTED"} (${mode}) ──`);
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
