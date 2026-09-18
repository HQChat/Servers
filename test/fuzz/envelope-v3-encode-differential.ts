/**
 * Differential fuzzing of the v3 ENCODERS: `encodeV3` (TypeScript) against
 * `ConversationEnvelopeV3.encoded()` (Swift), from identical structs.
 *
 * WHY A THIRD HARNESS. The decode driver proved the two PARSERS agree on the
 * same bytes. It said nothing about the encoders, and the encoders did not
 * agree — given an identical struct they produced different frames on every
 * malformed input, because they fail in structurally different ways:
 *
 *   TypeScript  builds a fixed `Buffer.alloc` and `.copy()`s into it, so a short
 *               field silently leaves zeros and a long one is clipped.
 *   Swift       APPENDS variable-length `Data`, so a wrong-length field shifts
 *               every field after it and the frame comes out a different size.
 *   integers    `writeUInt32BE` throws where `UInt32(truncatingIfNeeded:)`
 *               silently wraps.
 *
 * That was the exact class v3 exists to remove, sitting in the half nobody had
 * pointed a fuzzer at. Both encoders now validate and refuse, and this is what
 * holds them to it.
 *
 * TWO ORACLES:
 *   A. The same structs are REFUSED. One accept set, or the seam's promise —
 *      that the version is only a spelling — is false.
 *   B. The accepted ones produce IDENTICAL BYTES.
 *
 * No mutation corpus: a generator is enough, because the interesting inputs are
 * structural (a wrong-width id, a counter past u32, a present-but-empty blob)
 * rather than byte-level.
 *
 * Run:
 *   cd apps/apple/fuzz && ./run.sh envelope-v3-encode-verdict
 *   cd services/server && npx tsx test/fuzz/envelope-v3-encode-differential.ts --iterations 20000
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { encodeV3, EnvelopeV3 } from "../../lib/envelope-v3";
import { peerId } from "../../lib/identity";
import { makeRng, Rng } from "./rng";

const SWIFT = path.join(__dirname, "../../../../apps/apple/fuzz/build/envelope-v3-encode-verdict");
const FINDINGS = path.join(__dirname, "findings");

/** How a struct crosses the process boundary: JSON, binary fields as hex. */
type Wire = Record<string, unknown>;

const PK = crypto.randomBytes(7237);
const SENDER = peerId(PK.toString("hex"));
const RECIPIENT = peerId(crypto.randomBytes(7237).toString("hex"));

function goodMsg(): Wire {
  return {
    t: "msg",
    sender: SENDER,
    to: RECIPIENT,
    msgId: "01HQZX9K2M4N6P8R",
    cid: "0123456789abcdef0123456789abcdef",
    n: 7,
    pn: 3,
    payload: Buffer.from("ciphertext").toString("hex"),
  };
}

function goodInit(): Wire {
  return {
    ...goodMsg(),
    t: "init",
    rk: crypto.randomBytes(64).toString("hex"),
    senderPk: PK.toString("hex"),
    ctId: crypto.randomBytes(96).toString("hex"),
    ctMt: crypto.randomBytes(96).toString("hex"),
  };
}

function goodStep(): Wire {
  return {
    ...goodMsg(),
    rk: crypto.randomBytes(64).toString("hex"),
    kemCt: crypto.randomBytes(96).toString("hex"),
  };
}

/** The values a caller can actually get wrong, and a few nobody should. */
const HEX_MUTATIONS = [
  "", "ab", "ab".repeat(16), "ab".repeat(64), "z".repeat(64),
  "AB".repeat(32), " ".repeat(64), "0".repeat(63), "0".repeat(65),
];
const COUNTERS = [-1, 0, 1, 1.5, 2 ** 31, 2 ** 32 - 1, 2 ** 32, 2 ** 53 - 1, -0];
const MSG_IDS = ["", "a", "a".repeat(128), "a".repeat(129), "é".repeat(64), "é".repeat(65), "🔒"];

function mutate(base: Wire, rng: Rng): Wire {
  const out = { ...base };
  const edits = 1 + rng.int(2);
  for (let i = 0; i < edits; i++) {
    switch (rng.int(8)) {
      case 0: out.sender = rng.pick(HEX_MUTATIONS); break;
      case 1: out.to = rng.pick(HEX_MUTATIONS); break;
      case 2: out.cid = rng.pick(HEX_MUTATIONS); break;
      case 3: out.n = rng.pick(COUNTERS); break;
      case 4: out.pn = rng.pick(COUNTERS); break;
      case 5: out.msgId = rng.pick(MSG_IDS); break;
      case 6: {
        // Present-but-empty, and absent, on every optional blob.
        const field = rng.pick(["rk", "kemCt", "ctId", "ctMt", "ctOt", "senderPk"]);
        if (rng.bool()) out[field] = "";
        else delete out[field];
        break;
      }
      default: {
        if (rng.bool()) out.otId = rng.pick(COUNTERS);
        else if (rng.bool()) out.payload = "";
        else out.ctOt = crypto.randomBytes(32).toString("hex");
      }
    }
  }
  return out;
}

/** The struct as `encodeV3` wants it. Anything unreadable stays unreadable — a
 *  refusal on both sides is the correct answer, not a repaired input. */
function toEnvelope(w: Wire): EnvelopeV3 {
  const bin = (k: string) => {
    const v = w[k];
    return typeof v === "string" ? Buffer.from(v, "hex") : undefined;
  };
  const env: Record<string, unknown> = {
    v: 3,
    t: w.t === "init" ? "init" : "msg",
    sender: typeof w.sender === "string" ? w.sender : "",
    to: typeof w.to === "string" ? w.to : "",
    msgId: typeof w.msgId === "string" ? w.msgId : "",
    cid: typeof w.cid === "string" ? w.cid : "",
    n: typeof w.n === "number" ? w.n : -1,
    pn: typeof w.pn === "number" ? w.pn : -1,
    payload: bin("payload") ?? Buffer.alloc(0),
  };
  for (const k of ["rk", "kemCt", "ctId", "ctMt", "ctOt", "senderPk"]) {
    const b = bin(k);
    if (b !== undefined) env[k] = b;
  }
  if (typeof w.otId === "number") env.otId = w.otId;
  return env as unknown as EnvelopeV3;
}

function tsVerdict(w: Wire): string {
  let frame: Buffer | null;
  try {
    frame = encodeV3(toEnvelope(w));
  } catch (e) {
    // A throw is itself a divergence: the contract is refuse-or-encode.
    return `T encodeV3 threw: ${e instanceof Error ? e.message : String(e)}`;
  }
  return frame === null ? "R" : `A ${frame.toString("hex")}`;
}

function swiftVerdicts(batch: Wire[], batchFile: string): string[] {
  fs.writeFileSync(batchFile, batch.map((w) => JSON.stringify(w)).join("\n"));
  const out = execFileSync(SWIFT, [batchFile], { maxBuffer: 1 << 28 }).toString("utf8");
  const lines = out.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

function main() {
  const args = process.argv.slice(2);
  const num = (flag: string, fallback: number) => {
    const i = args.indexOf(flag);
    return i === -1 ? fallback : Number(args[i + 1]);
  };
  const iterations = num("--iterations", 20_000);
  const seed = num("--seed", 1);
  const batchSize = num("--batch", 2000);

  if (!fs.existsSync(SWIFT)) {
    console.error(`✗ missing ${SWIFT}\n  build it: cd apps/apple/fuzz && ./run.sh envelope-v3-encode-verdict`);
    process.exit(2);
  }

  const rng = makeRng(seed);
  const bases = [goodMsg, goodStep, goodInit];
  const batchFile = path.join(os.tmpdir(), `hqchat-v3-encode-fuzz-${process.pid}.jsonl`);
  let mismatches = 0;
  const started = Date.now();
  console.log(`iterations: ${iterations}  seed: ${seed}  batch: ${batchSize}`);

  for (let done = 0; done < iterations; done += batchSize) {
    const n = Math.min(batchSize, iterations - done);
    const batch: Wire[] = [];
    for (let i = 0; i < n; i++) {
      const base = rng.pick(bases)();
      // A tenth are left alone, so the harness also proves the two agree on
      // frames that SHOULD encode — an "everything refused" run would pass an
      // oracle that only checked disagreement.
      batch.push(rng.int(10) === 0 ? base : mutate(base, rng));
    }

    const ts = batch.map(tsVerdict);
    const swift = swiftVerdicts(batch, batchFile);
    if (swift.length !== batch.length) {
      console.error(`✗ the Swift half returned ${swift.length} verdicts for ${batch.length} structs`);
      process.exit(1);
    }
    for (let i = 0; i < batch.length; i++) {
      if (ts[i] === swift[i] && ts[i]![0] !== "T") continue;
      mismatches++;
      fs.mkdirSync(FINDINGS, { recursive: true });
      const file = path.join(FINDINGS, `v3-encode-mismatch-${seed}-${done + i}.json`);
      fs.writeFileSync(file, JSON.stringify(batch[i], null, 2));
      if (mismatches <= 10) {
        console.log(`\n✗ MISMATCH at iteration ${done + i}`);
        console.log(`  ts:    ${ts[i]!.slice(0, 120)}`);
        console.log(`  swift: ${swift[i]!.slice(0, 120)}`);
        console.log(`  input: ${file}`);
      }
    }
  }

  try { fs.unlinkSync(batchFile); } catch { /* the tmp file is not load-bearing */ }
  const secs = ((Date.now() - started) / 1000).toFixed(1);
  console.log(`done: ${iterations} structs in ${secs}s — ${mismatches} mismatch(es)`);
  process.exit(mismatches === 0 ? 0 : 1);
}

if (require.main === module) main();
