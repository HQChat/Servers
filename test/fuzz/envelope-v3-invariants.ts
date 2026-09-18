/**
 * TypeScript-side invariant fuzzing for the v3 frame. Runs on Linux with no
 * Swift toolchain, which is why this is the half that lives in CI.
 *
 * ── WHY THIS FILE EXISTS ────────────────────────────────────────────────────
 * It replaces `envelope-invariants.ts`, which did the same job for v2 and went
 * with v2. That file was a CI gate — 200,000 inputs on every pull request, and
 * the ONLY envelope fuzzing CI could run, because the differential harnesses
 * need a macOS build of the Swift twin and there is deliberately no macOS
 * runner. Deleting it without this would have removed the gate from the decoder
 * at the exact moment that decoder became the only one.
 *
 * ── WHY A SECOND HARNESS AT ALL ─────────────────────────────────────────────
 * `envelope-v3-differential.ts` is the stronger check — it compares against the
 * Swift implementation on identical bytes — but it cannot run here. So CI gets
 * the properties that hold for the TypeScript side ALONE, and the
 * cross-language oracle stays on the Apple gate (apps/apple/verify.sh).
 *
 * ── THREE INVARIANTS, none of which needs a second implementation ───────────
 *
 *   1. `decodeV3` never throws. It sits on the receive path with no try/catch
 *      around it, so a throw is an unhandled rejection, not a dropped frame.
 *
 *   2. THE AAD IS THE FRAME'S CANONICAL HEADER, AND A PREFIX OF IT. This is
 *      v3's whole argument. v2 carried a second construction — a canonical
 *      encoding beside the JSON — and a receiver binding a REBUILT header can
 *      bind something other than what arrived. v3 returns the byte range it
 *      read. That claim is made in three files' comments and was checked by
 *      nothing.
 *
 *      ⚠️ "Is a prefix" ALONE is not the invariant, and writing it that way is
 *      the trap: every shorter slice of a frame is also a prefix of it, so an
 *      AAD truncated by a byte satisfies it. Verified by injection — an
 *      off-by-one on `headerEnd` passed 20,000 inputs. The check that bites is
 *      equality with `canonicalHeaderV3` of the decoded envelope: the range
 *      returned must be the header, not merely inside it.
 *
 *   3. ACCEPTED BYTES RE-ENCODE TO THEMSELVES. If `decodeV3` accepts B and
 *      yields E, `encodeV3(E)` must be B exactly. Two byte strings decoding to
 *      one envelope means the encoder and decoder disagree about the format —
 *      the drift v3's single-construction design exists to make impossible, and
 *      the thing a length-prefixed binary format is easiest to get wrong about
 *      (a trailing byte nobody reads, a length honoured on the way in and
 *      recomputed on the way out).
 *
 * Note what is NOT asserted: that a mutated frame is REFUSED. Most mutations
 * land in the payload or a blob and produce a perfectly well-formed frame that
 * simply will not open — indistinguishable from a wrong key. Refusal is not the
 * property; self-consistency is.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { canonicalHeaderV3, decodeV3, encodeV3, looksLikeV3 } from "../../lib/envelope-v3";
import { makeRng, Rng } from "./rng";

const VECTORS = path.join(__dirname, "..", "helpers", "envelope-v3-vectors.json");

/** The pinned frames, as bytes. Five cases: msg, stepping, init, an init with
 *  no one-time prekey, and a multi-byte msgId. */
function loadSeeds(): Buffer[] {
  const vectors = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
  return Object.values(vectors.cases as Record<string, { frameHex: string }>)
    .map((c) => Buffer.from(c.frameHex, "hex"));
}

/**
 * One mutation, over BYTES.
 *
 * v2's mutator worked on JSON text — retyping fields, swapping escapes,
 * duplicating keys — and none of that means anything here. What a binary format
 * is vulnerable to is different: a length prefix that no longer matches its
 * blob, a truncation mid-field, a flag bit nobody defined, a frame with bytes
 * left over. So the operators are chosen to reach those, and the magic is left
 * alone most of the time — a frame that stops looking like v3 is refused by
 * `looksLikeV3` before anything interesting happens, and an input the decoder
 * rejects in its first line tests nothing.
 */
function mutate(seed: Buffer, rng: Rng): Buffer {
  const b = Buffer.from(seed);
  switch (rng.int(8)) {
    case 0: {                                   // flip one bit
      if (b.length === 0) return b;
      const i = rng.int(b.length);
      b[i] = b[i]! ^ (1 << rng.int(8));
      return b;
    }
    case 1: {                                   // replace one byte outright
      if (b.length === 0) return b;
      b[rng.int(b.length)] = rng.int(256);
      return b;
    }
    case 2:                                     // truncate
      return b.subarray(0, rng.int(b.length + 1));
    case 3:                                     // extend with noise
      return Buffer.concat([b, crypto.randomBytes(1 + rng.int(64))]);
    case 4: {                                   // corrupt a big-endian u32 in place
      if (b.length < 4) return b;
      const at = rng.int(b.length - 3);
      b.writeUInt32BE(rng.pick([0, 1, 0xffffffff, 0x7fffffff, rng.int(0xffff)]), at);
      return b;
    }
    case 5: {                                   // splice two seeds together
      const other = seed;
      const cut = rng.int(b.length + 1);
      return Buffer.concat([b.subarray(0, cut), other.subarray(rng.int(other.length + 1))]);
    }
    case 6: {                                   // zero a run of bytes
      if (b.length === 0) return b;
      const at = rng.int(b.length);
      b.fill(0, at, Math.min(b.length, at + 1 + rng.int(16)));
      return b;
    }
    default: {                                  // duplicate a slice
      if (b.length === 0) return b;
      const at = rng.int(b.length);
      const len = 1 + rng.int(Math.min(32, b.length - at));
      return Buffer.concat([b.subarray(0, at), b.subarray(at, at + len), b.subarray(at)]);
    }
  }
}

function main() {
  const args = process.argv.slice(2);
  const flag = (name: string, fallback: number) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 && args[i + 1] ? Number(args[i + 1]) : fallback;
  };
  const iterations = flag("iterations", 200_000);
  const seed = flag("seed", 1);

  const seeds = loadSeeds();
  const rng = makeRng(seed);
  const failures: string[] = [];
  const started = Date.now();
  let accepted = 0;
  let looked = 0;

  for (let i = 0; i < iterations && failures.length < 10; i++) {
    const raw = mutate(rng.pick(seeds), rng);
    const hex = raw.subarray(0, 96).toString("hex");

    if (looksLikeV3(raw)) looked++;

    let got: { env: ReturnType<typeof decodeV3> } | null = null;
    try {
      got = { env: decodeV3(raw) };
    } catch (e) {
      failures.push(`[1] decodeV3 threw: ${e instanceof Error ? e.message : String(e)}\n    ${hex}`);
      continue;
    }
    const decoded = got.env;
    if (!decoded) continue;
    accepted++;

    // [2] The AAD is the frame's own prefix — and is the WHOLE header, not a
    // slice of one. The second half is what catches a truncation; see the note
    // in this file's header about why the prefix check alone does not.
    if (!raw.subarray(0, decoded.aad.length).equals(decoded.aad)) {
      failures.push(`[2] the AAD is NOT a prefix of the frame — a receiver would bind `
        + `bytes it did not receive\n    aad ${decoded.aad.length}B of ${raw.length}B\n    ${hex}`);
      continue;
    }
    const header = canonicalHeaderV3(decoded.env);
    if (header === null) {
      failures.push(`[2] canonicalHeaderV3 refused an ACCEPTED frame\n    ${hex}`);
      continue;
    }
    if (!header.equals(decoded.aad)) {
      failures.push(`[2] the AAD is not the frame's canonical header — a receiver binds `
        + `${decoded.aad.length}B where the header is ${header.length}B\n    ${hex}`);
      continue;
    }

    // [3] Accepted bytes re-encode to themselves.
    let re: Buffer | null;
    try {
      re = encodeV3(decoded.env);
    } catch (e) {
      failures.push(`[3] encodeV3 threw on an ACCEPTED frame: ${e instanceof Error ? e.message : String(e)}\n    ${hex}`);
      continue;
    }
    if (re === null) {
      failures.push(`[3] encodeV3 REFUSED a frame decodeV3 accepted — the two disagree `
        + `about the format\n    ${hex}`);
      continue;
    }
    if (!re.equals(raw)) {
      failures.push(`[3] round trip changed the bytes — two encodings of one envelope\n`
        + `    in  ${raw.length}B ${hex}\n    out ${re.length}B ${re.subarray(0, 96).toString("hex")}`);
    }
  }

  const elapsed = (Date.now() - started) / 1000;
  console.log(`v3 frame invariants: ${iterations} inputs, seed ${seed}, `
    + `${looked} looked like v3, ${accepted} decoded, ${elapsed.toFixed(1)}s`);

  // A run where nothing decoded proves nothing, and would pass. The mutator is
  // deliberately destructive, so this is a floor on how destructive: if a change
  // to the format or the mutator makes every input unparseable, this fails
  // rather than reporting a clean 200,000.
  if (accepted === 0 && iterations >= 1000) {
    console.error("\n✗ not one input decoded — this run tested nothing");
    process.exit(1);
  }

  if (failures.length > 0) {
    console.error(`\n✗ ${failures.length} invariant violation(s):\n`);
    for (const f of failures) console.error("  " + f + "\n");
    process.exit(1);
  }
  console.log("✓ no violations");
}

main();
