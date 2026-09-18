// The committed cross-implementation vectors still match their generators.
//
// WHY THIS MATTERS MORE THAN IT LOOKS. The vector files are how the Swift client
// and the TypeScript server are held to the same answers: `apps/apple/tests/run.sh`
// READS them rather than pasting values into Swift, and the reason is recorded in
// that file — the v1 ratchet test pasted the hex in, so a change on the
// TypeScript side left the Swift side asserting stale values and passing.
//
// Reading them fixed the copy. It did not fix the other half: if a generator
// changes and nobody regenerates, both suites keep agreeing with a file that no
// longer describes either implementation, and they agree for the wrong reason.
// Nothing checked that until now.
//
// It is also what makes excluding `scripts/gen-*.ts` from the coverage
// denominator honest. They are excluded on the grounds that a broken generator
// fails the suites that assert against its output — which is only true while the
// committed output is actually the generator's output.
//
// All five generators are deterministic (verified: two runs, identical bytes),
// so this is a byte comparison rather than a semantic one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

const ROOT = path.join(__dirname, "..");

const VECTORS: Array<{ generator: string; file: string }> = [
  { generator: "scripts/gen-identity-vectors.ts", file: "test/helpers/identity-vectors.json" },
  { generator: "scripts/gen-envelope-v3-vectors.ts", file: "test/helpers/envelope-v3-vectors.json" },
  { generator: "scripts/gen-handshake-vectors.ts", file: "test/helpers/handshake-vectors.json" },
  { generator: "scripts/gen-ratchet-vectors.ts", file: "test/helpers/double-ratchet-vectors.json" },
];

function generate(generator: string): string {
  return execFileSync("npx", ["tsx", generator], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

for (const { generator, file } of VECTORS) {
  test(`${path.basename(file)} is what its generator produces`, () => {
    const committed = fs.readFileSync(path.join(ROOT, file), "utf8");
    const fresh = generate(generator);
    assert.equal(
      fresh.trim(),
      committed.trim(),
      `${file} is stale.\n` +
      `Both suites are asserting against a file that no longer matches ${generator}, ` +
      `so they agree with each other for the wrong reason.\n` +
      `Regenerate it:  npx tsx ${generator} > ${file}`,
    );
  });
}

test("every generator has a committed file, and every file has a generator", () => {
  // A generator whose output nobody committed is dead code pretending to be
  // covered; a vector file with no generator cannot be checked by the tests
  // above and would drift silently, which is the whole failure being guarded.
  const generators = fs.readdirSync(path.join(ROOT, "scripts"))
    .filter((f) => f.startsWith("gen-") && f.endsWith(".ts"))
    .map((f) => `scripts/${f}`);
  assert.deepEqual(
    generators.sort(),
    VECTORS.map((v) => v.generator).sort(),
    "a gen-*.ts script is not covered by this file",
  );

  const helpers = fs.readdirSync(path.join(ROOT, "test/helpers"))
    .filter((f) => f.endsWith("-vectors.json"))
    .map((f) => `test/helpers/${f}`);
  assert.deepEqual(
    helpers.sort(),
    VECTORS.map((v) => v.file).sort(),
    "a vector file has no generator checking it",
  );
});

test("the generators are deterministic, or this file proves nothing", () => {
  // A generator that reseeded per run would make every comparison above fail
  // for a reason that has nothing to do with drift — and the obvious response
  // would be to delete the check. Asserted on the cheapest one.
  const a = generate("scripts/gen-identity-vectors.ts");
  const b = generate("scripts/gen-identity-vectors.ts");
  assert.equal(a, b, "gen-identity-vectors is not deterministic; the freshness check cannot work");
});
