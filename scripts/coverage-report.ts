// The honest coverage number.
//
// WHY THIS EXISTS. `node --experimental-test-coverage` reports only on files
// something IMPORTED. A file no test ever loads does not appear as 0% — it does
// not appear at all, and the summary line is an average over the survivors. On
// this repo that is the difference between the 95.08% the tool printed and the
// 51.3% actually covered: 4,799 lines in api/main.ts, auth/main.ts, bot/bot.ts,
// push/main.ts, ops/broker-watch.ts, lib/health-monitor.ts, services/apns/api.ts
// and lib/mailer.ts were invisible to it, and every one of them is production
// code that runs in front of users.
//
// `--test-coverage-include` does not fix this: it filters what is REPORTED out
// of what was collected. It cannot report on a file that was never instrumented
// because it was never loaded. So the denominator has to come from the
// filesystem instead, which is what this does.
//
// Two numbers, because they answer different questions and averaging them would
// hide the interesting one:
//
//   REACHED    lcov's own line coverage over files a test actually loaded.
//              This is the number Node prints, and it is a fair measure of how
//              well the tested code is tested.
//
//   HONEST     every source file weighted by its line count, with unreached
//              files at zero. This is the number that answers "how much of this
//              service is covered", and it is the one the thresholds use.
//
// The weighting mixes lcov's instrumented-line ratio with raw file length, which
// is approximate — an unreached file's true instrumented-line count is unknown
// precisely because it was never instrumented. It errs toward counting unreached
// code as larger, which is the right direction for a number whose job is to stop
// anyone quoting 95% again.
//
// Usage:
//   npm run coverage
//   tsx scripts/coverage-report.ts --lcov coverage/lcov.info [--min-line 51] [--json]

import * as fs from "fs";
import * as path from "path";

const ROOT = path.join(__dirname, "..");

/** Directories whose .ts is source under test. "." picks up root-level files,
 *  which an earlier directory-only list missed entirely — checks.ts was
 *  production code sitting there uncounted until this walk found it. There is
 *  no root-level source today; "." stays so the next one is not missed either. */
const SOURCE_DIRS = [".", "api", "auth", "bot", "lib", "ops", "push", "services", "scripts"];

/**
 * Excluded from the denominator, deliberately, each for a stated reason.
 *
 * `scripts/gen-*.ts` are the vector generators. They are covered transitively:
 * every cross-implementation suite asserts against the fixtures they produce, so
 * a broken generator fails those suites rather than going unnoticed.
 *
 * That argument only holds while the COMMITTED output is still the generator's
 * output, and `test/vector-freshness.test.ts` is what makes it hold — it
 * regenerates all five and compares byte for byte. Without it, a generator could
 * change while both suites kept agreeing with a stale file, agreeing with each
 * other for the wrong reason.
 */
const EXCLUDE = [
  /^test\//,
  /^node_modules\//,
  /^scripts\/gen-.*\.ts$/,
  // The instrument does not measure itself. Counting this file would let the
  // number be improved by making the reporter longer, which is not a property
  // anyone wants a coverage metric to have.
  /^scripts\/coverage-report\.ts$/,
  /\.d\.ts$/,
  // Mutation testing copies the whole tree into a sandbox per concurrent runner.
  // Those copies are real .ts files on disk, so the filesystem walk that makes
  // this denominator HONEST counts every one of them — the number fell from
  // 91.7% to 26.2% over 37,426 lines while Stryker was running, which is the
  // denominator working correctly on a directory that is not source.
  /^\.stryker-tmp\//,
  /^reports\//,
];

interface FileCoverage {
  file: string;
  loc: number;
  instrumented: number;
  hit: number;
  linePct: number;
  reached: boolean;
}

// --- the denominator, from the filesystem -----------------------------------

function sourceFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const rel = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "node_modules") continue;
        walk(rel);
      } else if (e.name.endsWith(".ts")) {
        out.push(rel);
      }
    }
  };
  for (const d of SOURCE_DIRS) walk(d);
  // "." walks everything, so it re-finds what the named directories already
  // found. Dedupe rather than dropping the root walk — it is what catches a
  // source file added at the root, which no named directory would see.
  const unique = [...new Set(out.map((f) => (f.startsWith("./") ? f.slice(2) : f)))];
  return unique.filter((f) => !EXCLUDE.some((re) => re.test(f))).sort();
}

// --- what lcov saw ----------------------------------------------------------

/** Parse the SF / DA records we need. Everything else in lcov is ignored. */
function parseLcov(lcovPath: string): Map<string, { instrumented: number; hit: number }> {
  const seen = new Map<string, { instrumented: number; hit: number }>();
  if (!fs.existsSync(lcovPath)) {
    console.error(`❌ no lcov at ${lcovPath} — run the tests with --test-reporter=lcov first`);
    process.exit(2);
  }
  let current: string | null = null;
  let lines = new Map<number, number>();

  const flush = () => {
    if (current === null) return;
    // A file can appear more than once (one record per test process). Merge by
    // taking the max hit count per line, or a file covered in run A and merely
    // loaded in run B would read as uncovered.
    const prev = seen.get(current);
    const instrumented = lines.size;
    const hit = [...lines.values()].filter((n) => n > 0).length;
    if (!prev || hit > prev.hit) seen.set(current, { instrumented, hit });
    current = null;
    lines = new Map();
  };

  for (const raw of fs.readFileSync(lcovPath, "utf8").split("\n")) {
    const line = raw.trim();
    if (line.startsWith("SF:")) {
      flush();
      current = path.relative(ROOT, path.resolve(ROOT, line.slice(3)));
    } else if (line.startsWith("DA:")) {
      const parts = line.slice(3).split(",");
      const n = Number(parts[0]);
      const count = Number(parts[1] ?? 0);
      if (Number.isFinite(n)) {
        lines.set(n, Math.max(lines.get(n) ?? 0, Number.isFinite(count) ? count : 0));
      }
    } else if (line === "end_of_record") {
      flush();
    }
  }
  flush();
  return seen;
}

function countLines(rel: string): number {
  return fs.readFileSync(path.join(ROOT, rel), "utf8").split("\n").length;
}

// --- report -----------------------------------------------------------------

function build(): FileCoverage[] {
  const lcov = parseLcov(argValue("--lcov") ?? "coverage/lcov.info");
  return sourceFiles().map((file) => {
    const loc = countLines(file);
    const c = lcov.get(file);
    if (!c || c.instrumented === 0) {
      return { file, loc, instrumented: 0, hit: 0, linePct: 0, reached: false };
    }
    return {
      file,
      loc,
      instrumented: c.instrumented,
      hit: c.hit,
      linePct: (100 * c.hit) / c.instrumented,
      reached: true,
    };
  });
}

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function main() {
  const files = build();
  const unreached = files.filter((f) => !f.reached).sort((a, b) => b.loc - a.loc);

  const totalLoc = files.reduce((s, f) => s + f.loc, 0);
  const weightedCovered = files.reduce((s, f) => s + (f.loc * f.linePct) / 100, 0);
  const honest = (100 * weightedCovered) / totalLoc;

  const reachedFiles = files.filter((f) => f.reached);
  const reachedInstrumented = reachedFiles.reduce((s, f) => s + f.instrumented, 0);
  const reachedHit = reachedFiles.reduce((s, f) => s + f.hit, 0);
  const reached = reachedInstrumented ? (100 * reachedHit) / reachedInstrumented : 0;

  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ honest, reached, totalLoc, files }, null, 2));
  } else {
    const pad = (s: string, n: number) => s.padEnd(n);
    const num = (n: number, w = 6) => n.toFixed(1).padStart(w);

    console.log("");
    console.log("── Coverage, over every source file (not just the loaded ones) ──");
    console.log("");
    console.log(`  ${pad("files", 10)} ${files.length} source · ${reachedFiles.length} reached by a test · ${unreached.length} never loaded`);
    console.log(`  ${pad("REACHED", 10)} ${num(reached)}%  line coverage within the files a test loads`);
    console.log(`  ${pad("HONEST", 10)} ${num(honest)}%  LOC-weighted over all ${totalLoc} lines — unreached files count as zero`);

    if (unreached.length) {
      const lost = unreached.reduce((s, f) => s + f.loc, 0);
      console.log("");
      console.log(`  Never loaded by any test — ${lost} lines (${((100 * lost) / totalLoc).toFixed(1)}% of the source):`);
      for (const f of unreached) console.log(`    ${String(f.loc).padStart(6)}  ${f.file}`);
    }

    const weak = reachedFiles.filter((f) => f.linePct < 90).sort((a, b) => a.linePct - b.linePct);
    if (weak.length) {
      console.log("");
      console.log("  Reached but under 90% line:");
      for (const f of weak) {
        console.log(`    ${num(f.linePct)}%  ${pad(f.file, 34)} ${f.hit}/${f.instrumented} instrumented lines`);
      }
    }
    console.log("");
  }

  // --- the gate ---------------------------------------------------------------
  //
  // Enforced HERE rather than by node's own `--test-coverage-lines`, and the
  // reason is worth recording: that flag is documented, accepted, printed in
  // --help, and DOES NOT ENFORCE on node 22.12. Verified — a run reporting
  // 92.32% line coverage with `--test-coverage-lines=100` exits 0. A threshold
  // that looks like a gate and is not is worse than no gate, because it stops
  // anyone from adding a real one.
  //
  // Two numbers, because they fail differently. REACHED falls when a covered
  // file loses a test. HONEST falls when a whole file stops being loaded, which
  // REACHED cannot see — the file simply leaves the denominator.
  const failures: string[] = [];
  const gate = (flag: string, label: string, value: number) => {
    const min = Number(argValue(flag) ?? NaN);
    if (Number.isFinite(min) && value < min) {
      failures.push(`${label} ${value.toFixed(1)}% is below the required ${min}%`);
    }
  };
  gate("--min-line", "honest line coverage", honest);
  gate("--min-reached", "reached line coverage", reached);

  if (failures.length) {
    console.error("");
    for (const f of failures) console.error(`❌ ${f}`);
    console.error("   Thresholds only go up. If this drop is deliberate, the number to");
    console.error("   change is in package.json, and the change is the reviewable part.");
    process.exit(1);
  }
}

main();
