/**
 * Deterministic randomness for every fuzz target in this directory.
 *
 * It lived in `envelope-differential.ts` — the v2 harness — and the two v3
 * fuzzers imported it from there, so deleting v2 would have taken the random
 * number generator out from under the format that replaced it. That is the
 * ordinary shape of a mistake during a removal: the thing being deleted was
 * also the host of something general, and nothing says so until the build
 * breaks. Hence its own file, which belongs to no format.
 */

/** mulberry32 — seedable, so a finding replays. `Math.random()` cannot. */
export function makeRng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (upper: number) => (upper <= 0 ? 0 : Math.floor(next() * upper)),
    pick: <T>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)]!,
    bool: () => next() < 0.5,
  };
}
export type Rng = ReturnType<typeof makeRng>;
