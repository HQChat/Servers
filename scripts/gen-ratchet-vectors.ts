// Regenerates test/helpers/double-ratchet-vectors.json.
//
//   npx tsx scripts/gen-ratchet-vectors.ts > test/helpers/double-ratchet-vectors.json
//
// Committed rather than left in a scratch directory, which is what the v1
// vectors did ("regenerate with scratch") — so the only way to reproduce them
// was to rewrite the generator and hope it matched. Any change to the KDF
// labels or the policy constants in lib/double-ratchet.ts means re-running this
// AND re-running the Swift suite, which reads the same file.

import { initRoot, rootStep, messageKey, chainNext, walkChain, chainId,
         MAX_SKIPPED, RATCHET_MIN_STEP_INTERVAL_MS, RATCHET_MAX_MESSAGES_PER_CHAIN }
  from "../lib/double-ratchet";

const h = (b: Buffer) => b.toString("hex");
const B = (s: string) => Buffer.from(s, "hex");

// Fixed, arbitrary 32-byte secrets — KEM shared secrets are 32 bytes since CR-1,
// unlike the v1 vectors which still used 24-byte seeds.
const ssId = B("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
const ssMt = B("807f7e7d7c7b7a797877767574737271706f6e6d6c6b6a696867666564636261");
const ssOt = B("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
const stepSs = B("cafebabedeadbeef0123456789abcdeffedcba9876543210cafebabedeadbeef");
const rkPub  = B("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");

const withOt = initRoot(ssId, ssMt, ssOt);
const noOt   = initRoot(ssId, ssMt);
const step1  = rootStep(withOt.root, stepSs);
const step2  = rootStep(step1.root, stepSs);   // same ss, different root => different out

const walk = walkChain(withOt.chain, 0, 3);

console.log(JSON.stringify({
  _comment:
    "Cross-implementation known-answer vectors for the v2 KEM double ratchet. " +
    "Asserted by BOTH services/server/test/double-ratchet.test.ts and " +
    "apps/apple/tests/DoubleRatchetTests.swift, which READ this file rather than " +
    "copying the hex (the v1 vectors were copy-pasted into the Swift test, so " +
    "'cross-impl' rested on someone remembering). If these drift, the Swift " +
    "client and the TS bot no longer derive the same keys. All values hex.",
  version: 2,
  policy: {
    _comment:
      "Operational policy, asserted on both sides. v1 carried these as a prose " +
      "contract ('MUST stay equal to their Swift twins') that no test checked.",
    maxSkipped: MAX_SKIPPED,
    ratchetMinStepIntervalMs: RATCHET_MIN_STEP_INTERVAL_MS,
    ratchetMaxMessagesPerChain: RATCHET_MAX_MESSAGES_PER_CHAIN,
  },
  input: { ssId: h(ssId), ssMt: h(ssMt), ssOt: h(ssOt), stepSs: h(stepSs), rkPub: h(rkPub) },
  initRoot: {
    withOneTime: { root: h(withOt.root), chain: h(withOt.chain) },
    withoutOneTime: { root: h(noOt.root), chain: h(noOt.chain) },
  },
  rootStep: {
    first:  { root: h(step1.root), chain: h(step1.chain) },
    second: { root: h(step2.root), chain: h(step2.chain) },
  },
  chain: {
    _comment: "messageKey/chainNext walked from initRoot.withOneTime.chain",
    messageKeys_0_3: [0,1,2,3].reduce((acc: string[], _, i) => {
      let ck = withOt.chain;
      for (let j = 0; j < i; j++) ck = chainNext(ck);
      acc.push(h(messageKey(ck)));
      return acc;
    }, []),
    // The chain AFTER consuming positions 0..3 — four advances, one per key
    // above. Named for what a receiver holds once it has opened all four, which
    // is the value an implementation actually has to agree on.
    afterConsuming_0_3: h([0,1,2,3].reduce((ck) => chainNext(ck), withOt.chain)),
  },
  walkChain: {
    _comment: "from=0, target=3 over initRoot.withOneTime.chain",
    messageKey: h(walk.messageKey),
    ck: h(walk.ck),
    nextN: walk.nextN,
    skipped: walk.skipped.map((s) => ({ n: s.n, key: h(s.key) })),
  },
  chainId: { ofRkPub: chainId(rkPub) },
}, null, 2));
