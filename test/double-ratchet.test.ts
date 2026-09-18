// Cross-implementation known-answer vectors for the v2 KEM double ratchet.
//
// This file and apps/apple/tests/DoubleRatchetTests.swift assert the SAME
// helpers/double-ratchet-vectors.json. Both READ it — the v1 Swift test copied
// the hex into its source, so "cross-impl" rested on someone remembering to
// update two files, and nothing failed when they did not.
//
// The policy block is asserted too. v1 carried `ROTATE_AFTER_MESSAGES` and
// `MAX_SKIPPED` as a prose contract ("MUST stay equal to their Swift twins")
// that no test checked, so a smaller cap on one side would silently drop keys
// the peer still served.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  initRoot,
  rootStep,
  messageKey,
  chainNext,
  walkChain,
  chainId,
  MAX_SKIPPED,
  RATCHET_MIN_STEP_INTERVAL_MS,
  RATCHET_MAX_MESSAGES_PER_CHAIN,
} from "../lib/double-ratchet";

const V = JSON.parse(
  fs.readFileSync(path.join(__dirname, "helpers", "double-ratchet-vectors.json"), "utf8")
);

const hex = (b: Buffer) => b.toString("hex");
const B = (s: string) => Buffer.from(s, "hex");

const ssId = B(V.input.ssId);
const ssMt = B(V.input.ssMt);
const ssOt = B(V.input.ssOt);
const stepSs = B(V.input.stepSs);

test("the vector file is the v2 shape", () => {
  assert.equal(V.version, 2, "a v1 vector file would silently assert the wrong protocol");
  // KEM shared secrets are 32 bytes since CR-1; the v1 vectors still used
  // 24-byte seeds, which no longer represent anything the wire carries.
  for (const [name, value] of Object.entries(V.input)) {
    assert.equal((value as string).length, 64, `${name} is 32 bytes`);
  }
});

test("policy constants match the shared contract", () => {
  assert.equal(MAX_SKIPPED, V.policy.maxSkipped);
  assert.equal(RATCHET_MIN_STEP_INTERVAL_MS, V.policy.ratchetMinStepIntervalMs);
  assert.equal(RATCHET_MAX_MESSAGES_PER_CHAIN, V.policy.ratchetMaxMessagesPerChain);
});

test("initRoot matches the pinned vector, with and without a one-time prekey", () => {
  const withOt = initRoot(ssId, ssMt, ssOt);
  assert.equal(hex(withOt.root), V.initRoot.withOneTime.root);
  assert.equal(hex(withOt.chain), V.initRoot.withOneTime.chain);

  // The exhausted-pool fallback is a DIFFERENT session, not the same one with a
  // shorter forward-secrecy window by convention.
  const noOt = initRoot(ssId, ssMt);
  assert.equal(hex(noOt.root), V.initRoot.withoutOneTime.root);
  assert.equal(hex(noOt.chain), V.initRoot.withoutOneTime.chain);
  assert.notEqual(hex(noOt.root), hex(withOt.root));
});

test("rootStep matches the pinned vector and chains from the previous root", () => {
  const first = rootStep(B(V.initRoot.withOneTime.root), stepSs);
  assert.equal(hex(first.root), V.rootStep.first.root);
  assert.equal(hex(first.chain), V.rootStep.first.chain);

  // The same shared secret against the NEW root gives a different result. This
  // is the property v1's deriveEpochRoot lacked — it ignored the previous root
  // entirely, so epochs were independent re-keys rather than a ratchet.
  const second = rootStep(first.root, stepSs);
  assert.equal(hex(second.root), V.rootStep.second.root);
  assert.equal(hex(second.chain), V.rootStep.second.chain);
  assert.notEqual(hex(second.root), hex(first.root));
  assert.notEqual(hex(second.chain), hex(first.chain));
});

test("messageKey/chainNext match the pinned vectors", () => {
  // Annotated: `Buffer.from(hex)` narrows to Buffer<ArrayBuffer>, while the KDF
  // returns the wider Buffer<ArrayBufferLike>, so an inferred `ck` cannot be
  // reassigned from it.
  let ck: Buffer = B(V.initRoot.withOneTime.chain);
  for (const [i, expected] of (V.chain.messageKeys_0_3 as string[]).entries()) {
    assert.equal(hex(messageKey(ck)), expected, `message key ${i}`);
    ck = chainNext(ck);
  }
  assert.equal(hex(ck), V.chain.afterConsuming_0_3, "the chain lands where the vector says");
});

test("walkChain matches the pinned vector, target key and skipped keys alike", () => {
  const walk = walkChain(B(V.initRoot.withOneTime.chain), 0, 3);
  assert.equal(hex(walk.messageKey), V.walkChain.messageKey);
  assert.equal(hex(walk.ck), V.walkChain.ck);
  assert.equal(walk.nextN, V.walkChain.nextN);

  assert.equal(walk.skipped.length, V.walkChain.skipped.length);
  for (const [i, s] of walk.skipped.entries()) {
    assert.equal(s.n, V.walkChain.skipped[i].n, `skipped[${i}].n`);
    assert.equal(hex(s.key), V.walkChain.skipped[i].key, `skipped[${i}].key`);
  }

  // The skipped keys ARE the message keys of the positions walked past — a
  // receiver serving one from cache must get what the sender used.
  for (const [i, s] of walk.skipped.entries()) {
    assert.equal(hex(s.key), V.chain.messageKeys_0_3[i], `skipped[${i}] == messageKey[${i}]`);
  }
});

test("chainId matches the pinned vector", () => {
  assert.equal(chainId(B(V.input.rkPub)), V.chainId.ofRkPub);
});
