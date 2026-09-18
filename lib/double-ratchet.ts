import * as crypto from "crypto";

/**
 * KEM double ratchet — the v2 message-key core.
 *
 * Replaces `lib/ratchet.ts`, which is a symmetric ratchet plus an occasional
 * re-key and is deleted once the last caller moves over. Two things were wrong
 * with it, and both are structural rather than bugs:
 *
 *   - Every shared secret was a KEM encapsulation to the peer's LONG-TERM pinned
 *     key. Decapsulation is deterministic, so one leaked identity secret plus a
 *     recorded transcript recomputes every root, chain key and message key that
 *     conversation ever used. Deleting message keys after use bought nothing,
 *     because they were recomputable from ciphertexts the network saw.
 *   - The root did not chain: `deriveEpochRoot(seedA, seedB)` ignored the
 *     previous root, so "epochs" were independent re-keys sitting side by side.
 *
 * Here the root chains, and every step mixes a secret encapsulated to an
 * EPHEMERAL key that is destroyed after use. That is what makes forward secrecy
 * survive an identity compromise and post-compromise security self-heal.
 *
 * This module is pure and KEM-free on purpose: it takes shared secrets the
 * caller already has and returns key material. The HQC calls live in the driver
 * (`ratchetSession`) so these derivations unit-test on any platform and can be
 * pinned byte-for-byte against the Swift twin by `double-ratchet-vectors.json`.
 *
 * ── Why a KEM ratchet is not a DH ratchet transliterated ──────────────────────
 * With Diffie-Hellman both sides compute the same secret from public values, so
 * a header needs only the sender's new public key. With a KEM the ENCAPSULATOR
 * chooses the secret and must transmit a ciphertext for it. So a stepping header
 * carries two things — a fresh public key of the sender's own, and a ciphertext
 * encapsulated to the key the peer most recently advertised:
 *
 *   sender:   (ct, ss) = Encap(peerRkPub);  (root', ck) = rootStep(root, ss)
 *             header = { rk: myNewRkPub, kemCt: ct }
 *   receiver: ss = Decap(myRkSec, ct);      (root', ck) = rootStep(root, ss)
 *             adopt peerRkPub = rk, and encapsulate to it on the next step
 */

const SALT = Buffer.from("salt", "utf8");

// ── Operational policy ───────────────────────────────────────────────────────
// Shared with the Swift twin through `double-ratchet-policy.json`, which BOTH
// sides assert. The v1 constants were a prose contract ("MUST stay equal to
// their Swift twins") that no test checked, so drift was silent.

/** Cached skipped message keys, across all chains. Bounds memory and the walk. */
export const MAX_SKIPPED = 2000;

/**
 * A stepping header costs a public key (7237 B) plus a ciphertext (14421 B) —
 * ~29 kB base64. Stepping on every direction flip is the strongest option and
 * what Signal does, but in a fast back-and-forth that is 29 kB per turn on a
 * phone. So a flip only steps if the current sending chain has been used at
 * least once AND one of these thresholds is met; otherwise the reply continues
 * the existing chain, which costs nothing extra.
 *
 * COUNT IS THE PRIMARY TRIGGER, time the backstop. It used to be the other way
 * round, with the interval at 60 s, and that was tuned for a fast exchange —
 * where it is nearly free. In the pattern messaging actually has, replies
 * minutes apart, EVERY message crossed the threshold and carried a full step:
 * a 40-character message that would be a ~300-byte frame became a ~29 kB one.
 * A hundredfold, on mobile data, in the common case rather than the edge one.
 *
 * At 15 minutes a chain steps on VOLUME during a conversation and on ELAPSED
 * TIME between them, which is the shape the cost profile wants.
 *
 * The cost of waiting is bounded and explicit: a compromise heals within one
 * step, so these numbers ARE the post-compromise-security window. Concretely,
 * with the values below: **at most 32 messages, or 15 minutes of an idle
 * conversation, before a compromise heals.** Widening either widens that
 * window — it is a security decision, not only a tuning one.
 */
export const RATCHET_MIN_STEP_INTERVAL_MS = 900_000;
export const RATCHET_MAX_MESSAGES_PER_CHAIN = 32;

function hkdf(ikm: Buffer, info: string): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, SALT, Buffer.from(info, "utf8"), 32));
}

export interface RootAndChain {
  root: Buffer;
  chain: Buffer;
}

/**
 * The initial root and the INITIATOR's first sending chain, from the X3DH-style
 * handshake secrets.
 *
 * `ssId` is encapsulated to the peer's pinned identity key and is what
 * authenticates them — only the real holder can decapsulate it. `ssMt` and the
 * optional `ssOt` come from published prekeys and are what make the transcript
 * stop being decryptable once those secrets are gone. Both roles matter: identity
 * alone has no forward secrecy, prekeys alone authenticate nobody.
 *
 * `ssOt` is absent when the peer's one-time pool was exhausted and the server
 * served the reusable medium-term key instead. That is a weaker forward-secrecy
 * window, not a loss of confidentiality, and it is deliberately not an error.
 *
 * The responder derives the same pair by decapsulating the three ciphertexts in
 * the `init` frame, so no negotiation is needed — the roles are asymmetric,
 * which is also why none of the sorted-seed symmetry of v1 survives here.
 */
export function initRoot(ssId: Buffer, ssMt: Buffer, ssOt?: Buffer): RootAndChain {
  const ikm = Buffer.concat(ssOt ? [ssId, ssMt, ssOt] : [ssId, ssMt]);
  return {
    root: hkdf(ikm, "hqchat/v2/init/root"),
    chain: hkdf(ikm, "hqchat/v2/init/chain"),
  };
}

/**
 * Advance the root by one asymmetric step, yielding the next root and the chain
 * key for the direction that just stepped.
 *
 * This is the line v1 was missing. The new root depends on the OLD root as well
 * as the fresh secret, so an attacker who learns the state at step n cannot run
 * it backwards, and one who misses a step cannot rejoin by capturing later
 * ciphertexts alone.
 */
export function rootStep(root: Buffer, ss: Buffer): RootAndChain {
  const ikm = Buffer.concat([root, ss]);
  return {
    root: hkdf(ikm, "hqchat/v2/root"),
    chain: hkdf(ikm, "hqchat/v2/chain"),
  };
}

/** Message key at the current chain position. Delete after use. */
export function messageKey(ck: Buffer): Buffer {
  return hkdf(ck, "hqchat/v2/msg");
}

/** Advance the chain one step. Delete the old ck after use. */
export function chainNext(ck: Buffer): Buffer {
  return hkdf(ck, "hqchat/v2/ck");
}

export interface ChainWalk {
  messageKey: Buffer;
  ck: Buffer;
  nextN: number;
  skipped: { n: number; key: Buffer }[];
}

/**
 * Walk a receiving chain from `fromN` up to and including `targetN`, returning
 * the target's message key, the advanced chain, and the keys skipped on the way
 * (to cache for out-of-order and offline delivery).
 *
 * The gap is bounded BEFORE the walk. `n` arrives on a frame header and is read
 * to CHOOSE the key, so it cannot have been authenticated by the payload that
 * key opens; each step is an HKDF. Capping only the resulting cache is too late —
 * `n = 2^31` would spend two billion HKDF invocations first, and on the Swift
 * twin that runs on the MainActor. Anything past MAX_SKIPPED is undeliverable
 * regardless, since its keys would be evicted immediately.
 */
export function walkChain(ck: Buffer, fromN: number, targetN: number): ChainWalk {
  if (!Number.isInteger(targetN) || !Number.isInteger(fromN)) {
    throw new Error("walkChain: indices must be integers");
  }
  if (targetN < fromN) throw new Error("walkChain: targetN < fromN");
  if (targetN - fromN > MAX_SKIPPED) {
    throw new Error(`walkChain: gap ${targetN - fromN} exceeds MAX_SKIPPED (${MAX_SKIPPED})`);
  }
  const skipped: { n: number; key: Buffer }[] = [];
  let cur = ck;
  for (let i = fromN; i < targetN; i++) {
    skipped.push({ n: i, key: messageKey(cur) });
    cur = chainNext(cur);
  }
  return {
    messageKey: messageKey(cur),
    ck: chainNext(cur),
    nextN: targetN + 1,
    skipped,
  };
}

/**
 * Identifier for a ratchet public key, used to index skipped keys by the chain
 * they belong to. A skipped key is only meaningful together with the ratchet key
 * whose chain produced it: `n` repeats on every chain, so caching by `n` alone
 * would collide across steps and hand back a key from the wrong chain.
 *
 * A digest rather than the key itself because an HQC public key is 7237 bytes
 * and this ends up as a map key in persisted JSON on both sides.
 */
export function chainId(rkPub: Buffer): string {
  return crypto.createHash("sha256").update(rkPub).digest("hex").slice(0, 32);
}
