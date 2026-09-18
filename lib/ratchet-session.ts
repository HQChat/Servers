import {
  initRoot,
  rootStep,
  messageKey,
  chainNext,
  walkChain,
  chainId,
  MAX_SKIPPED,
  RATCHET_MAX_MESSAGES_PER_CHAIN,
  RATCHET_MIN_STEP_INTERVAL_MS,
} from "./double-ratchet";

/**
 * The double-ratchet state machine, driven over an injected KEM.
 *
 * Split from `double-ratchet.ts` so that module stays pure and pinnable by
 * cross-implementation vectors, and so this one can be tested with a stub KEM on
 * any platform — the real HQC library is a native .so built per architecture,
 * which is why `bot-crypto.test.ts` skips on an arm64 laptop today.
 *
 * ── The shape of a session ───────────────────────────────────────────────────
 * Roles are asymmetric only for the first message. The INITIATOR claims the
 * responder's prekeys, derives `root_0` plus its own first sending chain, and
 * sends `init`. The RESPONDER decapsulates, derives the same pair as its
 * receiving chain, and performs the first real ratchet step when it replies.
 * After that the two are interchangeable.
 *
 * ── What is deliberately NOT here ────────────────────────────────────────────
 * Nothing in this file authenticates the peer. That comes from `ssId` being
 * encapsulated to a TOFU-pinned identity key, decided by the caller. A session
 * built against an unpinned key is a session with whoever the server said.
 */

/** The KEM this ratchet rides on. HQC in production, a stub in tests. */
export interface Kem {
  generateKeypair(): { pk: Buffer; sk: Buffer };
  encapsulate(pk: Buffer): { ct: Buffer; ss: Buffer };
  decapsulate(sk: Buffer, ct: Buffer): Buffer;
}

/** One direction's symmetric chain. */
export interface Chain {
  ck: Buffer;
  /** Next index this chain will produce or expect. */
  n: number;
}

export interface SkippedKey {
  /** `chainId` of the ratchet key whose chain produced it. */
  chain: string;
  n: number;
  key: Buffer;
}

export interface SessionState {
  root: Buffer;
  /** My ratchet keypair. Peers encapsulate to `rkPub`; `rkSec` opens their step. */
  rkPub: Buffer;
  rkSec: Buffer;
  /** The peer's advertised ratchet key. Null until the initiator hears back. */
  peerRkPub: Buffer | null;
  send: Chain | null;
  recv: Chain | null;
  /** Length of the previous sending chain — the `pn` header field. */
  prevSendN: number;
  skipped: SkippedKey[];
  /**
   * The handshake header, carried on EVERY outbound frame until we hear back
   * from the peer. Absent on the responder side.
   *
   * Cleared on the first successful `open`, not on the first `seal`. Clearing it
   * when we send would lose it whenever the publish failed or the send was
   * retried — the retry would go out as a plain `msg` naming a session the peer
   * had never been told about, undeliverable forever with nothing to say why.
   * Receiving anything from them is the only proof they hold the session.
   *
   * The cost is that the handshake ciphertexts (~43 kB) repeat on each message
   * until they reply. That is the right trade: bounded by one reply, and the
   * alternative silently drops conversations.
   */
  pendingInit?: InitHeader;
  /**
   * Chains we have already stepped into, most recent last, bounded by
   * MAX_SEEN_CHAINS. Without this, a byte-identical REPLAY of a real stepping
   * frame is re-applied: `open` must process the header before the payload can
   * authenticate it, so the replay reaches the step logic with a ciphertext that
   * still decapsulates (our ratchet secret only rotates when WE send). It would
   * then recompute the root from the current root rather than the one that step
   * originally advanced, and the two sides diverge permanently — the same
   * failure class as TM-1.
   */
  seenChains: string[];
  /** Messages sent on the current sending chain, for the step policy. */
  sentOnChain: number;
  /** When the current sending chain started, for the step policy. */
  chainStartedAt: number;
}

/** The per-message header. Every field is bound as AEAD additional data. */
export interface MessageHeader {
  /**
   * `chainId` of the sender's CURRENT ratchet key. Present on every message,
   * including non-stepping ones, because `n` means nothing without the chain
   * that produced it: after a step, a bare frame from the sender's previous
   * chain would otherwise be read against the new one, yield the wrong key and
   * advance a chain it has no business touching.
   *
   * Signal solves this by putting the whole ratchet public key in every header.
   * Here that is 7237 bytes (~9.6 kB base64) per message, so the header carries
   * the 16-byte digest instead and the full key travels only on a step.
   */
  cid: string;
  /** Present only on a step: the sender's new ratchet public key. */
  rk?: Buffer;
  /** Present only on a step: encapsulated to the receiver's previous `rk`. */
  kemCt?: Buffer;
  n: number;
  pn: number;
}

/**
 * What the initiator must put in the `init` frame besides the sealed payload.
 *
 * No `n`/`pn`: those belong to the message header the init frame also carries,
 * and duplicating them here would be two places to disagree. Matches the Swift
 * `RatchetInitHeader` field for field.
 */
export interface InitHeader {
  ctId: Buffer;
  ctMt: Buffer;
  ctOt: Buffer | null;
  otId: number | null;
  rk: Buffer;
  /** `chainId(rk)`, so an init frame carries the same chain selector as a msg. */
  cid: string;
}

/** The peer's published bundle, as claimed from the directory. */
export interface PrekeyBundle {
  identityPk: Buffer;
  mediumPk: Buffer;
  /** Null when the peer's one-time pool was exhausted. */
  oneTimePk: Buffer | null;
  oneTimeId: number | null;
}

/** My own prekey secrets, needed to answer an `init`. */
export interface PrekeySecrets {
  identitySk: Buffer;
  mediumSk: Buffer;
  /** Looked up by the `otId` the initiator echoed back. */
  oneTimeSk(id: number): Buffer | null;
}

// ── Starting a session ───────────────────────────────────────────────────────

/**
 * Initiator side: derive `root_0` from the peer's bundle and open a sending
 * chain, so the very first message is already ratcheted and can be sent while
 * the peer is offline.
 *
 * Three encapsulations, each doing a different job:
 *   - to the pinned IDENTITY key: authenticates the peer. Without it, a server
 *     that substituted a prekey would be talking to us as them.
 *   - to the MEDIUM-term prekey: forward secrecy with a rotation-length window.
 *   - to a ONE-TIME prekey when one was available: forward secrecy that ends the
 *     moment the responder consumes it.
 */
export function startAsInitiator(kem: Kem, bundle: PrekeyBundle, now = Date.now()): {
  state: SessionState;
  header: InitHeader;
} {
  const id = kem.encapsulate(bundle.identityPk);
  const mt = kem.encapsulate(bundle.mediumPk);
  const ot = bundle.oneTimePk ? kem.encapsulate(bundle.oneTimePk) : null;

  const { root, chain } = initRoot(id.ss, mt.ss, ot?.ss);
  const mine = kem.generateKeypair();
  const header: InitHeader = {
    ctId: id.ct,
    ctMt: mt.ct,
    ctOt: ot?.ct ?? null,
    otId: bundle.oneTimeId,
    rk: mine.pk,
    cid: chainId(mine.pk),
  };

  return {
    state: {
      root,
      rkPub: mine.pk,
      rkSec: mine.sk,
      // Not the peer's prekey: that key is single-use and the responder may have
      // already dropped its secret. The peer advertises a real ratchet key on
      // its first reply, and only then can we step.
      peerRkPub: null,
      send: { ck: chain, n: 0 },
      recv: null,
      prevSendN: 0,
      skipped: [],
      seenChains: [],
      pendingInit: header,
      sentOnChain: 0,
      chainStartedAt: now,
    },
    header,
  };
}

/**
 * Responder side: rebuild the same root from an `init` frame and open the
 * matching receiving chain.
 *
 * Returns null when a ciphertext does not decapsulate — a forged or corrupt
 * frame, or an `otId` whose secret this device no longer holds (a duplicate
 * `init`, or one built on a key already consumed). A null must NOT tear down an
 * existing session: that is exactly how a replayed `init` would become a way to
 * reset someone's conversation.
 */
export function startAsResponder(
  kem: Kem,
  secrets: PrekeySecrets,
  header: InitHeader,
  now = Date.now()
): SessionState | null {
  try {
    const ssId = kem.decapsulate(secrets.identitySk, header.ctId);
    const ssMt = kem.decapsulate(secrets.mediumSk, header.ctMt);

    let ssOt: Buffer | undefined;
    if (header.ctOt) {
      // A one-time secret we no longer hold means this `init` cannot be answered
      // as sent. Failing here is right: deriving a root from two of the three
      // secrets would silently disagree with the initiator's three.
      if (header.otId === null) return null;
      const sk = secrets.oneTimeSk(header.otId);
      if (!sk) return null;
      ssOt = kem.decapsulate(sk, header.ctOt);
    }

    const { root, chain } = initRoot(ssId, ssMt, ssOt);
    const mine = kem.generateKeypair();

    return {
      root,
      rkPub: mine.pk,
      rkSec: mine.sk,
      peerRkPub: header.rk,
      send: null, // opened by the first step, taken when we reply
      recv: { ck: chain, n: 0 },
      prevSendN: 0,
      skipped: [],
      // The initiator's chain counts as entered: a replayed `init` must not be
      // able to re-derive it later as though it were a fresh step.
      seenChains: [chainId(header.rk)],
      // The responder answers, it does not initiate.
      sentOnChain: 0,
      chainStartedAt: now,
    };
  } catch {
    return null;
  }
}

// ── Sending ──────────────────────────────────────────────────────────────────

/**
 * Whether the next send should perform an asymmetric step.
 *
 * A step is only possible once the peer has advertised a ratchet key. Beyond
 * that it is a cost decision (see RATCHET_* in double-ratchet.ts): step when the
 * current chain has run long enough or lived long enough, and always when there
 * is no sending chain at all — which is the responder's first reply, the moment
 * the ratchet actually starts turning.
 */
export function shouldStep(state: SessionState, now = Date.now()): boolean {
  if (!state.peerRkPub) return false;
  if (!state.send) return true;
  // "used at least once" — the half of the documented policy that was never in
  // the code. A chain that has sent nothing has nothing to rotate away from, so
  // stepping off it spends ~29 kB to move from one unused chain to another.
  if (state.sentOnChain === 0) return false;
  if (state.sentOnChain >= RATCHET_MAX_MESSAGES_PER_CHAIN) return true;
  return now - state.chainStartedAt >= RATCHET_MIN_STEP_INTERVAL_MS;
}

/**
 * Take the next sending key, stepping the ratchet first when policy says to.
 * Mutates `state`; the returned header must travel with the ciphertext and be
 * bound as its AEAD additional data.
 */
export function seal(kem: Kem, state: SessionState, now = Date.now()): {
  key: Buffer;
  header: MessageHeader;
  /** Present until the peer answers — see `SessionState.pendingInit`. */
  initHeader?: InitHeader;
} {
  let stepped: { rk: Buffer; kemCt: Buffer } | undefined;

  if (shouldStep(state, now)) {
    const peerRk = state.peerRkPub!;
    const { ct, ss } = kem.encapsulate(peerRk);
    const next = rootStep(state.root, ss);

    // A fresh keypair per step is the point: the old secret is dropped, so a
    // later compromise cannot open the ciphertexts that named the old key.
    const mine = kem.generateKeypair();
    state.root = next.root;
    state.prevSendN = state.send?.n ?? 0;
    state.send = { ck: next.chain, n: 0 };
    state.rkPub = mine.pk;
    state.rkSec = mine.sk;
    state.sentOnChain = 0;
    state.chainStartedAt = now;
    stepped = { rk: mine.pk, kemCt: ct };
  }

  if (!state.send) {
    // Only reachable if a responder tries to send before it ever received, which
    // startAsResponder makes impossible — it always opens a recv chain and sets
    // peerRkPub, so shouldStep returns true above.
    throw new Error("seal: no sending chain and no peer ratchet key to step against");
  }

  const key = messageKey(state.send.ck);
  const header: MessageHeader = {
    // Always the sender's CURRENT chain, stepping or not — this is what lets the
    // receiver tell which chain `n` counts within.
    cid: chainId(state.rkPub),
    n: state.send.n,
    pn: state.prevSendN,
    ...(stepped ?? {}),
  };
  state.send.ck = chainNext(state.send.ck);
  state.send.n += 1;
  state.sentOnChain += 1;
  // Deliberately NOT cleared here — see `SessionState.pendingInit`.
  return { key, header, ...(state.pendingInit ? { initHeader: state.pendingInit } : {}) };
}

// ── Receiving ────────────────────────────────────────────────────────────────

/**
 * Index of a cached key, or -1. Deliberately does NOT remove it: the caller
 * consumes it only once the payload has authenticated, so a corrupt frame at a
 * skipped position cannot burn the key for the real message that belongs there.
 */
function findSkipped(state: SessionState, chain: string, n: number): number {
  return state.skipped.findIndex((s) => s.chain === chain && s.n === n);
}

/**
 * How many retired chains to remember for replay rejection. A step only lands if
 * its ciphertext still decapsulates under our CURRENT ratchet secret, and that
 * rotates every time we send a step — so a replay older than this is already
 * refused by the KEM. This list covers the window where it is not.
 */
const MAX_SEEN_CHAINS = 64;

function rememberChain(state: SessionState, cid: string) {
  state.seenChains.push(cid);
  if (state.seenChains.length > MAX_SEEN_CHAINS) {
    state.seenChains.splice(0, state.seenChains.length - MAX_SEEN_CHAINS);
  }
}

/**
 * Cache keys skipped on the way to a delivered one, bounded by MAX_SKIPPED.
 *
 * Deliberately still a linear array rather than a dictionary keyed on
 * "{chain}:{n}". The audit proposed the dictionary for O(1) lookup; measured, a
 * worst-case `findSkipped` over a FULL 2000-entry cache costs ~14 microseconds
 * per inbound frame, while JSON-encoding that same cache — which happens on
 * every save, and which an index does not help at all — costs ~392, twenty-eight
 * times more. So the index buys the small half of the win.
 *
 * It costs the persisted shape, which is not a fair trade: `skipped` is encoded
 * straight into the session state, a change there means bumping the state
 * version, and that version DELETES rather than migrates — with no recovery,
 * because a re-`init` from a peer who has heard from you is refused as a replay.
 * A 14-microsecond saving is not worth standing anywhere near that.
 */
function cacheSkipped(state: SessionState, chain: string, keys: { n: number; key: Buffer }[]) {
  for (const k of keys) state.skipped.push({ chain, n: k.n, key: k.key });
  // Oldest first — the cache is append-ordered, so the head is the least likely
  // to still be in flight.
  if (state.skipped.length > MAX_SKIPPED) {
    state.skipped.splice(0, state.skipped.length - MAX_SKIPPED);
  }
}

/**
 * Message key for an inbound header, or null if there is none to be had.
 *
 * `verify` is the AEAD open, and in this protocol it is the ONLY authenticator.
 * Nothing here writes to `state` until it has returned true.
 *
 * That is not defensive style, it is the fix for a specific failure. HQC uses
 * IMPLICIT REJECTION: `decapsulate` on a forged or corrupt ciphertext returns a
 * pseudo-random secret and no error (hqc.ts says so). So a fabricated step — a
 * random `rk` and 14421 random bytes as `kemCt` — reaches `rootStep` and
 * succeeds. When this function committed before the tag was checked, that one
 * frame replaced the root, adopted the sender's ratchet key and reset the
 * receive chain; the AEAD then failed, and both callers saved the mutated
 * session anyway. The two sides could never converge again, and no re-handshake
 * could rescue it — a fresh `init` is refused as a replay by anyone who has
 * heard from you. Any accepted friend could send that frame.
 *
 * The KEM cannot tell us a step was forged, and no amount of care here will
 * change that. The tag can. So the tag decides — and to make that impossible to
 * get wrong at a call site, this function performs the commit itself rather than
 * handing back a key and trusting four callers to be careful with it.
 *
 * A null is an ordinary outcome — a replay, a frame from a chain already
 * retired, a gap too large to bridge, or a payload that did not authenticate —
 * and must not be treated as an error the caller reports to the user.
 */
export function open(
  kem: Kem,
  state: SessionState,
  header: MessageHeader,
  verify: (key: Buffer) => boolean
): Buffer | null {
  if (!Number.isInteger(header.n) || header.n < 0) return null;
  if (!Number.isInteger(header.pn) || header.pn < 0) return null;
  if (typeof header.cid !== "string" || !/^[0-9a-f]{32}$/.test(header.cid)) return null;

  // A key cached while `cid`'s chain was current, for a message that arrived
  // late — including one from a chain since retired. This is checked first
  // precisely so a straggler resolves without touching any live state.
  //
  // Consumed only if it WORKS. Removing it before the tag check would let one
  // corrupt frame at a skipped position destroy the key for the real message
  // that position belongs to: the same "spend state on an unauthenticated
  // frame" mistake as the step branch below, on a much quieter path.
  const cachedIdx = findSkipped(state, header.cid, header.n);
  if (cachedIdx !== -1) {
    const key = state.skipped[cachedIdx]!.key;
    if (!verify(key)) return null;
    state.skipped.splice(cachedIdx, 1);
    return key;
  }

  const currentCid = state.peerRkPub ? chainId(state.peerRkPub) : null;

  // From here everything is computed into LOCALS. `state` is untouched until
  // `verify` has passed — see the note on this function.
  let root = state.root;
  let peerRkPub = state.peerRkPub;
  let recv = state.recv;
  /** Set on a step: the tail of the chain being retired, and which chain it is. */
  let tail: { cid: string; keys: { n: number; key: Buffer }[] } | null = null;
  /** Set on a step: the chain being entered, to remember once it is committed. */
  let enteredCid: string | null = null;

  if (header.cid !== currentCid) {
    // Not the chain we are on. The ONLY way to move is a well-formed step into a
    // chain we have never entered.
    if (!header.rk || !header.kemCt) return null;
    // `cid` must actually name the key it travels with, or the two selectors
    // could disagree and pick different chains on the two sides.
    if (chainId(header.rk) !== header.cid) return null;
    // Refuse to re-enter a retired chain. A byte-identical replay of a real
    // stepping frame still decapsulates — our ratchet secret only rotates when
    // WE send — so without this it would recompute the root from the CURRENT
    // root rather than the one that step originally advanced, and the two sides
    // would diverge for good.
    if (state.seenChains.includes(header.cid)) return null;

    let ss: Buffer;
    try {
      ss = kem.decapsulate(state.rkSec, header.kemCt);
    } catch {
      // A LENGTH mismatch, and nothing else. The wrappers throw on a wrong-sized
      // ciphertext and return a pseudo-random secret for every other bad input,
      // so reaching this line does not mean "forged" and never did.
      return null;
    }

    // Finish the chain we were on. `pn` says how long it ran, so anything we
    // never saw from it is cached rather than lost — the fine-grained version of
    // v1's one-epoch `prev` window.
    //
    // Computed BELOW the decapsulation and applied only past the `verify` gate,
    // because `pn` is attacker-chosen and `cacheSkipped` EVICTS. Run eagerly, a
    // repeated frame with a growing `pn` walks up to MAX_SKIPPED keys each time
    // and pushes out the keys for real messages still in flight — messages that
    // then never decrypt when they arrive. Retiring a chain is bookkeeping for a
    // step, and the step is exactly what has not been established yet.
    if (recv && currentCid) {
      const remaining = header.pn - recv.n;
      if (remaining > 0 && remaining <= MAX_SKIPPED) {
        const walked = walkChain(recv.ck, recv.n, header.pn - 1);
        tail = {
          cid: currentCid,
          keys: [...walked.skipped, { n: header.pn - 1, key: walked.messageKey }],
        };
      }
    }

    const next = rootStep(root, ss);
    root = next.root;
    peerRkPub = header.rk;
    recv = { ck: next.chain, n: 0 };
    enteredCid = header.cid;
  }

  if (!recv) return null;
  if (header.n < recv.n) return null; // consumed already, and not cached

  let walk: ChainWalkResult;
  try {
    walk = walkChain(recv.ck, recv.n, header.n);
  } catch {
    return null; // gap past MAX_SKIPPED — refused without walking it
  }

  // The sole authenticator. Everything above this line was a candidate.
  if (!verify(walk.messageKey)) return null;

  // ── Commit ─────────────────────────────────────────────────────────────────
  if (enteredCid) {
    state.root = root;
    state.peerRkPub = peerRkPub;
    if (tail) cacheSkipped(state, tail.cid, tail.keys);
    rememberChain(state, enteredCid);
  }
  cacheSkipped(state, header.cid, walk.skipped);
  state.recv = { ck: walk.ck, n: walk.nextN };
  // Hearing from them is the proof they hold the session, so the handshake no
  // longer needs to ride every frame.
  delete state.pendingInit;
  return walk.messageKey;
}

type ChainWalkResult = ReturnType<typeof walkChain>;

/** Re-export so callers need only this module. */
export { chainId, MAX_SKIPPED, RATCHET_MAX_MESSAGES_PER_CHAIN, RATCHET_MIN_STEP_INTERVAL_MS };
