/**
 * One frame — the name the rest of the system uses for a conversation message.
 *
 * ── WHAT THIS FILE USED TO BE ───────────────────────────────────────────────
 * A version seam. Two wire formats existed, v2 (JSON with base64 fields and a
 * second, parallel canonical encoding for the AAD) and v3 (length-prefixed
 * binary whose canonical header IS the frame's own prefix), and this file
 * confined the disagreement so that the ratchet, the router and the bot saw one
 * shape. v2 is gone, so the disagreement is gone, and what is left is a name.
 *
 * ── WHY IT SURVIVES THE FORMAT IT RECONCILED ────────────────────────────────
 * Honestly: mostly as the name. `Frame` is what a hundred call sites say, and
 * `lib/envelope-v3.ts` is the CODEC — the thing that knows about magic bytes,
 * offsets and blob framing. Keeping the two words apart keeps "a message in a
 * conversation" separable from "how one is spelled on the wire", which is the
 * distinction that made adding v3 possible without touching the ratchet at all.
 *
 * So this is deliberately thin, and says so rather than implying it still
 * reconciles anything. If a v4 is ever wanted, the seam reappears exactly here,
 * and the shape of the work is already written down in git.
 *
 * ── Sending ─────────────────────────────────────────────────────────────────
 * The payload is sealed AGAINST the header, so the header has to exist first:
 *
 *     const aad = frameHeader(fields);
 *     const payload = aesEncrypt(text, key, aad);
 *     const bytes = encodeFrame({ ...fields, payload });
 *
 * `encodeFrame` re-derives the same header, so the two cannot drift.
 */

import {
  EnvelopeV3,
  canonicalHeaderV3,
  decodeV3,
  encodeV3,
  validateV3,
} from "./envelope-v3";

export type { EnvelopeKind } from "./envelope-v3";

/**
 * A frame. Every binary field is bytes, never base64.
 *
 * Identical to `EnvelopeV3` and declared as an alias rather than re-typed, so
 * the two cannot drift into disagreeing about a field. `to` is required and `v`
 * is the literal 3: under v2 both were optional-ish, because a v2 frame said who
 * it was from and never who it was for — which is the whole reason a v2 receiver
 * had to fall back on checking the topic a frame arrived on.
 */
export type Frame = EnvelopeV3;

/**
 * Why a frame is checked on the way OUT.
 *
 * The v3 encoders used to validate nothing and disagreed on every malformed
 * input, because they fail in structurally different ways — a fixed buffer
 * copied into versus variable-length data appended. That is finding 02, and
 * `validateV3` closes it inside the encoder.
 *
 * The reachable case is ordinary: `sealMessage` reads `myID` and
 * `friend.peerID` and guards neither, and both are empty in ordinary states.
 */
export function validateFrame(f: Omit<Frame, "payload">): string | null {
  return validateV3(f);
}

/**
 * The bytes to bind as AAD for a frame being SENT, or null when these fields
 * cannot make a well-formed frame.
 *
 * `payload` is deliberately not a parameter: it is the thing being
 * authenticated, and it does not exist yet when this is called.
 */
export function frameHeader(f: Omit<Frame, "payload">): Buffer | null {
  return canonicalHeaderV3(f);
}

/** The complete frame ready to publish, or null when it would not be one. */
export function encodeFrame(f: Frame): Buffer | null {
  return encodeV3(f);
}

/**
 * Decode a frame, with the AAD it must be opened against.
 *
 * The AAD is the literal byte range that arrived — the header IS the frame
 * prefix — so a receiver binds what it was sent rather than a reconstruction.
 * That asymmetry is what v3 was for: v2 had to rebuild its header from parsed
 * fields, and a rebuild is a second construction that can differ from the first.
 *
 * There is nothing to discriminate any more. `decodeV3` refuses anything that is
 * not a well-formed v3 frame, starting with the magic and the version byte, and
 * a frame that fails there is simply not one — not "might be the older format".
 */
export function decodeFrame(raw: Buffer): { frame: Frame; aad: Buffer } | null {
  const got = decodeV3(raw);
  return got === null ? null : { frame: got.env, aad: got.aad };
}
