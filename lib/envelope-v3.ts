/**
 * The v3 client↔client wire format: length-prefixed binary, with the canonical
 * header as the frame's own prefix.
 *
 * ── Why a second format at all ───────────────────────────────────────────────
 * v2 is JSON carrying base64. That costs exactly the 33% you would expect, and
 * it lands on the frames that already hurt: roughly 24 kB of every 82 kB `init`
 * is encoding rather than protocol. A stepping `msg` is 28,880 characters for
 * 21,658 bytes of key material.
 *
 * But the size was never the strongest argument. The AAD is the thing that has
 * to agree byte-for-byte between a Swift client and a TypeScript bot, and in v2
 * it is a SECOND construction — a netstring encoding of a fixed field order,
 * written twice by hand, next to a JSON encoding written by two different
 * libraries. Keeping those two in step is unpaid work forever, and the ways they
 * can drift are not obvious: the differential fuzzer's first run against v2
 * found duplicate-key disagreement, unpaired surrogates, grapheme-vs-byte length
 * counting and wrong-typed optionals, none of which any test had caught.
 *
 * Here the header IS the frame prefix. The AAD is a byte range of the thing that
 * arrived — `frame.subarray(0, headerLength)` — so there is nothing to keep in
 * step and no second encoding to disagree about. That is the real reason for
 * this file; the third off the wire is a bonus.
 *
 * ── What is bound that was not ───────────────────────────────────────────────
 * `v` — the version is inside the header, so an attacker cannot flip a client
 * between two formats without breaking the tag. In v2 it rode entirely outside
 * the AAD, which was inert only because no second version existed. The moment
 * one does, that is a downgrade.
 *
 * `to` — the recipient's client id. A v2 frame says who it is FROM and never who
 * it is for, which is why the client had to be taught to check the topic it
 * arrived on. This is the durable form of that check: cryptographic rather than
 * transport-level.
 *
 * ── Layout ───────────────────────────────────────────────────────────────────
 * All integers big-endian. The header runs from byte 0 to the start of the
 * payload length, and that whole span is the AAD.
 *
 *   0   magic     4 bytes   "HQCE"
 *   4   version   u8        3
 *   5   kind      u8        0 = msg, 1 = init
 *   6   flags     u8        bit0 rk, bit1 kemCt, bit2 one-time (ctOt+otId)
 *   7   sender    32 bytes  the client id, RAW — v2 spent 64 characters on hex
 *   39  to        32 bytes  the recipient's client id, raw
 *   71  cid       16 bytes  the chain selector, raw — v2 spent 32 on hex
 *   87  n         u32
 *   91  pn        u32
 *   95  msgIdLen  u8        1..128
 *   96  msgId     msgIdLen bytes, UTF-8
 *       [rk]      u32 len + rk
 *       [kemCt]   u32 len + kemCt
 *       [init]    u32 len + senderPk, u32 len + ctId, u32 len + ctMt
 *       [oneTime] u32 len + ctOt, u32 otId
 *   --- header ends here; everything above is the AAD ---
 *       payload   u32 len + bytes
 *
 * Every variable field is length-prefixed rather than fixed at the HQC sizes.
 * Four bytes per blob is nothing beside a 14421-byte ciphertext, and it means a
 * KEM change is not also a framing change.
 */

import { keyMatchesId, PEER_ID_RE } from "./identity";
/**
 * What a frame IS: the opening of a session, or a message inside one.
 *
 * It lived in `envelope.ts` with the v2 codec and moved here when that file was
 * deleted — the kind is a property of the protocol, not of a wire format, and it
 * outlived the format that happened to host it.
 */
export type EnvelopeKind = "init" | "msg";

/** Frame kinds, as they appear on the wire. */
const KIND_MSG = 0;
const KIND_INIT = 1;

const MAGIC = Buffer.from("HQCE", "ascii");
export const V3_VERSION = 3;

/**
 * `rk` and `kemCt` get INDEPENDENT bits, which is the one place this format
 * deliberately refuses to copy v2.
 *
 * A `msg` carries both or neither: a ratchet key with no ciphertext is not
 * something a receiver can act on, and a ciphertext with no key names no chain.
 * An `init` carries `rk` alone — it advertises the initiator's first chain, and
 * there is no peer ratchet key to encapsulate against, so `kemCt` is meaningless
 * on one. v2 could only express that by TOLERATING a field it did not use, and
 * the two implementations then disagreed about whether the pairing rule applied
 * to an init: the bot omitted `kemCt`, the TypeScript parser demanded it, and
 * every e2e conversation failed with the frame dropped at parse. Separate bits
 * make the rule a property of the format instead of a convention.
 */
const FLAG_RK = 0x01;
const FLAG_KEMCT = 0x02;
const FLAG_ONE_TIME = 0x04;
const ALL_FLAGS = FLAG_RK | FLAG_KEMCT | FLAG_ONE_TIME;

/** Byte offsets of the fixed part, so the reader and the writer cannot drift. */
const OFF_VERSION = 4;
const OFF_KIND = 5;
const OFF_FLAGS = 6;
const OFF_SENDER = 7;
const OFF_TO = 39;
const OFF_CID = 71;
const OFF_N = 87;
const OFF_PN = 91;
const OFF_MSGID_LEN = 95;
const OFF_MSGID = 96;

const ID_BYTES = 32;
const CID_BYTES = 16;
const MAX_MSGID_BYTES = 128;

/**
 * Guards against a length prefix that claims more than could possibly be there.
 * Not a size policy — the transport has one of those — just a bound that keeps a
 * hostile prefix from being read as an allocation request.
 */
const MAX_FIELD_BYTES = 1 << 20;

/**
 * The largest counter this format carries. Four bytes, where v2 admitted any
 * safe integer — so `isIndex` in envelope.ts is tightened to match rather than
 * this being widened. Nothing legitimate approaches either bound: chains rotate
 * every 32 messages, so `n` stays small, and one range across both versions is
 * what the frame seam claims to provide.
 */
export const V3_MAX_COUNTER = 0xffffffff;

/**
 * A decoded frame.
 *
 * The field names were chosen to match v2's so that the ratchet, the router and
 * the bot never learned which version had delivered them — the difference lived
 * entirely in this file and its Swift twin. That worked: when v2 was deleted,
 * nothing above `lib/frame.ts` changed at all.
 *
 * Binary fields are Buffers here rather than base64 strings — that is the whole
 * point — and the callers that need text (`sender`, `cid`) get it as hex,
 * because that is what `peerId`, `chainId` and every stored digest already use.
 */
export interface EnvelopeV3 {
  v: 3;
  t: EnvelopeKind;
  /** Lowercase hex, 64 chars — decoded from the 32 raw bytes on the wire. */
  sender: string;
  /** Lowercase hex, 64 chars. The field v2 has no equivalent of. */
  to: string;
  msgId: string;
  /** Lowercase hex, 32 chars. */
  cid: string;
  n: number;
  pn: number;
  rk?: Buffer;
  kemCt?: Buffer;
  ctId?: Buffer;
  ctMt?: Buffer;
  ctOt?: Buffer;
  otId?: number;
  /** The initiator's full public key, raw. v2 carried this as 14,474 hex
   *  characters for 7,237 bytes; `keyMatchesId` still hashes the hex TEXT, so
   *  the conversion happens on arrival rather than on the wire. */
  senderPk?: Buffer;
  payload: Buffer;
}

// ── Writing ──────────────────────────────────────────────────────────────────

function u32(value: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value, 0);
  return b;
}

/** A length-prefixed blob. */
function blob(b: Buffer): Buffer {
  return Buffer.concat([u32(b.length), b]);
}

/** Exactly `bytes` bytes of lowercase hex, and nothing else. */
function isHexOfWidth(value: unknown, bytes: number): value is string {
  return typeof value === "string"
    && value.length === bytes * 2
    && /^[0-9a-f]+$/.test(value);
}

/** A counter this format can actually carry. See `V3_MAX_COUNTER`. */
function isCounter(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value)
    && value >= 0 && value <= V3_MAX_COUNTER;
}

/**
 * Why an encoder validates at all.
 *
 * It used to validate nothing, and the two implementations then disagreed about
 * every malformed input — because they fail in structurally different ways.
 * TypeScript builds a fixed `Buffer.alloc` and `.copy()`s into it, so a short
 * field silently leaves zeros and a long one is clipped; Swift appends
 * variable-length `Data`, so a wrong-length field SHIFTS every field after it
 * and the frame comes out a different size. `writeUInt32BE` throws where
 * `UInt32(truncatingIfNeeded:)` silently wraps.
 *
 * Same struct in, different bytes out — the exact class v3 exists to remove,
 * in the half the differential fuzzer was not pointed at. So: refuse, rather
 * than pad, clip, wrap or throw. A caller that cannot produce a well-formed
 * frame should learn that from a null, not from a frame nobody can place.
 *
 * The reachable case was not hypothetical. `sealMessage` reads `myID` and
 * `friend.peerID` and guards neither; both are empty in ordinary states (no
 * profile loaded, a contact an invite created before a directory sync filled it
 * in). On v2 that produced a frame the receiver rejected. On v3 it produced a
 * perfectly well-formed frame naming client 0000…0000.
 */
export function validateV3(env: Omit<EnvelopeV3, "payload">): string | null {
  if (!isHexOfWidth(env.sender, ID_BYTES)) return "sender is not a client id";
  if (!isHexOfWidth(env.to, ID_BYTES)) return "to is not a client id";
  if (!isHexOfWidth(env.cid, CID_BYTES)) return "cid is not a chain selector";
  if (!isCounter(env.n)) return "n is not a u32";
  if (!isCounter(env.pn)) return "pn is not a u32";

  const msgIdBytes = Buffer.byteLength(env.msgId ?? "", "utf8");
  if (msgIdBytes === 0 || msgIdBytes > MAX_MSGID_BYTES) return "msgId is empty or over 128 bytes";

  // Present-but-empty is refused for the same reason the decoder refuses it: a
  // zero-length blob is a field the sender believed in and the receiver cannot
  // use.
  for (const [name, value] of Object.entries({
    rk: env.rk, kemCt: env.kemCt, ctId: env.ctId, ctMt: env.ctMt,
    ctOt: env.ctOt, senderPk: env.senderPk,
  })) {
    if (value !== undefined && value.length === 0) return `${name} is present but empty`;
    if (value !== undefined && value.length > MAX_FIELD_BYTES) return `${name} is implausibly large`;
  }
  if (env.otId !== undefined && !isCounter(env.otId)) return "otId is not a u32";

  // The pairing rules, applied on the way OUT as well as the way in — an
  // encoder that can emit a frame its own decoder refuses is not much of a
  // contract.
  if (env.t === "msg" && (env.rk === undefined) !== (env.kemCt === undefined)) {
    return "a msg carries rk and kemCt together or not at all";
  }
  if (env.t === "init") {
    if (env.rk === undefined) return "an init must advertise rk";
    if (env.kemCt !== undefined) return "an init must not carry a kemCt";
    if (env.senderPk === undefined) return "an init must carry senderPk";
    if (env.ctId === undefined || env.ctMt === undefined) return "an init needs ctId and ctMt";
    if (!keyMatchesId(env.senderPk.toString("hex"), env.sender)) {
      return "senderPk does not hash to sender";
    }
  }
  if ((env.ctOt === undefined) !== (env.otId === undefined)) {
    return "ctOt and otId travel together or not at all";
  }
  return null;
}

/**
 * The bytes both peers must bind as AAD, and the prefix of the frame itself.
 *
 * There is deliberately no separate "canonical encoding" here. `encodeV3`
 * returns this buffer with a payload appended, and `decodeV3` reports where it
 * ended — so the AAD a receiver binds is the actual bytes it received, not a
 * reconstruction that could differ.
 *
 * Null when the fields cannot make a well-formed frame. See `validateV3`.
 */
export function canonicalHeaderV3(env: Omit<EnvelopeV3, "payload">): Buffer | null {
  if (validateV3(env) !== null) return null;

  const sender = Buffer.from(env.sender, "hex");
  const to = Buffer.from(env.to, "hex");
  const cid = Buffer.from(env.cid, "hex");
  const msgId = Buffer.from(env.msgId, "utf8");

  const hasRk = env.rk !== undefined;
  const hasKemCt = env.kemCt !== undefined;
  const hasOneTime = env.ctOt !== undefined && env.otId !== undefined;

  const fixed = Buffer.alloc(OFF_MSGID);
  MAGIC.copy(fixed, 0);
  fixed.writeUInt8(V3_VERSION, OFF_VERSION);
  fixed.writeUInt8(env.t === "init" ? KIND_INIT : KIND_MSG, OFF_KIND);
  fixed.writeUInt8(
    (hasRk ? FLAG_RK : 0) | (hasKemCt ? FLAG_KEMCT : 0) | (hasOneTime ? FLAG_ONE_TIME : 0),
    OFF_FLAGS
  );
  sender.copy(fixed, OFF_SENDER);
  to.copy(fixed, OFF_TO);
  cid.copy(fixed, OFF_CID);
  fixed.writeUInt32BE(env.n, OFF_N);
  fixed.writeUInt32BE(env.pn, OFF_PN);
  fixed.writeUInt8(msgId.length, OFF_MSGID_LEN);

  const parts: Buffer[] = [fixed, msgId];
  if (hasRk) parts.push(blob(env.rk!));
  if (hasKemCt) parts.push(blob(env.kemCt!));
  if (env.t === "init") parts.push(blob(env.senderPk!), blob(env.ctId!), blob(env.ctMt!));
  if (hasOneTime) parts.push(blob(env.ctOt!), u32(env.otId!));
  return Buffer.concat(parts);
}

/** Header + payload. The complete frame, or null when it would not be one. */
export function encodeV3(env: EnvelopeV3): Buffer | null {
  if (env.payload === undefined || env.payload.length === 0) return null;
  if (env.payload.length > MAX_FIELD_BYTES) return null;
  const header = canonicalHeaderV3(env);
  return header === null ? null : Buffer.concat([header, blob(env.payload)]);
}

// ── Reading ──────────────────────────────────────────────────────────────────

/** Whether these bytes even claim to be a v3 frame. Cheap, and total. */
export function looksLikeV3(raw: Buffer): boolean {
  return raw.length >= OFF_MSGID && raw.subarray(0, 4).equals(MAGIC)
    && raw.readUInt8(OFF_VERSION) === V3_VERSION;
}

/**
 * Decode a frame, or null.
 *
 * Returns the AAD alongside the envelope, as the exact byte range that arrived.
 * A caller cannot get this wrong by rebuilding it — which is the failure v2's
 * parallel canonical encoding invites, and the reason it is returned rather
 * than recomputed.
 */
export function decodeV3(raw: Buffer): { env: EnvelopeV3; aad: Buffer } | null {
  if (!looksLikeV3(raw)) return null;

  const kindByte = raw.readUInt8(OFF_KIND);
  if (kindByte !== KIND_MSG && kindByte !== KIND_INIT) return null;
  const t: EnvelopeKind = kindByte === KIND_INIT ? "init" : "msg";

  const flags = raw.readUInt8(OFF_FLAGS);
  // Unknown flag bits are refused rather than ignored: a bit this build does not
  // understand changes what the sender thinks it sent, and the tag would still
  // verify because the flags byte is inside the AAD.
  if (flags & ~ALL_FLAGS) return null;
  const hasRk = (flags & FLAG_RK) !== 0;
  const hasKemCt = (flags & FLAG_KEMCT) !== 0;
  const hasOneTime = (flags & FLAG_ONE_TIME) !== 0;

  // The pairing rule, as a property of the format rather than a convention.
  if (t === "msg" && hasRk !== hasKemCt) return null;
  // An init advertises its chain in `rk` and has nothing to encapsulate against,
  // so a `kemCt` on one is a field the sender believed in and the receiver would
  // ignore. Refused, not tolerated.
  if (t === "init" && (!hasRk || hasKemCt)) return null;

  const msgIdLen = raw.readUInt8(OFF_MSGID_LEN);
  if (msgIdLen === 0 || msgIdLen > MAX_MSGID_BYTES) return null;
  let cursor = OFF_MSGID + msgIdLen;
  if (raw.length < cursor) return null;

  const msgIdBytes = raw.subarray(OFF_MSGID, cursor);
  // Refused rather than replaced. `toString("utf8")` substitutes U+FFFD for
  // anything invalid, which would silently change the bytes the AAD covers — the
  // same class as v2's unpaired surrogates, arriving by a different door.
  const msgId = msgIdBytes.toString("utf8");
  if (!Buffer.from(msgId, "utf8").equals(msgIdBytes)) return null;

  /** Read a length-prefixed blob at the cursor, advancing it. */
  const readBlob = (): Buffer | null => {
    if (raw.length < cursor + 4) return null;
    const len = raw.readUInt32BE(cursor);
    if (len > MAX_FIELD_BYTES) return null;
    cursor += 4;
    if (raw.length < cursor + len) return null;
    const out = raw.subarray(cursor, cursor + len);
    cursor += len;
    return out;
  };

  let rk: Buffer | undefined;
  if (hasRk) {
    const a = readBlob();
    if (a === null || a.length === 0) return null;
    rk = a;
  }
  let kemCt: Buffer | undefined;
  if (hasKemCt) {
    const a = readBlob();
    if (a === null || a.length === 0) return null;
    kemCt = a;
  }

  let senderPk: Buffer | undefined;
  let ctId: Buffer | undefined;
  let ctMt: Buffer | undefined;
  if (t === "init") {
    const a = readBlob();
    const b = a === null ? null : readBlob();
    const c = b === null ? null : readBlob();
    if (a === null || b === null || c === null) return null;
    if (a.length === 0 || b.length === 0 || c.length === 0) return null;
    senderPk = a;
    ctId = b;
    ctMt = c;
  }

  let ctOt: Buffer | undefined;
  let otId: number | undefined;
  if (hasOneTime) {
    const a = readBlob();
    if (a === null || a.length === 0) return null;
    if (raw.length < cursor + 4) return null;
    ctOt = a;
    otId = raw.readUInt32BE(cursor);
    cursor += 4;
  }

  // Everything up to here is the header, and the header is the AAD.
  const headerEnd = cursor;
  const payload = readBlob();
  if (payload === null || payload.length === 0) return null;
  // Trailing bytes are refused. A frame with something after the payload is a
  // frame two implementations could disagree about, and nothing legitimate
  // produces one.
  if (cursor !== raw.length) return null;

  const sender = raw.subarray(OFF_SENDER, OFF_SENDER + ID_BYTES).toString("hex");
  const to = raw.subarray(OFF_TO, OFF_TO + ID_BYTES).toString("hex");
  const cid = raw.subarray(OFF_CID, OFF_CID + CID_BYTES).toString("hex");
  // Belt and braces: these are hex OF raw bytes, so they cannot fail the shape
  // check — but the shape is what the rest of the system relies on, and asserting
  // it here costs nothing.
  if (!PEER_ID_RE.test(sender) || !PEER_ID_RE.test(to)) return null;

  // An `init` must carry the key its `sender` id names. This is the check that
  // makes the id a commitment rather than a label, and it is the one place a
  // frame from an unknown peer introduces a key.
  if (t === "init" && !keyMatchesId(senderPk!.toString("hex"), sender)) return null;

  const env: EnvelopeV3 = {
    v: 3,
    t,
    sender,
    to,
    msgId,
    cid,
    n: raw.readUInt32BE(OFF_N),
    pn: raw.readUInt32BE(OFF_PN),
    payload: Buffer.from(payload),
    ...(rk ? { rk: Buffer.from(rk) } : {}),
    ...(kemCt ? { kemCt: Buffer.from(kemCt) } : {}),
    ...(ctId ? { ctId: Buffer.from(ctId) } : {}),
    ...(ctMt ? { ctMt: Buffer.from(ctMt) } : {}),
    ...(ctOt ? { ctOt: Buffer.from(ctOt) } : {}),
    ...(otId !== undefined ? { otId } : {}),
    ...(senderPk ? { senderPk: Buffer.from(senderPk) } : {}),
  };
  return { env, aad: Buffer.from(raw.subarray(0, headerEnd)) };
}
