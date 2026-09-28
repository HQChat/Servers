import * as net from "net";
import {
  HqnResponder,
  FrameReader,
  NoiseError,
  frame,
  sealFrames,
  msg1Length,
  HQN_VERSION,
  type ServerStatic,
  type Transport,
} from "../lib/noise";
import { connectClientId } from "./mqtt-connect";

/**
 * noise-gw: terminates hqn/1 (lib/noise.ts) and pipes the decrypted MQTT byte
 * stream to EMQX's internal plain-TCP listener.
 *
 * This process is the first thing on the public internet that reads a raw-TCP
 * client's bytes, before any authentication, so everything here is shaped by
 * what an attacker can make it do:
 *
 *   - Nothing is buffered beyond one message. The opening is two header bytes,
 *     then ONE length-prefixed msg1 whose length must fall in the window a real
 *     CONNECT can produce; anything else is closed before any cryptography.
 *   - The expensive step — HQC-256 decapsulation — is reached only by a msg1
 *     whose encrypted KEM ciphertext already OPENED under the X25519 key. Random
 *     bytes fail that AEAD tag for the price of one X25519 and never cost a
 *     decapsulation. (A real Noise client can still spend one decapsulation per
 *     handshake; that is what the per-IP handshake rate is for.)
 *   - Decapsulation runs off the event loop (`decapsulate` is async; main.ts
 *     backs it with a worker pool) behind a bounded queue, so a burst of
 *     well-formed handshakes sheds load instead of stalling every established
 *     stream on this process.
 *   - Every failure is a silent close. No error frame, no timing difference
 *     worth measuring, nothing that tells a prober which check it failed.
 *   - A msg1 whose ephemeral key was seen within the replay window is refused.
 *     It cannot yield a session (msg2 is keyed by ee), but it would forward a
 *     CONNECT — which the v1 proof's single-use nonce also refuses. Two locks.
 */

export interface GatewayOptions {
  /** Loaded server key pairs, by key id. */
  keys: Map<number, ServerStatic>;
  /** HQC-256 decapsulation, off the event loop. Rejects when overloaded. */
  decapsulate: (keyId: number, ct: Buffer) => Promise<Buffer>;
  /** Where the decrypted stream goes: EMQX's internal plain-TCP listener. */
  upstream: { host: string; port: number };
  limits?: Partial<GatewayLimits>;
  /** Clock, for the rate windows. */
  now?: () => number;
  /** Observability hook; never passed secrets. */
  onEvent?: (e: GatewayEvent) => void;
}

export interface GatewayLimits {
  /** Largest CONNECT accepted inside msg1. A real one is well under 1 kB. */
  maxConnectBytes: number;
  /** Time from accept to a complete msg1. */
  handshakeTimeoutMs: number;
  /** Handshakes in progress from one address. */
  perIpHandshakes: number;
  /** Established streams from one address — high, because carrier NAT puts
   *  thousands of phones behind one IPv4 address. */
  perIpConnections: number;
  /** Handshakes STARTED per address per minute (each may cost a decapsulation). */
  perIpHandshakesPerMinute: number;
  /** Handshakes in progress across the whole process. */
  maxHalfOpen: number;
  /** How long a client ephemeral key is remembered for replay refusal. */
  replayWindowMs: number;
  /** Cap on remembered ephemerals, so the cache cannot be grown without bound. */
  replayCacheMax: number;
}

export const DEFAULT_LIMITS: GatewayLimits = {
  maxConnectBytes: 4096,
  handshakeTimeoutMs: 5000,
  perIpHandshakes: 8,
  perIpConnections: 512,
  perIpHandshakesPerMinute: 120,
  maxHalfOpen: 1024,
  replayWindowMs: 120_000,
  replayCacheMax: 200_000,
};

export type GatewayEvent =
  | { t: "refused"; reason: RefusalReason; ip: string }
  | { t: "established"; ip: string; clientId: string | null; handshakeMs: number }
  | { t: "closed"; ip: string; clientId: string | null; bytesUp: number; bytesDown: number };

export type RefusalReason =
  | "header" | "length" | "timeout" | "ip-handshakes" | "ip-rate" | "ip-connections"
  | "half-open" | "replay" | "noise" | "overloaded" | "upstream" | "stream";

export interface GatewayStats {
  halfOpen: number;
  established: number;
  refused: Record<RefusalReason, number>;
  replayCacheSize: number;
}

export function createGateway(opts: GatewayOptions): { server: net.Server; stats: () => GatewayStats } {
  const L: GatewayLimits = { ...DEFAULT_LIMITS, ...(opts.limits ?? {}) };
  const now = opts.now ?? Date.now;
  const minMsg1 = msg1Length(0);
  const maxMsg1 = msg1Length(L.maxConnectBytes);

  let halfOpen = 0;
  let established = 0;
  const refused = {} as Record<RefusalReason, number>;
  const handshakesByIp = new Map<string, number>();
  const connectionsByIp = new Map<string, number>();
  const rateByIp = new Map<string, { windowStart: number; count: number }>();
  const seenEphemerals = new Map<string, number>();   // hex → expiry

  const bump = (m: Map<string, number>, ip: string, d: number) => {
    const n = (m.get(ip) ?? 0) + d;
    if (n <= 0) m.delete(ip); else m.set(ip, n);
  };

  function refuse(sock: net.Socket, ip: string, reason: RefusalReason) {
    refused[reason] = (refused[reason] ?? 0) + 1;
    opts.onEvent?.({ t: "refused", reason, ip });
    sock.destroy();
  }

  /** True if this ephemeral is fresh; records it. Expired entries are swept
   *  opportunistically, oldest first (Map preserves insertion order). */
  function freshEphemeral(e: Buffer): boolean {
    const t = now();
    for (const [k, exp] of seenEphemerals) {
      if (exp > t && seenEphemerals.size < L.replayCacheMax) break;
      seenEphemerals.delete(k);
    }
    const key = e.toString("hex");
    const exp = seenEphemerals.get(key);
    if (exp !== undefined && exp > t) return false;
    seenEphemerals.set(key, t + L.replayWindowMs);
    return true;
  }

  function rateOk(ip: string): boolean {
    const t = now();
    const r = rateByIp.get(ip);
    if (!r || t - r.windowStart >= 60_000) {
      rateByIp.set(ip, { windowStart: t, count: 1 });
      if (rateByIp.size > 100_000) {
        for (const [k, v] of rateByIp) { if (t - v.windowStart >= 60_000) rateByIp.delete(k); else break; }
      }
      return true;
    }
    r.count++;
    return r.count <= L.perIpHandshakesPerMinute;
  }

  const server = net.createServer({ noDelay: true, pauseOnConnect: false }, (sock) => {
    const ip = sock.remoteAddress ?? "?";
    const started = now();

    if (halfOpen >= L.maxHalfOpen) return refuse(sock, ip, "half-open");
    if ((handshakesByIp.get(ip) ?? 0) >= L.perIpHandshakes) return refuse(sock, ip, "ip-handshakes");
    if ((connectionsByIp.get(ip) ?? 0) >= L.perIpConnections) return refuse(sock, ip, "ip-connections");
    if (!rateOk(ip)) return refuse(sock, ip, "ip-rate");

    halfOpen++;
    bump(handshakesByIp, ip, 1);
    let inHandshake = true;
    const leaveHandshake = () => {
      if (!inHandshake) return;
      inHandshake = false;
      halfOpen--;
      bump(handshakesByIp, ip, -1);
    };
    sock.once("close", leaveHandshake);
    sock.on("error", () => { /* a reset client is not an event worth logging */ });

    const timer = setTimeout(() => refuse(sock, ip, "timeout"), L.handshakeTimeoutMs);
    sock.once("close", () => clearTimeout(timer));

    // ── Phase 1: header + msg1, buffered up to exactly one message ──────────
    let buf: Buffer = Buffer.alloc(0);
    let keyId = -1;
    let need = 2;            // header first
    const onData = (chunk: Buffer) => {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      if (keyId < 0) {
        if (buf.length < 2) return;
        if (buf[0] !== HQN_VERSION || !opts.keys.has(buf[1]!)) return refuse(sock, ip, "header");
        keyId = buf[1]!;
        buf = buf.subarray(2);
        need = 2;
      }
      if (need === 2) {
        if (buf.length < 2) return;
        const len = buf.readUInt16BE(0);
        if (len < minMsg1 || len > maxMsg1) return refuse(sock, ip, "length");
        need = 2 + len;
      }
      if (buf.length > need) return refuse(sock, ip, "length");   // nothing may follow msg1 before msg2
      if (buf.length < need) return;
      sock.off("data", onData);
      sock.pause();
      void handshake(buf.subarray(2));
    };
    sock.on("data", onData);

    // ── Phase 2: open the KEM ciphertext, decapsulate off-loop, finish ──────
    async function handshake(msg1: Buffer) {
      const key = opts.keys.get(keyId)!;
      if (!freshEphemeral(HqnResponder.ephemeralOf(msg1))) return refuse(sock, ip, "replay");
      const responder = new HqnResponder(key);
      let ct: Buffer;
      try {
        ct = responder.openMessage1(msg1);
      } catch {
        return refuse(sock, ip, "noise");
      }
      let ss: Buffer;
      try {
        ss = await opts.decapsulate(keyId, ct);
      } catch {
        return refuse(sock, ip, "overloaded");
      }
      if (sock.destroyed) return;
      let connect: Buffer;
      let transport: Transport;
      let msg2: Buffer;
      try {
        connect = responder.finishMessage1(ss);
        ({ message: msg2, transport } = responder.writeMessage2(Buffer.alloc(0)));
      } catch (e) {
        if (!(e instanceof NoiseError)) throw e;
        return refuse(sock, ip, "noise");
      }
      clearTimeout(timer);
      pipe(connect, msg2, transport);
    }

    // ── Phase 3: a decrypted MQTT stream to EMQX, and back ───────────────────
    function pipe(connect: Buffer, msg2: Buffer, t: Transport) {
      const clientId = connectClientId(connect);
      const up = net.connect({ host: opts.upstream.host, port: opts.upstream.port, noDelay: true });
      let bytesUp = 0;
      let bytesDown = 0;
      let open = false;
      const closeBoth = () => { sock.destroy(); up.destroy(); };

      up.on("error", () => {
        if (!open) return refuse(sock, ip, "upstream");
        closeBoth();
      });
      up.once("connect", () => {
        open = true;
        leaveHandshake();
        established++;
        bump(connectionsByIp, ip, 1);
        opts.onEvent?.({ t: "established", ip, clientId, handshakeMs: now() - started });
        // msg2 goes out without waiting for CONNACK, which then follows as the
        // first transport frame: the client's connect costs no extra round trip.
        sock.write(frame(msg2));
        up.write(connect);
        bytesUp += connect.length;
        sock.resume();
      });

      const reader = new FrameReader();
      sock.on("data", (chunk: Buffer) => {
        reader.push(chunk);
        try {
          for (let f = reader.next(); f; f = reader.next()) {
            const pt = t.recv.decryptWithAd(Buffer.alloc(0), f);
            bytesUp += pt.length;
            if (!up.write(pt)) sock.pause();
          }
        } catch {
          refused.stream = (refused.stream ?? 0) + 1;
          closeBoth();
        }
      });
      up.on("drain", () => sock.resume());

      up.on("data", (chunk: Buffer) => {
        bytesDown += chunk.length;
        if (!sock.write(sealFrames(t.send, chunk))) up.pause();
      });
      sock.on("drain", () => up.resume());

      let counted = false;
      const onClose = () => {
        closeBoth();
        if (!open || counted) return;
        counted = true;
        established--;
        bump(connectionsByIp, ip, -1);
        opts.onEvent?.({ t: "closed", ip, clientId, bytesUp, bytesDown });
      };
      sock.once("close", onClose);
      up.once("close", onClose);
    }
  });

  return {
    server,
    stats: () => ({ halfOpen, established, refused: { ...refused }, replayCacheSize: seenEphemerals.size }),
  };
}
