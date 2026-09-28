/**
 * An hqn/1 client stream for mqtt.js: a Duplex that speaks raw TCP + the hybrid
 * Noise handshake (lib/noise.ts) to noise-gw, and plain MQTT bytes to mqtt.js.
 *
 * The one piece of real protocol here: the CONNECT does not go out as a
 * transport frame, it rides INSIDE msg1. So the first MQTT packet mqtt.js
 * writes is held back until it is whole (mqtt.js may hand it over in several
 * writes), sealed into msg1, and only then does anything touch the network.
 * Anything written before msg2 arrives waits, and is sealed once the transport
 * keys exist. That is exactly what the app's HQNTransport does.
 *
 * `opening` exposes the exact bytes the client put on the wire first — header
 * plus msg1 — so a test can replay them the way an on-path attacker would.
 */

import * as net from "net";
import { Duplex } from "stream";
import {
  HqnInitiator,
  FrameReader,
  frame,
  sealFrames,
  HQN_VERSION,
  type ServerStaticPublic,
  type Transport,
} from "../../lib/noise";

/** Bytes of a complete MQTT packet at the head of `buf`, or 0 if incomplete. */
function packetLength(buf: Buffer): number {
  let len = 0;
  for (let i = 1, shift = 0; i < 5; i++, shift += 7) {
    if (i >= buf.length) return 0;
    const b = buf[i]!;
    len += (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return buf.length >= i + 1 + len ? i + 1 + len : 0;
  }
  throw new Error("malformed remaining length");
}

export class HqnStream extends Duplex {
  opening: Buffer | null = null;
  private sock: net.Socket | null = null;
  private pendingConnect = Buffer.alloc(0);
  private queued: Buffer[] = [];
  private transport: Transport | null = null;
  private readonly reader = new FrameReader();

  constructor(private host: string, private port: number, private server: ServerStaticPublic) {
    super();
  }

  _read(): void {
    this.sock?.resume();
  }

  _write(chunk: Buffer, _enc: BufferEncoding, cb: (e?: Error | null) => void): void {
    if (this.transport) {
      this.sock!.write(sealFrames(this.transport.send, chunk), cb);
      return;
    }
    if (this.sock) {
      this.queued.push(chunk);   // after msg1, before msg2
      cb();
      return;
    }
    this.pendingConnect = Buffer.concat([this.pendingConnect, chunk]);
    let n: number;
    try { n = packetLength(this.pendingConnect); } catch (e) { cb(e as Error); return; }
    if (n === 0) { cb(); return; }
    const connect = this.pendingConnect.subarray(0, n);
    const rest = this.pendingConnect.subarray(n);
    if (rest.length) this.queued.push(Buffer.from(rest));
    this.open(Buffer.from(connect));
    cb();
  }

  private open(connect: Buffer): void {
    const init = new HqnInitiator(this.server);
    this.opening = Buffer.concat([Buffer.from([HQN_VERSION, this.server.keyId]), frame(init.writeMessage1(connect))]);
    const sock = net.connect({ host: this.host, port: this.port, noDelay: true });
    this.sock = sock;
    sock.on("connect", () => sock.write(this.opening!));
    sock.on("data", (d: Buffer) => {
      this.reader.push(d);
      try {
        for (let f = this.reader.next(); f; f = this.reader.next()) {
          if (!this.transport) {
            this.transport = init.readMessage2(f).transport;
            for (const q of this.queued.splice(0)) sock.write(sealFrames(this.transport.send, q));
            continue;
          }
          if (!this.push(this.transport.recv.decryptWithAd(Buffer.alloc(0), f))) sock.pause();
        }
      } catch (e) {
        this.destroy(e as Error);
      }
    });
    sock.on("error", (e) => this.destroy(e));
    sock.on("close", () => { this.push(null); this.destroy(); });
  }

  _final(cb: (e?: Error | null) => void): void {
    this.sock?.end();
    cb();
  }

  _destroy(err: Error | null, cb: (e?: Error | null) => void): void {
    this.sock?.destroy();
    cb(err);
  }
}
