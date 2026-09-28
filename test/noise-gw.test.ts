// noise-gw (noise-gw/gateway.ts): the first process on the public internet to
// read a raw-TCP client's bytes. Driven over real loopback sockets, against a
// fake broker, with a fake KEM of the real sizes — every check here is about
// what the gateway does with bytes, and the KEM is tested on its own.
//
// Most of these are refusals, because that is almost all an internet-facing
// listener ever does. The property that matters most: garbage never costs a
// decapsulation.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import * as net from "node:net";
import * as crypto from "node:crypto";
import {
  HqnInitiator,
  FrameReader,
  frame,
  sealFrames,
  x25519KeyPair,
  msg1Length,
  HQN_VERSION,
  HQC_CIPHERTEXT_BYTES,
  HQC_PUBLIC_KEY_BYTES,
  type Kem,
  type ServerStatic,
  type Transport,
} from "../lib/noise";
import { createGateway, type GatewayLimits, type GatewayEvent } from "../noise-gw/gateway";
import { connectClientId } from "../noise-gw/mqtt-connect";
import { parseKeySeeds } from "../noise-gw/keys";

// --- fixtures ----------------------------------------------------------------

const fakeKem: Kem = {
  encapsulate: () => {
    const ct = crypto.randomBytes(HQC_CIPHERTEXT_BYTES);
    return { ct, ss: crypto.createHash("sha256").update(ct).digest() };
  },
  decapsulate: (_sk, ct) => crypto.createHash("sha256").update(ct).digest(),
};

const KEY: ServerStatic = {
  keyId: 3,
  x25519: x25519KeyPair(),
  hqc: { pk: crypto.randomBytes(HQC_PUBLIC_KEY_BYTES), sk: crypto.randomBytes(7333) },
};
const KEY_PUB = { keyId: KEY.keyId, x25519: KEY.x25519.pub, hqc: KEY.hqc.pk };

const CLIENT_ID = "ab".repeat(32);

/** A minimal MQTT 3.1.1 CONNECT with the given client id. */
function connectPacket(clientId = CLIENT_ID): Buffer {
  const vh = Buffer.concat([
    Buffer.from([0x00, 0x04]), Buffer.from("MQTT"), Buffer.from([0x04, 0x02, 0x00, 0x3c]),
  ]);
  const id = Buffer.from(clientId, "utf8");
  const payload = Buffer.concat([Buffer.from([id.length >> 8, id.length & 0xff]), id]);
  const body = Buffer.concat([vh, payload]);
  return Buffer.concat([Buffer.from([0x10, body.length]), body]);
}
const CONNACK = Buffer.from([0x20, 0x02, 0x00, 0x00]);

/** A fake broker: records what it receives, answers CONNECT with CONNACK, then
 *  echoes everything else back. */
async function fakeBroker() {
  const received: Buffer[] = [];
  const server = net.createServer((s) => {
    let first = true;
    s.on("data", (d: Buffer) => {
      received.push(d);
      if (first) { first = false; s.write(CONNACK); } else s.write(d);
    });
    s.on("error", () => {});
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { port: (server.address() as net.AddressInfo).port, received, server };
}

async function gateway(opts: { limits?: Partial<GatewayLimits>; upstreamPort: number; decapsulate?: (k: number, ct: Buffer) => Promise<Buffer> }) {
  const events: GatewayEvent[] = [];
  let decaps = 0;
  const gw = createGateway({
    keys: new Map([[KEY.keyId, KEY]]),
    decapsulate: opts.decapsulate ?? (async (_k, ct) => { decaps++; return fakeKem.decapsulate(Buffer.alloc(0), ct); }),
    upstream: { host: "127.0.0.1", port: opts.upstreamPort },
    ...(opts.limits ? { limits: opts.limits } : {}),
    onEvent: (e) => events.push(e),
  });
  await new Promise<void>((r) => gw.server.listen(0, "127.0.0.1", r));
  const port = (gw.server.address() as net.AddressInfo).port;
  return { ...gw, port, events, decaps: () => decaps };
}

const toClose: net.Server[] = [];
after(() => { for (const s of toClose) s.close(); });

function dial(port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const s = net.connect({ port, host: "127.0.0.1" }, () => resolve(s));
    s.on("error", reject);
  });
}

/** Resolves when the socket is closed by the far end. */
const closed = (s: net.Socket) => new Promise<void>((r) => { if (s.destroyed) r(); else s.once("close", () => r()); });

/** A full client: header, msg1 carrying a CONNECT, msg2, then a transport. */
async function handshake(port: number, connect = connectPacket()) {
  const s = await dial(port);
  const init = new HqnInitiator(KEY_PUB, { kem: fakeKem });
  const msg1 = init.writeMessage1(connect);
  s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]), frame(msg1)]));
  const reader = new FrameReader();
  const frames: Buffer[] = [];
  let transport: Transport | null = null;
  const waiters: (() => void)[] = [];
  s.on("data", (d: Buffer) => {
    reader.push(d);
    for (let f = reader.next(); f; f = reader.next()) {
      if (!transport) transport = init.readMessage2(f).transport;
      else frames.push(transport.recv.decryptWithAd(Buffer.alloc(0), f));
      waiters.splice(0).forEach((w) => w());
    }
  });
  const nextFrame = async (): Promise<Buffer> => {
    while (frames.length === 0) await new Promise<void>((r) => waiters.push(r));
    return frames.shift()!;
  };
  await new Promise<void>((r) => { const tick = () => (transport ? r() : waiters.push(tick)); tick(); });
  return { s, msg1, t: transport as unknown as Transport, nextFrame };
}

// --- the happy path -------------------------------------------------------------

test("a client's CONNECT reaches the broker verbatim, and the stream flows both ways", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port }); toClose.push(gw.server);
  const connect = connectPacket();
  const c = await handshake(gw.port, connect);

  assert.ok((await c.nextFrame()).equals(CONNACK), "CONNACK arrives as the first transport frame");
  assert.ok(Buffer.concat(broker.received).subarray(0, connect.length).equals(connect), "the broker got the CONNECT as sent");

  const publish = Buffer.from([0x30, 0x05, 0x00, 0x01, 0x74, 0x68, 0x69]);
  c.s.write(sealFrames(c.t.send, publish));
  assert.ok((await c.nextFrame()).equals(publish), "an upstream packet reaches the broker and its echo comes back");

  const est = gw.events.find((e) => e.t === "established");
  assert.ok(est && est.t === "established" && est.clientId === CLIENT_ID, "the log names the client id");
  assert.equal(gw.stats().established, 1);
  assert.equal(gw.stats().halfOpen, 0);
  c.s.destroy();
});

test("a large upstream write is split into frames and reassembled for the broker", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port }); toClose.push(gw.server);
  const c = await handshake(gw.port);
  await c.nextFrame();
  const big = crypto.randomBytes(200_000);
  c.s.write(sealFrames(c.t.send, big));
  const echoed: Buffer[] = [];
  let n = 0;
  while (n < big.length) { const f = await c.nextFrame(); echoed.push(f); n += f.length; }
  assert.ok(Buffer.concat(echoed).equals(big));
  c.s.destroy();
});

// --- refusals: none of these may cost a decapsulation -----------------------------

test("a wrong version or unknown key id is closed at the header", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port }); toClose.push(gw.server);
  for (const header of [[HQN_VERSION + 1, KEY.keyId], [HQN_VERSION, KEY.keyId + 1], [0x16, 0x03]]) {
    const s = await dial(gw.port);
    s.write(Buffer.from(header));
    await closed(s);
  }
  assert.equal(gw.stats().refused.header, 3);
  assert.equal(gw.decaps(), 0);
});

test("a msg1 length outside what a CONNECT can produce is closed before any cryptography", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, limits: { maxConnectBytes: 1024 } }); toClose.push(gw.server);
  for (const len of [0, msg1Length(0) - 1, msg1Length(1024) + 1, 65535]) {
    const s = await dial(gw.port);
    const pre = Buffer.alloc(4);
    pre[0] = HQN_VERSION; pre[1] = KEY.keyId; pre.writeUInt16BE(len, 2);
    s.write(pre);
    await closed(s);
  }
  assert.equal(gw.stats().refused.length, 4);
  assert.equal(gw.decaps(), 0);
});

test("random bytes of a valid length fail the X25519 layer and never reach decapsulation", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port }); toClose.push(gw.server);
  for (let i = 0; i < 5; i++) {
    const s = await dial(gw.port);
    s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]), frame(crypto.randomBytes(msg1Length(100)))]));
    await closed(s);
  }
  assert.equal(gw.stats().refused.noise, 5);
  assert.equal(gw.decaps(), 0, "garbage must not cost a decapsulation");
});

test("bytes after msg1, before msg2, are refused", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port }); toClose.push(gw.server);
  const s = await dial(gw.port);
  const msg1 = new HqnInitiator(KEY_PUB, { kem: fakeKem }).writeMessage1(connectPacket());
  s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]), frame(msg1), Buffer.from([1, 2, 3])]));
  await closed(s);
  assert.equal(gw.stats().refused.length, 1);
});

test("a replayed msg1 is refused, and the broker never sees its CONNECT twice", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port }); toClose.push(gw.server);
  const c = await handshake(gw.port);
  await c.nextFrame();
  const s = await dial(gw.port);
  s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]), frame(c.msg1)]));
  await closed(s);
  assert.equal(gw.stats().refused.replay, 1);
  const connects = broker.received.filter((b) => b[0] === 0x10).length;
  assert.equal(connects, 1);
  c.s.destroy();
});

test("a client that stalls mid-handshake is closed at the deadline", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, limits: { handshakeTimeoutMs: 150 } }); toClose.push(gw.server);
  const s = await dial(gw.port);
  s.write(Buffer.from([HQN_VERSION, KEY.keyId, 0x39]));   // half a length prefix, then nothing
  const t0 = Date.now();
  await closed(s);
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(gw.stats().refused.timeout, 1);
  // The client can see the close before the gateway's own close handler runs.
  for (let i = 0; i < 50 && gw.stats().halfOpen !== 0; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(gw.stats().halfOpen, 0, "a timed-out handshake gives its slot back");
});

test("per-address limits: concurrent handshakes and handshake rate", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, limits: { perIpHandshakes: 2, handshakeTimeoutMs: 2000 } }); toClose.push(gw.server);
  const a = await dial(gw.port), b = await dial(gw.port), c = await dial(gw.port);
  await closed(c);
  assert.equal(gw.stats().refused["ip-handshakes"], 1);
  a.destroy(); b.destroy();

  const gw2 = await gateway({ upstreamPort: broker.port, limits: { perIpHandshakesPerMinute: 2 } }); toClose.push(gw2.server);
  const x = await dial(gw2.port), y = await dial(gw2.port), z = await dial(gw2.port);
  await closed(z);
  assert.equal(gw2.stats().refused["ip-rate"], 1);
  x.destroy(); y.destroy();
});

test("a full decapsulation queue sheds the handshake instead of queueing it", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port, decapsulate: async () => { throw new Error("queue full"); } });
  toClose.push(gw.server);
  const s = await dial(gw.port);
  s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]),
    frame(new HqnInitiator(KEY_PUB, { kem: fakeKem }).writeMessage1(connectPacket()))]));
  await closed(s);
  assert.equal(gw.stats().refused.overloaded, 1);
});

test("a broker that is down closes the client rather than hanging it", async () => {
  const dead = net.createServer(); await new Promise<void>((r) => dead.listen(0, "127.0.0.1", r));
  const port = (dead.address() as net.AddressInfo).port;
  dead.close();
  const gw = await gateway({ upstreamPort: port }); toClose.push(gw.server);
  const s = await dial(gw.port);
  s.write(Buffer.concat([Buffer.from([HQN_VERSION, KEY.keyId]),
    frame(new HqnInitiator(KEY_PUB, { kem: fakeKem }).writeMessage1(connectPacket()))]));
  await closed(s);
  assert.equal(gw.stats().refused.upstream, 1);
});

test("a tampered transport frame closes both sides", async () => {
  const broker = await fakeBroker(); toClose.push(broker.server);
  const gw = await gateway({ upstreamPort: broker.port }); toClose.push(gw.server);
  const c = await handshake(gw.port);
  await c.nextFrame();
  const f = sealFrames(c.t.send, Buffer.from([0xc0, 0x00]));
  f[f.length - 1]! ^= 1;
  c.s.write(f);
  await closed(c.s);
  assert.equal(gw.stats().refused.stream, 1);
});

// --- the helpers ----------------------------------------------------------------

test("connectClientId reads 3.1.1 and 5, and returns null for anything else", () => {
  assert.equal(connectClientId(connectPacket()), CLIENT_ID);
  // MQTT 5: level 5 and a (here empty) properties block before the payload.
  const v5 = Buffer.from(connectPacket());
  const body = Buffer.concat([
    Buffer.from([0x00, 0x04]), Buffer.from("MQTT"), Buffer.from([0x05, 0x02, 0x00, 0x3c, 0x00]),
    Buffer.from([0x00, 0x40]), Buffer.from(CLIENT_ID),
  ]);
  assert.equal(connectClientId(Buffer.concat([Buffer.from([0x10, body.length]), body])), CLIENT_ID);
  assert.ok(v5);
  for (const bad of [Buffer.alloc(0), Buffer.from([0x30, 0x00]), connectPacket("not-an-id"),
    connectPacket().subarray(0, 10), Buffer.from([0x10, 0xff, 0xff, 0xff, 0xff, 0x7f])]) {
    assert.equal(connectClientId(bad), null);
  }
  for (let i = 0; i < 2000; i++) connectClientId(crypto.randomBytes(1 + (i % 80)));   // never throws
});

test("the key file is validated strictly", () => {
  const good = { keyId: 1, x25519: "11".repeat(32), hqcSeed: "22".repeat(32) };
  assert.equal(parseKeySeeds(JSON.stringify({ keys: [good] })).length, 1);
  for (const bad of [
    {}, { keys: [] }, { keys: [{ ...good, keyId: 256 }] }, { keys: [{ ...good, x25519: "11" }] },
    { keys: [{ ...good, hqcSeed: "zz".repeat(32) }] }, { keys: [good, good] },
  ]) {
    assert.throws(() => parseKeySeeds(JSON.stringify(bad)), Error, JSON.stringify(bad));
  }
});

// --- the real decapsulation pool ------------------------------------------------

test("the worker pool decapsulates with the real HQC library, off the main thread", async (t) => {
  let HqcWrapper: typeof import("../lib/hqc").HqcWrapper;
  try { ({ HqcWrapper } = await import("../lib/hqc")); } catch (e) { return t.skip(`native HQC unavailable: ${(e as Error).message}`); }
  const { DecapPool } = await import("../noise-gw/decap-pool");
  const kp = HqcWrapper.keypairFromSeed(crypto.randomBytes(32));
  const pool = new DecapPool([{ keyId: 5, sk: kp.sk }], 2, 8);
  try {
    const jobs = Array.from({ length: 4 }, () => HqcWrapper.encapsulate(kp.pk));
    const secrets = await Promise.all(jobs.map((j) => pool.decapsulate(5, j.ct)));
    secrets.forEach((ss, i) => assert.ok(ss.equals(jobs[i]!.ss), `job ${i}`));
    await assert.rejects(pool.decapsulate(9, jobs[0]!.ct), /unknown key id/, "an unknown key id is an error, not a crash");
  } finally {
    await pool.close();
  }
});

test("a full pool queue refuses at once rather than growing", async (t) => {
  try { await import("../lib/hqc"); } catch (e) { return t.skip(`native HQC unavailable: ${(e as Error).message}`); }
  const { DecapPool } = await import("../noise-gw/decap-pool");
  const pool = new DecapPool([], 1, 0);
  try {
    await assert.rejects(pool.decapsulate(1, Buffer.alloc(HQC_CIPHERTEXT_BYTES)), /queue full/);
  } finally {
    await pool.close();
  }
});

test("noise-gw-keys makes a seed file the gateway loads, and appends rather than overwrites", async (t) => {
  try { await import("../lib/hqc"); } catch (e) { return t.skip(`native HQC unavailable: ${(e as Error).message}`); }
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");
  const { execFileSync } = await import("node:child_process");
  const { readKeySeeds, loadServerKeys, publicKeys } = await import("../noise-gw/keys");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noise-keys-"));
  const secret = path.join(dir, "keys.json");
  const run = (id: number) => execFileSync("npx", ["tsx", "scripts/noise-gw-keys.ts", "--key-id", String(id), "--secret", secret],
    { cwd: path.join(__dirname, ".."), encoding: "utf8" });
  try {
    const pub1 = JSON.parse(run(1));
    assert.equal(pub1.keys.length, 1);
    assert.equal((fs.statSync(secret).mode & 0o777), 0o600, "the seed file is private");
    run(2);
    const keys = loadServerKeys(readKeySeeds(secret));
    assert.deepEqual([...keys.keys()], [1, 2], "rotation holds two key ids at once");
    const pub = publicKeys(keys);
    assert.equal(pub[0]!.x25519, pub1.keys[0].x25519, "the first key survived the second run");
    assert.equal(Buffer.from(pub[0]!.hqc, "base64").length, HQC_PUBLIC_KEY_BYTES);
    assert.throws(() => run(1), Error, "an existing key id is never overwritten");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
