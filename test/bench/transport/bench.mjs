// bench.mjs — measure ONE transport arm under whatever impairment is currently
// active on the test bed (bed.sh owns the impairment; this file owns the clock).
//
// Run it once per arm, as its own process, so nothing leaks between arms: no
// shared TLS session cache, no warm TCP, no mqtt.js state. run.sh drives the
// matrix.
//
// What is measured, and why each one is here:
//
//   connect   TCP -> [TLS] -> [WS upgrade] -> CONNECT/CONNACK, from a cold
//             socket. This is the ONLY place the WebSocket upgrade's extra
//             round trip can show up, and the reason to care about it on mobile
//             is that phones reconnect constantly (backgrounding, cell
//             handover, Wi-Fi->LTE). Measured with reconnectPeriod 0 so a
//             failure is recorded as a failure instead of being retried into a
//             good-looking number.
//
//   rtt       publish on A -> delivered to B, both already connected, QoS 1.
//             One clock, one process, so the subtraction is valid. This is what
//             a user experiences as "message latency", and it is where a
//             per-frame byte cost would have to show up if it mattered.
//
//   puback    A's publish -> A's PUBACK. One round trip to the broker.
//
//   wire      real bytes on the impaired link (read from the TUN counters by
//             run.sh, not here) for a fixed workload.
//
//   recover   abrupt socket kill -> session usable again (reconnected,
//             resubscribed, and a message actually round-tripped). The mobile
//             case that dominates perceived latency.
import mqtt from "mqtt";


const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [k, ...v] = a.replace(/^--/, "").split("=");
    return [k, v.join("=") || true];
  }),
);

const BROKER = args.host || "10.88.0.1";
const ARM = args.arm;
const PROFILE = args.profile || "unknown";
const CONNECTS = Number(args.connects ?? 20);
const MSGS = Number(args.msgs ?? 40);
const RECOVERS = Number(args.recovers ?? 5);
const SIZES = (args.sizes || "256,16384").split(",").map(Number);
const CONNECT_DEADLINE = Number(args.deadline ?? 20000);
const MSG_DEADLINE = Number(args.msgDeadline ?? 20000);

// The five arms. `wss-nginx` is production as deployed today
// (infra/deploy/nginx.conf `location /mqtt` -> emqx 8083); `mqtts` is the
// proposal. The plain pair exists to separate WebSocket framing from TLS, so a
// difference can be attributed rather than guessed at.
// The two `wss-edge-*` arms model the Cloudflare edge that actually sits in
// front of production: the client's TCP and TLS terminate LOCALLY (at edge.mjs,
// inside the client's namespace) and only the upgrade and CONNECT cross the
// impaired path. Without them the first five arms overstate the WebSocket's cost,
// because they charge the client full distance for handshakes Cloudflare absorbs.
// `warm` and `cold` bound the answer either side of the one thing we cannot
// observe from here: whether the edge already holds a connection to the origin.
const ARMS = {
  "tcp-plain":     { url: `mqtt://${BROKER}:1883` },
  "ws-plain":      { url: `ws://${BROKER}:8083/mqtt` },
  "mqtts":         { url: `mqtts://${BROKER}:8883`, tls: true },
  "wss-direct":    { url: `wss://${BROKER}:8084/mqtt`, tls: true },
  "wss-nginx":     { url: `wss://${BROKER}:8443/mqtt`, tls: true },
  "wss-edge-warm": { url: `wss://127.0.0.1:9443/mqtt`, tls: true, edge: "warm" },
  "wss-edge-cold": { url: `wss://127.0.0.1:9444/mqtt`, tls: true, edge: "cold" },
  // The transport that shipped out of this benchmark's findings: MQTT over raw
  // TCP inside hqn/1, the hybrid X25519 + HQC-256 Noise handshake, through
  // noise-gw (bed.sh starts it) to EMQX's plain TCP listener. The CONNECT rides
  // in the ~14.7 kB first flight, so this arm is where that flight's cost under
  // loss shows up. Needs the server's tsx loader and native HQC (run.sh passes
  // both) and the gateway's public keys (--hqnKeys, written by bed.sh).
  "hqn":           { url: `hqn://${BROKER}:9883`, hqn: { port: 9883 } },
};
if (!ARMS[ARM]) {
  console.error(`unknown arm ${ARM}; expected one of ${Object.keys(ARMS).join(", ")}`);
  process.exit(2);
}

// Certificate verification is off because the bed uses a self-signed cert. It
// is NOT a shortcut that flatters either arm: SPKI pinning (TLSPinning.swift)
// is a local hash comparison on a chain the handshake already carried, so it
// costs the same handful of microseconds on mqtts and on wss.
const base = {
  protocolVersion: 4,          // 3.1.1, same as MQTTWireClient.swift
  rejectUnauthorized: false,
  servername: "bench.local",
  keepalive: 60,               // MQTTWireClient.swift:379
  resubscribe: false,
};

const nowMs = () => Number(process.hrtime.bigint() / 1000n) / 1000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function pct(xs, p) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const i = Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1));
  return Math.round(s[i] * 100) / 100;
}
const summary = (xs, failures = 0) => ({
  n: xs.length, failures,
  p50: pct(xs, 50), p95: pct(xs, 95), p99: pct(xs, 99),
  min: pct(xs, 0), max: pct(xs, 100),
  mean: xs.length ? Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 100) / 100 : null,
});

// hqn/1 clients are mqtt.js over a Noise stream rather than a URL. Loaded only
// for that arm, so every other arm still runs on plain node with no loader.
let hqnStream = null;
if (ARMS[ARM].hqn) {
  const fs = await import("node:fs");
  const { HqnStream } = await import(new URL("../../helpers/hqn-stream.ts", import.meta.url).href);
  const k = JSON.parse(fs.readFileSync(args.hqnKeys, "utf8")).keys[0];
  const server = { keyId: k.keyId, x25519: Buffer.from(k.x25519, "base64"), hqc: Buffer.from(k.hqc, "base64") };
  hqnStream = () => new HqnStream(BROKER, ARMS[ARM].hqn.port, server);
}

/** A client for this arm: a URL for every transport mqtt.js knows, a Noise
 *  stream for hqn/1. Same options either way, so the arms stay comparable. */
function connectClient(opts) {
  if (hqnStream) return new mqtt.MqttClient(hqnStream, opts);
  return mqtt.connect(ARMS[ARM].url, opts);
}

let idSeq = 0;
const clientId = (tag) => `bench-${ARM}-${tag}-${process.pid}-${++idSeq}`;

function connectOnce(opts = {}, deadline = CONNECT_DEADLINE) {
  return new Promise((resolve) => {
    const t0 = nowMs();
    const c = connectClient({
      ...base, clientId: clientId("c"), clean: true, reconnectPeriod: 0,
      connectTimeout: deadline, ...opts,
    });
    let done = false;
    const finish = (ok, err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ ok, ms: nowMs() - t0, client: c, err: err?.message });
    };
    const timer = setTimeout(() => { try { c.end(true); } catch {} finish(false, new Error("deadline")); }, deadline + 2000);
    c.once("connect", () => finish(true));
    c.once("error", (e) => { try { c.end(true); } catch {} finish(false, e); });
  });
}

// One throwaway connection before anything is recorded. Node's first TLS
// handshake and first WebSocket upgrade pay JIT and lazy-module costs that have
// nothing to do with the network — on a clean path the first connect measured
// 92ms against a 4.6ms median, which would have landed entirely in p95 and been
// read as a transport difference.
async function warmup() {
  const r = await connectOnce();
  try { r.client?.end(true); } catch {}
  await sleep(150);
}

// --- connect: cold sockets, one at a time -----------------------------------
async function measureConnect() {
  const xs = []; let failures = 0;
  for (let i = 0; i < CONNECTS; i++) {
    const r = await connectOnce();
    if (r.ok) { xs.push(r.ms); } else { failures++; }
    try { r.client.end(true); } catch {}
    await sleep(120);   // let the broker retire the session before the next id
  }
  return summary(xs, failures);
}

// --- rtt + puback: two warm clients ----------------------------------------
async function measureRtt(size) {
  const topic = `bench/${process.pid}/${size}`;
  const a = await connectOnce({ clientId: clientId("pub") });
  const b = await connectOnce({ clientId: clientId("sub") });
  if (!a.ok || !b.ok) {
    try { a.client?.end(true); b.client?.end(true); } catch {}
    return { rtt: summary([], MSGS), puback: summary([], MSGS), note: "could not establish warm pair" };
  }
  await new Promise((res, rej) =>
    b.client.subscribe(topic, { qos: 1 }, (e) => (e ? rej(e) : res())));

  const rtts = []; const pubacks = []; let failures = 0;
  const filler = Buffer.alloc(Math.max(0, size - 24), 0x61);

  for (let i = 0; i < MSGS; i++) {
    const seq = String(i).padStart(8, "0");
    const payload = Buffer.concat([Buffer.from(seq), filler]);
    const t0 = nowMs();
    const got = new Promise((resolve) => {
      const onMsg = (t, m) => {
        if (t === topic && m.subarray(0, 8).toString() === seq) {
          b.client.removeListener("message", onMsg);
          resolve(nowMs() - t0);
        }
      };
      b.client.on("message", onMsg);
      setTimeout(() => { b.client.removeListener("message", onMsg); resolve(null); }, MSG_DEADLINE);
    });
    const acked = new Promise((resolve) => {
      a.client.publish(topic, payload, { qos: 1 }, () => resolve(nowMs() - t0));
      setTimeout(() => resolve(null), MSG_DEADLINE);
    });
    const [d, ack] = await Promise.all([got, acked]);
    if (d === null) failures++; else rtts.push(d);
    if (ack !== null) pubacks.push(ack);
    await sleep(25);
  }
  try { a.client.end(true); b.client.end(true); } catch {}
  return { rtt: summary(rtts, failures), puback: summary(pubacks) };
}

// --- recover: abrupt drop -> usable session again ---------------------------
// `clean: false` mirrors the app (MQTTWireClient.swift:453 connects with
// cleanSession false so the broker holds the subscription and queues).
async function measureRecover() {
  const xs = []; let failures = 0;
  for (let i = 0; i < RECOVERS; i++) {
    const topic = `bench/${process.pid}/recover/${i}`;
    const c = connectClient({
      ...base, clientId: clientId("rec"), clean: false, reconnectPeriod: 500,
      connectTimeout: CONNECT_DEADLINE,
    });
    const up = await new Promise((res) => {
      c.once("connect", () => res(true));
      c.once("error", () => res(false));
      setTimeout(() => res(false), CONNECT_DEADLINE + 2000);
    });
    if (!up) { failures++; try { c.end(true); } catch {} continue; }
    await new Promise((res) => c.subscribe(topic, { qos: 1 }, () => res()));

    // Kill the socket the way a cell handover does: no FIN, no DISCONNECT.
    const t0 = nowMs();
    const settled = new Promise((resolve) => {
      const onMsg = (t) => {
        if (t === topic) { c.removeListener("message", onMsg); resolve(nowMs() - t0); }
      };
      c.on("message", onMsg);
      c.on("connect", () => {
        // Re-subscribe (resubscribe:false above, so this is explicit, as the
        // app does in MQTTService.swift) then prove the path works end to end.
        c.subscribe(topic, { qos: 1 }, () => c.publish(topic, "up", { qos: 1 }));
      });
      setTimeout(() => { c.removeListener("message", onMsg); resolve(null); }, 45000);
    });
    c.stream.destroy();
    const d = await settled;
    if (d === null) failures++; else xs.push(d);
    try { c.end(true); } catch {}
    await sleep(200);
  }
  return summary(xs, failures);
}

// --- wire bytes: a fixed workload, counted outside by run.sh ---------------
// One cold connect plus `msgs` QoS-1 publishes of `size`, then a clean
// disconnect. run.sh reads the TUN byte counters either side of this and
// attributes the delta to the arm.
async function workload(size, msgs) {
  const topic = `bench/${process.pid}/wire`;
  const r = await connectOnce({ clientId: clientId("wire") });
  if (!r.ok) return { ok: false };
  const payload = Buffer.alloc(size, 0x62);
  await new Promise((res) => r.client.subscribe(topic, { qos: 1 }, () => res()));
  for (let i = 0; i < msgs; i++) {
    await new Promise((res) => r.client.publish(topic, payload, { qos: 1 }, () => res()));
  }
  await new Promise((res) => r.client.end(false, {}, () => res()));
  return { ok: true, msgs, size };
}

const out = { arm: ARM, profile: PROFILE, url: ARMS[ARM].url, at: new Date().toISOString() };

if (args.only === "wire") {
  out.wire = await workload(Number(args.wireSize ?? 256), Number(args.wireMsgs ?? 100));
} else {
  await warmup();
  out.connect = await measureConnect();
  out.messages = {};
  for (const s of SIZES) out.messages[s] = await measureRtt(s);
  out.recover = await measureRecover();
}
console.log(JSON.stringify(out));
process.exit(0);
