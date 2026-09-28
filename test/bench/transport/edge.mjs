// edge.mjs — a stand-in for the Cloudflare edge, so the production topology can
// be measured instead of argued about.
//
// The first five arms all put the client's TCP and TLS handshakes at the far end
// of the impaired path. Production does not: `chat` is orange-clouded
// (infra/cloudflare/dns.tf), so a phone's TCP and TLS terminate at a Cloudflare
// PoP typically 10–20ms away, and only what happens AFTER that handshake — the
// WebSocket upgrade, then MQTT CONNECT — has to travel to the origin.
//
// That changes the arithmetic the whole question rests on. Counting round trips
// over the FULL distance:
//
//   mqtts direct          TCP 1 + TLS1.3 1 + CONNECT 1                      = 3
//   wss via a warm edge   (TCP+TLS local) + upgrade 1 + CONNECT 1           = 2
//   wss via a cold edge   edge TCP 1 + TLS 1 + upgrade 1 + CONNECT 1        = 4
//
// So whether the WebSocket costs or saves a round trip turns entirely on whether
// the edge already holds a connection to the origin. Cloudflare keeps a
// keep-alive pool to origins, which argues for `warm`; a WebSocket upgrade needs
// a connection of its own, which argues for `cold`. Rather than guess, this
// proxy implements BOTH and the bench runs both, which bounds the answer.
//
//   --mode=warm   keep `--pool` origin connections pre-established
//   --mode=cold   dial the origin when the client arrives
//
// It works by splicing plaintext: it terminates the client's TLS and forwards
// the decrypted bytes over its own TLS connection to the origin's WSS listener.
// Client and origin both speak WebSocket and the framing is identical on both
// sides, so the upgrade request, the 101, and every frame after it pass through
// verbatim — exactly what an L7 proxy does. No WebSocket parsing happens here,
// so there is no chance of this file's own framing being what gets measured.
import { createServer, connect as tlsConnect } from "node:tls";
import { readFileSync } from "node:fs";

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [k, ...v] = a.replace(/^--/, "").split("=");
    return [k, v.join("=") || true];
  }),
);

const LISTEN = Number(args.listen ?? 9443);
const ORIGIN_HOST = args.originHost ?? "10.88.0.1";
const ORIGIN_PORT = Number(args.originPort ?? 8084);
const MODE = args.mode ?? "warm";
const POOL_SIZE = Number(args.pool ?? 4);
const CERT = args.cert ?? "certs/server.pem";
const KEY = args.key ?? "certs/server.key";

const dialOrigin = () =>
  tlsConnect({
    host: ORIGIN_HOST, port: ORIGIN_PORT,
    rejectUnauthorized: false, servername: "bench.local",
  });

// --- warm pool --------------------------------------------------------------
// Origin connections that have finished TCP and TLS and are sitting idle, the
// way a CDN's keep-alive pool to an origin does. Refilled eagerly so a client
// arriving mid-run still finds one ready. If the pool is empty the client falls
// back to a cold dial and that one connection is simply slower — the honest
// behaviour, rather than a stall that would show up as a timeout.
const pool = [];
let warmServed = 0, coldServed = 0;

function fillPool() {
  while (pool.length < POOL_SIZE) {
    const s = dialOrigin();
    s.ready = false;
    s.once("secureConnect", () => { s.ready = true; });
    const drop = () => {
      const i = pool.indexOf(s);
      if (i >= 0) pool.splice(i, 1);
    };
    s.once("error", drop);
    s.once("close", () => { drop(); setTimeout(fillPool, 50); });
    s.setKeepAlive(true, 15000);
    pool.push(s);
  }
}

function takeOrigin() {
  if (MODE === "warm") {
    const i = pool.findIndex((x) => x.ready && !x.destroyed);
    if (i >= 0) {
      const s = pool.splice(i, 1)[0];
      setImmediate(fillPool);
      warmServed++;
      return { sock: s, warm: true };
    }
  }
  coldServed++;
  return { sock: dialOrigin(), warm: false };
}

const server = createServer(
  { cert: readFileSync(CERT), key: readFileSync(KEY) },
  (client) => {
    const { sock: origin, warm } = takeOrigin();

    client.setNoDelay(true);
    origin.setNoDelay(true);

    // Bytes the client sends before the origin's TLS is up are buffered rather
    // than dropped. In warm mode there are none; in cold mode this is the
    // upgrade request waiting for the handshake it has to follow.
    const pending = [];
    let originReady = warm;
    if (!warm) {
      origin.once("secureConnect", () => {
        originReady = true;
        for (const b of pending) origin.write(b);
        pending.length = 0;
      });
    }

    client.on("data", (b) => (originReady ? origin.write(b) : pending.push(b)));
    origin.on("data", (b) => client.write(b));

    const shut = () => { try { client.destroy(); } catch {} try { origin.destroy(); } catch {} };
    for (const ev of ["error", "close", "end"]) {
      client.on(ev, shut);
      origin.on(ev, shut);
    }
  },
);

server.listen(LISTEN, "127.0.0.1", () => {
  if (MODE === "warm") fillPool();
  process.stderr.write(
    `edge.mjs mode=${MODE} listen=127.0.0.1:${LISTEN} origin=${ORIGIN_HOST}:${ORIGIN_PORT} pool=${MODE === "warm" ? POOL_SIZE : 0}\n`,
  );
});

// Lets the run confirm the warm arm was actually served warm. Cold hits in warm
// mode mean the pool drained faster than it refilled, so those numbers are a
// blend and should be reported as such rather than quoted as warm.
const report = () => {
  process.stderr.write(`edge.mjs served warm=${warmServed} cold=${coldServed}\n`);
  process.exit(0);
};
process.on("SIGTERM", report);
process.on("SIGINT", report);
