// noise-gw entrypoint: hqn/1 (raw TCP, hybrid post-quantum Noise) in front of
// EMQX's internal plain-TCP listener. See gateway.ts for the threat model and
// lib/noise.ts for the protocol.
//
//   NOISE_GW_PORT         listen port for clients                (8443)
//   NOISE_GW_HOST         client listener address         (every interface)
//   NOISE_GW_HEALTH_PORT  /health + counters, loopback-only use  (8081)
//   NOISE_GW_HEALTH_HOST  comma-separated addresses for it  (every interface)
//   NOISE_KEYS_FILE       secret seeds, see keys.ts              (required)
//   EMQX_TCP_HOST/PORT    the broker's internal TCP listener     (emqx:1883)
//   NOISE_GW_WORKERS      decapsulation workers         (cpus - 1, at least 1)
//   NOISE_GW_QUEUE        decapsulations allowed to wait            (64)

// Must be first: loads .env + resolves *_FILE secrets before anything reads env.
import "../lib/config";
import * as http from "http";
import * as os from "os";
import { initObservability } from "../lib/observability";
import { healthMonitor } from "../lib/health-monitor";
import { logger } from "../lib/logger";
import { createGateway } from "./gateway";
import { DecapPool } from "./decap-pool";
import { readKeySeeds, loadServerKeys, publicKeys } from "./keys";
import { listenOn, parseHosts } from "../lib/listen";

if (require.main === module) {
  initObservability("noise-gw");
  const port = Number(process.env.NOISE_GW_PORT || 8443);
  const healthPort = Number(process.env.NOISE_GW_HEALTH_PORT || process.env.PORT || 8081);
  const keysFile = process.env.NOISE_KEYS_FILE;
  if (!keysFile) throw new Error("NOISE_KEYS_FILE is required");
  const keys = loadServerKeys(readKeySeeds(keysFile));
  const pool = new DecapPool(
    [...keys.values()].map((k) => ({ keyId: k.keyId, sk: k.hqc.sk })),
    Number(process.env.NOISE_GW_WORKERS || Math.max(1, os.cpus().length - 1)),
    Number(process.env.NOISE_GW_QUEUE || 64),
  );

  const { server, stats } = createGateway({
    keys,
    decapsulate: (keyId, ct) => pool.decapsulate(keyId, ct),
    upstream: { host: process.env.EMQX_TCP_HOST || "emqx", port: Number(process.env.EMQX_TCP_PORT || 1883) },
    onEvent: (e) => {
      // Refusals are what an internet-facing listener sees all day: counted,
      // never logger.error (which bills a Sentry event each).
      if (e.t === "established") logger.debug(`[noise-gw] ${e.clientId?.slice(0, 12) ?? "?"}… from ${e.ip} in ${e.handshakeMs}ms`);
    },
  });
  // NOISE_GW_HOST: the reserved IP's anchor address, off Docker — the only
  // address the world may reach. Unset = every interface (compose publishes it).
  const host = process.env.NOISE_GW_HOST || undefined;
  server.listen(port, host, () => {
    logger.startup(`🔒 noise-gw on ${host ?? "*"}:${port} — keys ${[...keys.keys()].join(",")}, ${pool.size} decap workers`);
  });

  // /health and /keys: loopback (the host's health gate) and the WireGuard
  // address (auth reads /keys), never the public one. A list, like LISTEN_HOST.
  listenOn(() => http.createServer((req, res) => {
    if (req.url === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ ok: true, service: "noise-gw", ...stats(), decapQueued: pool.queued }));
    }
    if (req.url === "/keys") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ keys: publicKeys(keys) }));
    }
    res.writeHead(404).end();
  }), healthPort, parseHosts(process.env.NOISE_GW_HEALTH_HOST));

  healthMonitor.start();
}
