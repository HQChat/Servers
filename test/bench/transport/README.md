# Transport benchmark — MQTT-over-WSS vs raw MQTTS, on a bad network

Answers one question with numbers instead of opinion: **would dropping the
WebSocket layer and speaking raw MQTT-over-TLS from the mobile client to EMQX
make the app faster, particularly when the network is messy?**

Production today is `wss://DOMAIN/mqtt` → nginx → EMQX's plain WS listener
(`infra/deploy/nginx.conf`, `infra/deploy/emqx/emqx.conf`), with Cloudflare
proxying in front. The proposal is a native TLS MQTT listener on 8883 and a
client that speaks it directly.

## The five arms

Two of them are the actual question; three exist so a difference can be
**attributed** rather than guessed at.

| Arm | Path | What it isolates |
|:--|:--|:--|
| `wss-nginx` | wss → nginx → EMQX `ws:8083` | production as deployed |
| `wss-direct` | wss → EMQX `wss:8084` | WebSocket + TLS, no nginx hop |
| `mqtts` | mqtts → EMQX `ssl:8883` | the proposal |
| `ws-plain` | ws → EMQX `ws:8083` | framing with TLS removed |
| `tcp-plain` | tcp → EMQX `tcp:1883` | the floor |

So: `wss-direct − mqtts` is the WebSocket layer's own cost, `wss-nginx −
wss-direct` is the nginx hop, and `ws-plain − tcp-plain` is framing with the TLS
handshake taken out of the picture.

## How the network is made messy

`tc qdisc … netem` is the normal tool. It is **not available** on this kernel —
a Firecracker build with only `htb` and `pfifo` compiled in and no loadable
modules. So `impair.py` is a userspace netem: it carries the client's traffic
over a pair of TUN devices and impairs the **IP packets** between them.

```
[netns bench-client]                                    [host]
  bench.mjs                                               emqx :1883 :8083 :8883 :8084
     │ connects to 10.88.0.1                              nginx :8443
  tun-bc 10.88.0.2 ──impair.py──┐             ┌──impair.py── tun-bh 10.88.0.1
                                └─ UDP carrier over veth ─┘
                                   10.77.0.2 ↔ 10.77.0.1 (unimpaired)
```

Impairing real IP packets rather than proxying TCP is the point. A userspace TCP
proxy — the easy alternative — would terminate the client's connection, so the
client's TCP would see a fast local path with a stall in the middle: congestion
control, RTO and fast retransmit would all be measuring the wrong network. Here
TCP is end to end, so a dropped packet is a real drop that the real stack really
retransmits. At 5–10% loss the thing under test **is** how many round trips a
handshake needs, and a fake TCP would hide exactly that.

Each side impairs its own outbound direction, so a profile's `delay` is one-way
and the RTT is roughly double. `run.sh` measures the RTT each profile actually
produced (ICMP, same path) and records it alongside the results — **quote the
measured number, not the configured one.**

| Profile | One-way | Jitter | Loss | Rate | Meant to be |
|:--|--:|--:|--:|--:|:--|
| `clean` | – | – | – | – | the harness's own floor |
| `wifi` | 8 ms | 3 ms | 0.1% | – | decent Wi-Fi |
| `lte` | 25 ms | 10 ms | 0.5% | – | decent 4G |
| `lte-congested` | 45 ms | 25 ms | 2% | 8 Mbit | busy cell |
| `edge-hostile` | 90 ms | 40 ms | 5% | 2 Mbit | train, basement, festival |
| `awful` | 150 ms | 70 ms | 10% | 1 Mbit | the network you write retry logic for |

Why the broker runs in a network namespace at the end of a veth pair rather than
on loopback: EMQX talks to itself over `127.0.0.1` (node name `emqx@127.0.0.1`,
Erlang distribution). Shaping `lo` would put 10% loss on the **broker's
internals** as well as the client path, and the arms would be measuring a sick
broker rather than a bad network.

## What is measured

- **connect** — cold socket → CONNACK: TCP, then TLS, then the WebSocket upgrade
  where there is one, then CONNECT/CONNACK. The only place the upgrade's extra
  round trip can appear. `reconnectPeriod: 0`, so a failure is recorded as a
  failure rather than retried into a flattering number.
- **rtt** — publish on A → delivered to B, both already warm, QoS 1, at 256 B and
  16 KB. One process, one clock. This is what a user calls message latency, and
  where a per-frame byte cost would have to show up if it mattered.
- **puback** — publish → PUBACK, one round trip to the broker.
- **wire** — real bytes over the impaired link for a fixed workload, read from the
  TUN counters: IP and TCP headers and retransmissions included, not just the
  payload the app handed over.
- **recover** — abrupt socket kill (no FIN, no DISCONNECT, as a cell handover
  does) → session usable again: reconnected, resubscribed, and a message
  actually round-tripped.

## Running it

```bash
cd services/server/test/bench/transport
npm install                      # mqtt.js only; no native build
bash bed.sh up                   # namespace, veth, TUN relays, emqx, nginx
bash run.sh                      # ~25 min for the full matrix
node report.mjs results/<stamp>.jsonl
bash bed.sh down
```

Needs root (network namespaces, TUN), Docker, and `/dev/net/tun`. Subsets:

```bash
ARMS="mqtts wss-nginx" PROFILES="lte awful" CONNECTS=40 bash run.sh
bash bed.sh netem edge-hostile   # shape by hand
bash bed.sh ping                 # what the shaping actually came to
bash bed.sh exec node bench.mjs --arm=mqtts --profile=manual
```

## What this does not measure

Stated because each one bounds what the numbers can be used for.

- **No authn/authz.** Production POSTs every CONNECT to the auth server, which
  verifies a token, and reads the topic ACL from Postgres
  (`infra/deploy/emqx/emqx.conf`). Both cost the same on every transport, so
  including them would add one constant to every arm plus a Postgres round trip
  of variance. Connect numbers here are transport-only and **lower than
  production's**.
- **No Cloudflare.** This is the biggest gap, and it runs **against** the
  WSS arm here. In production `chat` is orange-clouded
  (`infra/cloudflare/dns.tf`), so a client's TCP and TLS handshakes terminate at
  a Cloudflare edge PoP typically 10–20 ms away and only the WebSocket upgrade
  travels to the origin. In this bed every handshake round trip pays the full
  impaired RTT. So the real-world WSS connect penalty is **smaller** than what
  this harness shows, and dropping Cloudflare — which raw MQTT on 8883 requires,
  since the non-Enterprise tiers proxy HTTP/WS and not raw MQTT — would make
  every handshake RTT full-distance for the `mqtts` arm too. Treat the WSS
  connect penalty measured here as an upper bound.
- **One broker, one region.** Geographic distance is modelled as delay, not as
  the multi-PoP steering sketched in `infra/multiregion`.
- **mqtt.js, not the Swift client.** The app has its own codec
  (`apps/apple/DissQus/Services/MQTTWireClient.swift`) on
  `URLSessionWebSocketTask`. Framing bytes and handshake shape are the protocol's,
  not the library's, so those transfer; absolute constants do not.
- **`recover` carries a 500 ms constant** — mqtt.js's `reconnectPeriod`. Compare
  arms against each other, not against zero.
- **TLS certificate verification is off** (self-signed bed). Not a thumb on the
  scale: SPKI pinning (`TLSPinning.swift`) is a hash comparison over a chain the
  handshake already carried, costing the same on both transports.
