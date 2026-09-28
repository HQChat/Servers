# Results — MQTT-over-WSS vs raw MQTTS, 2026-09-28

One run of the full matrix: 20 cold connects, 30 messages at 256 B and 16 KB,
5 recovery cycles, and a 100-publish wire-byte workload, per arm per profile.
`results/` is gitignored (the raw JSONL is large and machine-specific), so the
tables that the argument rests on are recorded here.

Read `README.md` first for what the arms are and what this does **not** measure.
The two gaps that matter most when quoting these numbers: there is no authn/authz
in the bed (so every connect figure is **lower** than production's), and there is
no Cloudflare (so the WSS connect penalty is an **upper bound**).

## The link the arms actually saw

Measured with ICMP through the same impaired path, not the configured values.
Loss matches theory for a round trip — `awful` is 10% each way, and
`1 − 0.9² = 19%` against 18.3% observed.

| profile | RTT avg | RTT min | RTT max | ICMP loss |
|:--|--:|--:|--:|--:|
| `clean` | 0.9 ms | 0.6 ms | 2.9 ms | 0% |
| `wifi` | 17.8 ms | 7.0 ms | 27.0 ms | 1.7% |
| `lte` | 53.7 ms | 20.0 ms | 82.0 ms | 0% |
| `lte-congested` | 90.3 ms | 28.5 ms | 152.1 ms | 1.7% |
| `edge-hostile` | 183.6 ms | 89.6 ms | 394.3 ms | 10% |
| `awful` | 283.3 ms | 104.3 ms | 506.7 ms | 10% |

## Finding 1 — the WebSocket upgrade costs a round trip, and loss multiplies it

Cold connect → CONNACK, p50 / p95 in ms. No arm failed a single connection
(0/20 everywhere), so this is a latency story, not a reliability one.

| profile | `tcp-plain` | `ws-plain` | `mqtts` | `wss-direct` | `wss-nginx` |
|:--|--:|--:|--:|--:|--:|
| `clean` | 4.1 / 5.1 | 5.8 / 9.9 | 10.1 / 12.2 | 11.7 / 18.2 | 10.8 / 12.4 |
| `wifi` | 36.5 / 49.0 | 58.9 / 73.1 | 61.8 / 73.6 | 85.8 / 94.8 | 91.6 / 329.2 |
| `lte` | 99.8 / 124.1 | 174.0 / 219.0 | 174.3 / 207.8 | 245.2 / 277.7 | 250.5 / 279.9 |
| `lte-congested` | 204.5 / 247.8 | 316.5 / 741.1 | 312.5 / 382.4 | 484.9 / 928.6 | 456.3 / 899.9 |
| `edge-hostile` | 377.5 / 991.0 | 631.3 / 1321.9 | 701.7 / 2212.8 | 1105.1 / 1999.8 | 1129.4 / 2027.2 |
| `awful` | 670.3 / 2153.1 | 1280.7 / 3121.8 | 1127.3 / 3028.8 | 1718.6 / 3224.8 | 2010.6 / 4271.3 |

Production (`wss-nginx`) against the proposal (`mqtts`), p50:

| profile | penalty | as a share of RTT |
|:--|--:|--:|
| `clean` | +0.6 ms | — |
| `wifi` | +29.8 ms | 1.7× RTT |
| `lte` | +76.2 ms | 1.4× RTT |
| `lte-congested` | +143.9 ms | 1.6× RTT |
| `edge-hostile` | +427.7 ms | 2.3× RTT |
| `awful` | +883.3 ms | 3.1× RTT |

It is worth being precise about why this grows faster than RTT. One extra round
trip should cost one RTT. Above `lte-congested` it costs two or three, because
each additional round trip is another chance to lose a packet and wait out an
RTO — the penalty compounds with loss rather than adding to it. That is the
mobile case, and it is the strongest argument in favour of dropping the
WebSocket.

## Finding 2 — the WebSocket arms put roughly twice the bytes on the wire

One connect plus 100 QoS-1 publishes of 256 B. Read off the client's TUN
counters, so IP and TCP headers and retransmissions are included. Upstream
(client → broker) is the column that matters on a metered link.

| profile | `tcp-plain` ↑ | `ws-plain` ↑ | `mqtts` ↑ | `wss-nginx` ↑ | WS multiple |
|:--|--:|--:|--:|--:|--:|
| `clean` | 41.7k | 82.3k | 46.9k | 103.3k | 2.2× |
| `wifi` | 43.7k | 88.4k | 49.1k | 105.9k | 2.2× |
| `lte` | 44.7k | 88.1k | 50.6k | 107.5k | 2.1× |
| `lte-congested` | 47.0k | 104.5k | 52.1k | 119.2k | 2.3× |
| `edge-hostile` | 48.3k | 92.9k | 55.4k | 111.5k | 2.0× |
| `awful` | 53.6k | 96.5k | 59.8k | 115.5k | 1.9× |

Consistent across every profile, so it is systematic rather than variance. The
packet counters say where it comes from — at `lte`, for the identical workload:

| arm | tx bytes | tx packets | bytes/packet |
|:--|--:|--:|--:|
| `tcp-plain` | 45,821 | 326 | 141 |
| `mqtts` | 51,851 | 311 | 167 |
| `ws-plain` | 90,253 | 1,051 | 86 |
| `wss-nginx` | 110,124 | 979 | 112 |

**3.2× the packets**, at a third of the payload per packet. This is not the 2–6
bytes of WebSocket framing; it is the same MQTT packets scattered across far more
TCP segments, so per-segment IP/TCP and TLS-record overhead is paid over and over.

It also supplies the mechanism for the message-latency gap in Finding 3, which
framing bytes could not explain: three times the packets is three times the
exposure to a 5% drop.

**This finding is not yet safe to attribute to the protocol.** It may be
`mqtt.js`/`ws` writing frame header and payload as separate small writes, in
which case it says nothing about `URLSessionWebSocketTask` and does not transfer
to the app at all. Settling that is the gate on any decision — see the plan on
the pull request.

## Finding 3 — warm message latency is a wash until loss enters

Publish → delivered, 256 B, p50 in ms. Both clients already connected.

| profile | `tcp-plain` | `mqtts` | `wss-nginx` | WSS penalty |
|:--|--:|--:|--:|--:|
| `clean` | 2.1 | 2.2 | 2.3 | +0.0 |
| `wifi` | 17.9 | 18.8 | 23.5 | +4.7 |
| `lte` | 50.1 | 55.9 | 65.9 | +10.0 |
| `lte-congested` | 98.5 | 91.8 | 117.5 | +25.7 |
| `edge-hostile` | 161.3 | 172.8 | 245.5 | +72.8 |
| `awful` | 309.8 | 320.0 | 430.1 | +110.1 |

Two things to take from this.

`mqtts` and `tcp-plain` are indistinguishable on the warm path — at
`lte-congested` `mqtts` is nominally *faster* (91.8 vs 98.5), which is variance,
not a real effect. **TLS costs nothing per message.** Anyone proposing plaintext
for speed is paying in confidentiality for a number that is not there.

At 16 KB the ordering breaks down entirely (`lte` p50: `tcp-plain` 141.2 vs
`wss-direct` 96.8) because a 16 KB message spans a dozen packets and a single
loss dominates whatever the transport did. Do not read anything into the large
payload numbers beyond "loss decides it".

## Finding 4 — recovery is dominated by a constant we chose

Abrupt socket kill → message round-trips again, p50 in ms. Every arm carries
mqtt.js's 500 ms `reconnectPeriod`, so compare arms, never against zero.

| profile | `tcp-plain` | `mqtts` | `wss-nginx` |
|:--|--:|--:|--:|
| `clean` | 507.0 | 516.1 | 515.6 |
| `lte` | 721.3 | 806.1 | 909.6 |
| `edge-hostile` | 1384.8 | 1826.7 | 2287.0 |
| `awful` | 2332.5 | 3056.5 | 4005.5 |

The transport ordering holds, but the headline is the 500 ms floor: **the
reconnect policy matters more than the transport.** The app's own settings are
larger still — `keepalive = 60` with a ping at half that
(`MQTTWireClient.swift:379`), so a link that dies silently can go unnoticed for
tens of seconds. No transport change touches that, and it is worth more than
every number above.

## What this run does not answer

- Whether Finding 2 survives a client that coalesces its writes. Everything else
  hinges on it.
- Where production actually lands, because Cloudflare terminates TLS near the
  user and this bed does not. The `wss-edge-warm` / `wss-edge-cold` arms were
  added for this and had not run when these numbers were taken.
- Whether TLS 1.3 session resumption recovers the connect penalty without any
  transport change. Cheapest untested idea on the list.

## Addendum — the `hqn` arm (hqn/1 over raw TCP), and what HQC-256 costs

The transport this benchmark led to is MQTT over raw TCP inside **hqn/1**, a
hybrid X25519 + HQC-256 Noise handshake whose first flight carries the CONNECT
(`services/server/lib/noise.ts`), through `noise-gw`. `bed.sh` now starts the
gateway and `run.sh` includes `hqn` in its default arms, so the next full run
puts it in every table above.

**Not yet run on the Linux bed** (the impairment needs root, TUN and netns).
What has been run is a sanity pass of the arm itself, unimpaired, on a laptop
(Apple M2 Pro, EMQX in Docker, gateway on the host):

| metric | hqn, loopback |
|:--|--:|
| connect p50 / p95 | 49.0 / 55.1 ms (15/15) |
| rtt 256 B p50 / p95 | 2.0 / 5.6 ms (15/15) |
| recover p50 | 566 ms (3/3; mqtt.js's 500 ms reconnect floor) |

The connect figure is almost entirely **CPU**, not network — measured directly
on the same machine:

| operation | time | who pays |
|:--|--:|:--|
| HQC-256 encapsulate | 11.3 ms | the client, per connect |
| HQC-256 decapsulate | 17.1 ms | the gateway, per connect |
| X25519 | 0.03 ms | both |

What that means, before the impaired numbers exist:

- hqn/1 adds ~28 ms of computation to every connect. Against `wss-nginx` that
  is still a win wherever the WebSocket penalty exceeds it — `lte` (+76 ms),
  `lte-congested` (+144 ms) and every lossier profile — and roughly break-even
  on `wifi` (+30 ms). The ~14.7 kB first flight's own cost under loss is what
  the full matrix will add on top.
- Gateway capacity is decapsulation-bound: ~60 full handshakes per second per
  core at this speed. A reconnect storm after a gateway restart is CPU work,
  which is what noise-gw's bounded decapsulation queue (it sheds to WSS rather
  than queueing) and the client's WSS fallback are for. Measure on the
  production CPU before sizing: the HQC build may differ (AVX2 on x86).

To run the full matrix including `hqn`, as before:

```bash
sudo bash bed.sh up && sudo bash run.sh
```
