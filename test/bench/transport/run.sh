#!/usr/bin/env bash
#
# run.sh — drive the whole matrix: every arm under every impairment profile.
#
#   bash bed.sh up
#   bash run.sh                       # all arms, all profiles
#   ARMS="mqtts wss-nginx" PROFILES="lte awful" bash run.sh
#
# Results are appended as JSONL to results/<stamp>.jsonl; report.mjs turns that
# into the tables. One process per (profile, arm) so no TLS session cache, warm
# socket or mqtt.js state survives from one arm into the next.
#
# Ordering note: arms are run in a fixed order inside each profile, and each
# profile re-creates the impairment relays (bed.sh netem) so no queued packet
# crosses a boundary. The arms within a profile share a machine and a broker, so
# they see the same background noise — which is the comparison that matters.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"

NS=bench-client
CLIENT_TUN=tun-bc
# mqtt is installed next to this file (see package.json); ESM ignores NODE_PATH,
# so the harness carries its own node_modules rather than borrowing the
# server's, which builds native HQC bindings this benchmark has no use for.

ARMS="${ARMS:-tcp-plain ws-plain mqtts wss-direct wss-nginx hqn}"
PROFILES="${PROFILES:-clean wifi lte lte-congested edge-hostile awful}"
CONNECTS="${CONNECTS:-20}"
MSGS="${MSGS:-40}"
RECOVERS="${RECOVERS:-5}"
SIZES="${SIZES:-256,16384}"
WIRE_MSGS="${WIRE_MSGS:-100}"
WIRE_SIZE="${WIRE_SIZE:-256}"

mkdir -p results
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="results/${STAMP}.jsonl"
echo "→ results: $OUT"

in_ns() { ip netns exec "$NS" "$@"; }

# The `wss-edge-*` arms need edge.mjs running INSIDE the client namespace, so the
# client's TLS terminates locally (as it does at a Cloudflare PoP) and only the
# upgrade and CONNECT cross the impaired path. Started per arm and stopped after,
# so its warm pool is built fresh under the profile being measured rather than
# carrying connections established under the previous one.
EDGE_PID=""
start_edge() {
  local mode="$1" port="$2"
  ip netns exec "$NS" setsid node edge.mjs --mode="$mode" --listen="$port" \
    --originHost=10.88.0.1 --originPort=8084 >>/tmp/edge.log 2>&1 &
  EDGE_PID=$!
  # Give the warm pool time to finish its handshakes over the impaired path;
  # on the worst profile a TLS handshake alone can take most of a second.
  for _ in $(seq 1 60); do
    ip netns exec "$NS" bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null && break
    sleep 0.2
  done
  sleep 2
}
stop_edge() {
  [ -n "$EDGE_PID" ] || return 0
  kill -TERM -- -"$EDGE_PID" 2>/dev/null || kill -TERM "$EDGE_PID" 2>/dev/null || true
  EDGE_PID=""
  sleep 0.3
}

# Real bytes on the impaired link, straight off the client's TUN counters. This
# is the honest answer to "what does the framing cost": it counts IP and TCP
# headers and retransmissions, not just the payload the application handed over.
tun_bytes() {
  # shellcheck disable=SC2016  # ${…} is a JavaScript template literal, not shell
  ip netns exec "$NS" ip -s -j link show "$CLIENT_TUN" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const l=JSON.parse(s)[0];console.log(`${l.stats64.rx.bytes} ${l.stats64.tx.bytes} ${l.stats64.rx.packets} ${l.stats64.tx.packets}`)})'
}

# The RTT the arms actually saw, not the number configured in impair.py. Always
# quote this one when reporting.
# `ping -q` summary, with `-F'[ /=]+'` collapsing " = " and the "/" separators:
#   "rtt min/avg/max/mdev = 9.837/15.955/25.235/5.508 ms"  -> $6 $7 $8 are min avg max
#   "… , 0% packet loss, …"                                -> $6 is the loss, with its %
measure_rtt() {
  ip netns exec "$NS" ping -q -c 60 -i 0.05 -W 3 10.88.0.1 2>/dev/null \
    | awk -F'[ /=]+' '/packet loss/{loss=$6; sub(/%/,"",loss)} /rtt min/{print $6" "$7" "$8" "loss}'
}

for profile in $PROFILES; do
  echo ""
  echo "════ profile: $profile ════"
  bash bed.sh netem "$profile" >/dev/null 2>&1
  sleep 1
  read -r ping_min ping_avg ping_max ping_loss <<<"$(measure_rtt)"
  echo "   measured: rtt avg ${ping_avg}ms (min ${ping_min} / max ${ping_max}), icmp loss ${ping_loss}%"
  node -e "console.log(JSON.stringify({kind:'calibration',profile:process.argv[1],rtt_min:+process.argv[2],rtt_avg:+process.argv[3],rtt_max:+process.argv[4],icmp_loss_pct:+process.argv[5]}))" \
    "$profile" "$ping_min" "$ping_avg" "$ping_max" "${ping_loss:-0}" >> "$OUT"

  for arm in $ARMS; do
    printf "   %-14s " "$arm"

    case "$arm" in
      wss-edge-warm) start_edge warm 9443 ;;
      wss-edge-cold) start_edge cold 9444 ;;
    esac

    # --- latency / recovery -------------------------------------------------
    # hqn/1 runs the server's TypeScript (lib/noise.ts, native HQC), so that arm
    # alone gets the tsx loader and the gateway's public keys.
    NODE_ARGS=(); ARM_ARGS=()
    if [ "$arm" = hqn ]; then
      NODE_ARGS=(--import "$HERE/../../../node_modules/tsx/dist/loader.mjs")
      ARM_ARGS=(--hqnKeys="$HERE/hqn/public.json")
    fi

    if line="$(in_ns node "${NODE_ARGS[@]}" bench.mjs "${ARM_ARGS[@]}" \
        --arm="$arm" --profile="$profile" \
        --connects="$CONNECTS" --msgs="$MSGS" --recovers="$RECOVERS" --sizes="$SIZES" \
        2>/dev/null | tail -1)" && [ -n "$line" ]; then
      echo "$line" >> "$OUT"
      # shellcheck disable=SC2016  # ${…} is a JavaScript template literal, not shell
      echo "$line" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const o=JSON.parse(s);const c=o.connect,m=o.messages&&o.messages[256]&&o.messages[256].rtt;process.stdout.write(`connect p50 ${String(c.p50).padStart(7)}ms p95 ${String(c.p95).padStart(7)}ms fail ${c.failures}/${c.n+c.failures} | rtt256 p50 ${String(m?m.p50:"-").padStart(7)}ms p95 ${String(m?m.p95:"-").padStart(7)}ms\n`)})'
    else
      echo "FAILED"
      node -e "console.log(JSON.stringify({kind:'error',arm:process.argv[1],profile:process.argv[2]}))" "$arm" "$profile" >> "$OUT"
    fi

    # --- wire bytes for a fixed workload -----------------------------------
    read -r rx0 tx0 rxp0 txp0 <<<"$(tun_bytes)"
    in_ns node "${NODE_ARGS[@]}" bench.mjs "${ARM_ARGS[@]}" --arm="$arm" --profile="$profile" --only=wire \
      --wireMsgs="$WIRE_MSGS" --wireSize="$WIRE_SIZE" >/dev/null 2>&1 || true
    sleep 0.5
    read -r rx1 tx1 rxp1 txp1 <<<"$(tun_bytes)"
    node -e '
      const [a,b,c,d,e,f,g,h,arm,profile,msgs,size]=process.argv.slice(1);
      console.log(JSON.stringify({kind:"wire",arm,profile,msgs:+msgs,size:+size,
        rx_bytes:+e-+a, tx_bytes:+f-+b, rx_pkts:+g-+c, tx_pkts:+h-+d}));
    ' "$rx0" "$tx0" "$rxp0" "$txp0" "$rx1" "$tx1" "$rxp1" "$txp1" "$arm" "$profile" "$WIRE_MSGS" "$WIRE_SIZE" >> "$OUT"

    stop_edge
  done
done

echo ""
echo "→ done: $OUT"
echo "→ report: node report.mjs $OUT"
