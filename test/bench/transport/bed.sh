#!/usr/bin/env bash
#
# bed.sh — stand up / tear down the transport benchmark test bed.
#
#   bash bed.sh up      # broker + proxy + impairable client namespace
#   bash bed.sh down
#   bash bed.sh netem <profile>   # re-shape the client<->broker path
#   bash bed.sh ping              # observed RTT under the current shaping
#
# Why a network namespace instead of just netem on `lo`: EMQX talks to itself
# over 127.0.0.1 (node name emqx@127.0.0.1, Erlang distribution). Shaping `lo`
# would put 10% loss on the BROKER'S INTERNALS as well as on the client path,
# so the arms would be measuring a sick broker rather than a bad network. A
# veth pair impairs exactly one hop: client -> broker.
#
#   [ netns: client ]  veth-c 10.77.0.2  <== netem ==>  veth-h 10.77.0.1  [ host: emqx + nginx ]
#
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"

NS=bench-client
VETH_H=veth-bh
VETH_C=veth-bc
HOST_IP=10.77.0.1
CLIENT_IP=10.77.0.2
NAME_MQ=hqcat-bench-emqx
NAME_NX=hqcat-bench-nginx

# The impaired address the bench connects to. Traffic to it rides the TUN pair
# through impair.py; the veth addresses below are only the unimpaired carrier
# those TUN packets are tunnelled over.
BROKER_IP=10.88.0.1
CLIENT_TUN_IP=10.88.0.2
TUN_H=tun-bh
TUN_C=tun-bc
MTU=1400

up() {
  down >/dev/null 2>&1 || true

  echo "→ namespace + veth"
  ip netns add "$NS"
  ip link add "$VETH_H" type veth peer name "$VETH_C"
  ip link set "$VETH_C" netns "$NS"
  ip addr add "$HOST_IP/24" dev "$VETH_H"
  ip link set "$VETH_H" up
  ip netns exec "$NS" ip addr add "$CLIENT_IP/24" dev "$VETH_C"
  ip netns exec "$NS" ip link set "$VETH_C" up
  ip netns exec "$NS" ip link set lo up
  # The default 1000-packet FIFO on a veth is deep enough to hide a bandwidth
  # cap's queueing; netem replaces it per profile anyway, but say so explicitly.
  ip netns exec "$NS" ip link set "$VETH_C" txqueuelen 1000
  ip link set "$VETH_H" txqueuelen 1000

  echo "→ emqx (host network, all four listeners)"
  docker run -d --name "$NAME_MQ" --network host \
    -v "$HERE/emqx-bench.conf:/opt/emqx/etc/emqx.conf:ro" \
    -v "$HERE/certs:/bench/certs:ro" \
    emqx/emqx:5.8 >/dev/null

  echo "→ nginx (host network, :8443 → emqx :8083)"
  docker run -d --name "$NAME_NX" --network host \
    -v "$HERE/nginx-bench.conf:/etc/nginx/nginx.conf:ro" \
    -v "$HERE/certs:/bench/certs:ro" \
    nginx:1.27-alpine >/dev/null

  echo "→ noise-gw (hqn/1, host network, :9883 → emqx :1883)"
  # Throwaway keys, made fresh for every bed. The bench reads the public half.
  local server; server="$(cd "$HERE/../../.." && pwd)"
  mkdir -p "$HERE/hqn"; rm -f "$HERE/hqn/keys.json" "$HERE/hqn/public.json"
  (cd "$server" && npx tsx scripts/noise-gw-keys.ts --key-id 1 \
      --secret "$HERE/hqn/keys.json" --public "$HERE/hqn/public.json" >/dev/null)
  (cd "$server" && NOISE_KEYS_FILE="$HERE/hqn/keys.json" NOISE_GW_PORT=9883 \
      NOISE_GW_HEALTH_PORT=9881 EMQX_TCP_HOST=127.0.0.1 EMQX_TCP_PORT=1883 LOG_LEVEL=warn \
      setsid node --import tsx noise-gw/main.ts > "$HERE/hqn/gw.log" 2>&1 &)

  # The carrier must hold a tunnelled 1400-byte packet plus UDP/IP headers
  # without fragmenting, or every full-size TCP segment becomes two carrier
  # datagrams and a single carrier loss takes out a fragment pair.
  ip link set "$VETH_H" mtu 1600
  ip netns exec "$NS" ip link set "$VETH_C" mtu 1600

  shape "${PROFILE:-clean}"

  echo "→ waiting for listeners"
  for port in 1883 8083 8883 8084 8443 9883; do
    ok=0
    for _ in $(seq 1 60); do
      if ip netns exec "$NS" bash -c "exec 3<>/dev/tcp/$BROKER_IP/$port" 2>/dev/null; then ok=1; break; fi
      sleep 1
    done
    if [ "$ok" = 1 ]; then
      echo "   :$port up"
    else
      echo "   :$port NEVER CAME UP" >&2; docker logs --tail 30 "$NAME_MQ" >&2; exit 1
    fi
  done
  echo "test bed up"
}

down() {
  pkill -f "impair.py --tun $TUN_H" >/dev/null 2>&1 || true
  pkill -f "impair.py --tun $TUN_C" >/dev/null 2>&1 || true
  pkill -f "noise-gw/main.ts" >/dev/null 2>&1 || true
  docker rm -f "$NAME_MQ" "$NAME_NX" >/dev/null 2>&1 || true
  ip link del "$TUN_H" >/dev/null 2>&1 || true
  ip netns del "$NS" >/dev/null 2>&1 || true
  ip link del "$VETH_H" >/dev/null 2>&1 || true
  echo "test bed down"
}

# Restart both relays under a new profile. Cheap enough (~200ms) to do between
# every arm, and restarting rather than reconfiguring guarantees no queued
# packet from the previous profile leaks into the next measurement.
shape() {
  local prof="$1"
  pkill -f "impair.py --tun $TUN_H" >/dev/null 2>&1 || true
  pkill -f "impair.py --tun $TUN_C" >/dev/null 2>&1 || true
  ip link del "$TUN_H" >/dev/null 2>&1 || true
  ip netns exec "$NS" ip link del "$TUN_C" >/dev/null 2>&1 || true

  setsid python3 "$HERE/impair.py" --tun "$TUN_H" --addr "$BROKER_IP/24" \
    --carrier-bind "$HOST_IP:9999" --carrier-peer "$CLIENT_IP:9999" \
    --profile "$prof" --mtu "$MTU" >>/tmp/impair-h.log 2>&1 &
  ip netns exec "$NS" setsid python3 "$HERE/impair.py" --tun "$TUN_C" --addr "$CLIENT_TUN_IP/24" \
    --carrier-bind "$CLIENT_IP:9999" --carrier-peer "$HOST_IP:9999" \
    --profile "$prof" --mtu "$MTU" >>/tmp/impair-c.log 2>&1 &

  for _ in $(seq 1 40); do
    ip link show "$TUN_H" >/dev/null 2>&1 && ip netns exec "$NS" ip link show "$TUN_C" >/dev/null 2>&1 && break
    sleep 0.1
  done
  sleep 0.4
  echo "profile '$prof' active (one-way; RTT is ~2x the delay — run 'bed.sh ping')"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  netem) shape "${2:?profile required}" ;;
  ping) ip netns exec "$NS" ping -q -c "${2:-20}" -i 0.2 -W 3 "$BROKER_IP" | tail -2 ;;
  exec) shift; exec ip netns exec "$NS" "$@" ;;
  *) echo "usage: bed.sh up|down|netem <profile>|ping|exec <cmd…>" >&2; exit 2 ;;
esac
