#!/usr/bin/env bash
#
# run-local.sh — the end-to-end suite, on your own machine, for free.
#
# The CI job that runs this is opt-in on pull requests (label a PR `run-e2e`),
# because standing up a broker, an API and an auth server costs Actions minutes
# on every push. That is the same trade the Apple job made when it moved to
# apps/apple/verify.sh: the coverage is worth having, paying for it on every
# iteration is not.
#
#   bash services/server/test/e2e/run-local.sh
#
# Needs Docker (for Postgres and EMQX) and the native HQC library. The suite
# skips cleanly rather than failing if either is missing.
set -euo pipefail

cd "$(dirname "$0")/../.."          # services/server
ROOT="$(cd ../.. && pwd)"

PG_PORT="${PG_PORT:-55432}"
MQTT_PORT="${MQTT_PORT:-58083}"
API_PORT="${API_PORT:-58080}"
AUTH_PORT="${AUTH_PORT:-58081}"
MQTT_TCP_PORT="${MQTT_TCP_PORT:-51883}"
HQN_PORT="${HQN_PORT:-58443}"
HQN_HEALTH_PORT="${HQN_HEALTH_PORT:-58444}"
NAME_PG="hqcat-e2e-pg"
NAME_MQ="hqcat-e2e-emqx"

step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

# macOS has no setsid(1). The servers below are started with it so cleanup can
# kill each one's whole process group; without it the script died at the first
# `setsid` on a Mac. The fallback EXECs, so a backgrounded call's $! is the
# session leader itself — the pid cleanup's `kill -- -pid` needs.
if ! command -v setsid >/dev/null 2>&1; then
  setsid() { exec perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV or die "exec: $!"' -- "$@"; }
fi
cleanup() {
  step "Tearing down"
  # Kill the PROCESS GROUP, not the pid. `npm run api` is a wrapper that execs
  # tsx, which spawns node — killing the wrapper leaves the server running and
  # holding its port. Two of those survived a run and answered the NEXT run's
  # health check, so the new servers' configuration was never the one under
  # test; that is how a raised rate limit appeared to have no effect. `setsid`
  # below puts each server in its own group so this can reach all of it.
  for pid in "${API_PID:-}" "${AUTH_PID:-}" "${GW_PID:-}"; do
    [ -n "$pid" ] || continue
    kill -- -"$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  done
  docker rm -f "$NAME_PG" "$NAME_MQ" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "❌ docker is required" >&2; exit 1; }

step "Postgres"
docker rm -f "$NAME_PG" >/dev/null 2>&1 || true
docker run -d --name "$NAME_PG" \
  -e POSTGRES_USER=hqcat -e POSTGRES_PASSWORD=hqcat -e POSTGRES_DB=hqcat \
  -p "${PG_PORT}:5432" postgres:17-alpine >/dev/null
until docker exec "$NAME_PG" pg_isready -U hqcat -d hqcat >/dev/null 2>&1; do sleep 1; done

export DATABASE_URL="postgresql://hqcat:hqcat@localhost:${PG_PORT}/hqcat"
export ADMISSION_POLICY=open
step "Migrate"
npm run migrate

# The broker runs the REAL config, rendered exactly as CI renders it — see the
# long note in .github/workflows/ci.yml for why each substitution differs from
# production. The short version: CI and this script reach Postgres directly,
# production reaches it through PgBouncer, and `disable_prepared_statements`
# has to flip for that.
step "EMQX (with the deployment's authorizer)"
HOST_GW="host.docker.internal"
sed -e "s|__PG_SERVER__|${HOST_GW}:${PG_PORT}|" \
    -e "s|__PG_HOST__|${HOST_GW}|" \
    -e "s|__PG_DATABASE__|hqcat|" \
    -e "s|__PG_USERNAME__|hqcat|" \
    -e "s|__PG_PASSWORD__|hqcat|" \
    -e "s|__PG_SSL__|false|" \
    -e "/cacertfile = /d" \
    -e "s|disable_prepared_statements = true|disable_prepared_statements = false|" \
    -e "s|//auth:8080/mqtt/authn|//${HOST_GW}:${AUTH_PORT}/mqtt/authn|" \
    "$ROOT/infra/deploy/emqx/emqx.conf" > /tmp/hqcat-e2e-emqx.conf
grep -q "__PG_" /tmp/hqcat-e2e-emqx.conf && { echo "❌ unrendered placeholders"; exit 1; } || true

# The API and auth start FIRST: EMQX's authn webhook fails its initial connect
# otherwise, marks the resource down, and refuses every CONNECT until it retries.
# /auth/init is rate-limited per IP — 20 a minute by default (ASVS-3, which
# closed deliberately and should stay closed). Every client this harness makes
# comes from 127.0.0.1, so the whole suite shares one bucket: the e2e run spends
# part of it and the load test, which registers 2 x LOAD_PAIRS clients in a
# burst, then gets 429 on its first `register`. That is the limiter working, not
# a bug in it.
#
# So the LOCAL stack gets a limit the local harness cannot trip. Deliberately
# not a change to the default in auth/main.ts: raising a rate limit in
# production to make a test pass is how a rate limit stops meaning anything.
step "API + auth"
export AUTH_INIT_IP_LIMIT="${AUTH_INIT_IP_LIMIT:-2000}"
setsid env PORT="$API_PORT"  npm run api  > /tmp/hqcat-e2e-api.log  2>&1 & API_PID=$!
# auth advertises the local gateway exactly as production would: opt-in, keys
# read from the gateway itself (which starts later — the route asks at request
# time, and an absent gateway is simply not advertised).
# MQTT_LEGACY_TOKEN=0: every client in this repo signs its CONNECT (v1), and
# this run proves it — anything still presenting the old token is refused.
setsid env PORT="$AUTH_PORT" MQTT_LEGACY_TOKEN=0 HQN_ENABLED=1 HQN_PUBLIC_HOST=127.0.0.1 HQN_PUBLIC_PORT="$HQN_PORT" \
  HQN_GATEWAY_KEYS_URL="http://localhost:${HQN_HEALTH_PORT}/keys" \
  npm run auth > /tmp/hqcat-e2e-auth.log 2>&1 & AUTH_PID=$!
for _ in $(seq 1 30); do
  curl -fsS "http://localhost:${API_PORT}/health"  >/dev/null 2>&1 &&
  curl -fsS "http://localhost:${AUTH_PORT}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://localhost:${API_PORT}/health"  >/dev/null || { cat /tmp/hqcat-e2e-api.log;  exit 1; }
curl -fsS "http://localhost:${AUTH_PORT}/health" >/dev/null || { cat /tmp/hqcat-e2e-auth.log; exit 1; }

docker rm -f "$NAME_MQ" >/dev/null 2>&1 || true
docker run -d --name "$NAME_MQ" \
  --add-host "${HOST_GW}:host-gateway" \
  -p "${MQTT_PORT}:8083" \
  -p "${MQTT_TCP_PORT}:1883" \
  -v /tmp/hqcat-e2e-emqx.conf:/opt/emqx/etc/emqx.conf:ro \
  emqx/emqx:5.8 >/dev/null
for _ in $(seq 1 40); do
  docker exec "$NAME_MQ" emqx ctl status >/dev/null 2>&1 && break
  sleep 2
done
docker exec "$NAME_MQ" emqx ctl status >/dev/null \
  || { echo "❌ emqx did not start"; docker logs "$NAME_MQ"; exit 1; }
for _ in $(seq 1 30); do
  docker exec "$NAME_MQ" emqx ctl alarms list 2>/dev/null \
    | grep -qiE "authn|authz|resource" || break
  echo "waiting for the auth resources…"; sleep 2
done

# EXPORTED, not prefixed onto one command. They used to be a prefix on
# `npm run test:e2e`, which applies to that command and nothing after it — so
# `npm run test:load` below ran with none of them, fell back to the defaults in
# test/helpers/mqtt-client.ts (ports 8080/8081/8083, where nothing is listening
# because this script uses 58080/58081/58083), found no stack, and SKIPPED all
# three tests. The step printed "ok" three times and the script exited 0.
#
# That is why LAT-4 was never closed: `LOAD=1 bash run-local.sh` is the
# documented way to close it, and it could not have measured anything.
export TEST_AUTH_URL="http://localhost:${AUTH_PORT}"
export TEST_API_URL="http://localhost:${API_PORT}"
export TEST_EMQX_URL="ws://localhost:${MQTT_PORT}/mqtt"

# noise-gw — the raw-TCP transport (hqn/1) — in front of EMQX's internal TCP
# listener, with throwaway keys. test/e2e/hqn.test.ts connects through it.
step "noise-gw"
HQN_KEYS="$(mktemp -d)/noise_keys"
printf '{"keys":[{"keyId":1,"x25519":"%s","hqcSeed":"%s"}]}\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > "$HQN_KEYS"
setsid env NOISE_KEYS_FILE="$HQN_KEYS" NOISE_GW_PORT="$HQN_PORT" NOISE_GW_HEALTH_PORT="$HQN_HEALTH_PORT" \
  EMQX_TCP_HOST=127.0.0.1 EMQX_TCP_PORT="$MQTT_TCP_PORT" \
  npm run noise-gw > /tmp/hqcat-e2e-noise-gw.log 2>&1 & GW_PID=$!
for _ in $(seq 1 30); do
  curl -fsS "http://localhost:${HQN_HEALTH_PORT}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://localhost:${HQN_HEALTH_PORT}/health" >/dev/null || { cat /tmp/hqcat-e2e-noise-gw.log; exit 1; }
export TEST_HQN_HOST=127.0.0.1
export TEST_HQN_PORT="$HQN_PORT"
export TEST_HQN_KEYS_URL="http://localhost:${HQN_HEALTH_PORT}/keys"

step "E2E"
npm run test:e2e

# The helper bot, live: it signs its CONNECT with a fresh v1 proof on every
# (re)connect. auth runs with MQTT_LEGACY_TOKEN=0 here, so "connected" means the
# proof was accepted — the one in-repo client the suite above does not start.
step "Helper bot connects with a signed CONNECT"
BOT_DIR="$(mktemp -d)"
setsid env AUTH_BASE_URL="http://localhost:${AUTH_PORT}" API_BASE_URL="http://localhost:${API_PORT}" \
  EMQX_URL="ws://localhost:${MQTT_PORT}/mqtt" BOT_STATE_DIR="$BOT_DIR" BOT_USERNAME="helper" \
  npm run bot > /tmp/hqcat-e2e-bot.log 2>&1 & BOT_PID=$!
for _ in $(seq 1 45); do
  grep -q "connected to EMQX" /tmp/hqcat-e2e-bot.log && break
  sleep 1
done
kill -- -"$BOT_PID" 2>/dev/null || kill "$BOT_PID" 2>/dev/null || true
if grep -q "connected to EMQX" /tmp/hqcat-e2e-bot.log; then
  echo "  ✓ the bot's signed CONNECT was accepted (legacy token refused)"
else
  echo "  ✗ the bot did not connect:"; tail -20 /tmp/hqcat-e2e-bot.log; exit 1
fi

# The Swift client, live: the app's own MQTT code over hqn/1 through noise-gw,
# and over WSS. macOS only (it needs xcrun and the native HQC dylib).
if [ "$(uname)" = "Darwin" ] && command -v xcrun >/dev/null; then
  step "Swift client over hqn/1 and WSS"
  bash "$ROOT/apps/apple/e2e/hqn-live/run.sh"
fi

  # The load test is separate and opt-in: it stands up 20+ clients and
  # deliberately saturates the broker, which is not a state the suite above
  # expects to inherit. Run it when you want the measurement.
  if [ -n "${LOAD:-}" ]; then
    step "Load (LAT-4)"
    # LOAD=1 is someone asking for the measurement. A skip is then a failure,
    # not a courtesy: the whole point of this step is that a number comes out
    # of it, and "skipped" reporting as success is what hid the bug above.
    LOAD_REQUIRED=1 npm run test:load
  else
    echo ""
    echo "  (load test skipped — LOAD=1 bash $0 to run it)"
  fi
