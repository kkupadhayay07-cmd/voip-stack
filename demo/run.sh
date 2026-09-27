#!/usr/bin/env bash
# demo/run.sh — build and run the zrtc voice service end to end.
#
#   1. builds the zrtc daemon
#   2. starts it with demo/zrtc.toml (UDP+TCP+TLS+WSS listeners, SBC,
#      proxy, registrar, b2bua, loopback sink, ai-bridge tap, REST API)
#   3. waits for startup REGISTER of the configured AoR
#   4. probes the TCP / TLS / WSS listeners with the in-repo UAC
#   5. places one inbound call through the in-repo UAC (UDP)
#   6. the daemon originates one outbound call (built-in, after a delay)
#   7. curls GET /cdrs and prints the two CDR records
#
# Exits 0 on success (two answered CDRs, one inbound + one outbound),
# non-zero on any failure. Daemon log: /tmp/zrtc-demo.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CFG="$SCRIPT_DIR/zrtc.toml"
LOG="${ZRTC_DEMO_LOG:-/tmp/zrtc-demo.log}"
API="http://127.0.0.1:8080"
BIN="$REPO_ROOT/target/debug/zrtc"

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

say() { printf '\n==> %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    [ -f "$LOG" ] && { echo "--- daemon log tail ---" >&2; tail -n 40 "$LOG" >&2; }
    exit 1
}

say "build the zrtc daemon"
cd "$REPO_ROOT"
cargo build -p zrtc

say "start daemon with local config ($CFG), log: $LOG"
: >"$LOG"
"$BIN" --config "$CFG" >"$LOG" 2>&1 &
DAEMON_PID=$!
trap 'kill "$DAEMON_PID" 2>/dev/null || true' EXIT

say "wait for the REST API (also proves all components are up)"
READY=0
for _ in $(seq 1 50); do
    if curl -sf "$API/healthz" >/dev/null 2>&1; then READY=1; break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then fail "daemon exited during startup"; fi
    sleep 0.2
done
[ "$READY" = 1 ] || fail "REST API did not come up"
grep -q "aor .* registered" "$LOG" || sleep 1
grep -q "aor .* registered" "$LOG" || fail "startup REGISTER of the AoR did not complete"
echo "daemon up (pid $DAEMON_PID):"
grep -E "listening on|registered" "$LOG" | sed 's/^/    /'

say "probe the TCP, TLS and WSS listeners with the in-repo UAC"
"$BIN" uac --probe --transport tcp --target 127.0.0.1:5060 || fail "TCP probe"
"$BIN" uac --probe --transport tls --target 127.0.0.1:5061 || fail "TLS probe"
"$BIN" uac --probe --transport wss --target 127.0.0.1:5063 || fail "WSS probe"

say "inbound call: in-repo UAC (UDP) -> listener -> SBC -> proxy -> b2bua -> sink"
"$BIN" uac --transport udp --target 127.0.0.1:5060 \
    --to "sip:1000@zrtc.local" --call-id "demo-inbound-$(date +%s)" \
    || fail "inbound call"

say "outbound call: daemon originates INVITE to sip:sink@127.0.0.1:5090 (built-in)"
echo "    (the daemon placed it automatically after the configured delay)"

say "wait for both CDRs to be written on BYE"
count_occurrences() {
    # grep -o exits 1 when there are no matches; neutralize for pipefail.
    printf '%s' "$1" | { grep -o "$2" || true; } | wc -l | tr -d ' '
}
CDRS=""
N_IN=0
N_OUT=0
for _ in $(seq 1 100); do
    CDRS="$(curl -sf "$API/cdrs" 2>/dev/null || echo '')"
    N_IN="$(count_occurrences "$CDRS" '"direction":"inbound"')"
    N_OUT="$(count_occurrences "$CDRS" '"direction":"outbound"')"
    if [ "$N_IN" -ge 1 ] && [ "$N_OUT" -ge 1 ]; then break; fi
    sleep 0.3
done
[ -n "$CDRS" ] || fail "GET /cdrs returned nothing"
[ "$N_IN" -ge 1 ] || fail "no inbound CDR record"
[ "$N_OUT" -ge 1 ] || fail "no outbound CDR record"

say "GET /cdrs — the two call records"
if command -v jq >/dev/null 2>&1; then
    curl -sf "$API/cdrs" | jq .
else
    curl -sf "$API/cdrs"
    echo
fi

say "verdict"
printf '%s' "$CDRS" | grep -q '"disposition":"answered"' || fail "calls were not answered"
echo "PASS: two answered calls through the full pipeline"
echo "      (listener -> SBC -> proxy -> registrar/b2bua -> media -> ai-bridge),"
echo "      one inbound + one outbound CDR, written on BYE and served by GET /cdrs."
exit 0
