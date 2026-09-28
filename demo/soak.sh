#!/usr/bin/env bash
# demo/soak.sh — load-harness soak: N concurrent calls through the full
# zrtc pipeline (listener → SBC → proxy → registrar/b2bua → sink → media).
#
#   1. builds the zrtc daemon
#   2. starts it with demo/zrtc.toml (same config as demo/run.sh)
#   3. waits for the REST API
#   4. runs `zrtc load` (CALLS / CONCURRENCY / RTP_MS env-overridable)
#   5. cross-checks the daemon CDR count against the answered calls
#   6. prints the load report (human + JSON)
#
# Exits non-zero if any call fails or the CDR cross-check mismatches.
# Daemon log: /tmp/zrtc-soak.log
#
# Environment:
#   CALLS        total call attempts   (default 1000)
#   CONCURRENCY  max calls in flight   (default 100)
#   RTP_MS       media per call in ms  (default 500)
#   BUILD_MODE   debug | release       (default debug; release is the
#               benchmark-mode build — debug numbers understate the stack)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CFG="$SCRIPT_DIR/zrtc.toml"
LOG="${ZRTC_SOAK_LOG:-/tmp/zrtc-soak.log}"
API="http://127.0.0.1:8080"
BIN="$REPO_ROOT/target/${BUILD_MODE:-debug}/zrtc"
CALLS="${CALLS:-1000}"
CONCURRENCY="${CONCURRENCY:-100}"
RTP_MS="${RTP_MS:-500}"

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

say() { printf '\n==> %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    [ -f "$LOG" ] && { echo "--- daemon log tail ---" >&2; tail -n 40 "$LOG" >&2; }
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null || true
    exit 1
}

say "pre-flight: the target ports must be free (a stale daemon poisons the run)"
if ss -uln 2>/dev/null | grep -q ':5060 '; then
    fail "UDP :5060 already in use — kill the stale zrtc first"
fi
if ss -tlnp 2>/dev/null | grep -q ':8080 '; then
    fail "TCP :8080 already in use — kill the stale zrtc first"
fi

say "build the zrtc daemon (${BUILD_MODE:-debug})"
cd "$REPO_ROOT"
if [ "${BUILD_MODE:-debug}" = "release" ]; then
    cargo build --release -p zrtc
else
    cargo build -p zrtc
fi

say "start daemon with local config ($CFG), log: $LOG"
: >"$LOG"
"$BIN" --config "$CFG" >"$LOG" 2>&1 &
DAEMON_PID=$!
cleanup() {
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 0.3
    kill -9 "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT

say "wait for the REST API"
READY=0
for _ in $(seq 1 50); do
    if curl -sf "$API/healthz" >/dev/null 2>&1; then READY=1; break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then fail "daemon exited during startup"; fi
    sleep 0.2
done
[ "$READY" = 1 ] || fail "REST API did not come up"

say "soak: $CALLS calls, concurrency $CONCURRENCY, rtp ${RTP_MS} ms"
JSON="$(mktemp /tmp/zrtc-load-report.XXXXXX.json)"
set +e
"$BIN" load \
    --transport udp --target 127.0.0.1:5060 \
    --to "sip:1000@zrtc.local" \
    --calls "$CALLS" --concurrency "$CONCURRENCY" --rtp-ms "$RTP_MS" \
    --tail-ms 150 --timeout-secs 30 --json >"$JSON"
RC=$?
set -e
cat "$JSON"
echo
if [ "$RC" -ne 0 ]; then
    fail "load run exited with $RC (see report above)"
fi

say "daemon CDR cross-check"
# The CDR store is bounded; count answered inbound CDRs served by the API.
CDRS="$(curl -sf "$API/cdrs" 2>/dev/null || echo '')"
N_ANSWERED="$(printf '%s' "$CDRS" | grep -o '"disposition":"answered"' | wc -l | tr -d ' ')"
ANSWERED="$(python3 -c "import json,sys; print(json.load(open('$JSON'))['answered'])")"
echo "daemon answered CDRs served: $N_ANSWERED; load report answered: $ANSWERED"
if [ "$N_ANSWERED" -lt "$ANSWERED" ]; then
    fail "daemon served fewer answered CDRs ($N_ANSWERED) than the load report ($ANSWERED)"
fi

if grep -qi "panic" "$LOG"; then
    fail "daemon log contains a panic"
fi

say "verdict"
echo "PASS: $ANSWERED answered calls through the full pipeline at concurrency $CONCURRENCY"
exit 0
