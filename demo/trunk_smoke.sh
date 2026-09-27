#!/usr/bin/env bash
# demo/trunk_smoke.sh — smoke-test the vendor trunk layer against the local
# daemon (the "vendor" is the daemon's own SBC/registrar).
#
#   ZRTC_TRUNK_AUTH=ip | digest | bearer | tls_client_cert   (default ip)
#   ZRTC_TRUNK_REGISTER=0 | 1      REGISTER on start          (default 0;
#                                  digest + register=1 exercises the 401
#                                  challenge path against the local registrar)
#
# The script builds a temp config on dedicated ports, starts the daemon,
# prints the "trunk configured: ..." line, places one call out the trunk
# (zrtc call 1000), and prints the resulting CDR. Exit 0 on success.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG="${ZRTC_TRUNK_SMOKE_LOG:-/tmp/zrtc-trunk-smoke.log}"
API="http://127.0.0.1:18080"

MODE="${ZRTC_TRUNK_AUTH:-ip}"
REGISTER="${ZRTC_TRUNK_REGISTER:-0}"
TRUNK_USER="${ZRTC_TRUNK_USER:-smokeuser}"
TRUNK_PASS="${ZRTC_TRUNK_PASS:-smokepass}"
TRUNK_TOKEN="${ZRTC_TRUNK_TOKEN:-smoke-token}"

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable SC1091
    source "$HOME/.cargo/env"
fi

say() { printf '\n==> %s\n' "$*"; }

case "$MODE" in
    ip|digest|bearer|tls_client_cert) : ;;
    *) echo "unknown ZRTC_TRUNK_AUTH '$MODE' (ip|digest|bearer|tls_client_cert)" >&2; exit 2 ;;
esac

say "build the zrtc daemon"
cd "$REPO_ROOT"
cargo build -p zrtc
BIN="$REPO_ROOT/target/debug/zrtc"

TMPDIR_SMOKE="$(mktemp -d /tmp/zrtc-trunk-smoke.XXXXXX)"
CFG="$TMPDIR_SMOKE/zrtc-smoke.toml"
trap 'kill "$DAEMON_PID" 2>/dev/null || true; rm -rf "$TMPDIR_SMOKE"' EXIT

CERTS=""
if [ "$MODE" = "tls_client_cert" ]; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo "FAIL: tls_client_cert smoke needs the openssl binary" >&2
        exit 1
    fi
    say "generate a client identity for the mTLS trunk"
    openssl req -x509 -newkey rsa:2048 -keyout "$TMPDIR_SMOKE/client.key" \
        -out "$TMPDIR_SMOKE/client.crt" -days 2 -nodes -subj "/CN=zrtc-smoke" \
        >/dev/null 2>&1
    CERTS=$'tls_cert_path = "'"$TMPDIR_SMOKE"/client.crt$'"'
    CERTS+=$'\ntls_key_path = "'"$TMPDIR_SMOKE"/client.key$'"'
fi

say "write temp config ($CFG) for mode=$MODE register=$REGISTER"
REG_AUTH=""
if [ "$MODE" = "digest" ] && [ "$REGISTER" = "1" ]; then
    # The local registrar plays the vendor: challenge REGISTERs with Digest.
    REG_AUTH=$'require_auth = true\nauth_user = "'"$TRUNK_USER"$'"\nauth_pass = "'"$TRUNK_PASS"$'"'
fi

cat >"$CFG" <<EOF
[daemon]
log_level = "info"

[sip]
host = "127.0.0.1"
udp_port = 15060
tcp_port = 15060
tls_port = 15061
wss_port = 15063

[sbc]
allow = ["127.0.0.0/8", "::1/128"]

[registrar]
domain = "127.0.0.1"
aor = "sip:1000@127.0.0.1"
expires = 300
$REG_AUTH

[b2bua]
port = 15070
media_host = "127.0.0.1"
default_target = "sip:sink@127.0.0.1:15090"

[sink]
port = 15090

[outbound]
enabled = false

[ai_bridge]
enabled = false

[api]
port = 18080

[trunk]
address = "127.0.0.1:$([ "$MODE" = "tls_client_cert" ] && echo 15061 || echo 15060)"
transport = "$([ "$MODE" = "tls_client_cert" ] && echo tls || echo udp)"
auth = "$MODE"
register = $([ "$REGISTER" = "1" ] && echo true || echo false)
auth_user = "$TRUNK_USER"
auth_pass = "$TRUNK_PASS"
auth_token = "$TRUNK_TOKEN"
keepalive_secs = 15
$CERTS
EOF

say "start daemon (log: $LOG)"
: >"$LOG"
"$BIN" --config "$CFG" >"$LOG" 2>&1 &
DAEMON_PID=$!

READY=0
for _ in $(seq 1 50); do
    if curl -sf "$API/healthz" >/dev/null 2>&1; then READY=1; break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAIL: daemon exited during startup" >&2
        tail -n 40 "$LOG" >&2
        exit 1
    fi
    sleep 0.2
done
[ "$READY" = 1 ] || { echo "FAIL: REST API did not come up" >&2; tail -n 40 "$LOG" >&2; exit 1; }
sleep 1

say "trunk startup lines"
grep -E "trunk " "$LOG" | sed 's/^/    /' || { echo "FAIL: no trunk lines in log" >&2; tail -n 20 "$LOG" >&2; exit 1; }
grep -q "trunk configured: " "$LOG" || { echo "FAIL: trunk not configured" >&2; exit 1; }
if [ "$REGISTER" = "1" ]; then
    grep -q "trunk REGISTER final code 200" "$LOG" \
        || { echo "FAIL: trunk REGISTER did not end with 200" >&2; tail -n 40 "$LOG" >&2; exit 1; }
fi

say "place one call out the trunk: zrtc call 1000"
if ! "$BIN" call 1000 --config "$CFG" --timeout-secs 20 2>&1 | sed 's/^/    /'; then
    echo "FAIL: trunk call failed" >&2
    tail -n 40 "$LOG" >&2
    exit 1
fi

say "GET /cdrs"
sleep 0.5
if command -v jq >/dev/null 2>&1; then
    curl -sf "$API/cdrs" | jq .
else
    curl -sf "$API/cdrs"
    echo
fi
CDRS="$(curl -sf "$API/cdrs" || echo '')"
printf '%s' "$CDRS" | grep -q '"disposition":"answered"' \
    || { echo "FAIL: no answered CDR after trunk call" >&2; exit 1; }

say "verdict"
echo "PASS: trunk mode=$MODE register=$REGISTER — configured, called, CDR written"
exit 0
