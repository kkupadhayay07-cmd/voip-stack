#!/usr/bin/env bash
# run_loopback_demo.sh — self-contained loopback call through the B2BUA.
#
# Runs the same integration test described in demo/README.md:
#   UAC(PCMU) -> B2BUA (transcode) -> UAS(PCMA), 1 s of RTP, BYE, CDR trail.
set -euo pipefail

# Locate the repo root relative to this script (works from any CWD).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Rust toolchain (needed when the environment isn't pre-sourced).
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

cd "$REPO_ROOT"

echo "==> VoIP stack loopback demo"
echo "    repo:    $REPO_ROOT"
echo "    crate:   b2bua (integration test: loopback_call)"
echo

echo "==> cargo test -p b2bua --test loopback_call -- --nocapture"
echo "    (UAC/PCMU -> B2BUA -> UAS/PCMA, transcoded audio + CDR trail)"
echo
cargo test -p b2bua --test loopback_call -- --nocapture

echo
echo "==> Demo complete."
echo "    A full SIP call (100/180/200/ACK, INVITE/BYE relay) was served"
echo "    end-to-end by the native stack, with PCMU -> PCMA transcoding"
echo "    verified by SNR and a complete CDR event trail."
echo
echo "    Interactive variant:  cargo run -p b2bua --bin b2bua-demo"
echo "    Documentation:        demo/README.md, docs/DESIGN.md"
