# ZRTC — Testing Guide

**Version 1.0 · Phase 1 · How the stack is verified**

Rules of the road: every public function carries tests (workspace rule);
parsers are tested for round-trip equality *and* panic-freedom; timing paths
are tested with virtual/configurable time, never sleeps.

---

## 1. Commands

```sh
cargo test --workspace                  # unit + integration + interop suites
cargo test -p sip-core                  # single crate
cargo test --workspace --no-default-features
                                        # build/test without system libopus
cargo bench -p sdp                      # criterion benches where present
RUST_LOG="info,b2bua=debug" cargo test -p b2bua -- --nocapture
                                        # verbose engine runs once b2bua lands
```

Toolchain is pinned by `rust-toolchain.toml` (stable). System dependency:
`pkg-config` + `libopus-dev` unless building `--no-default-features`.

## 2. Suite inventory (last verified full run)

| Crate | Tests | Focus |
|-------|-------|-------|
| `sip-core` | 50 | URI/headers/message model; datagram + stream framing (split reads, folding, limits, §18.3 trailing octets); canonical serializer round-trips; digest RFC 2617 vectors; builder defaults |
| `sdp` | 16 | parser grammar + positioned errors; canonical serialization; RFC 3264 offer/answer (codec/direction intersection, mux, ICE/DTLS carry); `StreamPlan` projection |
| `rtp` | 37 | packet/RTCP parse+serialize round-trips; RFC 8285 extensions; RFC 4733 events; RFC 5761 demux; jitter buffer with virtual time (reorder, loss→PLC, duplicates, wrap, SSRC restart, adaptive depth) |
| `codecs` | 92 | G.711/G.722 bit-exactness; G.729 ITU tables + interop gates (below); Opus binding; L16/CN/PLC; resampler; registry |
| `b2bua` | — | placeholder (engine + loopback integration test land with the crate) |

Counts move with the code; CI (§4) is the authoritative gate on every push.

## 3. Interop & conformance gates

| Gate | Mechanism | Threshold |
|------|-----------|-----------|
| G.729 decode fidelity | `codecs/tests/g729_interop.rs` decodes **bcg729 golden vectors** | output level within ±3 dB of reference |
| G.729 bitstream conformance | ffmpeg cross-decodes **our** encoder output in CI (runtime-detected) | decodes without gross corruption (±5 dB) |
| G.711 / G.722 | bit-exact round-trip against ITU structures | exact |
| Opus | libopus round-trip at supported modes | decodes, sane RMS |
| SIP/SDP/RTP/RTCP | `parse(serialize(x)) == x` property tests | exact equality |

The G.729 encoder's known fidelity deltas on synthetic fixtures are
**wire-invisible** and documented in `codecs/src/g729.rs` and
[`COMPLIANCE.md`](COMPLIANCE.md) §3 — the conformance contract is the
bitstream, verified by two independent third-party decoders.

## 4. CI gates

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every
push/PR: **fmt → clippy → test → audit → codec-interop**, with pkg-config +
libopus installed for workspace jobs.

Current known-state (tracked, temporary):

* `fmt-check` is `continue-on-error` until a formatting pass lands; flips to
  strict afterwards.
* clippy runs without `-D warnings` until the workspace is warning-free.
* `cargo audit` blocks on published advisories for the dependency tree.

## 5. Property & robustness testing

* **Round-trip laws**: SIP messages, SDP sessions, RTP/RTCP packets satisfy
  `parse(serialize(x)) == x` (with RFC-permitted canonicalization).
* **Panic-freedom**: every parser entry point is exercised with random bytes
  and structured mutations via in-process loops (stable toolchain, so CI runs
  them everywhere); `cargo-fuzz` targets mirror the same entry points for
  nightly/local campaigns.
* **Virtual time**: the jitter buffer and transaction timers are driven by
  injected clocks/virtual time in tests — the same code paths that run in
  production, without wall-clock sleeps. T1 is configurable (default 500 ms;
  integration tests use 10 ms).

## 6. Integration & end-to-end (as crates land)

| Stage | Scenario | Assertion style |
|-------|----------|-----------------|
| Transport | UDP loopback; TCP split-read + coalesced messages; TLS loopback with self-signed test certs; WS/WSS framing | message-level equality, framing invariants |
| Transaction | UAC/UAS INVITE + non-INVITE state walks; retransmit cadence; timeout paths; stray-packet absorption | state/order assertions at T1=10 ms |
| B2BUA | UAC ↔ B2BUA ↔ UAS full call: 100/180/200/ACK ordering, bidirectional RTP, DTMF relay, BYE teardown, CDR trail | signaling order + audio SNR gates (e.g. ≥12 dB transcode) + event completeness |
| Load (later) | N concurrent calls smoke; Phase-6 harness | setup-time P95, zero-call-loss under restart |

## 7. Benchmarks (targets)

| Bench | Target |
|-------|--------|
| SIP request parse | ≥150k msg/s/core (~60 MB/s) |
| SIP serialize | ≥200k msg/s/core |
| SDP parse (3 m-line typical) | ≥40k/s/core |
| RTP parse+serialize | ≥2M pkt/s/core |
| Jitter buffer push/pop | ≥1M ops/s/core |

Criterion benches live beside their crates (`cargo bench -p <crate>`); the
Phase-3 report records numbers against these targets.
