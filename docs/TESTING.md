# ZRTC — Testing Guide

**Version 1.1 · Post-Phase-6 hardening · How the stack is verified**

Rules of the road: every public function carries tests (workspace rule);
parsers are tested for round-trip equality *and* panic-freedom; timing paths
are tested with virtual/configurable time, never sleeps.

---

## 1. Commands

```sh
cargo test --workspace                  # unit + integration + interop suites
cargo test -p sip-tx --release          # transaction state machines at exact timer instants
cargo test -p sip-core                  # single crate
cargo test --workspace --no-default-features
                                        # build/test without system libopus
cargo bench -p sdp                      # criterion benches where present
RUST_LOG="info,b2bua=debug" cargo test -p b2bua -- --nocapture
                                        # verbose engine runs
```

Toolchain is pinned by `rust-toolchain.toml` (stable). System dependency:
`pkg-config` + `libopus-dev` unless building `--no-default-features`.

## 2. Suite inventory (last verified full run: 359 tests, 52 suites)

| Crate | Tests | Focus |
|-------|-------|-------|
| `sip-core` | 51 | URI/headers/message model; datagram + stream framing (split reads, folding, limits, §18.3 trailing octets); canonical serializer round-trips; digest RFC 2617 vectors; fuzz-smoke corpus; builder defaults |
| `sip-tx` | 14 | RFC 3261 §17 state machines with a fake clock: exact timer fire instants (0/500/1500/3500/7500/15500/31500 ms), T2 caps, 64·T1 timeouts, retransmission absorption, wrong-branch/wrong-CSeq rejection, 2xx-ACK-is-a-new-transaction, reliable-transport timer elision, transport-error teardown |
| `sdp` | 17 | parser grammar + positioned errors; canonical serialization; RFC 3264 offer/answer (codec/direction intersection, mux, ICE/DTLS carry); `StreamPlan` projection; fuzz-smoke corpus |
| `rtp` | 41 | packet/RTCP parse+serialize round-trips; RFC 8285 extensions; RFC 4733 events; RFC 5761 demux; jitter buffer with virtual time (reorder, loss→PLC, duplicates, wrap, SSRC restart, adaptive depth); fuzz-smoke corpus |
| `codecs` | 91 | G.711/G.722 bit-exactness; G.729 ITU tables + interop gates (§3); Opus binding; L16/CN/PLC; resampler; registry |
| `b2bua` | 3 | engine unit tests + full-loopback integration call: 100/180/200/ACK ordering, PCMU→PCMA transcode with SNR gate, DTMF relay, BYE, CDR trail; both legs driven by `sip-tx` transactions |
| `srtp` | 35 | RFC 3711 B.2/B.3 + RFC 7714 §16 vectors; round-trips; replay window/ROC semantics |
| `dtls` | 10 | real DTLS 1.2 handshake over UDP loopback, fingerprint pinning, key export, loss-resilient flights, SRTP roundtrip on exported keys |
| `ice` | 17 | STUN codec vs RFC 5769 vectors; agent gathering/checks/nomination/role-conflict; TURN allocation/permissions/relay; STUN server oracle |
| `sbc` | 6 | ACL, token-bucket rate limiting, NAT latch, topology hiding, rport |
| `media` | 13 | resampler anti-alias/streaming parity, mixer, recorder, VAD, full codec pipeline test |
| `cdr` | 6 | lifecycle builder, dispositions, bounded store, filters/stats, JSON |
| `dialer` | 8 | pacing modes, TCPA window, DNC, attempts/cooldowns, caller-ID rotation |
| `ai-bridge` | 4 | AudioSocket framing, WS tap, VAD events, barge-in latency budget |
| `api` | 8 | REST black-box: CDR queries/filters, campaign stats, pacing preview, metrics, health |
| `proxy` | 7 | routing, forking, CANCEL, Via/Record-Route, 483, NAT response routing |
| `registrar` | 9 | bindings, expiry, wildcard removal, digest challenge, CSeq/Call-ID consistency |
| `observ` | 14 | pcap writers, per-call trace buffer, diag counters (rx/tx/lost/jitter/concealed), redaction of per-packet RTP from traces |
| `zrtc` | 5 | daemon config parsing + assembly smoke |

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

Current state:

* `fmt-check` is strict (the tree is rustfmt-clean).
* clippy runs with **`-D warnings`** (workspace is warning-free, pinned
  clippy 1.98).
* `cargo audit` blocks on published advisories for the dependency tree
  (currently 0 vulnerabilities; one informational unmaintained notice on
  the whitelisted libopus FFI wrapper).
* The `test` job runs the **full workspace**; the `fuzz-smoke` job runs the
  deterministic malformed-input corpora for sip-core/sdp/rtp; the
  `codec-interop` job cross-decodes our G.729 encoder output with ffmpeg.

## 5. Property & robustness testing

* **Round-trip laws**: SIP messages, SDP sessions, RTP/RTCP packets satisfy
  `parse(serialize(x)) == x` (with RFC-permitted canonicalization).
* **Panic-freedom**: every parser entry point is exercised with random bytes
  and structured mutations via in-process loops (stable toolchain, so CI runs
  them everywhere); `cargo-fuzz` targets mirror the same entry points for
  nightly/local campaigns.
* **Virtual time**: the jitter buffer and the `sip-tx` transaction timers
  are driven by injected clocks/virtual time in tests — the same code paths
  that run in production, without wall-clock sleeps. T1 is configurable
  (default 500 ms; the `sip-tx` tests assert exact fire instants with a
  fake clock).

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
