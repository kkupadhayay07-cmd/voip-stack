# ZRTC — Native SIP & Media Stack in Rust

A from-scratch, production-grade SIP and media protocol stack written in
Rust. **No external SIP/media servers are wrapped** (no Kamailio, OpenSIPS,
FreeSWITCH, Asterisk, RTPengine, Janus, mediasoup, LiveKit, PJSIP) — every
protocol state machine, codec path and parser in this repository is
implemented natively, with **no `unsafe` anywhere**.

## Workspace layout

| Crate | Purpose | Status |
|-------|---------|--------|
| `crates/sip-core` | RFC 3261 message layer: parser, serializer, URI/headers, Digest helpers (RFC 2617/7616) | Message layer **done**; transactions/transports **in progress** |
| `crates/sdp` | RFC 4566/8866 SDP parser/serializer + RFC 3264 offer/answer engine (`StreamPlan` projection) | **Done** |
| `crates/rtp` | RTP/RTCP (RFC 3550/3551), adaptive jitter buffer + PLC hooks, RFC 4733 DTMF, RFC 5761 demux, RFC 8285 extensions, RTCP feedback (NACK/PLI/FIR/TWCC) | **Core done**; REMB/RTX planned |
| `crates/codecs` | G.711, G.722, G.729, Opus (system libopus), L16, CN (RFC 3389), PLC, resampler | **Done** (Phase-1 codec suite) |
| `crates/b2bua` | B2BUA call engine with anchored RTP relay + `voipd` demo daemon | **Placeholder** — next work package |

## Quick start

```sh
# Prereqs: rustup (stable, pinned by rust-toolchain.toml) + libopus
sudo apt-get install -y pkg-config libopus-dev   # Debian/Ubuntu

cargo test --workspace                           # unit + integration + interop
cargo build --release
```

## Phase status

* **Phase 1 (current)** — SIP message layer, SDP engine, RTP/RTCP + jitter
  buffer, full native codec suite, CI/docs/containers. Transactions,
  transports and the B2BUA daemon are the remaining Phase-1 work packages.
* **Phase 2** — SRTP/DTLS-SRTP/ICE/STUN (WebRTC interop), TLS/WS/WSS,
  registrar/proxy/SBC roles.
* **Phase 3+** — media pipeline (mixing/recording/transcoding), outbound
  dialer + CDR, AI bridge (AudioSocket/WebSocket), REST control plane.

## Documentation

* [`docs/DESIGN.md`](docs/DESIGN.md) — technical design (implementation contract)
* [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) — honest per-RFC compliance matrix
* [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — build, Docker/compose, ops notes, roadmap
* [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — fmt/clippy/test/audit + G.729↔ffmpeg interop

## License

Apache-2.0
