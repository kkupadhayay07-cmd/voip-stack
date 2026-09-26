# ZRTC — Native SIP & Media Stack in Rust

A from-scratch, production-grade SIP and media protocol stack written in
Rust. **No external SIP/media servers are wrapped** (no Kamailio, OpenSIPS,
FreeSWITCH, Asterisk, RTPengine, Janus, mediasoup, LiveKit, PJSIP) — every
protocol state machine, codec path and parser in this repository is
implemented natively, with **no `unsafe` anywhere** (the only FFI is the
explicitly-whitelisted codec/crypto layer: system libopus and OpenSSL).

**Current state: 328 tests passing across 11 crates; `cargo audit` clean.**

## Workspace layout

| Crate | Purpose | Status |
|-------|---------|--------|
| `crates/sip-core` | RFC 3261 message layer: parser, serializer, URI/headers, Digest helpers (RFC 2617/7616) | **Done** |
| `crates/sdp` | RFC 4566/8866 SDP parser/serializer + RFC 3264 offer/answer engine (`StreamPlan` projection) | **Done** |
| `crates/rtp` | RTP/RTCP (RFC 3550/3551), adaptive jitter buffer + PLC, RFC 4733 DTMF, RFC 5761 demux, RFC 8285 extensions, RTCP feedback (NACK/PLI/FIR/TWCC) | **Done** |
| `crates/codecs` | Full codec suite: **Opus, PCMU, PCMA, G.722, G.729, telephone-event**, L16, CN (RFC 3389), PLC, resampler; G.729 validated against bcg729 oracle vectors | **Done** |
| `crates/b2bua` | B2BUA call engine: dual-leg SIP (UAS+UAC, Timer A/B), SDP offer/answer both legs, cross-connected media pumps with 16 kHz transcode bridge (any codec pair), DTMF relay, CDR events, `b2bua-demo` binary, full-loopback integration test | **Done** |
| `crates/srtp` | RFC 3711 (AES-CM + HMAC-SHA1, KDF, replay window, ROC estimation) + RFC 7714 AES-GCM AEAD; validated against RFC 3711 B.2/B.3 and RFC 7714 §16 vectors | **Done** |
| `crates/dtls` | DTLS-SRTP (RFC 5764/6347) via whitelisted OpenSSL: runtime self-signed ECDSA P-256 certs, RFC 8122 fingerprint pinning, use_srtp negotiation, RFC 5764 §4.2 key export, flight retransmission | **Done** |
| `crates/ice` | RFC 5389 STUN codec (RFC 5769 vectors), RFC 8445 ICE agent (host/srflx/relay gathering, connectivity checks, nomination), RFC 5766 TURN server (long-term auth, permissions, Send/Data, ChannelBind) | **Done** |
| `crates/registrar` | RFC 3261 §10 registrar: AoR bindings, Digest auth (401 challenge, one-time nonces), wildcard/expiry/CSeq consistency | **Done** |
| `crates/proxy` | Stateful proxy (RFC 3261 §16): routing, parallel forking, Record-Route (loose router), Via prepend/pop, CANCEL per §9.1, 483 Max-Forwards, NAT response routing (received/rport) | **Done** |
| `crates/sbc` | Session border controller: CIDR ACL, token-bucket rate limiting, NAT latching, RFC 3581 rport, topology hiding (Call-ID remap + Contact rewrite) | **Done** |
| `crates/media` | Windowed-sinc resampler (anti-alias, arbitrary ratios), N-way conference mixer (clip protection, mute/gain), RIFF/WAVE recorder, adaptive energy+ZCR VAD with hangover | **Done** |
| `crates/cdr` | Call Detail Records: lifecycle builder, bounded store, filtered queries, campaign stats, JSON serialization | **Done** |
| `crates/dialer` | Outbound dialer: preview/progressive/predictive pacing (Erlang-C-inspired with abandonment guardrail), caller-ID rotation, TCPA 3% window, DNC list, AMD hooks, retry/attempt caps | **Done** |
| `crates/ai-bridge` | AI bridge: AudioSocket TCP framing (UUID/AUDIO/DTMF/TERMINATE), WebSocket media tap, VAD events (SpeechStart/End), **barge-in** detection, ≤ 20 ms added latency | **Done** |
| `crates/api` | Control plane: REST (CDR queries/stats, campaigns, pacing), WebSocket event stream, Prometheus `/metrics`, health/readiness | **Done** |

## Quick start

```sh
# Prereqs: rustup (stable) + libopus + OpenSSL dev
sudo apt-get install -y pkg-config libopus-dev libssl-dev

cargo test --workspace                           # 328 tests: unit + integration + RFC vectors
cargo run -p b2bua --bin b2bua-demo              # loopback B2BUA call demo
./demo/run_loopback_demo.sh                      # scripted demo (UAC→B2BUA→UAS + CDR)
cargo audit                                      # 0 vulnerabilities
```

## End-to-end verification (all in-repo tests)

* **Signaling**: UAC(PCMU) → B2BUA(transcode) → UAS(PCMA) loopback call with
  100/180/200/ACK ordering, RTP media, BYE, complete CDR trail.
* **Codecs**: every codec round-trips; G.729 additionally validated against
  ITU reference (bcg729) oracle vectors; Opus via system libopus FFI.
* **WebRTC path**: DTLS-SRTP handshake (self-signed P-256 certs, fingerprint
  pinning, `use_srtp`) → RFC 5764 key export → SRTP sessions protect real
  media; ICE agents complete checks over UDP loopback; TURN relays through
  our own server.
* **Security primitives**: SRTP validated against RFC 3711 B.2/B.3 and
  RFC 7714 §16 conformance vectors; STUN against RFC 5769 §2.1/§2.2.

## Phase status

* **Phase 1** — SIP message layer, SDP engine, RTP/RTCP + jitter buffer,
  full native codec suite, B2BUA. ✅
* **Phase 2** — SRTP / DTLS-SRTP / ICE / STUN / TURN. ✅
* **Phase 3** — registrar / proxy / SBC roles. ✅
* **Phase 4** — media pipeline (resampler, mixer, recorder, VAD). ✅
* **Phase 5** — outbound dialer + CDR + AI bridge. ✅
* **Phase 6** — REST/WS control plane + Prometheus metrics. ✅
* **Roadmap** — transaction-layer hardening (Timer F/H state machines are
  simplified in b2bua), TCP/TLS/WSS transports in the service binary,
  Postgres CDR persistence (sqlx), 1000-concurrent-call load harness.

## Documentation

* [`docs/DESIGN.md`](docs/DESIGN.md) — technical design (implementation contract)
* [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) — honest per-RFC compliance matrix
* [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — build, Docker/compose, ops notes, roadmap
* [`docs/SECURITY_NOTES.md`](docs/SECURITY_NOTES.md) — crypto design notes
* [`demo/README.md`](demo/README.md) — loopback demo walkthrough
* [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — fmt/clippy/test/audit + G.729↔ffmpeg interop

## License

Apache-2.0
