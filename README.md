# ZRTC — Native SIP & Media Stack in Rust

A from-scratch, production-grade SIP and media protocol stack written in
Rust. **No external SIP/media servers are wrapped** (no Kamailio, OpenSIPS,
FreeSWITCH, Asterisk, RTPengine, Janus, mediasoup, LiveKit, PJSIP) — every
protocol state machine, codec path and parser in this repository is
implemented natively, with **no `unsafe` anywhere** (the only FFI is the
explicitly-whitelisted codec/crypto layer: system libopus and OpenSSL).

The stack assembles into **one daemon** (`zrtc`): SIP listeners on
UDP/TCP/TLS/WSS, SBC edge controls, registrar, stateful proxy, B2BUA with
transcoding media bridge, outbound trunk support (IP / Digest / Bearer /
mTLS auth), an AI media tap, a REST/WebSocket control plane, and in-process
observability (pcap + per-call traces + CDRs, all correlated by SIP Call-ID).

**Current state: 396 tests passing across 54 suites in 19 crates;
`clippy -D warnings` clean; `cargo audit` clean.**

## Workspace layout

| Crate | Purpose | Status |
|-------|---------|--------|
| `crates/sip-core` | RFC 3261 message layer: parser, serializer, URI/headers, Digest helpers (RFC 2617/7616) | **Done** |
| `crates/sip-tx` | RFC 3261 §17 transaction state machines: client/server INVITE + non-INVITE (Timers A/B/D, E/F/K, G/H/I, J), §17.1.3/§17.2.3 matching, ACK rules; pure state machines — no I/O, fake-clock tested | **Done** |
| `crates/sdp` | RFC 4566/8866 SDP parser/serializer + RFC 3264 offer/answer engine (`StreamPlan` projection) | **Done** |
| `crates/rtp` | RTP/RTCP (RFC 3550/3551), adaptive jitter buffer + PLC, RFC 4733 DTMF, RFC 5761 demux, RFC 8285 extensions, RTCP feedback (NACK/PLI/FIR/TWCC) | **Done** |
| `crates/codecs` | Full codec suite: **Opus, PCMU, PCMA, G.722, G.729, telephone-event**, L16, CN (RFC 3389), PLC, resampler; G.729 validated against bcg729 oracle vectors | **Done** |
| `crates/b2bua` | B2BUA call engine: dual-leg SIP driven by `sip-tx` transactions, SDP offer/answer both legs, cross-connected media pumps with 16 kHz transcode bridge (any codec pair), DTMF relay, RFC 4028 session timers, RFC 3262 reliable 1xx + PRACK both legs, CDR events, `b2bua-demo` binary, full-loopback integration test | **Done** |
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
| `crates/observ` | In-process observability: Wireshark-openable pcap capture (SIP + RTP), human-readable per-call traces, per-leg media diag counters (rx/tx/lost/jitter/concealed) — everything correlated by SIP Call-ID | **Done** |
| `crates/zrtc` | The daemon: wires everything into one voice service — UDP/TCP/TLS/WSS SIP listeners, SBC → proxy → registrar, B2BUA + loopback sink, outbound trunk (IP / Digest / Bearer / mTLS), outbound originator, AI tap, REST API, observability. Config: `zrtc.toml` | **Done** |

## Quick start

```sh
# Prereqs: rustup (stable) + libopus + OpenSSL dev
sudo apt-get install -y pkg-config libopus-dev libssl-dev

cargo test --workspace                    # 396 tests: unit + integration + RFC vectors
./demo/run_loopback_demo.sh               # B2BUA loopback call (UAC→B2BUA→UAS + CDR)
./demo/run.sh                             # full zrtc daemon demo: REGISTER, TCP/TLS/WSS
                                          # listener probes, inbound + outbound calls,
                                          # GET /cdrs, pcap + per-call traces
cargo run -p b2bua --bin b2bua-demo       # standalone B2BUA demo binary (port 5060)
cargo audit                               # 0 vulnerabilities
```

The full-stack demo (`./demo/run.sh`) starts `zrtc` with `demo/zrtc.toml`,
waits for the configured AoR to REGISTER, probes the TCP/TLS/WSS listeners
with the in-repo UAC, places one inbound call (UDP) and one daemon-originated
outbound call, then prints both CDRs from `GET /cdrs`. Observability output
lands in `/tmp/zrtc-observ/`: `sip.pcap`, `rtp.pcap` (open both in
Wireshark) and per-call `trace-*.log` files with per-leg media counters
(rx/tx/lost/jitter/concealed) that match the CDR records.

## End-to-end verification (all in-repo tests)

* **Signaling**: UAC(PCMU) → B2BUA(transcode) → UAS(PCMA) loopback call with
  100/180/200/ACK ordering, RTP media, BYE, complete CDR trail — both legs
  now driven by real RFC 3261 §17 transaction state machines.
* **Transactions**: every §17 timer path (A/B/D, E/F/K, G/H/I, J) exercised
  at exact instants with a fake clock (T1=500 ms derivations, T2 caps,
  64·T1 timeouts), including retransmission absorption and non-2xx ACK.
* **Reliable provisional responses (RFC 3262)**: reliable 180 with the final
  200 parked until PRACK, Timer-G retransmission until acknowledged, RAck
  verdicts (481/400/488), lost-PRACK recovery on leg B, 421 dial retry.
* **Codecs**: every codec round-trips; G.729 additionally validated against
  ITU reference (bcg729) oracle vectors; Opus via system libopus FFI.
* **WebRTC path**: DTLS-SRTP handshake (self-signed P-256 certs, fingerprint
  pinning, `use_srtp`) → RFC 5764 key export → SRTP sessions protect real
  media; ICE agents complete checks over UDP loopback; TURN relays through
  our own server.
* **Security primitives**: SRTP validated against RFC 3711 B.2/B.3 and
  RFC 7714 §16 conformance vectors; STUN against RFC 5769 §2.1/§2.2.
* **Consistency**: per-leg diag counters, per-call traces and CDRs
  (`concealed_events`, `packets_lost`) come from the same pump counters —
  verified equal in the demo.

## Phase status

* **Phase 1** — SIP message layer, SDP engine, RTP/RTCP + jitter buffer,
  full native codec suite, B2BUA. ✅
* **Phase 2** — SRTP / DTLS-SRTP / ICE / STUN / TURN. ✅
* **Phase 3** — registrar / proxy / SBC roles. ✅
* **Phase 4** — media pipeline (resampler, mixer, recorder, VAD). ✅
* **Phase 5** — outbound dialer + CDR + AI bridge. ✅
* **Phase 6** — REST/WS control plane + Prometheus metrics + `zrtc` daemon. ✅
* **Hardening** — RFC 3261 §17 transaction layer (`sip-tx`), in-process
  observability (pcap/traces/diag/CDR), trunk auth (IP/Digest/Bearer/mTLS),
  UDP/TCP/TLS/WSS listeners, TCP/TLS/WSS framing audit under adverse input,
  RFC 4028 session timers, RFC 3262 PRACK/100rel — both on both B2BUA
  legs. ✅

## Roadmap (next)

1. Dialog layer extraction (§12) from the B2BUA's per-leg state.
2. Load harness — 1000-concurrent-call soak on 8-core hardware.
3. Postgres CDR persistence (sqlx) + retention policies.
4. WebRTC hardening — RTX/NACK resend path, TWCC-driven bandwidth estimation,
   data channels (SCTP).
5. SDP hardening (IPv6, BUNDLE, rejected m-lines), GRUU/Outbound, NAPTR/SRV
   for carrier-grade signaling.

## Documentation

* [`docs/VISION.md`](docs/VISION.md) — **the destination**: the dream platform, non-negotiables, milestones with verifiable checkpoints, order of operations — every task is measured against this
* [`docs/PRD.md`](docs/PRD.md) — product requirements: users, functional/non-functional requirements, milestones & acceptance gates
* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system architecture: crate graph, runtime model, data flows, deployment view
* [`docs/DESIGN.md`](docs/DESIGN.md) — technical design (implementation contract)
* [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) — honest per-RFC compliance matrix
* [`docs/TESTING.md`](docs/TESTING.md) — test strategy, suite inventory, interop/conformance gates, CI
* [`docs/BUG_AUDIT_2026-09.md`](docs/BUG_AUDIT_2026-09.md) — external audit triage: verdict + fix status for every reported finding
* [`docs/SECURITY_NOTES.md`](docs/SECURITY_NOTES.md) — security posture, parser hardening, threat model
* [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — build, Docker/compose, ops notes, roadmap
* [`FINAL_REPORT.md`](FINAL_REPORT.md) — phase-completion report + post-report hardening addendum
* [`demo/README.md`](demo/README.md) — demo walkthrough (loopback call + full-stack daemon demo)
* [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — fmt/clippy/test/audit + fuzz-smoke + G.729↔ffmpeg interop

## License

Apache-2.0
