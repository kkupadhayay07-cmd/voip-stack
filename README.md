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

**Current state: 555 tests passing across 56 suites in 20 crates;
`clippy -D warnings` clean; `cargo audit` clean. The external security/interop
audit (42 findings) is fully closed — every Critical, High and P2 (Medium/Low)
finding is fixed with regression tests
([`docs/BUG_AUDIT_2026-09.md`](docs/BUG_AUDIT_2026-09.md)).**

## Workspace layout

| Crate | Purpose | Status |
|-------|---------|--------|
| `crates/sip-core` | RFC 3261 message layer: parser, serializer, URI/headers, Digest helpers (RFC 2617/7616) | **Done** |
| `crates/sip-tx` | RFC 3261 §17 transaction state machines: client/server INVITE + non-INVITE (Timers A/B/D, E/F/K, G/H/I, J), §17.1.3/§17.2.3 matching, ACK rules; pure state machines — no I/O, fake-clock tested | **Done** |
| `crates/sdp` | RFC 4566/8866 SDP parser/serializer + RFC 3264 offer/answer engine (`StreamPlan` projection) | **Done** |
| `crates/rtp` | RTP/RTCP (RFC 3550/3551), adaptive jitter buffer + PLC, loss recovery (RFC 4585 Generic NACK + RFC 4588 RTX), transport-cc congestion feedback, RFC 4733 DTMF, RFC 5761 demux, RFC 8285 extensions, RTCP feedback (PLI/FIR) | **Done** |
| `crates/codecs` | Full codec suite: **Opus, PCMU, PCMA, G.722, G.729, telephone-event**, L16, CN (RFC 3389), PLC, resampler; G.729 validated against bcg729 oracle vectors | **Done** |
| `crates/b2bua` | B2BUA call engine: dual-leg SIP driven by `sip-tx` transactions, SDP offer/answer both legs, cross-connected media pumps with 16 kHz transcode bridge (any codec pair), DTMF relay, RTCP channel per leg (RFC 3550 SR/RR, RFC 4585 NACK answer + ask, transport-cc arrival feedback + sender-side ext stamping with feedback→delay/loss correlation), RFC 4028 session timers, RFC 3262 reliable 1xx + PRACK both legs, CDR events, `b2bua-demo` binary, full-loopback integration test | **Done** |
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
| `crates/rfc3263` | RFC 3263 SIP server discovery: RFC 1035 DNS wire codec (compression-safe name reader, loop-proof pointers), NAPTR protocol selection (RFC 2915 S-flag), RFC 2782 SRV priority + weighted ordering, A/AAAA fallback, UDP with TC→TCP fallback — pure std, zero deps | **Done** |
| `crates/zrtc` | The daemon: wires everything into one voice service — UDP/TCP/TLS/WSS SIP listeners, SBC → proxy → registrar, B2BUA + loopback sink, outbound trunk (IP / Digest / Bearer / mTLS, RFC 3263 NAPTR/SRV discovery with connection-time candidate failover), outbound originator, AI tap, REST API, observability. Config: `zrtc.toml` | **Done** |

## Quick start

```sh
# Prereqs: rustup (stable) + libopus + OpenSSL dev
sudo apt-get install -y pkg-config libopus-dev libssl-dev

cargo test --workspace                    # 555 tests: unit + integration + RFC vectors
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
  verdicts (481/400/488), stored-PRACK resend on 1xx retransmission (same
  CSeq and branch, RFC 3261 §17.1.2), §4 PRACK gates (100 and 1xx without
  `Require: 100rel` never PRACKed), 421 dial retry with `Supported` merge.
* **SDP offer/answer**: RFC 3264 §6.1 answer-direction matrix validated for
  every offer/caps combination, rejected m-lines answered port 0 with a
  null `c=` line (offer's address type), port-0 offers answered port 0,
  SDP extras (`u=/e=/p=/k=/z=`) serialize with their `typ=` prefix.
* **Codecs**: every codec round-trips; G.729 additionally validated against
  ITU reference (bcg729) oracle vectors; Opus via system libopus FFI —
  including frames longer than 20 ms (RFC 6716 allows up to 120 ms) and
  PLC that always emits exactly one frame; G.722 reset returns the decoder
  to fresh state; CN tolerates multi-byte payloads (RFC 3389 §2.2).
* **WebRTC path**: DTLS-SRTP handshake (self-signed P-256 certs, fingerprint
  pinning, `use_srtp`) → RFC 5764 key export → SRTP sessions protect real
  media; ICE agents complete checks over UDP loopback; TURN relays through
  our own server.
* **Media transport**: RTP packets round-trip byte-exactly INCLUDING the
  padding case (bit never emitted without its octets); the jitter buffer
  stays paced across the 32-bit timestamp wrap and never jumps sequence
  gaps (hole slots are concealed with proper loss accounting).
* **Security primitives**: SRTP validated against RFC 3711 B.2/B.3 and
  RFC 7714 §16 conformance vectors; SRTCP AEAD against RFC 7714 §17.1/§17.3
  (encrypted, tagging-only E=0, tamper); STUN against RFC 5769 §2.1/§2.2;
  TURN long-term auth (MD5 key) against independent known vectors;
  unauthenticated TURN Allocate is idempotent per RFC 5766 §6.2; IPv6 SDP
  candidates (bare + bracketed) parse per RFC 8839 §5.1.
* **Consistency**: per-leg diag counters, per-call traces and CDRs
  (`concealed_events`, `packets_lost`) come from the same pump counters —
  verified equal in the demo.
* **P2 audit sweep**: RTP/RTCP demux survives SRTCP auth trailers (no %4
  misroute), `push_via` prepends to the stack top, non-2xx ACK mirrors a
  single top Via and keeps the Route set (§17.1.1.2), non-INVITE server tx
  enters Proceeding and matches by method (§17.2.2), registrar answers 423
  + `Min-Expires` below the configured minimum and prunes its nonce table,
  trunk TLS with a configured CA actually chain-verifies the server cert,
  CDRs carry the real final code (486 → Busy, not everything = Failed 487),
  `--since ""` parses safely, and the Prometheus call counters are wired
  with `ws_clients` exposed as a gauge.
* **SDP hardening (IPv6 + BUNDLE)**: answers pick `IN IP4`/`IN IP6` for
  their `o=`/`c=` lines from the local host literal (RFC 8866 §4.4 — a v6
  address is never mislabeled IP4; the offer's family never dictates ours),
  and an answer to a bundled offer echoes `a=group:BUNDLE` with exactly the
  accepted mids in the offer group's order (RFC 8843 §6.2) — rejected
  (port 0) m-lines and mid-less m-lines never join the group, and answers
  to unbundled offers stay group-free.
* **Load harness**: `zrtc load` places N concurrent calls through the full
  pipeline (listener → SBC → proxy → B2BUA → sink → paced RTP) and reports
  setup-latency percentiles + a deduplicated failure breakdown (`--json`
  for machines); `demo/soak.sh` wraps it with a CDR cross-check and a
  panic gate. Sandbox baseline (2 vCPU, debug build): 200 calls at
  concurrency 20 → 200/200 answered, setup p50 116 ms / p95 305 ms.
* **Loss recovery + congestion feedback** (`rtp`): RTCP Generic NACK
  (RFC 4585 §6.2.1 — `PID`/`BLP` FCI with wraparound-aware extended
  sequences, repeat throttling and give-up limits), RFC 4588 RTX
  retransmission (sender pool + OSN packetizer + receiver depacketizer for
  `apt`-linked streams), and transport-cc feedback (RTPFB FMT 15,
  libwebrtc-compatible chunk/delta encoding with run-length loss
  compression, receiver monitor + sender delay/loss tracker) — the
  building blocks for talking to browser media stacks; the B2BUA's RTCP
  channel; **now wired into the live B2BUA** (see below).
* **B2BUA RTCP plumbing**: every media pump now speaks RTCP on its leg —
  periodic SR (NTP- timestamped, TX packet/octet counters) carrying a
  reception report about the peer (fraction/cumulative loss, highest
  extended sequence, jitter, DLSR against the peer's last SR); RFC 4585
  Generic NACK in both directions (gaps in the jitter buffer produce NACKs
  via the repeat-throttled tracker; inbound NACKs pull verbatim packets out
  of a 512-packet retransmission window with a 20 ms per-seq flood guard);
  transport-cc arrival feedback every 200 ms when the draft-holmerberg
  extension is negotiated; offers advertise `rtcp-fb nack`/`transport-cc`
  + the extmap, answers echo the negotiation, and pumps enable only what
  the leg negotiated.
* **Sender-side transport-cc + connection-time SRV failover**: outbound RTP
  (audio and DTMF relay) is stamped with the one-byte transport-cc sequence
  extension (RFC 8285 §4.2 element writer in `rtp`, length field = len−1)
  when the extmap is negotiated — retransmissions carry the original seq —
  and inbound RTPFB FMT 15 feedback about our SSRC is correlated against
  recorded send times into per-leg stats (feedback count, window loss, mean
  send→receive delay); the trunk client walks its RFC 3263 candidate list
  in priority order at connect time (3 s per-candidate budget for
  TCP/TLS/WSS) and pins `target`, keepalives and RTP to the winner.
* **Dependency hygiene sweep**: 36 unused `[dependencies]`/`[dev-dependencies]`
  entries removed across 14 crates (e.g. the pure-std `proxy` state machine
  carried `tokio`/`rand` for nothing), the never-referenced workspace
  `async-trait` entry dropped, `cdr` unified onto the workspace `uuid` entry,
  and two dead test-only `snr_db` helpers (superseded by `aligned_snr_db`)
  deleted; 503/54 gates + demo unchanged.

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
  TLS/WSS handshake timeout (silent peers release their slot),
  RFC 4028 session timers, RFC 3262 PRACK/100rel — both on both B2BUA
  legs, external audit fully closed: every finding (Critical, High and
  the complete P2 backlog) fixed with regression tests (remote-DoS panics,
  SRTP payload auth, G.729 postfilter output, ICE IPv6/TURN, SBC/proxy
  response maps, dialer pacing, mixer, CDR, sink echo/Contact/leak,
  RTP padding/jitter-wrap/concealment, Via/ACK/transaction edge rules,
  registrar 423 + nonce hygiene, TLS CA verification, CDR final codes,
  metrics wiring), SDP IPv6/BUNDLE answer hardening (IP4/IP6 `o=`/`c=`
  address types, RFC 8843 BUNDLE group echo).
  ✅

## Roadmap (next)

1. Dialog layer extraction (§12) from the B2BUA's per-leg state.
2. Release-mode soak on 8-core hardware — the load harness (`zrtc load` +
   `demo/soak.sh`) and the debug-build sandbox baseline (200 calls at
   concurrency 20, 100% answered, setup p95 305 ms) are shipped; publish
   the optimized-build numbers next.
3. Postgres CDR persistence (sqlx) + retention policies.
4. WebRTC hardening — library layer ✅ (RFC 4585 NACK, RFC 4588 RTX,
   transport-cc feedback in `crates/rtp`) **and B2BUA RTCP plumbing ✅**
   (SR/RR + NACK answer/ask + TWCC feedback live on every media leg)
   **and sender-side transport-cc ✅** (outbound ext stamping + feedback
   correlation into per-leg stats); remaining: data channels (SCTP).
5. SDP hardening — rejected m-lines, port-0 offers, RFC 3264 §6.1 direction
   clamp, extras serialization, **IPv6 answer address types and RFC 8843
   BUNDLE group echo done**. RFC 3263 NAPTR/SRV server discovery — **done**
   (new `rfc3263` crate, live on the zrtc outbound trunk) with
   **connection-time candidate failover done**; remaining: GRUU/Outbound.

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
