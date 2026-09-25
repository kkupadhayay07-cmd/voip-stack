# ZRTC — Native SIP & Media Protocol Stack

**Technical Design Document — v1.0 (Phase 1)**

A from-scratch, production-grade SIP and media protocol stack written in Rust.
No external SIP proxies, media servers, or softphone libraries are used or
wrapped (no Kamailio, OpenSIPS, FreeSWITCH, Asterisk, RTPengine, Janus,
mediasoup, LiveKit, PJSIP). Every protocol state machine, codec path and
parser in this repository is implemented natively.

---

## 1. Goals & Non-Goals

### 1.1 Goals

| # | Goal |
|---|------|
| G1 | Full RFC-3261 SIP core: message model, parser, serializer, transaction layer, dialog layer, transports (UDP/TCP/TLS/WS/WSS) |
| G2 | Full SDP engine (RFC 4566/8866) with a complete offer/answer state machine (RFC 3264) |
| G3 | Native RTP/RTCP stack (RFC 3550/3551/4585/5761) with an adaptive jitter buffer, PLC, and RFC 4733 DTMF |
| G4 | SRTP/SRTCP (RFC 3711/7714), DTLS-SRTP (RFC 5764/6347), ICE/STUN/TURN (RFC 8445/5389/5766/6062) — all self-implemented |
| G5 | Server roles: Registrar, Proxy, SBC, B2BUA — composable on one shared core |
| G6 | Outbound dialer (predictive/progressive/preview) with pacing & TCPA abandonment-rate governance |
| G7 | AI bridge: AudioSocket TCP + WebSocket bidirectional media streaming with <50 ms added latency |
| G8 | Media pipeline: N-way mixing, recording, transcoding, VAD, resampling |
| G9 | Control plane: REST + WebSocket API, CDR pipeline, Prometheus metrics, OpenTelemetry traces |
| G10 | 1,000 concurrent calls on 8 cores; <50 ms media path; <150 ms SIP setup; graceful restart with zero dropped calls |

### 1.2 Non-Goals (Phase 1)

- WebRTC browser interop (Phase 2), PSTN carrier interop tuning (Phase 3)
- Conference mixing & transcoding engines (Phase 4)
- Dialer / CDR / AI bridge (Phase 5), REST control plane (Phase 6)
- Any use of `unsafe` (forbidden everywhere; FFI only if an isolated codec
  binding ever becomes necessary — none exists in Phase 1)

### 1.3 Phase 1 Scope (this milestone)

1. `sip-core` — parser, serializer, transaction layer, transports (UDP/TCP/TLS/WS), digest-auth helpers, timers, branch/tag generation.
2. `sdp` — full SDP parse/serialize + offer/answer negotiation state machine.
3. `rtp` — RTP/RTCP parse+serialize, adaptive jitter buffer with PLC hooks, G.711 (μ-law/A-law) codecs, RFC 4733 telephone-event, RTCP SR/RR/SDES/BYE.
4. `b2bua` — basic back-to-back user agent: two-leg call bridge with anchored (relayed) RTP media; `voipd` demo daemon.
5. Tests (unit + integration + in-process robustness loops), cargo-fuzz targets, criterion benchmarks, Docker/compose, CI, docs, demo scripts.

---

## 2. Workspace Layout

```text
voip-stack/
├── Cargo.toml               # workspace: members, shared deps, lints
├── rust-toolchain.toml      # pinned stable channel
├── crates/
│   ├── sip-core/            # RFC 3261 core + transports + transactions
│   ├── sdp/                 # RFC 4566/8866 + RFC 3264 offer/answer
│   ├── rtp/                 # RFC 3550/3551 + jitter buffer + G.711 + 4733
│   └── b2bua/               # B2BUA engine + voipd demo binary
├── docs/                    # DESIGN.md, RFC-COMPLIANCE.md
├── demo/                    # runnable end-to-end demo scripts
├── docker/                  # Dockerfile
├── docker-compose.yml
└── .github/workflows/ci.yml
```

### 2.1 Full target architecture (Phases 1–6)

| Crate | Phase | Responsibility |
|-------|-------|----------------|
| `sip-core` | 1 | Parsing, transactions, dialogs, transports, auth |
| `sdp` | 1 | SDP & offer/answer |
| `rtp` | 1 | RTP/RTCP, jitter buffer, DTMF, codec traits |
| `srtp` | 2 | RFC 3711 CCM/GCM, key derivation, replay protection |
| `dtls` | 2 | DTLS 1.2/1.3 handshake state machine over our transport |
| `ice` | 2 | RFC 8445 agent, candidate pairing, consent freshness |
| `stun` | 2 | RFC 5389 messages (shared by ICE + our STUN/TURN server) |
| `turn` | 2 | RFC 5766/6062 TURN relay server |
| `registrar` | 3 | REGISTER/AOR/location service, digest auth, expiry |
| `proxy` | 3 | Stateless/stateful routing, forking, DNS/NAPTR/SRV (RFC 3263) |
| `sbc` | 3 | Topology hiding, ACL, rate limiting, NAT fixes, far-end NAT |
| `media` | 4 | Mixing, recording, resampling, VAD, transcoding graph |
| `dialer` | 5 | Predictive/progressive/preview campaigns, pacing, AMD |
| `cdr` | 5 | CDR pipeline, billing records, search API |
| `ai-bridge` | 5 | AudioSocket/WS media fork to STT→LLM→TTS & S2S models |
| `api` | 6 | REST + WS control plane, OpenAPI 3.1 |

### 2.2 Dependency policy

Allowed crates: `tokio`, `tokio-util`, `bytes`, `tracing`, `thiserror`,
`rand`, `rustls` (ring provider), `tokio-tungstenite`, `serde`, `axum`,
`sqlx`, AES-GCM/ring primitives, `criterion` (bench), `rcgen` (test certs).
No SIP/media server crates of any kind. `unsafe` forbidden. Crypto, parsers
and state machines are hand-written in this repo.

---

## 3. SIP Core Design

### 3.1 Message model

Zero-copy-friendly, allocation-light, fuzz-safe model:

```rust
pub enum SipMessage { Request(Request), Response(Response) }

pub struct Request  { pub method: Method, pub uri: SipUri, pub version: Version,
                      pub headers: HeaderMap, pub body: Bytes }
pub struct Response { pub code: u16, pub reason: String, pub version: Version,
                      pub headers: HeaderMap, pub body: Bytes }
```

- `HeaderMap` preserves raw ordering and supports repeated headers with
  comma-combining per RFC 3261 §7.3.1. Compact forms (`v f t m i c l k s e …`)
  are normalized to long names at parse time.
- Typed views (`Via`, `FromTo`, `CSeq`, `CallId`, `Contact`, `Route`,
  `ContentLength`, `ContentType`, `Supported`, `MaxForwards`, `Expires`,
  `RetryAfter`, `Authorization`, `RAck`, `ReferTo`, `Reason`) are
  reconstructed on access — no cached typed state to invalidate.
- `SipUri` supports `sip:`/`sips:`/`tel:` with user, password, host
  (domain or IP), port, URI parameters (`transport`, `lr`, `maddr`, `method`,
  `ttl`, `user`, `tag` at header level) and URI headers. Escaping handled.

### 3.2 Parser (hand-written, byte-oriented)

- Single pass, position-tracking, no regex, no recursion on unbounded input
  (bounds-checked loops everywhere) — fuzz targets must never panic.
- Message framing per transport:
  - **UDP**: datagram is one message; Content-Length validated, trailing
    octets beyond it are tolerated (robustness per RFC 3261 §18.3).
  - **TCP/TLS/WS**: stream framing via Content-Length accumulation with a
    configurable max message size (default 64 KiB).
- Multi-line header folding (leading SP/HT) accepted and unfolded.
- Strict `CRLF` with tolerant `LF` acceptance; `Content-Length` is
  recomputed on serialization, never trusted from input for framing beyond
  the declared buffer.

### 3.3 Serializer

Canonical order: Via, From, To, Call-ID, CSeq, then the rest in insertion
order; body last with computed `Content-Length`. Compact-form output is
available for wire-size-sensitive deployments.

### 3.4 Transaction layer (RFC 3261 §17)

Every transaction is an actor task driven by a single event loop:

```text
        ┌────────────┐  packets   ┌──────────────────┐
UDP/TCP─►│ transports ├───────────►│ TransactionLayer │──► TU events (app)
        │  (IO tasks) │◄───────────┤  (actor + timers) │◄── TU commands
        └────────────┘  send raw    └──────────────────┘
```

- **Client INVITE** (17.1.1): calling → proceeding → completed → terminated.
  Timer A retransmits (T1, doubling), Timer B (64·T1) → timeout, on 2xx the
  transaction completes and the TU owns the ACK (ACK-for-2xx is dialog-level).
- **Client non-INVITE** (17.1.2): trying → proceeding → completed →
  terminated; Timer F (64·T1), Timer K (T4).
- **Server INVITE** (17.2.1): proceeding → completed → confirmed;
  300–699 arms Timer G (response retransmits, capped at T2) and Timer H
  (64·T1, ACK wait); Timer I (T4) → terminated. Stray re-INVITEs absorbed.
- **Server non-INVITE** (17.2.2): trying → proceeding → completed; Timer J
  (64·T1 for UDP, 0 for TCP/TLS).
- **Reliability split**: transactions provide INVITE reliability; 2xx
  retransmission is TU/dialog responsibility (send 200 immediately when a
  duplicate INVITE arrives while confirmed — retransmit-last-200 rule).
- Transaction key: `branch + method (+ sent-by for server)`, matching
  RFC 3261 §17.2.3 mirroring rules.
- `T1` is configurable (default 500 ms) so integration tests run at T1=10 ms
  without long sleeps.

### 3.5 Dialog & session layer

- `Dialog { call_id, local_tag, remote_tag, local/remote cseq, route set,
  remote target, secure flag, state }`, created per §12 for UAC (from
  provisional/2xx response) and UAS (from request).
- Route-set construction from Record-Route + Contact (remote target),
  lr/non-lr route building for in-dialog requests.
- CSeq generation, ACK construction rules (2xx ACK vs non-2xx ACK differ),
  in-dialog re-INVITE/UPDATE/BYE helpers.
- Session state machine hooks offer/answer (see §4.3) to track
  pending/local/remote SDP and detect glare.

### 3.6 Transports

```rust
#[async_trait]
pub trait Transport: Send { /* framed message IO + connection registry */ }
```

| Transport | Notes |
|-----------|-------|
| UDP | One socket per bind addr; symmetric responses to rport/received; no connection state |
| TCP | Connection registry keyed by `IpAddr:Port`; find-or-create on send; per-conn framed reader task; LRU idle reaping |
| TLS | TCP framing over `tokio-rustls` (ring provider, TLS 1.2+1.3); client & server, SNI, optional client certs |
| WS/WSS | RFC 7118: SIP in text frames over WebSocket; `tokio-tungstenite` engine; WSS = WS over our TLS stream; virtual-connection registry |

All transports normalize into `TransportEvent { conn_id, peer, msg, raw }`
consumed by the transaction layer; sending is either connection-pinned
(reliable transports reuse the incoming connection per §18.2.2) or addressed
to a destination via the registry.

### 3.7 Authentication

RFC 2617 Digest with MD5/SHA-256 algorithms (`auth`/`auth-int` qop,
cnonce/nc tracking, AKAv1-MD5 placeholder), implemented as reusable
challenge/build helpers used by registrar (Phase 3) and UAC (Phase 2+).

---

## 4. SDP Engine Design

### 4.1 Model

```rust
pub struct Session { version, origin: Origin, name, info, connection: Option<Connection>,
                     bandwidths, timings: Vec<TimeDescription>, attributes: Vec<Attribute>,
                     medias: Vec<MediaDescription> }
pub struct MediaDescription { media, port, port_count, proto, formats,
                              connection, attributes: Vec<Attribute>, rtpmaps, fmtps, … }
```

- Typed attributes: direction (sendrecv/…), `rtpmap`, `fmtp`, `rtcp-fb`,
  `rtcp`, `rtcp-mux`, `ice-ufrag/pwd/options`, `fingerprint`, `setup`,
  `mid`, `extmap`, `ssrc`, `msid`, `group BUNDLE`, `ptime/maxptime`.
- Unknown `a=` attributes preserved verbatim (mandatory for round-trip
  fidelity and answer passthrough).

### 4.2 Parser

Strict line grammar `type=value`, section state machine, indexed error
reporting (`Error { kind, line, column }`), bounds on line count/length.
Serializer emits canonical RFC 4566 ordering; round-trip property tests
guarantee `parse(serialize(x)) == x` for all constructed sessions.

### 4.3 Offer/Answer (RFC 3264 + WebRTC extensions)

State machine per media block:

1. **Format intersection** — dynamic payload types matched via `rtpmap`
   (codec+clock+channels), static types from the RFC 3551 table
   (0=PCMU/8000, 8=PCMA/8000, 9=G722/8000, 3=GSM, 4=G723, 18=G729);
   `telephone-event` matched with matching clock. Unmatched m-line →
   rejected with `m=<media> 0 …` in the answer.
2. **Direction intersection** — `sendrecv/recvonly/sendonly/inactive`
   matrix (offer sendrecv ∩ answer sendrecv; offer sendonly → answer
   recvonly; …), per m-line.
3. **Mux negotiation** — `rtcp-mux` requires echo in answer; `group:BUNDLE`
   mid alignment validated; `rtcp` attribute honored for non-mux.
4. **ICE/DTLS fields** (Phase 2 use, parsed now) — `ice-ufrag/pwd` echoed,
   `fingerprint` validated + echoed, `setup:actpass`→`active`, `setup:
   active`→`passive`, `holdconn` conflict → error.
5. **Answer generation** is total: given `Offer` + `MediaCaps` (ordered
   codec list, directions, ICE creds, fingerprint) it always produces a
   valid answer or a precise error; re-offer (glare) handled per §6.2.

`MediaSession` (runtime projection) maps each m-line to
`StreamPlan { local_pt, remote_pt, codec, clock_rate, channels, fmtp,
direction, rtcp_mux, remote_addr, remote_port }` consumed by the media stack.

---

## 5. RTP / Media Design (Phase 1 subset)

### 5.1 Packet layer

- `RtpPacket` parse/serialize: V/P/X/CC, M, PT, sequence, timestamp, SSRC,
  CSRCs, header extensions (RFC 8285 one-byte/two-byte).
- `RtcpPacket`: SR/RR/SDES/BYE/APP + RTPFB/PSFB headers (NACK, PLI, FIR,
  generic feedback parsed at header level in Phase 1; full handling in
  Phase 2 with NACK/retransmit logic).
- RFC 5761 demux: PT range 64–95 ⇒ RTCP (when mux negotiated).
- RFC 4733 `telephone-event`: parse/build `{event, E, R, volume, duration}`,
  end-of-event detection, tone → DTMF event normalization.
- G.711 μ-law/A-law encode/decode implemented natively (table-free,
  branch-based — fast and constant-behavior), 8 kHz, 20 ms ptime (160 bytes).

### 5.2 Adaptive jitter buffer

```text
              ┌─────────────────────────────────────────────┐
RTP in ──push─►│ reorder by (ssrc, ext_seq)  (depth: target) │──pop──► PLC/dec ──► out
              │  late/duplicate/dropped handled             │
              └─────────────────────────────────────────────┘
```

- **Sequence model**: RFC 3711-style extended 48-bit sequence numbers with
  wraparound, probation on new SSRC (MIN_SEQUENTIAL=2), jump/slippage
  detection (spurious SSRC restart tolerated).
- **Adaptive target depth**: RFC 3550 interarrival jitter `J` maintained per
  SSRC; target = `min_frames + ceil(k·J_frames)` clamped to
  `[min 30 ms, max 300 ms]`, adjusted gradually (±1 frame per 500 ms
  step) to avoid audible level shifts; measured jitter→buffer-size hysteresis.
- **Output clock**: pop deadline driven by a 20 ms ticker; when buffer is
  empty past deadline, PLC hook is invoked (default: silence frame for
  PCMU; comfort-noise generator pluggable), and concealment stats are kept.
- **Late policy**: packets arriving more than target depth behind play-out
  are counted and dropped (never block the pop path).
- All decisions are unit-testable: the buffer is driven by virtual time in
  tests (no sleeps), deterministic and fuzz-safe.

### 5.3 Media relay (B2BUA, Phase 1)

Anchored relay: each leg owns one local RTP+RTCP UDP socket pair (even/odd
ports per RFC 3550 §11 convention, symmetric mode enabled for far-end NAT).
Packets are decoded to the jitter buffer, then re-emitted toward the other
leg after rewriting SSRC/timestamps. Payload pass-through requires codec
match on both legs (Phase 1: PCMU/PCMA/G722 + telephone-event). Transcoder
insertion lands in Phase 4 behind the same `MediaStream` trait.

---

## 6. B2BUA Design (Phase 1)

```text
  UAC ──INVITE(O)──►┌──────── B2BUA ────────┐──INVITE(O')──► UAS
   ◄───1xx/200(A)───│ leg A   bridge    leg B│◄──100/180/200(A')──
   ──────ACK───────►│                        │◄──────ACK────────
   ◄── RTP A ───────┤ relay(A↔B)             ├─────── RTP B ───►
   ──────BYE───────►│ tear down both legs    │◄──────BYE────────
                    └────────────────────────┘
```

- `CallEngine` manages `Call { legs: [Leg; 2], dialog_a, dialog_b, media }`
  with a leg state machine: `Idle → Incoming(offer) → Answering → Up →
  Releasing → Done`, mirrored for outgoing legs.
- Leg A receives INVITE(offer OA) → 100 Trying → (180) → B2BUA creates leg
  B INVITE with offer OB (same formats, own media address) → answer AB
  builds answer AA → 200(AA) → ACK both. Failure mapping: 4xx/5xx/6xx from
  B → relayed to A; 488 on codec mismatch.
- CSeq/tag/branch regenerated on both legs (topology isolation by design);
  Record-Route NOT propagated in Phase 1 (B2BUA is a UA pair, not a proxy).
- BYE/CANCEL/timeouts tear down both legs; re-INVITE pass-through deferred
  (hold, transfer → Phase 3/5).
- `voipd` binary: config-file driven, binds UDP/TCP, exposes `--bridge-to`
  static routing (Phase 1 demo), structured `tracing` logs, graceful Ctrl-C.

---

## 7. Concurrency & Runtime Model

- Single multi-threaded tokio runtime per process; IO tasks per transport;
  one actor task per SIP transaction; one task per call; per-stream media
  tasks pinned to `spawn_blocking`-free async loops (no blocking syscalls
  in the media path).
- Channels: bounded `mpsc` (backpressure) between transports ↔ transaction
  layer ↔ calls; unbounded only for management events.
- All timers centralized per actor via `tokio::time` (sleep-driven heaps),
  no global timer wheel in Phase 1 (benchmark first; introduce a wheel in
  Phase 6 if profiling demands it).
- Backpressure policy: UDP send is non-blocking with a drop counter
  (congestion signals via metrics), TCP writers use bounded queues.

---

## 8. Error Handling & Robustness

- `thiserror` enums per crate; no panics in library code; `unwrap` forbidden
  outside tests (`#![deny(clippy::unwrap_used)]` where practical).
- All parsers return `Result` with position info; unknown constructs are
  skipped-with-count rather than aborting the connection where RFC allows.
- Fuzz targets: `sip_parse_request`, `sip_parse_response`, `sdp_parse`,
  `rtp_parse`, `rtcp_parse`, `stun_parse` (Phase 2). In-process robustness
  loops (random-byte + mutation-based) run in CI on stable toolchain so
  fuzzing coverage does not require nightly.

---

## 9. Testing Strategy

| Layer | Tests |
|-------|-------|
| Unit | Every public function; table-driven cases per header/parser |
| Property/round-trip | `parse(serialize(m)) == m` for SIP/SDP/RTP/RTCP |
| Transaction | UAC/UAS INVITE + non-INVITE state walks, retransmit timing (T1=10 ms), timeout paths, stray-packet absorption |
| Transport | UDP loopback, TCP framing (split reads, coalesced messages), TLS loopback (self-signed test certs), WS/WSS framing |
| Media | Jitter buffer: reorder/loss/PLC/wrap/adaptive-depth with virtual time; G.711 codec vectors; 4733 flows |
| End-to-end | UAC↔B2BUA↔UAS over real UDP sockets: full call with bidirectional RTP + DTMF + BYE; N concurrent calls smoke test |
| Bench | criterion: SIP parse/serialize MB/s & msg/s, SDP parse, RTP parse, jitter-buffer ops/s |
| Fuzz | cargo-fuzz targets + stable in-process mutation loops |

---

## 10. Observability & Ops

- `tracing` structured logs (JSON option), span per call/transaction.
- Prometheus metrics via `api` crate (Phase 6); Phase 1 exposes counters
  internally (`transactions_active`, `tx_timeouts`, `packets_dropped`,
  `jitter_concealment_frames`).
- Docker: multi-stage build (rust builder → distroless/slim runtime),
  compose service `voipd` with UDP/TCP 5060–5062 mapped.

---

## 11. Security

- No `unsafe`; constant-time comparison for digest secrets (`subtle`-style
  hand-rolled, no external dep).
- Parser hard limits: max message 64 KiB (configurable), max headers 128,
  max header line 8 KiB, max SDP lines 512 — prevents resource exhaustion.
- TLS: ring-backed rustls, TLS 1.2+; self-signed test certs are test-only.
- SRTP/DTLS land in Phase 2 with replay windows (RFC 3711 §3.3.3) and
  constant-time tag verification.

---

## 12. Performance Targets (Phase 1 baseline)

| Metric | Target | Measurement |
|--------|--------|-------------|
| SIP request parse | ≥ 150k msg/s/core (~60 MB/s) | criterion bench |
| SIP serialize | ≥ 200k msg/s/core | criterion bench |
| SDP parse (WebRTC-typical 3 m-line) | ≥ 40k/s/core | criterion bench |
| RTP parse+serialize | ≥ 2M pkt/s/core | criterion bench |
| Jitter buffer push/pop | ≥ 1M ops/s/core | criterion bench |
| E2E call setup (loopback, T1=500) | < 150 ms P95 | integration test timing |

Phase 6 will validate the 1,000-call/8-core objective with a dedicated load
harness (SIPp-compatible scenario driver written in-crate, no external deps).

---

## 13. Roadmap

| Phase | Deliverables |
|-------|--------------|
| 1 (now) | sip-core + sdp + rtp + b2bua + tests/bench/fuzz + docker/CI + demo |
| 2 | srtp + dtls + ice/stun/turn + WebRTC (WSS/JSON) gateway, browser interop |
| 3 | registrar + proxy + sbc + NAT traversal, RFC 3263 routing |
| 4 | media pipeline: mixing, recording, transcoding (Opus↔G.711), VAD |
| 5 | dialer (predictive, TCPA pacing) + CDR + AI bridge (<50 ms) |
| 6 | REST/WS control plane, metrics/tracing, load harness, final report |
