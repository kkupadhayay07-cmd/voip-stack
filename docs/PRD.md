# ZRTC — Product Requirements Document

**Version 1.0 · Phase 1 · Status: living document**

ZRTC is a from-scratch, production-grade SIP and media protocol stack written
in Rust. It wraps **no** external SIP/media servers (no Kamailio, OpenSIPS,
FreeSWITCH, Asterisk, RTPengine, Janus, mediasoup, LiveKit, PJSIP) — every
protocol state machine, codec path and parser is implemented natively, with
`unsafe` forbidden repository-wide.

Companion documents:

* [`ARCHITECTURE.md`](ARCHITECTURE.md) — system structure, crate graph, data flows
* [`DESIGN.md`](DESIGN.md) — per-module technical design (implementation contract)
* [`COMPLIANCE.md`](COMPLIANCE.md) — honest per-RFC compliance matrix
* [`TESTING.md`](TESTING.md) — how the requirements below are verified
* [`SECURITY_NOTES.md`](SECURITY_NOTES.md) — security posture & threat model

---

## 1. Problem statement

Teams building voice/AI products face a choice between:

1. **C/C++ stacks** (PJSIP, oSIP, home-grown parsers) — memory-unsafe, hard to
   embed, difficult to audit;
2. **Wrapped servers** (Asterisk, FreeSWITCH, Kamailio + a media server) —
   operationally heavy, opaque internals, licensing/upgrade friction;
3. **Managed CPaaS** — per-minute cost, no on-prem option, no codec/media
   control.

There is no production-grade, memory-safe, fully-native SIP/media stack that
ships as **Rust libraries** composable into a single daemon. ZRTC fills that
gap: the protocol layer is a library first; daemons (`voipd`, later `zrtc`)
are thin binaries over the same crates.

## 2. Users & jobs to be done

| Persona | Job |
|---------|-----|
| Platform engineer | Embed SIP signaling + RTP media directly in a Rust service, no external server to operate |
| Telephony team | Auditable, spec-conformant codecs (G.711/G.722/G.729/Opus) with verifiable interop |
| AI voice builder | Fork live call audio to an STT→LLM→TTS pipeline with <50 ms added latency |
| SRE / operator | Deploy one static binary or container; observe via metrics/logs; load-bearing predictable behavior |

## 3. Goals & success criteria

| # | Goal | Success criterion |
|---|------|-------------------|
| G1 | Full RFC 3261 SIP core: messages, transactions, dialogs, UDP/TCP/TLS/WS/WSS transports | Parse/serialize round-trip property tests; transaction state-machine tests incl. timer paths; transport loopback tests |
| G2 | Full SDP engine (RFC 4566/8866) + RFC 3264 offer/answer | Total answer generation: valid answer or precise error for any offer; round-trip tests |
| G3 | Native RTP/RTCP (RFC 3550/3551/4585/5761) + adaptive jitter buffer + RFC 4733 DTMF | Virtual-time jitter-buffer tests (reorder/loss/wrap/PLC); packet round-trip tests |
| G4 | SRTP/SRTCP, DTLS-SRTP, ICE/STUN/TURN — all self-implemented | Interop with WebRTC browsers (Phase 2 gate) |
| G5 | Server roles — registrar, proxy, SBC, B2BUA — composed on one core | Role-level integration tests (register→route→call) |
| G6 | Outbound dialer (predictive/progressive/preview) with pacing & abandonment governance | Pacing decision tests incl. TCPA windows |
| G7 | AI bridge: AudioSocket + WebSocket media tap, ≤ one 20 ms frame added latency | Latency budget test; VAD/barge-in event tests |
| G8 | Media pipeline: N-way mixing, recording, transcoding, VAD, resampling | Transcode SNR gates (e.g. PCMU↔PCMA ≥ 12 dB end-to-end) |
| G9 | Control plane: REST + WebSocket, CDR pipeline, Prometheus metrics | API integration tests; CDR one-record-per-call invariant |
| G10 | Performance: 1,000 concurrent calls on 8 cores; <50 ms media path; <150 ms SIP setup | Criterion benches meet the §8 targets; Phase-6 load harness |

**Non-goals:** wrapping any external SIP/media server; `unsafe` anywhere;
browser front-end work; PSTN carrier tuning before Phase 3.

## 4. Functional requirements

Status legend: **Done** · **In progress** · **Planned** (phase). Verified per
[`TESTING.md`](TESTING.md); RFC-level detail per [`COMPLIANCE.md`](COMPLIANCE.md).

### FR-SIP — signaling core (`sip-core`)

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-SIP-1 | RFC 3261 message model: request/response, HeaderMap with repeated + compact headers, typed views | P0 | **Done** |
| FR-SIP-2 | Panic-free byte parser: UDP datagram framing (§18.3 robustness) + TCP/TLS/WS stream framing with Content-Length accumulation | P0 | **Done** |
| FR-SIP-3 | Canonical serializer (Via/From/To/Call-ID/CSeq order, recomputed Content-Length), round-trip equality | P0 | **Done** |
| FR-SIP-4 | URI model: `sip:`/`sips:`/`tel:`, IPv6, params, header-level tags, escaping | P0 | **Done** |
| FR-SIP-5 | Digest auth helpers RFC 2617/7616 (MD5, MD5-sess, SHA-256(-sess), qop auth/auth-int/none) | P1 | **Done** (helpers; server nonce flows with registrar) |
| FR-SIP-6 | Transaction layer §17: INVITE/non-INVITE client+server, Timers A–K, T1 configurable | P0 | **In progress** (Phase 1) |
| FR-SIP-7 | Dialog layer §12: route sets, CSeq, ACK rules (2xx vs non-2xx), in-dialog helpers | P0 | **Planned** (Phase 1) |
| FR-SIP-8 | Transports §18: UDP, TCP (connection registry), TLS (rustls), WS/WSS (RFC 7118) | P0 | **In progress** (UDP/TCP first; TLS/WS Phase 2) |

### FR-SDP — session description (`sdp`)

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-SDP-1 | RFC 4566/8866 parse + canonical serialize, positioned errors, unknown-attribute preservation | P0 | **Done** |
| FR-SDP-2 | RFC 3264 offer/answer: codec intersection (static PT table + rtpmap), direction matrix, mux/BUNDLE, ICE/DTLS field carry | P0 | **Done** |
| FR-SDP-3 | `StreamPlan` runtime projection consumed by the media layer | P0 | **Done** |

### FR-RTP — media transport (`rtp`)

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-RTP-1 | RTP fixed header + RFC 8285 one/two-byte extensions; RTCP SR/RR/SDES/BYE/APP + feedback headers (NACK/PLI/FIR/TWCC) | P0 | **Done** |
| FR-RTP-2 | Adaptive jitter buffer: 48-bit extended sequence, SSRC probation, RFC 3550 jitter estimator, adaptive depth 30–300 ms, PLC hooks, virtual-time testable | P0 | **Done** |
| FR-RTP-3 | RFC 4733 telephone-event (0–15, start/end), RFC 5761 demux | P0 | **Done** |

### FR-CODEC — media codecs (`codecs`)

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-CDC-1 | G.711 PCMU/PCMA — bit-exact, frame + packet APIs | P0 | **Done** |
| FR-CDC-2 | G.722 — bit-exact ITU structure (QMF, embedded ADPCM, 64/56/48 kb/s) | P0 | **Done** |
| FR-CDC-3 | G.729 — ITU-conformant bitstream; decoder verified against bcg729 golden vectors (±3 dB) and ffmpeg cross-decode in CI | P0 | **Done** (encoder quality caveats documented) |
| FR-CDC-4 | Opus via system libopus, feature-gated; workspace builds without it | P1 | **Done** |
| FR-CDC-5 | L16 (RFC 3551), CN (RFC 3389), PLC suite, resampler | P1 | **Done** |

### FR-ROLE — server roles & daemon

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-ROLE-1 | B2BUA: two-leg call bridge, anchored RTP relay, topology isolation (regenerated tags/branches/CSeq) | P0 | **Planned** (Phase 1 — `b2bua` crate placeholder present) |
| FR-ROLE-2 | `voipd` demo daemon: config-driven, UDP/TCP bind, `--bridge-to` routing, graceful shutdown | P1 | **Planned** (Phase 1) |
| FR-ROLE-3 | Registrar / proxy / SBC roles on the shared core | P1 | **Planned** (Phase 3) |
| FR-ROLE-4 | Single `zrtc` daemon composing the full stack end-to-end | P1 | **Planned** (Phase 6) |

### FR-MEDIA / FR-OUTBOUND / FR-AI / FR-API — later phases

| ID | Requirement | Phase | Status |
|----|-------------|-------|--------|
| FR-MED-1 | Mixing, recording, transcoding graph, VAD | 4 | Planned |
| FR-DIAL-1 | Predictive/progressive/preview dialer, pacing, TCPA abandonment governance | 5 | Planned |
| FR-CDR-1 | CDR pipeline: one record per call, search API, JSON export | 5 | Planned |
| FR-AI-1 | AudioSocket TCP + WebSocket media tap, VAD gating, barge-in, ≤20 ms added latency | 5 | Planned |
| FR-API-1 | REST + WebSocket control plane, CDR query, Prometheus metrics, OpenAPI | 6 | Planned |

## 5. Non-functional requirements

| ID | Requirement | Target | Verification |
|----|-------------|--------|--------------|
| NFR-1 | Memory safety | Zero `unsafe` (CI-enforced `#![forbid(unsafe_code)]`) | clippy + grep gate |
| NFR-2 | Panic-free parsers | No panic on any input | fuzz targets + in-process mutation loops |
| NFR-3 | SIP parse throughput | ≥150k msg/s/core (~60 MB/s) | criterion bench |
| NFR-4 | SIP serialize throughput | ≥200k msg/s/core | criterion bench |
| NFR-5 | RTP parse+serialize | ≥2M pkt/s/core | criterion bench |
| NFR-6 | Jitter buffer ops | ≥1M push/pop/s/core | criterion bench |
| NFR-7 | E2E call setup (loopback) | <150 ms P95 | integration timing |
| NFR-8 | Supply chain | `cargo audit` clean; minimal dep policy (see DESIGN §2.2) | CI audit job |
| NFR-9 | Portability | Linux + macOS; libopus optional via feature flag | CI + local no-default-features build |
| NFR-10 | Operability | Structured `tracing` logs; one static binary; non-root container | Docker/compose review |

## 6. Milestones & acceptance criteria

| Milestone | Scope | Acceptance gate |
|-----------|-------|-----------------|
| M1 — Protocol foundations (Phase 1) | sip-core message layer; sdp; rtp; codec suite; CI/Docker/docs | `cargo test --workspace` green; round-trip properties; G.729 interop gates pass; clippy clean |
| M2 — Session layer (Phase 1 cont.) | transactions (§17), dialogs (§12), UDP/TCP transports | Transaction timer-walk tests at T1=10 ms; TCP split-read/coalesced framing tests; UDP loopback call |
| M3 — First daemon (Phase 1 cont.) | b2bua engine + `voipd`; fuzz + benches | UAC↔B2BUA↔UAS full call with bidirectional RTP + DTMF + BYE; N-call smoke; benches meet §5 targets |
| M4 — WebRTC transport (Phase 2) | srtp, dtls, ice/stun/turn; TLS/WS/WSS | Browser interop demo; SRTP vectors; replay-window tests |
| M5 — Roles (Phase 3) | registrar, proxy, SBC; NAT handling | register→route→call integration; ACL/rate-limit tests |
| M6 — Media & outbound (Phases 4–5) | media pipeline; dialer; CDR; AI bridge | Transcode SNR gates; pacing unit tests; CDR invariant; AI tap latency budget |
| M7 — Control plane & scale (Phase 6) | REST/WS API; metrics; `zrtc` daemon; load harness | 1,000-call/8-core objective; GET /cdrs end-to-end demo |

## 7. Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| G.729 encoder fidelity below reference | Interop quality complaints | Wire-conformant bitstream is the contract; bcg729/ffmpeg decode gates in CI; quality deltas documented in-code; Phase-2 hardening item |
| Transaction/transport complexity slips schedule | M2/M3 delay | Timers virtual-time testable (T1=10 ms); message layer already frozen & round-trip locked |
| libopus system dependency friction | Build failures on odd platforms | Feature-gated default; workspace builds `--no-default-features` |
| Scope creep into server features | Library focus lost | Crate graph fixed in DESIGN §2.1; daemons are thin binaries only |

## 8. Traceability

Every requirement above maps to a compliance row in
[`COMPLIANCE.md`](COMPLIANCE.md), a design section in [`DESIGN.md`](DESIGN.md),
and a verification path in [`TESTING.md`](TESTING.md). The PRD is updated in
the same commit series that changes status — honesty over optimism.
