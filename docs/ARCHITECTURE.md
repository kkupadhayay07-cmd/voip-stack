# ZRTC — System Architecture

**Version 1.1 · Post-Phase-6 hardening · Companion to [`DESIGN.md`](DESIGN.md)**

DESIGN.md specifies *how each module works* (the implementation contract).
This document describes *how the system is put together*: the crate graph,
runtime model, data flows, ownership rules and deployment view — and how the
current tree maps onto the target architecture.

---

## 1. System context

```text
                    ┌───────────────────────────────────────────────┐
  SIP endpoints ────►                                               │
  (UDP/TCP/TLS)     │                                               │
                    │              ZRTC process                     │
  WebRTC clients ───►  transports → transactions → roles (B2BUA,   │
  (WS/WSS +         │  registrar, proxy, SBC) → media engine       │
   ICE/DTLS/SRTP)   │                    │                         │
                    │                    ▼                         │
  PSTN gateways ───►│        RTP: jitter buffer → decode →        │
  (SIP + RTP)       │        bridge → encode → RTP                │
                    │                    │                         │
  AI services ─────►│                    ▼                         │
  (AudioSocket/WS)  │        AI tap (VAD, barge-in, fork)          │
                    │                    │                         │
  Operators ───────►│        REST/WS control plane, CDR, metrics   │
                    └───────────────────────────────────────────────┘
```

One process, many roles: the same crates compose into the standalone
`b2bua-demo` binary (Phase-1 demo) or the full-stack `zrtc` daemon (the
runnable service: UDP/TCP/TLS/WSS listeners, SBC → proxy → registrar,
B2BUA + loopback sink, outbound trunk, AI tap, REST API, observability).
There is no forking to external servers — every arrow above terminates in
this repository's code.

## 2. Crate graph

### 2.1 Current tree (as built — 21 crates)

```text
   ops/assembly ┌─────────────┐  ┌──────────────┐
                │    zrtc     │  │    observ    │  pcap (SIP+RTP), per-call
                │ daemon: UDP │  │              │  traces, per-leg diag
                │ TCP/TLS/WSS │  └──────▲───────┘  (rx/tx/lost/jitter/concealed)
                │ SBC→proxy→  │         │ Call-ID-correlated events
                │ registrar→  │         │
                │ b2bua+sink, │  ┌──────┴───────┐
                │ trunk, AI,  │  │     api      │  REST/WS, /metrics, CDR queries
                │ REST, obs   │  └──────▲───────┘
                └──────┬──────┘         │ cdr events
        RFC 3263 ┌─────▼──────┐         │
        NAPTR/SRV│  rfc3263   │  pure-std DNS wire codec + §4.2 policy:
        targets  └────────────┘  ordered candidate list for the trunk client
   roles        ┌────────────┐  ┌──────┴───────┐  ┌────────────┐
                │    b2bua    │  │     cdr      │  │ registrar  │
                │ (legs driven│  │              │  │ proxy  sbc │
                │  by sip-tx) │  └──────────────┘  └────────────┘
                └──┬───────┬──┘
   transactions    │       │      ┌──────────────┐
                ┌──▼───────▼──┐   │   sip-tx     │  RFC 3261 §17 state machines,
                │  sip-core   │◄──│              │  Timers A–K, §17.1.3/§17.2.3
                │  messages   │   └──────────────┘  matching; no I/O, no tokio
                └──┬───────┬──┘
   media/security  │       │      ┌──────────────────────────────┐
                ┌──▼─────┐ └─────►│ srtp · dtls · ice (STUN/TURN)│
                │        │        │  (b2bua WebRTC legs: ICE →   │
                │        │        │   DTLS-SRTP → SRTP pump)     │
        ┌───────▼────┐   ┌──────▼──────┐└──────────────▲───────────────┘
        │    rtp     │   │    codecs   │   WebRTC keying (DTLS export)
        │ RTP/JB/DTMF│   │ Opus/G.711/ │
        └───────┬────┘   │ G.722/G.729 │   ┌──────────────────────────────┐
        ┌───────┴────┐   └─────────────┘   │ media · cdr · dialer ·       │
        │    sdp     │                     │ ai-bridge (AudioSocket/WS)   │
        │ offer/answer│                    └──────────────────────────────┘
        └────────────┘   data channels  ┌──────────────────────────────┐
                         (engine only,  │            sctp              │
        (attaches over  no I/O)         │ CRC32c wire codec, cookie    │
        DTLS via the    ┌───────────────│ handshake, TSN/SACK, T3-RTX, │
        packet seam)                    │ DCEP channels, FORWARD-TSN   │
                                        └──────────────────────────────┘
```

Dependency direction is strictly downward: `sdp`, `codecs` and `sctp` are
leaves (`sctp`'s only dependency is `sha2`/`hmac` for the state-cookie MAC);
`rtp` depends on codec traits; `sip-core` and `sip-tx` depend on nothing in
the workspace (`sip-tx` consumes only `sip-core` types); `observ` and `api`
observe rather than participate in media. No cycles, no cross-cutting
"common" crate — shared types live in the layer that owns them. The `sctp`
engine, like `ice`/`dtls`/`srtp`, is a library layer awaiting the B2BUA
WebRTC leg: it speaks packets in/out through a seam (`handle_packet` /
`drain_outbound`) so the RFC 8261 DTLS encapsulation — and only that —
belongs to the future caller.

### 2.2 Target architecture (Phases 1–6)

| Layer | Crates | Phase |
|-------|--------|-------|
| Protocol core | `sip-core` (messages → transactions → dialogs), `sip-tx` (§17 state machines), `sdp` | 1 |
| Transport | UDP/TCP/TLS/WS/WSS inside the `zrtc` daemon (message-layer framing in `sip-core`) | 1–2 |
| Media transport | `rtp` (packets, jitter buffer, DTMF), `srtp`, `dtls`, `ice` (+STUN/TURN), `sctp` (data-channel engine) | 1–2 |
| Codecs | `codecs` (G.711/G.722/G.729/Opus/L16/CN/PLC/resample) | 1 |
| Roles | `b2bua`, `registrar`, `proxy`, `sbc` | 1, 3 |
| Media services | `media` (mix, record, transcode, VAD) | 4 |
| Business | `dialer`, `cdr`, `ai-bridge` | 5 |
| Control plane | `api` (REST + WS, metrics), `zrtc` binary | 6 |
| Observability | `observ` (pcap, traces, diag) | hardening |

Full responsibility table: [`DESIGN.md` §2.1](DESIGN.md#21-full-target-architecture-phases-16).

## 3. Dependency policy

Allowed external crates (DESIGN §2.2): `tokio`, `tokio-util`, `bytes`,
`tracing`, `thiserror`, `rand`, `rustls` (ring provider),
`tokio-tungstenite`, `serde`, `axum`, `sqlx`, AES-GCM/ring primitives,
`criterion` (bench), `rcgen` (test certs). `opus` binds the system libopus
and is feature-gated.

Hard rules, enforced by review and CI:

1. **No SIP/media server crates** — every state machine is in-repo.
2. **`#![forbid(unsafe_code)]`** in every crate root; no exceptions.
3. **No new dev-framework dependencies** for tests (in-process mutation loops
   run on stable; `cargo-fuzz` is nightly-only, local).
4. Parser leaves (`sip-core`, `sdp`, `rtp`, `codecs`) must stay **I/O-free**
   so they are synchronously testable and fuzzable; async enters only at the
   transport/engine boundary.

## 4. Runtime model

```text
┌─ tokio multi-thread runtime ──────────────────────────────────────────┐
│                                                                       │
│  transport tasks        transaction actors          call/media tasks  │
│  (one per socket/   →   (one per transaction,   →   (one per call,   │
│   connection)            timer-driven actor)          pumps per leg)  │
│                                                                       │
│  channels: bounded mpsc (backpressure) on the hot path;               │
│  unbounded only for management/CDR events                             │
└───────────────────────────────────────────────────────────────────────┘
```

* **Single-owner state**: call maps, transaction tables and jitter buffers
  are owned by exactly one task; no `Mutex<HashMap>` sharing on hot paths.
* **Timers** are per-actor `tokio::time` drivers; the `sip-tx` transaction
  state machines are pure and consume injected time, so the same machines
  run under tokio in production and under a fake clock in tests (T1
  configurable; exact fire instants asserted).
* **Backpressure policy**: UDP sends are non-blocking with a drop counter;
  reliable-transport writers use bounded queues. Congestion surfaces as
  metrics, never as blocked application code.

## 5. Key data flows

### 5.1 SIP signaling (downstream request)

```text
wire ──► transport task ──► parse_stream/parse_message
          (framing, limits)        │
                                   ▼
                        SipMessage::Request
                                   │
                     transaction actor (§17 state machine)
                                   │
                                   ▼
                       TU / role (B2BUA, registrar, …)
                                   │
                     serialize → transport → wire
```

Parser hard limits (64 KiB message, 128 headers, 8 KiB/header line,
2 KiB URI) are enforced *inside* the parser, so every downstream consumer
inherits the bound.

### 5.2 Media (one leg)

```text
RTP in ─► RFC 5761 demux ─► jitter buffer (adaptive depth, probation)
                               │ pop at playout deadline
                               ▼
                    Decoder (codecs::Registry) → 16 kHz mono bridge
                               │
                    Encoder ← Resampler ← (mix/VAD/record tap)
                               │
RTP out ◄──────────── paced packetization (per-frame ticker)
```

The bridge domain is linear PCM at a fixed rate; transcoding is decode →
bridge → encode, so **any codec pair** the registry supports can be bridged
without pairwise code. RTCP is demultiplexed per RFC 5761; DTMF
(telephone-event) relays payload-level without transcoding.

Every media pump also runs an RTCP channel on its leg (RFC 3550 SR/RR,
RFC 4585 Generic NACK both directions against a 512-packet retransmission
window, transport-cc arrival feedback every 200 ms on negotiated legs).
Every SR compound carries SDES CNAME (§6.5.1); standalone NACK/transport-cc
feedback is prefixed with an empty RR so compounds always start with SR/RR
(§6.1). The B2BUA offers `a=rtcp-mux` (RFC 5761) because the pump is
mux-only — one socket carries RTP and RTCP. Sender side: outbound packets
are stamped with the 2-byte transport-cc sequence (RFC 8285 §4.2 element,
draft-holmerberg §3.1) before entering the retransmission window, and the
peer's RTPFB FMT 15 feedback about our SSRC is correlated against recorded
send times into per-leg stats (feedback count, window loss, excess
delay over the fastest observed packet — clock-domain free). The wire
format follows the draft exactly: 1-bit/2-bit vector chunks + run chunks
with the S-bit (bit 14) selecting symbol size, and inter-arrival recv
deltas the sender accumulates. Pumps enable only what the leg's SDP
negotiation allows — unnegotiated legs stay RTCP-silent.

### 5.3 WebRTC media legs (b2bua::webrtc)

A leg whose offer is `UDP/TLS/RTP/SAVPF` with ICE + a sha-256 fingerprint
runs ICE → DTLS → SRTP instead of plaintext RTP. On INVITE the engine
prepares the transport (`WebRtcMedia::prepare`): the ICE agent binds its
own socket (controlled role; its port becomes the answer's media port),
gathers a host candidate and adopts the offer's credentials/candidates;
the DTLS endpoint is created as the CLIENT because we answer
`setup:active` (RFC 5763 §5 — the answerer may not start DTLS until ICE
completes), with the offer's fingerprint pinned (sha-256 enforced). The
answer carries `ice-ufrag/pwd`, our candidate lines (new
`MediaCaps::ice_candidates` echo, prefix-less wire form, parse→serialize
fixed point), `a=fingerprint` and `a=setup:active`. After the 200 OK
leaves, `establish()` connects ICE (checks re-issued every 500 ms until
nomination — the answerer's first burst races the answer), drives the
DTLS handshake over the nominated pair through the RFC 7983 filter, and
exports the RFC 5764 §4.2 keying into the pump's SRTP sessions. From
then on the pump owns the crypto: RFC 7983 demux drops STUN/DTLS bytes
before the media parsers, every send is protected (SRTCP compounds for
RTCP, verbatim-RTP retransmits for NACK answers), every receive is
opened BEFORE parsing, an unprotectable datagram is counted and dropped,
and a leg that negotiated SAVPF has no plaintext fallback. A SAVPF offer
without ICE credentials is rejected 488.

### 5.4 Data channels (library layer — SCTP engine ready, DTLS transport now exists)

The `sctp` crate holds the full data-channel protocol engine with NO
transport attached: `SctpEndpoint::handle_packet(bytes)` consumes one SCTP
packet and `drain_outbound()` yields the response packets — the caller
wraps each in a DTLS application record (RFC 8261) over the ICE channel.
Inside: CRC32c-checked chunk codec, four-way cookie handshake (server
cookie = HMAC-SHA256 over the handshake state, stale cookies refresh from
the retained INIT), TSN window with gap-block SACKs, T3-RTX with RFC 6298
RTO, fragmentation + ordered/unordered reassembly, RFC 8832 DCEP channel
establishment (OPEN rides the ordered pipeline; stream-id parity: INIT
sender odd, responder even), RFC 3758 partial reliability with
FORWARD-TSN, graceful SHUTDOWN and ABORT. All timers are caller-driven
(`poll_timeout` + `on_timeout(now)`), so the engine is testable on a
virtual clock — the lossy-loopback suite pins gap recovery, PR
abandonment, forged cookies and the timer ordering that prevents a
retransmission of an expired message. The DTLS transport the data
channels will ride now EXISTS (see §5.2's WebRTC leg); until the SCTP
engine is attached to it, the SDP engine answers `m=application` offers
with port 0 (RFC 3264 §6) so the negotiation never promises a channel
the media pump cannot serve.

### 5.5 Control & observability

CDR events are emitted on unbounded channels from call engines and drained by
a single writer task (one record per call, persisted via the `cdr` store).
REST/WS (`api` crate) reads the same stores — the control plane never blocks
the media path.

## 6. Error handling & robustness

* `thiserror` enums per crate; libraries return `Result`, never panic.
* Parsers return positioned errors (`Error { kind, line, column }`-style);
  unknown constructs are skipped-with-count where RFC allows.
* Fuzz surface = every parser entry point (`sip_parse_request`,
  `sip_parse_response`, `sdp_parse`, `rtp_parse`, `rtcp_parse`); stable
  in-process mutation loops run in CI so coverage does not require nightly.
* Robustness behaviors are tests, not comments: trailing octets after UDP
  Content-Length (§18.3), split/coalesced TCP framing, folded headers,
  SSRC restart mid-stream, late/duplicate jitter-buffer pushes.

## 7. Deployment view

* **Trunk failover**: the outbound trunk resolves its address through the
  `rfc3263` crate into a priority-ordered candidate list; `trunk::connect`
  walks it at connect time (3 s per-candidate budget for TCP/TLS/WSS) and
  pins the winner for keepalives, request-URIs and RTP — a dead SRV primary
  costs one connect attempt, not the call.

* **Registration & flow layer (RFC 5626/5627)**: the trunk UAC registers
  with `Supported: outbound, gruu` and an instance-tagged Contact
  (`+sip.instance` from `[trunk].instance_id`, `reg-id=1`). The registrar
  detects the transport flow from the top Via, stores per-reg-id bindings,
  synthesizes a pub-gruu (`sip:AOR;gr=<instance>`) per instance, and
  answers with `Flow-Timer` + `Supported: outbound` on reliable transports.
  A single `flow_loop` task owns the session afterwards: OPTIONS
  keepalives, `Flow-Timer`-driven CRLF (TCP/TLS) / WS-Ping (WSS) flow
  keep-alives, and re-REGISTER at half the granted expiry on the same
  Call-ID — the binding never silently expires and dead flows surface
  within one keep-alive interval.

* **Build**: `cargo build --release`; pinned toolchain via
  `rust-toolchain.toml`; libopus is the only native dep and is optional.
* **Container**: multi-stage Dockerfile (rust builder → slim runtime,
  libopus, non-root user); compose file for the demo daemon.
* **CI**: fmt → clippy → test → audit → codec-interop (G.729 bitstreams
  cross-decoded by ffmpeg; bcg729 golden vectors). Gate details:
  [`.github/workflows/ci.yml`](../.github/workflows/ci.yml),
  ops details: [`DEPLOYMENT.md`](DEPLOYMENT.md).

## 8. Traceability

| Concern | Document |
|---------|----------|
| Product requirements & phase gates | [`PRD.md`](PRD.md) |
| Module-level design contract | [`DESIGN.md`](DESIGN.md) |
| Per-RFC status | [`COMPLIANCE.md`](COMPLIANCE.md) |
| Verification & test inventory | [`TESTING.md`](TESTING.md) |
| Security posture | [`SECURITY_NOTES.md`](SECURITY_NOTES.md) |
| Build & operations | [`DEPLOYMENT.md`](DEPLOYMENT.md) |
