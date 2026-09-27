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

### 2.1 Current tree (as built — 19 crates)

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
   roles        ┌──────▼──────┐  ┌──────┴───────┐  ┌────────────┐
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
        ┌───────▼────┐   ┌──────▼──────┐└──────────────▲───────────────┘
        │    rtp     │   │    codecs   │   WebRTC keying (DTLS export)
        │ RTP/JB/DTMF│   │ Opus/G.711/ │
        └───────┬────┘   │ G.722/G.729 │   ┌──────────────────────────────┐
        ┌───────┴────┐   └─────────────┘   │ media · cdr · dialer ·       │
        │    sdp     │                     │ ai-bridge (AudioSocket/WS)   │
        │ offer/answer│                    └──────────────────────────────┘
        └────────────┘
```

Dependency direction is strictly downward: `sdp` and `codecs` are leaves;
`rtp` depends on codec traits; `sip-core` and `sip-tx` depend on nothing in
the workspace (`sip-tx` consumes only `sip-core` types); `observ` and `api`
observe rather than participate in media. No cycles, no cross-cutting
"common" crate — shared types live in the layer that owns them.

### 2.2 Target architecture (Phases 1–6)

| Layer | Crates | Phase |
|-------|--------|-------|
| Protocol core | `sip-core` (messages → transactions → dialogs), `sip-tx` (§17 state machines), `sdp` | 1 |
| Transport | UDP/TCP/TLS/WS/WSS inside the `zrtc` daemon (message-layer framing in `sip-core`) | 1–2 |
| Media transport | `rtp` (packets, jitter buffer, DTMF), `srtp`, `dtls`, `ice` (+STUN/TURN) | 1–2 |
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

### 5.3 Control & observability

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
