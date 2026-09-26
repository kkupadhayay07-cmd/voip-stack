# Deployment Guide

How to build, run and operate the ZRTC VoIP stack. Status notes are honest:
Phase 1 ships **libraries + tests**; the B2BUA demo daemon (`voipd`) is the
next work package, so binary-level sections below are marked accordingly.

## 1. Prerequisites

* **Rust** — stable, pinned by `rust-toolchain.toml` (currently `stable`,
  1.98). rustup picks it up automatically:
  ```sh
  rustup show   # installs the pinned toolchain if missing
  ```
* **libopus** — the `codecs` crate binds the system libopus via pkg-config:
  ```sh
  # Debian/Ubuntu
  sudo apt-get install -y pkg-config libopus-dev
  # macOS
  brew install pkg-config opus
  ```
  The `opus` dependency is feature-gated (`codecs/default = ["opus"]`); the
  workspace also builds with `--no-default-features` if libopus is unwanted.
* No other native dependencies. No `unsafe` code anywhere in the stack.

## 2. Build from source

```sh
git clone <repo> && cd voip-stack
cargo build --release            # full workspace; binaries in target/release/
cargo test --workspace           # unit + integration + interop suites
```

Local-sandbox convention (single-machine multi-agent setups): set
`CARGO_TARGET_DIR=/tmp/voip-target` so builds don't collide with other
projects' file watchers. CI uses the default target dir.

## 3. Running the demo binaries — status

| Binary | Status |
|--------|--------|
| `voipd` (B2BUA demo daemon) | **Not yet built** — the `b2bua` crate is still a placeholder; the two-leg call bridge with anchored RTP relay is the current/next work package. |
| `codecs` examples (`codec_report`) | **Planned** — the codec-contract sketch exists; the example lands with the media pipeline. |

Today the runnable artifacts are the test suites and benchmarks:

```sh
cargo test --workspace
cargo bench -p sdp               # criterion benches where present
```

Once `voipd` lands (and this section will be updated then), the intended
shape is:

```sh
./target/release/voipd --sip-listen 0.0.0.0:5060 --rtp-start 10000 --http 0.0.0.0:8080
```

## 4. Docker

The Dockerfile is a two-stage build:

* **builder** — `rust:1.98-slim` + `pkg-config libopus-dev`, builds the whole
  workspace, then stages every ELF executable found in `target/release` into
  `/out/bin` (glob-safe: no assumption about which binaries exist yet).
* **runtime** — `debian:bookworm-slim` + `libopus0 ca-certificates` only,
  non-root user `zrtc` (UID/GID 10001), `EXPOSE 5060/udp 5060/tcp 5061/tcp
  8080/tcp`.

```sh
docker build -t zrtc/voip-stack:latest .
docker run --rm -e RUST_LOG=info \
  -p 5060:5060/udp -p 5060:5060/tcp -p 8080:8080 \
  zrtc/voip-stack:latest
```

* The `HEALTHCHECK` is currently a `/bin/true` **placeholder** (always
  healthy). Replace it with a real probe (SIP OPTIONS ping or `voipd`
  health endpoint) when the daemon lands — there is a `TODO(healthcheck)`
  in the Dockerfile.
* Until `voipd` exists the container starts and exits cleanly; the image
  still validates the build pipeline end-to-end.

## 5. Docker Compose

```sh
docker compose up -d --build
docker compose logs -f zrtc-b2bua
docker compose down
```

Service `zrtc-b2bua`: builds the local image, maps 5060/udp + 5060/tcp +
8080, `restart: unless-stopped`, `RUST_LOG=info`. A **commented-out
postgres** service is included for later phases (CDR store, registrar
state, dialer) — uncomment when those land.

## 6. Ports

| Port | Proto | Purpose | Since |
|------|-------|---------|-------|
| 5060 | UDP | SIP signaling | Phase 1 (transports in flight) |
| 5060 | TCP | SIP signaling | Phase 1 (transports in flight) |
| 5061 | TCP | SIPS (TLS) — exposed in the image, not mapped by compose | Phase 2 |
| 10000–20000/udp | RTP/RTCP (muxed per RFC 5761) | media anchors | Phase 2 (B2BUA relay) |
| 8080 | TCP | HTTP: metrics/control plane | Phase 6 |

## 7. Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `RUST_LOG` | `info` (set in the image) | `tracing` env-filter. Examples: `info`, `info,b2bua=debug`, `warn,rtp::jitter=trace`. |
| `RUST_LOG_STYLE` | — | `tracing_subscriber` style override (auto/always/never). |

Phase-2+ additions (SIP domain, TLS material, CDR sink, dialer pacing) will be
documented here as they are implemented.

## 8. Operational notes

### 8.1 Jitter buffer sizing

The receiver-side jitter buffer (`rtp::jitter`) is **adaptive**: it starts
small, tracks the RFC 3550 interarrival jitter estimate plus clock skew
(48-bit extended sequence numbers, SSRC probation), and grows/shrinks within
configured bounds. Guidance:

* LAN/low-jitter: target delay 20–60 ms is typically sufficient.
* WAN/mobile: 60–120 ms absorbs most burst loss without feeling laggy.
* Prefer the concealment hook (`set_concealment`) over a large static buffer —
  late packets are worse than well-PLC'd gaps for conversational quality.
* Cap the buffer; unbounded growth means clock skew, which should be handled
  by playout-rate correction (planned), not depth.

### 8.2 Codec negotiation

* Use the `sdp::negotiate` offer/answer engine and consume its `StreamPlan`
  projection rather than hand-patching SDP; it enforces RFC 3264 direction
  and codec intersection rules.
* Recommended offer preference order: `opus/48000/2` → `G722` → `PCMU/PCMA`
  (keep both for legacy interop) → `G729` (licensing-aware) → `L16` (local
  only). Always include `telephone-event` so DTMF survives any negotiation.
* The stack transcodes lazily via the `codecs` registry — plan CPU headroom
  for G.729 ↔ Opus hops; G.711↔G.711 relays are pass-through in the B2BUA.
* Opus: the image/runtime binds **system libopus**; keep the container's
  libopus0 in sync with the one used at build time (bookworm-slim pairing in
  the Dockerfile guarantees this).

## 9. Roadmap (Phase 2+)

1. **Security & WebRTC** — SRTP/SRTCP (RFC 3711/7714), DTLS-SRTP
   (RFC 5764/6347), STUN/TURN (5389/5766), ICE (8445); WS/WSS transports.
2. **Server roles** — registrar, stateful proxy, SBC, full B2BUA media
   anchoring; TLS (5061).
3. **Media pipeline** — N-way mixing, recording, transcoding engine, VAD,
   streaming resampler integration.
4. **Outbound dialer** — predictive/progressive/preview pacing with
   TCPA abandonment-rate governance; AMD.
5. **AI bridge & control plane** — AudioSocket TCP + WebSocket media
   streaming (<50 ms added latency), CDR pipeline, REST/WebSocket control
   API, Prometheus metrics, OpenTelemetry traces.
6. **Scale targets** — 1,000 concurrent calls on 8 cores, <50 ms media path,
   <150 ms SIP setup, graceful restart with zero dropped calls.

See `docs/DESIGN.md` for the full architecture contract and
`docs/COMPLIANCE.md` for the per-RFC status matrix.
