# Deployment Guide

How to build, run and operate the ZRTC VoIP stack. The stack ships as
libraries **and** as a runnable service: the `zrtc` daemon wires the whole
stack (SIP listeners on UDP/TCP/TLS/WSS, SBC → proxy → registrar, B2BUA +
loopback sink, outbound trunk, AI tap, REST API, observability) behind one
`zrtc.toml` config.

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

## 3. Running the stack

### 3.1 Binaries

| Binary | Crate | Purpose |
|--------|-------|---------|
| `zrtc` | `zrtc` | The full daemon: SIP listeners (UDP/TCP/TLS/WSS), SBC, registrar, proxy, B2BUA + loopback sink, outbound trunk + originator, AI tap, REST API, observability |
| `b2bua-demo` | `b2bua` | Standalone B2BUA demo daemon (listens on `0.0.0.0:5060`, logs every CDR event) |

### 3.2 Full-stack demo (one command)

```sh
./demo/run.sh
```

The script builds `zrtc`, starts it with `demo/zrtc.toml`, waits for the
configured AoR (`sip:1000@zrtc.local`) to REGISTER, probes the TCP/TLS/WSS
listeners with the in-repo UAC, places one inbound call (UDP) and one
daemon-originated outbound call, then fetches `GET /cdrs` and prints both
records. Exit 0 = two answered CDRs. Daemon log: `/tmp/zrtc-demo.log`;
observability output: `/tmp/zrtc-observ/` (`sip.pcap`, `rtp.pcap`,
per-call `trace-*.log`).

### 3.3 Running `zrtc` directly

```sh
cargo build --release -p zrtc
./target/release/zrtc --config /path/to/zrtc.toml
```

`zrtc.toml` sections: `[daemon]` (log level), `[sip]` (host +
udp/tcp/tls/wss ports), `[sbc]` (CIDR allow-list, rate limit, topology
hiding), `[registrar]` (domain, AoR, expiry), `[b2bua]` (port, media host,
prefix routes), `[sink]` (loopback UAS for demos), `[outbound]`
(daemon-originated call: delay, target, duration), `[ai_bridge]`, `[api]`
(REST port), `[observ]` (enable, log dir, pcap + trace options), and
`[trunk]` for outbound carrier peering — auth modes `ip`, `digest`
(REGISTER or INVITE-challenge), `bearer`, or `tls_client_cert` (mTLS);
see `demo/zrtc.toml.example` for a worked example of each. `[trunk].address`
accepts `HOST`, `HOST:PORT`, `sip:user@HOST:PORT`, and IPv6 literals
(`[2001:db8::1]` or `[2001:db8::1]:5060`): a port-less target is resolved
through RFC 3263 NAPTR/SRV discovery (SRV priority/weight ordering with
failover candidates, A/AAAA fallback), while an explicit port pins the
endpoint and skips SRV per §4.2. At connect time the daemon walks the
resolved candidate list in priority order (3 s connect budget per candidate
for TCP/TLS/WSS; a dead primary logs `trunk failover` and the next candidate
takes the call), and the winning address is pinned for keepalives, request
URIs and RTP. If every candidate fails, the error names each attempt.

The UAC probe supports `--transport udp|tcp|tls|wss`, `--to`, `--from`,
`--rtp-ms`, `--timeout-secs`.

### 3.4 Tests and benchmarks

```sh
cargo test --workspace
cargo bench -p sdp               # criterion benches where present
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
  healthy). Replace it with a real probe (REST `/healthz` or a SIP OPTIONS
  ping) when the container entrypoint is wired — there is a `TODO(healthcheck)`
  in the Dockerfile.
* The image builds the whole workspace and stages every binary (`zrtc`,
  `b2bua-demo`) into `/usr/local/bin`; the **entrypoint is still a
  placeholder** (`CMD ["/bin/true"]`) — the container validates the build
  pipeline end-to-end but does not yet run the daemon (config + media port
  range mounting is the pending piece).

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

| Port | Proto | Purpose | Status |
|------|-------|---------|--------|
| 5060 | UDP | SIP signaling | live (`[sip].udp_port`) |
| 5060 | TCP | SIP signaling | live (`[sip].tcp_port`) |
| 5061 | TCP | SIPS (TLS) — self-signed identity generated at startup, or mTLS for trunks | live (`[sip].tls_port`) |
| 5063 | TCP | SIP over WSS (WebSocket Secure, RFC 7118) | live (`[sip].wss_port`) |
| 5070 | UDP | B2BUA leg (internal) | live (`[b2bua].port`) |
| 10000–20000/udp | RTP/RTCP (muxed per RFC 5761) | media anchors | live |
| 8080 | TCP | HTTP: REST/WS control plane + `/metrics` | live (`[api].port`) |

## 7. Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `RUST_LOG` | `info` (set in the image) | `tracing` env-filter. Examples: `info`, `info,b2bua=debug`, `warn,rtp::jitter=trace`. |
| `RUST_LOG_STYLE` | — | `tracing_subscriber` style override (auto/always/never). |
| `ZRTC_TRUNK_USER` | — | Trunk Digest auth user (overrides `[trunk].auth_user`). |
| `ZRTC_TRUNK_PASS` | — | Trunk Digest auth password (overrides `[trunk].auth_pass`). |
| `ZRTC_TRUNK_TOKEN` | — | Trunk bearer token (overrides `[trunk].auth_token`). |
| `ZRTC_DEMO_LOG` | `/tmp/zrtc-demo.log` | Daemon log path used by `demo/run.sh`. |

Observability (pcap files, per-call traces, diag counters) is configured in
the `[observ]` section of `zrtc.toml`, not via environment variables.

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

## 9. Roadmap

1. **Dialog layer extraction** (§12) from the B2BUA's per-leg state;
   `sip-tx` adoption in the proxy.
2. **Load harness** ✅ shipped — `zrtc load` (`--calls`/`--concurrency`/`--pace-ms`,
   `--json`) drives N concurrent calls through the full pipeline and reports
   setup-latency percentiles + failure breakdowns; `demo/soak.sh` adds a
   port pre-flight, CDR cross-check and panic gate. Sandbox baseline
   (2 vCPU, debug build, 500 ms media/call): 200 calls at concurrency 20 →
   200/200 answered, setup p50 116 ms / p95 305 ms, 5.3 calls/s. The
   release-build 1000-concurrent soak on 8-core hardware remains the
   published follow-up.
3. **Postgres CDR backend** (sqlx) + retention/archival policies.
4. **WebRTC hardening** — library layer ✅ shipped in `crates/rtp`
   (RFC 4585 Generic NACK, RFC 4588 RTX retransmission, transport-cc
   feedback) **and B2BUA RTCP plumbing ✅ live on every media leg**
   (periodic SR/RR, NACK answer from a 512-packet retransmission window +
   NACK ask on jitter-buffer gaps, 200 ms transport-cc arrival feedback
   when the extmap is negotiated); remaining: data channels (SCTP),
   sender-side transport-cc extension attach.
5. **Container entrypoint** — wire `zrtc` as the image entrypoint with a
   mounted config + real healthcheck.
6. **SDP hardening** (rejected m-lines, port-0 answers, the RFC 3264 §6.1
   direction clamp, **IPv6 answer address types and RFC 8843 BUNDLE group
   echo are done**), GRUU/Outbound,
   NAPTR/SRV for carrier-grade signaling. (PRACK/100rel shipped — see
   `COMPLIANCE.md`. The external audit is fully closed at every severity —
   Critical, High and the complete P2 backlog — with regression tests;
   see `docs/BUG_AUDIT_2026-09.md`.)

See `docs/DESIGN.md` for the full architecture contract and
`docs/COMPLIANCE.md` for the per-RFC status matrix.
