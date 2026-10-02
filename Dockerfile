# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# ZRTC VoIP stack — multi-stage production image
#
# Stage 1 (builder): rust:1-slim + pkg-config/libopus-dev → cargo build
# Stage 2 (runtime): debian:bookworm-slim + libopus0/ca-certificates only.
#
# The whole workspace is built (cargo build --release --workspace); the
# builder stages every executable it finds in target/release into /out/bin
# using an ELF-magic check (glob-safe, no dependency on specific binary
# names). Today that is the `zrtc` daemon and the `b2bua-demo` binary. The
# container CMD is intentionally still a no-op healthcheck stub (see the
# TODO at the bottom): the image validates the build pipeline end to end
# and stages the binaries; wiring the daemon entrypoint to a mounted
# zrtc.toml is the documented follow-up (docs/DEPLOYMENT.md,
# demo/zrtc.toml.example). The toolchain channel is pinned by
# rust-toolchain.toml (stable) inside the source tree, so the base tag
# stays deliberately floating.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM rust:1-slim AS builder

# libopus + pkg-config are required by the `codecs` crate (opus 0.3 binds the
# system libopus via pkg-config).
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libopus-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy the whole workspace (rust-toolchain.toml pins the toolchain channel).
COPY . .

# Build the full workspace in release mode.
# NOTE: not using --locked so an in-flight Cargo.lock bump never bricks the
# image build; the lockfile is committed and CI (cargo test) guards it anyway.
ENV CARGO_TARGET_DIR=/usr/local/target
RUN cargo build --release --workspace

# Stage all ELF executables from target/release into /out/bin.
# Glob-safe: does not assume the b2bua binary exists, does not depend on
# `file(1)` (not present in slim images), and excludes build scripts,
# .d files and other non-executable artifacts.
RUN set -eux; \
    mkdir -p /out/bin; \
    for f in "$CARGO_TARGET_DIR"/release/*; do \
        if [ -f "$f" ] && [ -x "$f" ]; then \
            magic=$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n'); \
            if [ "$magic" = "7f454c46" ]; then \
                cp "$f" /out/bin/; \
            fi; \
        fi; \
    done; \
    ls -la /out/bin

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Runtime deps: libopus0 (codecs), ca-certificates (outbound TLS/SIPS later).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libopus0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (fixed UID/GID for predictable volume permissions).
RUN groupadd --system --gid 10001 zrtc \
    && useradd --system --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin zrtc

COPY --from=builder /out/bin/ /usr/local/bin/

# Log to stdout by default; docker-compose / `docker run -e` can override.
ENV RUST_LOG=info

# SIP over UDP and TCP; 5061 for SIPS/TLS; 5063 for WSS; 8080 for the
# HTTP/metrics/control-plane surface.
EXPOSE 5060/udp 5060/tcp 5061/tcp 5063/tcp 8080/tcp

# TODO(healthcheck): replace with a real liveness probe for the `zrtc` daemon —
# e.g. a GET /healthz against the REST API or a SIP OPTIONS ping to 127.0.0.1:5060.
# /bin/true keeps the plumbing in place and always reports healthy for now.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/bin/true"]

# TODO(zrtc): wire the daemon as the entrypoint once a container config story
# lands (mount a zrtc.toml + media port range):
#   ENTRYPOINT ["/usr/local/bin/zrtc", "--config", "/etc/zrtc/zrtc.toml"]
# Until then the image validates the build pipeline end-to-end and stages the
# binaries (`zrtc`, `b2bua-demo`); it starts, exits cleanly, and is exercised via CI.
CMD ["/bin/true"]

USER zrtc
