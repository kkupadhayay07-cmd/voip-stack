# ZRTC — Security Notes

**Version 1.1 · Post-Phase-6 hardening · Status: living document**

Security posture of the ZRTC stack: what the code guarantees today and what
is enforced by CI. Honest by design — no "secure by roadmap" claims.

---

## 1. Principles

1. **Memory safety is non-negotiable** — `#![forbid(unsafe_code)]` in every
   crate root. The Opus binding uses libopus through its safe public API;
   no raw pointer code exists in the repository.
2. **The parser is the boundary.** All wire input is hostile. Every parser is
   hand-written, panic-free, position-tracking, and bounds-limited *inside*
   the parse loop — callers cannot bypass the limits.
3. **Native over opaque.** Crypto-adjacent primitives (digest computation,
   later SRTP/DTLS) are implemented in-repo or via `ring`/`rustls` — never
   bundled external crypto binaries.
4. **Minimal dependency surface.** No SIP/media server crates; dependency
   additions require a stated reason and an audit pass (`cargo audit` in CI).

## 2. Parser hardening (current)

| Limit | Value | Where |
|-------|-------|-------|
| Max SIP message | 64 KiB | `sip-core::parse` |
| Max headers per message | 128 | `sip-core::parse` |
| Max header line | 8 KiB | `sip-core::parse` |
| Max header name | 64 bytes | `sip-core::parse` |
| Max URI | 2 KiB | `sip-core::parse` |
| SDP lines / line length | bounded, indexed errors | `sdp::parse` |

Behaviors covered by tests (robustness per RFC 3261 §18.3): trailing octets
beyond UDP Content-Length, tolerant `LF`, multi-line folded headers,
stream truncation (`ParseError::Truncated`) for TCP/TLS/WS framing.

Fuzz surface: `sip_parse_request`, `sip_parse_response`, `sdp_parse`,
`rtp_parse`, `rtcp_parse` — cargo-fuzz targets plus stable-toolchain
in-process mutation loops (see [`TESTING.md`](TESTING.md)).

## 3. Authentication

* **Digest (RFC 2617/7616)** helpers are implemented in `sip-core::digest`:
  MD5, MD5-sess, SHA-256, SHA-256-sess; qop `auth`/`auth-int`/none; the RFC
  2617 reference vector is a unit test.
* **Server-side nonce issuance/single-use tracking is live** in the
  `registrar` (401 challenge, one-time nonces, CSeq/Call-ID consistency);
  the trunk layer answers 401/407 challenges with the same helpers.
* **Trunk authentication** supports four modes: IP peering (no
  credentials), Digest (REGISTER or INVITE-challenge), static Bearer
  tokens, and TLS client certificates (mTLS). Secrets come from the
  environment (`ZRTC_TRUNK_USER/PASS/TOKEN`), never from the repo.
* Constant-time comparison for secrets is applied where secrets are compared;
  SRTP tag verification uses the constant-time check in the `srtp` crate.

## 4. Transport security (current state)

| Capability | Status | Notes |
|------------|--------|-------|
| UDP/TCP transports | **Done** | framing + limits; no plaintext assumptions beyond RFC 3261 |
| TLS | **Done** | via whitelisted OpenSSL (same backend as the `dtls` crate); TLS 1.2+; self-signed server identity generated at startup; mTLS client certs for trunks |
| WS/WSS (RFC 7118) | **Done** | listeners wired in `zrtc`; WSS = WS over the same TLS stack |
| SRTP/SRTCP (RFC 3711/7714) | **Done** | key derivation, AES-CM/GCM, replay window (§3.3.3), constant-time tag check, RFC vectors |
| DTLS-SRTP (RFC 5764/6347) | **Done** | handshake over in-repo transport; cert fingerprint binding via SDP |
| SBC edge controls | **Done** | ACL (CIDR allow/deny), per-source token-bucket rate limiting, NAT latching (RFC 3581), topology hiding |

## 5. Supply chain

* `cargo audit` runs in CI on every push; findings block merge.
* `opus 0.3` binds the **system** libopus via pkg-config and is
  feature-gated (`codecs/default = ["opus"]`) — the workspace builds and
  passes tests without it.
* No `serde` deserialization of untrusted input exists outside the `api`
  crate; the control plane confines untrusted JSON to the `api` crate and
  size-limits it at the HTTP layer. CDR/trace JSON written by `observ` is
  self-produced, not client-controlled.
* GitHub Actions use least-privilege `permissions: contents: read`.

## 6. Operational hardening

* Containers run **non-root**; the image contains only the binaries + libopus.
* Structured `tracing` logging; authentication headers are **not** logged at
  info level (digest responses never appear in logs); per-packet RTP is
  kept **out of the human traces** (pcap capture is opt-in per deployment).
* No secrets belong in the repository; config files carry addresses and
  policy, not credentials (`zrtc.toml` + `ZRTC_TRUNK_*` environment
  overrides for trunk secrets).
* Panic-free mandate: library code never `unwrap`s on untrusted input; a
  panic in one connection/transaction must not take down the process
  (enforced by architecture: per-task isolation, no shared locks).

## 7. Threat model sketch

| Threat | Vector | Mitigation today |
|--------|--------|------------------|
| Memory corruption via wire input | malformed SIP/SDP/RTP | safe Rust + bounded panic-free parsers + fuzz gates |
| Resource exhaustion | oversized/flooded messages | hard limits inside parsers (§2); token-bucket rate limiting at the SBC (live) |
| Parsing differentials | compact headers, folding, obs-grammar | canonical normalization at parse; round-trip property tests |
| Replayed/downgraded signaling | missing auth | Digest registrar (one-time nonces), trunk auth modes (IP/Digest/Bearer/mTLS) (live) |
| Media tampering/replay | RTP injection, replay | SRTP replay window + ROC estimation + constant-time tag check (live, vector-verified) |
| Malicious dependency | supply chain | audit gate + minimal-dep policy (§5) |

Items marked with a phase are tracked in the compliance matrix
([`COMPLIANCE.md`](COMPLIANCE.md)) and merged only with the tests that prove
them.
