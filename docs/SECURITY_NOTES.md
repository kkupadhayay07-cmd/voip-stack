# ZRTC — Security Notes

**Version 1.0 · Phase 1 · Status: living document**

Security posture of the ZRTC stack: what the code guarantees today, what is
enforced by CI, and what lands in which phase. Honest by design — no
"secure by roadmap" claims.

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
* Server-side nonce issuance/single-use tracking lands with the registrar
  (Phase 3); challenge construction is reusable before that.
* Constant-time comparison for secrets is applied where secrets are compared;
  full `subtle`-style audit is a Phase-2 gate together with SRTP tag
  verification.

## 4. Transport security roadmap

| Phase | Capability | Notes |
|-------|------------|-------|
| 1 | UDP/TCP transports | framing + limits only; no plaintext assumptions beyond RFC 3261 |
| 2 | TLS via rustls (ring), TLS 1.2+1.3 | server + client, SNI; self-signed certs are test-only |
| 2 | WS/WSS (RFC 7118) | SIP text frames; WSS = WS over the same TLS stream |
| 2 | SRTP/SRTCP (RFC 3711/7714) | key derivation, AES-CM/GCM, replay window (§3.3.3), constant-time tag check |
| 2 | DTLS-SRTP (RFC 5764/6347) | handshake over in-repo transport; cert fingerprint binding via SDP |
| 3 | SBC edge controls | ACL (CIDR allow/deny), per-source token-bucket rate limiting, NAT latching (RFC 3581), topology hiding |

## 5. Supply chain

* `cargo audit` runs in CI on every push; findings block merge.
* `opus 0.3` binds the **system** libopus via pkg-config and is
  feature-gated (`codecs/default = ["opus"]`) — the workspace builds and
  passes tests without it.
* No `serde` deserialization of untrusted input exists yet; when the control
  plane lands (Phase 6), untrusted JSON is confined to the `api` crate and
  size-limited at the HTTP layer.
* GitHub Actions use least-privilege `permissions: contents: read`.

## 6. Operational hardening

* Containers run **non-root**; the image contains only the binary + libopus.
* Structured `tracing` logging; authentication headers are **not** logged at
  info level (digest responses never appear in logs).
* No secrets belong in the repository; config files carry addresses and
  policy, not credentials (daemon config lands with `voipd`/`zrtc`).
* Panic-free mandate: library code never `unwrap`s on untrusted input; a
  panic in one connection/transaction must not take down the process
  (enforced by architecture: per-task isolation, no shared locks).

## 7. Threat model sketch (Phase-1 scope)

| Threat | Vector | Mitigation today |
|--------|--------|------------------|
| Memory corruption via wire input | malformed SIP/SDP/RTP | safe Rust + bounded panic-free parsers + fuzz gates |
| Resource exhaustion | oversized/flooded messages | hard limits inside parsers (§2); rate limiting at SBC in Phase 3 |
| Parsing differentials | compact headers, folding, obs-grammar | canonical normalization at parse; round-trip property tests |
| Replayed/downgraded signaling | missing auth | digest helpers ready; full challenge flows in Phase 3 |
| Malicious dependency | supply chain | audit gate + minimal-dep policy (§5) |

Items marked with a phase are tracked in the compliance matrix
([`COMPLIANCE.md`](COMPLIANCE.md)) and merged only with the tests that prove
them.
