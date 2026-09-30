# ZRTC — Testing Guide

**Version 1.1 · Post-Phase-6 hardening · How the stack is verified**

Rules of the road: every public function carries tests (workspace rule);
parsers are tested for round-trip equality *and* panic-freedom; timing paths
are tested with virtual/configurable time, never sleeps.

---

## 1. Commands

```sh
cargo test --workspace                  # unit + integration + interop suites
cargo test -p sip-tx --release          # transaction state machines at exact timer instants
cargo test -p sip-core                  # single crate
cargo test --workspace --no-default-features
                                        # build/test without system libopus
cargo bench -p sdp                      # criterion benches where present
RUST_LOG="info,b2bua=debug" cargo test -p b2bua -- --nocapture
                                        # verbose engine runs
```

Toolchain is pinned by `rust-toolchain.toml` (stable). System dependency:
`pkg-config` + `libopus-dev` unless building `--no-default-features`.

## 2. Suite inventory (last verified full run: 555 tests, 56 suites)

| Crate | Tests | Focus |
|-------|-------|-------|
| `sip-core` | 67 | URI/headers/message model incl. host-only URIs (§19.1), `Session-Expires`/`refresher` accessors (RFC 4028) and `RSeq`/`RAck` accessors (RFC 3262); `push_via` prepends to the TOP of the Via stack with wire-order proof (§8.1.1/§16.6); datagram + stream framing (split reads, folding, limits, §18.3 trailing octets); canonical serializer round-trips; digest RFC 2617 vectors; fuzz-smoke corpus; builder defaults |
| `sip-tx` | 18 | RFC 3261 §17 state machines with a fake clock: exact timer fire instants (0/500/1500/3500/7500/15500/31500 ms), T2 caps, 64·T1 timeouts, retransmission absorption, wrong-branch/wrong-CSeq rejection, 2xx-ACK-is-a-new-transaction, reliable-transport timer elision, Timer B/F armed on reliable transports and firing at exactly 64·T1 with UDP-parity terminal state, transport-error teardown; non-2xx ACK mirrors a single top Via and keeps the original Route set (§17.1.1.2); non-INVITE server tx enters Proceeding on a provisional and absorbs foreign-method retransmissions (§17.2.2) |
| `sdp` | 30 | parser grammar + positioned errors; canonical serialization (extras keep their `typ=` prefix); RFC 3264 offer/answer (codec/direction intersection, mux, ICE/DTLS carry); §6.1 answer-direction matrix validated for every offer/caps pair and clamped to the offer; rejected m-lines answered port 0 with a null `c=` line of the offer's address type; port-0 offers answered port 0; answer `o=`/`c=` address types follow the local host literal (`IP6` for v6, hostnames stay `IP4` — the offer's family never dictates ours); RFC 8843 BUNDLE group echo (accepted mids only, offer group order, rejected/mid-less m-lines excluded, no group against an unbundled offer); `StreamPlan` projection incl. `rtcp_fb_nack`/`twcc_ext_id` capability extraction; answer echoes the offer's `rtcp-fb` list per accepted payload (RFC 4585 §4.2) and the transport-cc extmap (RFC 8285 §6), and stays clean against an unfeedbacked offer; fuzz-smoke corpus |
| `rtp` | 71 | packet/RTCP parse+serialize round-trips (padding byte-exact incl. bit-without-octets regression); RFC 8285 extensions incl. the one-byte element builder (`RtpExtension::onebyte`, length field = len−1) round-tripped through encode/parse; RFC 4733 events; RFC 5761 demux incl. SRTCP auth-trailer (mis)alignment — an encrypted compound with E/index + HMAC trailer is still classified RTCP; jitter buffer with virtual time (reorder, loss→PLC, duplicates, wrap, 32-bit timestamp-wrap playout pacing, sequence-gap concealment guard, SSRC restart, adaptive depth); RFC 4585 Generic NACK (FCI round-trip + PID/BLP expansion, gap detection, repeat throttle, give-up/expiry, SSRC restart clears, wraparound, >16-packet FCI batching); RFC 4588 RTX (packetize→depacketize roundtrip with OSN, CSRC drop, SSRC pinning/learning, foreign-PT/SSRC rejection, bounded pool eviction); transport-cc (vector/run chunk encode+parse, small/large/negative deltas, quantization, hand-built wire-form guard, full RTCP round-trip incl. seq wrap, truncated/reserved rejection, receiver monitor gap markers + 64 ms reference floor, sender delay/loss correlation, send-history eviction); `NackTracker::highest_extended` wrap-cycle getter; fuzz-smoke corpus |
| `codecs` | 95 | G.711/G.722 bit-exactness (G.722 decoder reset matches a fresh decoder); G.729 ITU tables + interop gates (§3) incl. postfilter output-path regression (80 samples/frame, postfilter presence); Opus binding incl. RFC 6716 frames up to 120 ms and one-frame PLC; L16/CN/PLC (CN multi-byte payload tolerance per RFC 3389 §2.2); resampler; registry |
| `b2bua` | 36 | RFC 4028 timer negotiation matrix + refresh/expiry clock math (unit); RFC 3262 rel100 rules (Timer-G backoff clock, PRACK decision matrix with §4 gates — 100 and non-100rel 1xx never PRACKed — stored-PRACK retransmit, RAck matching, `Supported` merge for 421) (unit); full-loopback integration call: 100/180/200/ACK ordering, PCMU→PCMA transcode with SNR gate, DTMF relay, BYE, CDR trail; session-timer integration flows: negotiation mirrored on the 200s, downstream half-interval refresh, leg-A refresher election, 422/Min-SE floor, 422 retry with the peer's Min-SE, UPDATE refresh, expiry teardown with BYEs on both legs; rel100 integration flows: reliable 180 with the parked 200 (§3), retransmission until PRACK with the STORED PRACK resent (same CSeq and branch), RAck verdicts (481/488), plain-180 + unsolicited PRACK, both-legs PRACK incl. lost-PRACK recovery, 421 dial retry with `Supported` merge, CANCEL-for-unknown-transaction 481; both legs driven by `sip-tx` transactions; per-leg RTCP pump tests (socket-level): NACK answer retransmits the original packet verbatim from the retransmission window with flood-guard counters, gap detection emits Generic NACK naming the missing seqs plus the periodic SR (NTP-epoch-1900 sender info + RR block about the peer), transport-cc feedback appears only when the extmap is negotiated, and an unnegotiated leg stays RTCP-silent on media gaps; sender-side transport-cc: outbound media carries the one-byte ext with an incrementing sequence, retransmissions carry the original sequence, unnegotiated legs send bare media, and inbound feedback about our SSRC correlates into stats (feedback count, window loss, positive mean delay) |
| `srtp` | 42 | RFC 3711 B.2/B.3 + RFC 7714 §16 vectors; RFC 7714 §17.1/§17.3 SRTCP AEAD vectors (encrypted, tagging-only E=0, tamper) pinning the tag-before-index wire order; E=0 authenticate-only acceptance for AEAD and RFC 3711 profiles; round-trips; replay window/ROC semantics |
| `dtls` | 10 | real DTLS 1.2 handshake over UDP loopback, fingerprint pinning, key export, loss-resilient flights, SRTP roundtrip on exported keys |
| `ice` | 28 | STUN codec vs RFC 5769 vectors; ERROR-CODE/CHANNEL-NUMBER wire layout; MD5 long-term key + MESSAGE-INTEGRITY against independent known vectors; agent gathering/checks/nomination/role-conflict; IPv6 SDP candidates (bare + bracketed, incl. raddr); TURN allocation (authenticated + unauthenticated idempotent per RFC 5766 §6.2)/permissions/relay; STUN server oracle |
| `sbc` | 9 | ACL, token-bucket rate limiting, NAT latch, topology hiding with the reverse Call-ID map (core responses restore the peer's id), rport |
| `media` | 15 | resampler anti-alias/streaming parity, mixer (inactive inputs skipped, stale inputs stop contributing), recorder, VAD, full codec pipeline test |
| `cdr` | 8 | lifecycle builder, dispositions, bounded store (panic-free at any capacity incl. 0), filters/stats, JSON |
| `dialer` | 11 | pacing modes incl. predictive deficit over dialing+ringing+active, TCPA window, DNC enforced at every candidacy decision, answered leads never re-dialed, attempts/cooldowns, caller-ID rotation |
| `ai-bridge` | 4 | AudioSocket framing, WS tap, VAD events, barge-in latency budget |
| `api` | 10 | REST black-box: CDR queries/filters, campaign stats, pacing preview (incl. caller-supplied `dialed_recent`/`answered_recent`), metrics, health; Prometheus exposition — call counters incremented via `Metrics::record_cdr`, `ws_clients_connected` rendered as a gauge |
| `proxy` | 9 | routing, forking, CANCEL matched on the upstream Via branch, shared request/response transaction keying, Via/Record-Route, 483, NAT response routing |
| `registrar` | 11 | bindings, expiry, wildcard removal, digest challenge, CSeq/Call-ID consistency; 423 `Interval Too Brief` + `Min-Expires` below the configured minimum (binding untouched, expiry 0 exempt); nonce table pruned of expired entries on every challenge |
| `rfc3263` | 31 | RFC 1035 wire codec (query encode incl. label/length limits, response parse with owner-name compression, NAPTR character-strings, A/AAAA, unknown-type passthrough, rcode/TC surfaces, truncated + pointer-loop + RDLENGTH-overrun rejection, backwards pointer chains, uncompressed-name root-byte end-offset regression); UDP client (canned SRV round-trip, mismatched-id discard, TC→TCP fallback with id patching, silent-server timeout); RFC 3263 policy (IP-literal fast path — v4, bracketed and bare v6, zero DNS queries, explicit-port SRV skip, SRV priority ordering, weighted shuffle with zero-weight-last + proportional-distribution sanity over 30k shuffles, unresolvable-target failover, SRV-absent A fallback with 5060/5061 defaults, AAAA-only hosts, NAPTR S-flag service+replacement selection with order/preference sorting, regexp-only/A-flag/non-SIP skipping, replacement-less owner-key SRV, all-paths-dead error, single-failing-family tolerance, resolv.conf parser) |
| `observ` | 16 | pcap writers, per-call trace buffer, diag counters (rx/tx/lost/jitter/concealed), redaction of per-packet RTP from traces, obs-fold auth continuation-line redaction |
| `zrtc` | 33 | trunk address splitting (IPv4/v6 bracketed and bare, bad-port and unclosed-bracket errors) + RFC 3263 Endpoint resolution on IP literals (explicit port honored, SIP-URI user/params stripped, single-candidate list, v6 literal targets) + keepalive request-URI in `sip:host:port` form; connection-time candidate failover (dead candidate skipped → target pinned to the live winner with the keepalive URI following it, every failed candidate named in the error, target unchanged on total failure, single-candidate behavior unchanged); daemon config parsing + assembly smoke; core response-path regressions (proxy Via pop + SBC processing, b2bua-Via relay, bindings key, client-map cleanup); loopback sink end-to-end (Contact = own host, cached-200 retransmission, PT-filtered echo with negotiated-clock ts step, telephone-event never echoed, no-BYE idle reap); TLS/WSS handshake-budget regressions (silent peer released, slot reusable); TLS client connector chain-verifies the server cert against a configured CA (matching CA accepted, foreign CA rejected); `--since` window parsing (valid windows, malformed values incl. `""` rejected without panic); load-harness stats (nearest-rank percentiles, report aggregation with failure dedup, JSON validity, zero-args validation) — the call loop itself is exercised by `demo/soak.sh` |

Counts move with the code; CI (§4) is the authoritative gate on every push.

## 3. Interop & conformance gates

| Gate | Mechanism | Threshold |
|------|-----------|-----------|
| G.729 decode fidelity | `codecs/tests/g729_interop.rs` decodes **bcg729 golden vectors** | output level within ±5 dB of reference (postfilter implementations differ) |
| G.729 bitstream conformance | ffmpeg cross-decodes **our** encoder output in CI (runtime-detected) | decodes without gross corruption (±6 dB) |
| G.711 / G.722 | bit-exact round-trip against ITU structures | exact |
| Opus | libopus round-trip at supported modes | decodes, sane RMS |
| SIP/SDP/RTP/RTCP | `parse(serialize(x)) == x` property tests | exact equality |

The G.729 encoder's known fidelity deltas on synthetic fixtures are
**wire-invisible** and documented in `codecs/src/g729.rs` and
[`COMPLIANCE.md`](COMPLIANCE.md) §3 — the conformance contract is the
bitstream, verified by two independent third-party decoders.

## 4. CI gates

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every
push/PR: **fmt → clippy → test → audit → codec-interop**, with pkg-config +
libopus installed for workspace jobs.

Current state:

* `fmt-check` is strict (the tree is rustfmt-clean).
* clippy runs with **`-D warnings`** (workspace is warning-free, pinned
  clippy 1.98).
* `cargo audit` blocks on published advisories for the dependency tree
  (currently 0 vulnerabilities; one informational unmaintained notice on
  the whitelisted libopus FFI wrapper).
* The `test` job runs the **full workspace**; the `fuzz-smoke` job runs the
  deterministic malformed-input corpora for sip-core/sdp/rtp; the
  `codec-interop` job cross-decodes our G.729 encoder output with ffmpeg.

## 5. Property & robustness testing

* **Round-trip laws**: SIP messages, SDP sessions, RTP/RTCP packets satisfy
  `parse(serialize(x)) == x` (with RFC-permitted canonicalization).
* **Panic-freedom**: every parser entry point is exercised with random bytes
  and structured mutations via in-process loops (stable toolchain, so CI runs
  them everywhere); `cargo-fuzz` targets mirror the same entry points for
  nightly/local campaigns.
* **Virtual time**: the jitter buffer and the `sip-tx` transaction timers
  are driven by injected clocks/virtual time in tests — the same code paths
  that run in production, without wall-clock sleeps. T1 is configurable
  (default 500 ms; the `sip-tx` tests assert exact fire instants with a
  fake clock).

## 6. Integration & end-to-end (as crates land)

| Stage | Scenario | Assertion style |
|-------|----------|-----------------|
| Transport | UDP loopback; TCP split-read + coalesced messages; TLS loopback with self-signed test certs; WS/WSS framing | message-level equality, framing invariants |
| Transaction | UAC/UAS INVITE + non-INVITE state walks; retransmit cadence; timeout paths; stray-packet absorption | state/order assertions at T1=10 ms |
| B2BUA | UAC ↔ B2BUA ↔ UAS full call: 100/180/200/ACK ordering, bidirectional RTP, DTMF relay, BYE teardown, CDR trail; RFC 3262 reliable-1xx flows on both legs incl. §4 gates and stored-PRACK retransmission | signaling order + audio SNR gates (e.g. ≥12 dB transcode) + event completeness |
| Load (later) | N concurrent calls smoke; Phase-6 harness | setup-time P95, zero-call-loss under restart |

## 7. Benchmarks (targets)

| Bench | Target |
|-------|--------|
| SIP request parse | ≥150k msg/s/core (~60 MB/s) |
| SIP serialize | ≥200k msg/s/core |
| SDP parse (3 m-line typical) | ≥40k/s/core |
| RTP parse+serialize | ≥2M pkt/s/core |
| Jitter buffer push/pop | ≥1M ops/s/core |

Criterion benches live beside their crates (`cargo bench -p <crate>`); the
Phase-3 report records numbers against these targets.
