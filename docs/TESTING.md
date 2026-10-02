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

## 2. Suite inventory (last verified full run: 644 tests, 69 suites)

| Crate | Tests | Focus |
|-------|-------|-------|
| `sip-core` | 68 | URI/headers/message model incl. host-only URIs (§19.1), `Session-Expires`/`refresher` accessors (RFC 4028) and `RSeq`/`RAck` accessors (RFC 3262); `push_via` prepends to the TOP of the Via stack with wire-order proof (§8.1.1/§16.6); datagram + stream framing (split reads, folding, limits, §18.3 trailing octets); canonical serializer round-trips; digest RFC 2617 vectors; fuzz-smoke corpus; builder defaults; `+sip.instance`/`pub-gruu` quoted-generic-param round-trips (quote-aware param split keeps `;`-carrying quoted values whole) and 430/439 reason phrases |
| `sip-tx` | 18 | RFC 3261 §17 state machines with a fake clock: exact timer fire instants (0/500/1500/3500/7500/15500/31500 ms), T2 caps, 64·T1 timeouts, retransmission absorption, wrong-branch/wrong-CSeq rejection, 2xx-ACK-is-a-new-transaction, reliable-transport timer elision, Timer B/F armed on reliable transports and firing at exactly 64·T1 with UDP-parity terminal state, transport-error teardown; non-2xx ACK mirrors a single top Via and keeps the original Route set (§17.1.1.2); non-INVITE server tx enters Proceeding on a provisional and absorbs foreign-method retransmissions (§17.2.2) |
| `sdp` | 33 | parser grammar + positioned errors; canonical serialization (extras keep their `typ=` prefix); RFC 3264 offer/answer (codec/direction intersection, mux, ICE/DTLS carry); §6.1 answer-direction matrix validated for every offer/caps pair and clamped to the offer; rejected m-lines answered port 0 with a null `c=` line of the offer's address type; port-0 offers answered port 0; `m=application … UDP/DTLS/SCTP` offers are answered in kind only when the caps carry data-channel capabilities (RFC 8841: mirrored proto + `webrtc-datachannel`, real port, `a=sctp-port` + `a=max-message-size` raw attributes, mid/ICE/fingerprint/setup echo with the inverse setup role, parse→serialize fixed point) and stay rejected port-0 otherwise (proto + format preserved verbatim, position-stable; wrong-proto/DTLS-SCTP offers rejected even with caps); answer `o=`/`c=` address types follow the local host literal (`IP6` for v6, hostnames stay `IP4` — the offer's family never dictates ours); RFC 8843 BUNDLE group echo (accepted mids only, offer group order, rejected/mid-less m-lines excluded, no group against an unbundled offer); `StreamPlan` projection incl. `rtcp_fb_nack`/`twcc_ext_id` capability extraction; answer echoes the offer's `rtcp-fb` list per accepted payload (RFC 4585 §4.2) and the transport-cc extmap (RFC 8285 §6), and stays clean against an unfeedbacked offer; caps can carry our ICE candidate lines into the answer (prefix-less wire form, parse→serialize fixed point); fuzz-smoke corpus |
| `rtp` | 74 | packet/RTCP parse+serialize round-trips (padding byte-exact incl. bit-without-octets regression); RFC 8285 extensions incl. the one-byte element builder (`RtpExtension::onebyte`, length field = len−1, runtime-validated: reserved ids 0/15 and empty/oversized payloads are errors, never malformed wire) round-tripped through encode/parse; RFC 4733 events; RFC 5761 demux incl. SRTCP auth-trailer (mis)alignment — an encrypted compound with E/index + HMAC trailer is still classified RTCP; jitter buffer with virtual time (reorder, loss→PLC, duplicates, wrap, 32-bit timestamp-wrap playout pacing, sequence-gap concealment guard, SSRC restart, adaptive depth); RFC 4585 Generic NACK (FCI round-trip + PID/BLP expansion, gap detection, repeat throttle, give-up/expiry, SSRC restart clears, wraparound, >16-packet FCI batching); RFC 4588 RTX (packetize→depacketize roundtrip with OSN, CSRC drop, SSRC pinning/learning, foreign-PT/SSRC rejection, bounded pool eviction); transport-cc with the draft's real chunk layout (run chunks T=0; one-bit vector chunks T=1/S=0 at bits 13..0 — libwebrtc/pion's dominant form — encode + hand-built wire-form parse; two-bit vector chunks T=1/S=1 word 0xC000 with symbols at bit pairs 13:12 … 1:0 MSB-first), true inter-arrival recv deltas (first vs reference, rest vs the previous received packet) with sender-side accumulation, small/large/negative deltas, quantization, full RTCP round-trip incl. seq wrap, truncated/reserved rejection, receiver monitor gap markers + 64 ms reference floor + cursor-advance under window saturation (black-hole slide), sender delay/loss correlation relative to the fastest observed packet (clock-domain free) + no-restamp on re-recording, send-history eviction; `NackTracker::highest_extended` wrap-cycle getter; fuzz-smoke corpus |
| `codecs` | 95 | G.711/G.722 bit-exactness (G.722 decoder reset matches a fresh decoder); G.729 ITU tables + interop gates (§3) incl. postfilter output-path regression (80 samples/frame, postfilter presence); Opus binding incl. RFC 6716 frames up to 120 ms and one-frame PLC; L16/CN/PLC (CN multi-byte payload tolerance per RFC 3389 §2.2); resampler; registry |
| `b2bua` | 49 | RFC 4028 timer negotiation matrix + refresh/expiry clock math (unit); RFC 3262 rel100 rules (Timer-G backoff clock, PRACK decision matrix with §4 gates — 100 and non-100rel 1xx never PRACKed — stored-PRACK retransmit, RAck matching, `Supported` merge for 421) (unit); full-loopback integration call: 100/180/200/ACK ordering, PCMU→PCMA transcode with SNR gate, DTMF relay, BYE, CDR trail; session-timer integration flows: negotiation mirrored on the 200s, downstream half-interval refresh, leg-A refresher election, 422/Min-SE floor, 422 retry with the peer's Min-SE, UPDATE refresh, expiry teardown with BYEs on both legs; rel100 integration flows: reliable 180 with the parked 200 (§3), retransmission until PRACK with the STORED PRACK resent (same CSeq and branch), RAck verdicts (481/488), plain-180 + unsolicited PRACK, both-legs PRACK incl. lost-PRACK recovery, 421 dial retry with `Supported` merge, CANCEL-for-unknown-transaction 481; both legs driven by `sip-tx` transactions; per-leg RTCP pump tests (socket-level): NACK answer retransmits the original packet verbatim from the retransmission window with flood-guard counters, gap detection emits Generic NACK naming the missing seqs plus the periodic SR (NTP-epoch-1900 sender info + RR block about the peer), transport-cc feedback appears only when the extmap is negotiated, and an unnegotiated leg stays RTCP-silent on media gaps; sender-side transport-cc: outbound media carries the 2-byte transport-cc ext with an incrementing sequence, retransmissions carry the original sequence, unnegotiated legs send bare media, and inbound feedback about our SSRC correlates into stats (feedback count, window loss, positive excess delay vs the fastest packet); SR compounds carry SDES CNAME (RFC 3550 §6.5.1), standalone NACK/TWCC feedback is RR-prefixed (§6.1), the offer advertises `a=rtcp-mux` (RFC 5761), and SR bookkeeping keys `last_sr` to the peer's media SSRC only; **WebRTC leg integration** (`webrtc_leg`): a mini ICE+DTLS+SRTP caller (controlling agent, DTLS server per actpass/active) INVITEs with `UDP/TLS/RTP/SAVPF`, the answer carries mirrored proto + `ice-ufrag/pwd` + `a=candidate` lines + `a=fingerprint` + `setup:active`, is parse→serialize stable, both sides complete ICE nomination → DTLS-SRTP (AEAD-AES-128-GCM) over the nominated pair, and real PCMU audio crosses SRTP → transcode bridge → plain PCMA UA (echoing) → back as SRTP with clean CDR trail (`webrtc_reject`, own binary: a SAVPF offer without ICE credentials is rejected 488 — no plaintext fallback, no call leak); **data-channel integration** (`webrtc_datachan`): the offer adds `m=application 9 UDP/DTLS/SCTP webrtc-datachannel` (`a=sctp-port`), the answer mirrors the m-line in kind with `a=sctp-port:5000` + our max-message-size and stays roundtrip-stable, then over the SAME established DTLS the caller (SCTP responder — DTLS server, ODD stream 1 per RFC 8832 §5.1/§6) opens a channel, receives the in-band ack, and three user messages — including a 2000 B message the association fragments — echo back byte-for-byte with their PPIDs, all while SRTP PCMU audio keeps round-tripping on the same socket (RFC 7983 demux both directions) and the CDR trail completes; **leg-B WebRTC offerer** (`webrtc_leg_b_active`,
`webrtc_leg_b_passive`, `webrtc_leg_b_reject` — one engine per binary, the CDR
sink is process-global): the B2BUA dials a `webrtc` route with a SAVPF offer
carrying ICE creds/candidates + fingerprint + `setup:actpass` + rtcp-mux +
rtcp-fb (asserted by the mini callee before it answers), runs ICE as the
CONTROLLING agent, and completes DTLS in whichever role the answer picks —
`setup:active` → B2BUA is the DTLS server, `setup:passive` → the client
(RFC 5763 §5) — then SRTP PCMA audio crosses the leg both ways through the
plain-caller bridge with the full CDR trail; a downstream that answers plain
`RTP/AVP` (downgrade) releases the call with 503 instead of degrading;
**leg-B data channels** (`webrtc_leg_b_datachan`, `webrtc_leg_b_dc_rejected`
— one engine per binary): the RFC 8841 mirror policy — when the caller
offered an `m=application` m-line AND the route dials WebRTC, the leg-B
offer carries the same `m=application UDP/DTLS/SCTP webrtc-datachannel`
block (own `a=sctp-port`/`a=max-message-size`, same transport attributes,
`a=mid:0`/`a=mid:1` + session-level `a=group:BUNDLE 0 1` per RFC 8843/5888;
wire form pinned by sdp_util unit tests incl. a parse→serialize fixed point;
the caller's bundled offer gets its group echoed by the leg-A answer) — the mirror loopback proves BOTH legs' associations come up with
role-correct parity (leg B: the callee is the DTLS client → SCTP initiator
opening EVEN stream 0; leg A: the B2BUA is the DTLS client opening even,
the mini caller as DTLS server opens ODD stream 1 — RFC 8832 §5.1/§6),
user messages (one fragmented at 2000 B) echo byte-for-byte with PPIDs on
both legs while SRTP audio bridges, and the CDR trail completes; the
decline test answers the application m-line with port 0 (RFC 3264 §6) —
no association comes up on leg B, audio bridges normally, the call ends
cleanly |
| `srtp` | 42 | RFC 3711 B.2/B.3 + RFC 7714 §16 vectors; RFC 7714 §17.1/§17.3 SRTCP AEAD vectors (encrypted, tagging-only E=0, tamper) pinning the tag-before-index wire order; E=0 authenticate-only acceptance for AEAD and RFC 3711 profiles; round-trips; replay window/ROC semantics |
| `dtls` | 11 | real DTLS 1.2 handshake over UDP loopback, fingerprint pinning, key export, loss-resilient flights, SRTP roundtrip on exported keys; post-handshake app-data (the RFC 8261 seam) round-trips both directions and an oversized write re-concatenates byte-exactly across ordered records (recv buffer sized for the largest DTLS record — the queue transport truncates silently) |
| `ice` | 28 | STUN codec vs RFC 5769 vectors; ERROR-CODE/CHANNEL-NUMBER wire layout; MD5 long-term key + MESSAGE-INTEGRITY against independent known vectors; agent gathering/checks/nomination/role-conflict; IPv6 SDP candidates (bare + bracketed, incl. raddr); TURN allocation (authenticated + unauthenticated idempotent per RFC 5766 §6.2)/permissions/relay; STUN server oracle |
| `sbc` | 9 | ACL, token-bucket rate limiting, NAT latch, topology hiding with the reverse Call-ID map (core responses restore the peer's id), rport |
| `media` | 15 | resampler anti-alias/streaming parity, mixer (inactive inputs skipped, stale inputs stop contributing), recorder, VAD, full codec pipeline test |
| `cdr` | 8 | lifecycle builder, dispositions, bounded store (panic-free at any capacity incl. 0), filters/stats, JSON |
| `dialer` | 11 | pacing modes incl. predictive deficit over dialing+ringing+active, TCPA window, DNC enforced at every candidacy decision, answered leads never re-dialed, attempts/cooldowns, caller-ID rotation |
| `ai-bridge` | 4 | AudioSocket framing, WS tap, VAD events, barge-in latency budget |
| `api` | 10 | REST black-box: CDR queries/filters, campaign stats, pacing preview (incl. caller-supplied `dialed_recent`/`answered_recent`), metrics, health; Prometheus exposition — call counters incremented via `Metrics::record_cdr`, `ws_clients_connected` rendered as a gauge |
| `proxy` | 9 | routing, forking, CANCEL matched on the upstream Via branch, shared request/response transaction keying, Via/Record-Route, 483, NAT response routing |
| `registrar` | 16 | bindings, expiry, wildcard removal, digest challenge, CSeq/Call-ID consistency; 423 `Interval Too Brief` + `Min-Expires` below the configured minimum (binding untouched, expiry 0 exempt); nonce table pruned of expired entries on every challenge; RFC 5626 Outbound (TCP registration with `+sip.instance`/`reg-id=1` echoes a quoted instance, `pub-gruu="AOR;gr=…"`, `reg-id`, `q` and `Flow-Timer: 120` + `Supported: outbound, gruu`, binding stores instance/reg-id/pub-gruu/flow; UDP registration never negotiates Outbound but still gets its GRUU; two reg-ids are distinct bindings and de-registration is scoped to one reg-id; `reg-id=0` → 400) + 200 OK wire-form fixed-point |
| `rfc3263` | 38 | fuzz-smoke corpus (deterministic malformed-corpus + xorshift mutations of a real encoded query through `parse_response`/`read_name`: self-pointing and out-of-range compression pointers, absurd RR counts, unterminated labels, truncations — the parser returns `Result`, never panics); RFC 5452 hardening: owner-name bailiwick filter (strict query-name rule; out-of-zone records dropped, case-insensitive owner match, additional-section SRV-target addresses dropped by design since targets are re-resolved via dedicated A/AAAA queries) and locally-truncated UDP fallback (a datagram filling the 4096 B buffer is retried over TCP BEFORE parsing, so a cut-off response can never contribute a partial record set); RFC 1035 wire codec (query encode incl. label/length limits, response parse with owner-name compression, NAPTR character-strings, A/AAAA, unknown-type passthrough, rcode/TC surfaces, truncated + pointer-loop + RDLENGTH-overrun rejection, backwards pointer chains, uncompressed-name root-byte end-offset regression; RR-count reservation capped by buffer size so a forged header cannot trigger a huge allocation); UDP client (canned SRV round-trip, mismatched-id discard, QR-bit-clear rejection — a reflected query is not an answer, TC→TCP fallback with id patching, silent-server timeout, IPv6 nameserver end-to-end with the family-matched UDP bind); RFC 3263 policy (IP-literal fast path — v4, bracketed and bare v6, zero DNS queries, explicit-port SRV skip, SRV priority ordering, weighted shuffle with zero-weight-last + proportional-distribution sanity over 30k shuffles, unresolvable-target failover, SRV-absent A fallback with 5060/5061 defaults, AAAA-only hosts, NAPTR S-flag service+replacement selection with order/preference sorting, regexp-only/A-flag/non-SIP skipping, replacement-less owner-key SRV, all-paths-dead error, single-failing-family tolerance, resolv.conf parser) |
| `sctp` | 52 | fuzz-smoke corpus (handcrafted nasty packets + xorshift mutations of a valid INIT through `parse_packet` both checksum modes and `dcep::parse` — including the trailing-parameter padding-overrun attack form, absurd SACK gap counts, header-only chunks of every type, truncations; the parsers return `Result`, never panic); wire codec pinned to hand-built byte vectors (INIT field-for-field incl. the Supported-Extensions param, SACK gap-block/dup layout, FORWARD-TSN stream entries, unknown-chunk 4-byte-alignment passthrough, trailing-short-param stop-cleanly, truncated/oversized chunk rejection, checksum corruption rejection); CRC32c validated entry-for-entry against the RFC 9260 Appendix A reference table plus the CRC-32/ISCSI check value (`"123456789"` → `0xE3069283`) and packet-validate roundtrip; DCEP (RFC 8832) OPEN layout pinned byte-for-byte (reliable ordered, partial-reliability unordered `0x81`, lifetime type), ack is the single `0x02` byte, unicode label roundtrip, unknown message types/truncations rejected; association loopback on a virtual clock with a lossy network: four-way handshake both roles, stream-id parity (INIT-sender/DTLS-client EVEN, responder/DTLS-server ODD — RFC 8832 §5.1/§6; a wrong-parity inbound DATA_CHANNEL_OPEN is dropped without an ACK and the association survives), reliable messages both directions, 5000-byte message fragmentation/reassembly, lost-packet T3-RTX recovery, ordered streams hold delivery behind gaps while unordered channels deliver through them, max-retransmits + max-packet-lifetime abandonment with FORWARD-TSN advance and ordered-SSN skip, corrupted-packet silent drop with honest retransmission still arriving, duplicate reporting, graceful three-way SHUTDOWN (and deferred until outstanding acked), ABORT propagation, lost-COOKIE-ECHO T1 recovery, forged-cookie HMAC rejection, heartbeat liveness, `poll_timeout` deadlines, message-size cap and wrong-state/stream errors; **Task 47 hardening regressions**: trailing-short-param padding overrun stops cleanly (unit + corpus), send-buffer overflow rejected with `SendBufferFull` before TSNs are consumed, lost FORWARD-TSN retransmitted until SACK-acked, T2-SHUTDOWN retransmits survive lost SHUTDOWN / SHUTDOWN-ACK (T2 exhaustion aborts with `ShutdownTimeout`), SACK a_rwnd discounts parked/undelivered bytes, cookie nonce makes reissued cookies distinct; **RFC 8832 §5.1 PPID pins**: the emitted DATA_CHANNEL_OPEN chunk carries PPID 50 (spec value — a self-roundtrip suite cannot catch a wrong PPID, the chunk itself is parsed in the test) and user data on RFC 8831 PPIDs (51/53/60000) is delivered as user messages, never swallowed by the DCEP dispatch |
| `observ` | 16 | pcap writers, per-call trace buffer, diag counters (rx/tx/lost/jitter/concealed), redaction of per-packet RTP from traces, obs-fold auth continuation-line redaction |
| `zrtc` | 38 | trunk REGISTER flow (`Flow` mining of `Flow-Timer`/granted expiry, refresh interval = half expiry with floor, Contact expires preference our-contact-first; end-to-end TCP flow test: instance-tagged REGISTER + `Supported: outbound, gruu` on the wire → 200 with Flow-Timer → double-CRLF keep-alive within the timer → refresh on the SAME Call-ID with CSeq+1); trunk address splitting (IPv4/v6 bracketed and bare, bad-port and unclosed-bracket errors, plus hardening: port 0 rejected, trailing junk after `]` rejected, empty host rejected) + RFC 3263 Endpoint resolution on IP literals (explicit port honored, SIP-URI user/params stripped, single-candidate list, v6 literal targets) + keepalive request-URI in `sip:host:port` form; **IPv6 URI bracketing regression** (`host_uri()` brackets literals in request-URIs/keepalives/AORs per RFC 3261 §19.1.2 while the SDP `c=` fallback stays bare per RFC 4566, URIs follow the failover-pinned target, bracketed R-URI parses back); connection-time candidate failover (dead candidate skipped → target pinned to the live winner with the keepalive URI following it, every failed candidate named in the error, target unchanged on total failure, single-candidate behavior unchanged); daemon config parsing + assembly smoke; core response-path regressions (proxy Via pop + SBC processing, b2bua-Via relay, bindings key, client-map cleanup); loopback sink end-to-end (Contact = own host, cached-200 retransmission, PT-filtered echo with negotiated-clock ts step, telephone-event never echoed, no-BYE idle reap); TLS/WSS handshake-budget regressions (silent peer released, slot reusable); TLS client connector chain-verifies the server cert against a configured CA (matching CA accepted, foreign CA rejected); `--since` window parsing (valid windows, malformed values incl. `""` rejected without panic); load-harness stats (nearest-rank percentiles, report aggregation with failure dedup, JSON validity, zero-args validation) — the call loop itself is exercised by `demo/soak.sh` |

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
  clippy 1.99).
* `cargo audit` blocks on published advisories for the dependency tree
  (currently 0 vulnerabilities; one informational unmaintained notice on
  the whitelisted libopus FFI wrapper).
* The `test` job runs the **full workspace**; the `fuzz-smoke` job runs the
  deterministic malformed-input corpora for sip-core/sdp/rtp/sctp/rfc3263; the
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
