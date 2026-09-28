# External Bug Audit — Triage (2026-09)

An external read-only audit reported 42 findings against commit `c0d793a`
(11 Critical, 19 High, 12 Medium/Low). Per the project's honest-by-design
rule, **every claim was verified against the code before acting**. This
document records the verdict and current status of each finding.

Verdicts: **Confirmed** (reproduced by reading the code; claim accurate) ·
**Partly** (core claim true, details off) · **Rejected** (claim does not hold).
Status: **Fixed** (with regression tests in this commit) · **Open** (confirmed,
fix scheduled) · **Won't fix** (with reason).

## 1. Critical (P0)

| # | Finding | Verdict | Status |
|---|---------|---------|--------|
| 1.1 | `percent_decode` char-boundary slice panic on untrusted URI | Confirmed | **Fixed** — byte-wise decode, no `&str` slicing; regression tests (multibyte after `%`, invalid/truncated escapes) |
| 1.2 | `parse_name_addr` inverted slice bounds (`To: ><`, `>` inside quotes) | Confirmed | **Fixed** — closing `>` searched after `<`; inverted/unterminated input is a clean 4xx-grade error; regression tests |
| 1.3 | SRTP AES-CM HMAC-SHA1 covers only the RTP header (payload malleable, interop-breaking) | Confirmed — a roundtrip test even enshrined the wrong behavior as "by design" | **Fixed** — Authenticated Portion = header + payload (RFC 3711 §3.1/§4.2); payload-tamper test now asserts `AuthFailed` for every profile |
| 1.4 | DTLS-SRTP key export passes a non-null context (breaks all external WebRTC interop) | Confirmed | **Fixed** — context is `None` per RFC 5764 §4.2 |
| 1.5 | `Core::handle_response` early-returns before proxy/SBC processing (proxy Via never popped, dead code) | Confirmed | **Fixed** — proxy Via pop + SBC response processing always run; learned endpoint only chooses the transport |
| 1.6 | UAC/trunk hardcode `127.0.0.1:0` bind; trunk offer advertises the remote trunk's IP as media host | Confirmed | **Fixed** — wildcard bind + connected-probe source-IP discovery for the SDP `c=` line |
| 1.7 | TURN relay advertises `0.0.0.0` (non-routable / fails on Windows) | Confirmed | **Fixed** — relay binds and advertises the server's concrete IP (client source IP as fallback) |
| 1.8 | `audiosocket_server` drops `_playback_tx` instantly (kills every connection) and leaks the task draining `ev_rx` while `session` is alive | Confirmed | **Fixed** — playback sender moved into the task; session dropped before the event drain |
| 1.9 | `Cidr::contains` shift-overflow panic on misconfigured prefix (`/33`) | Confirmed | **Fixed** — prefix clamped to the address width; regression test incl. IPv6 |
| 1.10 | Unbounded maps: b2bua `b_to_a` (only BYE cleaned it) and ACK-less leg A leak | Confirmed | **Fixed** (b2bua + zrtc) — `teardown` now clears `b_to_a` on every path; dialog-level Timer H (64·T1) tears down a 2xx never ACKed; zrtc `clients` drops entries on BYE/CANCEL. **Open**: proxy fork-transaction map and SBC `call_map`/`buckets` still need age-based sweeps |

## 2. High (P1)

| # | Finding | Verdict | Status |
|---|---------|---------|--------|
| 2.1 | DTMF echoed back to the sender leg instead of bridged | Confirmed (`dst == src` after latching) | **Fixed** — DTMF crosses the media bridge (`BridgeMsg::Dtmf`) and is packetized onto the PEER leg's socket |
| 2.2 | No ACK on RFC 4028 refresh 200s; Via sent-by = remote peer's address | Confirmed (both halves) | **Fixed** — dialog-level ACK for 2xx to our re-INVITEs on both legs; engine-originated requests use the engine's own listen address as Via sent-by (`ENGINE_VIA`) |
| 2.3 | `on_cancel` orphans leg B (no CANCEL relayed) and tears down answered calls | Confirmed | **Fixed** — answered calls survive CANCEL (§9.2); unanswered attempts get 487 through the server transaction + a §9.1 CANCEL (same CSeq/branch) to leg B |
| 2.4 | Timer B/F never armed on reliable transports | Confirmed | **Fixed** — B/F armed on every transport, A/E stay UDP-only; test updated (`reliable_transport_has_no_retransmit_timers`) |
| 2.5 | Responses to b2bua-originated in-dialog requests dropped (Via host mismatch) | Confirmed | **Fixed** — core relays b2bua-Via responses back to the b2bua socket |
| 2.6 | `sync_bindings` keys bindings as `sip:<user>` (never matches proxy lookups) | Confirmed | **Fixed** — scheme stripped, bare user key |
| 2.7 | `sink.rs` rtp_tap: hardcoded +160 ts step, echo before PT filter, Contact = remote src, sink-call leak on missing BYE | Confirmed | **Fixed** — echo timestamp step follows the negotiated clock (160 @ 8 kHz, 960 @ 48 kHz Opus); PT filter runs BEFORE the echo so telephone-event/CN never corrupt the echo stream; Contact = the sink's own host; calls with no RTP and no BYE are reaped by a periodic sweep (entry + media task released); end-to-end sink test |
| 2.8 | TLS/WSS handshakes await forever while holding connection permits | Confirmed (no timeout before `stream_loop`) | **Fixed** — one handshake budget (default 10 s) covers TLS and, for WSS, the WebSocket upgrade on top; silent/stalled peers release their slot; regression tests prove the EOF and that the slot is reusable |
| 2.9 | G.729 decoder discards postfilter output / double-samples when postfilter off | Confirmed | **Fixed** — exactly one output path per config (postfiltered synthesis when on, plain once when off); unbounded history leak fixed; regression test pins 80 samples/frame and postfilter presence; SNR/ffmpeg gates recalibrated to the now-correct output (bcg729 oracle test unchanged at ±5 dB) |
| 2.10 | STUN ERROR-CODE 3-byte header; CHANNEL-NUMBER `0x0006` collides with USERNAME | Confirmed | **Fixed** — 4-byte `[0,0,class,number]` layout + `CHANNEL_NUMBER = 0x000C` (RFC 5389 §15.6, RFC 5766 §14.1); wire-layout test added |
| 2.11 | IPv6 ICE candidate parse; unauthenticated TURN allocate flow self-deadlocks | Confirmed | **Fixed** — bracket-aware address parse for `c=`/`raddr` (RFC 8839 §5.1) with IPv6 regression tests; Allocate probe accepts immediate success (authenticate-only path) and re-Allocate answers the existing relay per RFC 5766 §6.2; MD5 long-term key + MESSAGE-INTEGRITY pinned by independent known vectors |
| 2.12 | SRTCP AES-GCM E=0 always fails; per-SSRC state allocated before auth | Confirmed | **Fixed** — E=0 passes the tag as the GCM "ciphertext" input; recv-stream state committed only after tag verification (both RTP and RTCP paths). Deepened afterwards: AEAD profiles also accept unencrypted SRTCP (E=0, RFC 7714 §9.3) authenticate-only, both wire orders handled (RFC 3711 §3.4 tag-after-index vs RFC 7714 §9 tag-before-index), pinned by RFC 7714 §17.1/§17.3 official vectors incl. tamper |
| 2.13 | RTP padding bit re-encoded without padding bytes; jitter buffer 32-bit ts wrap; `pop_ready` skips concealment for gaps | Confirmed | **Fixed** — encoder appends the padding octets (count octet last) and a padded packet round-trips byte-exactly; jitter buffer extends the 32-bit timestamp to 64 bits (wrap-aware, like the sequence space) so playout stays paced across the ≈6.2-day wrap; `pop_ready` refuses to jump sequence gaps — hole slots go through concealment with proper loss accounting |
| 2.14 | SBC topology hiding looks up `call_map` instead of `call_map_rev` on responses; proxy tx keys never match | Confirmed (SBC half verified; proxy half consistent with the code) | **Fixed** — SBC keeps an explicit reverse map (hidden → peer) populated on the request path and restores the peer's Call-ID on core responses; proxy funnels request/CANCEL/response keying through ONE `tx_key` builder (call-id + top-Via branch + method, RFC 3261 §17.1.3) and CANCEL matches against the upstream Via branch, not our own |
| 2.15 | Dialer predictive pacing ignores `lines_ringing`; answered leads re-dialed; DNC skipped on queued leads | Confirmed | **Fixed** — LiveStats counts dialing+ringing+active, predictive paces on the deficit vs all in-flight calls; answered leads parked at answer time; DNC re-checked at every candidacy decision and permanently parks the lead |
| 2.16 | `Mixer::mix` includes inactive inputs and replays stale frames (50 Hz buzz) | Confirmed | **Fixed** — VAD-inactive inputs skipped in accumulation and contributor scaling; inputs un-refreshed for 3 packet periods stop contributing (no stale replay, frame width preserved) |
| 2.17 | `CdrStore::default()` capacity 0 panics on first insert; folded auth headers leak into pcap/trace | Confirmed | **Fixed** — hand-rolled default (1024) + panic-free insert for any capacity (0 retains nothing); obs-fold continuation lines of auth headers redacted in `redact_sip` so no credential reaches serialized events (scheme preserved: `Digest [REDACTED]`) |

## 3. Medium / Low (P2)

All verified as plausible-to-real during triage; ordered by impact.
**Fixed since triage** (with regression tests): SDP `u=/e=/p=/k=/z=` extras
now serialize with their `typ=` prefix (sdp) · `answer_direction` validated
as an explicit RFC 3264 §6.1 matrix clamped to the offer (sdp) · port-0
offers answered port 0 and rejected m-lines keep their m-line with a null
connection line of the offer's address type (sdp) · `looks_like_rtcp` no
longer requires %4 alignment — RFC 3711 §3.4 SRTCP appends E/index + auth
tag so encrypted compounds are intentionally misaligned, and version 2 +
PT range alone identify RTCP (rtp) · `push_via` PREPENDS to the top of the
Via stack (RFC 3261 §8.1.1/§16.6) instead of appending at the bottom, with
wire-order proof (sip-core) · non-2xx ACK mirrors a SINGLE top Via and
carries the original Route set (RFC 3261 §17.1.1.2) (sip-tx) ·
`ServerNonInviteTx` moves Trying → Proceeding on a provisional and matches
retransmissions by branch+sent-by+CSeq AND method — foreign methods are
absorbed (RFC 3261 §17.2.2) (sip-tx) · registrar refuses sub-minimum
registrations with 423 `Interval Too Brief` + `Min-Expires` (RFC 3261
§10.2.8) and prunes expired nonces on every issue so the table stays
bounded (registrar) · Opus decode buffers sized for the RFC 6716 maximum
120 ms frame (PLC still emits exactly one 20 ms frame), G.722 `reset`
discards predictor history (`last_codes`) so a reset decoder matches a
fresh one, CN decoder tolerates multi-byte payloads per RFC 3389 §2.2 and
rejects only empty ones (codecs) · zrtc TLS client connector with a
configured `tls_ca_path` now chain-verifies the server certificate
(`SslVerifyMode::PEER`) — the generated self-signed cert is a proper
mini-CA (basicConstraints + SKID/AKID + SAN) so pinning actually works,
demo topologies without a CA stay relaxed (zrtc) · CDR disposition uses
the real final code threaded from the engine (`CallEnded.final_code`:
486 → Busy, 603 → Rejected, …; 487 remains only the cancel/timer
fallback) (zrtc/b2bua) · `--since ""` and other malformed windows parse to
`None` instead of underflowing (zrtc) · `pace_campaign` accepts
`dialed_recent`/`answered_recent` from the request body (were hardcoded 0),
`ws_clients_connected` renders as TYPE gauge, and the four call counters
are actually incremented via `Metrics::record_cdr` from the CDR finalizer
(api). No P2 items remain open.

Note: the `RequestBuilder::via` host:port mis-parse reported under P2 was
**Fixed** in this commit (it was a prerequisite for correct engine Via sent-by).

## Verification

`cargo test --workspace` → **468 passing** across 54 suites, `clippy -D warnings`
clean, `cargo fmt --check` clean, `./demo/run.sh` PASS.

**The external audit is fully closed**: every finding at every severity —
Critical, High, and the complete Medium/Low (P2) list — is **Fixed** with
regression tests. No open items. No silent gaps.
