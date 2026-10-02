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

`cargo test --workspace` → **656 passing** across 70 suites, `clippy -D warnings`
clean, `cargo fmt --check` clean, `./demo/run.sh` PASS.

**The external audit is fully closed**: every finding at every severity —
Critical, High, and the complete Medium/Low (P2) list — is **Fixed** with
regression tests. No open items. No silent gaps.

---

# Self-Audit of Tasks 39–42 (2026-09, Task 43)

After the Task 39–42 feature wave (NACK/RTX/TWCC library, B2BUA RTCP
plumbing, RFC 3263 discovery + failover), a three-track read-only audit
(b2bua media pump / rfc3263+zrtc / rtp nack-rtx-twcc) re-examined the new
code against the RFCs and the libwebrtc/pion reference implementations.
**1 Critical + 5 Major + ~12 minor findings** — all verified against the
code before acting (same rule as the external audit). Fixed in this commit:

## Fixed

| # | Finding | Severity | Fix |
|---|---------|----------|-----|
| S1 | TWCC status-vector chunks: encoder wrote 7×2-bit symbols under word `0x8000` (S-bit ignored, symbols also misplaced one bit left of the spec's `12−2k` layout); parser treated every T=1 chunk as 2-bit. Wire-incompatible with Chrome/pion in BOTH directions while self-roundtrips stayed green | **Critical** | Encoder emits `0xC000` for 2-bit chunks (spec bit order) and compact 1-bit vector chunks (14 symbols at bits 13..0) when no large delta is pending; parser dispatches on the S-bit. Hand-built spec wire-form tests + libwebrtc-layout vector |
| S2 | TWCC recv deltas were offsets-from-reference, not inter-arrival deltas (§3.1.5); sender reconstructed per-packet without accumulating — a conformant peer's BWE would see exploding arrival times | **Major** | `build_feedback` reports deltas vs the previous RECEIVED packet; `on_feedback` accumulates from the reference. Monitor test re-pinned (40 000/5 000/7 000) |
| S3 | transport-cc sequence carried as a 1-byte element; the draft requires 2 bytes BE (Chrome rejects both directions) | **Major** | `attach_twcc` writes `seq.to_be_bytes()`, reader accepts `data_len == 2`; the u8→u16 unwrap loop deleted |
| S4 | TWCC delay = `recv − sent` across INDEPENDENT clock domains (peer epoch vs our pump elapsed) — the stat was meaningless garbage in production | **Major** | `TwccSendTracker` estimates the clock offset (min observed raw delay) and reports EXCESS delay vs the fastest observed packet — domain-free, like reference delay estimators |
| S5 | zrtc emitted bare IPv6 literals inside SIP URIs (keepalive/R-URI/AOR) — unparseable (`sip:2001:db8::1:5060`); SDP `c=` needs the BARE form while URIs need brackets | **Major** | New `host_uri()` (bracketed, RFC 3261 §19.1.2) used for URIs; `host()` kept bare for RFC 4566 `c=`; failover pinning keeps URIs following the winner; regression test parses the bracketed R-URI back |
| S6 | Blocking RFC 3263 DNS + libc fallback ran on tokio workers (daemon + `zrtc call`), stalling the runtime and making the outer `timeout` unenforceable (up to ~20 s+ on a black-holed resolver) | **Major** | Resolution wrapped in `spawn_blocking` at both call sites |
| S7 | SDP offered `rtcp_mux: false` while the pump is mux-only — strict non-zrtc peers would address RTCP at port+1 (never bound) and the whole RTCP channel would silently die | **Major** | Offer advertises `a=rtcp-mux`; the serializer now emits it from the typed mirror (parse consumes it — roundtrip stays a fixed point), negotiation echoes it when offered |
| S8 | RFC 3550 compound violations: NACK/TWCC sent as bare RTPFB (§6.1: compounds start with SR/RR); SR compounds lacked SDES CNAME (§6.5.1 MUST) | Minor | Empty-RR prefix on standalone feedback; CNAME (`zrtc-<ssrc>`) appended to every SR compound |
| S9 | SR field accuracy: cumulative-lost clamp allowed the sign bit of the signed 24-bit field (`0xFFFFFF` reads negative); DLSR quantization drifted up to 7.4 ms (ms shortcut); jitter truncated to whole ms (0.9 ms → 0); `last_sr` accepted an SR from ANY sender SSRC | Minor | Clamp `0x007F_FFFF`; DLSR via µs × 65536 / 1e6 rounded; jitter via µs; `last_sr` recorded only when the SR sender == the peer's media SSRC |
| S10 | SR packet/octet counters incremented for packets never sent (dst not yet latched) — RFC 3550 §6.4.1 counts SENT packets; `RtpExtension::onebyte` validated ids/lengths with `debug_assert` only (release builds could emit malformed wire); `TwccSendTracker::record_send` re-stamped retransmits; `TwccRxMonitor` cursor froze when a gap run saturated the pending window | Minor | Counters/counters move into the send path; `onebyte` returns `Result` with runtime checks (+regression test); `or_insert` on record; monitor slides the window (oldest dropped) so the cursor always advances (+regression test) |
| S11 | rfc3263 hardening: forged 12-byte header could trigger a ~12 MB allocation (`with_capacity` of unvalidated RR counts); IPv6 nameserver from resolv.conf failed on the IPv4-only UDP bind; QR bit never checked (a reflected QUERY accepted); query IDs re-derived per call from the wall clock | Minor | RR-count reservation capped by buffer size; family-matched UDP bind (+v6 FakeDns e2e test); QR-bit check in UDP + TCP accept (+canned-query rejection test); process-wide atomic xorshift ID state |
| S12 | `split_host_port` accepted port 0 (→ confusing later failures), silently dropped junk after `]`, accepted empty hosts | Minor | Port 0, trailing junk, and empty hosts are rejected with clear errors (+test edges) |

## Deferred (documented, not silent)

* Non-mux RTCP port (port+1) listener — we advertise rtcp-mux instead;
  strict non-mux peers remain unsupported (COMPLIANCE §5).
* ~~DNS bailiwick (owner-name) filtering of response records; TCP fallback on
  locally-truncated UDP datagrams without the server TC flag~~ — FIXED in
  Task 45 (see the DNS hardening note below; workspace 571→574).
* RTP destination from the SDP answer's `c=` line (split signaling/media
  hosts) — pre-existing, now documented in COMPLIANCE §5.
* RTCP BYE on media teardown; `nacks_tx` counts FCI entries (documented).
* SCTP (Task 47): fast retransmit on gap-ack/dup-SACK signals (loss recovery
  waits a full RTO); zero-window probe when the peer advertises a_rwnd 0;
  oversized inbound messages abort the association (could discard instead);
  DCEP ACK accepts any 0x02-prefixed buffer (RFC 8832 §5.2 wants exactly one
  byte); FORWARD-TSN parse tolerates non-multiple-of-4 bodies; `shutdown()`
  discards queued-but-unsent messages without an event.

Net: **571 tests / 56 suites** (was 561) — 6 new regression tests pin the
fixed behavior; the wire-format expectations were cross-checked against
libwebrtc/pion because self-roundtrip tests structurally could not catch
S1–S3.


---

# GRUU/Outbound wave findings (2026-09, Task 44)

The RFC 5626/5627 implementation wave surfaced two real parser-layer defects
during development (both caught by new roundtrip tests BEFORE any push —
the Task 43 lesson "self-roundtrip tests catch spec bugs only if the test
encodes the spec form" applied again, this time at the generic-param layer):

| # | Finding | Severity | Fix |
|---|---------|----------|-----|
| G1 | `Param::Display` re-emitted `+sip.instance="<urn:uuid:…>"` UNQUOTED (the quote rule did not cover `<`/`>`), producing a generic-param value that is not a legal token — strict RFC 5626/5627 peers reject the header | **Major** (wire) | Quote rule widened to `<`/`>`; roundtrip test pins instance + pub-gruu forms |
| G2 | `parse_params` split the parameter string with a blind `split(';')`, so a quoted value containing `;` (`pub-gruu="sip:alice@example.com;gr=urn:uuid:…"`) was shredded into a phantom `gr` param and a truncated value | **Major** (parser) | Quote-aware `split_outside_quotes` (backslash-escape aware) used for all URI/name-addr params; regression test covers instance, gr, and pub-gruu |

Also corrected while implementing: registrar de-registration of one
reg-id no longer removes the other flows of the same contact, the `q`
value is echoed in the 200 OK (RFC 3261 §10.2.8), and the dead
`max_expires.checked_sub(0)` no-op in the registrar was removed.

Net: **571 tests / 56 suites** (was 561) — 10 new tests (sip-core +1,
registrar +5, zrtc +4 incl. an end-to-end TCP flow test driving the real
flow loop against a fake registrar).

# DNS hardening closed (2026-09, Task 45)

The two DNS residues deferred by the Task 43 self-audit are fixed in
`crates/rfc3263/src/client.rs`, each pinned by a new test:

* **Bailiwick filtering (RFC 5452)**: `DnsClient::query` drops every record
  whose owner is neither the queried name nor a subdomain of it
  (case-insensitive, trailing-dot normalized). Strict query-name rule —
  additional-section addresses for SRV targets are dropped BY DESIGN and
  safely: the resolver never trusts piggybacked data, it re-resolves every
  target via a dedicated A/AAAA query whose own bailiwick check passes.
* **Local-truncation TCP fallback (RFC 1035 §4.2.2)**: a UDP datagram that
  fills the 4096 B receive buffer is treated as locally truncated BEFORE
  parsing — a cut-off response may parse cleanly and silently yield a
  partial record set — and is retried over TCP even though the server's
  TC flag is no longer observable.

Net: **574 tests / 56 suites** (was 571) — rfc3263 33→36.


# Self-audit of the Task 46 SCTP engine (2026-09)

The `sctp` crate was written with the Task 43 lesson applied from the start:
every codec path is pinned by hand-built byte vectors (not self-roundtrips),
the CRC32c is validated entry-for-entry against the RFC 9260 Appendix A
reference table plus the CRC-32/ISCSI check value, and the association runs
in a lossy virtual-clock loopback. Findings caught DURING this build — all
fixed before commit:

| # | Finding | Severity | Fix |
|---|---------|----------|-----|
| T1 | **Timer-order race**: with a collapsed RTO (loopback RTT sample → rto_min), T3-RTX fired BEFORE the RFC 3758 lifetime sweep in the same `on_timeout` pass and retransmitted a message whose packet-lifetime had just expired — the receiver delivered a message the sender believed abandoned | **Major** | Timer handlers reordered (T1 → lifetime sweep → T3 → heartbeat) so abandonment always precedes retransmission; the max-lifetime loopback test pins the order |
| T2 | **DCEP bypassed SSN accounting**: the receiver dispatched DCEP messages by PPID before the ordered pipeline, so a DATA_CHANNEL_OPEN never advanced the stream's expected SSN and the first user message on the channel parked forever (ordered deadlock) | **Major** | DCEP rides the ordered reassembly pipeline and dispatches at delivery time; SSN parity restored; stream-parity + reliable-message tests cover it |
| T3 | **Unordered delivery gated on TSN contiguity**: unordered messages waited for the cumulative TSN to advance (a lost predecessor blocked them) — RFC 9260 §6.6 requires immediate unordered delivery | **Major** | Unordered chunks feed the reassembler on arrival; TSN contiguity gates only ordered delivery; the unordered-gap test pins it |
| T4 | **MTU budget double-counted the common header**: chunk `size` included the 12-byte packet header, making a full-size fragmented chunk unschedulable (12 + size > MTU forever) | Minor | `size` = chunk wire size (16 + payload); fragmentation budget `mtu − 28` unchanged; fragmentation test covers a full-size chunk stream |
| T5 | **State cookie magic was 7 bytes, not 8** — every cookie field read back shifted by one octet, so the server silently dropped every valid COOKIE-ECHO | Minor (found by unit probe) | 8-byte `SCTPCK01` magic; cookie build/parse roundtrip probe added |

Also fixed during the wave: T1-COOKIE retransmission was verified against a
dropped COOKIE-ECHO (recovers on the next T1 fire), and `m=application`
offers are answered port-0 (RFC 3264 §6) in the SDP engine until the
ICE/DTLS/SRTP leg exists — pinned by a new `sdp` test so the negotiation
never claims a data channel the media pump cannot serve.

Net: **614 tests / 59 suites** (was 574/56) — sctp +39 (20 lib + 19
loopback), sdp +1.

# Full-repo audit round + SCTP hardening (Task 47, 2026-09)

A whole-codebase audit wave with three read-only tracks — (a) SCTP engine
deep-audit against RFC 9260/3758/8832, (b) doc-sync verification of every
document against the code at HEAD, (c) cross-crate consistency (CI, fuzz
parity, Docker, demo, workspace hygiene). Findings and fixes:

| # | Finding | Severity | Fix |
|---|---------|----------|-----|
| C1 | **Unauthenticated remote panic in `parse_params`**: the last parameter's 4-byte padded advance (`pad4(plen)`) could exceed the remaining slice (`plen ≤ buf.len()` was validated, the ADVANCE was not) — `&buf[8..]` on a 6-byte slice panics. Reachable by a single INIT/HEARTBEAT/ABORT datagram (vtag 0 + valid CRC32c, no handshake state needed) — a DoS of the future DTLS/SCTP seam | **Critical** | Stop cleanly at chunk end when the padded advance overruns (usrsctp/libwebrtc behavior); pinned by a unit test with the exact attack byte form + a packet-entry corpus test |
| S1 | **Send-buffer overflow silently dropped tail chunks** (`pop_back` after TSNs were consumed) — a permanent TSN hole that stuck the receiver's `cum_tsn` and stalled every later ordered message association-wide, with `send_message` returning `Ok` | **Major** | Reject with `SendBufferFull` BEFORE any TSN is consumed (message granularity); overflow test pins no-loss |
| S2 | **FORWARD-TSN was fire-and-forget** (RFC 3758 §3.5 violation): the abandoned state was destroyed at emission and nothing retransmitted a lost FTSN — the receiver's `cum_tsn` never advanced and ordered delivery died on every stream | **Major** | Outstanding-FTSN record (new_cum + stream skips) retransmitted on timer/SACK passes until a SACK's cum_tsn covers it; lossy-loopback test drops the FTSN and requires delivery to resume |
| S3 | **Graceful-shutdown FSM deadlocked on one packet loss**: no T2-SHUTDOWN timer, SHUTDOWN in ShutdownAckSent ignored, no shutdown deadline in `poll_timeout` once outstanding hit 0 (RFC 9260 §9.1/§9.2) | **Major** | T2-SHUTDOWN with exponential backoff + `ShutdownTimeout` abort; SHUTDOWN re-ACKed in ShutdownAckSent; deadline surfaced for both shutdown states; lossy tests cover lost SHUTDOWN and lost SHUTDOWN-ACK |
| S4 | **Advertised a_rwnd ignored reassembly-held bytes**: only `ofo` counted — parked fragment runs, the unordered current run and pre-DCEP buffers were invisible, so a compliant peer could grow memory unbounded (RFC 9260 §6.2.1) | **Major** | `undelivered_bytes()` spans ofo + ordered runs + unordered + pre-DCEP, saturating the advertised window; parked-data test pins the shrink |
| S5 | **Predictable security randomness**: one clock-seeded xorshift64\* drew the cookie MAC key, local verification tag and initial TSN — the tag is transmitted in the clear in INIT (state recoverable), the clock seed is brute-forceable, and cookies had no nonce (captured COOKIE-ECHO replayable within the lifetime) | **Major** | Global state seeded once from OS entropy (`getrandom`); 8-byte random nonce added inside the MAC'd cookie region; config overrides preserved; distinct-cookie test added |
| M1–M9 | Minor: SACK gap processing was O(gaps×span×inflight) per-TSN scans (hostile-peer CPU burn) → merged-range walk; handshake-retransmit exhaustion closed silently (`HandshakeTimeout` close event added); `feed_ordered` opened fragment runs from non-B chunks + post-skip late chunks parked forever (refused/dropped); FORWARD-TSN carried duplicate (sid, ssn) entries (one max-SSN entry per stream, §3.2); T1-INIT/COOKIE retransmits had no RTO backoff (doubles, clamped); a client accepted an uninvited INIT in InitSent and bricked its own handshake (collision guard, §8.5.1(E)); stale-cookie refresh omitted the Stale-Cookie cause (cause 3 + measured µs); `recv_window_chunks` unclamped (≤ 65535 — SACK gap offsets are u16); `heartbeat_interval.unwrap()` in the timeout path (removed) | Minor | All fixed with tests where the behavior is observable |
| D1 | `docs/TESTING.md` claimed "every parser entry point is exercised" while the newest, most attack-exposed parser (sctp wire) — and the older rfc3263 DNS wire — had no fuzz corpus and no cargo-fuzz target; the gap was silent in this document | **Major (coverage)** | `crates/sctp/tests/fuzz_smoke.rs` + `crates/rfc3263/tests/fuzz_smoke.rs` (deterministic corpora + xorshift mutations, stable CI), `fuzz/fuzz_targets/parse_sctp_packet.rs` + `parse_dcep.rs` + `parse_dns_response.rs`, CI corpus jobs added |
| D2 | `FINAL_REPORT.md`: the Task 45 history row was deleted by the Task 46 commit, a blank line broke the addendum table, and the §6 Remaining list still claimed sender-side TWCC / GRUU / NAPTR-SRV were open (three tasks stale) | Minor (docs) | Task 45 row restored, table seam fixed, §6 rewritten (Remaining = B2BUA WebRTC leg, dialog-layer extraction, release soak M2, Postgres CDR) |
| D3 | Cross-crate drift: Dockerfile/compose carried a stale "b2bua is a placeholder / voipd" narrative, no `.dockerignore`, `rust:1.98-slim` base tag implied a pin the floating `stable` toolchain file doesn't provide, `demo/zrtc.toml.example` lacked the documented `[trunk].instance_id` key, demo/README said "Three ways" listing four and "five auth modes" for four, `hmac`/`sha1` were version-literal in 3 manifests while sibling crypto deps are workspace-centralized, `docs/DESIGN.md` retained voipd-era planning sketches | Minor (hygiene) | All fixed in the same commit: Dockerfile header rewritten + `rust:1-slim` base, `.dockerignore` added, example config + README counts corrected, `hmac = { workspace = true }` / `sha1 = { workspace = true }` centralized, DESIGN.md marked as the frozen planning artifact with errata pointers |

**Deferred (documented, not silent)** — added to the list above: SCTP fast
retransmit on gap-ack/dup-SACK signals (loss recovery currently waits a full
RTO); zero-window probe when the peer advertises a_rwnd 0; oversized inbound
messages abort the association (could discard instead); DCEP ACK accepts any
0x02-prefixed buffer (RFC 8832 §5.2 wants exactly one byte); FORWARD-TSN
parse tolerates non-multiple-of-4 bodies; `shutdown()` discards queued-but-
unsent messages without an event.

Net: **626 tests / 61 suites** (was 614/59) — sctp +10 (49: 23 lib + 24
loopback + 2 fuzz-smoke), rfc3263 +2 (38, incl. 2 fuzz-smoke).

## Task 48 — B2BUA WebRTC leg: bugs caught and hardened while wiring

Wiring ICE + DTLS-SRTP into the live B2BUA (the first time the `ice`, `dtls`
and `srtp` crates compose under a real call) surfaced three defects in the
same class the user's audit instruction targets — integration races the
unit tests cannot see:

| # | Finding | Severity | Fix |
|---|---------|----------|-----|
| W1 | The ICE answerer's first check burst races the answer: the peer cannot validate our STUN checks until the 200 OK carries our ufrag/pwd, so early checks are dropped as unauthorized — and `connect()` never re-sent them. When the answerer happened to draw the controlling role, aggressive nomination (USE-CANDIDATE) could never fire and ICE stalled until timeout | **Major** (integration) | `connect()` re-issues checks every 500 ms until nomination (and after every role-conflict switch); the WebRTC loopback test exercises exactly the answerer-side race it fixes |
| W2 | `DtlsEndpoint::handshake_udp` routed datagrams to the DTLS state machine by SOURCE ADDRESS only — ICE keepalives / STUN from the selected pair's address (the same address during and after ICE) would be handed to OpenSSL as garbage records | **Major** (integration) | RFC 7983 content filter inside `handshake_udp`: only first-byte 20–63 feeds the state machine; other bytes go to the `packets_from_peer` callback and do not reset the retransmission timer |
| W3 | SDP answer built from caps could not carry ICE candidates (`MediaCaps` had credentials but no candidate list), so a WebRTC answer would have advertised credentials with no reachable address | **Major** (coverage) | `MediaCaps::ice_candidates` + `answer_session` echo, emitting the prefix-less form the parser's mirror uses (a full `candidate:`-prefixed line would double the prefix on the wire — `a=candidate:candidate:1 …`) |

Also documented: the engine's CDR sink is a process-global `OnceLock`, so
two engines in one test process silently lose `CallEnded` events from the
second engine — the 488-rejection test lives in its own test binary.

Net after Task 48: **628 tests / 63 suites** (was 626/61) — b2bua +2
integration tests + 2 new suites (`webrtc_leg`, `webrtc_reject`).

## Task 49 — data channels over DTLS: the integration test caught a real spec bug

The `webrtc_datachan` loopback (mini WebRTC caller: ICE controlling, DTLS
server, SCTP responder) opened a channel and sent user messages — and every
message vanished. The root cause was NOT in the new wiring: **the sctp
engine's DCEP OPEN rode PPID 51 while RFC 8832 §5.1 puts both DCEP messages
(DATA_CHANNEL_OPEN and DATA_CHANNEL_ACK) on PPID 50** — a Task 46 defect of
exactly the Task 43 "self-consistent wire form" class: every roundtrip test
passed because both ends agreed on the wrong value, while a real browser's
PPID-50 OPEN would have been treated as user data and dropped (and our OPEN
would have been ignored by every peer). Fixed (`PPID_DCEP = 50`) and pinned
two ways:

| # | Finding | Severity | Fix |
|---|---------|----------|-----|
| P1 | DCEP OPEN emitted with PPID 51 (RFC 8832 §5.1: PPID 50 for BOTH DCEP messages) — interoperability-fatal, invisible to self-roundtrips | **Critical** (interop) | `PPID_DCEP = 50`; regression test parses the emitted DATA chunk and asserts PPID 50 + the 0x03 OPEN marker (the Task 43 lesson applied: inspect the wire, never trust a roundtrip) |
| P2 | User messages whose PPID collided with the (wrong) DCEP dispatch were silently swallowed — my test picked PPID 51 (the RFC 8831 "WebRTC String" PPID) for user data and the engine dispatched it into the DCEP parser | **Major** (interop) | DCEP dispatch now keys on PPID 50 only; regression test sends RFC 8831 PPIDs 51/53/60000 and asserts delivery as user messages |
| D1 | `dtls` post-handshake app-data reads truncated a datagram to the caller's buffer with no error (the queue transport's `read` copies `min(len)`), and OpenSSL does NOT fragment app-data writes to the handshake MTU — a peer record can legitimately exceed one MTU; a truncated record fails its MAC and is dropped silently | **Major** (integration — found by my own first-draft test) | `recv_app_data` enforces a ≥ 18_432-byte buffer (largest DTLS record = 2^14 + overhead) and documents why; the engine uses 64 KiB; the test that exposed it is kept as the pin (2048-byte buffer → 3037-byte record → zero bytes decoded) |
| D2 | Multi-m-line offers (any browser sends audio + video + application) failed `CapsCountMismatch` → 488 | **Major** (coverage) | `sdp_util::answer` walks every m-line positionally: first audio + first application (RFC 8841, WebRTC legs only) accepted, everything else rejected port 0 per RFC 3264 §6 — never a caps-count error |

Net after Task 49: **634 tests / 64 suites** (was 628/63) — dtls 10→11,
sdp 31→33, sctp 49→51 (+2 spec pins), b2bua 39→40 + the `webrtc_datachan`
suite.

## Task 50 — leg-B WebRTC offerer: two wire bugs caught by self-review before shipping

The offerer side (`webrtc` routes dial downstream with a SAVPF offer) was
built with the Task 48/49 lessons applied up front — and two defects were
still caught during development, both by tests/warnings rather than by the
integration loopback:

| ID | Finding | Severity | Fix |
|----|---------|----------|-----|
| W1 | `WebRtcOffer::establish` parsed the answer's ICE ufrag/pwd/candidates but never called `agent.set_remote` — ICE would have had no remote side and every `webrtc` route call would have timed out at establishment | **Critical** (dead feature) | `set_remote` called before `connect`; the unused-variable warnings during `cargo check` are what surfaced it (kept as the tripwire — warnings are errors in the gates anyway) |
| W2 | `build_webrtc_offer` set only the typed SDP fields (`m.ice_ufrag`, `m.setup`, …) — but the sdp serializer emits the m-line's raw `attributes`, so the entire ICE/DTLS transport block was silently absent from the wire while the typed mirror looked correct in-process | **Critical** (wire) | the transport block is pushed as raw attributes too (the same rule `answer_session` follows); the new offer-shape unit tests assert the wire form (`a=setup:actpass`, `a=fingerprint:sha-256`, `a=candidate:…`) and a parse→serialize fixed point |
| W3 | Three integration engines initially shared one test binary — only the first engine's CDR channel receives `CallEnded` (the CDR sink is a process-global OnceLock), so the second test failed on a missing trail even though the call was fine | **Major** (test infra — Task 48 lesson re-applied) | one engine per test binary: `webrtc_leg_b_active` / `webrtc_leg_b_passive` / `webrtc_leg_b_reject`, sharing a `tests/webrtc_leg_b/common.rs` module |
| D1 | A failing leg-B establishment (e.g. a plaintext downgrade answer) previously tore the call down without answering leg A through the server INVITE transaction — a single raw datagram a loss would swallow | **Minor** (resilience) | the 503 is staged into the still-open `a_tx` (`send_staged`) so the response is retransmitted (Timer G/H) before teardown |

Net after Task 50: **639 tests / 67 suites** (was 634/64) — b2bua lib 40→42
(offer-shape unit tests), +3 integration suites.

## Task 51 — leg-B data channels: the RFC 8832 stream-parity rule had shipped INVERTED

Wiring the data channel into the leg-B offer (RFC 8841 mirror policy) demanded
one more DTLS-role case, and settling it honestly meant fetching the RFC text
instead of trusting the engine's own test comments — which caught a wire-format
defect that had shipped two tasks earlier and was PINNED by a test asserting
the wrong rule with a spec citation.

| ID | Finding | Severity | Fix |
|----|---------|----------|-----|
| P1 | The DCEP stream-id parity rule was inverted everywhere since Task 46: `is_client → odd streams`, and the Task 49 test asserted `responder == 0` with a comment citing "RFC 8832 §6". The actual RFC 8832 §5.1/§6 rule keys on the **DTLS role**: the DTLS client opens EVEN streams, the DTLS server ODD. Both self-roundtrip ends were our own engine (allocated odd/even from inverted bases), so no test could catch it — but a real browser would have ignored our DATA_CHANNEL_OPEN on the wrong parity (libwebrtc validates parity per role) | **Critical** (wire, interop blocker) | allocator base flipped (`is_client → 0`); `DataChannelConfig.we_are_dtls_client` added so the SCTP association initiator follows the DTLS role (RFC 8261 allows either side to initiate; libwebrtc convention = the DTLS client initiates); doc comments in `assoc.rs`/`dcep.rs`/`lib.rs` corrected; the parity test and the PPID-50 test re-pinned to the true rule; a new hand-built-wire test feeds the server an OPEN on a wrong-parity stream and asserts it is dropped without an ACK, no channel registers, and the association survives. Lesson re-confirmed: self-roundtrip CANNOT catch spec-constant bugs — only an external reference (RFC text, wire capture, real peer) can |
| P2 | The wrong-parity OPEN originally had no receiver-side guard at all — an OPEN on an arbitrary stream was registered and acked | **Major** (spec) | `handle_dcep` validates parity before any state mutation (the Task 47 reject-before-consume lesson): a parity-violating OPEN is dropped WITHOUT the ACK RFC 8832 §5.1 forbids issuing; per-channel RFC 8831 stream reset is not implemented, so dropping (association stays up, the peer's reliable OPEN retransmission keeps hitting the guard) is the documented closest-spec action |
| W1 | The first leg-B mirror loopback never established the association: the harness callee was now the SCTP INITIATOR but its queued INIT sat in `drain_outbound()` — the initiator must flush immediately (nothing inbound arrives to trigger the drain before the association exists) | **Major** (test harness) | the harness flushes right after endpoint construction and re-drains on a 200 ms tick; the engine's own `run()` already flushed at construction |
| D1 | `build_webrtc_offer`'s dc parameter, the answer's application m-line parsing (`a=sctp-port` → `remote_sctp_port`), and the staged `dtls_tx` forwarder on `Leg` | Minor (wiring) | covered above; the engine spawns on `est.dtls` when the callee accepts (port ≠ 0) and logs an info + keeps audio when it declines |
| D2 | The TESTING.md `b2bua` row had drifted 3 below its own header arithmetic (42 vs the real 45) — per-crate counts were bumped by feature tasks without re-deriving the aggregation | Minor (docs) | row corrected to the true aggregation (49 after this task); header totals were always computed from real output and stay authoritative |

Net after Task 51: **644 tests / 69 suites** (was 639/67) — sctp +1
(wrong-parity drop), b2bua +2 (sdp_util dc offer tests), +2 integration
suites; suite inventory re-derived per crate (b2bua 42→49 corrected against
its own header arithmetic).

---

## Task 53 — RFC 6525 stream reset (RFC 8831 §6.7 channel close)

Scope note: a feature task (the last WebRTC roadmap remainder), not an
external-audit wave — but the new tests caught two real engine bugs before
shipping, recorded here with the same discipline.

| ID | Finding | Severity | Fix |
|----|---------|----------|-----|
| T53-1 | The new two-pass stream-id allocator presented an OCCUPIED id as free after a fully exhausted first pass: the wrap-around assignment at the end of the scan loop leaked past the final free check, so with every parity id taken the next `open_data_channel` handed out an already-registered stream | **Major** (state corruption) | the scan result is explicit (`found: Option<u16>`); the exhaustion loopback test (6-stream limit → `SendBufferFull` → close one channel → the freed id is handed out again) failed immediately and pins the fix |
| T53-2 | The close INITIATOR never reset its INBOUND stream: its channel was removed when its own request was acknowledged, so when the peer's reciprocal reset arrived the "known stream" gate (keyed on registered channels only) answered Nothing-to-do and the initiator's expected-SSN never restarted — the first DATA on the reused id was silently dropped by the phase-0 guard | **Major** (spec + interop) | a stream is known if its channel OR its ordered receive buffer exists; the reuse loopback test (re-open the freed id, send, expect delivery) caught it via the missing DataChannelAck |
| T53-3 | `send_re_config_request` never armed `reconfig_deadline` — a fresh request would never retransmit after a loss (surfaced as a dead-code warning on the unused `now` parameter, the same parsed-but-unconsumed tripwire class as Task 50's `set_remote`) | Minor (liveness) | deadline armed at request emission; `poll_timeout` surfaces it; exhaustion completes the close locally |
| W1 | The wrong-parity-OPEN action (Task 51's documented drop) is upgraded now that the tool it lacked exists: a parity-violating OPEN is closed with an Outgoing SSN Reset Request (RFC 8831 §6.7 — which also stops the peer's reliable OPEN retransmissions); the drop remains the fallback while one of our resets is in flight or the peer never advertised RFC 6525 | Improvement | implemented in `handle_dcep` with the fallback documented in-code; the Task 51 test re-pinned to assert the reset |

Net after Task 53: **656 tests / 70 suites** (was 644/69) — sctp 52→63
(4 hand-built RE-CONFIG wire tests + 7 close loopback tests), b2bua 49→50
(`webrtc_datachan_close`: the channel close over a live leg with the
association surviving and the CDR completing). No external-audit items
affected; all previous fixes re-verified green.
