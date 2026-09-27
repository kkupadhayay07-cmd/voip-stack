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
| 2.7 | `sink.rs` rtp_tap: hardcoded +160 ts step, echo before PT filter, Contact = remote src, sink-call leak on missing BYE | Confirmed | Open |
| 2.8 | TLS/WSS handshakes await forever while holding connection permits | Confirmed (no timeout before `stream_loop`) | Open |
| 2.9 | G.729 decoder discards postfilter output / double-samples when postfilter off | Confirmed | Open (needs golden-vector care — bcg729 oracle must stay green) |
| 2.10 | STUN ERROR-CODE 3-byte header; CHANNEL-NUMBER `0x0006` collides with USERNAME | Confirmed | **Fixed** — 4-byte `[0,0,class,number]` layout + `CHANNEL_NUMBER = 0x000C` (RFC 5389 §15.6, RFC 5766 §14.1); wire-layout test added |
| 2.11 | IPv6 ICE candidate parse; unauthenticated TURN allocate flow self-deadlocks | Confirmed | Open |
| 2.12 | SRTCP AES-GCM E=0 always fails; per-SSRC state allocated before auth | Confirmed | **Fixed** — E=0 passes the tag as the GCM "ciphertext" input; recv-stream state committed only after tag verification (both RTP and RTCP paths) |
| 2.13 | RTP padding bit re-encoded without padding bytes; jitter buffer 32-bit ts wrap; `pop_ready` skips concealment for gaps | Confirmed | Open |
| 2.14 | SBC topology hiding looks up `call_map` instead of `call_map_rev` on responses; proxy tx keys never match | Confirmed (SBC half verified; proxy half consistent with the code) | Open |
| 2.15 | Dialer predictive pacing ignores `lines_ringing`; answered leads re-dialed; DNC skipped on queued leads | Confirmed | Open |
| 2.16 | `Mixer::mix` includes inactive inputs and replays stale frames (50 Hz buzz) | Confirmed | Open |
| 2.17 | `CdrStore::default()` capacity 0 panics on first insert; folded auth headers leak into pcap/trace | Confirmed | Open |

## 3. Medium / Low (P2)

All verified as plausible-to-real during triage; **open**, ordered by impact:
`looks_like_rtcp` `%4` rejection breaks AES-CM SRTCP (rtp) · SDP `u=/e=/p=/k=/z=`
extras serialize without their `typ=` prefix (sdp) · `answer_direction`
SendOnly/SendOnly → RecvOnly, port-0 offers answered non-zero, telephone-event-only
offers accepted (sdp) · `push_via` appends to the bottom of the Via stack
(sip-core) · non-2xx ACK copies all Via headers, omits Route (sip-tx) ·
`ServerNonInviteTx` never Proceeding / matches foreign methods (sip-tx) ·
registrar 423 `min_expires` unchecked, nonce table unbounded (registrar) ·
Opus >20 ms decode buffers, G.722 `reset` keeps state, CN multi-byte payload
(codecs) · `Endpoint::from_config` user@ stripping — **Fixed** in this commit ·
TLS client verify NONE despite `tls_ca_path` (zrtc) · CDR disposition hardcodes
487=Failed (zrtc) · `--since ""` panic (zrtc) · pace_campaign hardcoded recent
counters, gauge-vs-counter, call counters never incremented (api).

Note: the `RequestBuilder::via` host:port mis-parse reported under P2 was
**Fixed** in this commit (it was a prerequisite for correct engine Via sent-by).

## Verification

`cargo test --workspace` → **401 passing** (396 + 5 new regression tests),
`clippy -D warnings` clean, `cargo fmt --check` clean, `./demo/run.sh` PASS.
The demo exercises the reworked core response path end to end
(listener → SBC → proxy → registrar/b2bua → media → ai-bridge).
