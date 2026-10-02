# RFC Compliance Matrix

Status of the ZRTC VoIP stack against the RFCs and ITU codecs it targets.
**Honest by design** — no row is marked Done without implementation and tests
behind it. Last reviewed: 2026-09 (all six phases implemented plus the
hardening series: `sip-tx` transaction layer, in-process observability,
trunk auth, `zrtc` daemon transports, the TCP/TLS/WSS framing audit, RFC 4028
session timers and RFC 3262 PRACK/100rel on both B2BUA legs, plus the
external security/interop audit triage with its follow-up fix waves
(Remote-DoS parser panics, SRTP payload authentication, G.729 postfilter
output, ICE IPv6/TURN, SBC/proxy response maps, dialer/mixer/CDR data
integrity), the final Critical/High wave (TLS/WSS handshake budget,
loopback sink echo/Contact/reaper, RTP padding round-trip, jitter-buffer
timestamp wrap and sequence-gap concealment), and the full P2 sweep
(SRTCP-aware RTP/RTCP demux, top-of-stack Via push, single-Via + Route
non-2xx ACK, non-INVITE Proceeding + method matching, registrar 423
`Min-Expires` + nonce pruning, CA-verified trunk TLS with real
mini-CA/SAN certs, real CDR final codes, safe `--since` parsing, wired
Prometheus call counters + gauge semantics), and the SDP IPv6/BUNDLE answer
hardening (IP4/IP6 `o=`/`c=` address types picked from the local host
literal, RFC 8843 BUNDLE group echo with the accepted mids), a
concurrent-call load harness with percentile reporting, and RTP loss
recovery + congestion feedback (RFC 4585 Generic NACK, RFC 4588 RTX,
transport-cc) and SIP RFC 5626 Outbound + RFC 5627 GRUU, WebRTC data
classes end to end at the protocol layer (RFC 9260/4960 SCTP engine,
RFC 8832 DCEP, RFC 3758 FORWARD-TSN in the `sctp` crate), and WebRTC MEDIA
legs in the B2BUA (RFC 5763/5764/8445/3711: SAVPF offers answered with ICE
→ DTLS-SRTP → SRTP pump crypto, and `webrtc` routes dialing downstream with
a SAVPF offer as the ICE-controlling offerer, with the RFC 8841 mirror
policy offering the data channel downstream when the caller did, and
channels closing per RFC 8831 §6.7 via RFC 6525 stream reset); 656 tests green
across 70 suites — **every audit finding at every severity is fixed**).

Legend: **Done** · **Partial** · **Planned** (target phase in parentheses).

## 1. SIP signaling

| RFC | Feature | Status | Notes |
|-----|---------|--------|-------|
| RFC 3261 | SIP: message layer | **Done** | `sip-core`: strict panic-free byte parser (UDP datagram + TCP/TLS/WS stream framing, §18.3), canonical serializer, URI/header model, branch/tag/Call-ID generators. Parser limits enforced (64 KiB msg, 128 headers, 8 KiB/line). |
| RFC 3261 | SIP: registrar (§10) | **Done** | `registrar` crate: AoR binding DB (q-ordering, expiry, CSeq/Call-ID consistency, wildcard removal), Digest auth challenge/verify with one-time nonces, domain check. §10.2.8: registrations below the configured minimum expiry are refused with 423 `Interval Too Brief` carrying `Min-Expires`; the nonce table is pruned of expired entries on every challenge so it stays bounded under floods. |
| RFC 3261 | SIP: stateful proxy (§16) | **Done** (core) | `proxy` crate: request validation (483), Route-set processing, Via prepend/pop, Record-Route, parallel forking, 100 Trying, CANCEL matching (§9.1), response routing (received/rport → sent-by). Fork state is in-memory only (no failover); adopting the `sip-tx` timer state machines in the proxy is a planned hardening step. |
| RFC 3261 | SIP: transactions (§17) | **Done** (core) | `sip-tx` crate: client INVITE (Timers A/B/D), client non-INVITE (E/F/K), server INVITE (G/H/I), server non-INVITE (J); §17.1.3 response matching + §17.2.3 ACK matching; the non-2xx ACK carries a single top Via plus the original Route set (§17.1.1.2); the non-INVITE server transaction enters Proceeding on a provisional and matches retransmissions by branch+sent-by+CSeq AND method (§17.2.2); pure state machines, fake-clock tests at exact fire instants. The B2BUA drives both call legs through it. Connection-time failover across the trunk's RFC 3263 candidate list is live in the zrtc trunk client (see RFC 3263 row). |
| RFC 3261 | SIP: transports (§18) | **Done** (core) | UDP/TCP/TLS/WSS listeners wired in the `zrtc` daemon (TLS via whitelisted OpenSSL, self-signed identity at startup, mTLS client certs for trunks); message layer covers datagram + stream framing incl. §18.3 robustness. |
| RFC 3261 | SIP: dialogs (§12) | **Partial** | B2BUA tracks per-leg dialog state (tags/Call-ID/CSeq); generic dialog package not extracted. |
| RFC 3262 | PRACK / 100rel | **Done** (core) | B2BUA, both legs. UAS: reliable 180 (`Require: 100rel` + `RSeq` from [1, 2³¹−1], To-tagged early dialog) when the caller advertises 100rel, Timer-G-style retransmission (T1 doubling to T2) until `PRACK`, 64·T1 give-up with 503 + BYE, the final 200 parked until the PRACK arrives (§3), RAck matching with 481/400 verdicts and idempotent 200 for retransmitted PRACKs. UAC: only a 101–199 carrying BOTH `Require: 100rel` and `RSeq` is PRACKed (§4 — never a 100, never an unmarked 1xx), answered with PRACK carrying `RAck` (own dialog CSeq); a retransmitted 1xx (same `RSeq`) is answered by resending the STORED PRACK byte-identically (same CSeq number and branch, RFC 3261 §17.1.2); 421 Extension-Required dial retry once with the demanded extensions merged into `Supported` (§3); non-INVITE responses excluded from the INVITE transaction slot. |
| RFC 3263 | DNS (NAPTR/SRV) for SIP | **Done** (client discovery) | `rfc3263` crate: RFC 1035 wire codec (name decompression with a strictly-backwards pointer rule + jump cap — loops are structurally rejected), NAPTR (RFC 2915) S-flag protocol selection from the service field (SIP+D2U/D2T, SIPS+D2T) with the replacement key as the next SRV query, SRV (RFC 2782) priority + weighted-random ordering (zero-weight last, seeded xorshift, deterministic in tests), A/AAAA fallback with transport-default ports (5060/5061), explicit-port short-circuit per §4.2, IP-literal fast path (no DNS). Client: UDP with one retransmission, TC→TCP fallback, ID-validated responses. Live on the zrtc outbound trunk: HOST / HOST:PORT / `sip:` URI / IPv6-literal addresses resolve through RFC 3263 into an ordered candidate list (SRV targets whose addresses fail are skipped — client-side failover to the next candidate), with a libc-resolver fallback when no nameserver is configured. **Connection-time failover is live**: `trunk::connect` walks the candidate list in priority order with a 3 s per-candidate connect budget (TCP/TLS/WSS) and pins `target`, keepalives and RTP to the winner. Remaining: NAPTR regexp rewrite (regexp-only NAPTRs are skipped), DNSSEC, mid-dialog re-resolution (an established session that dies does not yet re-resolve). |
| RFC 3264 | Offer/answer | **Done** | `sdp::negotiate`: full RFC 3264 engine with `StreamPlan` projection. Answer direction is the explicit §6.1 matrix clamped to what the offer permits (sendonly offers can never draw a receiving answer, etc.), rejected m-lines are answered with their own m-line at port 0 and a null `c=` line of the offer's address type (§6), port-0 offers are answered port 0. The answer's own `o=`/`c=` lines pick `IN IP4`/`IN IP6` from the local host literal (RFC 8866 §4.4 — an IPv6 address is never mislabeled IP4); the offer's family never dictates the answer's. |
| RFC 3326 | Reason header | **Partial** | Header type modelled; no protocol semantics applied yet. |
| RFC 3515 | REFER | **Planned** | `Refer-To` header type modelled; call flows not implemented. |
| RFC 3581 | rport / Symmetric RTP | **Done** | SBC marks `rport` on requests and routes responses via received/rport; NAT latch table maps contact → source. |
| RFC 4028 | Session timers | **Done** | B2BUA, both legs: `Min-SE`/422 floor on inbound INVITEs, `Session-Expires`+`refresher` negotiation mirrored end-to-end on the 200s, half-interval refresh re-INVITEs (no-change offer), in-dialog UPDATE refresh, expiry teardown with BYEs on both legs, 422-retry with the peer's `Min-SE`, tag-checked in-dialog re-INVITE/UPDATE routing (481/491/488). |
| RFC 4566 | SDP | **Done** | `sdp` crate: strict positioned-error parser + canonical serializer; session extras (`u=/e=/p=/k=/z=`) serialize with their `typ=` prefixes. |
| RFC 8843 | BUNDLE (grouping) | **Done** (core) | `sdp`: `a=group:BUNDLE` + `a=mid` parsed into typed projections; the answer echoes the group with exactly the accepted mids in the offer group's order (§6.2/§7.1.1) — rejected (port 0) m-lines and accepted m-lines without a mid never join the group, an answer to an unbundled offer never grows a group; mid echo per accepted m-line. The B2BUA's leg-B WebRTC offer is now itself bundled when it carries the data channel (RFC 8841 mirror policy): `a=mid:0`/`a=mid:1` on the two m-lines and a session-level `a=group:BUNDLE 0 1` — the shape the answerer side already echoed (wire-pinned by sdp_util unit tests and the mirror-loopback integration test). Single-transport reuse by the media engine (m-line demux by mid) is future work. |
| RFC 8866 | SDP v2 | **Partial** | Parser/model cover `rtpmap`/`fmtp`, `ice-*`, `fingerprint`, `bundle`, `extmap`; answers emit IP4/IP6 connection types per the local literal (§4.4); full 8866 grammar validation not complete. |
| RFC 2617/7616 | Digest auth | **Done** (server side) | `sip-core` helpers + registrar nonce store; `respond_to_challenge` used in tests/clients. |
| RFC 6140 / 5627 | GRUU | **Done** (pub-gruu) | Registrar synthesizes a public GRUU (`sip:AOR;gr=<instance>`) for every contact registering `+sip.instance`, echoes it (quoted) in the 200 OK with `Supported: gruu`; the trunk UAC advertises the option tag. Quoted generic-params are parser round-trip stable (quote-aware param split). Not done: temp-gruu (temporary opaque GRUUs with lifetime), instance-aware proxy routing (a request to a GRUU forks to all of the user's contacts, not the targeted instance). |
| RFC 5626 / 6223 | Outbound | **Done** (client + registrar) | Registrar: flow detection via the top Via transport, `+sip.instance`/`reg-id` bindings (per-reg-id de-registration, reg-id=0 → 400), `Flow-Timer` + `Supported: outbound` echo on reliable transports only. Trunk UAC: `Supported: outbound, gruu` on every REGISTER, instance-tagged Contact (stable `[trunk] instance_id` config, process-local generated otherwise), refresh at half the granted expiry on the same Call-ID, CRLF (TCP/TLS) / WS-Ping (WSS) flow keep-alives per `Flow-Timer`; 430 `Flow Failed` reason phrase available. Not done: STUN keep-alives over UDP flows, proxy-side flow tokens / 430 generation on flow loss, `Path` / Service-Route support. |
| RFC 7118 | SIP over WS | **Done** | WS/WSS listeners wired in the `zrtc` daemon (WSS = WS over TLS); message layer handles text-frame streaming + Content-Length accumulation. |

## 2. Media transport

| RFC | Feature | Status | Notes |
|-----|---------|--------|-------|
| RFC 3550 | RTP/RTCP | **Done** | `rtp` crate: fixed-header parse/serialize; RTCP SR/RR/SDES/BYE/APP compound parse/encode; interarrival jitter estimator; SSRC probation. Padding round-trips byte-exactly (the padding bit is never emitted without its octets); the playout buffer is wrap-safe for both the 16-bit sequence and 32-bit timestamp spaces. The B2BUA media pumps send periodic SRs (NTP 1900-epoch timestamps, TX packet/octet counts counting only actually-sent packets) carrying a reception report about the peer (fraction/cumulative loss clamped to the signed-24-bit positive range, highest extended sequence, jitter converted via µs to keep sub-millisecond precision, last-SR/DLSR with µs-accurate DLSR, LSR keyed to the peer's media SSRC only). Every SR compound carries SDES with CNAME (§6.5.1); standalone NACK/transport-cc feedback packets are prefixed with an empty RR so every compound starts with SR/RR (§6.1). |
| RFC 3551 | RTP/AVP profile | **Done** | Static payload types (0 PCMU, 8 PCMA, 9 G722, 18 G729, 13 CN, 100 telephone-event) + L16 (BE). |
| RFC 3556 | SDP bandwidth modifiers | **Partial** | `b=` lines parsed/modelled; `TIAS` pacing semantics not applied. |
| RFC 4585 | RTCP-based feedback | **Done (core)** | `rtp::nack`: Generic NACK `PID`/`BLP` FCI encode/parse (§6.2.1) + receiver-side gap tracker (extended sequences, repeat throttle, give-up limits, stream-restart guards); **wired into the B2BUA**: legs that negotiate `a=rtcp-fb:<pt> nack` answer inbound NACKs verbatim from a 512-packet retransmission window (20 ms per-seq flood guard) and NACK the peer's gaps; PLI/FIR still modelled as typed Psfb (no B2BUA path); REMB not implemented. |
| RFC 4588 | RTX retransmission | **Done (core)** | `rtp::nack`: sender `RtxPool` (bounded retransmission window), `RtxStream` packetizer (separate SSRC/PT + OSN payload prefix, CSRCs dropped per §4), receiver `RtxDepacketizer` restoring `apt` PT + original sequence; SSRC learning until pinned from SDP. |
| transport-cc (draft-holmerberg-avt-01) | RTPFB FMT 15 congestion feedback | **Done (audit-corrected)** | `rtp::twcc`: draft-conformant FCI encode/parse — run chunks (T=0), one-bit vector chunks (T=1, S=0, fourteen symbols at bits 13..0, the form libwebrtc/pion emit most) and two-bit vector chunks (T=1, S=1 = word 0xC000, seven symbols at bit pairs 13:12 … 1:0 MSB-first); recv deltas are true INTER-ARRIVAL deltas (§3.1.5: first vs the reference, rest vs the previous received packet) with the sender reconstructing arrivals by accumulation; small u8 + large i16 deltas at 250 µs, 64 ms reference time, feedback counter. Receiver `TwccRxMonitor` (gap-marked arrival windows, cursor slides under window saturation) and sender `TwccSendTracker` (delay relative to the fastest observed packet — clock-domain free — plus window loss attribution). **B2BUA both sides wired**: offers advertise the extmap (`id 1`, draft URI), answers echo it; negotiated legs feed arrival times into `TwccRxMonitor` from the 2-byte big-endian sequence element emitting RTPFB FMT 15 every 200 ms, and outbound RTP (audio + DTMF relay) is stamped with the 2-byte element (RFC 8285 §4.2 writer; retransmissions carry the original seq) — inbound feedback about our SSRC is validated (`media_ssrc` match), correlated against send times, and surfaced as per-leg stats (feedback count, window loss, excess delay). *History: a self-audit (Task 43) found the first implementation wrote 7×2-bit symbols under word 0x8000, used reference-relative deltas, and carried a 1-byte sequence — self-interop only; all three were corrected against libwebrtc/pion and the draft before any real peer use.* |
| RFC 4733 | RTP DTMF (telephone-event) | **Done** | Events 0–15 with start/end semantics + tests; relayed end-to-end by the B2BUA. |
| RFC 5761 | RTP/RTCP demultiplexing | **Done** | §4 heuristic, unit-tested; the B2BUA offers `a=rtcp-mux` (the media pump is mux-only) and SDP negotiation echoes it when offered. |
| RFC 8285 | RTP header extensions | **Done** | One-byte and two-byte blocks parse/serialize; `RtpExtension::onebyte` builds single-element one-byte blocks (id 1–14, 1–16 data bytes, length field = len−1) used by the transport-cc sender path — validation is runtime (`Result`), so release builds can never emit malformed wire data. |
| RFC 3711 | SRTP/SRTCP | **Done** | `srtp` crate: AES-CM + HMAC-SHA1 (80/32 tags), key derivation (labels 0–5, rate semantics), 64-entry replay window (libsrtp-style relative bits), RFC 3711 Appendix A ROC estimation, per-SSRC stream state, SRTCP E-bit/index. Validated against RFC 3711 B.2/B.3 vectors. |
| RFC 7714 | SRTP AES-GCM | **Done** | AEAD_AES_128/256_GCM (16-byte tags) + 96-bit tag variants; SRTP/SRTCP IV per §8.1/§9.1; E=0 AAD semantics per §9.3 incl. authenticate-only acceptance of unencrypted SRTCP and the §9 tag-before-index wire order; validated against §16.1.1/16.1.2/16.1.4/16.2.1 and §17.1/§17.3 (SRTCP encrypted + tagging-only, tamper-tested) vectors. |
| RFC 5764 | DTLS-SRTP handshake/usage | **Done** | `dtls` crate: use_srtp negotiation, RFC 8122 fingerprint generation + pinning, RFC 5764 §4.2 keying export (`EXTRACTOR-dtls_srtp`), self-signed runtime ECDSA P-256 identities. **Live in the B2BUA both roles**: the exported keying material keys the leg pump's SRTP sessions on negotiated WebRTC legs — the answerer drives the handshake as the DTLS client over the ICE-nominated pair, and on a `webrtc` route the offerer takes server (answer `setup:active`) or client (answer `setup:passive`), with the role's keying material protecting its outbound stream. |
| RFC 5763 | Connection-oriented media (ICE + DTLS-SRTP offer/answer) | **Done** (both roles) | `b2bua::webrtc`: ANSWERER — a `UDP/TLS/RTP/SAVPF` offer with ICE + a sha-256 fingerprint is answered with our ICE credentials + gathered candidate lines + certificate fingerprint, `setup:active` (the answerer is the DTLS client and starts the handshake only after ICE completes — §5), the offer's fingerprint is pinned (handshake fails on mismatch; sha-384 offers rejected — we pin sha-256 only), and DTLS runs over the nominated pair with RFC 7983 filtering. OFFERER (`webrtc` routes, `b2bua::WebRtcOffer` + `sdp_util::build_webrtc_offer`) — leg B is dialed with a SAVPF offer carrying our ICE credentials/candidates, our certificate fingerprint and `setup:actpass`; the answer's `a=setup` picks the roles (`active` → we are the DTLS server, `passive` → the client), the answer is validated (secure proto kept, ICE creds/candidates/fingerprint present) before ICE runs as the CONTROLLING agent, and a plain-RTP answer releases the call with 503 — no downgrade to plaintext. |
| RFC 6347 | DTLS 1.2 | **Done** (via OpenSSL) | DTLS 1.2 only (NO_DTLSV1); handshake driven over a datagram queue transport with our own flight retransmission + 30 s deadline; loss-resilient handshake covered by tests. |
| RFC 5389 | STUN | **Done** | `ice::stun`: full TLV codec (XOR-MAPPED/PEER/RELAYED, USERNAME, MESSAGE-INTEGRITY, FINGERPRINT, ERROR-CODE, ICE-* attrs, TURN attrs); validated against RFC 5769 §2.1/§2.2. |
| RFC 8489 | STUN (newer) | **Partial** | 5389 semantics implemented; 8489-only additions (e.g. new error codes, ADDITIONAL-ADDRESS-FAMILY) not modelled. |
| RFC 8445 | ICE | **Done** (core) | `ice::agent`: candidate gathering (host/srflx/relay), priorities (§5.1.2.1), connectivity checks with short-term creds, role + tie-breaker, USE-CANDIDATE nomination, keepalives, prflx discovery; SDP candidate lines parse IPv6 (bare + bracketed, RFC 8839 §5.1). Triggered-check pacing simplified (all-pairs-at-once; documented). **Live in the B2BUA both roles**: the answerer gathers a host candidate, adopts the offer's credentials/candidates, re-issues checks every 500 ms until nomination (the answerer's first burst races the 200 OK carrying the credentials); the offerer on a `webrtc` route runs the CONTROLLING agent and nominates aggressively with USE-CANDIDATE. |
| RFC 5766 | TURN server | **Done** (core) | Allocation (long-term MD5 auth), refresh, CreatePermission, Send/Data indications, ChannelBind; per-allocation relay sockets pumped concurrently; permission enforcement on both paths. TCP allocations, ReservationToken and mobility not implemented. |
| RFC 5766 | TURN client | **Done** | Agent-side allocation flow: 401 → credentials → verified response (MD5 long-term key pinned by independent known vectors), plus the unauthenticated path with idempotent re-Allocate per RFC 5766 §6.2; used for relay candidate gathering. |
| RFC 7983 | Demultiplexing STUN/DTLS/RTP | **Done** | First-byte classification in the ICE agent; the media pump drops STUN (0–3) before the RTP/RTCP parsers and forwards DTLS records (20–63) to the data-channel engine when the leg negotiated one (dropping them otherwise); the DTLS handshake driver feeds the state machine only datagrams whose first byte is a DTLS record (20–63), so ICE keepalives on the same address cannot reach OpenSSL. |
| RFC 9260/4960 | SCTP (data-channel transport) | **Done** (engine subset) | `sctp` crate: common header with CRC32c (pinned entry-for-entry to the RFC 9260 Appendix A reference table + the CRC-32/ISCSI check value), four-way handshake with an HMAC-SHA256-protected state cookie (stale-cookie refresh from the retained INIT — the refresh carries the §5.1.5 Stale-Cookie cause with measured staleness — forged cookies silently discarded, cookie secret/tag/TSN OS-entropy seeded with a random cookie nonce inside the MAC'd region), verification-tag rules (INIT vtag 0, T-bit reflected ABORT/SHUTDOWN-COMPLETE, uninvited-INIT collision guard §8.5.1(E)), TSN window with gap-block SACKs + duplicate reporting, T3-RTX with RFC 6298 RTO (Karn's rule, T1 retransmit backoff), cwnd slow start/CA + peer a_rwnd flow control (the advertised window discounts ALL received-undelivered bytes per §6.2.1), message fragmentation, ordered/unordered reassembly (unordered delivers on arrival; TSN contiguity gates only ordered delivery), HEARTBEAT/ACK, graceful SHUTDOWN (deferred until outstanding acked, T2-SHUTDOWN retransmission with backoff per §9.1) + ABORT. Timer-handler ordering is pinned by a regression test (the lifetime sweep runs before T3 so an expired message can never be retransmitted). Hardened by the Task 47 audit round (1 Critical + 5 Major + 9 minor closed with regressions; deferred: fast retransmit on gap-acks, zero-window probe, oversize-inbound discard instead of abort). Transport-agnostic packet seam (`handle_packet`/`drain_outbound`); not implemented: multi-homing, restart, RFC 5061 re-config, ECN, unknown-chunk ERROR reports (skip-class honored). |
| RFC 6525 | SCTP stream reconfiguration | **Done** (RFC 8831 subset) | RE-CONFIG chunk (type 130) wire codec pinned to hand-built byte vectors (§4.1 Outgoing SSN Reset Request: RSN initialized to the initial TSN, response-seq = next expected peer RSN − 1, sender's last assigned TSN, stream numbers packed adjacently — length 16+2N, odd lengths padded to the chunk boundary; §4.4 Response: copied RSN + result table 0–6), the §3.1 two-parameter combination (Response + Outgoing reset) and unknown-parameter skip, handshake advertisement through the RFC 5061 Supported-Extensions parameter (RFC 8831 §6.1 signaling; the state cookie's padding byte now carries the flag so the server role learns it through the cookie — old-version cookies parse conservatively as no-support), [`SctpEndpoint::close_channel`] implementing the RFC 8831 §6.7 close: A1 send freeze → Outgoing SSN Reset Request (retransmitted on the re-configuration timer with RTO backoff until the Response — or an E1 implicit acknowledgment via the peer's response_seq — arrives) → receiver resets its incoming streams (§5.2.2 E3: expected SSN to 0, received-but-undelivered data discarded) and reciprocates with its own reset, §5.2.2 E2 deferred reset processing ("In progress" while our cumulative point has not reached the peer's last assigned TSN; held post-reset data released through the normal receive path on completion), duplicate-request response replay (§5.2.1), all-messages-delivered-before-reset pinned by an event-order test, and stream ids reusable after a completed reset (allocator wrap-around scan; the exhaustion test caught an occupied-id bug in its first draft). Known simplifications (documented in-code): one outstanding request at a time (a reciprocal demanded while another is in flight is queued), Incoming-SSN/SSN-TSN/Add-Streams parameters not implemented. |
| RFC 8832 | DCEP (data channel establishment) | **Done** (live in the B2BUA) | `sctp::dcep`: DATA_CHANNEL_OPEN/ACK with all three reliability classes (reliable, max-retransmits, max-packet-lifetime) × ordered/unordered (0x00–0x02, 0x80–0x82), the single-byte ACK, UTF-8 label/protocol, OPEN dispatched through the ordered pipeline so stream sequence numbers stay consistent, duplicate OPEN → protocol-violation ABORT, stream-id parity per §5.1/§6 (DTLS client EVEN, DTLS server ODD — the association initiator is the DTLS client in the RFC 8261 wiring; the parity was originally shipped INVERTED because every self-roundtrip agreed with itself — caught by an RFC text cross-check, fixed), and the §5.1 wire form pinned: BOTH DCEP messages ride PPID 50 (a wire test parses the emitted chunk; the original engine shipped OPEN on PPID 51 — invisible to self-roundtrips, fatal to real peers). A wrong-parity inbound OPEN is never acked (§5.1) and — since RFC 6525 landed — closed per RFC 8831 §6.7 with an Outgoing SSN Reset Request (the documented drop remains only while one of our own resets is in flight). Channels carry the reliability policy into the association's send path. |

| RFC 8261 | SCTP over DTLS | **Done** (live in the B2BUA) | An SCTP packet is the entire DTLS application payload (no extra header): `dtls::DtlsEndpoint::send_app_data`/`recv_app_data` drive post-handshake OpenSSL over the leg's queue transport (recv buffer sized for the largest DTLS record — the queue truncates silently), the B2BUA's data-channel engine owns the live DTLS association after keying, the leg pump forwards RFC 7983 DTLS records (20–63) into it, and the engine encrypts SCTP→DTLS→UDP with no SRTP involvement. The B2BUA (DTLS client) initiates the association. Verified by the `webrtc_datachan` loopback (channel open + fragmented 2000 B message echo while SRTP audio coexists). |
| RFC 8841 | SDP offer/answer for data channels | **Done** (both roles) | `sdp::negotiate`: an `m=application 9 UDP/DTLS/SCTP webrtc-datachannel` offer with data-channel caps is answered in kind — proto + format mirrored, real port, `a=sctp-port` (default 5000 per §4.1) + `a=max-message-size` (256 KiB) emitted as raw attributes, mid/ICE/candidates/fingerprint/setup echoed with the inverse setup role, parse→serialize fixed point; without caps (plain-RTP legs) the m-line is rejected port 0 per RFC 3264 §6, as are wrong-proto formats. The B2BUA's answer engine walks every m-line positionally (first audio + first application accepted, everything else port 0). Offerer side: on a `webrtc` route the B2BUA mirrors the caller's data-channel capability into the leg-B offer (own `a=sctp-port`/`a=max-message-size`, same ICE/DTLS transport attributes — wire form pinned by unit tests incl. a parse→serialize fixed point), and the callee's answer `a=sctp-port` feeds the engine; a port-0 answer keeps the call audio-only. |
| RFC 3758 | PR-SCTP (partial reliability) | **Done** (engine layer) | `sctp::assoc`: sender-side abandonment for both policies (max-retransmits counts per T3 fire; max-packet-lifetime swept by first-send age) with whole-message abandonment granularity, FORWARD-TSN emission only up to the point where everything below is abandoned/acked (ordered streams carry one (SID, SSN) skip entry per abandoned stream — max SSN, one entry per stream per §3.2 — never re-generated as fresh reports), receiver-side advance (out-of-order purge below the point, ordered-SSN skip, partial-run discard), the emitted FORWARD-TSN is retransmitted until the receiver's SACK cum_tsn covers it (§3.5 — a lost FORWARD-TSN no longer stalls ordered delivery), and PR degrades to reliable automatically when the peer did not advertise FORWARD-TSN support (RFC 3758 §3.1). |

## 3. Codecs

| Codec | Status | Notes |
|-------|--------|-------|
| G.711 PCMU/PCMA | **Done** | ITU tables; frame API (`codecs::g711`) + packet path (`rtp::g711`); round-trip + midstream-loss tests. |
| G.722 | **Done** | Bit-exact ITU structure: two-polyphase QMF, 6-bit embedded low-band ADPCM with bit stealing (64/56/48 kb/s), 2-bit high band; ≥20 dB round-trip, 28 dB post-loss recovery. `reset()` returns the decoder to fresh-constructed state (predictor history discarded, verified against a fresh decoder). |
| G.729 | **Done** (wire-conformant; quality caveats documented) | ITU codebooks, 4-pulse/13-bit algebraic CB, ITU pitch-delay mappings + parity. Decoder verified against **bcg729 golden vectors** (±3 dB); bitstreams **cross-decoded by ffmpeg in CI**. Fidelity deviations documented in `codecs/src/g729.rs`. |
| Opus | **Done** | Safe binding to system libopus 1.5.2 (8–48 kHz, mono/stereo, DTX/FEC/bitrate control), feature-gated. Decodes any RFC 6716 frame duration up to 120 ms; PLC always emits exactly one 20 ms frame so playout pacing is stable. |
| L16 | **Done** | RFC 3551 §5.1. |
| CN (silence) | **Done** | RFC 3389 comfort-noise payload + noise generation; multi-byte payloads tolerated with the first octet used (§2.2), empty payload rejected. |
| PLC | **Done** (engineering feature) | `PitchPlc`/`EnergyDecayPlc`/`SilencePlc` + per-codec `Decoder::conceal()` wired into the jitter buffer. |
| RFC 4733 DTMF | **Done** | Event payload encode/decode + relay; audio-band DTMF detection not implemented. |
| Transcoding | **Done** | B2BUA 16 kHz bridge converts any negotiated codec pair (e.g. PCMU↔PCMA verified end-to-end with SNR-checked audio). |

## 4. Platform services

| Service | Status | Notes |
|---------|--------|-------|
| Conference mixing | **Done** | `media::Mixer`: N-way at bridge rate, per-input gain/mute, √N scaling + hard clip protection, VAD-gated contributions. |
| Recording | **Done** | `media::Recorder`: streaming RIFF/WAVE (PCM-16) with duration accounting; Opus tap hook attached. |
| Resampling | **Done** | `media::Resampler`: windowed-sinc (Kaiser), anti-aliasing on downsample (7 kHz → folds, tested), streaming + batch parity. |
| VAD | **Done** | Adaptive noise floor, energy + ZCR gating, hangover; drives AI barge-in and mixer gating. |
| CDR | **Done** | `cdr` crate: lifecycle builder, dispositions from SIP codes, bounded store, query/stats API, JSON; REST exposure via `api`. |
| Outbound dialer | **Done** (core) | `dialer` crate: preview/progressive/predictive pacing (Erlang-C-inspired), caller-ID rotation, TCPA 3% abandonment window, calling-hour windows, DNC, AMD hooks, attempt caps + cooldowns. |
| AI bridge | **Done** | AudioSocket TCP framing (UUID/AUDIO/DTMF/TERMINATE), WebSocket tap, VAD events, barge-in, ≤ 20 ms added latency. |
| Control plane | **Done** | `api` crate: REST (health/ready/metrics, CDR queries + filters, campaign stats, pacing preview, campaign creation), WebSocket event/echo channel, Prometheus text exposition. |
| Metrics | **Done** | Prometheus counters (calls in/out/answered/failed, WS clients, HTTP requests) at `/metrics`. |

## 5. Not claimed (honest gaps)

* **Failover (RFC 3263)**: connection-time failover across the resolved
  candidate list is live on the trunk client (priority-ordered walk with a
  per-candidate connect budget, winner pinned for keepalives/RTP). Not yet
  covered: mid-dialog re-resolution for an established session whose peer
  dies, and DNS TTL-driven cache refresh.
* **Standalone dialog layer (§12)**: the B2BUA tracks per-leg dialog state
  (tags/Call-ID/CSeq, in-dialog re-INVITE/UPDATE with tag checks); a
  reusable dialog package has not been extracted yet.
* **In-dialog SDP renegotiation**: re-INVITEs that would change the session
  (hold, codec change) are answered 488 instead of renegotiating; only
  no-change refreshes are accepted. A PRACK carrying an SDP offer is
  likewise answered 488 (no early-media renegotiation).
* **PRACK/100rel scope**: exactly one reliable 1xx per call attempt (the
  180) — no 183 progress responses, no RSeq sequence across multiple
  provisional responses; reliable 1xx to our own re-INVITEs (session
  refresh) are not PRACKed (finals answer quickly, stopping peer
  retransmission); 421 is retried once and only on the initial dial.
* **Postgres CDR persistence**: CDRs are in-memory (bounded) + JSON; sqlx
  storage backend planned.
* **Load verification**: the 8-core/1000-call target is an architecture goal;
  the harness is shipped and a debug-build soak ran in this 2-vCPU sandbox
  (200 calls @ concurrency 20 → 100% answered, setup p95 305 ms; knee
  between 20–50 under CPU saturation); the release-build 8-core soak
  remains.
* REMB, audio-band DTMF detection,
  mid-dialog RFC 3263 re-resolution.
* **WebRTC media legs: DONE at the answerer layer.** A
  `UDP/TLS/RTP/SAVPF` offer with ICE + a sha-256 fingerprint is answered
  with our ICE credentials/candidates (RFC 8445, controlled role, checks
  re-issued until nomination), `setup:active` → we drive DTLS as the
  client over the nominated pair (RFC 5763 §5, fingerprint pinned from
  the offer, sha-256 only), and the pump protects/opens every datagram
  with the exported SRTP sessions (RFC 3711; RFC 7983 demux — STUN/DTLS
  never reach the media parser; an unprotectable datagram is dropped, and
  a leg that negotiated SAVPF has NO plaintext fallback; a SAVPF offer
  without ICE credentials is rejected 488). Verified end to end by an
  ICE+DTLS+SRTP loopback integration test through the transcode bridge.
  **OFFERER side: DONE too** — a `webrtc` route dials downstream with a
  SAVPF offer (`setup:actpass`), runs ICE as the CONTROLLING agent, and
  completes DTLS in whichever role the answer picks (server on
  `setup:active`, client on `setup:passive` — both covered by integration
  tests, one engine per binary); a plain-RTP answer releases the call with
  503 instead of degrading.
  **Data channels: DONE on both legs** — `m=application` answered per
  RFC 8841 AND offered downstream when the caller offered one (mirror
  policy on `webrtc` routes), the SCTP association rides the established
  DTLS (RFC 8261) with the association role and RFC 8832 §5.1/§6 stream
  parity following the negotiated DTLS role, DCEP channels open across the
  B2BUA and messages echo (fragmentation included) while media flows; a
  callee that declines the m-line keeps the call audio-only, and the leg-B
  offer is bundled per RFC 8843/5888 (`a=mid` on both m-lines +
  `a=group:BUNDLE 0 1`), and channels CLOSE per RFC 8831 §6.7 (RFC 6525
  stream reset: request → response → reciprocal reset, E2 deferred
  processing, duplicate-response replay, stream ids reusable; the wrong-parity-OPEN
  guard closes the bogus channel with a reset). Remaining: trickle ICE,
  data-channel application semantics beyond
  echo (a real messaging API is engine-level today).
* **RTCP non-mux addressing (RFC 3550 §11)**: the media pump is mux-only;
  peers that refuse `a=rtcp-mux` would address RTCP at the RTP port+1,
  which we never bind (their feedback would be lost). We now at least
  advertise rtcp-mux so mux-capable peers (browsers, this stack) negotiate
  the channel correctly; a non-mux RTCP listener remains future work.
* **DNS hardening (RFC 5452)**: responses are validated for QR bit and
  query id, every real RR is size-checked, records are filtered by
  owner-name bailiwick (strict query-name rule — additional-section
  target addresses are dropped by design; targets are re-resolved through
  dedicated A/AAAA queries), and a locally-truncated UDP datagram (fills
  the 4096 B buffer without a server TC flag) now falls back to TCP
  instead of parsing a partial record set.
* **RTP destination from the SDP answer**: the trunk call path sends RTP
  to the pinned signaling target's IP + the answer's media port; a
  carrier with split signaling/media hosts would need the answer's `c=`
  line honored (pre-existing gap, unchanged by the RFC 3263 work).

## 6. Verification methodology

* Every public function carries tests (workspace rule); run
  `cargo test --workspace` → **656 passing across 70 suites**.
* RFC conformance vectors: SRTP (RFC 3711 B.2/B.3, RFC 7714 §16 + §17.1/§17.3
  SRTCP AEAD), STUN (RFC 5769 §2.1/§2.2; MD5 long-term keys + MESSAGE-INTEGRITY
  against independent vectors), G.729 (bcg729 oracle), cross-decode by ffmpeg.
* End-to-end in-repo: B2BUA loopback call, RFC 4028 session-timer flows
  (negotiation, refresh, 422 floor/retry, UPDATE, expiry BYEs), RFC 3262
  rel100 flows (reliable 180 with the parked 200, retransmission until
  PRACK, RAck verdicts 481/488, plain-180 path, both-legs PRACK incl.
  stored-PRACK retransmission recovery, §4 PRACK gates, 421 retry with
  `Supported` merge), DTLS-SRTP
  handshake → SRTP media, ICE agent pair checks (incl. IPv6 candidates),
  TURN relay round-trip (authenticated + unauthenticated idempotent), REST
  API black-box tests.
* `cargo audit`: 0 vulnerabilities (1 allowed unmaintained notice on the
  whitelisted libopus FFI wrapper).
