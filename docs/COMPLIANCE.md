# RFC Compliance Matrix

Status of the ZRTC VoIP stack against the RFCs and ITU codecs it targets.
**Honest by design** — no row is marked Done without implementation and tests
behind it. Last reviewed: 2026-09 (Phase 1, commit series after the native
codec suite landed).

Legend: **Done** · **Partial** · **Planned** (target phase in parentheses).

## 1. SIP signaling

| RFC | Feature | Status | Notes |
|-----|---------|--------|-------|
| RFC 3261 | SIP: message layer | **Done** | `sip-core`: strict panic-free byte parser (UDP datagram + TCP/TLS/WS stream framing, §18.3), canonical serializer, URI/header model, branch/tag/Call-ID generators. Parser limits enforced (64 KiB msg, 128 headers, 8 KiB/line). |
| RFC 3261 | SIP: transactions (§17) | **In progress** | Timers/state machines are the current work package; not merged yet. |
| RFC 3261 | SIP: transports (§18) | **In progress** | UDP/TCP transaction-transport wiring in flight; TLS/WS/WSS planned (Phase 2). |
| RFC 3261 | SIP: dialogs (§12) | **Planned** | After transactions/transports land. |
| RFC 3262 | PRACK / 100rel | **Planned** | `RAck` and `RSeq` header types already modelled in the message layer; reliability state machine not started. |
| RFC 3263 | DNS (NAPTR/SRV) for SIP | **Planned** | No resolver yet; static host:port targets only. |
| RFC 3264 | Offer/answer | **Done** | `sdp::negotiate`: full RFC 3264 engine (offer→answer, direction/codec intersection) with `StreamPlan` projection for the media layer. |
| RFC 3326 | Reason header | **Partial** | `Reason` header type modelled/serializable in `sip-core`; no protocol semantics (e.g. Q.850 mappings) applied yet. |
| RFC 3515 | REFER | **Planned** | `Refer-To` header type modelled; REFER/Replaces call flows not implemented. |
| RFC 4566 | SDP | **Done** | `sdp` crate: strict positioned-error parser + canonical serializer, round-trip tests. |
| RFC 8866 | SDP v2 (WebRTC era) | **Partial** | Parser/model cover `rtpmap`/`fmtp`, `ice-*` (candidates stored as strings), `fingerprint`, `bundle`, `extmap`; full 8866 grammar validation not complete. |
| RFC 2617/7616 | Digest auth | **Partial** | Challenge/response helper functions in `sip-core` (incl. `-nextnonce`/`cnonce` inputs); server-side nonce store/registration flows not yet. |

## 2. Media transport

| RFC | Feature | Status | Notes |
|-----|---------|--------|-------|
| RFC 3550 | RTP/RTCP | **Done** | `rtp` crate: fixed-header parse/serialize; RTCP SR/RR/SDES/BYE/APP compound parse/encode; RFC 3550 A\* interarrival jitter estimator; SSRC probation. |
| RFC 3551 | RTP/AVP profile | **Done** | Static payload types (0 PCMU, 8 PCMA, 9 G722, 18 G729, 13 CN, 100 telephone-event) + L16 (BE) support. |
| RFC 3556 | SDP bandwidth modifiers | **Partial** | `b=` lines parsed and modelled generically; `TIAS`/packet-rate semantics not applied to pacing yet. |
| RFC 4585 | RTCP-based feedback | **Partial** | Feedback packets modelled: NACK (transport, fmt=1), TWCC (fmt=15), PLI/FIR (payload-specific). **REMB is not implemented**; no RTX retransmission logic yet. |
| RFC 4733 | RTP DTMF (telephone-event) | **Done** | `rtp::dtmf`: events 0–15 with start/end semantics + tests; `telephone-event` descriptors in the codecs registry. |
| RFC 5761 | RTP/RTCP demultiplexing | **Done** | `is_rtcp()` §4 heuristic (PT range check), unit-tested. |
| RFC 8285 | RTP header extensions | **Done** | One-byte and two-byte extension blocks parse/serialize in `rtp::packet`. |
| RFC 3711 | SRTP/SRTCP | **Planned** (Phase 2) | Key derivation, AES-CM, replay protection all to be self-implemented. |
| RFC 7714 | SRTP AES-GCM | **Planned** (Phase 2) | After 3711 core. |
| RFC 5764 | DTLS-SRTP handshake/usage | **Planned** (Phase 2) | `use_srtp` ext, cert fingerprint (SDP field already modelled). |
| RFC 6347 | DTLS 1.2 | **Planned** (Phase 2) | Needed for 5764/WebRTC. |
| RFC 5389 | STUN | **Planned** (Phase 2) | |
| RFC 8445 | ICE | **Planned** (Phase 2) | SDP `ice-*` attributes already carried by the sdp model. |

## 3. Codecs

| Codec | Status | Notes |
|-------|--------|-------|
| G.711 PCMU/PCMA | **Done** | ITU-T G.711 μ-law/A-law tables; implemented in `codecs::g711` (frame API) and `rtp::g711` (packet path); round-trip + midstream-loss tests. |
| G.722 | **Done** | Bit-exact ITU structure per `codecs/src/g722.rs`: two-polyphase QMF, 6-bit embedded low-band ADPCM with bit stealing (64/56/48 kb/s), 2-bit high band, spec quantizer tables; ≥20 dB round-trip, 28 dB post-loss recovery. |
| G.729 | **Done** (wire-conformant; quality caveats documented) | ITU codebooks (LSP split VQ + MA prediction, two-stage gain VQ), 4-pulse/13-bit algebraic CB with gray-coded track, ITU pitch-delay mappings + parity. Encoder emits fully conformant bitstreams; decoder verified against **bcg729 golden vectors** (level match within ±3 dB) and our bitstreams are **cross-decoded by ffmpeg in CI** (`g729_interop` test, runtime-detected). Phase-1 fidelity deviations (float analysis-by-synthesis, open-loop pitch preselection, simplified postfilter tilt) are wire-invisible and documented in `codecs/src/g729.rs`. |
| Opus | **Done** | Safe binding to system libopus 1.5.2 (8–48 kHz, mono/stereo, DTX/FEC/bitrate control), feature-gated (`opus`, on by default; stack builds without it). |
| L16 | **Done** | RFC 3551 §5.1 linear 16-bit big-endian. |
| CN (silence) | **Done** | RFC 3389 comfort-noise payload + noise generation (`codecs::cn`). |
| PLC | **Done** (engineering feature) | `PitchPlc` / `EnergyDecayPlc` / `SilencePlc` + per-codec `Decoder::conceal()` hook wired into the jitter buffer. |
| RFC 4733 DTMF generation/detection | **Done** | Event payload encode/decode (`rtp::dtmf`); audio-band DTMF detection not implemented (Phase 3). |

## 4. Verification methodology

* Every public function carries tests (workspace rule); run `cargo test --workspace`.
* **G.729**: offline oracle — bcg729-encoded bitstream + reference PCM committed
  under `crates/codecs/tests/data/`; decoder must match reference decode within
  ±3 dB. Encoder bitstreams are cross-decoded by `ffmpeg` in the CI
  `codec-interop` job when available.
* **G.722/G.711**: ITU table conformance + SNR thresholds asserted in unit tests.
* CI runs fmt/clippy/test/audit plus the codec interop job — see
  `.github/workflows/ci.yml`. Known temporary relaxations (fmt drift,
  clippy without `-D warnings`) are annotated in that file and are removed as
  soon as the in-flight work packages land.

## 5. Not claimed

For the record, the following are **not** implemented anywhere yet and must not
be advertised by dashboards/milestones: SRTP/DTLS/ICE/STUN (Phase 2),
PRACK/3263 DNS (Phase 2), TLS/WS/WSS transports (Phase 2), audio-band DTMF
detection, REMB, RTX retransmission, conference mixing, transcoding engine,
registrar/proxy/SBC roles, REST control plane.
