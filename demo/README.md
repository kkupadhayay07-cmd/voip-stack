# demo

End-to-end demonstration of the VoIP stack: a **complete call served entirely
by the native stack** — no external SIP proxy, PBX or media server.

## What the demo shows

A full RFC 3261 call flows through the B2BUA (back-to-back user agent) with
**real-time audio transcoding**:

```
 UAC (A-leg)                        B2BUA                        UAS (B-leg)
──── PCMU ────►  INVITE ──────────►│◄───── INVITE (relayed) ────►  ◄── PCMA ────
  (send)         PCMU RTP ────────►│ decode ► 16 kHz bridge ► encode
                 100 / 180 / 200 ◄─│───── 200 OK (relayed) ─────►  (answer)
                 ACK ─────────────►│────── ACK (relayed) ─────────►
                 1 s of RTP audio: │  PCMU in ─► PCMA out (SNR-verified)
                 BYE ─────────────►│────── BYE (relayed) ─────────►
                 CDR trail: LegInvited(A) → LegInvited(B) → LegAnswered(A)
                            → LegAnswered(B) → LegConfirmed×2 → CallEnded
```

The integration test behind this demo asserts, among other things:

* correct signaling order (`100 → 180 → 200 → ACK`), retransmission timers,
  ACK/BYE/CANCEL relay;
* the B-leg INVITE is a genuine relay (new tags/Call-ID, rewritten SDP);
* **actual transcoded audio**: a PCMU tone is decoded, bridged and re-encoded
  as PCMA, then SNR-checked against the reference waveform (lag-aligned to
  absorb resampler group delay);
* clean teardown and a complete CDR (call-detail-record) event trail.

## How to run it

Option 1 — the interactive demo binary (listens on `0.0.0.0:5060`, logs every
CDR event):

```sh
cargo run -p b2bua --bin b2bua-demo
```

Configuration via env vars: `B2BUA_SIP_BIND` (default `0.0.0.0:5060`),
`B2BUA_TARGET` (default outbound target URI), `B2BUA_MEDIA_HOST` (SDP `c=`
host). Send it an INVITE with any SIP client to see the CDR trail at INFO.

Option 2 — the scripted loopback call (self-contained, no external endpoints;
this is what `demo/run_loopback_demo.sh` runs):

```sh
./demo/run_loopback_demo.sh
# equivalent to:
cargo test -p b2bua --test loopback_call -- --nocapture
```

## What to expect

The script builds the workspace, then runs the ~3 s loopback call. With
`--nocapture` you see the B2BUA's `tracing` output (leg setup, media bridge,
jitter-buffer playout), e.g.:

```
INFO b2bua::engine: b2bua engine listening local=127.0.0.1:57838
INFO b2bua::engine: media bridge up: Pcmu <-> Pcma call_id=loopback-call-1
DEBUG b2bua::media: pump stopped: encoded=62 concealed=0
```

The CDR trail (`INVITED-A → INVITED-B → ANSWERED-B → CONFIRMED-B →
CONFIRMED-A → TERMINATED-A → CALL_ENDED`) is captured by the test and asserted
line by line; with the interactive `b2bua-demo` binary the same events are
logged live at INFO under the `cdr` target:

```
INFO cdr: call_id=... side=A event=INVITED "sip:caller@127.0.0.1 -> sip:b2bua@127.0.0.1"
INFO cdr: call_id=... side=B event=ANSWERED "PCMA"
...
INFO cdr: call_id=... event=CALL_ENDED "duration_ms=... a2b=50 b2a=50"
```

Exit code 0 + `test result: ok. 1 passed` means the whole stack — SIP
parsing/serialization, SDP offer/answer, RTP with jitter buffering, PCMU/PCMA
transcoding, call state and CDRs — worked end to end. (If libopus is missing,
the Opus path degrades to an error at registration; the demo only needs
PCMU/PCMA, which are native.)

## Pointers to the docs

* `docs/DESIGN.md` — architecture: SIP/SDP/RTP layers, jitter buffer, codec
  matrix, B2BUA design.
* `docs/COMPLIANCE.md` — RFC compliance matrix (RFC 3261/3264/4566/3550/4733…).
* `docs/DEPLOYMENT.md` — running the stack for real (Docker, ports, config).
* `docs/SECURITY_NOTES.md` — dependency audit status.
* `crates/b2bua/src/engine.rs` / `media.rs` — the call engine and the
  cross-connected media pumps that make this demo work.
