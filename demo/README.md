# demo

End-to-end demonstrations of the VoIP stack: a **complete call served entirely
by the native stack** — no external SIP proxy, PBX or media server.

Four ways to run:

1. **Full-stack daemon demo** — `./demo/run.sh` (the `zrtc` service end to end).
2. **Load-harness soak** — `CALLS=200 CONCURRENCY=20 ./demo/soak.sh` (N concurrent
   calls + latency report; see below).
3. **B2BUA loopback call** — `./demo/run_loopback_demo.sh` (in-repo integration test).
4. **Vendor trunk smoke** — `ZRTC_TRUNK_AUTH=digest ./demo/trunk_smoke.sh` (outbound
   trunk auth modes against the local daemon; see below).

## Full-stack daemon demo (`./demo/run.sh`)

One command exercises the whole service, exactly as deployed:

1. builds the `zrtc` daemon;
2. starts it with `demo/zrtc.toml` — UDP/TCP/TLS/WSS SIP listeners, SBC
   (CIDR allow-list + rate limit), registrar, B2BUA with a loopback sink,
   AI-bridge tap, REST API, observability;
3. waits for the configured AoR (`sip:1000@zrtc.local`) to REGISTER;
4. probes the **TCP**, **TLS** and **WSS** listeners with the in-repo UAC;
5. places one **inbound call** over UDP (UAC → SBC → B2BUA → sink), with
   real RTP both ways;
6. the daemon **originates one outbound call** itself (after a delay);
7. fetches `GET /cdrs` and prints both CDR records.

Exit 0 = **two answered CDRs** (one inbound, one outbound).

## Load-harness soak (`./demo/soak.sh`)

`zrtc load` drives `--calls` total call attempts (at most `--concurrency` in
flight) through the **same full pipeline** as the daemon demo — listener →
SBC → proxy → B2BUA → sink → real paced RTP both ways — and reports the
per-call INVITE→200 setup latency (mean / p50 / p95 / p99 / max), answered
and failed counts with a deduplicated failure breakdown, and the sustained
calls-per-second. `--json` emits one machine-readable JSON line (the human
report then goes to stderr, so `> report.json` stays pure). The script also
cross-checks the daemon's served CDR count against the load report and
fails on any daemon panic.

Sizing guidance: each in-flight call holds ~5 sockets across the two
processes (UAC SIP+RTP, two B2BUA leg sockets, sink RTP) — keep
`CONCURRENCY` well under the `ulimit -n` budget.

Measured baseline (sandbox: 2 vCPU, **debug build**, full pipeline with
pcap + traces on, 500 ms PCMU per call): 200 calls at concurrency 20 →
**200/200 answered, setup p50 116 ms / p95 305 ms, 5.3 calls/s**; the
debug-build knee sits between concurrency 20 and 50. Release-mode soak on
8-core hardware (the VISION M2 target) is the pending follow-up.

Observability output lands in `/tmp/zrtc-observ/`:

| File | Content |
|------|---------|
| `sip.pcap` | every SIP packet, Wireshark-openable (SIP dissected natively) |
| `rtp.pcap` | every RTP packet on every leg, Wireshark-openable |
| `trace-*.log` | one human-readable trace per call: signaling timeline + per-leg media diag (`rx/tx/lost/jitter/concealed`) |

The per-leg diag counters in the trace and the CDR record
(`packets_rx`, `packets_tx`, `packets_lost`, `avg_jitter_ms`,
`concealed_events`) come from the **same pump counters** — the numbers you
see in Wireshark, the trace and the CDR always agree.

## B2BUA loopback call (`./demo/run_loopback_demo.sh`)

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


## Additional end-to-end scenarios (in-repo tests)

Beyond the loopback call, each security/platform layer ships a runnable
end-to-end scenario:

| Scenario | Command | What is proven |
|----------|---------|----------------|
| Full-stack daemon | `./demo/run.sh` | REGISTER + TCP/TLS/WSS listener probes + inbound & outbound calls + CDRs + pcap/traces |
| Load-harness soak | `CALLS=200 CONCURRENCY=20 ./demo/soak.sh` | N concurrent calls through the full pipeline, setup-latency percentiles, CDR cross-check, panic gate |
| B2BUA loopback call | `./demo/run_loopback_demo.sh` | Full SIP call + PCMU→PCMA transcoding + CDR trail |
| Vendor trunk smoke | `ZRTC_TRUNK_AUTH=digest ./demo/trunk_smoke.sh` | Outbound call through the vendor trunk layer (`ip`/`digest`/`bearer`/`tls_client_cert`), optional REGISTER challenge path, CDR printed |
| DTLS-SRTP handshake | `cargo test -p dtls --test handshake` | Real DTLS 1.2 over UDP, fingerprint pinning, key export, loss recovery, SRTP media roundtrip on the exported keys |
| ICE agent pair | `cargo test -p ice --test integration` | Host-candidate gathering, connectivity checks, nomination, keepalives |
| STUN server | `cargo test -p ice --lib server` | Binding request → XOR-MAPPED-ADDRESS oracle |
| TURN relay | `cargo test -p ice --test integration turn` | Authenticated allocation, permissions, Send/Data relay both directions |
| SRTP conformance | `cargo test -p srtp` | RFC 3711 B.2/B.3 + RFC 7714 §16 vectors, replay/ROC behavior |
| REST control plane | `cargo test -p api --test http` | CDR queries/filters, campaign stats, pacing preview, metrics |
| Codec pipeline | `cargo test -p media --test pipeline` | PCMU decode → VAD → mix → 8k↔16k resample → WAV record |
