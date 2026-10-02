# ZRTC — The Dream Platform

> **One sentence:** Anyone can describe a voice agent in plain language and have
> a real phone number answering calls in under five minutes — running on our own
> SIP stack, our own media pipeline, our own AI orchestration, with zero
> dependence on Twilio, Vapi, Retell, Bland, LiveKit Cloud, or any other
> third-party voice platform.

---

## 1. The User

**Primary user:** A small business owner, agency, or product team who wants
an AI voice agent but cannot justify a $50k integration project, cannot
tolerate vendor lock-in, and cannot accept per-minute pricing that scales
with success.

**Their job to be done:**

- "I want a receptionist that answers my phone 24/7."
- "I want an outbound agent that calls my leads and books demos."
- "I want it to sound like a human, not like an IVR from 2008."
- "I want to own my data, my prompts, my numbers — not rent them."
- "I want to see every call, every transcript, every outcome."

**Secondary user:** A developer who wants a programmable voice stack they
can extend with custom codecs, custom call handlers, custom AI providers —
without forking a monolith or reading 100,000 lines of someone else's Rust.

---

## 2. The Experience

### Creating an agent (target: 3 minutes)

```text
User types: "You're a friendly receptionist for a dental clinic in Pune.
Greet callers, ask if they're a new or existing patient,
and book appointments. Speak Hindi and English."

System: Compiles this into a structured agent config.
        Picks a natural voice. Wires STT/LLM/TTS.
        Assigns a phone number. Deploys it.
        Live in 30 seconds.

User calls: The number. Hears a natural greeting in the right language.
            Books an appointment. Gets a confirmation.
```

### Watching calls (target: one screen)

```text
Live dashboard shows:

  - Active calls with duration, direction, agent name
  - Real-time transcript streaming
  - Latency waterfall: STT ms + LLM ms + TTS ms
  - Audio quality: jitter, packet loss, MOS estimate

Click any call → full trace, pcap, recording, transcript, CDR
Click any transcript line → jump to that moment in the recording
```

### Debugging a call (target: 30 seconds)

```text
zrtc diag --call-id <id>
  → Full signaling trace
  → Per-stage latency breakdown
  → Media quality stats
  → Wireshark filter ready to copy
  → Links to pcap and recording
```

### Making changes (target: instant)

```text
User: "Make the agent more empathetic when callers sound frustrated."

System: Rewrites system prompt based on past failed calls.
        A/B tests against the current version on 20 simulated calls.
        Shows diff and success metrics.
        One click to deploy.
        Rollback is one click too.
```

---

## 3. The Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│ L7 · BUSINESS                                                    │
│ Billing · Multi-tenant · Analytics · SLAs                        │
├──────────────────────────────────────────────────────────────────┤
│ L6 · OPERATIONS                                                  │
│ K8s · Monitoring · HA · Backups · Security · Compliance          │
├──────────────────────────────────────────────────────────────────┤
│ L5 · PRODUCT UI                                                  │
│ Agent builder · Live monitor · CDR explorer · Prompt playground  │
├──────────────────────────────────────────────────────────────────┤
│ L4 · PRODUCT                                                     │
│ Prompt→Agent compiler · Registry · Tools · Webhooks · Versions   │
├──────────────────────────────────────────────────────────────────┤
│ L3 · AI PIPELINE                                                 │
│ STT · LLM · TTS · VAD · Barge-in · Fallbacks · <200ms P95        │
├──────────────────────────────────────────────────────────────────┤
│ L2 · TELEPHONY  <- we are here, ~70% done                        │
│ Trunk · GRUU · WebRTC legs (answerer+offerer) · SCTP channels    │
│ Postgres CDR · release soak [pending] · M1 [x] · M2 in reach     │
├──────────────────────────────────────────────────────────────────┤
│ L1 · FOUNDATION — complete (M1 verified: 400+ gate, release)     │
│ sip-tx · sdp · rtp · srtp · dtls · ice · codecs · b2bua · media  │
│ registrar · proxy · sbc · observ · cdr · dialer · ai-bridge      │
└──────────────────────────────────────────────────────────────────┘
```

**Every layer above depends on the layers below being correct.**
**Never build L(n+1) before L(n) is verified. That is the rule.**

---

## 4. The Non-Negotiables

These are the qualities that make ZRTC *this* platform, not another.

### Ownership

- The SIP stack is ours. Not PJSIP, not FreeSWITCH, not Kamailio, not Asterisk.
- The media pipeline is ours. Not LiveKit Cloud, not Twilio Media Streams.
- The AI orchestration is ours. Not Vapi, not Retell, not Bland.
- Users bring their own AI keys (BYOK). We never mark up provider costs.
- Users own their data, prompts, recordings, transcripts. Export anytime.

### Native

- SIP is implemented in our code, not wrapped.
- RTP/RTCP is ours. Jitter buffer, PLC, transcoding — all native.
- WebRTC termination is ours. ICE, DTLS-SRTP, TURN — all native.
- No hidden SaaS dependencies in the critical path.

### Programmable

- Every layer has a public Rust trait.
- Custom codecs load without forking the core.
- Custom call handlers load without patching b2bua.
- Custom CDR sinks (Postgres, S3, BigQuery) plug in.
- Config-driven, not code-driven, for common cases.
- Full CLI with `--json` on every command.

### Observable

- Every call has a trace, a pcap, a CDR, a transcript, a recording.
- Every log line carries a call_id.
- Every metric has a call_id label.
- One command shows everything about one call.

### Honest

- Every claim is backed by a command and raw output.
- Tests prove behavior, not aspiration.
- Reports describe what *is*, never what *should be*.
- If something isn't done, it says so.
- If something is a stub, it's marked a stub.
- If something fails, it fails loudly — never silently.

---

## 5. The Explicit Non-Goals

What ZRTC will NOT be. These are decisions, not oversights.

- **Not a contact center.** No agent queues, no supervisor dashboards,
  no skill-based routing. Those exist (VICIdial, FreeSWITCH). Use them.
- **Not a video platform.** Audio only. Video is a separate product.
- **Not a PBX.** No extension dialing, no voicemail boxes, no BLF.
  Route to one when you need one (Asterisk, FreeSWITCH, or a real PBX).
- **Not a SIP trunk provider.** We connect to carriers, we don't become one.
- **Not a hosted-only SaaS.** Self-hostable, source-available. If someone
  wants to run it in their own datacenter with their own carrier, they can.
- **Not for 10,000 concurrent calls on day one.** The architecture supports
  it. The engineering doesn't until Phase F. Be honest about that.
- **Not a replacement for human agents.** Augmentation, not replacement.
  The escalation path to a human is a first-class feature.

---

## 6. Milestones with Verifiable Checkpoints

Every milestone is checked by a command. Not by a report.

### M1 · Foundation Complete

**Checkpoint:** `cargo test --workspace --release` passes with 400+ tests.

- `sip-tx` crate implements RFC 3261 §17 with fake-clock tests
- TCP/TLS/WSS framing is fuzz-tested
- Session timers (RFC 4028) work
- PRACK (RFC 3262) works
- SDP handles IPv6, BUNDLE, rejected m-lines

### M2 · Real Telephony

**Checkpoint:** A real phone call, both directions, CDR in Postgres.

- `zrtc call +91XXXXXXXXXX` rings a real mobile
- Inbound call from PSTN answers and bridges
- WebRTC browser call works (Chrome + Firefox)
- Load test on real hardware with published numbers
- Postgres CDR with retention policies

### M3 · First AI Call

**Checkpoint:** Call your mobile. Say "hello." An AI voice answers in <1s.

- STT wired (Deepgram or equivalent)
- LLM wired (GPT-4o-mini or equivalent)
- TTS wired (Cartesia or equivalent)
- Barge-in works (interrupt the agent mid-sentence)
- P95 latency < 500ms measured and published

### M4 · Prompt → Agent

**Checkpoint:** Type a prompt. Get a working agent in <5 minutes.

- Compiler turns NL into agent config
- Registry with versioning and rollback
- Tools/functions (book, transfer, query)
- Webhooks on call events
- Test dial from prompt editor

### M5 · Product UI

**Checkpoint:** A non-technical user can create, test, and monitor an agent.

- Agent builder form
- Live call monitor
- CDR explorer with search
- Recording + transcript with sync playback
- One-click prompt iteration

### M6 · Production Operations

**Checkpoint:** Runs unattended for 30 days with 99.9% uptime.

- Docker images published
- K8s manifests with autoscaling
- Prometheus + Grafana + alerts
- Loki for logs
- Backup and disaster recovery tested
- Security audit passed

### M7 · Business

**Checkpoint:** A paying customer.

- Multi-tenant isolation
- Usage metering and billing
- SLA and status page
- TCPA / DNC compliance
- Evaluation framework (resolution rate, handle time)

---

## 7. How to Know You're On Track

Every task in the roadmap must satisfy these:

✅ **Moves one layer up.** If it's polish on L1 when L3 is empty, question it.

✅ **Has a command that proves it works.** No task is done until it prints
   a number, a pcap, or a phone call log.

✅ **Doesn't touch unrelated layers.** Fixes stay in one crate.

✅ **Adds tests, not just code.** New behavior gets new tests. Regressions
   get regression tests.

✅ **Compiles without warnings, passes clippy, passes audit.**

✅ **Gets committed, tagged, and pushed before the next task starts.**

---

## 8. How to Know You're Off Track

🚩 **Another report that says "done" without terminal output.**

🚩 **Polishing one crate while a whole layer above is empty.**

🚩 **"Just one more feature" before the previous milestone is verified.**

🚩 **A branch with unpushed commits.** (Happens every time state is lost.)

🚩 **Tests skipped, disabled, or marked `#[ignore]`.**

🚩 **A new external dependency added "just for this."**

🚩 **"We'll fix it in Phase X" repeated more than twice for the same class of bug.**

If any of these happen, stop, take stock, and return to the last verified
milestone.

---

## 9. The Order of Operations

Never reorder. Each step unlocks the next.

```text
FOUNDATION              TELEPHONY           AI
─────────               ─────────           ──
sip-tx        ───►      real trunk    ───►  STT
framing                 WebRTC              LLM
timers                  Postgres CDR        TTS
PRACK                   load test           barge-in
SDP hardening           latency
RTP fixes
jitter tuning
codecs

PRODUCT                 OPS
───────                 ───
prompt→agent  ───►      Docker
registry                K8s
tools                   monitoring
webhooks                backups
tenant isolation        security
billing                 compliance
                        → paying customer
```

Each arrow is a **gate**. Do not cross a gate until the node before it
has passed its checkpoint.

---

## 10. The One Rule

> **If you cannot run it, watch it, hear it, or measure it — it is not done.**

Not "implemented." Not "reported." Not "claimed." Done.

This rule has saved this project three times already:

- When a "bi-directional fix" turned out to be unimplemented
- When a "Working Daemon" turned out to be a report
- When a "force-push recovery" turned out to be a transient state

It will save it again. Trust it.

---

## 11. What Success Looks Like in Twelve Months

A small business in Pune runs a dental receptionist on ZRTC.
Agencies deploy 50 outbound agents on ZRTC for their clients.
A developer forks ZRTC to build a specialized vertical.
A telecom operator embeds ZRTC as the voice AI layer in their network.
Nobody pays Twilio per minute.
Nobody loses their prompts to a vendor.
Nobody's recordings sit on someone else's S3.

**That is the dream. Everything else serves it.**

---

## 12. The One-Paragraph Summary

ZRTC is a native SIP voice AI platform. It owns its own protocol stack,
its own media pipeline, and its own AI orchestration. It is programmable
at every layer, observable to the packet, and honest about what works.
It is built one verified milestone at a time, never skipping gates.
It exists so that anyone — a solo developer, a small business, an
operator — can build a voice agent without renting one from a company
that will always charge more as they grow.

**Build it in that order. Measure it with commands. Ship it when it works.**

---

## How to Use This Document

Reference it before every task. When a task is proposed, ask:

1. Which layer does this move up?
2. Which milestone checkpoint does it advance?
3. Does it violate a non-negotiable?
4. Does it trip an "off track" signal?
5. What command proves it's done?

If you can't answer all five, the task isn't ready.

Reference it when you're stuck. Read §6 (Milestones) and §9 (Order of
Operations). You'll see immediately where you are.

Update it only when the dream changes. Not when a task completes.
This doc is the destination, not the map.
