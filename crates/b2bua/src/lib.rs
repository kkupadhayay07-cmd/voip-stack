//! # b2bua — back-to-back user agent
//!
//! Dual-leg call engine on top of `sip-core` (message layer), `sip-tx`
//! (RFC 3261 §17 transaction state machines), `sdp` (offer/answer), `rtp`
//! (adaptive jitter buffer, RTCP demux, RFC 4733) and `codecs` (full codec
//! suite). Every call gets two independent legs with their own SDP
//! negotiation; media flows through a linear-PCM bridge (16 kHz mono
//! intermediate) with per-leg decode → resample → encode, so **any codec
//! pair** from the registry can be bridged (e.g. WebRTC-style Opus ↔ PSTN
//! G.711/G.729). RFC 4733 DTMF events are relayed payload-level without
//! transcoding.
//!
//! Architecture (no shared locks; single-owner engine loop):
//!
//! ```text
//!            ┌──────────── engine loop (SIP) ────────────┐
//! INVITE ─▶ │ leg A (UAS) ───── originate ─▶ leg B (UAC) │
//!           │   plan A          plan B       plan B      │
//!           └──────┬─────────────────────────┬───────────┘
//!                  ▼                         ▼
//!            media pump A               media pump B
//!       (JB → decode → 16k → encode) (JB → decode → 16k → encode)
//! ```
//!
//! * UAS leg (A): a `sip-tx` `ServerInviteTx` drives INVITE →
//!   100/180/200(answer) with SDP answer built by
//!   `sdp::negotiate::answer_session`; retransmitted INVITEs after the 200
//!   get the cached response (§17.2.1 Completed state).
//! * UAC leg (B): a `sip-tx` `ClientInviteTx` sends the generated offer at
//!   t=0 (no dial delay); the state machine owns Timer A/B retransmission
//!   and 2xx/non-2xx ACK rules (§17.1.1).
//! * Media: one pump task per leg owning its jitter buffer, decoder and
//!   encoder; paced TX by encoder frame duration; latches the remote media
//!   address from the first valid RTP datagram if SDP routing fails (NAT).
//! * Session timers (RFC 4028, `timers` module): negotiated per leg on the
//!   initial INVITE (`422`/`Min-SE` below the floor, `Session-Expires`
//!   mirrored with an explicit `refresher`), refreshes as no-change
//!   re-INVITEs or UPDATEs, expiry tears the call down with BYEs on both
//!   legs. In-dialog re-INVITEs are answered with the cached answer when
//!   they do not change the session and `488` otherwise.
//! * Reliable provisional responses (RFC 3262, `rel100` module): the 180 is
//!   sent with `Require: 100rel` + `RSeq` when the caller supports it and is
//!   retransmitted with Timer-G backoff until the caller's `PRACK` (64·T1
//!   give-up); the final 200 to leg A waits for that PRACK (§3). Downstream,
//!   reliable 1xx from the peer are answered with `PRACK` carrying `RAck`,
//!   including retransmissions (lost-PRACK recovery), and a 421
//!   Extension Required on the dial is retried once with `Supported:
//!   100rel`.
//!
//! CDR events are emitted for every leg transition and call termination on an
//! [`tokio::sync::mpsc::UnboundedSender`].

pub mod datachan;
pub mod engine;
pub mod media;
pub mod rel100;
pub mod sdp_util;
pub mod timers;
pub mod webrtc;

use serde::{Deserialize, Serialize};
use std::time::Instant;

pub use engine::{B2bua, B2buaConfig, Route};

/// Which side of a call a leg is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Inbound (UAS) leg.
    A,
    /// Outbound (UAC) leg.
    B,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::A => "A",
            Side::B => "B",
        }
    }
}

/// CDR events emitted per call-leg transition.
#[derive(Debug, Clone)]
pub enum CdrEvent {
    /// INVITE received (A) or originated (B).
    LegInvited {
        call_id: String,
        side: Side,
        from: String,
        to: String,
        at: Instant,
    },
    /// Leg answered (200 sent/received) with the negotiated codec name.
    LegAnswered {
        call_id: String,
        side: Side,
        codec: String,
        at: Instant,
    },
    /// Leg confirmed (ACK sent/received).
    LegConfirmed {
        call_id: String,
        side: Side,
        at: Instant,
    },
    /// Leg torn down.
    LegTerminated {
        call_id: String,
        side: Side,
        reason: String,
        at: Instant,
    },
    /// Whole call ended with aggregate media stats.
    CallEnded {
        call_id: String,
        duration_ms: u64,
        frames_a_to_b: u64,
        frames_b_to_a: u64,
        /// PLC/concealment frames across both legs (same total diag reports).
        concealed: u64,
        /// The final SIP code that ended a never-answered call (404/486/
        /// 603/...). `None` for timers/cancel paths; the CDR layer maps it
        /// to a real disposition instead of hardcoding 487=Failed.
        final_code: Option<u16>,
        at: Instant,
    },
}

/// JSON-serializable CDR record (what `cdr` persists in Phase 5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdrRecord {
    pub call_id: String,
    pub side: String,
    pub event: String,
    pub detail: String,
}

impl CdrEvent {
    /// Flattens the event into a storable record.
    pub fn to_record(&self) -> CdrRecord {
        let (call_id, side, event, detail) = match self {
            CdrEvent::LegInvited {
                call_id: c,
                side: s,
                from,
                to,
                ..
            } => (
                c.clone(),
                s.as_str().into(),
                "INVITED".into(),
                format!("{from} -> {to}"),
            ),
            CdrEvent::LegAnswered {
                call_id: c,
                side: s,
                codec,
                ..
            } => (
                c.clone(),
                s.as_str().into(),
                "ANSWERED".into(),
                codec.clone(),
            ),
            CdrEvent::LegConfirmed {
                call_id: c,
                side: s,
                ..
            } => (
                c.clone(),
                s.as_str().into(),
                "CONFIRMED".into(),
                String::new(),
            ),
            CdrEvent::LegTerminated {
                call_id: c,
                side: s,
                reason,
                ..
            } => (
                c.clone(),
                s.as_str().into(),
                "TERMINATED".into(),
                reason.clone(),
            ),
            CdrEvent::CallEnded {
                call_id: c,
                duration_ms,
                frames_a_to_b,
                frames_b_to_a,
                concealed,
                ..
            } => (
                c.clone(),
                "-".to_string(),
                "CALL_ENDED".into(),
                format!(
                    "duration_ms={duration_ms} a2b={frames_a_to_b} b2a={frames_b_to_a} concealed={concealed}"
                ),
            ),
        };
        CdrRecord {
            call_id,
            side,
            event,
            detail,
        }
    }
}

/// Convenience: install a CDR printer (used by the demo binary).
pub fn log_cdr_task(mut rx: tokio::sync::mpsc::UnboundedReceiver<CdrEvent>) {
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let r = ev.to_record();
            tracing::info!(target: "cdr", call_id = %r.call_id, side = %r.side, event = %r.event, "{}", r.detail);
        }
    });
}
