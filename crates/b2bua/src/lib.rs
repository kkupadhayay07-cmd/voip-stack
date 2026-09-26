//! # b2bua — back-to-back user agent
//!
//! Dual-leg call engine on top of `sip-core` (message layer), `sdp`
//! (offer/answer), `rtp` (adaptive jitter buffer, RTCP demux, RFC 4733) and
//! `codecs` (full codec suite). Every call gets two independent legs with
//! their own SDP negotiation; media flows through a linear-PCM bridge
//! (16 kHz mono intermediate) with per-leg decode → resample → encode, so
//! **any codec pair** from the registry can be bridged (e.g. WebRTC-style
//! Opus ↔ PSTN G.711/G.729). RFC 4733 DTMF events are relayed payload-level
//! without transcoding.
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
//! * UAS leg: INVITE → 100/180/200(answer) with SDP answer built by
//!   `sdp::negotiate::answer_session`; 200 retransmission on INVITE retry.
//! * UAC leg: INVITE with generated offer, Timer A/B retransmission, ACK on 2xx.
//! * Media: one pump task per leg owning its jitter buffer, decoder and
//!   encoder; paced TX by encoder frame duration; latches the remote media
//!   address from the first valid RTP datagram if SDP routing fails (NAT).
//!
//! CDR events are emitted for every leg transition and call termination on an
//! [`tokio::sync::mpsc::UnboundedSender`].

pub mod engine;
pub mod media;
pub mod sdp_util;

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
        let mut call_id = String::new();
        let mut side = "-".to_string();
        let mut event = String::new();
        let mut detail = String::new();
        match self {
            CdrEvent::LegInvited {
                call_id: c,
                side: s,
                from,
                to,
                ..
            } => {
                call_id = c.clone();
                side = s.as_str().into();
                event = "INVITED".into();
                detail = format!("{from} -> {to}");
            }
            CdrEvent::LegAnswered {
                call_id: c,
                side: s,
                codec,
                ..
            } => {
                call_id = c.clone();
                side = s.as_str().into();
                event = "ANSWERED".into();
                detail = codec.clone();
            }
            CdrEvent::LegConfirmed {
                call_id: c,
                side: s,
                ..
            } => {
                call_id = c.clone();
                side = s.as_str().into();
                event = "CONFIRMED".into();
            }
            CdrEvent::LegTerminated {
                call_id: c,
                side: s,
                reason,
                ..
            } => {
                call_id = c.clone();
                side = s.as_str().into();
                event = "TERMINATED".into();
                detail = reason.clone();
            }
            CdrEvent::CallEnded {
                call_id: c,
                duration_ms,
                frames_a_to_b,
                frames_b_to_a,
                ..
            } => {
                call_id = c.clone();
                event = "CALL_ENDED".into();
                detail =
                    format!("duration_ms={duration_ms} a2b={frames_a_to_b} b2a={frames_b_to_a}");
            }
        }
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
