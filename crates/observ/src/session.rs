//! CallSession: stamps events with call context (call_id, trunk, direction,
//! leg) and publishes them on the global bus. Also hosts the socket-boundary
//! tap helpers every integration hook calls — each hook is therefore a
//! single short line in the producing crate.

use crate::bus;
use crate::event::{redact_sip, rtp_header_fields, Event, EventKind, Leg, Peer, Transport};
use std::net::SocketAddr;

/// Per-call emission context. Cloneable; every clone emits for the same
/// call.
#[derive(Debug, Clone)]
pub struct CallSession {
    pub(crate) call_id: String,
    pub(crate) trunk: Option<String>,
    pub(crate) direction: Option<crate::event::Direction>,
    pub(crate) leg: Leg,
}

impl CallSession {
    pub fn new(
        call_id: impl Into<String>,
        trunk: Option<&str>,
        direction: Option<crate::event::Direction>,
    ) -> Self {
        CallSession {
            call_id: call_id.into(),
            trunk: trunk.map(str::to_string),
            direction,
            leg: Leg::Core,
        }
    }

    /// A session for call-less producers (events still flow, keyed by "").
    pub fn detached() -> Self {
        CallSession {
            call_id: String::new(),
            trunk: None,
            direction: None,
            leg: Leg::Unknown,
        }
    }

    pub fn with_leg(mut self, leg: Leg) -> Self {
        self.leg = leg;
        self
    }

    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn leg(&self) -> Leg {
        self.leg
    }

    /// Emits one event for this call on the global bus.
    pub fn emit(&self, kind: EventKind) {
        bus::emit(Event {
            ts_ms: crate::event::now_ms(),
            call_id: self.call_id.clone(),
            trunk: self.trunk.clone(),
            direction: self.direction,
            leg: self.leg,
            kind,
        });
    }
}

/// Extracts the Call-ID header value from raw serialized SIP bytes (header
/// block scan; no parser dependency).
pub fn call_id_of_bytes(bytes: &[u8]) -> Option<String> {
    let head_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(bytes.len());
    let head = &bytes[..head_end];
    let mut pos = 0usize;
    while pos < head.len() {
        let end = head[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(head.len());
        let line = &head[pos..end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon]).trim().to_ascii_lowercase();
            if name == "call-id" {
                let val = String::from_utf8_lossy(&line[colon + 1..])
                    .trim()
                    .to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
        pos = end;
    }
    None
}

/// Socket-boundary tap: emits SipRx/SipTx with auth-redacted bytes. Safe to
/// call anywhere; no-ops when no bus is installed.
pub fn sip_tap(bytes: &[u8], peer: SocketAddr, transport: Transport, rx: bool) {
    if bus::global().is_none() {
        return;
    }
    let redacted = redact_sip(bytes);
    let call_id = call_id_of_bytes(&redacted).unwrap_or_default();
    let peer = Peer { addr: peer, transport };
    bus::emit(Event {
        ts_ms: crate::event::now_ms(),
        call_id,
        trunk: None,
        direction: None,
        leg: Leg::Core,
        kind: if rx {
            EventKind::SipRx { peer, bytes: redacted, plaintext: true }
        } else {
            EventKind::SipTx { peer, bytes: redacted, plaintext: true }
        },
    });
}

/// Media tap: emits RtpRx/RtpTx for one datagram (valid RTP only).
#[allow(clippy::too_many_arguments)]
pub fn rtp_tap(
    call_id: &str,
    leg: Leg,
    src: SocketAddr,
    dst: SocketAddr,
    bytes: &[u8],
    rx: bool,
) {
    if bus::global().is_none() {
        return;
    }
    let Some((ssrc, seq, pt)) = rtp_header_fields(bytes) else {
        return;
    };
    bus::emit(Event {
        ts_ms: crate::event::now_ms(),
        call_id: call_id.to_string(),
        trunk: None,
        direction: None,
        leg,
        kind: if rx {
            EventKind::RtpRx { src, dst, pump_leg: leg, bytes: bytes.to_vec(), ssrc, seq, pt }
        } else {
            EventKind::RtpTx { src, dst, pump_leg: leg, bytes: bytes.to_vec(), ssrc, seq, pt }
        },
    });
}

/// Emits one call-contextual event via the global bus (for hooks that know
/// the call id but hold no session, e.g. SBC/proxy/registrar).
pub fn emit_for(call_id: &str, kind: EventKind) {
    if bus::global().is_none() {
        return;
    }
    bus::emit(Event::now(call_id.to_string(), kind));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_call_id_from_bytes() {
        let msg = b"INVITE sip:1000@x SIP/2.0\r\nVia: SIP/2.0/UDP a\r\nCall-ID:  demo-42 \r\nFrom: <sip:a@x>\r\n\r\n";
        assert_eq!(call_id_of_bytes(msg).as_deref(), Some("demo-42"));
        assert_eq!(call_id_of_bytes(b"OPTIONS sip:x SIP/2.0\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn taps_are_noops_without_global_bus() {
        // No install_global in this process (tests run in parallel in one
        // process, so the global may exist from another test — either way
        // these must not panic).
        sip_tap(b"OPTIONS sip:x SIP/2.0\r\n\r\n", "127.0.0.1:1".parse().unwrap(), Transport::Udp, true);
        rtp_tap("c", Leg::A, "127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap(), &[0u8; 12], true);
        emit_for("c", EventKind::Vad { state: "s".into() });
    }
}
