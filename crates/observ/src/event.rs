//! Event model: one correlated, serializable record per thing worth
//! observing. Every event is stamped with the SIP Call-ID (see
//! [`crate::session`]) so calls can be reconstructed from the stream alone.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Wire transport a SIP frame travelled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    Ws,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
            Transport::Ws => "wss",
        }
    }
}

/// Call direction as seen by the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Which leg of a call an event belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Leg {
    /// Caller side (b2bua UAS leg).
    A,
    /// Callee side (b2bua UAC leg).
    B,
    /// Platform-internal (SBC/proxy/registrar/CDR), not tied to one leg.
    #[default]
    Core,
    /// Unknown / not yet classified.
    Unknown,
}

impl Leg {
    pub fn as_str(self) -> &'static str {
        match self {
            Leg::A => "a",
            Leg::B => "b",
            Leg::Core => "core",
            Leg::Unknown => "?",
        }
    }
}

/// Remote endpoint of a SIP frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub addr: SocketAddr,
    pub transport: Transport,
}

/// Hex codec for byte payloads so jsonl lines stay compact.
pub mod bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(v.len() * 2);
        for b in v {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom("odd hex length"));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            out.push(
                u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom)?,
            );
        }
        Ok(out)
    }
}

/// The one interesting thing that happened. Serialized with a `kind` tag so
/// jsonl consumers can dispatch on `event.kind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// Raw SIP frame read at a socket boundary (bytes are auth-redacted and
    /// carry cleartext even for TLS/WSS — `plaintext` is always true because
    /// we tap after the handshake).
    SipRx {
        peer: Peer,
        #[serde(with = "bytes_hex")]
        bytes: Vec<u8>,
        plaintext: bool,
    },
    /// Raw SIP frame written to a socket boundary (same guarantees as SipRx).
    SipTx {
        peer: Peer,
        #[serde(with = "bytes_hex")]
        bytes: Vec<u8>,
        plaintext: bool,
    },
    /// One RTP datagram relayed by a media pump. `pump_leg` is the pump's
    /// leg (named distinctly from the outer `Event.leg` to stay unique
    /// under serde flatten).
    RtpRx {
        src: SocketAddr,
        dst: SocketAddr,
        pump_leg: Leg,
        #[serde(with = "bytes_hex")]
        bytes: Vec<u8>,
        ssrc: u32,
        seq: u16,
        pt: u8,
    },
    RtpTx {
        src: SocketAddr,
        dst: SocketAddr,
        pump_leg: Leg,
        #[serde(with = "bytes_hex")]
        bytes: Vec<u8>,
        ssrc: u32,
        seq: u16,
        pt: u8,
    },
    /// Border decision after ACL + rate limiting.
    SbcDecision {
        verdict: String,
        reason: String,
        method: String,
        source: SocketAddr,
    },
    /// Proxy forked a request to one or more targets.
    ProxyFork { method: String, targets: Vec<String> },
    /// Registrar finished an AoR lookup for a REGISTER.
    RegistrarLookup { aor: String, found: bool, bindings: usize },
    /// A b2bua leg answered (came up).
    B2buaLegUp { side: String, peer: SocketAddr, codec: String },
    /// A b2bua leg went down.
    B2buaLegDown { side: String, reason: String },
    /// Media pump started for one leg (`pump_leg`: the pump's leg).
    MediaStart { pump_leg: Leg, local: SocketAddr, rx_codec: String, tx_codec: String },
    /// Rolling media counters (every 5 s per pump).
    MediaStats {
        pump_leg: Leg,
        rx: u64,
        tx: u64,
        lost: u64,
        jitter_ms: f64,
        plc: u64,
    },
    /// Media pump stopped; final counters.
    MediaEnd {
        pump_leg: Leg,
        rx: u64,
        tx: u64,
        lost: u64,
        jitter_ms: f64,
        plc: u64,
        talk_ms: u64,
    },
    /// Voice-activity transition on caller audio.
    Vad { state: String },
    /// Speech-to-text turn boundary (emitted by STT integrations).
    Stt { state: String, text: String },
    /// LLM turn (emitted by agent integrations).
    Llm { state: String, ms: u64 },
    /// Text-to-speech playback transition.
    Tts { state: String, bytes: usize },
    /// A finished CDR record was persisted (carries the full record).
    CdrWritten { record: serde_json::Value },
}

/// One correlated event. `kind` is flattened (tagged) into the struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unix timestamp in milliseconds.
    pub ts_ms: i64,
    pub call_id: String,
    #[serde(default)]
    pub trunk: Option<String>,
    #[serde(default)]
    pub direction: Option<Direction>,
    #[serde(default)]
    pub leg: Leg,
    #[serde(flatten)]
    pub kind: EventKind,
}

impl Event {
    pub fn now(call_id: impl Into<String>, kind: EventKind) -> Self {
        Event {
            ts_ms: now_ms(),
            call_id: call_id.into(),
            trunk: None,
            direction: None,
            leg: Leg::Core,
            kind,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            EventKind::SipRx { .. } => "sip-rx",
            EventKind::SipTx { .. } => "sip-tx",
            EventKind::RtpRx { .. } => "rtp-rx",
            EventKind::RtpTx { .. } => "rtp-tx",
            EventKind::SbcDecision { .. } => "sbc-decision",
            EventKind::ProxyFork { .. } => "proxy-fork",
            EventKind::RegistrarLookup { .. } => "registrar-lookup",
            EventKind::B2buaLegUp { .. } => "b2bua-leg-up",
            EventKind::B2buaLegDown { .. } => "b2bua-leg-down",
            EventKind::MediaStart { .. } => "media-start",
            EventKind::MediaStats { .. } => "media-stats",
            EventKind::MediaEnd { .. } => "media-end",
            EventKind::Vad { .. } => "vad",
            EventKind::Stt { .. } => "stt",
            EventKind::Llm { .. } => "llm",
            EventKind::Tts { .. } => "tts",
            EventKind::CdrWritten { .. } => "cdr-written",
        }
    }
}

/// Unix time in milliseconds.
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// RFC 3339 UTC timestamp with millisecond precision.
pub fn ts_iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Parses minimal RTP fixed-header fields (ssrc, seq, payload type) from a
/// datagram without pulling in the rtp crate.
pub fn rtp_header_fields(bytes: &[u8]) -> Option<(u32, u16, u8)> {
    if bytes.len() < 12 || bytes[0] >> 6 != 2 {
        return None;
    }
    let ssrc = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let seq = u16::from_be_bytes([bytes[2], bytes[3]]);
    let pt = bytes[1] & 0x7f;
    Some((ssrc, seq, pt))
}

/// Replaces the value of every `Authorization` / `Proxy-Authorization`
/// header with `[REDACTED]`. Operates on raw serialized SIP bytes (header
/// block only; bodies are untouched) so both pcap and trace outputs are
/// safe by construction.
pub fn redact_sip(bytes: &[u8]) -> Vec<u8> {
    let split = find_header_end(bytes);
    let (head, tail) = bytes.split_at(split);
    let mut out = Vec::with_capacity(bytes.len() + 16);
    let mut pos = 0usize;
    while pos < head.len() {
        let end = head[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(head.len());
        let line = &head[pos..end];
        if is_auth_header(line) {
            let name_end = line.iter().position(|&b| b == b':').unwrap_or(line.len());
            out.extend_from_slice(&line[..=name_end]);
            out.extend_from_slice(b" [REDACTED]\r\n");
        } else {
            out.extend_from_slice(line);
        }
        pos = end;
    }
    out.extend_from_slice(tail);
    out
}

fn find_header_end(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(bytes.len())
}

fn is_auth_header(line: &[u8]) -> bool {
    let name = if let Some(colon) = line.iter().position(|&b| b == b':') {
        &line[..colon]
    } else {
        return false;
    };
    let name = String::from_utf8_lossy(name).trim().to_ascii_lowercase();
    name == "authorization" || name == "proxy-authorization"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_auth_and_proxy_auth() {
        let msg = b"INVITE sip:1000@x SIP/2.0\r\nAuthorization: Digest username=\"u\", response=\"deadbeef\"\r\nCall-ID: abc\r\nProxy-Authorization: Bearer sk-123\r\n\r\nv=0\r\n";
        let out = redact_sip(msg);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("Authorization: [REDACTED]"), "{s}");
        assert!(s.contains("Proxy-Authorization: [REDACTED]"), "{s}");
        assert!(!s.contains("deadbeef") && !s.contains("sk-123"));
        assert!(s.contains("Call-ID: abc"));
        assert!(s.contains("v=0"), "body preserved");
        // lowercase header name variant
        let out2 = redact_sip(b"REGISTER sip:x SIP/2.0\r\nauthorization: Basic Zm9v\r\n\r\n");
        assert!(String::from_utf8_lossy(&out2).contains("[REDACTED]"));
    }

    #[test]
    fn rtp_fields_roundtrip() {
        let mut p = vec![0x80, 0x00, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4];
        p[2..4].copy_from_slice(&5_000u16.to_be_bytes());
        let (ssrc, seq, pt) = rtp_header_fields(&p).unwrap();
        assert_eq!((ssrc, seq, pt), (0x01020304, 5_000, 0));
        assert!(rtp_header_fields(&[0u8; 4]).is_none());
    }

    #[test]
    fn event_json_roundtrip() {
        let ev = Event::now(
            "c-1",
            EventKind::SipRx {
                peer: Peer {
                    addr: "127.0.0.1:5060".parse().unwrap(),
                    transport: Transport::Udp,
                },
                bytes: b"REGISTER\r\n\r\n".to_vec(),
                plaintext: true,
            },
        );
        let line = serde_json::to_string(&ev).unwrap();
        assert!(line.contains("\"kind\":\"sip_rx\""), "{line}");
        assert!(line.contains("\"bytes\":\"52454749535445520d0a0d0a\""), "{line}");
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(back.call_id, "c-1");
        assert!(matches!(back.kind, EventKind::SipRx { plaintext: true, .. }));
    }
}
