//! [RFC 8832] Data Channel Establishment Protocol (DCEP).
//!
//! DCEP messages ride as SCTP user data on the channel's stream:
//! `DATA_CHANNEL_OPEN` (PPID 51) and `DATA_CHANNEL_ACK` (PPID 50, a single
//! 0x02 byte). The channel type packs the reliability class (2 bits) and the
//! out-of-order flag (high bit):
//!
//! | type  | class                              | reliability param   |
//! |-------|------------------------------------|---------------------|
//! | 0x00  | reliable                           | ignored (0)         |
//! | 0x01  | partial: max retransmits           | retransmit count    |
//! | 0x02  | partial: max packet lifetime       | lifetime in ms      |
//! | +0x80 | same class, unordered              | same                |
//!
//! Stream-id parity (§5.1/§6): the side acting as the DTLS *client* (the
//! association initiator in the RFC 8261 wiring) opens channels on EVEN
//! stream ids (0, 2, …), the DTLS server on ODD ids (1, 3, …). The OPEN MUST
//! be the first user message on its stream.
//!
//! [RFC 8832]: https://datatracker.ietf.org/doc/html/rfc8832

use crate::wire::SctpError;

/// RFC 8832 §5.1: BOTH DCEP messages (DATA_CHANNEL_OPEN and
/// DATA_CHANNEL_ACK) ride PPID 50 (`WEBRTC_DCEP`). Keeping the two
/// historical names is deliberate — call sites document intent — but the
/// value is the spec value for both; a real peer dispatches on 50 and
/// ignores anything else (a PPID-51 OPEN silently vanishes on the wire).
pub const PPID_DCEP_OPEN: u32 = PPID_DCEP;
pub const PPID_DCEP_ACK: u32 = PPID_DCEP;

/// THE DCEP PPID (RFC 8832 §5.1, `WEBRTC_DCEP`).
pub const PPID_DCEP: u32 = 50;

pub const MSG_OPEN: u8 = 0x03;
pub const MSG_ACK: u8 = 0x02;

/// Parsed DATA_CHANNEL_OPEN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChannelOpen {
    pub label: String,
    pub protocol: String,
    pub channel_type: ChannelType,
    /// The channel "priority" field — sent verbatim, not interpreted (the
    /// current RFC 8832 leaves it to the application).
    pub priority: u16,
}

/// Channel type: reliability class + ordering, exactly as it appears on the
/// wire (2 classes × ordered/unordered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    Reliable,
    MaxRetransmits(u32),
    MaxLifetimeMs(u32),
    ReliableUnordered,
    MaxRetransmitsUnordered(u32),
    MaxLifetimeUnorderedMs(u32),
}

impl ChannelType {
    pub fn unordered(self) -> bool {
        matches!(
            self,
            ChannelType::ReliableUnordered
                | ChannelType::MaxRetransmitsUnordered(_)
                | ChannelType::MaxLifetimeUnorderedMs(_)
        )
    }

    pub fn wire_type(self) -> u8 {
        match self {
            ChannelType::Reliable => 0x00,
            ChannelType::MaxRetransmits(_) => 0x01,
            ChannelType::MaxLifetimeMs(_) => 0x02,
            ChannelType::ReliableUnordered => 0x80,
            ChannelType::MaxRetransmitsUnordered(_) => 0x81,
            ChannelType::MaxLifetimeUnorderedMs(_) => 0x82,
        }
    }

    /// The 32-bit reliability parameter (ignored for the reliable class).
    pub fn reliability_param(self) -> u32 {
        match self {
            ChannelType::Reliable | ChannelType::ReliableUnordered => 0,
            ChannelType::MaxRetransmits(n) | ChannelType::MaxRetransmitsUnordered(n) => n,
            ChannelType::MaxLifetimeMs(ms) | ChannelType::MaxLifetimeUnorderedMs(ms) => ms,
        }
    }

    pub fn from_wire(wire_type: u8, reliability_param: u32) -> Option<Self> {
        match wire_type {
            0x00 => Some(ChannelType::Reliable),
            0x01 => Some(ChannelType::MaxRetransmits(reliability_param)),
            0x02 => Some(ChannelType::MaxLifetimeMs(reliability_param)),
            0x80 => Some(ChannelType::ReliableUnordered),
            0x81 => Some(ChannelType::MaxRetransmitsUnordered(reliability_param)),
            0x82 => Some(ChannelType::MaxLifetimeUnorderedMs(reliability_param)),
            _ => None,
        }
    }
}

/// Encode a DATA_CHANNEL_OPEN message (label/protocol are UTF-8 per §5.2;
/// both may be empty).
pub fn encode_open(msg: &DataChannelOpen, out: &mut Vec<u8>) {
    out.push(MSG_OPEN);
    out.push(msg.channel_type.wire_type());
    out.extend_from_slice(&msg.priority.to_be_bytes());
    out.extend_from_slice(&msg.channel_type.reliability_param().to_be_bytes());
    out.extend_from_slice(&(msg.label.len() as u16).to_be_bytes());
    out.extend_from_slice(&(msg.protocol.len() as u16).to_be_bytes());
    out.extend_from_slice(msg.label.as_bytes());
    out.extend_from_slice(msg.protocol.as_bytes());
}

/// Encode the one-byte DATA_CHANNEL_ACK.
pub fn encode_ack(out: &mut Vec<u8>) {
    out.push(MSG_ACK);
}

/// Parse a DCEP message. `Ok(None)` for the ACK (no fields); an error for
/// anything malformed or unknown — per §5.1 an unknown message type is a
/// protocol violation.
pub fn parse(buf: &[u8]) -> Result<Option<DataChannelOpen>, SctpError> {
    if buf.is_empty() {
        return Err(SctpError::BadChunk("DCEP message empty"));
    }
    match buf[0] {
        // §5: an ACK is EXACTLY one byte — a longer 0x02-prefixed buffer is
        // garbage that would otherwise forge a channel acknowledgment.
        MSG_ACK if buf.len() == 1 => Ok(None),
        MSG_ACK => Err(SctpError::BadChunk("DCEP ACK with trailing bytes")),
        MSG_OPEN => {
            if buf.len() < 12 {
                return Err(SctpError::BadChunk("DCEP OPEN < 12 bytes"));
            }
            let wire_type = buf[1];
            let priority = u16::from_be_bytes([buf[2], buf[3]]);
            let rel = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let label_len = u16::from_be_bytes([buf[8], buf[9]]) as usize;
            let proto_len = u16::from_be_bytes([buf[10], buf[11]]) as usize;
            if buf.len() < 12 + label_len + proto_len {
                return Err(SctpError::BadChunk("DCEP OPEN label/protocol truncated"));
            }
            if buf.len() > 12 + label_len + proto_len {
                return Err(SctpError::BadChunk("DCEP OPEN with trailing bytes"));
            }
            let label = String::from_utf8_lossy(&buf[12..12 + label_len]).into_owned();
            let protocol =
                String::from_utf8_lossy(&buf[12 + label_len..12 + label_len + proto_len])
                    .into_owned();
            let channel_type = ChannelType::from_wire(wire_type, rel)
                .ok_or(SctpError::BadChunk("unknown DCEP channel type"))?;
            Ok(Some(DataChannelOpen {
                label,
                protocol,
                channel_type,
                priority,
            }))
        }
        _ => Err(SctpError::BadChunk("unknown DCEP message type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built reliable ordered open, byte by byte: type 0x03, channel
    /// type 0x00, priority 0, reliability param 0, label "Chat" (4 bytes),
    /// protocol "http://example.com/protocol" (27 bytes). Pins the field
    /// order and widths of §5.1.
    #[test]
    fn rfc8832_reliable_open_layout() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&[
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 27,
        ]);
        wire.extend_from_slice(b"Chat");
        wire.extend_from_slice(b"http://example.com/protocol");
        assert_eq!(wire.len(), 12 + 4 + 27);

        let parsed = parse(&wire).unwrap().expect("OPEN");
        assert_eq!(parsed.label, "Chat");
        assert_eq!(parsed.protocol, "http://example.com/protocol");
        assert_eq!(parsed.channel_type, ChannelType::Reliable);
        assert_eq!(parsed.priority, 0);
    }

    /// Hand-built partial-reliability unordered open: type 0x81,
    /// maxRetransmits = 3, empty label/protocol.
    #[test]
    fn partial_reliable_unordered_open() {
        let wire: &[u8] = &[
            0x03, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = parse(wire).unwrap().expect("OPEN");
        assert_eq!(parsed.channel_type, ChannelType::MaxRetransmitsUnordered(3));
        assert!(parsed.channel_type.unordered());
        assert_eq!(parsed.channel_type.wire_type(), 0x81);
        assert_eq!(parsed.channel_type.reliability_param(), 3);
    }

    #[test]
    fn ack_is_a_single_0x02_byte() {
        let mut out = Vec::new();
        encode_ack(&mut out);
        assert_eq!(out, vec![0x02]);
        assert!(parse(&out).unwrap().is_none());
    }

    #[test]
    fn encode_open_roundtrip_with_unicode_label() {
        let msg = DataChannelOpen {
            label: "канал-1".into(),
            protocol: " RFC-8835 ".into(),
            channel_type: ChannelType::MaxLifetimeMs(7777),
            priority: 9,
        };
        let mut out = Vec::new();
        encode_open(&msg, &mut out);
        let parsed = parse(&out).unwrap().expect("OPEN");
        assert_eq!(parsed, msg);
        assert_eq!(parsed.channel_type, ChannelType::MaxLifetimeMs(7777));
        assert_eq!(parsed.channel_type.wire_type(), 0x02);
    }

    #[test]
    fn unknown_message_type_and_truncation_rejected() {
        assert!(parse(&[0x99]).is_err());
        assert!(parse(&[]).is_err());
        assert!(parse(&[0x03, 0x00, 0x00]).is_err());
        // Label length beyond the buffer.
        let mut w = vec![0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0];
        w.extend_from_slice(b"short");
        assert!(parse(&w).is_err());
        // Unknown channel type.
        let bad = [0x03, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse(&bad).is_err());
    }
}
