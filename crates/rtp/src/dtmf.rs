//! RFC 4733 telephone-event (DTMF) payload encode/decode.

use crate::packet::RtpError;

/// A decoded RFC 4733 event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfEvent {
    /// Event code (0-9, * = 10, # = 11, A-D = 12-15).
    pub event: u8,
    /// End-of-event flag.
    pub end: bool,
    /// Reserved bit (must be ignored).
    pub reserved: bool,
    /// Power level in dBm0 (0..=-63 as unsigned bias).
    pub volume: u8,
    /// Event duration in timestamp units.
    pub duration: u16,
}

/// Map a digit character to its RFC 4733 event code.
pub fn encode_digit(c: char) -> Option<u8> {
    Some(match c {
        '0'..='9' => c as u8 - b'0',
        '*' => 10,
        '#' => 11,
        'A' | 'a' => 12,
        'B' | 'b' => 13,
        'C' | 'c' => 14,
        'D' | 'd' => 15,
        _ => return None,
    })
}

/// Map an RFC 4733 event code to its digit character.
pub fn decode_digit(code: u8) -> Option<char> {
    Some(match code {
        0..=9 => (b'0' + code) as char,
        10 => '*',
        11 => '#',
        12 => 'A',
        13 => 'B',
        14 => 'C',
        15 => 'D',
        _ => return None,
    })
}

/// Parse a 4-byte RFC 4733 event payload.
pub fn parse_event(payload: &[u8]) -> Result<DtmfEvent, RtpError> {
    if payload.len() < 4 {
        return Err(RtpError::TooShort {
            need: 4,
            got: payload.len(),
        });
    }
    Ok(DtmfEvent {
        event: payload[0],
        end: payload[1] & 0x80 != 0,
        reserved: payload[1] & 0x40 != 0,
        volume: payload[1] & 0x3F,
        duration: u16::from_be_bytes([payload[2], payload[3]]),
    })
}

/// Encode an event into the 4-byte RFC 4733 payload.
pub fn encode_event(e: &DtmfEvent) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[0] = e.event;
    out[1] = if e.end { 0x80 } else { 0 } | if e.reserved { 0x40 } else { 0 } | (e.volume & 0x3F);
    out[2..4].copy_from_slice(&e.duration.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_mapping() {
        assert_eq!(encode_digit('0'), Some(0));
        assert_eq!(encode_digit('9'), Some(9));
        assert_eq!(encode_digit('*'), Some(10));
        assert_eq!(encode_digit('#'), Some(11));
        assert_eq!(encode_digit('D'), Some(15));
        assert_eq!(encode_digit('d'), Some(15));
        assert_eq!(encode_digit('x'), None);
        for c in "0123456789*#ABCD".chars() {
            let e = encode_digit(c).unwrap();
            assert_eq!(decode_digit(e).unwrap().to_ascii_uppercase(), c);
        }
    }

    #[test]
    fn event_roundtrip() {
        let ev = DtmfEvent {
            event: 5,
            end: true,
            reserved: false,
            volume: 10,
            duration: 800, // 100ms at 8kHz
        };
        let bytes = encode_event(&ev);
        assert_eq!(bytes.len(), 4);
        let parsed = parse_event(&bytes).unwrap();
        assert_eq!(parsed, ev);
    }

    #[test]
    fn rejects_short_payload() {
        assert!(parse_event(&[0, 1, 2]).is_err());
        assert!(parse_event(&[]).is_err());
    }

    #[test]
    fn end_flag_and_volume_range() {
        let ev = DtmfEvent {
            event: 11,
            end: false,
            reserved: false,
            volume: 63,
            duration: 1,
        };
        let parsed = parse_event(&encode_event(&ev)).unwrap();
        assert!(!parsed.end);
        assert_eq!(parsed.volume, 63);
        let ev_end = DtmfEvent { end: true, ..ev };
        assert!(parse_event(&encode_event(&ev_end)).unwrap().end);
    }
}
