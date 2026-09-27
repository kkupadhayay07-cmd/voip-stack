//! RTP packet layer (RFC 3550 §5) with RFC 8285 header extensions.

use bytes::BufMut;
use bytes::{Bytes, BytesMut};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtpError {
    TooShort { need: usize, got: usize },
    BadVersion(u8),
    BadExtensionLength,
    Truncated,
    BadCsrcCount(u8),
}

impl fmt::Display for RtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtpError::TooShort { need, got } => {
                write!(f, "buffer too short: need {} bytes, got {}", need, got)
            }
            RtpError::BadVersion(v) => write!(f, "unsupported RTP version {}", v),
            RtpError::BadExtensionLength => write!(f, "bad extension length"),
            RtpError::Truncated => write!(f, "truncated packet"),
            RtpError::BadCsrcCount(c) => write!(f, "bad CSRC count {}", c),
        }
    }
}

impl std::error::Error for RtpError {}

/// RFC 8285 generic header extension block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpExtension {
    /// Extension profile (0xbede for one-byte, 0x1000.. for two-byte).
    pub profile: u16,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    pub padding: bool,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    pub header: RtpHeader,
    pub extension: Option<RtpExtension>,
    pub payload: Bytes,
    /// Set when padding bytes were present at the end of the payload.
    pub padding_len: u8,
}

impl RtpPacket {
    pub fn new(pt: u8, seq: u16, ts: u32, ssrc: u32, marker: bool, payload: Bytes) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                padding: false,
                marker,
                payload_type: pt,
                sequence: seq,
                timestamp: ts,
                ssrc,
                csrcs: Vec::new(),
            },
            extension: None,
            payload,
            padding_len: 0,
        }
    }

    /// Parse an RTP packet from `buf`.
    pub fn parse(buf: &[u8]) -> Result<RtpPacket, RtpError> {
        if buf.len() < 12 {
            return Err(RtpError::TooShort {
                need: 12,
                got: buf.len(),
            });
        }
        let b0 = buf[0];
        let version = b0 >> 6;
        if version != 2 {
            return Err(RtpError::BadVersion(version));
        }
        let padding = b0 & 0x20 != 0;
        let has_ext = b0 & 0x10 != 0;
        let cc = (b0 & 0x0F) as usize;
        let b1 = buf[1];
        let marker = b1 & 0x80 != 0;
        let payload_type = b1 & 0x7F;
        let sequence = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let mut off = 12usize;
        if buf.len() < off + cc * 4 {
            return Err(RtpError::BadCsrcCount(cc as u8));
        }
        let mut csrcs = Vec::with_capacity(cc);
        for i in 0..cc {
            csrcs.push(u32::from_be_bytes([
                buf[off + i * 4],
                buf[off + i * 4 + 1],
                buf[off + i * 4 + 2],
                buf[off + i * 4 + 3],
            ]));
        }
        off += cc * 4;

        let mut extension = None;
        if has_ext {
            if buf.len() < off + 4 {
                return Err(RtpError::Truncated);
            }
            let profile = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let words = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            let ext_len = words * 4;
            off += 4;
            if buf.len() < off + ext_len {
                return Err(RtpError::BadExtensionLength);
            }
            extension = Some(RtpExtension {
                profile,
                data: Bytes::copy_from_slice(&buf[off..off + ext_len]),
            });
            off += ext_len;
        }

        let mut payload_end = buf.len();
        let mut padding_len = 0u8;
        if padding {
            if buf.is_empty() {
                return Err(RtpError::Truncated);
            }
            let p = buf[buf.len() - 1];
            if p == 0 || p as usize > buf.len() {
                return Err(RtpError::Truncated);
            }
            padding_len = p;
            payload_end -= p as usize;
        }
        if payload_end < off {
            return Err(RtpError::Truncated);
        }

        Ok(RtpPacket {
            header: RtpHeader {
                padding,
                marker,
                payload_type,
                sequence,
                timestamp,
                ssrc,
                csrcs,
            },
            extension,
            payload: Bytes::copy_from_slice(&buf[off..payload_end]),
            padding_len,
        })
    }

    /// Serialize into `out`.
    pub fn encode_into(&self, out: &mut BytesMut) {
        let cc = self.header.csrcs.len().min(15);
        let b0 = 0x80u8
            | if self.header.padding { 0x20 } else { 0 }
            | if self.extension.is_some() { 0x10 } else { 0 }
            | cc as u8;
        out.reserve(12 + cc * 4 + self.payload.len() + 16);
        out.put_u8(b0);
        out.put_u8(if self.header.marker { 0x80 } else { 0 } | (self.header.payload_type & 0x7F));
        out.put_u16(self.header.sequence);
        out.put_u32(self.header.timestamp);
        out.put_u32(self.header.ssrc);
        for c in self.header.csrcs.iter().take(cc) {
            out.put_u32(*c);
        }
        if let Some(ext) = &self.extension {
            out.put_u16(ext.profile);
            let words = ext.data.len().div_ceil(4);
            out.put_u16(words as u16);
            out.extend_from_slice(&ext.data);
            let pad = words * 4 - ext.data.len();
            out.put_bytes(0, pad);
        }
        out.extend_from_slice(&self.payload);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.payload.len() + 16);
        self.encode_into(&mut out);
        out.to_vec()
    }

    pub fn sequence(&self) -> u16 {
        self.header.sequence
    }

    pub fn timestamp(&self) -> u32 {
        self.header.timestamp
    }

    pub fn ssrc(&self) -> u32 {
        self.header.ssrc
    }

    pub fn payload_type(&self) -> u8 {
        self.header.payload_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let mut p = RtpPacket::new(0, 1234, 160, 0xDEADBEEF, true, Bytes::from_static(b"hello"));
        p.header.csrcs = vec![1, 2, 3];
        let enc = p.encode();
        let q = RtpPacket::parse(&enc).unwrap();
        assert_eq!(q.payload.as_ref(), b"hello");
        assert_eq!(q.header.sequence, 1234);
        assert_eq!(q.header.timestamp, 160);
        assert_eq!(q.header.ssrc, 0xDEADBEEF);
        assert!(q.header.marker);
        assert_eq!(q.header.payload_type, 0);
        assert_eq!(q.header.csrcs, vec![1, 2, 3]);
    }

    #[test]
    fn roundtrip_with_extension() {
        let mut p = RtpPacket::new(111, 5, 960, 42, false, Bytes::from_static(b"x"));
        p.extension = Some(RtpExtension {
            profile: 0xBEBE,
            data: Bytes::from_static(b"abcd"),
        });
        let q = RtpPacket::parse(&p.encode()).unwrap();
        assert_eq!(q.extension.unwrap().data.as_ref(), b"abcd");
        assert_eq!(q.payload.as_ref(), b"x");
    }

    #[test]
    fn rejects_garbage() {
        assert!(RtpPacket::parse(&[]).is_err());
        assert!(RtpPacket::parse(&[0u8; 11]).is_err());
        // version 1
        let mut v1 = vec![0x40u8, 0, 0, 1];
        v1.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            RtpPacket::parse(&v1),
            Err(RtpError::BadVersion(1))
        ));
        // bad csrc count (declares 15 but buffer too small)
        let mut bad = vec![0x8Fu8, 0, 0, 1];
        bad.extend_from_slice(&[0u8; 8]);
        assert!(RtpPacket::parse(&bad).is_err());
        // truncated extension
        let mut te = vec![0x90u8, 0, 0, 1];
        te.extend_from_slice(&[0u8; 8]);
        te.extend_from_slice(&[0xBE, 0xDE, 0x00, 0xFF]); // claims 255 words
        assert!(RtpPacket::parse(&te).is_err());
    }

    #[test]
    fn padding_handled() {
        let mut raw = vec![0xA0u8, 0, 0, 1]; // padding bit set, no ext
        raw.extend_from_slice(&[0u8; 8]);
        raw.extend_from_slice(b"ab");
        raw.extend_from_slice(&[0, 0, 0]);
        raw.push(4); // final octet = padding count including itself
        let p = RtpPacket::parse(&raw).unwrap();
        assert_eq!(p.payload.as_ref(), b"ab");
        assert_eq!(p.padding_len, 4);
    }

    #[test]
    fn encode_decode_speed_smoke() {
        let p = RtpPacket::new(0, 1, 2, 3, false, Bytes::from_static(&[0u8; 160]));
        let enc = p.encode();
        assert_eq!(RtpPacket::parse(&enc).unwrap().header.ssrc, 3);
    }
}
