//! # rtp
//!
//! Native RTP/RTCP stack:
//! - [RFC 3550]/[RFC 3551] packet parse/serialize (RTP + RTCP SR/RR/SDES/BYE/APP, generic feedback)
//! - Adaptive jitter buffer with virtual-time API, RFC 3550 jitter estimation,
//!   SSRC probation, sequence wrap handling and pluggable PLC
//! - [RFC 4733] telephone-event (DTMF)
//! - Native G.711 μ-law / A-law codecs
//! - [RFC 5761] RTP/RTCP demultiplexing helper
//!
//! [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550
//! [RFC 3551]: https://datatracker.ietf.org/doc/html/rfc3551
//! [RFC 4733]: https://datatracker.ietf.org/doc/html/rfc4733
//! [RFC 5761]: https://datatracker.ietf.org/doc/html/rfc5761

pub mod dtmf;
pub mod g711;
pub mod jitter;
pub mod packet;
pub mod rtcp;

pub use dtmf::{decode_digit, encode_digit, DtmfEvent};
pub use g711::{pcma_decode, pcma_encode, pcmu_decode, pcmu_encode};
pub use jitter::{JbStats, JitterBuffer, JitterConfig, PushResult, RtpFrame};
pub use packet::{RtpError, RtpExtension, RtpHeader, RtpPacket};
pub use rtcp::{parse_compound, ReportBlock, RtcpPacket, SdesChunk, SdesType, SenderInfo};

/// RFC 5761 §4: does this datagram look like RTCP rather than RTP?
///
/// Applies the reduced-size (mux) rules: payload types 64–95 identify RTCP
/// when muxing is negotiated; the classic 192–223 range is also matched so
/// non-muxed sockets can demux safely.
pub fn looks_like_rtcp(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let pt = buf[1];
    if (192..=223).contains(&pt) {
        // Classic RTCP range; also verify version 2 and 4-byte alignment.
        return buf[0] >> 6 == 2 && buf.len().is_multiple_of(4);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demux_rtp_vs_rtcp() {
        // minimal SR
        let mut sr = vec![0x81u8, 200, 0, 6];
        sr.extend_from_slice(&[0u8; 28]);
        assert!(looks_like_rtcp(&sr));
        // minimal RTP
        let mut rtp = vec![0x80u8, 0, 0, 1];
        rtp.extend_from_slice(&[0u8; 8]);
        assert!(!looks_like_rtcp(&rtp));
        assert!(!looks_like_rtcp(&[0x80]));
        assert!(!looks_like_rtcp(&[]));
    }
}
