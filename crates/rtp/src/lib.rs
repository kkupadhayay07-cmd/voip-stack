//! # rtp
//!
//! Native RTP/RTCP stack:
//! - [RFC 3550]/[RFC 3551] packet parse/serialize (RTP + RTCP SR/RR/SDES/BYE/APP, generic feedback)
//! - Adaptive jitter buffer with virtual-time API, RFC 3550 jitter estimation,
//!   SSRC probation, sequence wrap handling and pluggable PLC
//! - Loss recovery: [RFC 4585] Generic NACK generation/parsing and
//!   [RFC 4588] RTX retransmission streams (pool, packetizer, depacketizer)
//! - transport-cc congestion feedback (RTPFB FMT 15, draft-holmerberg:
//!   receiver monitor + sender tracker, libwebrtc-compatible wire form)
//! - [RFC 4733] telephone-event (DTMF)
//! - Native G.711 μ-law / A-law codecs
//! - [RFC 5761] RTP/RTCP demultiplexing helper
//!
//! [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550
//! [RFC 3551]: https://datatracker.ietf.org/doc/html/rfc3551
//! [RFC 4585]: https://datatracker.ietf.org/doc/html/rfc4585
//! [RFC 4588]: https://datatracker.ietf.org/doc/html/rfc4588
//! [RFC 4733]: https://datatracker.ietf.org/doc/html/rfc4733
//! [RFC 5761]: https://datatracker.ietf.org/doc/html/rfc5761

pub mod dtmf;
pub mod g711;
pub mod jitter;
pub mod nack;
pub mod packet;
pub mod rtcp;
pub mod twcc;

pub use dtmf::{decode_digit, encode_digit, DtmfEvent};
pub use g711::{pcma_decode, pcma_encode, pcmu_decode, pcmu_encode};
pub use jitter::{JbStats, JitterBuffer, JitterConfig, PushResult, RtpFrame};
pub use nack::{
    nack_fci, nack_packet, nack_seqs, osn_of, parse_nack_fci, GenericNack, NackConfig, NackTracker,
    RtxDepacketizer, RtxPool, RtxStream,
};
pub use packet::{RtpError, RtpExtension, RtpHeader, RtpPacket};
pub use rtcp::{parse_compound, ReportBlock, RtcpPacket, SdesChunk, SdesType, SenderInfo};
pub use twcc::{
    parse_twcc, twcc_fci, twcc_packet, TwccEntry, TwccFeedback, TwccPacketResult, TwccReport,
    TwccRxMonitor, TwccSendTracker, DELTA_SCALE_US, FMT_TWCC, REF_SCALE_MS,
};

/// RFC 5761 §4: does this datagram look like RTCP rather than RTP?
///
/// The classic 192–223 payload-type range with version 2 identifies RTCP so
/// non-muxed sockets can demux safely. Deliberately NO 4-byte length
/// alignment check: RFC 3711 §3.4 SRTCP appends the E flag / SRTCP index
/// (4 bytes) plus a 10- or 16-byte authentication tag after the RTCP
/// compound, so an encrypted packet's total length is generally NOT a
/// multiple of 4 — requiring alignment here misrouted every AES-CM SRTCP
/// datagram into the RTP path.
pub fn looks_like_rtcp(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let pt = buf[1];
    if (192..=223).contains(&pt) {
        // Classic RTCP range; verify version 2 only (see above for why the
        // historic %4 alignment probe must not reject).
        return buf[0] >> 6 == 2;
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

    #[test]
    fn srtcp_with_auth_trailer_still_detected() {
        // RFC 3711 §3.4: SRTCP = RTCP compound + 4-byte E/index + auth tag.
        // With a 10-byte tag the total is not a multiple of 4 — the old %4
        // probe misrouted this into the RTP path.
        let mut srtcp = vec![0x81u8, 200, 0, 6];
        srtcp.extend_from_slice(&[0u8; 28]); // SR body
        srtcp.extend_from_slice(&[0u8; 4]); // E flag + SRTCP index
        srtcp.extend_from_slice(&[0u8; 10]); // HMAC-SHA1 auth tag
        assert_eq!(srtcp.len() % 4, 2, "encrypted trailer breaks alignment");
        assert!(looks_like_rtcp(&srtcp));
        // Version must still be checked: a v0/v1 packet in the PT range is
        // not RTCP.
        let mut v1 = srtcp.clone();
        v1[0] = 0x41;
        assert!(!looks_like_rtcp(&v1));
    }
}
