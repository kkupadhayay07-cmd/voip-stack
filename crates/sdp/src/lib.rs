//! # sdp
//!
//! Native SDP ([RFC 4566]/[RFC 8866]) parser, serializer and
//! [RFC 3264] offer/answer negotiation engine.
//!
//! The crate is dependency-free and fuzz-safe: every parser is
//! hand-written, bounds-checked and returns positioned errors.
//!
//! [RFC 4566]: https://datatracker.ietf.org/doc/html/rfc4566
//! [RFC 8866]: https://datatracker.ietf.org/doc/html/rfc8866
//! [RFC 3264]: https://datatracker.ietf.org/doc/html/rfc3264

pub mod negotiate;
pub mod parse;
pub mod types;

pub use negotiate::{
    answer_direction, answer_session, stream_plans, CodecCap, IceCreds, MediaCaps,
    NegotiateError, StreamPlan,
};
pub use parse::{parse, SdpError, SdpErrorKind};
pub use types::{
    Attribute, Bandwidth, BundleGroup, Connection, Direction, ExtMap, Fingerprint,
    MediaDescription, Origin, RtpMap, Session, SetupRole, SsrcInfo, Timing,
};

/// Static payload type table from [RFC 3551] §6 (audio/video defaults).
///
/// [RFC 3551]: https://datatracker.ietf.org/doc/html/rfc3551#section-6
pub fn static_rtpmap(pt: u8) -> Option<(&'static str, u32)> {
    Some(match pt {
        0 => ("PCMU", 8000),
        3 => ("GSM", 8000),
        4 => ("G723", 8000),
        5 => ("DVI4", 8000),
        6 => ("DVI4", 16000),
        7 => ("LPC", 8000),
        8 => ("PCMA", 8000),
        9 => ("G722", 8000),
        10 => ("L16", 44100),
        11 => ("L16", 44100),
        12 => ("QCELP", 8000),
        13 => ("CN", 8000),
        14 => ("MPA", 90000),
        15 => ("G728", 8000),
        16 => ("DVI4", 11025),
        17 => ("DVI4", 22050),
        18 => ("G729", 8000),
        25 => ("CelB", 90000),
        26 => ("JPEG", 90000),
        28 => ("nv", 90000),
        31 => ("H261", 90000),
        32 => ("MPV", 90000),
        33 => ("MP2T", 90000),
        34 => ("H263", 90000),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_table_values() {
        assert_eq!(static_rtpmap(0), Some(("PCMU", 8000)));
        assert_eq!(static_rtpmap(8), Some(("PCMA", 8000)));
        assert_eq!(static_rtpmap(9), Some(("G722", 8000)));
        assert_eq!(static_rtpmap(18), Some(("G729", 8000)));
        assert_eq!(static_rtpmap(96), None);
        assert_eq!(static_rtpmap(35), None);
    }
}
