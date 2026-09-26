//! Unified encoder/decoder traits and codec identifiers.

use crate::error::{CodecError, Result};

/// Identifiers for every codec known to the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecId {
    /// ITU-T G.711 μ-law (RFC 3551 payload type 0).
    Pcmu,
    /// ITU-T G.711 A-law (RFC 3551 payload type 8).
    Pcma,
    /// ITU-T G.722 64/56/48 kbit/s subband ADPCM (payload type 9).
    G722,
    /// ITU-T G.729 CS-ACELP 8 kbit/s (payload type 18).
    G729,
    /// IETF Opus (RFC 6716), dynamic payload type.
    Opus,
    /// Uncompressed linear 16-bit PCM (RFC 3551 §5.1), dynamic.
    L16,
    /// RFC 3389 comfort noise, payload type 13.
    ComfortNoise,
    /// RFC 4733 telephone-event, dynamic payload type.
    TelephoneEvent,
}

/// Static SDP descriptor for a codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatInfo {
    pub id: CodecId,
    /// Encoding name as it appears in `a=rtpmap` (e.g. "PCMU", "opus").
    pub name: &'static str,
    /// Default payload type (static per RFC 3551, or our chosen dynamic).
    pub payload_type: u8,
    /// RTP timestamp clock rate in Hz.
    pub clock_rate: u32,
    pub channels: u8,
    /// Default `a=fmtp` string, if any.
    pub fmtp: Option<&'static str>,
}

impl FormatInfo {
    /// `a=rtpmap:<pt> <name>/<clock>[/<channels>]` value string.
    pub fn rtpmap_string(&self) -> String {
        if self.channels > 1 {
            format!(
                "{} {}/{}/{}",
                self.payload_type, self.name, self.clock_rate, self.channels
            )
        } else {
            format!("{} {}/{}", self.payload_type, self.name, self.clock_rate)
        }
    }
}

/// Encodes 16-bit linear PCM into codec frames.
///
/// Encoders are frame-synchronous: each `encode` call consumes exactly
/// [`Encoder::frame_samples`] samples per channel and appends one wire frame
/// to `out`, returning the number of bytes written.
pub trait Encoder: Send {
    fn encode(&mut self, pcm: &[i16], out: &mut Vec<u8>) -> Result<usize>;
    fn sample_rate(&self) -> u32;
    fn channels(&self) -> u8;
    /// Samples per channel consumed per frame (e.g. 160 for 20 ms @ 8 kHz).
    fn frame_samples(&self) -> usize;
    fn set_bitrate(&mut self, _bps: u32) -> Result<()> {
        Err(CodecError::Unsupported("bitrate control"))
    }
    fn set_dtx(&mut self, _on: bool) -> Result<()> {
        Err(CodecError::Unsupported("dtx"))
    }
    /// Reset encoder state to a fresh-session condition.
    fn reset(&mut self);
}

/// Decodes codec frames into 16-bit linear PCM, with packet-loss concealment.
pub trait Decoder: Send {
    /// Decode `data` (one frame) appending interleaved PCM to `out`.
    /// Returns samples appended per channel.
    fn decode(&mut self, data: &[u8], out: &mut Vec<i16>) -> Result<usize>;
    /// Conceaal a lost frame (PLC), appending samples per channel.
    fn conceal(&mut self, out: &mut Vec<i16>) -> Result<usize>;
    fn sample_rate(&self) -> u32;
    fn channels(&self) -> u8;
    fn frame_samples(&self) -> usize;
    /// Reset decoder state (also clears PLC history).
    fn reset(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_formats() -> Vec<FormatInfo> {
        vec![
            FormatInfo {
                id: CodecId::Pcmu,
                name: "PCMU",
                payload_type: 0,
                clock_rate: 8000,
                channels: 1,
                fmtp: None,
            },
            FormatInfo {
                id: CodecId::Opus,
                name: "opus",
                payload_type: 111,
                clock_rate: 48000,
                channels: 2,
                fmtp: Some("minptime=10;useinbandfec=1"),
            },
        ]
    }

    #[test]
    fn rtpmap_strings() {
        let f = sample_formats();
        assert_eq!(f[0].rtpmap_string(), "0 PCMU/8000");
        assert_eq!(f[1].rtpmap_string(), "111 opus/48000/2");
    }

    #[test]
    fn format_info_fields() {
        let f = &sample_formats()[1];
        assert_eq!(f.id, CodecId::Opus);
        assert_eq!(f.payload_type, 111);
        assert_eq!(f.clock_rate, 48000);
        assert_eq!(f.fmtp, Some("minptime=10;useinbandfec=1"));
    }

    #[test]
    fn default_trait_impls_report_unsupported() {
        // The default set_bitrate/set_dtx bodies must return Unsupported.
        struct Nop;
        impl Encoder for Nop {
            fn encode(&mut self, _: &[i16], _: &mut Vec<u8>) -> Result<usize> {
                Err(CodecError::Internal("nop".to_string()))
            }
            fn sample_rate(&self) -> u32 {
                8000
            }
            fn channels(&self) -> u8 {
                1
            }
            fn frame_samples(&self) -> usize {
                160
            }
            fn reset(&mut self) {}
        }
        let mut n = Nop;
        assert!(matches!(
            n.set_bitrate(24000),
            Err(CodecError::Unsupported(_))
        ));
        assert!(matches!(n.set_dtx(true), Err(CodecError::Unsupported(_))));
    }

    #[test]
    fn codec_id_hashable_and_copiable() {
        use std::collections::HashSet;
        let mut s = HashSet::new();
        s.insert(CodecId::Pcmu);
        s.insert(CodecId::Pcmu);
        s.insert(CodecId::Opus);
        assert_eq!(s.len(), 2);
        let c = CodecId::G722;
        assert_eq!(c, CodecId::G722);
    }
}
