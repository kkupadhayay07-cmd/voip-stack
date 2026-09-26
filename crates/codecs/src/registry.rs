//! Codec factory: builds encoders/decoders and exposes the SDP format table.

use crate::error::{CodecError, Result};
use crate::traits::{CodecId, Decoder, Encoder, FormatInfo};

/// All formats the stack can advertise, in preference order.
pub const FORMATS: &[FormatInfo] = &[
    crate::g711::PCMU_INFO,
    crate::g711::PCMA_INFO,
    FormatInfo {
        id: CodecId::G722,
        name: "G722",
        payload_type: 9,
        clock_rate: 8000, // wire clock per RFC 3551 (16 kHz internally)
        channels: 1,
        fmtp: None,
    },
    FormatInfo {
        id: CodecId::G729,
        name: "G729",
        payload_type: 18,
        clock_rate: 8000,
        channels: 1,
        fmtp: Some("annexb=no"),
    },
    crate::cn::CN_INFO,
    crate::l16::L16_INFO,
    #[cfg(feature = "opus")]
    crate::opus::OPUS_INFO,
    FormatInfo {
        id: CodecId::TelephoneEvent,
        name: "telephone-event",
        payload_type: 100,
        clock_rate: 8000,
        channels: 1,
        fmtp: Some("0-16"),
    },
];

/// Codec factory helpers.
pub struct Registry;

impl Registry {
    /// Static format table (preference-ordered).
    pub fn formats() -> &'static [FormatInfo] {
        FORMATS
    }

    /// Look up a format by encoding name + clock + channels (case-insensitive).
    pub fn format_for_name(name: &str, clock: u32, channels: u8) -> Option<FormatInfo> {
        FORMATS.iter().copied().find(|f| {
            f.name.eq_ignore_ascii_case(name)
                && f.clock_rate == clock
                && f.channels == channels.max(1)
        })
    }

    /// Map a name/clock/channels triple to a [`CodecId`].
    pub fn codec_for_name(name: &str, clock: u32, channels: u8) -> Option<CodecId> {
        Self::format_for_name(name, clock, channels).map(|f| f.id)
    }

    /// Whether a codec is compiled in / implemented.
    pub fn is_supported(id: CodecId) -> bool {
        match id {
            CodecId::Pcmu | CodecId::Pcma | CodecId::L16 | CodecId::ComfortNoise => true,
            CodecId::G722 => crate::g722::SUPPORTED,
            CodecId::G729 => crate::g729::SUPPORTED,
            CodecId::TelephoneEvent => false, // handled by rtp crate
            #[cfg(feature = "opus")]
            CodecId::Opus => true,
            #[cfg(not(feature = "opus"))]
            CodecId::Opus => false,
        }
    }

    /// Build an encoder for `id` at the given clock rate.
    pub fn encoder(id: CodecId, clock: u32, channels: u8) -> Result<Box<dyn Encoder>> {
        match id {
            CodecId::Pcmu => {
                Self::check_clock(id, clock, 8000)?;
                Ok(Box::new(crate::g711::G711Encoder::new(
                    crate::g711::G711Law::Mu,
                )))
            }
            CodecId::Pcma => {
                Self::check_clock(id, clock, 8000)?;
                Ok(Box::new(crate::g711::G711Encoder::new(
                    crate::g711::G711Law::A,
                )))
            }
            CodecId::L16 => Ok(Box::new(crate::l16::L16Encoder::new(clock, channels, 20))),
            CodecId::ComfortNoise => {
                Self::check_clock(id, clock, 8000)?;
                Ok(Box::new(crate::cn::ComfortNoiseEncoder::new()))
            }
            CodecId::G722 => crate::g722::make_encoder(clock),
            CodecId::G729 => crate::g729::make_encoder(clock),
            #[cfg(feature = "opus")]
            CodecId::Opus => Ok(Box::new(crate::opus::OpusEncoder::new(clock, channels)?)),
            #[cfg(not(feature = "opus"))]
            CodecId::Opus => Err(CodecError::Unsupported("opus feature disabled")),
            CodecId::TelephoneEvent => Err(CodecError::Unsupported(
                "telephone-event is packetized by the rtp crate",
            )),
        }
    }

    /// Build a decoder for `id` at the given clock rate.
    pub fn decoder(id: CodecId, clock: u32, channels: u8) -> Result<Box<dyn Decoder>> {
        match id {
            CodecId::Pcmu => {
                Self::check_clock(id, clock, 8000)?;
                Ok(Box::new(crate::g711::G711Decoder::new(
                    crate::g711::G711Law::Mu,
                )))
            }
            CodecId::Pcma => {
                Self::check_clock(id, clock, 8000)?;
                Ok(Box::new(crate::g711::G711Decoder::new(
                    crate::g711::G711Law::A,
                )))
            }
            CodecId::L16 => Ok(Box::new(crate::l16::L16Decoder::new(clock, channels, 20))),
            CodecId::ComfortNoise => {
                Self::check_clock(id, clock, 8000)?;
                Ok(Box::new(crate::cn::ComfortNoiseDecoder::new(0x5EED_C0DE)))
            }
            CodecId::G722 => crate::g722::make_decoder(clock),
            CodecId::G729 => crate::g729::make_decoder(clock),
            #[cfg(feature = "opus")]
            CodecId::Opus => Ok(Box::new(crate::opus::OpusDecoder::new(clock, channels)?)),
            #[cfg(not(feature = "opus"))]
            CodecId::Opus => Err(CodecError::Unsupported("opus feature disabled")),
            CodecId::TelephoneEvent => Err(CodecError::Unsupported(
                "telephone-event is parsed by the rtp crate",
            )),
        }
    }

    fn check_clock(_id: CodecId, got: u32, want: u32) -> Result<()> {
        if got != want {
            return Err(CodecError::InvalidData(format!(
                "clock {got} invalid for this codec (want {want})"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_core_payloads() {
        let pts: Vec<u8> = FORMATS.iter().map(|f| f.payload_type).collect();
        assert!(pts.contains(&0));
        assert!(pts.contains(&8));
        assert!(pts.contains(&9));
        assert!(pts.contains(&18));
        assert!(pts.contains(&13));
        assert!(pts.contains(&111));
    }

    #[test]
    fn name_lookup() {
        assert_eq!(
            Registry::codec_for_name("PCMU", 8000, 1),
            Some(CodecId::Pcmu)
        );
        assert_eq!(
            Registry::codec_for_name("pcma", 8000, 1),
            Some(CodecId::Pcma)
        );
        assert_eq!(
            Registry::codec_for_name("opus", 48000, 2),
            Some(CodecId::Opus)
        );
        assert_eq!(
            Registry::codec_for_name("telephone-event", 8000, 1),
            Some(CodecId::TelephoneEvent)
        );
        assert_eq!(
            Registry::codec_for_name("G722", 16000, 1),
            None,
            "G722 wire clock is 8000"
        );
        assert_eq!(Registry::codec_for_name("nope", 8000, 1), None);
    }

    #[test]
    fn rtpmap_strings() {
        let f = Registry::format_for_name("opus", 48000, 2).unwrap();
        assert_eq!(f.rtpmap_string(), "111 opus/48000/2");
        let f = Registry::format_for_name("PCMU", 8000, 1).unwrap();
        assert_eq!(f.rtpmap_string(), "0 PCMU/8000");
    }

    #[test]
    fn telephone_event_not_a_stream_codec() {
        assert!(matches!(
            Registry::encoder(CodecId::TelephoneEvent, 8000, 1),
            Err(CodecError::Unsupported(_))
        ));
        assert!(matches!(
            Registry::decoder(CodecId::TelephoneEvent, 8000, 1),
            Err(CodecError::Unsupported(_))
        ));
    }

    #[test]
    fn wrong_clock_rejected_for_static() {
        assert!(matches!(
            Registry::encoder(CodecId::Pcmu, 16000, 1),
            Err(CodecError::InvalidData(_))
        ));
    }
}
