//! # codecs
//!
//! Native audio codec suite for the ZRTC stack.
//!
//! Codecs (all payload types per RFC 3551 defaults):
//! - **PCMU / PCMA** (G.711 μ-law / A-law) — PT 0 / 8, 8 kHz, native branch companding.
//! - **G.722** — PT 9, 64/56/48 kbit/s subband ADPCM (native, `g722` module).
//! - **G.729** — PT 18, 8 kbit/s CS-ACELP (native, `g729` module).
//! - **Opus** — PT 111 (dynamic), 8–48 kHz via system libopus (`opus` module, feature `opus`).
//! - **L16** — linear 16-bit PCM, network byte order.
//! - **CN** — RFC 3389 comfort noise, PT 13.
//! - **telephone-event** — RFC 4733 lives in the `rtp` crate; descriptor only here.
//!
//! Shared infrastructure: [`Encoder`]/[`Decoder`] traits, [`Registry`],
//! packet-loss concealment ([`plc`]) and a streaming resampler ([`resample`]).
//!
//! # Example
//! ```no_run
//! use codecs::{Registry, CodecId};
//! let mut enc = Registry::encoder(CodecId::Pcmu, 8000, 1).unwrap();
//! let mut dec = Registry::decoder(CodecId::Pcmu, 8000, 1).unwrap();
//! let pcm = vec![0i16; 160];
//! let mut wire = Vec::new();
//! enc.encode(&pcm, &mut wire).unwrap();
//! let mut back = Vec::new();
//! dec.decode(&wire, &mut back).unwrap();
//! ```

#![forbid(unsafe_code)]

pub mod cn;
pub mod error;
pub mod g711;
pub mod l16;
pub mod plc;
pub mod registry;
pub mod resample;
pub mod traits;

/// G.722 subband ADPCM (populated by Task 3-b).
pub mod g722;
/// G.729 CS-ACELP (populated by Task 3-b).
pub mod g729;
#[cfg(feature = "opus")]
pub mod opus;

pub use cn::{ComfortNoiseDecoder, ComfortNoiseEncoder, CN_INFO};
pub use error::{CodecError, Result};
pub use g711::{G711Decoder, G711Encoder, G711Law, PCMA_INFO, PCMU_INFO};
pub use l16::{L16Decoder, L16Encoder, L16_INFO};
pub use plc::{EnergyDecayPlc, PitchPlc, Plc, SilencePlc};
pub use registry::Registry;
pub use resample::Resampler;
pub use traits::{CodecId, Decoder, Encoder, FormatInfo};

#[cfg(feature = "opus")]
pub use opus::{OpusDecoder, OpusEncoder, OPUS_INFO};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_roundtrip_all_codecs() {
        let cases: &[(CodecId, u32, u8)] = &[
            (CodecId::Pcmu, 8000, 1),
            (CodecId::Pcma, 8000, 1),
            (CodecId::L16, 16000, 1),
            (CodecId::ComfortNoise, 8000, 1),
            #[cfg(feature = "opus")]
            (CodecId::Opus, 48000, 2),
        ];
        for &(id, rate, ch) in cases {
            let mut e = Registry::encoder(id, rate, ch).unwrap();
            let mut d = Registry::decoder(id, rate, ch).unwrap();
            let n = e.frame_samples();
            let pcm = vec![1_000i16; n * ch as usize];
            let mut wire = Vec::new();
            e.encode(&pcm, &mut wire).unwrap();
            let mut back = Vec::new();
            d.decode(&wire, &mut back).unwrap();
            assert_eq!(back.len(), n * ch as usize, "codec {id:?} roundtrip len");
        }
    }

    #[test]
    fn registry_rejects_unknown() {
        // G.722/G.729 modules are added by Task 3-b; until then they report unsupported.
        if !Registry::is_supported(CodecId::G722) {
            assert!(matches!(
                Registry::encoder(CodecId::G722, 8000, 1),
                Err(CodecError::Unsupported(_))
            ));
        }
        assert!(matches!(
            Registry::encoder(CodecId::TelephoneEvent, 8000, 1),
            Err(CodecError::Unsupported(_))
        ));
    }
}
