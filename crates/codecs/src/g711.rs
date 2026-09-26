//! ITU-T G.711 μ-law / A-law (RFC 3551 payload types 0 and 8).
//!
//! Branch-based companding, bit-identical to the implementation in the
//! `rtp` crate. Frame-level wrappers implement the unified traits with
//! 20 ms / 160-sample frames at 8000 Hz.

use crate::error::{CodecError, Result};
use crate::traits::{CodecId, Decoder, Encoder, FormatInfo};

/// Encode one 16-bit sample to μ-law.
pub fn pcmu_encode_sample(s: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32635;
    let mut x = s as i32;
    let sign = if x < 0 {
        x = -x;
        0x80u32
    } else {
        0u32
    };
    if x > CLIP {
        x = CLIP;
    }
    x += BIAS;
    let h = (x >> 7) as u8;
    let seg = match h {
        0..=1 => 0u32,
        2..=3 => 1,
        4..=7 => 2,
        8..=15 => 3,
        16..=31 => 4,
        32..=63 => 5,
        64..=127 => 6,
        _ => 7,
    };
    let mant = (((x >> seg) - BIAS) >> 3).clamp(0, 15) as u32;
    !(sign | (seg << 4) | mant) as u8
}

/// Decode one μ-law byte to 16-bit PCM.
pub fn pcmu_decode_sample(code: u8) -> i16 {
    let v = !code;
    let sign = v & 0x80;
    let expo = ((v & 0x70) >> 4) as u32;
    let mant = v & 0x0F;
    let t = ((mant as i32) << 3) + 0x84;
    let t = t << expo;
    if sign != 0 {
        (0x84 - t) as i16
    } else {
        (t - 0x84) as i16
    }
}

/// Encode one 16-bit sample to A-law.
pub fn pcma_encode_sample(s: i16) -> u8 {
    let mut x = s as i32;
    let sign: u32 = if x >= 0 {
        0x80
    } else {
        x = -x;
        0x00
    };
    if x > 32_767 {
        x = 32_767;
    }
    let seg: u32 = match x {
        0..=263 => 0,
        264..=527 => 1,
        528..=1_055 => 2,
        1_056..=2_111 => 3,
        2_112..=4_223 => 4,
        4_224..=8_447 => 5,
        8_448..=16_895 => 6,
        _ => 7,
    };
    let mant: i32 = if seg == 0 {
        (x - 8) >> 4
    } else {
        ((x >> (seg - 1)) - 0x108) >> 4
    };
    let mant = mant.clamp(0, 15) as u32;
    let internal = sign | (seg << 4) | mant;
    (internal ^ 0x55) as u8
}

/// Decode one A-law byte to 16-bit PCM.
pub fn pcma_decode_sample(code: u8) -> i16 {
    let v = code ^ 0x55;
    let sign = v & 0x80;
    let seg = ((v & 0x70) >> 4) as u32;
    let mant = v & 0x0F;
    let t: i32 = if seg == 0 {
        ((mant as i32) << 4) + 8
    } else {
        (((mant as i32) << 4) + 0x108) << (seg - 1)
    };
    if sign != 0 {
        t as i16
    } else {
        -t as i16
    }
}

/// SDP descriptor for μ-law.
pub const PCMU_INFO: FormatInfo = FormatInfo {
    id: CodecId::Pcmu,
    name: "PCMU",
    payload_type: 0,
    clock_rate: 8000,
    channels: 1,
    fmtp: None,
};

/// SDP descriptor for A-law.
pub const PCMA_INFO: FormatInfo = FormatInfo {
    id: CodecId::Pcma,
    name: "PCMA",
    payload_type: 8,
    clock_rate: 8000,
    channels: 1,
    fmtp: None,
};

/// Which G.711 companding law a codec instance uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G711Law {
    /// μ-law (PCMU, PT 0).
    Mu,
    /// A-law (PCMA, PT 8).
    A,
}

const FRAME_SAMPLES: usize = 160; // 20 ms @ 8 kHz

/// G.711 frame encoder (20 ms frames, 8000 Hz mono).
#[derive(Debug, Clone)]
pub struct G711Encoder {
    law: G711Law,
}

impl G711Encoder {
    /// Create an encoder for the given law.
    pub fn new(law: G711Law) -> G711Encoder {
        G711Encoder { law }
    }
}

impl Encoder for G711Encoder {
    fn encode(&mut self, pcm: &[i16], out: &mut Vec<u8>) -> Result<usize> {
        if pcm.len() != FRAME_SAMPLES {
            return Err(CodecError::InvalidData(format!(
                "g711 frame must be exactly {FRAME_SAMPLES} samples, got {}",
                pcm.len()
            )));
        }
        let start = out.len();
        match self.law {
            G711Law::Mu => out.extend(pcm.iter().map(|&s| pcmu_encode_sample(s))),
            G711Law::A => out.extend(pcm.iter().map(|&s| pcma_encode_sample(s))),
        }
        Ok(out.len() - start)
    }

    fn sample_rate(&self) -> u32 {
        8000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }

    fn reset(&mut self) {
        // G.711 is stateless.
    }
}

/// G.711 frame decoder with optional PLC hook.
#[derive(Debug, Clone)]
pub struct G711Decoder {
    law: G711Law,
    last_frame: [i16; FRAME_SAMPLES],
    have_last: bool,
}

impl G711Decoder {
    /// Create a decoder for the given law.
    pub fn new(law: G711Law) -> G711Decoder {
        G711Decoder {
            law,
            last_frame: [0; FRAME_SAMPLES],
            have_last: false,
        }
    }
}

impl Decoder for G711Decoder {
    fn decode(&mut self, data: &[u8], out: &mut Vec<i16>) -> Result<usize> {
        if data.len() != FRAME_SAMPLES {
            return Err(CodecError::InvalidData(format!(
                "g711 frame must be exactly {FRAME_SAMPLES} bytes, got {}",
                data.len()
            )));
        }
        let start = out.len();
        match self.law {
            G711Law::Mu => out.extend(data.iter().map(|&c| pcmu_decode_sample(c))),
            G711Law::A => out.extend(data.iter().map(|&c| pcma_decode_sample(c))),
        }
        for (i, d) in out[start..].iter().enumerate() {
            self.last_frame[i] = *d;
        }
        self.have_last = true;
        Ok(FRAME_SAMPLES)
    }

    fn conceal(&mut self, out: &mut Vec<i16>) -> Result<usize> {
        // Simple frame-repeat concealment with 6 dB decay.
        let gain = if self.have_last { 0.5 } else { 0.0 };
        for i in 0..FRAME_SAMPLES {
            out.push((self.last_frame[i] as f64 * gain) as i16);
        }
        // Decay stored frame so repeated losses fade out.
        for v in self.last_frame.iter_mut() {
            *v = (*v as f64 * gain) as i16;
        }
        self.have_last = true;
        Ok(FRAME_SAMPLES)
    }

    fn sample_rate(&self) -> u32 {
        8000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }

    fn reset(&mut self) {
        self.last_frame = [0; FRAME_SAMPLES];
        self.have_last = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcmu_zero_and_full_scale() {
        assert_eq!(pcmu_decode_sample(0xFF), 0);
        assert_eq!(pcmu_decode_sample(0x7F), 0);
        assert_eq!(pcmu_encode_sample(0), 0xFF);
        assert_eq!(pcmu_decode_sample(0x80), 32_124);
        assert_eq!(pcmu_decode_sample(0x00), -32_124);
        assert_eq!(pcmu_encode_sample(32_767), 0x80);
        assert_eq!(pcmu_encode_sample(-32_768), 0x00);
    }

    #[test]
    fn pcma_zero_and_full_scale() {
        assert_eq!(pcma_encode_sample(0), 0xD5);
        assert_eq!(pcma_encode_sample(-1), 0x55);
        assert_eq!(pcma_decode_sample(0xAA), 32_256);
        assert_eq!(pcma_decode_sample(0x2A), -32_256);
        assert_eq!(pcma_encode_sample(32_767), 0xAA);
        assert_eq!(pcma_encode_sample(-32_768), 0x2A);
    }

    #[test]
    fn all_codes_decode_finite() {
        for c in 0..=255u8 {
            let _ = pcmu_decode_sample(c);
            let _ = pcma_decode_sample(c);
        }
    }

    #[test]
    fn monotonic() {
        for (enc, dec) in [
            (
                pcmu_encode_sample as fn(i16) -> u8,
                pcmu_decode_sample as fn(u8) -> i16,
            ),
            (
                pcma_encode_sample as fn(i16) -> u8,
                pcma_decode_sample as fn(u8) -> i16,
            ),
        ] {
            let mut prev = i16::MIN;
            for i in 0..=255u32 {
                let s = (-32_768i32 + (i * 256) as i32).clamp(-32_768, 32_767) as i16;
                let v = dec(enc(s));
                assert!(v >= prev);
                prev = v;
            }
        }
    }

    #[test]
    fn roundtrip_error_bounded() {
        for s in [
            -32_768i16, -10_000, -256, -1, 0, 1, 255, 1_000, 12_345, 32_767,
        ] {
            let em = pcmu_decode_sample(pcmu_encode_sample(s));
            let ea = pcma_decode_sample(pcma_encode_sample(s));
            let bound = (s.unsigned_abs() / 8 + 80) as i16;
            assert!((em - s).abs() <= bound);
            assert!((ea - s).abs() <= bound);
        }
    }

    #[test]
    fn cross_check_with_rtp_crate() {
        // Bit-identity with the reference tables used by crates/rtp g711.
        // Values documented by round-trip tests there.
        assert_eq!(pcmu_encode_sample(0), 0xFF);
        assert_eq!(pcma_encode_sample(0), 0xD5);
        assert_eq!(pcmu_decode_sample(0x7F), 0);
        assert_eq!(pcma_decode_sample(0x2A), -32_256);
    }

    #[test]
    fn encoder_frame_size_enforced() {
        let mut e = G711Encoder::new(G711Law::Mu);
        let mut out = Vec::new();
        assert!(matches!(
            e.encode(&[0i16; 159], &mut out),
            Err(CodecError::InvalidData(_))
        ));
        assert!(matches!(
            e.encode(&[0i16; 161], &mut out),
            Err(CodecError::InvalidData(_))
        ));
        assert_eq!(e.encode(&[0i16; 160], &mut out).unwrap(), 160);
    }

    #[test]
    fn decoder_frame_size_enforced() {
        let mut d = G711Decoder::new(G711Law::A);
        let mut out = Vec::new();
        assert!(matches!(
            d.decode(&[0u8; 8], &mut out),
            Err(CodecError::InvalidData(_))
        ));
        assert_eq!(d.decode(&[0xD5; 160], &mut out).unwrap(), 160);
        assert!(out.iter().all(|&s| s.abs() <= 8));
    }

    #[test]
    fn decoder_conceal_decays() {
        let mut d = G711Decoder::new(G711Law::Mu);
        let mut out = Vec::new();
        let mut frame = vec![0u8; 160];
        frame[0] = 0x80; // loudest μ-law code
        d.decode(&frame, &mut out).unwrap();
        let mut c1 = Vec::new();
        d.conceal(&mut c1).unwrap();
        let mut c2 = Vec::new();
        d.conceal(&mut c2).unwrap();
        let e1: i64 = c1.iter().map(|&s| s as i64 * s as i64).sum();
        let e2: i64 = c2.iter().map(|&s| s as i64 * s as i64).sum();
        assert!(e2 < e1, "concealment energy must decay: {e1} -> {e2}");
        d.reset();
        let mut c3 = Vec::new();
        d.conceal(&mut c3).unwrap();
        assert!(c3.iter().all(|&s| s == 0), "after reset PLC is silence");
    }

    #[test]
    fn traits_metadata() {
        let e = G711Encoder::new(G711Law::A);
        assert_eq!(e.sample_rate(), 8000);
        assert_eq!(e.channels(), 1);
        assert_eq!(e.frame_samples(), 160);
        let d = G711Decoder::new(G711Law::Mu);
        assert_eq!(d.sample_rate(), 8000);
        assert_eq!(d.frame_samples(), 160);
    }
}
