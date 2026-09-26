//! Linear 16-bit PCM payload (RFC 3551 §5.1 "L16", network byte order).

use crate::error::{CodecError, Result};
use crate::traits::{CodecId, Decoder, Encoder, FormatInfo};

/// SDP descriptor for L16 @ 16 kHz mono (dynamic PT 120, test/legacy use).
pub const L16_INFO: FormatInfo = FormatInfo {
    id: CodecId::L16,
    name: "L16",
    payload_type: 120,
    clock_rate: 16000,
    channels: 1,
    fmtp: None,
};

/// Encode a single sample big-endian (RFC 3551 network order).
pub fn encode_sample_be(s: i16, out: &mut Vec<u8>) {
    let u = s as u16;
    out.push((u >> 8) as u8);
    out.push((u & 0xFF) as u8);
}

/// Decode one big-endian pair.
pub fn decode_sample_be(data: &[u8]) -> Result<i16> {
    if data.len() < 2 {
        return Err(CodecError::InvalidData("l16 needs 2 bytes".into()));
    }
    Ok(((data[0] as u16) << 8 | data[1] as u16) as i16)
}

/// L16 encoder: consumes `frame_samples` samples per channel, big-endian wire.
#[derive(Debug, Clone)]
pub struct L16Encoder {
    sample_rate: u32,
    channels: u8,
    frame_samples: usize,
}

impl L16Encoder {
    /// Create an L16 encoder (e.g. 20 ms frames via `new(rate, ch, 20)`).
    pub fn new(sample_rate: u32, channels: u8, frame_ms: u32) -> L16Encoder {
        let frame_samples = (sample_rate as u64 * frame_ms as u64 / 1000) as usize;
        L16Encoder {
            sample_rate,
            channels,
            frame_samples,
        }
    }
}

impl Encoder for L16Encoder {
    fn encode(&mut self, pcm: &[i16], out: &mut Vec<u8>) -> Result<usize> {
        if self.channels != 1 {
            return Err(CodecError::Unsupported("l16 multi-channel"));
        }
        if pcm.len() != self.frame_samples {
            return Err(CodecError::InvalidData(format!(
                "l16 frame must be exactly {} samples, got {}",
                self.frame_samples,
                pcm.len()
            )));
        }
        let start = out.len();
        for &s in pcm {
            encode_sample_be(s, out);
        }
        Ok(out.len() - start)
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    fn channels(&self) -> u8 {
        self.channels
    }

    fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    fn reset(&mut self) {}
}

/// L16 decoder.
#[derive(Debug, Clone)]
pub struct L16Decoder {
    sample_rate: u32,
    channels: u8,
    frame_samples: usize,
}

impl L16Decoder {
    /// Create an L16 decoder matching an encoder.
    pub fn new(sample_rate: u32, channels: u8, frame_ms: u32) -> L16Decoder {
        let frame_samples = (sample_rate as u64 * frame_ms as u64 / 1000) as usize;
        L16Decoder {
            sample_rate,
            channels,
            frame_samples,
        }
    }
}

impl Decoder for L16Decoder {
    fn decode(&mut self, data: &[u8], out: &mut Vec<i16>) -> Result<usize> {
        if !data.len().is_multiple_of(2) {
            return Err(CodecError::InvalidData(
                "l16 frame must be even-sized".into(),
            ));
        }
        if data.len() != self.frame_samples * 2 {
            return Err(CodecError::InvalidData(format!(
                "l16 frame must be exactly {} bytes, got {}",
                self.frame_samples * 2,
                data.len()
            )));
        }
        let start = out.len();
        for c in data.as_chunks::<2>().0 {
            out.push(decode_sample_be(c)?);
        }
        Ok(out.len() - start)
    }

    fn conceal(&mut self, out: &mut Vec<i16>) -> Result<usize> {
        for _ in 0..self.frame_samples {
            out.push(0);
        }
        Ok(self.frame_samples)
    }

    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    fn channels(&self) -> u8 {
        self.channels
    }

    fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    fn reset(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_order() {
        let mut v = Vec::new();
        encode_sample_be(0x1234, &mut v);
        assert_eq!(v, vec![0x12, 0x34]);
        encode_sample_be(-1, &mut v);
        assert_eq!(&v[2..], &[0xFF, 0xFF]);
        assert_eq!(decode_sample_be(&[0x12, 0x34]).unwrap(), 0x1234);
        assert_eq!(decode_sample_be(&v[2..]).unwrap(), -1);
    }

    #[test]
    fn decode_short_rejected() {
        assert!(matches!(
            decode_sample_be(&[0x12]),
            Err(CodecError::InvalidData(_))
        ));
    }

    #[test]
    fn roundtrip_identity() {
        let mut e = L16Encoder::new(16000, 1, 20);
        let mut d = L16Decoder::new(16000, 1, 20);
        let pcm: Vec<i16> = (0..320).map(|i| (i * 97 % 32768) as i16 - 16384).collect();
        let mut wire = Vec::new();
        assert_eq!(e.encode(&pcm, &mut wire).unwrap(), 640);
        let mut back = Vec::new();
        assert_eq!(d.decode(&wire, &mut back).unwrap(), 320);
        assert_eq!(pcm, back, "L16 must be lossless");
    }

    #[test]
    fn odd_and_wrong_length_rejected() {
        let mut d = L16Decoder::new(16000, 1, 20);
        let mut out = Vec::new();
        assert!(matches!(
            d.decode(&[0u8; 641], &mut out),
            Err(CodecError::InvalidData(_))
        ));
        assert!(matches!(
            d.decode(&[0u8; 100], &mut out),
            Err(CodecError::InvalidData(_))
        ));
    }

    #[test]
    fn conceal_silence() {
        let mut d = L16Decoder::new(16000, 1, 20);
        let mut out = Vec::new();
        assert_eq!(d.conceal(&mut out).unwrap(), 320);
        assert!(out.iter().all(|&s| s == 0));
    }

    #[test]
    fn encoder_frame_size() {
        let mut e = L16Encoder::new(8000, 1, 20);
        let mut out = Vec::new();
        assert!(matches!(
            e.encode(&[0i16; 100], &mut out),
            Err(CodecError::InvalidData(_))
        ));
        assert_eq!(e.encode(&[0i16; 160], &mut out).unwrap(), 320);
    }
}
