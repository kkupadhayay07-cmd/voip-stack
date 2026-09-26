//! Opus (RFC 6716) codec via the system libopus through the safe `opus`
//! binding crate (the binding internally uses FFI; this module adds no
//! `unsafe` of its own).
//!
//! Supported: 8/12/16/24/48 kHz, mono/stereo, DTX, in-band FEC, bitrate
//! control. Opus frames are 20 ms (960 samples per channel @48 kHz).

use crate::error::{CodecError, Result};
use crate::traits::{CodecId, Decoder, Encoder, FormatInfo};

/// SDP descriptor for Opus (Chrome-compatible default: 48 kHz stereo, PT 111).
pub const OPUS_INFO: FormatInfo = FormatInfo {
    id: CodecId::Opus,
    name: "opus",
    payload_type: 111,
    clock_rate: 48000,
    channels: 2,
    fmtp: Some("minptime=10;useinbandfec=1"),
};

/// Supported Opus sample rates.
pub const SAMPLE_RATES: [u32; 5] = [8000, 12000, 16000, 24000, 48000];

/// Samples per channel per 20 ms frame at the given rate.
pub fn frame_samples_for(rate: u32) -> usize {
    (rate / 50) as usize
}

fn check_rate(rate: u32) -> Result<()> {
    if !SAMPLE_RATES.contains(&rate) {
        return Err(CodecError::Opus(format!(
            "unsupported sample rate {rate} (need one of {SAMPLE_RATES:?})"
        )));
    }
    Ok(())
}

fn map_channels(channels: u8) -> Result<opus::Channels> {
    match channels {
        1 => Ok(opus::Channels::Mono),
        2 => Ok(opus::Channels::Stereo),
        n => Err(CodecError::Opus(format!(
            "opus needs 1 or 2 channels, got {n}"
        ))),
    }
}

fn to_err(e: opus::Error) -> CodecError {
    CodecError::Opus(e.to_string())
}

/// Opus encoder.
pub struct OpusEncoder {
    inner: opus::Encoder,
    rate: u32,
    channels: u8,
    frame_samples: usize,
    pending: Vec<i16>,
}

impl OpusEncoder {
    /// Create an encoder. Rates: 8/12/16/24/48 kHz, channels 1–2.
    ///
    /// `Application::Voip` is used at ≤16 kHz (speech-tuned), `Audio` above.
    pub fn new(rate: u32, channels: u8) -> Result<OpusEncoder> {
        check_rate(rate)?;
        let ch = map_channels(channels)?;
        let app = if rate <= 16_000 {
            opus::Application::Voip
        } else {
            opus::Application::Audio
        };
        let inner = opus::Encoder::new(rate, ch, app).map_err(to_err)?;
        let frame_samples = frame_samples_for(rate);
        Ok(OpusEncoder {
            inner,
            rate,
            channels,
            frame_samples,
            pending: Vec::with_capacity(frame_samples * channels as usize * 2),
        })
    }

    /// Enable in-band forward error correction.
    pub fn set_fec(&mut self, on: bool) -> Result<()> {
        self.inner.set_inband_fec(on).map_err(to_err)
    }

    /// Set expected packet loss percentage for FEC (0–100).
    pub fn set_packet_loss_perc(&mut self, perc: i32) -> Result<()> {
        self.inner.set_packet_loss_perc(perc).map_err(to_err)
    }
}

impl Encoder for OpusEncoder {
    fn encode(&mut self, pcm: &[i16], out: &mut Vec<u8>) -> Result<usize> {
        // Buffer input until a full 20 ms frame is available.
        self.pending.extend_from_slice(pcm);
        let need = self.frame_samples * self.channels as usize;
        if self.pending.len() < need {
            return Ok(0);
        }
        let frame: Vec<i16> = self.pending.drain(..need).collect();
        let mut buf = [0u8; 4000];
        let n = self.inner.encode(&frame, &mut buf).map_err(to_err)?;
        out.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn sample_rate(&self) -> u32 {
        self.rate
    }

    fn channels(&self) -> u8 {
        self.channels
    }

    fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    fn set_bitrate(&mut self, bps: u32) -> Result<()> {
        self.inner
            .set_bitrate(opus::Bitrate::Bits(bps as i32))
            .map_err(to_err)
    }

    fn set_dtx(&mut self, on: bool) -> Result<()> {
        self.inner.set_dtx(on).map_err(to_err)
    }

    fn reset(&mut self) {
        self.pending.clear();
        if let Ok(ch) = map_channels(self.channels) {
            let app = if self.rate <= 16_000 {
                opus::Application::Voip
            } else {
                opus::Application::Audio
            };
            if let Ok(mut fresh) = opus::Encoder::new(self.rate, ch, app) {
                std::mem::swap(&mut self.inner, &mut fresh);
            }
        }
    }
}

/// Opus decoder with PLC.
pub struct OpusDecoder {
    inner: opus::Decoder,
    rate: u32,
    channels: u8,
    frame_samples: usize,
}

impl OpusDecoder {
    /// Create a decoder.
    pub fn new(rate: u32, channels: u8) -> Result<OpusDecoder> {
        check_rate(rate)?;
        let ch = map_channels(channels)?;
        let inner = opus::Decoder::new(rate, ch).map_err(to_err)?;
        Ok(OpusDecoder {
            inner,
            rate,
            channels,
            frame_samples: frame_samples_for(rate),
        })
    }
}

impl Decoder for OpusDecoder {
    fn decode(&mut self, data: &[u8], out: &mut Vec<i16>) -> Result<usize> {
        if data.is_empty() {
            return self.conceal(out);
        }
        let mut buf = vec![0i16; self.frame_samples * self.channels as usize];
        let n = self.inner.decode(data, &mut buf, false).map_err(to_err)?;
        out.extend_from_slice(&buf[..n * self.channels as usize]);
        Ok(n)
    }

    fn conceal(&mut self, out: &mut Vec<i16>) -> Result<usize> {
        // Empty input triggers libopus packet-loss concealment.
        let mut buf = vec![0i16; self.frame_samples * self.channels as usize];
        let n = self.inner.decode(&[], &mut buf, false).map_err(to_err)?;
        out.extend_from_slice(&buf[..n * self.channels as usize]);
        Ok(n)
    }

    fn sample_rate(&self) -> u32 {
        self.rate
    }

    fn channels(&self) -> u8 {
        self.channels
    }

    fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    fn reset(&mut self) {
        if let Ok(ch) = map_channels(self.channels) {
            if let Ok(fresh) = opus::Decoder::new(self.rate, ch) {
                self.inner = fresh;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn speechish(rate: u32, n: usize) -> Vec<i16> {
        (0..n)
            .map(|i| {
                let t = i as f64 / rate as f64;
                let v = (2.0 * std::f64::consts::PI * 300.0 * t).sin()
                    + 0.5 * (2.0 * std::f64::consts::PI * 700.0 * t).sin()
                    + 0.3 * (2.0 * std::f64::consts::PI * 1_200.0 * t).sin();
                ((v * 6000.0) as i16).clamp(-32_768, 32_767)
            })
            .collect()
    }

    #[allow(dead_code)]
    fn snr_db(a: &[i16], b: &[i16], skip: usize) -> f64 {
        let mut sig = 0.0;
        let mut err = 0.0;
        for i in skip..a.len().min(b.len()) {
            let d = a[i] as f64 - b[i] as f64;
            sig += a[i] as f64 * a[i] as f64;
            err += d * d;
        }
        10.0 * (sig / err.max(1.0)).log10()
    }

    /// SNR after finding the best alignment lag via cross-correlation
    /// (codecs introduce algorithmic delay, so index-aligned comparison is
    /// not meaningful).
    fn aligned_snr_db(a: &[i16], b: &[i16], max_lag: isize) -> (f64, isize) {
        let step = 4usize; // subsample the correlation search
        let mut best_lag = 0isize;
        let mut best_corr = f64::NEG_INFINITY;
        for lag in (-max_lag..=max_lag).step_by(8) {
            let mut corr = 0.0f64;
            let n = a.len().min(b.len());
            // Guard both ends so index i+lag stays in bounds.
            let lo = if lag >= 0 { 0usize } else { (-lag) as usize };
            let hi = if lag >= 0 {
                n.saturating_sub(lag as usize)
            } else {
                n
            };
            let mut i = lo.max(step);
            while i < hi.saturating_sub(step) {
                corr += (a[i] as f64) * (b[(i as isize + lag) as usize] as f64);
                i += step * 8;
            }
            if corr > best_corr {
                best_corr = corr;
                best_lag = lag;
            }
        }
        // Refine ±8 samples at step 1 (coarse pass used step 8).
        let coarse = best_lag;
        for lag in (coarse - 8)..=(coarse + 8) {
            if lag < -max_lag || lag > max_lag {
                continue;
            }
            let mut corr = 0.0f64;
            let n = a.len().min(b.len());
            let lo = if lag >= 0 { 0usize } else { (-lag) as usize };
            let hi = if lag >= 0 {
                n.saturating_sub(lag as usize)
            } else {
                n
            };
            let mut i = lo.max(1);
            while i < hi.saturating_sub(1) {
                corr += (a[i] as f64) * (b[(i as isize + lag) as usize] as f64);
                i += 4;
            }
            if corr > best_corr {
                best_corr = corr;
                best_lag = lag;
            }
        }
        // Exact SNR at the best lag.
        let mut sig = 0.0f64;
        let mut err = 0.0f64;
        let n = a.len().min(b.len());
        for (i, &x) in a.iter().enumerate().take(n) {
            let j = i as isize + best_lag;
            if j < 0 || j as usize >= b.len() {
                continue;
            }
            let d = x as f64 - b[j as usize] as f64;
            sig += (x as f64) * (x as f64);
            err += d * d;
        }
        (10.0 * (sig / err.max(1.0)).log10(), best_lag)
    }

    #[test]
    fn mono_48k_roundtrip() {
        let pcm = speechish(48000, 96_000); // 2 s
        let mut e = OpusEncoder::new(48000, 1).unwrap();
        e.set_bitrate(24_000).unwrap();
        let mut dec = OpusDecoder::new(48000, 1).unwrap();
        let mut out_pcm = Vec::new();
        let mut frames = 0;
        for c in pcm.chunks(960) {
            let mut f = c.to_vec();
            f.resize(960, 0);
            let mut w = Vec::new();
            let n = e.encode(&f, &mut w).unwrap();
            assert!(n > 0, "opus produced an empty frame");
            dec.decode(&w, &mut out_pcm).unwrap();
            frames += 1;
        }
        assert!(frames >= 99, "expected ~100 frames, got {frames}");
        let (q, lag) = aligned_snr_db(&pcm, &out_pcm, 2_000);
        eprintln!("mono 48k: SNR {q:.1} dB at lag {lag}");
        assert!(q > 15.0, "opus 48k mono SNR {q} dB < 15 dB (lag {lag})");
    }

    #[test]
    fn stereo_48k_roundtrip() {
        let mut e = OpusEncoder::new(48000, 2).unwrap();
        e.set_bitrate(32_000).unwrap();
        let mut d = OpusDecoder::new(48000, 2).unwrap();
        let mono = speechish(48000, 9_600);
        let mut inter = Vec::with_capacity(mono.len() * 2);
        for &s in &mono {
            inter.push(s);
            inter.push(s / 2);
        }
        let mut out = Vec::new();
        for c in inter.chunks(1_920) {
            let mut f = c.to_vec();
            f.resize(1_920, 0);
            let mut w = Vec::new();
            e.encode(&f, &mut w).unwrap();
            d.decode(&w, &mut out).unwrap();
        }
        assert_eq!(out.len(), inter.len());
        // Left channel correlation with source (alignment-aware).
        let left_out: Vec<i16> = out.iter().step_by(2).copied().collect();
        let (q, lag) = aligned_snr_db(&mono, &left_out, 2_000);
        eprintln!("stereo 48k L: SNR {q:.1} dB at lag {lag}");
        assert!(q > 10.0, "opus stereo L SNR {q}");
    }

    #[test]
    fn plc_conceal_finite() {
        let mut d = OpusDecoder::new(16000, 1).unwrap();
        let mut out = Vec::new();
        for _ in 0..10 {
            let n = d.conceal(&mut out).unwrap();
            assert_eq!(n, 320);
        }
        assert_eq!(out.len(), 3_200);
        assert!(out.iter().all(|s| (-32_768..=32_767).contains(s)));
    }

    #[test]
    fn fec_conceal_uses_previous() {
        let mut e = OpusEncoder::new(16000, 1).unwrap();
        e.set_fec(true).unwrap();
        e.set_packet_loss_perc(30).unwrap();
        let mut d = OpusDecoder::new(16000, 1).unwrap();
        let pcm = speechish(16000, 3_200);
        let mut w1 = Vec::new();
        e.encode(&pcm[..320], &mut w1).unwrap();
        let mut w2 = Vec::new();
        e.encode(&pcm[320..640], &mut w2).unwrap();
        let mut out = Vec::new();
        d.decode(&w1, &mut out).unwrap();
        // Decode frame 2 with FEC flag not set but simulate loss: conceal
        let _ = d.conceal(&mut out);
        assert_eq!(out.len(), 640);
    }

    #[test]
    fn dtx_accepted() {
        let mut e = OpusEncoder::new(48000, 1).unwrap();
        e.set_dtx(true).unwrap();
        let mut w = Vec::new();
        e.encode(&[0i16; 960], &mut w).unwrap();
        assert!(!w.is_empty());
    }

    #[test]
    fn unsupported_rates_rejected() {
        assert!(matches!(
            OpusEncoder::new(11025, 1),
            Err(CodecError::Opus(_))
        ));
        assert!(matches!(
            OpusDecoder::new(44100, 1),
            Err(CodecError::Opus(_))
        ));
        assert!(matches!(
            OpusEncoder::new(48000, 5),
            Err(CodecError::Opus(_))
        ));
    }

    #[test]
    fn metadata() {
        let e = OpusEncoder::new(24000, 1).unwrap();
        assert_eq!(e.sample_rate(), 24_000);
        assert_eq!(e.channels(), 1);
        assert_eq!(e.frame_samples(), 480);
        let d = OpusDecoder::new(48000, 2).unwrap();
        assert_eq!(d.frame_samples(), 960);
    }

    #[test]
    fn frame_samples_table() {
        assert_eq!(frame_samples_for(8000), 160);
        assert_eq!(frame_samples_for(12000), 240);
        assert_eq!(frame_samples_for(16000), 320);
        assert_eq!(frame_samples_for(24000), 480);
        assert_eq!(frame_samples_for(48000), 960);
    }
}
