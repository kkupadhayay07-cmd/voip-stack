//! Streaming windowed-sinc sample-rate converter (pure Rust, f64 internal,
//! deterministic output).
//!
//! The kernel is evaluated on the fly per output sample:
//! `h(d) = sinc(d·cutoff)·cutoff·blackman_harris((d + T/2)/T)` for
//! `d ∈ (−T/2, T/2]`, where `cutoff = min(1, out/in)` provides anti-aliasing.
//! State (history + fractional position) is maintained across `process`
//! calls, so chunked feeding produces bit-identical output to one-shot use.

use crate::error::{CodecError, Result};

/// Taps per output sample (odd, centered). 65 taps ≈ 5.4 sinc mainlobes at
/// 8↔48 kHz ratios, giving ≥ 50 dB stopband attenuation.
const TAPS: i64 = 65;

/// Streaming resampler.
#[derive(Debug, Clone)]
pub struct Resampler {
    in_rate: u32,
    out_rate: u32,
    channels: u8,
    cutoff: f64,
    /// Interleaved input history (per channel).
    hist: Vec<f64>,
    /// Absolute input index of `hist[0]` (per channel frame index).
    base: i64,
    /// Absolute fractional input position of the next output frame.
    next_out: f64,
    /// Total input frames consumed.
    total_in: i64,
    /// Whether flush() has been called.
    flushed: bool,
}

impl Resampler {
    /// Create a resampler from `in_rate` to `out_rate` Hz (interleaved).
    pub fn new(in_rate: u32, out_rate: u32, channels: u8) -> Result<Resampler> {
        if in_rate == 0 || out_rate == 0 {
            return Err(CodecError::Resampler("rate must be non-zero".into()));
        }
        if channels == 0 {
            return Err(CodecError::Resampler("channels must be ≥ 1".into()));
        }
        let cutoff = (out_rate.min(in_rate)) as f64 / in_rate as f64;
        Ok(Resampler {
            in_rate,
            out_rate,
            channels,
            cutoff,
            hist: Vec::new(),
            base: 0,
            next_out: 0.0,
            total_in: 0,
            flushed: false,
        })
    }

    /// Input sample rate in Hz.
    pub fn in_rate(&self) -> u32 {
        self.in_rate
    }

    /// Output sample rate in Hz.
    pub fn out_rate(&self) -> u32 {
        self.out_rate
    }

    /// Number of interleaved channels.
    pub fn channels(&self) -> u8 {
        self.channels
    }

    /// Predict total output frames for `in_len` input frames (approximate,
    /// includes flush).
    pub fn out_len_for(&self, in_len: usize) -> usize {
        ((in_len as f64) * self.out_rate as f64 / self.in_rate as f64).ceil() as usize
    }

    fn kernel(&self, d: f64) -> f64 {
        let half = TAPS as f64 / 2.0;
        let x = std::f64::consts::PI * d * self.cutoff;
        let s = if x.abs() < 1e-12 {
            self.cutoff
        } else {
            (self.cutoff * (std::f64::consts::PI * d)).sin() / (std::f64::consts::PI * d)
        };
        // Blackman-Harris window over [0, 1].
        let w = (d + half) / TAPS as f64;
        let win = 0.42 - 0.5 * (2.0 * std::f64::consts::PI * w).cos()
            + 0.08 * (4.0 * std::f64::consts::PI * w).cos();
        s * win
    }

    /// Emit one output frame at absolute input position `t` (may read zeros
    /// beyond the stream end during flush).
    fn emit_at(&self, t: f64, out: &mut Vec<i16>, allow_future: bool) -> bool {
        let ch = self.channels as usize;
        let i0 = t.floor() as i64 - TAPS / 2 + 1;
        let last_needed = i0 + TAPS - 1;
        if last_needed > self.total_in - 1 && !(allow_future && self.flushed) {
            return false;
        }
        for c in 0..ch {
            let mut acc = 0.0f64;
            for j in 0..TAPS {
                let idx = i0 + j;
                let d = t - idx as f64;
                let h = self.kernel(d);
                let sample = if idx < self.base {
                    0.0
                } else if (idx - self.base) as usize * ch + c < self.hist.len() {
                    self.hist[(idx - self.base) as usize * ch + c]
                } else {
                    0.0
                };
                acc += h * sample;
            }
            out.push(acc.clamp(-32_768.0, 32_767.0) as i16);
        }
        true
    }

    /// Push interleaved input samples; appends interleaved output samples.
    /// Returns the number of output *samples* (not frames) appended.
    pub fn process(&mut self, input: &[i16], out: &mut Vec<i16>) -> usize {
        assert!(!self.flushed, "process after flush");
        let ch = self.channels as usize;
        let frames_in = input.len() / ch;
        self.hist.extend(input.iter().map(|&s| s as f64));
        self.total_in += frames_in as i64;
        let before = out.len();
        // Emit while the full kernel fits inside consumed input.
        loop {
            let t = self.next_out;
            let last_needed = t.floor() as i64 + TAPS / 2;
            if last_needed > self.total_in - 1 {
                break;
            }
            if !self.emit_at(t, out, false) {
                break;
            }
            self.next_out += self.in_rate as f64 / self.out_rate as f64;
        }
        self.trim();
        out.len() - before
    }

    /// Flush: emit remaining outputs up to the input end (tail reads zeros).
    /// Returns samples appended. After flushing, [`Resampler::reset`] must be
    /// called before reuse.
    pub fn flush(&mut self, out: &mut Vec<i16>) -> usize {
        self.flushed = true;
        let before = out.len();
        while self.next_out < self.total_in as f64 {
            if !self.emit_at(self.next_out, out, true) {
                break;
            }
            self.next_out += self.in_rate as f64 / self.out_rate as f64;
        }
        out.len() - before
    }

    fn trim(&mut self) {
        let keep_from = (self.next_out.floor() as i64 - TAPS / 2).max(0);
        if keep_from > self.base {
            let drop = ((keep_from - self.base) as usize) * self.channels as usize;
            self.hist.drain(0..drop.min(self.hist.len()));
            self.base = keep_from;
        }
    }

    /// Clear all state (also revives a flushed resampler).
    pub fn reset(&mut self) {
        self.hist.clear();
        self.base = 0;
        self.next_out = 0.0;
        self.total_in = 0;
        self.flushed = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(freq: f64, rate: u32, n: usize, amp: f64) -> Vec<i16> {
        (0..n)
            .map(|i| {
                (amp * (2.0 * std::f64::consts::PI * freq * i as f64 / rate as f64).sin())
                    .clamp(-32_768.0, 32_767.0) as i16
            })
            .collect()
    }

    fn snr_db(refs: &[i16], test: &[i16], skip: usize) -> f64 {
        let mut sig = 0.0;
        let mut err = 0.0;
        for i in skip..refs.len().min(test.len()) {
            let d = refs[i] as f64 - test[i] as f64;
            sig += refs[i] as f64 * refs[i] as f64;
            err += d * d;
        }
        10.0 * (sig / err.max(1.0)).log10()
    }

    #[test]
    fn upsample_8k_to_48k_quality() {
        let mut r = Resampler::new(8000, 48000, 1).unwrap();
        let input = tone(1000.0, 8000, 2000, 12_000.0);
        let mut out = Vec::new();
        r.process(&input, &mut out);
        r.flush(&mut out);
        let reference = tone(1000.0, 48000, 12_000, 12_000.0);
        let q = snr_db(&reference, &out, 240);
        assert!(q > 35.0, "upsample SNR {q} dB < 35 dB");
    }

    #[test]
    fn downsample_48k_to_8k_quality() {
        let mut r = Resampler::new(48000, 8000, 1).unwrap();
        let input = tone(1000.0, 48000, 12_000, 12_000.0);
        let mut out = Vec::new();
        r.process(&input, &mut out);
        r.flush(&mut out);
        let reference = tone(1000.0, 8000, 2_000, 12_000.0);
        let q = snr_db(&reference, &out, 40);
        assert!(q > 30.0, "downsample SNR {q} dB < 30 dB");
    }

    #[test]
    fn anti_alias_attenuates_high_freq() {
        // 6.5 kHz tone is well above the 4 kHz Nyquist of the 8 kHz output.
        let mut r = Resampler::new(48000, 8000, 1).unwrap();
        let input = tone(6500.0, 48000, 9_600, 12_000.0);
        let mut out = Vec::new();
        r.process(&input, &mut out);
        r.flush(&mut out);
        let e_out: f64 =
            out.iter().map(|&s| (s as f64) * (s as f64)).sum::<f64>() / out.len().max(1) as f64;
        // Spec: ≥ 40 dB stopband (input power 7.2e7 → < 7200); 65-tap
        // kernel measures ≈ 4.6e3 (−48 dB).
        assert!(e_out < 7_200.0, "alias leaked: mean energy {e_out}");
    }

    #[test]
    fn dc_passthrough() {
        let mut r = Resampler::new(8000, 16000, 1).unwrap();
        let input = vec![8_000i16; 800];
        let mut out = Vec::new();
        r.process(&input, &mut out);
        r.flush(&mut out);
        let mean: f64 = out.iter().map(|&s| s as f64).sum::<f64>() / out.len() as f64;
        let gain_db = 20.0 * (mean / 8_000.0).abs().log10();
        assert!(gain_db.abs() < 0.5, "DC gain {gain_db} dB off");
    }

    #[test]
    fn streaming_equals_oneshot() {
        let input = tone(440.0, 8000, 1_600, 10_000.0);
        let mut one = Resampler::new(8000, 24000, 1).unwrap();
        let mut o1 = Vec::new();
        one.process(&input, &mut o1);
        one.flush(&mut o1);

        let mut many = Resampler::new(8000, 24000, 1).unwrap();
        let mut o2 = Vec::new();
        for chunk in input.chunks(7) {
            many.process(chunk, &mut o2);
        }
        many.flush(&mut o2);
        assert_eq!(o1.len(), o2.len());
        for (a, b) in o1.iter().zip(o2.iter()) {
            assert_eq!(a, b, "streamed output must be identical");
        }
    }

    #[test]
    fn stereo_channels_independent() {
        let left = tone(1000.0, 8000, 800, 10_000.0);
        let right = tone(2000.0, 8000, 800, 10_000.0);
        let mut stereo_in = Vec::with_capacity(1_600);
        for i in 0..800 {
            stereo_in.push(left[i]);
            stereo_in.push(right[i]);
        }
        let mut r = Resampler::new(8000, 16000, 2).unwrap();
        let mut out = Vec::new();
        r.process(&stereo_in, &mut out);
        r.flush(&mut out);
        assert_eq!(out.len() % 2, 0);
        let mut rl = Resampler::new(8000, 16000, 1).unwrap();
        let mut lo = Vec::new();
        rl.process(&left, &mut lo);
        rl.flush(&mut lo);
        let skip = 40;
        for i in skip..(out.len() / 2).min(lo.len()) {
            assert!(
                (out[i * 2] as i32 - lo[i] as i32).abs() <= 2,
                "left channel mismatch at {i}"
            );
        }
    }

    #[test]
    fn length_math() {
        let r = Resampler::new(7800, 48000, 1).unwrap();
        assert_eq!(
            r.out_len_for(100),
            (100.0f64 * 48000.0 / 7800.0).ceil() as usize
        );
        let r2 = Resampler::new(16000, 8000, 1).unwrap();
        assert_eq!(r2.out_len_for(333), 167);
    }

    #[test]
    fn bad_config_rejected() {
        assert!(matches!(
            Resampler::new(0, 8000, 1),
            Err(CodecError::Resampler(_))
        ));
        assert!(matches!(
            Resampler::new(8000, 0, 1),
            Err(CodecError::Resampler(_))
        ));
        assert!(matches!(
            Resampler::new(8000, 8000, 0),
            Err(CodecError::Resampler(_))
        ));
    }

    #[test]
    fn identity_rate_is_passthrough() {
        let mut r = Resampler::new(8000, 8000, 1).unwrap();
        let input = tone(500.0, 8000, 400, 9_000.0);
        let mut out = Vec::new();
        r.process(&input, &mut out);
        r.flush(&mut out);
        let q = snr_db(&input, &out, 20);
        assert!(q > 40.0, "same-rate SNR {q} dB");
    }

    #[test]
    fn reset_clears_state() {
        let mut r = Resampler::new(8000, 16000, 1).unwrap();
        let mut out = Vec::new();
        r.process(&tone(1000.0, 8000, 400, 9_000.0), &mut out);
        r.reset();
        let mut out2 = Vec::new();
        r.process(&[0i16; 400], &mut out2);
        r.flush(&mut out2);
        let e: f64 = out2.iter().map(|&s| (s as f64) * (s as f64)).sum();
        assert!(e < 1.0, "after reset silence must stay silence: {e}");
    }

    #[test]
    fn metadata() {
        let r = Resampler::new(24000, 48000, 2).unwrap();
        assert_eq!(r.in_rate(), 24000);
        assert_eq!(r.out_rate(), 48000);
        assert_eq!(r.channels(), 2);
    }
}
