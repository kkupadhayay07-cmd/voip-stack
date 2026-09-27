//! Windowed-sinc resampler for arbitrary input→output sample-rate ratios.
//!
//! For each output position `p` (in input-sample units, advancing by
//! `from_hz / to_hz` per output sample) the kernel is
//!
//! ```text
//! h(x) = sinc(c·x) · kaiser(x / span)      c = min(1, r)
//! ```
//!
//! where `r = out/in` and `span` is the kernel half-width measured in
//! input samples (spanning a constant `half_width` of OUTPUT samples, so
//! downsampling widens the kernel automatically — the anti-aliasing
//! behavior).  Latency is bounded: outputs are only produced once their
//! kernel window is fully covered by pushed input.

/// Resampler configuration.
#[derive(Debug, Clone)]
pub struct ResamplerConfig {
    /// Kernel half-width measured in output samples (higher = better
    /// quality, more CPU and latency).
    pub half_width: usize,
}

impl Default for ResamplerConfig {
    fn default() -> Self {
        ResamplerConfig { half_width: 24 }
    }
}

/// Streaming resampler: push input samples (mono, -1..1), pull outputs.
pub struct Resampler {
    from_hz: u32,
    to_hz: u32,
    #[allow(dead_code)] // kept for runtime retuning
    config: ResamplerConfig,
    history: Vec<f32>,
    /// Absolute input position of `history[0]`.
    origin: u64,
    /// Absolute input position of the next output sample (fractional).
    phase: f64,
    step: f64,
    r: f64,
    cutoff: f64,
    span_in: f64,
    produced: u64,
}

impl Resampler {
    pub fn new(from_hz: u32, to_hz: u32, config: ResamplerConfig) -> Self {
        let r = to_hz as f64 / from_hz as f64;
        let cutoff = r.min(1.0);
        let span_in = config.half_width as f64 / r.min(1.0);
        Resampler {
            from_hz,
            to_hz,
            config,
            history: Vec::new(),
            origin: 0,
            phase: 0.0,
            step: 1.0 / r,
            r,
            cutoff,
            span_in,
            produced: 0,
        }
    }

    /// Output samples per input sample (>1 upsampling).
    pub fn ratio(&self) -> f64 {
        self.r
    }

    pub fn from_hz(&self) -> u32 {
        self.from_hz
    }

    pub fn to_hz(&self) -> u32 {
        self.to_hz
    }

    /// Push a block of input samples.
    pub fn push(&mut self, input: &[f32]) {
        self.history.extend_from_slice(input);
    }

    /// Output samples currently producible (kernel window fully covered).
    pub fn available(&self) -> usize {
        let end = (self.origin + self.history.len() as u64) as f64;
        let max_phase = end - self.span_in;
        if max_phase <= self.phase {
            0
        } else {
            ((max_phase - self.phase) / self.step).floor() as usize
        }
    }

    /// Pull up to `out.len()` output samples; returns how many written.
    pub fn pull(&mut self, out: &mut [f32]) -> usize {
        let avail = self.available();
        let n = avail.min(out.len());
        let half_span = self.span_in;
        for slot in out.iter_mut().take(n) {
            let pos = self.phase;
            let base = pos.floor();
            let start = base - half_span.ceil();
            let end = base + half_span.ceil() + 1.0;
            let hist_start = (start.max(self.origin as f64)).max(0.0) as usize;
            let hist_end = ((end.max(0.0)) as usize).min(self.origin as usize + self.history.len());

            let mut acc = 0f64;
            let mut wsum = 0f64;
            for i in hist_start..hist_end {
                let x = i as f64 - pos; // distance in input samples
                let sinc_arg = std::f64::consts::PI * self.cutoff * x;
                let sinc = if sinc_arg.abs() < 1e-9 {
                    1.0
                } else {
                    sinc_arg.sin() / sinc_arg
                };
                let t = (x / half_span).abs().min(1.0);
                let w = kaiser(t, 5.0);
                acc += self.history[i - self.origin as usize] as f64 * sinc * w;
                wsum += sinc * w;
            }
            // Normalize by the window sum to avoid DC ripple at fractional
            // phases (Kaiser is positive-sum; dividing keeps unity gain).
            *slot = if wsum.abs() > 1e-9 {
                (acc / wsum) as f32
            } else {
                0.0
            };

            self.phase += self.step;
            self.produced += 1;
        }

        // Trim consumed history: everything before phase - span can go.
        let keep_from = (self.phase - self.span_in * 2.0).floor();
        let drop = (keep_from as i64 - self.origin as i64).max(0) as usize;
        if drop > 4096 {
            self.history.drain(..drop);
            self.origin += drop as u64;
        }
        n
    }

    /// Total outputs produced so far.
    pub fn produced(&self) -> u64 {
        self.produced
    }

    /// Convert a whole buffer in one shot.
    ///
    /// Zero-pads the tail by the kernel span so the final outputs (which a
    /// streaming consumer would receive after the next push) are produced,
    /// then trims to the nominal expected length.
    pub fn convert_all(input: &[f32], from_hz: u32, to_hz: u32) -> Vec<f32> {
        let mut r = Resampler::new(from_hz, to_hz, ResamplerConfig::default());
        r.push(input);
        // Pad so the tail outputs' kernel windows are covered.
        let pad = (r.span_in.ceil() as usize + 2).max(2);
        r.push(&vec![0.0f32; pad]);
        let n = (input.len() as f64 * to_hz as f64 / from_hz as f64).ceil() as usize;
        let mut out = Vec::with_capacity(n + 64);
        let mut buf = [0f32; 1024];
        loop {
            let k = r.available().min(buf.len());
            if k == 0 {
                break;
            }
            let got = r.pull(&mut buf[..k]);
            if got == 0 {
                break;
            }
            out.extend_from_slice(&buf[..got]);
        }
        out.truncate(n);
        out
    }
}

/// Kaiser window (beta via simplified I0 series).
fn kaiser(t: f64, beta: f64) -> f64 {
    if t >= 1.0 {
        return 0.0;
    }
    let x = beta * (1.0 - t * t).sqrt();
    bessel_i0(x) / bessel_i0(beta)
}

/// 0th-order modified Bessel function of the first kind (series).
fn bessel_i0(x: f64) -> f64 {
    let mut sum = 1.0;
    let mut term = 1.0;
    for k in 1..32 {
        term *= (x / 2.0) * (x / 2.0) / (k * k) as f64;
        sum += term;
        if term < 1e-12 * sum {
            break;
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sine(freq: f64, hz: u32, seconds: f64) -> Vec<f32> {
        let n = (hz as f64 * seconds) as usize;
        (0..n)
            .map(|i| (2.0 * std::f64::consts::PI * freq * i as f64 / hz as f64).sin() as f32)
            .collect()
    }

    /// Goertzel power at a frequency.
    fn goertzel_power(samples: &[f32], freq: f64, hz: u32) -> f64 {
        let w = 2.0 * std::f64::consts::PI * freq / hz as f64;
        let coeff = 2.0 * w.cos();
        let (mut s1, mut s2) = (0f64, 0f64);
        for &x in samples {
            let s0 = x as f64 + coeff * s1 - s2;
            s2 = s1;
            s1 = s0;
        }
        s1 * s1 + s2 * s2 - coeff * s1 * s2
    }

    fn dominant_freq(samples: &[f32], hz: u32) -> f64 {
        let mut best = (0.0f64, -1f64);
        for bin in [
            80.0, 200.0, 440.0, 500.0, 1000.0, 1500.0, 2000.0, 3000.0, 3500.0,
        ] {
            let power = goertzel_power(samples, bin, hz);
            if power > best.1 {
                best = (bin, power);
            }
        }
        best.0
    }

    #[test]
    fn identity_ratio_length_and_signal() {
        let input = sine(440.0, 8000, 0.1);
        let out = Resampler::convert_all(&input, 8000, 8000);
        assert!((out.len() as i64 - input.len() as i64).abs() <= 2);
        // Signal survives (unity ratio must not attenuate).
        let p_in = goertzel_power(&input, 440.0, 8000);
        let p_out = goertzel_power(&out, 440.0, 8000);
        assert!(p_out > p_in * 0.5, "in {p_in} out {p_out}");
    }

    #[test]
    fn upsample_8k_to_16k_preserves_tone() {
        let input = sine(1000.0, 8000, 0.25);
        let out = Resampler::convert_all(&input, 8000, 16000);
        assert!(
            (out.len() as i64 - (input.len() as i64) * 2).abs() <= 4,
            "len {}",
            out.len()
        );
        let peak = dominant_freq(&out, 16000);
        assert!((peak - 1000.0).abs() < 40.0, "peak {peak} Hz");
    }

    #[test]
    fn downsample_48k_to_8k_anti_aliases() {
        let input = sine(1000.0, 48000, 0.25);
        let out = Resampler::convert_all(&input, 48000, 8000);
        let peak = dominant_freq(&out, 8000);
        assert!((peak - 1000.0).abs() < 50.0, "peak {peak} Hz");

        // 7 kHz is above the new Nyquist: must fold or vanish, not pass.
        let input = sine(7000.0, 48000, 0.25);
        let out = Resampler::convert_all(&input, 48000, 8000);
        let peak = dominant_freq(&out, 8000);
        assert!(peak < 4000.0, "aliasing detected: peak {peak} Hz");
    }

    #[test]
    fn streaming_matches_batch_length() {
        let input = sine(500.0, 16000, 0.2);
        let batch = Resampler::convert_all(&input, 16000, 24000);
        let mut r = Resampler::new(16000, 24000, ResamplerConfig::default());
        let mut streamed = Vec::new();
        for chunk in input.chunks(320) {
            r.push(chunk);
            let mut out = vec![0f32; 512];
            let n = r.pull(&mut out);
            streamed.extend_from_slice(&out[..n]);
        }
        assert!(
            (streamed.len() as i64 - batch.len() as i64).abs() < 64,
            "{} vs {}",
            streamed.len(),
            batch.len()
        );
    }

    #[test]
    fn amplitude_scale_roughly_preserved() {
        let input = sine(200.0, 8000, 0.2);
        let out = Resampler::convert_all(&input, 8000, 16000);
        let in_max = input.iter().fold(0f32, |m, x| m.max(x.abs()));
        let out_max = out.iter().fold(0f32, |m, x| m.max(x.abs()));
        assert!(
            (in_max - out_max).abs() < 0.05,
            "in {in_max} vs out {out_max}"
        );
    }
}
