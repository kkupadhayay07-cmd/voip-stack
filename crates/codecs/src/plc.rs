//! Packet-loss concealment strategies shared by all decoders.
//!
//! [`PitchPlc`] implements a G.711 Appendix-I-style waveform concealment:
//! it tracks recent good audio, finds the pitch period by normalized
//! autocorrelation at loss time, and repeats that period with progressive
//! decay. [`EnergyDecayPlc`] and [`SilencePlc`] are simpler fallbacks.

/// Common PLC interface.
pub trait Plc: Send {
    /// Feed a correctly decoded frame (keeps history fresh).
    fn feed(&mut self, frame: &[i16]);
    /// Synthesize a concealed frame, appending to `out`; returns samples added.
    fn conceal(&mut self, out: &mut Vec<i16>) -> usize;
    /// Clear all history.
    fn reset(&mut self);
}

/// Pitch-repeat waveform concealment (G.711 App I-lite).
pub struct PitchPlc {
    history: Vec<i16>,
    /// Pitch range searched, in samples.
    min_pitch: usize,
    max_pitch: usize,
    losses: usize,
    frame_len: usize,
    /// Cached pitch period (from the last good audio).
    period: Option<Vec<i16>>,
}

const MAX_HISTORY: usize = 800; // 100 ms @ 8 kHz

impl PitchPlc {
    /// Create a pitch PLC with default pitch bounds for 8 kHz audio.
    pub fn new() -> PitchPlc {
        PitchPlc {
            history: Vec::with_capacity(MAX_HISTORY),
            min_pitch: 44,
            max_pitch: 160,
            losses: 0,
            frame_len: 160,
            period: None,
        }
    }

    /// Override the frame length used for concealment output.
    pub fn with_frame_len(mut self, frame_len: usize) -> PitchPlc {
        self.frame_len = frame_len.max(1);
        self
    }

    /// Find the pitch period within the recent history window.
    fn find_pitch(&self) -> Option<Vec<i16>> {
        let n = self.history.len();
        if n < self.max_pitch * 2 {
            return None;
        }
        let win_start = n - self.max_pitch;
        let win = &self.history[win_start..];
        let w_energy: f64 = win.iter().map(|&s| (s as f64) * (s as f64)).sum();
        if w_energy < 1.0 {
            return None;
        }
        let mut best = 0usize;
        let mut best_score = 0.0f64;
        for p in self.min_pitch..=self.max_pitch {
            // Comparison window of the SAME length, p samples earlier.
            let prev = &self.history[win_start - p..n - p];
            let mut corr = 0.0f64;
            let mut p_energy = 0.0f64;
            for i in 0..self.max_pitch {
                let a = win[i] as f64;
                let b = prev[i] as f64;
                corr += a * b;
                p_energy += b * b;
            }
            if p_energy < 1.0 {
                continue;
            }
            let score = corr / (w_energy.sqrt() * p_energy.sqrt());
            if score > best_score {
                best_score = score;
                best = p;
            }
        }
        if best_score <= 0.5 {
            return None;
        }
        Some(self.history[n - best..].to_vec())
    }
}

impl Default for PitchPlc {
    fn default() -> PitchPlc {
        PitchPlc::new()
    }
}

impl Plc for PitchPlc {
    fn feed(&mut self, frame: &[i16]) {
        self.losses = 0;
        self.frame_len = frame.len().max(1);
        for &s in frame {
            self.history.push(s);
        }
        if self.history.len() > MAX_HISTORY {
            let excess = self.history.len() - MAX_HISTORY;
            self.history.drain(0..excess);
        }
        // Refresh the cached period from clean audio.
        self.period = self.find_pitch();
    }

    fn conceal(&mut self, out: &mut Vec<i16>) -> usize {
        self.losses += 1;
        let decay = 0.80f64.powi(self.losses as i32);
        match (&self.period, decay) {
            (Some(p), d) if d >= 0.01 && !p.is_empty() => {
                let period = p.len();
                let skip = (self.losses - 1) * self.frame_len;
                for i in 0..self.frame_len {
                    let idx = (skip + i) % period;
                    let s = p[idx] as f64 * d;
                    out.push(s.clamp(-32_768.0, 32_767.0) as i16);
                }
            }
            _ => {
                for _ in 0..self.frame_len {
                    out.push(0);
                }
            }
        }
        self.frame_len
    }

    fn reset(&mut self) {
        self.history.clear();
        self.losses = 0;
        self.period = None;
    }
}

/// Repeats the last frame with geometric decay; silent after 8 losses.
pub struct EnergyDecayPlc {
    last: Vec<i16>,
    losses: usize,
    frame_len: usize,
}

impl EnergyDecayPlc {
    /// Create with the given expected frame length.
    pub fn new(frame_len: usize) -> EnergyDecayPlc {
        EnergyDecayPlc {
            last: Vec::new(),
            losses: 0,
            frame_len: frame_len.max(1),
        }
    }
}

impl Plc for EnergyDecayPlc {
    fn feed(&mut self, frame: &[i16]) {
        self.losses = 0;
        self.frame_len = frame.len().max(1);
        self.last = frame.to_vec();
    }

    fn conceal(&mut self, out: &mut Vec<i16>) -> usize {
        self.losses += 1;
        if self.last.is_empty() || self.losses > 8 {
            for _ in 0..self.frame_len {
                out.push(0);
            }
            return self.frame_len;
        }
        let decay = 0.7f64.powi(self.losses as i32);
        for &s in &self.last {
            out.push((s as f64 * decay) as i16);
        }
        self.frame_len
    }

    fn reset(&mut self) {
        self.last.clear();
        self.losses = 0;
    }
}

/// Outputs silence.
#[derive(Debug, Clone, Default)]
pub struct SilencePlc {
    frame_len: usize,
}

impl SilencePlc {
    /// Create with the given expected frame length.
    pub fn new(frame_len: usize) -> SilencePlc {
        SilencePlc {
            frame_len: frame_len.max(1),
        }
    }
}

impl Plc for SilencePlc {
    fn feed(&mut self, _frame: &[i16]) {}

    fn conceal(&mut self, out: &mut Vec<i16>) -> usize {
        for _ in 0..self.frame_len {
            out.push(0);
        }
        self.frame_len
    }

    fn reset(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 150 Hz voiced-ish signal @ 8 kHz with harmonics.
    fn voiced(n: usize, start_index: usize) -> Vec<i16> {
        (0..n)
            .map(|i| {
                let t = (start_index + i) as f64 / 8000.0;
                let f0 = 150.0;
                let v = (2.0 * std::f64::consts::PI * f0 * t).sin()
                    + 0.5 * (2.0 * std::f64::consts::PI * 2.0 * f0 * t).sin()
                    + 0.25 * (2.0 * std::f64::consts::PI * 3.0 * f0 * t).sin();
                (v * 8000.0) as i16
            })
            .collect()
    }

    fn snr_db(a: &[i16], b: &[i16]) -> f64 {
        let mut sig = 0.0;
        let mut err = 0.0;
        for i in 0..a.len().min(b.len()) {
            sig += (a[i] as f64) * (a[i] as f64);
            let d = a[i] as f64 - b[i] as f64;
            err += d * d;
        }
        10.0 * (sig / err.max(1.0)).log10()
    }

    #[test]
    fn pitch_plc_recovers_voiced_continuation() {
        let mut plc = PitchPlc::new();
        let mut idx = 0usize;
        for _ in 0..8 {
            plc.feed(&voiced(160, idx));
            idx += 160;
        }
        let mut out = Vec::new();
        plc.conceal(&mut out);
        // Truth continues from index `idx`; the concealment repeats the last
        // pitch period, which stays phase-coherent for a periodic signal.
        let truth = voiced(160, idx);
        let q = snr_db(&truth, &out);
        assert!(q > 6.0, "concealment SNR {q} dB below 6 dB");
        assert_eq!(out.len(), 160);
    }

    #[test]
    fn pitch_plc_energy_decays_with_losses() {
        let mut plc = PitchPlc::new();
        // Feed enough history (≥ 2·max_pitch) for pitch detection.
        let mut idx = 0usize;
        for _ in 0..4 {
            plc.feed(&voiced(160, idx));
            idx += 160;
        }
        let mut energies = Vec::new();
        for _ in 0..3 {
            let mut out = Vec::new();
            plc.conceal(&mut out);
            let e: f64 = out.iter().map(|&s| (s as f64) * (s as f64)).sum();
            assert!(e > 0.0, "must conceal with waveform, not silence");
            energies.push(e);
        }
        assert!(
            energies[1] < energies[0] && energies[2] < energies[1],
            "energies must decay: {energies:?}"
        );
        // After enough losses the decay floor (0.01) turns output to silence
        // (0.8^22 < 0.01); loop 22 more times.
        let mut out = Vec::new();
        for _ in 0..22 {
            out.clear();
            plc.conceal(&mut out);
        }
        assert!(out.iter().all(|&s| s == 0), "deep loss → silence");
    }

    #[test]
    fn pitch_plc_reset_and_silence_input() {
        let mut plc = PitchPlc::new();
        plc.feed(&[0i16; 160]);
        let mut out = Vec::new();
        plc.conceal(&mut out);
        assert!(out.iter().all(|&s| s == 0), "silence input → silence out");
        plc.feed(&voiced(160, 0));
        plc.reset();
        let mut out2 = Vec::new();
        plc.conceal(&mut out2);
        assert!(out2.iter().all(|&s| s == 0), "after reset → silence");
    }

    #[test]
    fn pitch_plc_short_history_is_silent() {
        let mut plc = PitchPlc::new();
        plc.feed(&voiced(10, 0)); // below 2*max_pitch history
        let mut out = Vec::new();
        plc.conceal(&mut out);
        assert!(out.iter().all(|&s| s == 0));
    }

    #[test]
    fn energy_decay_plc_monotonic() {
        let mut plc = EnergyDecayPlc::new(160);
        plc.feed(&voiced(160, 0));
        let mut prev = f64::MAX;
        for _ in 0..5 {
            let mut out = Vec::new();
            plc.conceal(&mut out);
            assert_eq!(out.len(), 160);
            let e: f64 = out.iter().map(|&s| (s as f64) * (s as f64)).sum();
            assert!(e <= prev, "energy must be non-increasing");
            prev = e;
        }
        // After 8 losses output is silence.
        let mut out = Vec::new();
        for _ in 0..8 {
            out.clear();
            plc.conceal(&mut out);
        }
        assert!(out.iter().all(|&s| s == 0), "deep loss → silence");
    }

    #[test]
    fn silence_plc_outputs_zeros() {
        let mut plc = SilencePlc::new(160);
        plc.feed(&voiced(160, 0));
        let mut out = Vec::new();
        assert_eq!(plc.conceal(&mut out), 160);
        assert!(out.iter().all(|&s| s == 0));
        plc.reset();
    }

    #[test]
    fn plc_traits_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PitchPlc>();
        assert_send::<EnergyDecayPlc>();
        assert_send::<SilencePlc>();
    }
}
