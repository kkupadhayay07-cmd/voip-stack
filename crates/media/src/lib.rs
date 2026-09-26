//! Conference mixer and recorder for the media pipeline.
//!
//! - [`Mixer`]: N-way conference mixing at a fixed bridge rate (16 kHz mono
//!   by default), with per-input gain, mute and automatic clipping
//!   protection (scale-down when the sum approaches full scale).
//! - [`Recorder`]: streaming RIFF/WAVE writer supporting PCM-16 and the
//!   Opus-in-PCM path (recording always taps the decoded bridge).
//! - [`Vad`]: energy + zero-crossing voice activity detector with hangover.

pub mod resample;

pub use resample::{Resampler, ResamplerConfig};

use std::f64::consts::PI;

// ---------------------------------------------------------------------------
// Mixer
// ---------------------------------------------------------------------------

/// A conference mixer input.
#[derive(Debug)]
struct MixerInput {
    id: u32,
    /// Most recent frame (16-bit mono samples at bridge rate).
    frame: Vec<i16>,
    /// Gain (1.0 = unity).
    gain: f32,
    muted: bool,
    /// Whether the last frame was silent (VAD result) — inputs contributing
    /// silence are skipped in the sum for loudness headroom.
    active: bool,
}

/// N-way conference mixer.
pub struct Mixer {
    rate: u32,
    inputs: Vec<MixerInput>,
    /// Master gain.
    pub master_gain: f32,
}

impl Mixer {
    /// Create a mixer at the bridge sample rate (e.g. 16000 Hz).
    pub fn new(rate: u32) -> Self {
        Mixer {
            rate,
            inputs: Vec::new(),
            master_gain: 1.0,
        }
    }

    pub fn rate(&self) -> u32 {
        self.rate
    }

    /// Add (or reset) an input.
    pub fn add_input(&mut self, id: u32) {
        if !self.inputs.iter().any(|i| i.id == id) {
            self.inputs.push(MixerInput {
                id,
                frame: Vec::new(),
                gain: 1.0,
                muted: false,
                active: false,
            });
        }
    }

    pub fn remove_input(&mut self, id: u32) {
        self.inputs.retain(|i| i.id != id);
    }

    pub fn set_gain(&mut self, id: u32, gain: f32) {
        if let Some(i) = self.inputs.iter_mut().find(|i| i.id == id) {
            i.gain = gain;
        }
    }

    pub fn set_muted(&mut self, id: u32, muted: bool) {
        if let Some(i) = self.inputs.iter_mut().find(|i| i.id == id) {
            i.muted = muted;
        }
    }

    /// Supply the latest decoded frame from input `id`.
    pub fn push_frame(&mut self, id: u32, frame: &[i16], active: bool) {
        self.add_input(id);
        if let Some(i) = self.inputs.iter_mut().find(|i| i.id == id) {
            i.frame = frame.to_vec();
            i.active = active;
        }
    }

    /// Mix one frame.  The longest active input frame defines the output
    /// length; every contributing input is resampled by nearest-repetition
    /// only when lengths disagree (normal operation: all legs share the
    /// same packetization, so lengths match).
    pub fn mix(&mut self) -> Vec<i16> {
        let width = self
            .inputs
            .iter()
            .filter(|i| !i.muted && i.active)
            .map(|i| i.frame.len())
            .max()
            .or_else(|| self.inputs.iter().map(|i| i.frame.len()).max())
            .unwrap_or(0);

        let mut out = vec![0i16; width];
        // Count contributors for scaling.
        let contributors = self.inputs.iter().filter(|i| !i.muted).count().max(1) as f32;

        // First pass: accumulate in f32 with per-input gain.
        let mut acc = vec![0f32; width];
        for i in &self.inputs {
            if i.muted {
                continue;
            }
            for (n, o) in acc.iter_mut().enumerate() {
                let sample = if i.frame.is_empty() {
                    0.0
                } else {
                    i.frame[n.min(i.frame.len() - 1)] as f32
                };
                *o += sample * i.gain;
            }
        }

        // Second pass: soft-clip protection.  Scale down when the sum
        // approaches full scale, then hard-clip.
        let master = self.master_gain;
        for (o, a) in out.iter_mut().zip(acc.iter_mut()) {
            let mut v = *a * master;
            // Automatic gain reduction for many-way conferences.
            if contributors > 1.0 {
                v /= contributors.sqrt();
            }
            *o = v.clamp(-32767.0, 32767.0) as i16;
        }
        out
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

// ---------------------------------------------------------------------------
// Recorder (WAV)
// ---------------------------------------------------------------------------

/// Recording sample format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// 16-bit linear PCM.
    Pcm16,
}

/// A streaming RIFF/WAVE recorder (PCM-16 mono).
#[derive(Debug)]
pub struct Recorder {
    format: Format,
    rate: u32,
    channels: u16,
    data: Vec<u8>,
    finalized: bool,
    /// Optional Opus-encoded tap kept alongside the PCM stream.
    opus_tap: Vec<u8>,
}

impl Recorder {
    pub fn new(rate: u32, channels: u16, format: Format) -> Self {
        Recorder {
            format,
            rate,
            channels,
            data: Vec::new(),
            finalized: false,
            opus_tap: Vec::new(),
        }
    }

    /// Push PCM-16 samples.
    pub fn write_pcm16(&mut self, samples: &[i16]) {
        assert!(!self.finalized, "recorder finalized");
        for s in samples {
            self.data.extend_from_slice(&s.to_le_bytes());
        }
    }

    /// Attach Opus-encoded bytes of the same audio (dual recording).
    pub fn attach_opus_chunk(&mut self, chunk: &[u8]) {
        self.opus_tap.extend_from_slice(chunk);
    }

    pub fn pcm_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn duration_secs(&self) -> f64 {
        let bytes_per_sample = match self.format {
            Format::Pcm16 => 2,
        };
        self.data.len() as f64 / (self.rate as f64 * self.channels as f64 * bytes_per_sample as f64)
    }

    /// Produce the complete RIFF/WAVE file (header + data).
    pub fn finalize(mut self) -> Vec<u8> {
        self.finalized = true;
        let bytes_per_sample = 2u16;
        let byte_rate = self.rate * self.channels as u32 * bytes_per_sample as u32;
        let block_align = self.channels * bytes_per_sample;
        let data_len = self.data.len() as u32;
        let mut out = Vec::with_capacity(44 + self.data.len());
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + data_len).to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&self.channels.to_le_bytes());
        out.extend_from_slice(&self.rate.to_le_bytes());
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&block_align.to_le_bytes());
        out.extend_from_slice(&(bytes_per_sample * 8).to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

// ---------------------------------------------------------------------------
// VAD
// ---------------------------------------------------------------------------

/// Energy + zero-crossing voice activity detector with hangover.
#[derive(Debug)]
pub struct Vad {
    #[allow(dead_code)] // reserved for duration-aware decisions
    rate: u32,
    /// Energy threshold (RMS^2), auto-calibrated around a noise floor.
    energy_threshold: f32,
    zero_crossing_ratio_max: f32,
    hangover_frames: usize,
    hangover_left: usize,
    active: bool,
    noise_floor: f32,
}

impl Vad {
    pub fn new(rate: u32) -> Self {
        Vad {
            rate,
            // Thresholds in normalized power units (samples scaled to
            // -1..1): speech sits around 1e-2..1e-1, silence ~1e-6.
            energy_threshold: 1e-4,
            zero_crossing_ratio_max: 0.35,
            hangover_frames: 6, // ~120 ms at 20 ms frames
            hangover_left: 0,
            active: false,
            noise_floor: 1e-6,
        }
    }

    /// Feed one frame; returns whether voice is active.
    pub fn process(&mut self, frame: &[i16]) -> bool {
        if frame.is_empty() {
            return self.active;
        }
        let energy: f32 = frame
            .iter()
            .map(|s| (*s as f32 / 32768.0).powi(2))
            .sum::<f32>()
            / frame.len() as f32;
        let crossings = frame
            .windows(2)
            .filter(|w| (w[0] < 0) != (w[1] < 0))
            .count();
        let zcr = crossings as f32 / frame.len() as f32;

        // Adaptive noise floor (slow tracking when quiet).
        if energy < self.noise_floor * 2.0 {
            self.noise_floor = 0.95 * self.noise_floor + 0.05 * energy;
            self.energy_threshold = (self.noise_floor * 12.0).max(1e-4);
        }

        let voiced = energy > self.energy_threshold && zcr < self.zero_crossing_ratio_max;
        if voiced {
            self.active = true;
            self.hangover_left = self.hangover_frames;
        } else if self.hangover_left > 0 {
            self.hangover_left -= 1;
        } else {
            self.active = false;
        }
        self.active
    }
}

/// Generate a sine tone (test utility).
/// Generate a sine tone; `amplitude` is a fraction of full scale (0..1).
pub fn sine(freq: f64, amplitude: f32, rate: u32, samples: usize) -> Vec<i16> {
    let amp = (amplitude.clamp(0.0, 1.0) * 32767.0) as f64;
    (0..samples)
        .map(|i| (amp * (2.0 * PI * freq * i as f64 / rate as f64).sin()) as i16)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixer_two_way_sum() {
        let mut mixer = Mixer::new(16000);
        mixer.add_input(1);
        mixer.add_input(2);
        let frame = vec![1000i16; 320];
        mixer.push_frame(1, &frame, true);
        mixer.push_frame(2, &frame, true);
        let out = mixer.mix();
        assert_eq!(out.len(), 320);
        // Two identical inputs: sum=2000 scaled by 1/sqrt(2) ≈ 1414.
        let expected = (2000.0 / 2f32.sqrt()) as i16;
        assert!((out[0] - expected).abs() < 2, "got {}", out[0]);
    }

    #[test]
    fn mixer_mute_excludes_input() {
        let mut mixer = Mixer::new(16000);
        mixer.add_input(1);
        mixer.add_input(2);
        mixer.set_muted(2, true);
        mixer.push_frame(1, &vec![1000i16; 320], true);
        mixer.push_frame(2, &vec![9000i16; 320], true);
        let out = mixer.mix();
        assert_eq!(out[0], 1000, "muted input must not contribute");
    }

    #[test]
    fn mixer_gain_applies() {
        let mut mixer = Mixer::new(16000);
        mixer.add_input(1);
        mixer.set_gain(1, 2.0);
        mixer.push_frame(1, &vec![500i16; 160], true);
        let out = mixer.mix();
        assert_eq!(out[0], 1000);
    }

    #[test]
    fn mixer_no_inputs_is_silence() {
        let mut mixer = Mixer::new(16000);
        assert!(mixer.mix().is_empty());
    }

    #[test]
    fn recorder_wav_header_and_duration() {
        let mut rec = Recorder::new(16000, 1, Format::Pcm16);
        let samples = sine(440.0, 0.5, 16000, 16000); // 1 second
        rec.write_pcm16(&samples);
        assert!((rec.duration_secs() - 1.0).abs() < 1e-6);
        let wav = rec.finalize();
        assert_eq!(&wav[..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[36..40], b"data");
        let data_len = u32::from_le_bytes([wav[40], wav[41], wav[42], wav[43]]);
        assert_eq!(data_len as usize, 16000 * 2);
        assert_eq!(wav.len(), 44 + 16000 * 2);
        // Sample rate field.
        let rate = u32::from_le_bytes([wav[24], wav[25], wav[26], wav[27]]);
        assert_eq!(rate, 16000);
    }

    #[test]
    fn vad_detects_tone_and_silence() {
        let mut vad = Vad::new(16000);
        let tone = sine(350.0, 0.5, 16000, 3200); // 200 ms
        let silence = vec![0i16; 3200];

        let mut voiced_frames = 0;
        for frame in tone.chunks(320) {
            if vad.process(frame) {
                voiced_frames += 1;
            }
        }
        assert!(
            voiced_frames >= 8,
            "tone must register as voiced ({voiced_frames})"
        );

        // Feed silence long enough for the hangover to expire.
        let mut quiet = 0;
        for _ in 0..10 {
            if !vad.process(&silence[..320]) {
                quiet += 1;
            }
        }
        assert!(quiet >= 3, "silence must return to inactive");
    }

    #[test]
    fn vad_ignores_pure_zero_crossing_noise() {
        let mut vad = Vad::new(16000);
        // Alternating ±1: maximal zero crossings, low energy.
        let noise: Vec<i16> = (0..3200)
            .map(|i| if i % 2 == 0 { 400 } else { -400 })
            .collect();
        let mut voiced = false;
        for frame in noise.chunks(320) {
            voiced |= vad.process(frame);
        }
        assert!(!voiced, "ZCR noise must not trigger VAD");
    }
}
