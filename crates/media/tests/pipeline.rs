//! Integration: codecs + media pipeline.
//!
//! Exercises the full decode → VAD → mix → resample → record chain with
//! real G.711 codecs, validating the WAV output and the resampler's role
//! in bridging 8 kHz legs onto the 16 kHz conference bridge.

use codecs::{CodecId, Registry};
use media::{Format, Mixer, Recorder, Resampler, Vad};

fn tone(freq: f64, amp: f32, rate: u32, samples: usize) -> Vec<i16> {
    let a = (amp.clamp(0.0, 1.0) * 32767.0) as f64;
    (0..samples)
        .map(|i| (a * (2.0 * std::f64::consts::PI * freq * i as f64 / rate as f64).sin()) as i16)
        .collect()
}

#[test]
fn pcmu_decode_vad_mix_record_pipeline() {
    // Two "legs": leg A speaks 440 Hz, leg B speaks 600 Hz. Both are
    // encoded as PCMU (8 kHz, 20 ms frames), decoded, mixed on the 16 kHz
    // bridge, and recorded to WAV.
    let mut enc_a = Registry::encoder(CodecId::Pcmu, 8000, 1).unwrap();
    let mut dec_a = Registry::decoder(CodecId::Pcmu, 8000, 1).unwrap();
    let mut enc_b = Registry::encoder(CodecId::Pcmu, 8000, 1).unwrap();
    let mut dec_b = Registry::decoder(CodecId::Pcmu, 8000, 1).unwrap();

    let frame_8k = 160; // 20 ms at 8 kHz
    let rate_frames = 100; // 2 seconds

    // Resampler per leg: 8k → 16k bridge rate.
    let mut rs_a = Resampler::new(8000, 16000, Default::default());
    let mut rs_b = Resampler::new(8000, 16000, Default::default());

    let mut mixer = Mixer::new(16000);
    mixer.add_input(1);
    mixer.add_input(2);
    let mut vad_a = Vad::new(16000);
    let mut recorder = Recorder::new(16000, 1, Format::Pcm16);

    for n in 0..rate_frames {
        // Leg B is silent for the first half (simulated speech pattern).
        let pcm_a = tone(440.0, 0.4, 8000, frame_8k);
        let pcm_b = if n < 50 {
            vec![0i16; frame_8k]
        } else {
            tone(600.0, 0.4, 8000, frame_8k)
        };

        let mut wa = Vec::new();
        enc_a.encode(&pcm_a, &mut wa).unwrap();
        let mut pcm_a = Vec::new();
        dec_a.decode(&wa, &mut pcm_a).unwrap();

        let mut wb = Vec::new();
        enc_b.encode(&pcm_b, &mut wb).unwrap();
        let mut pcm_b = Vec::new();
        dec_b.decode(&wb, &mut pcm_b).unwrap();

        let fl_a: Vec<f32> = pcm_a.iter().map(|s| *s as f32 / 32768.0).collect();
        let fl_b: Vec<f32> = pcm_b.iter().map(|s| *s as f32 / 32768.0).collect();
        rs_a.push(&fl_a);
        rs_b.push(&fl_b);

        let mut up_a = vec![0f32; 320];
        let mut up_b = vec![0f32; 320];
        let na = rs_a.pull(&mut up_a);
        let nb = rs_b.pull(&mut up_b);
        let _ = (na, nb);

        let frame16_a: Vec<i16> = up_a.iter().map(|x| (*x * 32767.0) as i16).collect();
        let frame16_b: Vec<i16> = up_b.iter().map(|x| (*x * 32767.0) as i16).collect();

        let active_a = vad_a.process(&frame16_a);
        mixer.push_frame(1, &frame16_a, active_a);
        mixer.push_frame(2, &frame16_b, true);
        let mixed = mixer.mix();
        recorder.write_pcm16(&mixed);
    }

    // Record ~2 s of conference audio (± resampler warmup).
    let dur = recorder.duration_secs();
    assert!((1.8..2.2).contains(&dur), "recorded {dur}s expected ~2s");
    let wav = recorder.finalize();
    assert_eq!(&wav[..4], b"RIFF");
    assert!(wav.len() > 44 + 16000 * 2);

    // Non-silence actually recorded: peak must be well above zero.
    let peak = wav[44..]
        .chunks(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .fold(0i32, |m, s| m.max(s.abs() as i32));
    assert!(peak > 4000, "recorded audio peak {peak} too small");
}
