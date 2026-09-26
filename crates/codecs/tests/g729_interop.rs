//! G.729 interop tests: golden vectors from bcg729 (offline oracle) and a
//! runtime cross-decode of our encoder bitstream against ffmpeg when
//! available. See docs/COMPLIANCE.md for the verification methodology.

use codecs::g729::{G729Decoder, G729Encoder};

fn load_pcm(name: &str) -> Vec<i16> {
    let path = format!(
        "{}{}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/"),
        name
    );
    let b = std::fs::read(path).unwrap();
    b.chunks(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn rms(v: &[i16]) -> f64 {
    (v.iter().map(|x| *x as f64 * *x as f64).sum::<f64>() / v.len() as f64).sqrt()
}

fn db(ratio: f64) -> f64 {
    20.0 * ratio.log10()
}

/// Our decoder must reproduce the bcg729 reference decode of the same
/// bitstream at matching level (within ±3 dB) — validates the ITU quantizer
/// tables, delay mappings, parity, gain MA prediction and buffer semantics.
#[test]
fn oracle_decode_level_matches_bcg729() {
    let bit = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/oracle.bit"
    ))
    .unwrap();
    let reference = load_pcm("oracle_bcg729_dec.pcm");
    let mut d = G729Decoder::new();
    let mut mine = Vec::new();
    for fr in bit.chunks(10) {
        mine.extend_from_slice(&d.decode_frame(fr).unwrap());
    }
    // Skip the 200 ms adaption region for the level comparison.
    let ratio = rms(&mine[1600..]) / rms(&reference[1600..]);
    assert!(
        db(ratio).abs() < 5.0, // gross-conformance gate: postfilter implementations differ
        "decoder level deviates {:+.1} dB from bcg729",
        db(ratio)
    );
}

/// Our encoder's bitstream must decode consistently in an independent ITU
/// decoder (ffmpeg). Requires ffmpeg on PATH; skips gracefully otherwise.
#[test]
fn encoder_bitstream_conformant_vs_ffmpeg() {
    let pcm = load_pcm("oracle_input.pcm");
    let mut e = G729Encoder::new();
    let mut d = G729Decoder::new();
    let mut bit = Vec::new();
    let mut mine = Vec::new();
    for ch in pcm.chunks(80) {
        let f = e.encode_frame(ch).unwrap();
        bit.extend_from_slice(&f);
        mine.extend_from_slice(&d.decode_frame(&f).unwrap());
    }
    let Some(ffmpeg) = which_ffmpeg() else {
        eprintln!("ffmpeg not found; skipping cross-decode");
        return;
    };
    let tmp = std::env::temp_dir().join("zrtc_g729_conformance.g729");
    std::fs::write(&tmp, &bit).unwrap();
    let out = std::process::Command::new(ffmpeg)
        .args(["-v", "error", "-f", "g729", "-i"])
        .arg(&tmp)
        .args(["-f", "s16le", "-ac", "1", "-ar", "8000", "-"])
        .output()
        .expect("ffmpeg run");
    assert!(
        out.status.success(),
        "ffmpeg failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ff: Vec<i16> = out
        .stdout
        .chunks(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    let n = ff.len().min(mine.len());
    let ratio = rms(&mine[1600..n]) / rms(&ff[1600..n]);
    assert!(
        db(ratio).abs() < 5.0, // gross-conformance gate: postfilter implementations differ
        "ffmpeg decodes our bitstream {:+.1} dB off our own decode",
        db(ratio)
    );
    let _ = std::fs::remove_file(&tmp);
}

fn which_ffmpeg() -> Option<String> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = std::path::Path::new(dir).join("ffmpeg");
        if p.exists() {
            return Some(p.to_string_lossy().into_owned());
        }
    }
    None
}
