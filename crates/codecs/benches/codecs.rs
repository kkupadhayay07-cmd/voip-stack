//! Codec throughput benchmarks (criterion): per-second audio encode/decode
//! for every Phase-1 codec plus the resampler.

use codecs::{CodecId, Registry};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn tone(rate: u32, seconds: usize) -> Vec<i16> {
    let n = rate as usize * seconds;
    (0..n)
        .map(|i| {
            (f64::from(i as u32) * 220.0 * std::f64::consts::TAU / f64::from(rate)).sin() * 9000.0
        })
        .map(|v| v.clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16)
        .collect()
}

fn bench_codec(c: &mut Criterion, id: CodecId, rate: u32, label: &str) {
    let mut g = c.benchmark_group(label.to_string());
    g.throughput(Throughput::Elements(u64::from(rate)));
    let pcm = tone(rate, 1);

    g.bench_function(format!("{label}_encode_1s"), |b| {
        b.iter(|| {
            let mut enc = Registry::encoder(id, rate, 1).unwrap();
            let frame = enc.frame_samples();
            let mut total = 0usize;
            for chunk in black_box(&pcm).chunks(frame) {
                let mut wire = Vec::new();
                total += enc.encode(chunk, &mut wire).unwrap_or(0);
            }
            total
        })
    });

    let payloads: Vec<Vec<u8>> = {
        let mut enc = Registry::encoder(id, rate, 1).unwrap();
        let frame = enc.frame_samples();
        let mut out = Vec::new();
        for chunk in pcm.chunks(frame) {
            let mut wire = Vec::new();
            let _ = enc.encode(chunk, &mut wire);
            out.push(wire);
        }
        out
    };
    g.bench_function(format!("{label}_decode_1s"), |b| {
        b.iter(|| {
            let mut dec = Registry::decoder(id, rate, 1).unwrap();
            let mut total = 0usize;
            for p in black_box(&payloads) {
                let mut pcm_out = Vec::new();
                total += dec.decode(p, &mut pcm_out).unwrap_or(0);
            }
            total
        })
    });
    g.finish();
}

fn bench_resample(c: &mut Criterion) {
    let mut g = c.benchmark_group("resample");
    g.throughput(Throughput::Elements(8000));
    let pcm8 = tone(8000, 1);
    g.bench_function("8k_to_16k_1s", |b| {
        b.iter(|| {
            let mut r = codecs::Resampler::new(8000, 16000, 1).unwrap();
            let mut out = Vec::new();
            for chunk in black_box(&pcm8).chunks(160) {
                r.process(chunk, &mut out);
            }
            out.len()
        })
    });
    g.finish();
}

fn all_codecs(c: &mut Criterion) {
    bench_codec(c, CodecId::Pcmu, 8000, "pcmu");
    bench_codec(c, CodecId::Pcma, 8000, "pcma");
    bench_codec(c, CodecId::G722, 8000, "g722"); // wire clock 8000; PCM is 16k internally
    bench_codec(c, CodecId::G729, 8000, "g729");
    bench_codec(c, CodecId::Opus, 48000, "opus");
}

criterion_group!(benches, all_codecs, bench_resample);
criterion_main!(benches);
