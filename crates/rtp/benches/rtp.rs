use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rtp::jitter::{JitterBuffer, JitterConfig, PushResult};
use rtp::rtcp::{parse_compound, ReportBlock, RtcpPacket, SenderInfo};
use rtp::RtpPacket;

fn bench_rtp_parse(c: &mut Criterion) {
    let pkt = RtpPacket::new(
        0,
        42,
        640,
        0xCAFEBABE,
        false,
        Bytes::from(vec![0x55u8; 160]),
    );
    let wire = pkt.encode();
    c.bench_function("rtp_parse_160b", |b| {
        b.iter(|| RtpPacket::parse(black_box(&wire)).unwrap())
    });
    c.bench_function("rtp_encode_160b", |b| b.iter(|| black_box(pkt.encode())));
}

fn bench_rtcp(c: &mut Criterion) {
    let sr = RtcpPacket::SenderReport(
        SenderInfo {
            ssrc: 1,
            ntp_sec: 2,
            ntp_frac: 3,
            rtp_timestamp: 4,
            packet_count: 5,
            octet_count: 6,
        },
        vec![
            ReportBlock {
                ssrc: 9,
                fraction_lost: 0,
                cumulative_lost: 0,
                highest_sequence: 1,
                interarrival_jitter: 2,
                last_sr: 3,
                delay_since_last_sr: 4,
            };
            3
        ],
    );
    let wire = rtp::rtcp::encode_packet(&sr);
    c.bench_function("rtcp_sr_parse", |b| {
        b.iter(|| parse_compound(black_box(&wire)).unwrap())
    });
}

fn bench_jitter(c: &mut Criterion) {
    c.bench_function("jitter_push_pop_20ms", |b| {
        b.iter_batched(
            || JitterBuffer::new(JitterConfig::for_clock(8000)),
            |mut jb| {
                let mut now = 0u64;
                let mut seq = 0u16;
                let mut ts = 0u32;
                for _ in 0..100 {
                    let r = jb.push(1, seq, ts, false, 0, vec![0u8; 160], now);
                    assert_eq!(r, PushResult::Buffered);
                    while let Some(_f) = jb.pop_ready(now) {}
                    seq = seq.wrapping_add(1);
                    ts = ts.wrapping_add(160);
                    now += 20;
                }
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_jitter_conceal(c: &mut Criterion) {
    c.bench_function("jitter_conceal_path", |b| {
        b.iter_batched(
            || JitterBuffer::new(JitterConfig::for_clock(8000)),
            |mut jb| {
                jb.push(1, 0, 0, false, 0, vec![0u8; 160], 0);
                jb.pop_ready(30);
                let mut now = 70u64;
                for _ in 0..100 {
                    // nothing arrives: pure PLC path
                    while let Some(_f) = jb.conceal(now) {}
                    now += 20;
                }
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_rtp_parse,
    bench_rtcp,
    bench_jitter,
    bench_jitter_conceal
);
criterion_main!(benches);
