//! Stable-runnable fuzz smoke corpus for the RTP packet parser and the
//! RFC 4733 DTMF payload parser.
//!
//! Handcrafted nasty inputs fed through the same public entry points as
//! `fuzz/fuzz_targets/parse_rtp.rs` and `parse_dtmf.rs`. Property: **the
//! parsers return `Result` for any input and never panic.**
//!
//! Run on stable CI via `cargo test -p rtp --test fuzz_smoke`.

use rtp::packet::RtpPacket;
use rtp::{dtmf, looks_like_rtcp};

fn rtp_parse_no_panic(corpus: &[&[u8]]) {
    for input in corpus {
        // Err is fine; a panic fails the test.
        let _ = RtpPacket::parse(input);
        let _ = looks_like_rtcp(input);
    }
}

fn dtmf_parse_no_panic(corpus: &[&[u8]]) {
    for input in corpus {
        let _ = dtmf::parse_event(input);
    }
}

#[test]
fn rtp_parser_survives_malformed_corpus() {
    let csrc_declared_no_data: Vec<u8> =
        vec![0x8F, 0x00, 0x00, 0x01, 0, 0, 0, 1]; // CC=15, no CSRC bytes
    let ext_huge_len: Vec<u8> = vec![
        0x90, 0x00, 0x00, 0x01, // X=1, CC=0
        0, 0, 0, 1, // SSRC
        0xBE, 0xDE, // profile
        0xFF, 0xFF, // declared ext length 65535 words, none present
    ];
    let ext_truncated: Vec<u8> = vec![
        0x90, 0x00, 0x00, 0x01, 0, 0, 0, 1, 0xBE, 0xDE, // header only, 1 short
    ];
    let pad_zero: Vec<u8> = vec![
        0xA0, 0x00, 0x00, 0x01, 0, 0, 0, 1, // P=1, padding count byte 0
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, // payload with trailing 0 pad byte
    ];
    let pad_too_big: Vec<u8> = vec![
        0xA0, 0x00, 0x00, 0x01, 0, 0, 0, 1, 0xAA, 0xBB, 0xFF, // pad byte 255 > len
    ];
    let huge_packet: Vec<u8> = vec![0xFF; 65_536];
    let all_zero: Vec<u8> = vec![0; 1400];

    let corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x80],
        vec![0x80, 0x00],
        vec![0x00, 0x00, 0x00, 0x01], // version 0
        vec![0x40, 0x00, 0x00, 0x01], // version 1
        vec![0xC0, 0x00, 0x00, 0x01], // version 3
        vec![0x80, 0x00, 0x00, 0x01], // truncated (no SSRC)
        vec![0x80, 0x7F, 0xFF, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF], // marker+pt 127, no payload
        vec![0x80, 0xFF, 0x00, 0x01], // marker + pt 127 byte pattern
        vec![0x81, 0xE0, 0x00, 0x01], // marker + pt 96
        csrc_declared_no_data,
        ext_huge_len,
        ext_truncated,
        pad_zero,
        pad_too_big,
        huge_packet,
        all_zero,
    ];
    let refs: Vec<&[u8]> = corpus.iter().map(|v| v.as_slice()).collect();
    rtp_parse_no_panic(&refs);
}

#[test]
fn rtp_parser_survives_random_byte_blobs() {
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for seed in 0u8..16 {
        let mut v = Vec::new();
        let mut state = u32::from(seed).wrapping_mul(0x9E3779B9) | 0x80u32 << 24;
        for _ in 0..256 {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            v.push((state >> 16) as u8);
        }
        // First two bytes forced into plausible header space so the parser
        // actually walks the packet instead of bailing at version check.
        v[0] = 0x80 | (seed & 0x0F); // version 2, CC/P/X vary
        v[1] = seed.wrapping_mul(7);
        blobs.push(v);
    }
    let refs: Vec<&[u8]> = blobs.iter().map(|v| v.as_slice()).collect();
    rtp_parse_no_panic(&refs);
}

#[test]
fn dtmf_parser_survives_malformed_corpus() {
    let corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x05],
        vec![0x05, 0x80],
        vec![0x05, 0x80, 0x10],
        vec![0x05, 0x80, 0x10, 0x00, 0x00], // 5 bytes (longer than 4, fine)
        vec![0xFF, 0xFF, 0xFF, 0xFF],       // all flags set, max volume/duration
        vec![0x00, 0x40, 0x00, 0x00],       // reserved bit set
        vec![0x0B, 0xC0, 0xFF, 0xFF],       // end + reserved, duration 65535
        vec![0x10, 0x3F, 0x80, 0x00],       // event code 16 (undefined range)
        vec![0x00, 0x00, 0x00, 0x00],       // all-zero event
    ];
    let refs: Vec<&[u8]> = corpus.iter().map(|v| v.as_slice()).collect();
    dtmf_parse_no_panic(&refs);
}
