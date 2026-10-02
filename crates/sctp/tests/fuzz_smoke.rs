//! Stable-runnable fuzz smoke corpus for the SCTP wire codec and the DCEP
//! channel parser.
//!
//! Handcrafted nasty inputs plus deterministic pseudo-random mutations fed
//! through the same public entry points as `fuzz/fuzz_targets/
//! parse_sctp_packet.rs` and `parse_dcep.rs`. Property: **the parsers
//! return `Result` for any input and never panic** — in particular,
//! trailing parameters whose 4-byte padding overruns the chunk must stop
//! cleanly instead of slicing out of bounds.
//!
//! Run on stable CI via `cargo test -p sctp --test fuzz_smoke`.

use sctp::crc32c::crc32c;
use sctp::dcep;
use sctp::wire::parse_packet;

/// Deterministic xorshift64* — the same pseudo-random source the engine
/// tests use, so the corpus is reproducible across runs and platforms.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 32) as u8
    }
}

/// Finish a packet: zero the checksum field (common-header bytes 8..12),
/// compute CRC32c over the whole packet, write it back in place.
fn seal(packet: &mut [u8]) {
    packet[8..12].copy_from_slice(&[0; 4]);
    let crc = crc32c(packet);
    packet[8..12].copy_from_slice(&crc.to_be_bytes());
}

/// A syntactically valid INIT packet: common header (src 1, dst 1, vtag 0,
/// CRC), INIT chunk with the 16-byte fixed part and one IPv4 address param.
fn valid_init() -> Vec<u8> {
    // common header
    let mut p: Vec<u8> = [
        0x00, 0x01, // src port 1
        0x00, 0x01, // dst port 1
        0x00, 0x00, 0x00, 0x00, // vtag 0 (INIT rule)
        0x00, 0x00, 0x00, 0x00, // checksum, sealed below
    ]
    .to_vec();
    // INIT chunk: type 0x01, flags 0, length = 4 + 16 + 8
    let mut chunk: Vec<u8> = vec![0x01, 0x00, 0x00, 28];
    // fixed part: initiate tag, a_rwnd, OS, MIS, initial TSN
    chunk.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // initiate tag
    chunk.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // a_rwnd
    chunk.extend_from_slice(&[0x00, 0x0A]); // OS 10
    chunk.extend_from_slice(&[0x00, 0x0A]); // MIS 10
    chunk.extend_from_slice(&[0x00, 0x00, 0x00, 0x2A]); // initial TSN 42
                                                        // IPv4 address param: type 1, len 8, 10.0.0.1
    chunk.extend_from_slice(&[0x00, 0x01, 0x00, 0x08, 10, 0, 0, 1]);
    p.extend_from_slice(&chunk);
    seal(&mut p);
    p
}

/// The audit's attack form delivered through the public packet entry:
/// an INIT whose params tail is `type 1, plen 6, 2 value bytes` — the
/// 4-byte-padded advance (8) overruns the 6-byte remainder and previously
/// panicked (`&buf[8..]` on a 6-byte slice).
fn trailing_short_param() -> Vec<u8> {
    let mut p: Vec<u8> = [
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
    .to_vec();
    // INIT chunk, length = 4 + 16 + 6 = 26
    let mut chunk: Vec<u8> = vec![0x01, 0x00, 0x00, 26];
    chunk.extend_from_slice(&[0u8; 16]); // fixed part
    chunk.extend_from_slice(&[0x00, 0x01, 0x00, 0x06, 0xAA, 0xBB]); // attack param
    p.extend_from_slice(&chunk);
    seal(&mut p);
    p
}

fn sctp_parse_no_panic(corpus: &[&[u8]]) {
    for input in corpus {
        // Err is fine; a panic fails the test.
        let _ = parse_packet(input, true);
        let _ = parse_packet(input, false);
    }
}

#[test]
fn sctp_wire_survives_malformed_corpus() {
    // Sanity: the two crafted "valid" packets really parse (they pin the
    // corpus' premise — mutations are meaningful only from a parseable base).
    assert!(parse_packet(&valid_init(), true).is_ok());
    assert!(parse_packet(&trailing_short_param(), true).is_ok());

    let huge: Vec<u8> = vec![0xFF; 65_536];
    let all_zero: Vec<u8> = vec![0; 1400];
    // DATA chunk declaring 65535 length with 4 bytes present
    let data_huge_len: Vec<u8> = vec![0x00, 0x00, 0xFF, 0xFF, 1, 2, 3, 4];
    // Every known chunk type, header-only
    let mut chunk_headers: Vec<u8> = Vec::new();
    for t in [
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 64, 65, 128, 0xC0, 0xC1, 0xFE, 0xFF,
    ] {
        chunk_headers.extend_from_slice(&[t, 0x00, 0x00, 0x04]);
    }
    // SACK with absurd gap counts and zero bodies
    let sack_absurd: Vec<u8> = [
        &[0x03u8, 0x00, 0x00, 0x10][..],
        &[1, 2, 3, 4],             // cum tsn
        &[0xFF, 0xFF, 0xFF, 0xFF], // a_rwnd
        &[0xFF, 0xFF],             // 65535 gap blocks ...
        &[0xFF, 0xFF],             // ... 65535 dup tsns, no data
    ]
    .concat();

    let corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8; 3],  // shorter than the common header
        vec![0u8; 11], // one byte short
        vec![0u8; 12], // header with zero checksum (mismatches)
        valid_init(),
        valid_init()[..16].to_vec(), // chunk header truncated mid-length
        trailing_short_param(),
        data_huge_len,
        chunk_headers,
        sack_absurd,
        huge,
        all_zero,
    ];
    let refs: Vec<&[u8]> = corpus.iter().map(|v| v.as_slice()).collect();
    sctp_parse_no_panic(&refs);

    // Deterministic mutations of a valid INIT: flip bytes, truncate, extend.
    let base = valid_init();
    let mut rng = Lcg(0x5EED_5EED);
    let mut mutated: Vec<Vec<u8>> = Vec::new();
    for i in 0..512u32 {
        let mut m = base.clone();
        match i % 4 {
            0 => {
                let idx = (rng.next() as usize) % m.len();
                m[idx] = rng.byte();
            }
            1 => m.truncate((rng.next() as usize) % (m.len() + 1)),
            2 => m.extend_from_slice(&[rng.byte(), rng.byte(), rng.byte()]),
            _ => {
                let idx = (rng.next() as usize) % m.len();
                m[idx] ^= 0x80;
            }
        }
        mutated.push(m);
    }
    let refs: Vec<&[u8]> = mutated.iter().map(|v| v.as_slice()).collect();
    sctp_parse_no_panic(&refs);
}

// The trailing-short-param attack form is also pinned directly against
// `parse_params` by unit tests inside `wire.rs`; here it rides the public
// packet entry point only.

#[test]
fn dcep_parser_survives_malformed_corpus() {
    let mut rng = Lcg(0xDCE0_0001);
    for _ in 0..512 {
        let len = (rng.next() as usize) % 64;
        let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let _ = dcep::parse(&buf);
    }
    // Crafted: OPEN message type with absurd declared label lengths.
    let absurd: Vec<u8> = [
        &[0x03u8, 0x00][..],               // msg_type OPEN, channel type even
        &0xFFFFu16.to_be_bytes()[..],      // priority
        &0xFFFF_FFFFu32.to_be_bytes()[..], // reliability
        &0xFFFFu16.to_be_bytes()[..],      // label len 65535
        &0xFFFFu16.to_be_bytes()[..],      // protocol len 65535
        &[0x41u8, 0x42],                   // "AB"
    ]
    .concat();
    assert!(dcep::parse(&absurd).is_err());
    // ACK is a single 0x02 byte — parses as "no OPEN" (Ok(None)).
    assert!(dcep::parse(&[0x02]).is_ok());
}
