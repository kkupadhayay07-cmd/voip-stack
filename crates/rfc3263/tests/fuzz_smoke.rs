//! Stable-runnable fuzz smoke corpus for the RFC 1035 DNS wire codec.
//!
//! Handcrafted nasty inputs plus deterministic pseudo-random mutations of a
//! real encoded query fed through the same public entry points as
//! `fuzz/fuzz_targets/parse_dns_response.rs`. Property: **`parse_response`
//! and `read_name` return `Result` for any input and never panic** — name
//! compression loops, absurd RR counts and truncated bodies included.
//!
//! Run on stable CI via `cargo test -p rfc3263 --test fuzz_smoke`.

use rfc3263::wire::{encode_query, parse_response, read_name};

/// Deterministic xorshift64* — reproducible corpus across runs/platforms.
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

fn dns_parse_no_panic(corpus: &[&[u8]]) {
    for input in corpus {
        // Err is fine; a panic fails the test.
        let _ = parse_response(input);
    }
}

#[test]
fn dns_wire_survives_malformed_corpus() {
    // Header claiming thousands of records of each kind, no body.
    let absurd_counts: Vec<u8> = [
        &[0xABu8, 0xCD][..], // id
        &[0x81, 0x80],       // flags: response, RD, RA
        &[0xFF, 0xFF],       // qdcount 65535
        &[0xFF, 0xFF],       // ancount 65535
        &[0xFF, 0xFF],       // nscount 65535
        &[0xFF, 0xFF],       // arcount 65535
    ]
    .concat();
    // Compression pointer that points at itself (offset into the header).
    let self_pointing: Vec<u8> = [
        &[0x00u8, 0x01][..],
        &[0x81, 0x80],
        &[0x00, 0x01],
        &[0x00, 0x00],
        &[0x00, 0x00],
        &[0x00, 0x00],
        &[0x05, b'e', b'v', b'i', b'l', 0xC0, 0x0C], // name, pointer → offset 12 = itself
        &[0x00, 0x01, 0x00, 0x01],                   // qtype/qclass
    ]
    .concat();
    // Forward pointer (beyond end), dangling length byte, unterminated label.
    let wild_pointers: Vec<Vec<u8>> = vec![
        [0xC0u8, 0xFF].to_vec(),
        [0xC0u8, 0x0C, 0x00, 0x01, 0x00, 0x01].to_vec(),
        {
            let mut v = vec![0x3F_u8];
            v.resize(64, b'a'); // 63-length label byte + junk, no terminator
            v
        },
        vec![0x41], // dangling length byte
    ];
    // A real encoded query as the mutation base.
    let query = encode_query(0x1234, "_sip._tcp.example.com", 33).expect("query encodes");

    let mut corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8; 11], // one byte short of the header
        vec![0u8; 12], // header only, all counts zero (valid, empty)
        absurd_counts,
        self_pointing,
        [0xC0u8, 0xFF].to_vec(),
        [0xC0u8, 0x0C, 0x00, 0x01, 0x00, 0x01].to_vec(),
        {
            let mut v = vec![0x3F_u8];
            v.resize(64, b'a'); // unterminated label
            v
        },
        vec![0x41],
        query.clone(),
    ];
    corpus.extend(wild_pointers);

    let refs: Vec<&[u8]> = corpus.iter().map(|v| v.as_slice()).collect();
    dns_parse_no_panic(&refs);

    // Deterministic mutations of the real query: flip, truncate, extend.
    let mut rng = Lcg(0xD05_5EED);
    let mut mutated: Vec<Vec<u8>> = Vec::new();
    for i in 0..512u32 {
        let mut m = query.clone();
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
    dns_parse_no_panic(&refs);
}

#[test]
fn read_name_rejects_degenerate_buffers_without_panic() {
    // Pointer chasing into itself must error, not loop or panic.
    let buf = [0xC0u8, 0x00];
    assert!(read_name(&buf, 0).is_err());
    // Trailing single length byte, no content.
    assert!(read_name(&[0x04], 0).is_err());
    // Valid root.
    let (name, next) = read_name(&[0x00], 0).expect("root parses");
    assert_eq!(name, "");
    assert_eq!(next, 1);
}
