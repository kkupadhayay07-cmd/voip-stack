//! Stable-runnable fuzz smoke corpus for the SIP parser.
//!
//! These are handcrafted nasty inputs (the kind libFuzzer finds in minutes)
//! fed through the same public entry points as
//! `fuzz/fuzz_targets/parse_sip_message.rs`. The property under test is
//! identical: **the parser returns `Result` for any input and never panics.**
//! Run on stable CI via `cargo test -p sip-core --test fuzz_smoke`.

use sip_core::{parse_message, parse_stream};

/// Feed every corpus entry through both public framing modes and require the
/// process to survive (a panic fails the test; `Err` results are expected and
/// fine).
fn assert_no_panic(corpus: &[&[u8]]) {
    for (i, input) in corpus.iter().enumerate() {
        // Both calls must return Result — we deliberately do not unwrap.
        let a = parse_message(input);
        let b = parse_stream(input);
        // Cross-check the documented invariant cheaply: when both framings
        // accept the datagram, the stream parser must have consumed no more
        // bytes than were handed to it.
        if let (Ok(_), Ok((_, used))) = (a.as_ref(), b.as_ref()) {
            assert!(*used <= input.len(), "corpus[{i}]: consumed > input length");
        }
    }
}

#[test]
fn sip_parser_survives_malformed_corpus() {
    let too_many_headers: Vec<u8> = {
        let mut v = b"INVITE sip:alice@atlanta.com SIP/2.0\r\n".to_vec();
        for i in 0..300 {
            v.extend_from_slice(format!("X-Pad-{i}: {i}\r\n").as_bytes());
        }
        v.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        v
    };
    let long_header_line: Vec<u8> = {
        let mut v = b"INVITE sip:a@b SIP/2.0\r\nSubject: ".to_vec();
        v.extend(std::iter::repeat_n(b'a', 16 * 1024));
        v.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        v
    };
    let long_uri: Vec<u8> = {
        let mut v = b"INVITE sip:".to_vec();
        v.extend(std::iter::repeat_n(b'a', 4096));
        v.extend_from_slice(b"@atlanta.com SIP/2.0\r\nContent-Length: 0\r\n\r\n");
        v
    };
    let deep_folding: Vec<u8> = {
        let mut v = b"INVITE sip:a@b SIP/2.0\r\nSubject: start".to_vec();
        for _ in 0..200 {
            v.extend_from_slice(b"\r\n more-fold");
        }
        v.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        v
    };

    let corpus: Vec<Vec<u8>> = vec![
        // empties / bare line endings
        b"".to_vec(),
        b"\r\n".to_vec(),
        b"\r\n\r\n".to_vec(),
        // truncated request / status lines
        b"INVITE sip:alice@atlanta.com SIP/2.0\r\n".to_vec(),
        b"INVITE sip:".to_vec(),
        b"SIP/2".to_vec(),
        b"SIP/9.9 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"SIP/2.0 99999 Very Weird Status\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"invite sip:a@b SIP/2.0\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"INV\0ITE sip:a@b SIP/2.0\r\nContent-Length: 0\r\n\r\n".to_vec(),
        // header-layer abuse
        b" INVITE\r\n".to_vec(), // continuation with no preceding header
        b"INVITE sip:a@b SIP/2.0\r\nNoColonHere\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"INVITE sip:a@b SIP/2.0\r\n: empty-name\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"INVITE sip:a@b SIP/2.0\r\nHead[er]: bad token\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"INVITE sip:a@b SIP/2.0\r\nVia: x\rContent-Length: 0\r\n\r\n".to_vec(), // bare CR
        b"INVITE sip:a@b SIP/2.0\r\nSubject: \xff\xfe\r\nContent-Length: 0\r\n\r\n".to_vec(),
        too_many_headers,
        long_header_line,
        long_uri,
        deep_folding,
        // Content-Length torture
        b"INVITE sip:a@b SIP/2.0\r\nContent-Length: -5\r\n\r\n".to_vec(),
        b"INVITE sip:a@b SIP/2.0\r\nContent-Length: 99999999999999999999999\r\n\r\n".to_vec(),
        b"INVITE sip:a@b SIP/2.0\r\nContent-Length: 999999\r\n\r\n".to_vec(), // huge, body missing
        b"INVITE sip:a@b SIP/2.0\r\nContent-Length: 0\r\n\r\ntrailing-garbage".to_vec(),
        b"INVITE sip:a@b SIP/2.0\r\nContent-Length: 0x10\r\n\r\n".to_vec(),
        b"INVITE sip:a@b SIP/2.0\r\nContent-Length:\r\n\r\n".to_vec(),
    ];
    let corpus_refs: Vec<&[u8]> = corpus.iter().map(|v| v.as_slice()).collect();
    assert_no_panic(&corpus_refs);
}

#[test]
fn sip_parser_survives_random_byte_blobs() {
    // Deterministic pseudo-noise blobs: high-bit bytes, NULs, CRLF fragments.
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for seed in 0u8..16 {
        let mut v = Vec::new();
        let mut state = u32::from(seed).wrapping_mul(2654435761);
        for _ in 0..512 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            // Mix in CRLF-ish bytes so framing is exercised, plus NULs and
            // invalid UTF-8 to hit the byte-level paths.
            v.push(match state % 6 {
                0 => b'\r',
                1 => b'\n',
                2 => 0,
                3 => 0xFF,
                4 => b':',
                _ => (state >> 8) as u8,
            });
        }
        blobs.push(v);
    }
    let refs: Vec<&[u8]> = blobs.iter().map(|v| v.as_slice()).collect();
    assert_no_panic(&refs);
}
