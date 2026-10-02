//! Fuzz the SCTP packet wire parser (RFC 9260 §3.1/§3.3).
//!
//! Property: `wire::parse_packet` must return `Result` for any input —
//! never panic, even for truncated chunks, absurd lengths, or trailing
//! parameters whose 4-byte padding overruns the chunk.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sctp::wire::parse_packet(data, true);
    let _ = sctp::wire::parse_packet(data, false);
});
