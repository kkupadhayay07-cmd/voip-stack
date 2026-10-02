//! Fuzz the RFC 1035 DNS message parser (rfc3263).
//!
//! Property: `wire::parse_response` must return `Result` for any input —
//! never panic, even for self-pointing compression pointers, absurd RR
//! counts, or truncated name fields.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rfc3263::wire::parse_response(data);
});
