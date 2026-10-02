//! Fuzz the RFC 8832 DCEP channel-open parser.
//!
//! Property: `dcep::parse` must return `Result` for any input — never
//! panic, even for absurd declared label/protocol lengths.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sctp::dcep::parse(data);
});
