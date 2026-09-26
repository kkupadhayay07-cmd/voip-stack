//! Fuzz the RFC 4733 telephone-event (DTMF) payload parser.
//!
//! Property: `dtmf::parse_event` must return `Result` for any input — never
//! panic, even for payloads shorter than the 4-byte minimum.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rtp::dtmf::parse_event(data);
});
