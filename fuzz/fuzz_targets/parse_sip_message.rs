//! Fuzz the SIP datagram parser (RFC 3261 §18.3 framing).
//!
//! Property: `parse_message` / `parse_stream` must return `Result` for any
//! input — never panic, never UB (sip-core is `#![forbid(unsafe_code)]`).

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Datagram framing: Content-Length validated, trailing octets tolerated.
    let _ = sip_core::parse_message(data);
    // Stream framing: may report Truncated for partial input.
    let _ = sip_core::parse_stream(data);
});
