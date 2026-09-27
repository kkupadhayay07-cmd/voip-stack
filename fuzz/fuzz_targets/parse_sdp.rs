//! Fuzz the SDP parser (RFC 4566 / RFC 8866).
//!
//! Property: `sdp::parse` must return `Result` for any input — never panic.
//! The parser takes `&str`, so invalid UTF-8 is rejected before it is called
//! (mirrors what a network caller must do anyway).

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sdp::parse(s);
    }
});
