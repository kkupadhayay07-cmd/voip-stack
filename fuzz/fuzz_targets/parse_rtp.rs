//! Fuzz the RTP packet parser (RFC 3550 §5.1).
//!
//! Property: `RtpPacket::parse` must return `Result` for any input — never
//! panic, even for truncated headers, absurd CSRC counts or padding lies.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rtp::RtpPacket::parse(data);
});
