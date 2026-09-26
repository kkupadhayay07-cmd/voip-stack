//! # srtp
//!
//! Native Secure RTP / Secure RTCP (RFC 3711 + RFC 7714):
//!
//! - **AES-CM + HMAC-SHA1** profiles (`AES_CM_128_HMAC_SHA1_80` / `_32`)
//! - **AES-GCM AEAD** profiles (`AEAD_AES_128_GCM`, `AEAD_AES_256_GCM`,
//!   plus the 96-bit tag variants)
//! - RFC 3711 key derivation with all six session-key labels
//! - Sliding-window replay protection and Appendix A ROC estimation
//! - Sender ROC tracking and 31-bit SRTCP index management
//!
//! The crate operates on raw packet buffers (`Vec<u8>`) in place, so it
//! composes with the `rtp` crate (or any other serializer) without
//! re-encoding packets.  Profile negotiation with DTLS-SRTP is provided via
//! [`Profile::dtls_name`] / [`Profile::from_dtls_name`].
//!
//! # Example
//!
//! ```
//! use srtp::{Profile, SrtpSession};
//!
//! let key = [0x42u8; 16];
//! let salt = [0x99u8; 14];
//! let mut a = SrtpSession::new(Profile::AesCm128Sha1_80, &key, &salt).unwrap();
//! let mut b = SrtpSession::new(Profile::AesCm128Sha1_80, &key, &salt).unwrap();
//!
//! let mut packet = vec![0x80, 0, 0, 7, 0, 0, 0, 1, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4];
//! let idx = a.protect(&mut packet).unwrap();
//! assert_eq!(packet.len(), 12 + 4 + 10); // payload + HMAC-SHA1/80 tag
//! b.unprotect(&mut packet).unwrap();
//! assert_eq!(&packet, &vec![0x80, 0, 0, 7, 0, 0, 0, 1, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4]);
//! # let _ = idx;
//! ```

#![forbid(unsafe_code)]

pub mod aes_cm;
pub mod context;
pub mod kdf;
pub mod replay;

pub use aes_cm::AesCmError;
pub use context::{Profile, SessionKeySet, SrtpError, SrtpSession};
pub use kdf::Label;
pub use replay::ReplayWindow;
