//! # dtls
//!
//! DTLS-SRTP key exchange for WebRTC ([RFC 5764], [RFC 6347]):
//!
//! - DTLS 1.2 via OpenSSL (whitelisted FFI for encryption, wrapped in a
//!   safe, `unsafe`-free API for crate consumers)
//! - runtime-generated self-signed ECDSA P-256 certificates with
//!   RFC 8122 SDP fingerprints
//! - `use_srtp` extension negotiation with profile mapping into the
//!   `srtp` crate
//! - RFC 5764 §4.2 keying-material export (`EXTRACTOR-dtls_srtp`)
//! - peer certificate fingerprint pinning from SDP
//! - our own flight retransmission timer (RFC 6347 §4.2.4) since the
//!   datagram queue transport carries no DTLS timers
//!
//! [RFC 5764]: https://datatracker.ietf.org/doc/html/rfc5764
//! [RFC 6347]: https://datatracker.ietf.org/doc/html/rfc6347

#![forbid(unsafe_code)]

pub mod agent;
pub mod cert;
pub mod transport;

use thiserror::Error;

pub use agent::{DtlsEndpoint, DtlsRole, SrtpKeying, SrtpOffers};
pub use cert::{fingerprint_matches, Identity};

/// Errors from the DTLS layer.
#[derive(Debug, Error)]
pub enum DtlsError {
    /// OpenSSL reported a handshake failure.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// The peer certificate does not match the SDP fingerprint.
    #[error("peer fingerprint mismatch: expected {0}")]
    FingerprintMismatch(String),
    /// SRTP keying material export failed.
    #[error("keying material export failed: {0}")]
    KeyExport(String),
    /// Socket I/O error.
    #[error("io error: {0}")]
    Io(String),
    /// Certificate or key operation failed.
    #[error("certificate error: {0}")]
    Cert(String),
    /// Underlying OpenSSL error stack.
    #[error("openssl: {0}")]
    OpenSSL(#[from] openssl::error::ErrorStack),
}

impl From<std::io::Error> for DtlsError {
    fn from(e: std::io::Error) -> Self {
        DtlsError::Io(e.to_string())
    }
}
