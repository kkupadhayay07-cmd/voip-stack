//! Self-signed certificate management for DTLS-SRTP.
//!
//! WebRTC endpoints authenticate each other by exchanging a SHA-256
//! fingerprint of the self-signed certificate in SDP
//! ([RFC 8122]) and pinning the peer certificate against it during the
//! DTLS handshake.  This module generates a fresh ECDSA P-256 certificate
//! per process (or per session) and computes the fingerprint in the SDP
//! "ucase-hex-colon" form.
//!
//! [RFC 8122]: https://datatracker.ietf.org/doc/html/rfc8122

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder, X509};

use crate::DtlsError;

/// Number of days the generated certificate stays valid.
const CERT_VALIDITY_DAYS: u32 = 3650;

/// A self-signed identity: certificate + private key.
#[derive(Clone)]
pub struct Identity {
    cert: X509,
    #[allow(dead_code)]
    pkey: PKey<Private>,
    fingerprint_hex: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint_hex)
            .finish()
    }
}

impl Identity {
    /// Generate a fresh self-signed identity.
    ///
    /// ECDSA P-256 is the WebRTC-mandatory curve.  Falls back to RSA-2048
    /// only if EC key generation is unavailable in the linked OpenSSL.
    pub fn generate(common_name: &str) -> Result<Self, DtlsError> {
        let pkey = match openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
        {
            Ok(group) => match openssl::ec::EcKey::generate(&group) {
                Ok(ec) => PKey::from_ec_key(ec)?,
                Err(_) => {
                    let rsa = Rsa::generate(2048)?;
                    PKey::from_rsa(rsa)?
                }
            },
            Err(_) => {
                let rsa = Rsa::generate(2048)?;
                PKey::from_rsa(rsa)?
            }
        };
        Self::from_pkey(&pkey, common_name)
    }

    /// Build a self-signed certificate around an existing key.
    fn from_pkey(pkey: &PKey<Private>, common_name: &str) -> Result<Self, DtlsError> {
        let mut builder: X509Builder = X509::builder()?;
        builder.set_version(2)?;

        // random 128-bit serial
        let mut serial = BigNum::new()?;
        serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
        builder.set_serial_number(Asn1Integer::from_bn(&serial)?.as_ref())?;

        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", common_name)?;
        let name = name.build();
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?; // self-signed

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(CERT_VALIDITY_DAYS)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        builder.set_pubkey(pkey)?;
        builder.sign(pkey, MessageDigest::sha256())?;
        let cert = builder.build();

        let fingerprint_hex = fingerprint_of(&cert)?;
        Ok(Identity {
            cert,
            pkey: pkey.clone(),
            fingerprint_hex,
        })
    }

    /// The DER-encoded certificate.
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert.to_der().expect("DER encode never fails")
    }

    /// The certificate reference.
    pub fn certificate(&self) -> &X509 {
        &self.cert
    }

    /// The private key reference.
    pub fn key(&self) -> &PKey<Private> {
        &self.pkey
    }

    /// Local fingerprint for SDP `a=fingerprint` lines
    /// (`sha-256 XX:XX:...` uppercase hex, colon-separated).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint_hex
    }
}

/// Compute the SHA-256 certificate fingerprint in RFC 8122 SDP form.
pub fn fingerprint_of(cert: &X509) -> Result<String, DtlsError> {
    let digest = cert.digest(MessageDigest::sha256())?;
    Ok(format_fingerprint(&digest))
}

/// Format raw digest bytes as `AB:CD:...` uppercase.
pub fn format_fingerprint(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Validate a remote fingerprint string against a certificate
/// (case-insensitive, tolerant of the `sha-256 ` prefix and of case).
pub fn fingerprint_matches(cert: &X509, remote: &str) -> bool {
    let remote = remote.trim().trim_start_matches("sha-256 ").trim();
    match fingerprint_of(cert) {
        Ok(actual) => actual.eq_ignore_ascii_case(remote),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_self_signed_cert_with_fingerprint() {
        let id = Identity::generate("voip-test").unwrap();
        // SHA-256 fingerprint = 32 bytes → 32 hex pairs.
        assert_eq!(id.fingerprint().split(':').count(), 32);
        assert!(id
            .fingerprint()
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':'));
        // DER parses back.
        let der = id.cert_der();
        let parsed = X509::from_der(&der).unwrap();
        assert_eq!(fingerprint_of(&parsed).unwrap(), *id.fingerprint());
    }

    #[test]
    fn fingerprints_are_unique_per_identity() {
        let a = Identity::generate("a").unwrap();
        let b = Identity::generate("b").unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_matching_is_case_insensitive() {
        let id = Identity::generate("x").unwrap();
        assert!(fingerprint_matches(id.certificate(), id.fingerprint()));
        assert!(fingerprint_matches(
            id.certificate(),
            &id.fingerprint().to_lowercase()
        ));
        assert!(fingerprint_matches(
            id.certificate(),
            &format!("sha-256 {}", id.fingerprint())
        ));
        assert!(!fingerprint_matches(id.certificate(), "00:00:00"));
    }
}
