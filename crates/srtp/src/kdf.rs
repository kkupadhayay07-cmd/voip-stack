//! SRTP key derivation ([RFC 3711 §4.3]) for AES-CM profiles and the
//! AES-GCM profiles of [RFC 7714 §11] (which reuse the same KDF).
//!
//! # Algorithm
//!
//! * `r      = index DIV key_derivation_rate` (0 when the rate is 0)
//! * `key_id = <label> || r` (8-bit label concatenated with the 48-bit `r`)
//! * `x      = key_id XOR master_salt` (right-aligned)
//! * `PRF_n(k_master, x) = AES-CM(k_master, IV = x * 2^16)`, truncated to n bits
//!
//! Labels (RFC 3711 §4.3.1/§4.3.2): `0x00` SRTP enc, `0x01` SRTP auth,
//! `0x02` SRTP salt, `0x03` SRTCP enc, `0x04` SRTCP auth, `0x05` SRTCP salt.
//!
//! [RFC 3711 §4.3]: https://datatracker.ietf.org/doc/html/rfc3711#section-4.3
//! [RFC 7714 §11]: https://datatracker.ietf.org/doc/html/rfc7714#section-11

use crate::aes_cm::keystream;

/// Session key labels defined by RFC 3711 §4.3.1 and §4.3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    /// SRTP encryption key (0x00).
    RtpEnc,
    /// SRTP authentication key (0x01).
    RtpAuth,
    /// SRTP salting key (0x02).
    RtpSalt,
    /// SRTCP encryption key (0x03).
    RtcpEnc,
    /// SRTCP authentication key (0x04).
    RtcpAuth,
    /// SRTCP salting key (0x05).
    RtcpSalt,
    /// Any extension label in the 0x06..=0xff range (RFC 3711 §4.3.1).
    Ext(u8),
}

impl Label {
    fn value(self) -> u8 {
        match self {
            Label::RtpEnc => 0x00,
            Label::RtpAuth => 0x01,
            Label::RtpSalt => 0x02,
            Label::RtcpEnc => 0x03,
            Label::RtcpAuth => 0x04,
            Label::RtcpSalt => 0x05,
            Label::Ext(v) => v,
        }
    }
}

/// Errors from key derivation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KdfError {
    /// Master salt must be 14 octets (AES-CM) or 12 octets (AES-GCM).
    #[error("invalid master salt length {got} for key length {key_len}")]
    BadSaltLen { got: usize, key_len: usize },
    /// Underlying AES-CM PRF failure (bad master key length).
    #[error(transparent)]
    AesCm(#[from] crate::aes_cm::AesCmError),
}

/// Derive `out.len()` bytes of session keying material.
///
/// `index` is the 48-bit SRTP packet index (`ROC || SEQ`) or, for SRTCP, the
/// 32-bit value `0 || SRTCP-index`.  `rate` is the key derivation rate
/// (RFC 3711 §4.3.1); pass `0` for the mandatory initial derivation.
pub fn derive(
    master_key: &[u8],
    master_salt: &[u8],
    label: Label,
    index: u64,
    rate: u64,
    out: &mut [u8],
) -> Result<(), KdfError> {
    let key_id_width = 7usize; // 1 byte label + 6 bytes r (48 bits)
    if master_salt.len() < key_id_width {
        return Err(KdfError::BadSaltLen {
            got: master_salt.len(),
            key_len: master_key.len(),
        });
    }

    // r = index DIV rate ("a DIV 0 = 0" per RFC 3711 §4.3.1).
    let r: u64 = if rate == 0 { 0 } else { index / rate };

    // x = key_id XOR master_salt, right-aligned: key_id (7 bytes) occupies
    // the low-order bytes of the salt-width big-endian field.
    let mut x = master_salt.to_vec();
    let kid = key_id_bytes(label.value(), r);
    let off = x.len() - key_id_width;
    for (i, b) in kid.iter().enumerate() {
        x[off + i] ^= b;
    }

    // IV = x * 2^16  (x left-aligned in 16 bytes, two zero octets appended).
    let mut iv = [0u8; 16];
    iv[..x.len()].copy_from_slice(&x);

    keystream(master_key, &iv, out)?;
    Ok(())
}

/// Serialize `key_id = <label> || r` as 7 big-endian bytes.
fn key_id_bytes(label: u8, r: u64) -> [u8; 7] {
    let rb = (r & 0xFFFF_FFFF_FFFF).to_be_bytes(); // 8 bytes, low 6 significant
    let mut kid = [0u8; 7];
    kid[0] = label;
    kid[1..].copy_from_slice(&rb[2..]);
    kid
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    /// RFC 3711 Appendix B.3 key derivation test vectors
    /// (initial derivation, key_derivation_rate = 0).
    #[test]
    fn rfc3711_b3_kdf() {
        let mk = hex::decode("E1F97A0D3E018BE0D64FA32C06DE4139").unwrap();
        let ms = hex::decode("0EC675AD498AFEEBB6960B3AABE6").unwrap();

        // cipher key (label 0x00, 16 octets)
        let mut ke = [0u8; 16];
        derive(&mk, &ms, Label::RtpEnc, 0, 0, &mut ke).unwrap();
        assert_eq!(hex::encode(ke), "c61e7a93744f39ee10734afe3ff7a087");

        // auth key (label 0x01, 94 octets) — first and last blocks checked
        let mut ka = [0u8; 94];
        derive(&mk, &ms, Label::RtpAuth, 0, 0, &mut ka).unwrap();
        assert_eq!(hex::encode(&ka[..16]), "cebe321f6ff7716b6fd4ab49af256a15");
        assert_eq!(hex::encode(&ka[80..]), "6b68642c59bbfc2f34db60dbdfb2");

        // cipher salt (label 0x02, 14 octets)
        let mut ks = [0u8; 14];
        derive(&mk, &ms, Label::RtpSalt, 0, 0, &mut ks).unwrap();
        assert_eq!(hex::encode(ks), "30cbbc08863d8c85d49db34a9ae1");
    }

    /// Key derivation with a non-zero rate must shift the packet index
    /// (RFC 3711 §4.3.1: `r = index DIV rate`).
    #[test]
    fn kdf_rate_shifting() {
        let mk = hex::decode("E1F97A0D3E018BE0D64FA32C06DE4139").unwrap();
        let ms = hex::decode("0EC675AD498AFEEBB6960B3AABE6").unwrap();

        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        // index 0..2^16 with rate 2^16 all give r = 0 → identical keys.
        derive(&mk, &ms, Label::RtpEnc, 0, 1 << 16, &mut a).unwrap();
        derive(&mk, &ms, Label::RtpEnc, 0xFFFF, 1 << 16, &mut b).unwrap();
        assert_eq!(a, b);
        // index 2^16 gives r = 1 → different keys.
        derive(&mk, &ms, Label::RtpEnc, 1 << 16, 1 << 16, &mut b).unwrap();
        assert_ne!(a, b);
    }

    /// A 12-octet salt (AES-GCM profiles) derives with the key_id
    /// right-aligned inside the shorter salt field.
    #[test]
    fn kdf_gcm_salt_width() {
        let mk = [0x00u8; 16];
        let ms = [0xffu8; 12];
        let mut out = [0u8; 16];
        // Must not panic and must be deterministic; RFC 7714 §11 reuses the
        // same construction with the 96-bit salt.
        derive(&mk, &ms, Label::RtpEnc, 0, 0, &mut out).unwrap();
        let mut out2 = [0u8; 16];
        derive(&mk, &ms, Label::RtpEnc, 0, 0, &mut out2).unwrap();
        assert_eq!(out, out2);

        // Salt shorter than key_id is invalid.
        let err = derive(&mk, &[0u8; 6], Label::RtpEnc, 0, 0, &mut out);
        assert!(matches!(err, Err(KdfError::BadSaltLen { .. })));
    }
}
