//! AES Counter Mode as specified by [RFC 3711 §4.1.1].
//!
//! The keystream segment is `E(k, IV) || E(k, IV+1) || ...` where the
//! increment is a full 128-bit big-endian addition.  The IV formation
//! (salt/SSRC/index XOR) lives in [`crate::context`]; this module only
//! provides the raw cipher primitive.
//!
//! [RFC 3711 §4.1.1]: https://datatracker.ietf.org/doc/html/rfc3711#section-4.1.1

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes::{Aes192, Aes256};

/// Increment a 128-bit big-endian counter block by one.
pub(crate) fn incr128(block: &mut [u8; 16]) {
    for byte in block.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

enum Cipher {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

impl Cipher {
    fn new(key: &[u8]) -> Result<Self, AesCmError> {
        match key.len() {
            16 => Ok(Cipher::A128(
                Aes128::new_from_slice(key).expect("len checked"),
            )),
            24 => Ok(Cipher::A192(
                Aes192::new_from_slice(key).expect("len checked"),
            )),
            32 => Ok(Cipher::A256(
                Aes256::new_from_slice(key).expect("len checked"),
            )),
            n => Err(AesCmError::BadKeyLen(n)),
        }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut arr = aes::Block::from(*block);
        match self {
            Cipher::A128(c) => c.encrypt_block(&mut arr),
            Cipher::A192(c) => c.encrypt_block(&mut arr),
            Cipher::A256(c) => c.encrypt_block(&mut arr),
        }
        *block = arr.into();
    }
}

/// Errors from the AES-CM primitive.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AesCmError {
    /// AES-CM accepts 128, 192 or 256 bit keys only.
    #[error("invalid AES key length {0} (expected 16, 24 or 32 bytes)")]
    BadKeyLen(usize),
}

/// Generate the AES-CM keystream segment starting at `iv` into `out`.
///
/// The last keystream block is truncated to fit `out.len()`, exactly as
/// SRTP requires for the final partial block of a packet payload.
pub fn keystream(key: &[u8], iv: &[u8; 16], out: &mut [u8]) -> Result<(), AesCmError> {
    let cipher = Cipher::new(key)?;
    let mut counter = *iv;
    for chunk in out.chunks_mut(16) {
        let mut block = counter;
        cipher.encrypt_block(&mut block);
        for (dst, src) in chunk.iter_mut().zip(block.iter()) {
            *dst ^= src;
        }
        incr128(&mut counter);
    }
    Ok(())
}

/// XOR the keystream into `data` in place (encrypt == decrypt in CTR mode).
pub fn xor_keystream(key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<(), AesCmError> {
    let cipher = Cipher::new(key)?;
    let mut counter = *iv;
    for chunk in data.chunks_mut(16) {
        let mut block = counter;
        cipher.encrypt_block(&mut block);
        for (dst, src) in chunk.iter_mut().zip(block.iter()) {
            *dst ^= *src;
        }
        incr128(&mut counter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    /// RFC 3711 Appendix B.2 AES-CM keystream test vector.
    #[test]
    fn rfc3711_b2_keystream() {
        // Session Key:      2B7E151628AED2A6ABF7158809CF4F3C
        // (Session salt already shifted into the IV)
        // Offset/IV:        F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000
        // first block:      E03EAD0935C95E80E166B16DD92B4EB4
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
        let iv = hex::decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000").unwrap();
        let mut iv_a = [0u8; 16];
        iv_a.copy_from_slice(&iv);

        // First two blocks are given by NIST SP 800-38A F.5.1 continuation
        // (second block D23513162B02D0F72A43A2FE4A5F97AB per RFC 3711 B.2).
        let mut out = [0u8; 32];
        keystream(&key, &iv_a, &mut out).unwrap();
        assert_eq!(hex::encode(&out[..16]), "e03ead0935c95e80e166b16dd92b4eb4");
        assert_eq!(hex::encode(&out[16..]), "d23513162b02d0f72a43a2fe4a5f97ab");
    }

    /// The counter must wrap around the full 128-bit block space.
    #[test]
    fn incr128_carries() {
        let mut b = [0u8; 16];
        incr128(&mut b);
        assert_eq!(b[15], 1);
        let mut arr = [0xffu8; 16];
        arr.copy_from_slice(&hex::decode("000000000000000000000000FFFFFFFF").unwrap());
        incr128(&mut arr);
        assert_eq!(hex::encode(arr), "00000000000000000000000100000000");
        let mut arr = [0xffu8; 16];
        incr128(&mut arr);
        assert_eq!(arr, [0u8; 16]);
    }

    #[test]
    fn bad_key_len_rejected() {
        let iv = [0u8; 16];
        let mut out = [0u8; 8];
        assert!(keystream(&[0u8; 8], &iv, &mut out).is_err());
        assert!(keystream(&[0u8; 17], &iv, &mut out).is_err());
    }
}
