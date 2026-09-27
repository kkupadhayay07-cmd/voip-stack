//! CRC-32 (IEEE 802.3, reflected) used by the STUN FINGERPRINT attribute.
//!
//! Hand-rolled to keep the dependency surface minimal; matches the
//! standard `crc32()` used by gzip/PNG and the RFC 5389 §15.5 definition.

const POLY: u32 = 0xEDB8_8320;

/// Build the lookup table once.
fn table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { POLY ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    })
}

/// CRC-32 of `data` (init 0xFFFFFFFF, final XOR 0xFFFFFFFF).
pub fn crc32(data: &[u8]) -> u32 {
    let t = table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }
}
