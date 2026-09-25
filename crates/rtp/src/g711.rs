//! Native G.711 (μ-law / A-law) PCM codec, RFC 3551 payload types 0 and 8.
//!
//! Implemented natively (branch-based companding) with a consistent
//! encode/decode pair verified by roundtrip and quantization-error tests.

/// Decode a μ-law byte to 16-bit linear PCM.
pub fn pcmu_decode(code: u8) -> i16 {
    let v = !code;
    let sign = v & 0x80;
    let expo = ((v & 0x70) >> 4) as u32;
    let mant = v & 0x0F;
    let t = ((mant as i32) << 3) + 0x84;
    let t = t << expo;
    if sign != 0 {
        (0x84 - t) as i16
    } else {
        (t - 0x84) as i16
    }
}

/// Encode 16-bit linear PCM to a μ-law byte.
pub fn pcmu_encode(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    const CLIP: i32 = 32635;
    let mut x = sample as i32;
    // wire sign bit convention: 0x80 present when sample negative
    let sign = if x < 0 {
        x = -x;
        0x80u32
    } else {
        0u32
    };
    if x > CLIP {
        x = CLIP;
    }
    x += BIAS;
    // segment = floor(log2(x)) - 7, i.e. position of MSB of x>>7 (0..7)
    let h = (x >> 7) as u8;
    let seg = match h {
        0..=1 => 0u32,
        2..=3 => 1,
        4..=7 => 2,
        8..=15 => 3,
        16..=31 => 4,
        32..=63 => 5,
        64..=127 => 6,
        _ => 7,
    };
    // inverse of decode: value = ((m*8 + BIAS) << seg) - BIAS  =>  m = ((x>>seg) - BIAS) >> 3
    let mant = (((x >> seg) - BIAS) >> 3).clamp(0, 15) as u32;
    !(sign | (seg << 4) | mant) as u8
}

/// Decode an A-law byte to 16-bit linear PCM.
pub fn pcma_decode(code: u8) -> i16 {
    let v = code ^ 0x55;
    let sign = v & 0x80;
    let seg = ((v & 0x70) >> 4) as u32;
    let mant = v & 0x0F;
    let t: i32 = if seg == 0 {
        ((mant as i32) << 4) + 8
    } else {
        (((mant as i32) << 4) + 0x108) << (seg - 1)
    };
    if sign != 0 {
        t as i16
    } else {
        -t as i16
    }
}

/// Encode 16-bit linear PCM to an A-law byte.
pub fn pcma_encode(sample: i16) -> u8 {
    let mut x = sample as i32;
    // internal sign bit: 0x80 = positive (A-law); wire = internal ^ 0x55
    let sign: u32 = if x >= 0 { 0x80 } else { x = -x; 0x00 };
    if x > 32_767 {
        x = 32_767;
    }
    // segment boundaries at 264·2^(e-1): inverse of decode's ((m*16+0x108) << (e-1))
    let seg: u32 = match x {
        0..=263 => 0,
        264..=527 => 1,
        528..=1_055 => 2,
        1_056..=2_111 => 3,
        2_112..=4_223 => 4,
        4_224..=8_447 => 5,
        8_448..=16_895 => 6,
        _ => 7,
    };
    let mant: i32 = if seg == 0 {
        (x - 8) >> 4
    } else {
        ((x >> (seg - 1)) - 0x108) >> 4
    };
    let mant = mant.clamp(0, 15) as u32;
    let internal = sign | (seg << 4) | mant;
    (internal ^ 0x55) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcmu_zero_codes() {
        // +0 and -0 both decode to 0
        assert_eq!(pcmu_decode(0xFF), 0);
        assert_eq!(pcmu_decode(0x7F), 0);
        assert_eq!(pcmu_encode(0), 0xFF);
    }

    #[test]
    fn pcmu_full_scale() {
        assert_eq!(pcmu_decode(0x80), 32_124);
        assert_eq!(pcmu_decode(0x00), -32_124);
        assert_eq!(pcmu_encode(32_767), 0x80);
        assert_eq!(pcmu_encode(-32_768), 0x00);
    }

    #[test]
    fn pcma_zero_codes() {
        assert_eq!(pcma_encode(0), 0xD5);
        assert_eq!(pcma_encode(-1), 0x55);
    }

    #[test]
    fn pcma_full_scale() {
        assert_eq!(pcma_decode(0xAA), 32_256);
        assert_eq!(pcma_decode(0x2A), -32_256);
        assert_eq!(pcma_encode(32_767), 0xAA);
        assert_eq!(pcma_encode(-32_768), 0x2A);
    }

    #[test]
    fn pcmu_roundtrip_error_bounded() {
        // μ-law quantization: truncation error bounded by one segment step;
        // safe envelope: |s|/8 + 80
        for s in [-32_768i16, -32_767, -10_000, -1_000, -256, -1, 0, 1, 8, 255, 256, 1_000, 12_345, 32_767] {
            let back = pcmu_decode(pcmu_encode(s));
            let err = (back as i32 - s as i32).abs();
            assert!(err <= s.unsigned_abs() as i32 / 8 + 80, "pcmu roundtrip {} -> {} err {}", s, back, err);
        }
        // small amplitudes are tightly coded (segment 0 step = 8)
        for s in -64i16..=64 {
            let back = pcmu_decode(pcmu_encode(s));
            assert!((back as i32 - s as i32).abs() <= 16, "pcmu small {} -> {}", s, back);
        }
    }

    #[test]
    fn pcma_roundtrip_error_bounded() {
        for s in [-32_768i16, -32_767, -10_000, -1_000, -256, -1, 0, 1, 128, 1_000, 12_345, 32_767] {
            let back = pcma_decode(pcma_encode(s));
            let err = (back as i32 - s as i32).abs();
            assert!(err <= s.unsigned_abs() as i32 / 8 + 80, "pcma roundtrip {} -> {} err {}", s, back, err);
        }
        for s in -64i16..=64 {
            let back = pcma_decode(pcma_encode(s));
            assert!((back as i32 - s as i32).abs() <= 16, "pcma small {} -> {}", s, back);
        }
    }

    #[test]
    fn monotonicity() {
        let mut prev = i16::MIN;
        for i in 0..=255u32 {
            let s = (-32_768i32 + (i * 256) as i32).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            let v = pcmu_decode(pcmu_encode(s));
            assert!(v >= prev, "pcmu not monotonic at {}", s);
            prev = v;
        }
        let mut prev = i16::MIN;
        for i in 0..=255u32 {
            let s = (-32_768i32 + (i * 256) as i32).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            let v = pcma_decode(pcma_encode(s));
            assert!(v >= prev, "pcma not monotonic at {}", s);
            prev = v;
        }
    }

    #[test]
    fn all_codes_decode_finite() {
        for c in 0..=255u8 {
            let _ = pcmu_decode(c);
            let _ = pcma_decode(c);
        }
    }
}
