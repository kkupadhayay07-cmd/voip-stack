//! ITU-T G.722 subband ADPCM codec (64/56/48 kbit/s), native Rust implementation.
//!
//! Structure (per ITU-T G.722):
//! - 16 kHz input is split by a 24-tap quadrature mirror filter (implemented
//!   as two 12-tap polyphase branches, `QMF_FWD`/`QMF_REV`) into a low band
//!   (0–4 kHz) and a high band (4–8 kHz), each sampled at 8 kHz.
//! - The low band is coded by a 6-bit embedded ADPCM (the 4-bit core is
//!   always transmitted; in 56/48 kbit/s modes the two/three least
//!   significant low-band bits are stolen to carry high-band information).
//! - The high band uses a 2-bit ADPCM.
//! - Each band runs a two-pole/two-six-zero adaptive predictor with
//!   Miura-style scale-factor adaptation (`block4`).
//!
//! One wire octet is produced per 8 kHz tick: `(ihigh << 6) | ilow6` for
//! 64 kbit/s, right-shifted by 1 or 2 for 56/48 kbit/s.
//!
//! Provenance: algorithm and coefficient tables follow the ITU-T G.722
//! recommendation (the tables are the specification's published constants).

use crate::error::{CodecError, Result};
use crate::traits::{CodecId, Decoder, Encoder, FormatInfo};

/// Whether the full G.722 implementation is compiled in.
pub const SUPPORTED: bool = true;

/// SDP descriptor for G.722 (wire clock 8000 per RFC 3551 PT 9).
pub const G722_INFO: FormatInfo = FormatInfo {
    id: CodecId::G722,
    name: "G722",
    payload_type: 9,
    clock_rate: 8000,
    channels: 1,
    fmtp: None,
};

/// Transmit/receive QMF polyphase coefficients (forward phase).
const QMF_FWD: [i16; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];
/// QMF polyphase coefficients (reverse phase).
const QMF_REV: [i16; 12] = [-11, 53, -156, 362, -805, 3876, 951, -210, 32, 12, -11, 3];

/// High-band inverse quantizer (2-bit codes).
const QM2: [i16; 4] = [-7408, -1616, 7408, 1616];
/// 4-bit inverse quantizer (low-band core, also used for predictor feedback).
const QM4: [i16; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];
/// 5-bit inverse quantizer (56 kbit/s low band).
const QM5: [i16; 32] = [
    -280, -280, -23352, -17560, -14120, -11664, -9752, -8184, -6864, -5712, -4696, -3784, -2960,
    -2208, -1520, -880, 23352, 17560, 14120, 11664, 9752, 8184, 6864, 5712, 4696, 3784, 2960, 2208,
    1520, 880, 280, -280,
];
/// 6-bit inverse quantizer (64 kbit/s low band).
const QM6: [i16; 64] = [
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192, -10232,
    -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576, -3168, -2776,
    -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704, 14984, 13512, 12280,
    11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944, 4464, 4008, 3576, 3168, 2776,
    2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
];
/// Low-band quantizer decision thresholds (normalized).
const Q6: [i16; 32] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
];
/// Log-scale factor lookup.
const ILB: [i16; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];
/// Negative low-band code mapping.
const ILN: [i16; 32] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 0,
];
/// Positive low-band code mapping.
const ILP: [i16; 32] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 0,
];
/// Negative high-band code mapping.
const IHN: [i16; 3] = [0, 1, 0];
/// Positive high-band code mapping.
const IHP: [i16; 3] = [0, 3, 2];
/// Low-band scale adaptation multipliers.
const WL: [i16; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
/// Low-band 4-bit code reordering.
const RL42: [i16; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
/// High-band scale adaptation multipliers.
const WH: [i16; 3] = [0, -214, 798];
/// High-band code reordering.
const RH2: [i16; 4] = [2, 1, 2, 1];

#[inline]
fn sat16(v: i32) -> i16 {
    v.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

#[inline]
fn sat_add16(a: i16, b: i16) -> i16 {
    sat16(a as i32 + b as i32)
}

#[inline]
fn sat_sub16(a: i16, b: i16) -> i16 {
    sat16(a as i32 - b as i32)
}

/// Clamp to the 15-bit range used by the G.722 low band (`saturate15`).
#[inline]
fn sat15(v: i32) -> i16 {
    v.clamp(-16384, 16383) as i16
}

/// One ADPCM band state: two-pole/six-zero predictor + scale factor.
#[derive(Debug, Clone, Copy)]
struct Band {
    s: i16,
    sz: i16,
    r: i16,
    a: [i16; 2],
    b: [i16; 6],
    d: [i16; 7],
    p: [i16; 2],
    nb: i16,
    det: i16,
}

impl Band {
    fn new(det: i16) -> Band {
        Band {
            s: 0,
            sz: 0,
            r: 0,
            a: [0; 2],
            b: [0; 6],
            d: [0; 7],
            p: [0; 2],
            nb: 0,
            det,
        }
    }

    /// `block4`: predictor update + state advance for difference `dx`.
    fn block4(&mut self, dx: i16) {
        // RECONS
        let r = sat_add16(self.s, dx);
        // PARREC
        let p = sat_add16(self.sz, dx);

        // UPPOL2
        let wd1 = sat16(self.a[0] as i32 * 4);
        let mut wd32: i32 = if ((p as u16) ^ (self.p[0] as u16)) & 0x8000 != 0 {
            wd1 as i32
        } else {
            -(wd1 as i32)
        };
        if wd32 > 32767 {
            wd32 = 32767;
        }
        let sign2: i32 = if ((p as u16) ^ (self.p[1] as u16)) & 0x8000 != 0 {
            -128
        } else {
            128
        };
        let mut wd3: i16 = (sign2 + (wd32 >> 7) + ((self.a[1] as i32 * 32512) >> 15)) as i16;
        if wd3.abs() > 12288 {
            wd3 = if wd3 < 0 { -12288 } else { 12288 };
        }
        let ap1 = wd3;

        // UPPOL1
        let wd1: i16 = if ((p as u16) ^ (self.p[0] as u16)) & 0x8000 != 0 {
            -192
        } else {
            192
        };
        let wd2: i16 = ((self.a[0] as i32 * 32640) >> 15) as i16;
        let mut ap0 = sat_add16(wd1, wd2);

        let wd3 = sat_sub16(15360, ap1);
        if ap0.abs() > wd3 {
            ap0 = if ap0 < 0 { -wd3 } else { wd3 };
        }

        // FILTEP
        let mut w = sat_add16(r, r);
        let sp: i16 = {
            let t1 = ((ap0 as i32 * w as i32) >> 15) as i16;
            w = sat_add16(self.r, self.r);
            let t2 = ((ap1 as i32 * w as i32) >> 15) as i16;
            sat_add16(t1, t2)
        };
        self.r = r;
        self.a[1] = ap1;
        self.a[0] = ap0;
        self.p[1] = self.p[0];
        self.p[0] = p;

        // UPZERO + DELAYA + FILTEZ
        let wd1: i16 = if dx == 0 { 0 } else { 128 };
        self.d[0] = dx;
        let mut sz: i32 = 0;
        for i in (0..6).rev() {
            let wd2: i16 = if ((self.d[i + 1] as u16) ^ (dx as u16)) & 0x8000 != 0 {
                -wd1
            } else {
                wd1
            };
            let wd3: i16 = ((self.b[i] as i32 * 32640) >> 15) as i16;
            self.b[i] = sat_add16(wd2, wd3);
            let wd4 = sat_add16(self.d[i], self.d[i]);
            sz += (self.b[i] as i32 * wd4 as i32) >> 15;
            self.d[i + 1] = self.d[i];
        }
        self.sz = sat16(sz);

        // PREDIC
        self.s = sat_add16(sp, self.sz);
    }

    /// Low-band scale update (`LOGSCL` + `SCALEL`).
    fn update_scale_low(&mut self, ril: usize) {
        let il4 = RL42[ril] as usize;
        let wd = ((self.nb as i32 * 127) >> 7) + WL[il4] as i32;
        self.nb = wd.clamp(0, 18432) as i16;
        let wd1 = ((self.nb >> 6) & 31) as usize;
        let wd2 = 8 - (self.nb >> 11);
        let wd3 = if wd2 < 0 {
            ILB[wd1] << (-wd2)
        } else {
            ILB[wd1] >> wd2
        };
        self.det = wd3 << 2;
    }

    /// High-band scale update (`LOGSCH` + `SCALEH`).
    fn update_scale_high(&mut self, ihigh: usize) {
        let ih2 = RH2[ihigh] as usize;
        let wd = ((self.nb as i32 * 127) >> 7) + WH[ih2] as i32;
        self.nb = wd.clamp(0, 22528) as i16;
        let wd1 = ((self.nb >> 6) & 31) as usize;
        let wd2 = 10 - (self.nb >> 11);
        let wd3 = if wd2 < 0 {
            ILB[wd1] << (-wd2)
        } else {
            ILB[wd1] >> wd2
        };
        self.det = wd3 << 2;
    }
}

// (helper removed — sign selection is inlined in `block4`)

/// G.722 operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G722Mode {
    /// 64 kbit/s (6-bit low band + 2-bit high band).
    Mode64k,
    /// 56 kbit/s (5-bit low band, 3 high bits carried).
    Mode56k,
    /// 48 kbit/s (4-bit low band only).
    Mode48k,
}

impl G722Mode {
    fn bits_per_sample(self) -> u32 {
        match self {
            G722Mode::Mode64k => 8,
            G722Mode::Mode56k => 7,
            G722Mode::Mode48k => 6,
        }
    }
}

/// Circular 12-entry line used by the QMF polyphase branches.
#[derive(Debug, Clone, Copy)]
struct Line {
    buf: [i16; 12],
    ptr: usize,
}

impl Line {
    fn new() -> Line {
        Line {
            buf: [0; 12],
            ptr: 0,
        }
    }

    #[inline]
    fn push(&mut self, v: i16) {
        self.buf[self.ptr] = v;
        self.ptr = (self.ptr + 1) % 12;
    }

    /// `Σ coeffs[k]·buf[(ptr+k) % 12]` (oldest first).
    #[inline]
    fn dot(&self, coeffs: &[i16; 12]) -> i32 {
        let mut sum = 0i32;
        let mut idx = self.ptr;
        for &c in coeffs.iter() {
            sum += c as i32 * self.buf[idx] as i32;
            idx = (idx + 1) % 12;
        }
        sum
    }
}

/// G.722 encoder (16 kHz mono PCM in, G.722 octets out).
#[derive(Debug, Clone)]
pub struct G722Encoder {
    mode: G722Mode,
    x: Line,
    y: Line,
    low: Band,
    high: Band,
}

impl G722Encoder {
    /// Create an encoder for the given mode.
    pub fn new(mode: G722Mode) -> G722Encoder {
        G722Encoder {
            mode,
            x: Line::new(),
            y: Line::new(),
            low: Band::new(32),
            high: Band::new(8),
        }
    }

    /// Wire clock (RTP timestamp rate) — always 8000 for G.722.
    pub fn wire_clock() -> u32 {
        8000
    }

    /// Encode 20 ms: exactly 320 PCM samples @16 kHz → 160 octets.
    pub fn encode_frame(&mut self, pcm16k: &[i16]) -> Result<Vec<u8>> {
        if pcm16k.len() != 320 {
            return Err(CodecError::InvalidData(format!(
                "g722 frame must be exactly 320 samples @16 kHz, got {}",
                pcm16k.len()
            )));
        }
        let mut out = Vec::with_capacity(160);
        let bits = self.mode.bits_per_sample();
        let mut j = 0usize;
        while j < 320 {
            // Transmit QMF: two input samples per octet.
            let s0 = pcm16k[j];
            let s1 = pcm16k[j + 1];
            j += 2;
            self.x.push(s0);
            self.y.push(s1);
            let sumodd = self.x.dot(&QMF_FWD);
            let sumeven = self.y.dot(&QMF_REV);
            let xlow = ((sumeven + sumodd) >> 14) as i16;
            let xhigh = ((sumeven - sumodd) >> 14) as i16;

            // ---- Low band ----
            let el = sat_sub16(xlow, self.low.s) as i32;
            let wd = if el >= 0 { el } else { !el };
            let mut i = 1usize;
            while i < 30 {
                let wd1 = (Q6[i] as i32 * self.low.det as i32) >> 12;
                if wd < wd1 {
                    break;
                }
                i += 1;
            }
            let ilow = if el < 0 { ILN[i] as i32 } else { ILP[i] as i32 };

            // INVQAL
            let ril = (ilow >> 2) as usize;
            let dlow = ((self.low.det as i32 * QM4[ril] as i32) >> 15) as i16;
            self.low.update_scale_low(ril);
            self.low.block4(dlow);

            // ---- High band ----
            let eh = sat_sub16(xhigh, self.high.s) as i32;
            let wd = if eh >= 0 { eh } else { !eh };
            let wd1 = (564 * self.high.det as i32) >> 12;
            let mih = if wd >= wd1 { 2usize } else { 1usize };
            let ihigh = if eh < 0 {
                IHN[mih] as i32
            } else {
                IHP[mih] as i32
            };

            let dhigh = ((self.high.det as i32 * QM2[ihigh as usize] as i32) >> 15) as i16;
            self.high.update_scale_high(ihigh as usize);
            self.high.block4(dhigh);

            let code = ((ihigh << 6) | ilow) >> (8 - bits);
            out.push(code as u8);
        }
        Ok(out)
    }
}

impl Encoder for G722Encoder {
    fn encode(&mut self, pcm: &[i16], out: &mut Vec<u8>) -> Result<usize> {
        let frame = self.encode_frame(pcm)?;
        out.extend_from_slice(&frame);
        Ok(frame.len())
    }

    fn sample_rate(&self) -> u32 {
        16000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_samples(&self) -> usize {
        320
    }

    fn reset(&mut self) {
        *self = G722Encoder::new(self.mode);
    }
}

/// G.722 decoder (G.722 octets in, 16 kHz mono PCM out).
#[derive(Debug, Clone)]
pub struct G722Decoder {
    mode: G722Mode,
    x: Line,
    y: Line,
    low: Band,
    high: Band,
    last_codes: Vec<u8>,
}

impl G722Decoder {
    /// Create a decoder for the given mode.
    pub fn new(mode: G722Mode) -> G722Decoder {
        G722Decoder {
            mode,
            x: Line::new(),
            y: Line::new(),
            low: Band::new(32),
            high: Band::new(8),
            last_codes: Vec::new(),
        }
    }

    /// Decode one wire octet into two 16 kHz PCM samples.
    fn decode_octet(&mut self, code: u8, out: &mut Vec<i16>) {
        let c = code as i32;
        let (low_mask, ihigh_shift, core_shift) = match self.mode {
            G722Mode::Mode64k => (0x3Fi32, 6, 2usize),
            G722Mode::Mode56k => (0x1Fi32, 5, 1),
            G722Mode::Mode48k => (0x0Fi32, 4, 0),
        };
        let low6 = c & low_mask;
        let ihigh = (c >> ihigh_shift) & 0x03;
        let wd2_inv: i16 = match self.mode {
            G722Mode::Mode64k => QM6[low6 as usize],
            G722Mode::Mode56k => QM5[low6 as usize],
            G722Mode::Mode48k => QM4[low6 as usize],
        };

        // Block 5L, INVQBL + RECONS + LIMIT
        let wd2l = ((self.low.det as i32 * wd2_inv as i32) >> 15) as i16;
        let rlow = sat15(self.low.s as i32 + wd2l as i32);

        // Block 2L, INVQAL
        let ril = (low6 >> core_shift) as usize;
        let dlow = ((self.low.det as i32 * QM4[ril] as i32) >> 15) as i16;
        self.low.update_scale_low(ril);
        self.low.block4(dlow);

        // Block 2H..6H
        let dhigh = ((self.high.det as i32 * QM2[ihigh as usize] as i32) >> 15) as i16;
        let rhigh = sat15(dhigh as i32 + self.high.s as i32);
        self.high.update_scale_high(ihigh as usize);
        self.high.block4(dhigh);

        // Synthesis QMF: shift by 12 (DC gain 4096) less 1 (15-bit input).
        self.x.push(sat_add16(rlow, rhigh));
        self.y.push(sat_sub16(rlow, rhigh));
        let o1 = sat16(self.y.dot(&QMF_REV) >> 11);
        let o2 = sat16(self.x.dot(&QMF_FWD) >> 11);
        out.push(o1);
        out.push(o2);
    }
}

impl Decoder for G722Decoder {
    fn decode(&mut self, data: &[u8], out: &mut Vec<i16>) -> Result<usize> {
        if data.len() != 160 {
            return Err(CodecError::InvalidData(format!(
                "g722 frame must be exactly 160 octets, got {}",
                data.len()
            )));
        }
        let start = out.len();
        for &c in data {
            self.decode_octet(c, out);
        }
        self.last_codes.clear();
        self.last_codes.extend_from_slice(data);
        Ok(out.len() - start)
    }

    fn conceal(&mut self, out: &mut Vec<i16>) -> Result<usize> {
        // Repeat the last received frame (state evolves, standard
        // frame-repeat concealment), attenuated by 6 dB.
        if self.last_codes.is_empty() {
            for _ in 0..320 {
                out.push(0);
            }
            return Ok(320);
        }
        let start = out.len();
        let codes = self.last_codes.clone();
        for c in codes {
            let before = out.len();
            self.decode_octet(c, out);
            for s in out[before..].iter_mut() {
                *s /= 2;
            }
        }
        Ok(out.len() - start)
    }

    fn sample_rate(&self) -> u32 {
        16000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_samples(&self) -> usize {
        320
    }

    fn reset(&mut self) {
        // A reset must return the decoder to freshly-constructed state:
        // re-importing the old `last_codes` predictor history here kept the
        // previous stream's state alive across resets, so the post-reset
        // output diverged from a fresh decoder (audit 2026-09 P2).
        *self = G722Decoder::new(self.mode);
    }
}

pub(crate) fn make_encoder(clock: u32) -> Result<Box<dyn Encoder>> {
    if clock != 8000 {
        return Err(CodecError::InvalidData(format!(
            "g722 wire clock is 8000, got {clock}"
        )));
    }
    Ok(Box::new(G722Encoder::new(G722Mode::Mode64k)))
}

pub(crate) fn make_decoder(clock: u32) -> Result<Box<dyn Decoder>> {
    if clock != 8000 {
        return Err(CodecError::InvalidData(format!(
            "g722 wire clock is 8000, got {clock}"
        )));
    }
    Ok(Box::new(G722Decoder::new(G722Mode::Mode64k)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn speechish(n: usize) -> Vec<i16> {
        (0..n)
            .map(|i| {
                let t = i as f64 / 16000.0;
                let env = 0.6 + 0.4 * (2.0 * std::f64::consts::PI * 4.0 * t).sin();
                let v = (2.0 * std::f64::consts::PI * 300.0 * t).sin()
                    + 0.6 * (2.0 * std::f64::consts::PI * 900.0 * t).sin()
                    + 0.4 * (2.0 * std::f64::consts::PI * 2400.0 * t).sin()
                    + 0.2 * (2.0 * std::f64::consts::PI * 5200.0 * t).sin();
                (v * 9000.0 * env).clamp(-32768.0, 32767.0) as i16
            })
            .collect()
    }

    /// SNR with best-lag alignment (the QMF contributes ~22 samples of delay).
    fn aligned_snr_db(a: &[i16], b: &[i16], max_lag: isize) -> (f64, isize) {
        let mut best_lag = 0isize;
        let mut best_corr = f64::NEG_INFINITY;
        for lag in (-max_lag..=max_lag).step_by(2) {
            let mut corr = 0.0f64;
            let n = a.len().min(b.len());
            let lo = if lag >= 0 { 0usize } else { (-lag) as usize };
            let hi = if lag >= 0 {
                n.saturating_sub(lag as usize)
            } else {
                n
            };
            let mut i = lo.max(2);
            while i < hi.saturating_sub(2) {
                corr += (a[i] as f64) * (b[(i as isize + lag) as usize] as f64);
                i += 4;
            }
            if corr > best_corr {
                best_corr = corr;
                best_lag = lag;
            }
        }
        let mut sig = 0.0f64;
        let mut err = 0.0f64;
        let n = a.len().min(b.len());
        for (i, &x) in a.iter().enumerate().take(n) {
            let j = i as isize + best_lag;
            if j < 0 || j as usize >= b.len() {
                continue;
            }
            let d = x as f64 - b[j as usize] as f64;
            sig += (x as f64) * (x as f64);
            err += d * d;
        }
        (10.0 * (sig / err.max(1.0)).log10(), best_lag)
    }

    #[test]
    fn wire_lengths_all_modes() {
        let pcm = speechish(320);
        for mode in [G722Mode::Mode64k, G722Mode::Mode56k, G722Mode::Mode48k] {
            let mut e = G722Encoder::new(mode);
            let frame = e.encode_frame(&pcm).unwrap();
            assert_eq!(frame.len(), 160, "{mode:?}");
        }
    }

    #[test]
    fn roundtrip_snr_64k() {
        let mut e = G722Encoder::new(G722Mode::Mode64k);
        let mut d = G722Decoder::new(G722Mode::Mode64k);
        let pcm = speechish(32000); // 2 s
        let mut back = Vec::new();
        for chunk in pcm.chunks(320) {
            let frame = e.encode_frame(chunk).unwrap();
            let mut got = Vec::new();
            d.decode(&frame, &mut got).unwrap();
            back.extend_from_slice(&got);
        }
        let (q, lag) = aligned_snr_db(&pcm, &back, 40);
        assert!(
            q > 20.0,
            "g722 64k round-trip SNR {q} dB < 20 dB (lag {lag})"
        );
    }

    #[test]
    fn modes_56k_48k_roundtrip() {
        for mode in [G722Mode::Mode56k, G722Mode::Mode48k] {
            let mut e = G722Encoder::new(mode);
            let mut d = G722Decoder::new(mode);
            let pcm = speechish(6400);
            let mut back = Vec::new();
            for chunk in pcm.chunks(320) {
                let frame = e.encode_frame(chunk).unwrap();
                let mut got = Vec::new();
                d.decode(&frame, &mut got).unwrap();
                back.extend_from_slice(&got);
            }
            let (q, lag) = aligned_snr_db(&pcm, &back, 40);
            assert!(q > 14.0, "{mode:?} SNR {q} dB (lag {lag})");
        }
    }

    #[test]
    fn determinism_after_reset() {
        let pcm = speechish(320);
        let mut e = G722Encoder::new(G722Mode::Mode64k);
        let a = e.encode_frame(&pcm).unwrap();
        e.reset();
        let b = e.encode_frame(&pcm).unwrap();
        assert_eq!(a, b, "encoder must be deterministic after reset");
    }

    #[test]
    fn decoder_reset_returns_to_fresh_state() {
        // A reset decoder must behave exactly like a newly constructed one:
        // predictor history (last_codes) must NOT survive the reset.
        let pcm = speechish(320 * 8);
        let mut e = G722Encoder::new(G722Mode::Mode64k);
        let mut frames: Vec<Vec<u8>> = Vec::new();
        for chunk in pcm.chunks(320) {
            frames.push(e.encode_frame(chunk).unwrap());
        }

        let mut warmed = G722Decoder::new(G722Mode::Mode64k);
        let mut sink = Vec::new();
        for f in &frames {
            warmed.decode(f, &mut sink).unwrap();
        }
        warmed.reset();

        let mut fresh = G722Decoder::new(G722Mode::Mode64k);
        let mut expect = Vec::new();
        let mut got = Vec::new();
        for f in &frames {
            fresh.decode(f, &mut expect).unwrap();
            warmed.decode(f, &mut got).unwrap();
        }
        assert_eq!(got, expect, "post-reset decode must match a fresh decoder");
    }

    #[test]
    fn recovery_after_concealment() {
        // Operationally meaningful invariant: after a loss burst handled by
        // frame-repeat concealment, the decoder re-tracks normal frames.
        let mut e = G722Encoder::new(G722Mode::Mode64k);
        let mut d = G722Decoder::new(G722Mode::Mode64k);
        let speech = speechish(320 * 30);
        let mut frames: Vec<Vec<u8>> = Vec::new();
        for chunk in speech.chunks(320) {
            frames.push(e.encode_frame(chunk).unwrap());
        }
        // 10 good, 10 concealed (lost), 10 good.
        let mut back = Vec::new();
        for (i, f) in frames.iter().enumerate() {
            if (10..20).contains(&i) {
                d.conceal(&mut back).unwrap();
            } else {
                d.decode(f, &mut back).unwrap();
            }
        }
        let tail_in = &speech[320 * 26..];
        let tail_out = &back[320 * 26..];
        let (q, _lag) = aligned_snr_db(tail_in, tail_out, 40);
        eprintln!("g722 post-loss tail SNR: {q:.1} dB");
        assert!(q > 12.0, "decoder did not recover after loss burst: {q} dB");
        // Bounded throughout.
        assert!(back.iter().all(|s| (-32_768..=32_767).contains(s)));
    }

    #[test]
    fn dc_input_bounded() {
        let mut e = G722Encoder::new(G722Mode::Mode64k);
        let mut d = G722Decoder::new(G722Mode::Mode64k);
        let pcm = vec![0i16; 320 * 20];
        let mut out = Vec::new();
        for chunk in pcm.chunks(320) {
            let frame = e.encode_frame(chunk).unwrap();
            d.decode(&frame, &mut out).unwrap();
        }
        let max_amp = out.iter().map(|s| s.unsigned_abs()).max().unwrap();
        assert!(max_amp < 500, "zero input produced {max_amp}");
    }

    #[test]
    fn random_octets_never_panic() {
        let mut d = G722Decoder::new(G722Mode::Mode64k);
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..500 {
            let mut frame = [0u8; 160];
            for b in frame.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = (state >> 24) as u8;
            }
            let mut out = Vec::new();
            let n = d.decode(&frame, &mut out).unwrap();
            assert_eq!(n, 320);
        }
    }

    #[test]
    fn conceal_repeats_and_decays() {
        let mut e = G722Encoder::new(G722Mode::Mode64k);
        let mut d = G722Decoder::new(G722Mode::Mode64k);
        let pcm = speechish(3200);
        for chunk in pcm.chunks(320).take(5) {
            let frame = e.encode_frame(chunk).unwrap();
            let mut got = Vec::new();
            d.decode(&frame, &mut got).unwrap();
        }
        let mut c1 = Vec::new();
        d.conceal(&mut c1).unwrap();
        let mut c2 = Vec::new();
        d.conceal(&mut c2).unwrap();
        assert_eq!(c1.len(), 320);
        let e1: i64 = c1.iter().map(|&s| s as i64 * s as i64).sum();
        let e2: i64 = c2.iter().map(|&s| s as i64 * s as i64).sum();
        assert!(e2 < e1, "concealment energy must decay: {e1} -> {e2}");
        // Fresh decoder: conceal is silence.
        let mut d2 = G722Decoder::new(G722Mode::Mode64k);
        let mut c3 = Vec::new();
        d2.conceal(&mut c3).unwrap();
        assert!(c3.iter().all(|&s| s == 0));
    }

    #[test]
    fn factory_clock_checks() {
        assert!(make_encoder(8000).is_ok());
        assert!(make_decoder(8000).is_ok());
        assert!(matches!(
            make_encoder(16000),
            Err(CodecError::InvalidData(_))
        ));
        assert!(matches!(
            make_decoder(44100),
            Err(CodecError::InvalidData(_))
        ));
    }

    #[test]
    fn trait_metadata() {
        let e = G722Encoder::new(G722Mode::Mode64k);
        assert_eq!(e.sample_rate(), 16000);
        assert_eq!(e.channels(), 1);
        assert_eq!(e.frame_samples(), 320);
        assert_eq!(G722Encoder::wire_clock(), 8000);
        let mut d = G722Decoder::new(G722Mode::Mode56k);
        d.reset();
    }

    #[test]
    fn frame_size_enforced() {
        let mut e = G722Encoder::new(G722Mode::Mode64k);
        assert!(matches!(
            e.encode_frame(&[0i16; 319]),
            Err(CodecError::InvalidData(_))
        ));
        let mut d = G722Decoder::new(G722Mode::Mode64k);
        let mut out = Vec::new();
        assert!(matches!(
            d.decode(&[0u8; 159], &mut out),
            Err(CodecError::InvalidData(_))
        ));
    }

    #[test]
    fn sat_helpers() {
        assert_eq!(sat16(40000), 32767);
        assert_eq!(sat16(-40000), -32768);
        assert_eq!(sat15(20000), 16383);
        assert_eq!(sat15(-20000), -16384);
        assert_eq!(sat_add16(32000, 32000), 32767);
        assert_eq!(sat_sub16(-32000, 32000), -32768);
    }
}
