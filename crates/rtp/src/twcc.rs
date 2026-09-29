//! transport-cc congestion feedback (draft-holmerberg-avt-01, the format
//! every WebRTC stack sends as `RTPFB` FMT 15).
//!
//! The media *receiver* reports per-packet arrival deltas; the media
//! *sender* turns those into send/receive delay measurements for
//! congestion control.
//!
//! Wire format (FCI, after the shared RTPFB sender/media SSRC header):
//! - base sequence number (u16) — first sequence covered
//! - packet status count (u16) — sequences covered
//! - reference time (u24) — in 64 ms units ([`REF_SCALE_MS`])
//! - feedback packet count (u8) — sender-side round-trip counter
//! - status chunk stream: run chunks (V=0: 1-bit symbol + 13-bit run
//!   length) or vector chunks (V=1: fourteen 2-bit symbols), symbols
//!   0 = not received, 1 = small delta, 2 = large/negative delta
//! - recv delta stream, in packet order: small = u8 · [`DELTA_SCALE_US`],
//!   large = i16 · [`DELTA_SCALE_US`]

use crate::nack::wrap_diff;
use crate::packet::RtpError;
use crate::rtcp::RtcpPacket;
use std::collections::{HashMap, HashSet, VecDeque};

/// FMT for transport-cc feedback inside `RTPFB` (PT 205).
pub const FMT_TWCC: u8 = 15;
/// Recv-delta unit: microseconds per LSB (draft §3.1.5).
pub const DELTA_SCALE_US: i64 = 250;
/// Reference-time unit: milliseconds per LSB (draft §3.1.4).
pub const REF_SCALE_MS: i64 = 64;

/// One packet covered by a transport-cc feedback report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwccEntry {
    /// Wire sequence number (base sequence + offset, mod 2¹⁶).
    pub seq: u16,
    pub received: bool,
    /// Arrival delta from the reference time, in microseconds.
    pub delta_us: Option<i64>,
}

/// A transport-cc feedback report (typed view over `RTPFB` FMT 15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwccFeedback {
    pub sender_ssrc: u32,
    pub media_ssrc: u32,
    /// First sequence number covered.
    pub base_seq: u16,
    /// Reference time in milliseconds (multiple of [`REF_SCALE_MS`]).
    pub ref_time_ms: u64,
    /// Round-trip counter of feedback packets — a gap means feedback loss.
    pub fb_count: u8,
    pub entries: Vec<TwccEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sym {
    NotReceived,
    Small(u8),
    Large(i16),
}

/// Round microseconds to the nearest 250 µs tick.
fn quantize_ticks(us: i64) -> i64 {
    ((us as f64) / DELTA_SCALE_US as f64).round() as i64
}

fn symbol_for(entry: &TwccEntry) -> Option<Sym> {
    if !entry.received {
        return Some(Sym::NotReceived);
    }
    let us = entry.delta_us?;
    let ticks = quantize_ticks(us);
    if (0..=255).contains(&ticks) {
        Some(Sym::Small(ticks as u8))
    } else if (i16::MIN as i64..=i16::MAX as i64).contains(&ticks) {
        Some(Sym::Large(ticks as i16))
    } else {
        None // beyond the representable range
    }
}

/// Encode the status-chunk + recv-delta stream. Chunks are chosen greedily:
/// a run chunk when ≥ 7 consecutive packets share one run-encodable status
/// (runs only support not-received / one fixed small delta), otherwise
/// vector chunks packing up to 7 packets each. Per the draft the recv-delta
/// list strictly FOLLOWS the complete chunk list (in packet order); the
/// stream is padded to a 4-byte boundary.
pub fn twcc_fci(entries: &[TwccEntry]) -> Result<Vec<u8>, RtpError> {
    if entries.len() > 0xFFFF {
        return Err(RtpError::TooShort {
            need: 0xFFFF,
            got: entries.len(),
        });
    }
    let mut syms: Vec<Sym> = Vec::with_capacity(entries.len());
    for e in entries {
        match symbol_for(e) {
            Some(s) => syms.push(s),
            None => return Err(RtpError::BadVersion(0)), // unrepresentable delta
        }
    }

    // Pass 1: chunk words + the full delta stream (packet order).
    let mut chunk_words: Vec<u16> = Vec::new();
    let mut deltas: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < syms.len() {
        let run_len = syms[i..]
            .iter()
            .take_while(|s| **s == syms[i])
            .count()
            .min(0x1FFF);
        let run_ok = matches!(syms[i], Sym::NotReceived | Sym::Small(_)) && run_len >= 7;
        if run_ok {
            // Run chunk: V=0, S=symbol-bit, 13-bit length.
            let w: u16 = match syms[i] {
                Sym::NotReceived => run_len as u16,
                Sym::Small(_) => 0x4000 | run_len as u16,
                _ => unreachable!("run_ok implies not-received or small"),
            };
            chunk_words.push(w);
            if let Sym::Small(d) = syms[i] {
                for _ in 0..run_len {
                    deltas.push(d);
                }
            }
            i += run_len;
        } else {
            let take = (syms.len() - i).min(7);
            // Vector chunk: V=1 + up to fourteen 2-bit symbols.
            let mut w: u16 = 0x8000;
            for (k, s) in syms[i..i + take].iter().enumerate() {
                let bits: u16 = match s {
                    Sym::NotReceived => 0,
                    Sym::Small(_) => 1,
                    Sym::Large(_) => 2,
                };
                w |= bits << (13 - 2 * k);
            }
            chunk_words.push(w);
            for s in &syms[i..i + take] {
                match s {
                    Sym::Small(d) => deltas.push(*d),
                    Sym::Large(d) => deltas.extend_from_slice(&d.to_be_bytes()),
                    Sym::NotReceived => {}
                }
            }
            i += take;
        }
    }

    // Pass 2: chunk stream, then delta stream, then pad to 4 bytes.
    let mut out: Vec<u8> = Vec::with_capacity(chunk_words.len() * 2 + deltas.len() + 4);
    for w in chunk_words {
        out.extend_from_slice(&w.to_be_bytes());
    }
    out.extend_from_slice(&deltas);
    let pad = (4 - out.len() % 4) % 4;
    out.extend(std::iter::repeat_n(0, pad));
    Ok(out)
}

/// Parse the FCI of a `RTPFB` FMT-15 packet into typed entries.
///
/// The chunk stream is walked until `status_count` packets are described
/// (the final chunk may carry unused slots); the recv-delta stream then
/// follows contiguously in packet order.
pub fn parse_twcc(pkt: &RtcpPacket) -> Result<TwccFeedback, RtpError> {
    let RtcpPacket::Rtpfb {
        fmt,
        sender_ssrc,
        media_ssrc,
        payload,
    } = pkt
    else {
        return Err(RtpError::BadVersion(0));
    };
    if *fmt != FMT_TWCC {
        return Err(RtpError::BadVersion(*fmt));
    }
    if payload.len() < 8 {
        return Err(RtpError::TooShort {
            need: 8,
            got: payload.len(),
        });
    }
    let base_seq = u16::from_be_bytes([payload[0], payload[1]]);
    let status_count = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let ref_ticks = ((payload[4] as u32) << 16) | ((payload[5] as u32) << 8) | payload[6] as u32;
    let fb_count = payload[7];
    let fci = &payload[8..];

    // ---- chunk pass ----
    let mut syms: Vec<Sym> = Vec::with_capacity(status_count);
    let mut off = 0usize;
    while syms.len() < status_count {
        if fci.len() < off + 2 {
            return Err(RtpError::Truncated);
        }
        let w = u16::from_be_bytes([fci[off], fci[off + 1]]);
        off += 2;
        if w & 0x8000 == 0 {
            // Run chunk.
            let run = (w & 0x1FFF) as usize;
            let sym = if w & 0x4000 != 0 {
                Sym::Small(0) // delta value filled in during the delta pass
            } else {
                Sym::NotReceived
            };
            for _ in 0..run.min(status_count - syms.len()) {
                syms.push(sym);
            }
        } else {
            // Vector chunk: V=1 + seven 2-bit symbols (libwebrtc wire form:
            // sym_k at bits 13−2k, bit 0 unused).
            for k in 0..7u32 {
                if syms.len() >= status_count {
                    break;
                }
                let bits = (w >> (13 - 2 * k)) & 0b11;
                syms.push(match bits {
                    0 => Sym::NotReceived,
                    1 => Sym::Small(0),
                    2 => Sym::Large(0),
                    _ => return Err(RtpError::BadVersion(bits as u8)), // reserved
                });
            }
        }
    }

    // ---- delta pass ----
    let mut entries = Vec::with_capacity(status_count);
    let mut seq = base_seq;
    for sym in &syms {
        let (received, delta_us) = match sym {
            Sym::NotReceived => (false, None),
            Sym::Small(_) => {
                if fci.len() < off + 1 {
                    return Err(RtpError::Truncated);
                }
                let ticks = fci[off] as i64;
                off += 1;
                (true, Some(ticks * DELTA_SCALE_US))
            }
            Sym::Large(_) => {
                if fci.len() < off + 2 {
                    return Err(RtpError::Truncated);
                }
                let ticks = i16::from_be_bytes([fci[off], fci[off + 1]]) as i64;
                off += 2;
                (true, Some(ticks * DELTA_SCALE_US))
            }
        };
        entries.push(TwccEntry {
            seq,
            received,
            delta_us,
        });
        seq = seq.wrapping_add(1);
    }
    Ok(TwccFeedback {
        sender_ssrc: *sender_ssrc,
        media_ssrc: *media_ssrc,
        base_seq,
        ref_time_ms: ((ref_ticks as i64) * REF_SCALE_MS) as u64,
        fb_count,
        entries,
    })
}

/// Build the typed `RTPFB` FMT-15 packet for `fb`.
pub fn twcc_packet(fb: &TwccFeedback) -> Result<RtcpPacket, RtpError> {
    let fci_body = twcc_fci(&fb.entries)?;
    let ref_ticks = (fb.ref_time_ms as i64 / REF_SCALE_MS) as u32;
    let mut payload = Vec::with_capacity(8 + fci_body.len());
    payload.extend_from_slice(&fb.base_seq.to_be_bytes());
    payload.extend_from_slice(&(fb.entries.len() as u16).to_be_bytes());
    payload.push((ref_ticks >> 16) as u8);
    payload.push((ref_ticks >> 8) as u8);
    payload.push(ref_ticks as u8);
    payload.push(fb.fb_count);
    payload.extend_from_slice(&fci_body);
    Ok(RtcpPacket::Rtpfb {
        fmt: FMT_TWCC,
        sender_ssrc: fb.sender_ssrc,
        media_ssrc: fb.media_ssrc,
        payload,
    })
}

/// Receiver-side arrival recorder: feed every accepted media packet, then
/// periodically drain a [`TwccFeedback`] to send back to the media sender.
///
/// Sequence gaps the receiver observed are reported as not-received slots
/// so the sender can attribute loss. Wraparound handled via extended
/// sequence numbers; arrival times are microseconds (virtual or wall).
#[derive(Debug)]
pub struct TwccRxMonitor {
    max_entries: usize,
    last_ext: i64,
    started: bool,
    pending: Vec<(i64, Option<u64>)>,
}

impl TwccRxMonitor {
    pub fn new(max_entries: usize) -> TwccRxMonitor {
        TwccRxMonitor {
            max_entries: max_entries.max(1),
            last_ext: -1,
            started: false,
            pending: Vec::new(),
        }
    }

    /// Observe a packet (or a gap, via `arrival_us = None`).
    pub fn on_packet(&mut self, seq: u16, arrival_us: Option<u64>) {
        if !self.started {
            self.started = true;
            self.last_ext = seq as i64;
            self.pending.push((seq as i64, arrival_us));
            return;
        }
        let d = wrap_diff(seq, (self.last_ext & 0xFFFF) as u16);
        let ext = self.last_ext + d;
        if d.abs() > 1_000 {
            // Stream restart: forget pending history.
            self.pending.clear();
            self.pending.push((seq as i64, arrival_us));
            self.last_ext = seq as i64;
            return;
        }
        if ext <= self.last_ext {
            return; // duplicate / reorder below the cursor: not re-reported
        }
        // Mark the skipped slots as not received (bounded by max_entries).
        let mut gap = self.last_ext + 1;
        while gap < ext && self.pending.len() < self.max_entries {
            self.pending.push((gap, None));
            gap += 1;
        }
        if self.pending.len() < self.max_entries {
            self.pending.push((ext, arrival_us));
            self.last_ext = ext;
        }
        self.trim();
    }

    fn trim(&mut self) {
        while self.pending.len() > self.max_entries {
            self.pending.remove(0);
        }
    }

    /// Build a feedback report from the pending window (if any) and clear it.
    pub fn build_feedback(
        &mut self,
        sender_ssrc: u32,
        media_ssrc: u32,
        fb_count: u8,
    ) -> Option<TwccFeedback> {
        if self.pending.is_empty() {
            return None;
        }
        let base_ext = self.pending[0].0;
        let ref_us = self.pending.iter().find_map(|(_, a)| *a).unwrap_or(0);
        // Reference time lives on the 64 ms grid, at or below the first
        // arrival, so every delta stays non-negative.
        let ref_time_ms = (ref_us / 1_000 / REF_SCALE_MS as u64) * REF_SCALE_MS as u64;
        let ref_us_grid = ref_time_ms * 1_000;
        let entries = self
            .pending
            .drain(..)
            .map(|(ext, arrival)| TwccEntry {
                seq: ext as u16,
                received: arrival.is_some(),
                delta_us: arrival.map(|a| (a as i64 - ref_us_grid as i64).max(0)),
            })
            .collect();
        Some(TwccFeedback {
            sender_ssrc,
            media_ssrc,
            base_seq: base_ext as u16,
            ref_time_ms,
            fb_count,
            entries,
        })
    }
}

/// Per-packet send/receive correlation produced by [`TwccSendTracker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwccPacketResult {
    pub seq: u16,
    pub received: bool,
    pub sent_us: Option<u64>,
    pub recv_us: Option<u64>,
    /// `recv − sent` in microseconds; `None` when unknown or lost.
    pub delay_us: Option<i64>,
}

/// Aggregated transport-cc measurements for the congestion controller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwccReport {
    pub packets: Vec<TwccPacketResult>,
    /// Sequences inside the reported window that this peer sent.
    pub sent_in_window: usize,
    /// Of those, how many the receiver reported as received.
    pub received: usize,
    /// Of those, how many the receiver reported as missing.
    pub lost: usize,
    pub max_delay_us: i64,
    pub mean_delay_us: i64,
}

/// Sender-side tracker: record send times, correlate incoming transport-cc
/// feedback into per-packet delays and window loss.
#[derive(Debug)]
pub struct TwccSendTracker {
    sent: HashMap<u16, u64>,
    order: VecDeque<u16>,
    max_tracked: usize,
}

impl TwccSendTracker {
    pub fn new(max_tracked: usize) -> TwccSendTracker {
        TwccSendTracker {
            sent: HashMap::new(),
            order: VecDeque::new(),
            max_tracked: max_tracked.max(1),
        }
    }

    /// Remember when `seq` was sent (microseconds).
    pub fn record_send(&mut self, seq: u16, now_us: u64) {
        if !self.sent.contains_key(&seq) {
            self.order.push_back(seq);
        }
        self.sent.insert(seq, now_us);
        while self.order.len() > self.max_tracked {
            let old = self.order.pop_front().expect("non-empty");
            self.sent.remove(&old);
        }
    }

    /// Correlate a feedback report against recorded send times.
    pub fn on_feedback(&self, fb: &TwccFeedback) -> TwccReport {
        let recv_base_us = fb.ref_time_ms * 1_000;
        let packets: Vec<TwccPacketResult> = fb
            .entries
            .iter()
            .map(|e| {
                let recv_us = e
                    .received
                    .then(|| (recv_base_us as i64 + e.delta_us.unwrap_or(0)) as u64);
                let sent_us = self.sent.get(&e.seq).copied();
                let delay_us = match (sent_us, recv_us) {
                    (Some(s), Some(r)) => Some(r as i64 - s as i64),
                    _ => None,
                };
                TwccPacketResult {
                    seq: e.seq,
                    received: e.received,
                    sent_us,
                    recv_us,
                    delay_us,
                }
            })
            .collect();

        let received_set: HashSet<u16> = fb
            .entries
            .iter()
            .filter(|e| e.received)
            .map(|e| e.seq)
            .collect();
        let window: HashSet<u16> = (0..fb.entries.len())
            .map(|k| fb.base_seq.wrapping_add(k as u16))
            .collect();
        let mut received = 0usize;
        let mut lost = 0usize;
        for seq in &window {
            if self.sent.contains_key(seq) {
                if received_set.contains(seq) {
                    received += 1;
                } else {
                    lost += 1;
                }
            }
        }

        let delays: Vec<i64> = packets.iter().filter_map(|p| p.delay_us).collect();
        let max_delay_us = delays.iter().copied().max().unwrap_or(0);
        let mean_delay_us = if delays.is_empty() {
            0
        } else {
            delays.iter().sum::<i64>() / delays.len() as i64
        };
        TwccReport {
            sent_in_window: received + lost,
            received,
            lost,
            max_delay_us,
            mean_delay_us,
            packets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtcp::encode_packet;

    fn entry(seq: u16, delta_us: Option<i64>) -> TwccEntry {
        TwccEntry {
            seq,
            received: delta_us.is_some(),
            delta_us,
        }
    }

    #[test]
    fn small_delta_vector_roundtrip() {
        let entries: Vec<TwccEntry> = (0..7)
            .map(|i| entry(i, Some(1000 + i as i64 * 250)))
            .collect();
        let fci = twcc_fci(&entries).unwrap();
        // 2-byte chunk + 7 one-byte deltas = 9 → padded to a 4-byte boundary.
        assert_eq!(fci.len(), 12);
        let w = u16::from_be_bytes([fci[0], fci[1]]);
        assert_eq!(w >> 15, 1, "vector chunk");
        for k in 0..7u32 {
            assert_eq!((w >> (13 - 2 * k)) & 0b11, 1, "symbol {k} small");
        }
    }

    #[test]
    fn run_chunk_compresses_loss() {
        let mut entries: Vec<TwccEntry> = (0..3).map(|i| entry(i, Some(500))).collect();
        entries.extend((3..23).map(|i| entry(i, None)));
        entries.extend((23..25).map(|i| entry(i, Some(500))));
        let fci = twcc_fci(&entries).unwrap();
        let has_run = fci.chunks(2).any(|c| c.len() == 2 && c[0] & 0x80 == 0);
        assert!(has_run, "expected a run chunk in {fci:02x?}");
        assert!(fci.len() < 25 * 2, "runs must compress: {}", fci.len());
    }

    #[test]
    fn large_and_negative_deltas() {
        let entries = vec![
            entry(0, Some(200_000)), // > 63.75 ms → large positive
            entry(1, Some(-4_000)),  // negative → large negative
            entry(2, Some(0)),       // zero → small 0
        ];
        let fci = twcc_fci(&entries).unwrap();
        let w = u16::from_be_bytes([fci[0], fci[1]]);
        assert_eq!((w >> 15) & 1, 1, "vector chunk");
        assert_eq!((w >> 13) & 0b11, 2, "sym0 large");
        assert_eq!((w >> 11) & 0b11, 2, "sym1 large");
        assert_eq!((w >> 9) & 0b11, 1, "sym2 small");
        assert_eq!(&fci[2..4], &800i16.to_be_bytes());
        assert_eq!(&fci[4..6], &(-16i16).to_be_bytes());
        assert_eq!(fci[6], 0);
    }

    #[test]
    fn delta_quantized_to_250us_grid() {
        // 499 µs rounds to tick 2 (500 µs) in the small range.
        let fci = twcc_fci(&[entry(0, Some(499))]).unwrap();
        assert_eq!(fci[2], 2);
    }

    #[test]
    fn unrepresentable_delta_rejected() {
        assert!(twcc_fci(&[entry(0, Some(10_000_000))]).is_err());
    }

    #[test]
    #[allow(clippy::identity_op)] // hand-built wire form keeps all symbol slots visible
    fn parse_known_wire_form() {
        // Hand-built FCI: base=100, count=3, ref_ticks=5 (320 ms), fb=7;
        // vector chunk [small, not-received, large]; deltas u8 4, i16 -8.
        let mut fci: Vec<u8> = vec![0x00, 0x64, 0x00, 0x03, 0x00, 0x00, 0x05, 0x07];
        // Vector chunk word: V=1, sym0=small(1), sym1=not-received(0), sym2=large(2).
        let w: u16 = 0x8000 | (1 << 13) | (0 << 11) | (2 << 9);
        fci.extend_from_slice(&w.to_be_bytes());
        fci.push(4); // small delta: 4 × 250 µs
        fci.extend_from_slice(&(-8i16).to_be_bytes()); // large: −2000 µs
        fci.extend(std::iter::repeat_n(0, (4 - fci.len() % 4) % 4));

        let pkt = RtcpPacket::Rtpfb {
            fmt: FMT_TWCC,
            sender_ssrc: 0x1111,
            media_ssrc: 0x2222,
            payload: fci,
        };
        let fb = parse_twcc(&pkt).unwrap();
        assert_eq!(fb.sender_ssrc, 0x1111);
        assert_eq!(fb.media_ssrc, 0x2222);
        assert_eq!(fb.base_seq, 100);
        assert_eq!(fb.ref_time_ms, 320);
        assert_eq!(fb.fb_count, 7);
        assert_eq!(
            fb.entries,
            vec![
                entry(100, Some(1_000)),
                entry(101, None),
                entry(102, Some(-2_000)),
            ]
        );
    }

    #[test]
    fn packet_roundtrip_via_rtcp_codec() {
        let fb = TwccFeedback {
            sender_ssrc: 0xAA,
            media_ssrc: 0xBB,
            base_seq: 65530,
            ref_time_ms: 64 * 1_000,
            fb_count: 42,
            entries: vec![
                entry(65530, Some(500)),
                entry(65531, None),
                entry(65532, None),
                entry(65533, Some(90_000)),
                entry(65534, Some(-1_000)),
                entry(65535, Some(750)),
                entry(0, Some(250)),
                entry(1, None),
                entry(2, Some(63_750)),
            ],
        };
        let pkt = twcc_packet(&fb).unwrap();
        let compound = encode_packet(&pkt);
        let parsed = crate::rtcp::parse_compound(&compound).unwrap();
        let back = parse_twcc(&parsed[0]).unwrap();
        assert_eq!(back, fb, "full RTCP round-trip incl. seq wraparound");
    }

    #[test]
    fn rejects_non_twcc_and_short_payloads() {
        let pli = RtcpPacket::Psfb {
            fmt: 1,
            sender_ssrc: 1,
            media_ssrc: 2,
            payload: vec![],
        };
        assert!(parse_twcc(&pli).is_err());
        let nack = RtcpPacket::Rtpfb {
            fmt: 1,
            sender_ssrc: 1,
            media_ssrc: 2,
            payload: vec![0, 1, 0, 2],
        };
        assert!(parse_twcc(&nack).is_err());
        let short = RtcpPacket::Rtpfb {
            fmt: FMT_TWCC,
            sender_ssrc: 1,
            media_ssrc: 2,
            payload: vec![0; 7],
        };
        assert!(parse_twcc(&short).is_err());
        // Truncated delta stream (small-delta symbol but no delta byte).
        let truncated = RtcpPacket::Rtpfb {
            fmt: FMT_TWCC,
            sender_ssrc: 1,
            media_ssrc: 2,
            payload: vec![0, 0, 0, 1, 0, 0, 0, 0, 0xA0, 0x00],
        };
        assert!(parse_twcc(&truncated).is_err());
    }

    #[test]
    fn monitor_builds_feedback_with_gap_markers() {
        let mut m = TwccRxMonitor::new(256);
        m.on_packet(10, Some(1_000_000));
        m.on_packet(11, Some(1_005_000));
        m.on_packet(14, Some(1_012_000)); // 12, 13 never seen
        let fb = m.build_feedback(0x1, 0x2, 1).expect("feedback");
        assert_eq!(fb.base_seq, 10);
        // Reference floors to the 64 ms grid at/below the first arrival:
        // 1_000_000 µs = 1000 ms → 15 × 64 = 960 ms.
        assert_eq!(fb.ref_time_ms, 960);
        assert_eq!(fb.fb_count, 1);
        assert_eq!(fb.entries.len(), 5);
        assert_eq!(fb.entries[0].seq, 10);
        assert_eq!(fb.entries[0].delta_us, Some(40_000));
        assert_eq!(fb.entries[1].delta_us, Some(45_000));
        assert_eq!(fb.entries[2], entry(12, None));
        assert_eq!(fb.entries[3], entry(13, None));
        assert_eq!(fb.entries[4].delta_us, Some(52_000));
        // Window drained.
        assert!(m.build_feedback(0x1, 0x2, 2).is_none());
        // And it parses back identically.
        let pkt = twcc_packet(&fb).unwrap();
        let parsed = crate::rtcp::parse_compound(&crate::rtcp::encode_packet(&pkt)).unwrap();
        let back = parse_twcc(&parsed[0]).unwrap();
        assert_eq!(back.entries, fb.entries);
        assert_eq!(back.ref_time_ms, 960);
    }

    #[test]
    fn monitor_bounds_memory_and_restarts_on_jump() {
        let mut m = TwccRxMonitor::new(8);
        for s in 0..50u16 {
            m.on_packet(s, Some(1_000 + s as u64 * 1_000));
        }
        // Feedback window is capped at max_entries.
        let fb = m.build_feedback(1, 1, 1).expect("feedback");
        assert!(fb.entries.len() <= 8);
        // A > 1000 forward jump restarts the window.
        let mut m2 = TwccRxMonitor::new(64);
        m2.on_packet(5, Some(1_000));
        m2.on_packet(5 + 2_000, Some(2_000));
        let fb2 = m2.build_feedback(1, 1, 1).expect("feedback");
        assert_eq!(fb2.entries.len(), 1);
        assert_eq!(fb2.entries[0].seq, 2005);
    }

    #[test]
    fn send_tracker_correlates_delays_and_loss() {
        let mut t = TwccSendTracker::new(1024);
        t.record_send(10, 100_000);
        t.record_send(11, 107_000);
        t.record_send(12, 120_000);
        let fb = TwccFeedback {
            sender_ssrc: 9,
            media_ssrc: 9,
            base_seq: 10,
            ref_time_ms: 100,
            fb_count: 1,
            entries: vec![
                entry(10, Some(5_000)),
                entry(11, Some(15_000)),
                entry(12, None),
            ],
        };
        let rep = t.on_feedback(&fb);
        assert_eq!(rep.sent_in_window, 3);
        assert_eq!(rep.received, 2);
        assert_eq!(rep.lost, 1);
        assert_eq!(rep.packets[0].delay_us, Some(5_000)); // 105_000 − 100_000
        assert_eq!(rep.packets[1].delay_us, Some(8_000)); // 115_000 − 107_000
        assert_eq!(rep.packets[2].delay_us, None);
        assert_eq!(rep.max_delay_us, 8_000);
        assert_eq!(rep.mean_delay_us, 6_500);
        // Unknown seq (never sent) reports delay None without panicking.
        let fb2 = TwccFeedback {
            entries: vec![entry(99, Some(1_000))],
            ..fb
        };
        let rep2 = t.on_feedback(&fb2);
        assert_eq!(rep2.packets[0].sent_us, None);
        assert_eq!(rep2.packets[0].delay_us, None);
    }

    #[test]
    fn send_tracker_evicts_old_sends() {
        let mut t = TwccSendTracker::new(2);
        t.record_send(1, 100);
        t.record_send(2, 200);
        t.record_send(3, 300);
        assert_eq!(t.sent.get(&1), None, "oldest evicted");
        assert_eq!(t.sent.get(&3), Some(&300));
    }
}
