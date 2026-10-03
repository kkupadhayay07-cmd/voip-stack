//! Loss recovery: RTCP Generic NACK (RFC 4585 §6.2.1) and RTX
//! retransmission streams (RFC 4588).
//!
//! Receiver side: [`NackTracker`] watches the incoming sequence space and
//! reports missing packets as `(PID, BLP)` FCI entries — the same bitmap
//! format Chrome and every WebRTC stack sends. Sender side: an
//! [`RtxPool`] stores recent packets; NACKed packets are re-sent either
//! verbatim (same-SSRC) or through an [`RtxStream`] (RFC 4588: separate
//! SSRC + payload type, the original sequence number prepended to the
//! payload as the OSN). [`RtxDepacketizer`] reverses the RTX format so a
//! receiver can feed restored packets straight into the jitter buffer.

use crate::packet::{RtpError, RtpPacket};
use crate::rtcp::RtcpPacket;
use std::collections::{BTreeMap, VecDeque};

/// RTCP transport-feedback packet type (RFC 4585 §6.1).
pub const PT_RTPFB: u8 = 205;
/// RTPFB FMT for Generic NACK (RFC 4585 §6.2.1).
pub const FMT_NACK: u8 = 1;

/// One Generic NACK FCI entry: a missing `pid` plus a 16-bit bitmap of the
/// 16 packets that follow it (RFC 4585 §6.2.1, Figure 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericNack {
    /// Packet ID of the first missing sequence number.
    pub pid: u16,
    /// Bit `i` (LSB first) set ⇒ `pid + 1 + i` is missing too.
    pub blp: u16,
}

impl GenericNack {
    /// All missing sequence numbers covered by this entry, in ascending
    /// wire order (`pid` first, then bitmap bits LSB→MSB).
    pub fn seqs(&self) -> Vec<u16> {
        let mut out = vec![self.pid];
        for bit in 0..16u32 {
            if self.blp & (1 << bit) != 0 {
                out.push(self.pid.wrapping_add(1 + bit as u16));
            }
        }
        out
    }
}

/// Encode FCI entries (4 bytes each: PID + BLP, RFC 4585 §6.2.1).
pub fn nack_fci(entries: &[GenericNack]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 4);
    for e in entries {
        out.extend_from_slice(&e.pid.to_be_bytes());
        out.extend_from_slice(&e.blp.to_be_bytes());
    }
    out
}

/// Decode Generic NACK FCI entries. The payload must be a whole number of
/// 4-byte entries.
pub fn parse_nack_fci(payload: &[u8]) -> Result<Vec<GenericNack>, RtpError> {
    if !payload.len().is_multiple_of(4) {
        return Err(RtpError::Truncated);
    }
    let mut out = Vec::with_capacity(payload.len() / 4);
    for c in payload.as_chunks::<4>().0 {
        out.push(GenericNack {
            pid: u16::from_be_bytes([c[0], c[1]]),
            blp: u16::from_be_bytes([c[2], c[3]]),
        });
    }
    Ok(out)
}

/// Build a Generic NACK RTCP packet (`RTPFB`, FMT 1).
pub fn nack_packet(sender_ssrc: u32, media_ssrc: u32, entries: &[GenericNack]) -> RtcpPacket {
    RtcpPacket::Rtpfb {
        fmt: FMT_NACK,
        sender_ssrc,
        media_ssrc,
        payload: nack_fci(entries),
    }
}

/// Expand FCI entries into the flat list of missing sequence numbers.
pub fn nack_seqs(entries: &[GenericNack]) -> Vec<u16> {
    let mut out = Vec::new();
    for e in entries {
        out.extend(e.seqs());
    }
    out
}

/// Tunables for [`NackTracker`].
#[derive(Debug, Clone)]
pub struct NackConfig {
    /// Give up on a missing packet once it is this old (ms of virtual time).
    pub max_hold_ms: u64,
    /// Minimum gap between re-NACKs of the same packet.
    pub repeat_ms: u64,
    /// Stop asking after this many NACKs per packet.
    pub max_nacks: u32,
    /// Never track more missing packets than this (drop the oldest).
    pub max_missing: usize,
    /// A forward jump larger than this is a stream restart, not a gap.
    pub max_jump: i64,
    /// Maximum FCI entries emitted per [`NackTracker::take_ready`] call.
    pub max_fci_per_packet: usize,
}

impl Default for NackConfig {
    fn default() -> Self {
        NackConfig {
            max_hold_ms: 2_000,
            repeat_ms: 100,
            max_nacks: 8,
            max_missing: 512,
            max_jump: 1_000,
            max_fci_per_packet: 64,
        }
    }
}

#[derive(Debug)]
struct Missing {
    first_seen_ms: u64,
    last_nack_ms: Option<u64>,
    nacks: u32,
}

/// Receiver-side missing-packet detector that drives Generic NACK
/// generation. Feed it every accepted media packet (`on_packet`) and every
/// RTX-restored packet (`on_recovered`); poll `take_ready` on an RTCP
/// timer to obtain the FCI entries to send.
///
/// Sequence wraparound is handled by extending the 16-bit wire sequence
/// into an i64 space exactly like the jitter buffer does.
#[derive(Debug)]
pub struct NackTracker {
    cfg: NackConfig,
    ssrc: Option<u32>,
    highest_ext: i64,
    missing: BTreeMap<i64, Missing>,
}

impl Default for NackTracker {
    fn default() -> Self {
        NackTracker::new(NackConfig::default())
    }
}

impl NackTracker {
    pub fn new(cfg: NackConfig) -> NackTracker {
        NackTracker {
            cfg,
            ssrc: None,
            highest_ext: -1,
            missing: BTreeMap::new(),
        }
    }

    fn extend(&self, seq: u16) -> i64 {
        let d = wrap_diff(seq, (self.highest_ext & 0xFFFF) as u16);
        self.highest_ext + d
    }

    fn reset(&mut self, ssrc: u32, seq: u16) {
        self.ssrc = Some(ssrc);
        self.highest_ext = seq as i64;
        self.missing.clear();
    }

    /// Observe a media packet arriving on `ssrc` with wire `seq`.
    pub fn on_packet(&mut self, ssrc: u32, seq: u16, now_ms: u64) {
        match self.ssrc {
            None => {
                self.reset(ssrc, seq);
                return;
            }
            Some(cur) if cur != ssrc => {
                // New stream: restart tracking (RFC 4585 — NACKs are per SSRC).
                self.reset(ssrc, seq);
                return;
            }
            _ => {}
        }
        let ext = self.extend(seq);
        if ext > self.highest_ext {
            if ext - self.highest_ext > self.cfg.max_jump {
                // Absurd jump: treat as a stream restart, not a gap storm.
                self.reset(ssrc, seq);
                return;
            }
            for m in (self.highest_ext + 1)..ext {
                if self.missing.len() >= self.cfg.max_missing {
                    break;
                }
                self.missing.entry(m).or_insert(Missing {
                    first_seen_ms: now_ms,
                    last_nack_ms: None,
                    nacks: 0,
                });
            }
            self.highest_ext = ext;
            // Drop long-lost packets that fell behind the give-up window.
            self.prune(now_ms);
        } else {
            // A previously-missing packet just arrived in order (or a very
            // late one): recover it either way.
            self.missing.remove(&ext);
        }
    }

    /// Observe a packet restored from the RTX stream (original sequence
    /// number already extracted).
    pub fn on_recovered(&mut self, seq: u16) {
        let ext = self.extend(seq);
        self.missing.remove(&ext);
    }

    fn prune(&mut self, now_ms: u64) {
        let cfg = &self.cfg;
        // Give up on packets that are too old or have been NACKed enough.
        self.missing.retain(|_, m| {
            now_ms.saturating_sub(m.first_seen_ms) < cfg.max_hold_ms && m.nacks < cfg.max_nacks
        });
        // Hard cap: drop the oldest entries.
        while self.missing.len() > self.cfg.max_missing {
            let oldest = *self.missing.keys().next().expect("non-empty");
            self.missing.remove(&oldest);
        }
    }

    /// Report missing packets as FCI entries. Each returned entry is marked
    /// as NACKed; re-NACKs are throttled by `repeat_ms` and bounded by
    /// `max_nacks`. Returns at most `max_fci_per_packet` entries (one RTCP
    /// feedback packet's worth).
    pub fn take_ready(&mut self, now_ms: u64) -> Vec<GenericNack> {
        self.prune(now_ms);
        let mut ready: Vec<i64> = Vec::new();
        for (&ext, m) in self.missing.iter_mut() {
            let due = match m.last_nack_ms {
                None => true,
                Some(t) => now_ms.saturating_sub(t) >= self.cfg.repeat_ms,
            };
            if due {
                ready.push(ext);
            }
        }
        ready.sort_unstable();
        ready.truncate(self.cfg.max_fci_per_packet);
        let mut out = Vec::with_capacity(ready.len());
        for &ext in &ready {
            if let Some(m) = self.missing.get_mut(&ext) {
                m.last_nack_ms = Some(now_ms);
                m.nacks += 1;
            }
            out.push(ext as u16);
        }
        batch_into_fci(&out)
    }

    /// Number of currently-tracked missing packets.
    pub fn missing_count(&self) -> usize {
        self.missing.len()
    }

    /// Is this wire sequence number currently considered missing?
    pub fn is_missing(&self, seq: u16) -> bool {
        let ext = self.extend(seq);
        self.missing.contains_key(&ext)
    }

    /// Highest extended sequence observed (−1 before the first packet) —
    /// the value an RTCP receiver report's `highest_sequence` field carries
    /// (cycles in the upper 16 bits, wire sequence in the lower 16).
    pub fn highest_extended(&self) -> i64 {
        self.highest_ext
    }
}

/// 16-bit sequence difference folded into ±32768 (RFC 3550 §A.1) — shared
/// with the TWCC monitor's extended-sequence bookkeeping.
pub(crate) fn wrap_diff(new: u16, old: u16) -> i64 {
    let d = new as i64 - old as i64;
    // RFC 3550 §A.1 canonical comparison: backward wrap above 32767, forward
    // wrap below -32768 — so the ±32768 boundary classifies CONSISTENTLY
    // (half a cycle behind), not one-of-two by sign.
    if d > 32767 {
        d - 65536
    } else if d < -32768 {
        d + 65536
    } else {
        d
    }
}

/// Pack ascending sequence numbers into `(PID, BLP)` FCI entries: a new
/// entry starts whenever a sequence is more than 16 ahead of the entry's
/// `pid` (RFC 4585 §6.2.1 — BLP only covers pid+1..=pid+16).
fn batch_into_fci(seqs: &[u16]) -> Vec<GenericNack> {
    let mut out: Vec<GenericNack> = Vec::new();
    for &s in seqs {
        match out.last_mut() {
            // Fits the current entry's window pid+1..=pid+16 (u16 wrap-safe).
            Some(e) if (1..=16).contains(&s.wrapping_sub(e.pid)) => {
                let bit = s.wrapping_sub(e.pid) - 1;
                e.blp |= 1 << bit;
            }
            _ => out.push(GenericNack { pid: s, blp: 0 }),
        }
    }
    out
}

/// Depth of the sender-side retransmission window ([`RtxPool`]).
pub const RTX_POOL_DEFAULT: usize = 512;

/// Sender-side retransmission storage: keeps the most recent `max_packets`
/// media packets so a Generic NACK can be answered with the original
/// packet (verbatim or re-packetized as RTX).
#[derive(Debug)]
pub struct RtxPool {
    max_packets: usize,
    buf: VecDeque<RtpPacket>,
}

impl RtxPool {
    pub fn new(max_packets: usize) -> RtxPool {
        RtxPool {
            max_packets: max_packets.max(1),
            buf: VecDeque::new(),
        }
    }

    /// Remember a sent packet (cloned).
    pub fn store(&mut self, pkt: &RtpPacket) {
        self.buf.push_back(pkt.clone());
        while self.buf.len() > self.max_packets {
            self.buf.pop_front();
        }
    }

    /// The stored packet with this sequence number, if still in the window.
    pub fn get(&self, seq: u16) -> Option<&RtpPacket> {
        self.buf.iter().find(|p| p.sequence() == seq)
    }

    /// Clones of the stored packets for `seqs`, in input order, skipping
    /// packets that have already left the window.
    pub fn take_for_seqs(&self, seqs: &[u16]) -> Vec<RtpPacket> {
        seqs.iter().filter_map(|s| self.get(*s).cloned()).collect()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// RTX stream state (RFC 4588 §4): a retransmitted packet is sent on its
/// own SSRC with its own payload type (`apt`-linked in SDP) and its own
/// sequence counter; the original 16-bit sequence number rides at the head
/// of the payload as the OSN.
#[derive(Debug)]
pub struct RtxStream {
    pub ssrc: u32,
    pub pt: u8,
    next_seq: u16,
}

impl RtxStream {
    pub fn new(ssrc: u32, pt: u8, first_seq: u16) -> RtxStream {
        RtxStream {
            ssrc,
            pt,
            next_seq: first_seq,
        }
    }

    /// Wrap a media packet into an RTX packet (§4: payload = OSN ‖ original
    /// payload; timestamp and marker are copied; CSRCs MUST NOT be copied;
    /// header extensions are preserved because they may carry MID/RID).
    pub fn packetize(&mut self, orig: &RtpPacket) -> RtpPacket {
        let mut payload = Vec::with_capacity(2 + orig.payload.len());
        payload.extend_from_slice(&orig.sequence().to_be_bytes());
        payload.extend_from_slice(&orig.payload);
        let mut pkt = RtpPacket::new(
            self.pt,
            self.next_seq,
            orig.timestamp(),
            self.ssrc,
            orig.header.marker,
            payload.into(),
        );
        pkt.extension = orig.extension.clone();
        self.next_seq = self.next_seq.wrapping_add(1);
        pkt
    }
}

/// The original sequence number (OSN) from an RTX payload, if present.
pub fn osn_of(rtx_payload: &[u8]) -> Option<u16> {
    if rtx_payload.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([rtx_payload[0], rtx_payload[1]]))
}

/// Receiver-side RTX decoder: recognizes packets on the RTX payload type
/// and restores them to media packets (`apt` payload type + original
/// sequence number + the shared media SSRC) so they can be pushed into the
/// jitter buffer.
#[derive(Debug)]
pub struct RtxDepacketizer {
    media_ssrc: u32,
    media_pt: u8,
    rtx_pt: u8,
    rtx_ssrc: Option<u32>,
}

impl RtxDepacketizer {
    pub fn new(media_ssrc: u32, media_pt: u8, rtx_pt: u8) -> RtxDepacketizer {
        RtxDepacketizer {
            media_ssrc,
            media_pt,
            rtx_pt,
            rtx_ssrc: None,
        }
    }

    /// Pin the RTX SSRC (from SDP `ssrc-group:FID` when available). Until
    /// set, the first packet carrying the RTX payload type teaches it.
    pub fn set_rtx_ssrc(&mut self, ssrc: u32) {
        self.rtx_ssrc = Some(ssrc);
    }

    /// The learned RTX SSRC, if known.
    pub fn rtx_ssrc(&self) -> Option<u32> {
        self.rtx_ssrc
    }

    /// Decode an RTX packet into its original media form; `None` for
    /// non-RTX packets (caller pushes those straight to the JB), foreign
    /// SSRCs, or malformed payloads.
    pub fn process(&mut self, pkt: &RtpPacket) -> Option<RtpPacket> {
        if pkt.payload_type() != self.rtx_pt {
            return None;
        }
        match self.rtx_ssrc {
            Some(s) => {
                if pkt.ssrc() != s {
                    return None;
                }
            }
            None => self.rtx_ssrc = Some(pkt.ssrc()),
        }
        let osn = osn_of(&pkt.payload)?;
        Some(RtpPacket::new(
            self.media_pt,
            osn,
            pkt.timestamp(),
            self.media_ssrc,
            pkt.header.marker,
            pkt.payload.slice(2..),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtcp::parse_compound;
    use bytes::Bytes;

    fn pkt(seq: u16) -> RtpPacket {
        RtpPacket::new(
            96,
            seq,
            1000 * seq as u32,
            0xAA,
            false,
            Bytes::from_static(b"media"),
        )
    }

    #[test]
    fn nack_fci_roundtrip_and_expansion() {
        let entries = vec![
            GenericNack {
                pid: 5,
                blp: 0xA000,
            },
            GenericNack {
                pid: 40,
                blp: 0x0001,
            },
        ];
        let fci = nack_fci(&entries);
        assert_eq!(fci.len(), 8);
        assert_eq!(parse_nack_fci(&fci).unwrap(), entries);
        assert!(parse_nack_fci(&fci[..5]).is_err());
        // pid 5 + blp 0xA000 (bits 13,15) → 5, 19, 21; pid 40 + bit 0 → 41.
        assert_eq!(nack_seqs(&entries), vec![5, 19, 21, 40, 41]);
    }

    #[test]
    fn nack_packet_wire_form() {
        let p = nack_packet(0x1111, 0x2222, &[GenericNack { pid: 7, blp: 0 }]);
        assert_eq!(
            p,
            RtcpPacket::Rtpfb {
                fmt: 1,
                sender_ssrc: 0x1111,
                media_ssrc: 0x2222,
                payload: vec![0, 7, 0, 0],
            }
        );
        let parsed = parse_compound(&crate::rtcp::encode_packet(&p)).unwrap();
        assert_eq!(parsed[0], p);
    }

    #[test]
    fn tracker_detects_gap_and_batches() {
        let mut t = NackTracker::new(NackConfig::default());
        for s in 0..=5u16 {
            t.on_packet(1, s, 100);
        }
        t.on_packet(1, 10, 120);
        assert_eq!(t.missing_count(), 4); // 6,7,8,9
        let nacks = t.take_ready(130);
        assert_eq!(nacks, vec![GenericNack { pid: 6, blp: 0b111 }]);
        assert_eq!(nack_seqs(&nacks), vec![6, 7, 8, 9]);
        // Repeat throttle: immediately again → nothing.
        assert!(t.take_ready(140).is_empty());
        // After repeat_ms the same entries come back.
        let again = t.take_ready(235);
        assert_eq!(again, vec![GenericNack { pid: 6, blp: 0b111 }]);
        assert!(t.take_ready(245).is_empty());
    }

    #[test]
    fn tracker_recovers_on_late_arrival_and_rtx() {
        let mut t = NackTracker::new(NackConfig::default());
        for s in 0..=3u16 {
            t.on_packet(1, s, 10);
        }
        t.on_packet(1, 6, 20);
        assert_eq!(t.missing_count(), 2); // 4,5
        t.on_packet(1, 4, 30); // arrived late
        assert_eq!(t.missing_count(), 1);
        t.on_recovered(5); // RTX restored it
        assert_eq!(t.missing_count(), 0);
        assert!(t.take_ready(40).is_empty());
    }

    #[test]
    fn tracker_gives_up_after_max_nacks_and_expiry() {
        let cfg = NackConfig {
            max_hold_ms: 500,
            repeat_ms: 100,
            max_nacks: 3,
            ..Default::default()
        };
        let mut t = NackTracker::new(cfg);
        t.on_packet(1, 0, 0);
        t.on_packet(1, 2, 0);
        for round in 0..10u32 {
            let now = 50 + round as u64 * 100;
            let nacks = t.take_ready(now);
            if round < 3 {
                assert_eq!(nacks.len(), 1, "round {round}");
            } else {
                assert!(nacks.is_empty(), "round {round}");
            }
        }
        // Expiry path: a fresh gap older than max_hold_ms is dropped.
        t.on_packet(1, 9, 4_000);
        t.on_packet(1, 10, 4_600);
        assert!(t.take_ready(4_700).is_empty());
    }

    #[test]
    fn tracker_stream_restart_clears_stale_gaps() {
        let mut t = NackTracker::new(NackConfig::default());
        t.on_packet(1, 100, 10);
        t.on_packet(1, 105, 20); // gap 101..104
        assert_eq!(t.missing_count(), 4);
        // SSRC change restarts tracking — no stale NACKs from the old stream.
        t.on_packet(2, 500, 30);
        assert_eq!(t.missing_count(), 0);
        assert!(t.take_ready(40).is_empty());
        // A > max_jump forward jump on the same SSRC is also a restart.
        t.on_packet(2, 500 + 2_000, 50);
        assert_eq!(t.missing_count(), 0);
    }

    #[test]
    fn tracker_handles_sequence_wraparound() {
        let mut t = NackTracker::new(NackConfig::default());
        for s in [65530u16, 65531, 65532, 65533] {
            t.on_packet(1, s, 10);
        }
        t.on_packet(1, 2, 20); // wraps past 65534,65535,0,1
        assert_eq!(t.missing_count(), 4);
        let nacks = t.take_ready(30);
        assert_eq!(nack_seqs(&nacks), vec![65534, 65535, 0, 1]);
    }

    #[test]
    fn fci_batching_splits_beyond_sixteen() {
        let seqs: Vec<u16> = (0..20).collect(); // 0..=19
        let entries = batch_into_fci(&seqs);
        assert_eq!(
            entries,
            vec![
                GenericNack {
                    pid: 0,
                    blp: 0xFFFF
                }, // 1..=16
                GenericNack { pid: 17, blp: 0b11 }, // 18, 19
            ]
        );
        assert_eq!(nack_seqs(&entries), seqs);
    }

    #[test]
    fn rtx_packetize_depacketize_roundtrip() {
        let mut orig = pkt(100);
        orig.header.marker = true;
        let mut stream = RtxStream::new(0xBB, 117, 900);
        let rtx = stream.packetize(&orig);
        assert_eq!(rtx.payload_type(), 117);
        assert_eq!(rtx.ssrc(), 0xBB);
        assert_eq!(rtx.sequence(), 900);
        assert_eq!(rtx.timestamp(), orig.timestamp());
        assert!(rtx.header.marker);
        assert_eq!(osn_of(&rtx.payload), Some(100));
        // Payload = OSN ‖ original payload.
        assert_eq!(&rtx.payload[2..], &*orig.payload);

        let mut dep = RtxDepacketizer::new(0xAA, 96, 117);
        let restored = dep.process(&rtx).expect("decoded");
        assert_eq!(restored, orig);
        assert_eq!(dep.rtx_ssrc(), Some(0xBB));
        // Second packet gets the next RTX sequence.
        let rtx2 = stream.packetize(&pkt(101));
        assert_eq!(rtx2.sequence(), 901);
        assert_eq!(dep.process(&rtx2).unwrap().sequence(), 101);
    }

    #[test]
    fn rtx_pool_eviction_bounds_memory() {
        let mut pool = RtxPool::new(4);
        for s in 0..6u16 {
            pool.store(&pkt(s));
        }
        assert_eq!(pool.len(), 4);
        assert!(pool.get(0).is_none(), "oldest evicted");
        assert!(pool.get(2).is_some());
        let got = pool.take_for_seqs(&[2, 3, 99]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].sequence(), 2);
        assert_eq!(got[1].sequence(), 3);
    }

    #[test]
    fn highest_extended_tracks_wrap_cycles() {
        let mut t = NackTracker::default();
        assert_eq!(t.highest_extended(), -1, "nothing observed yet");
        t.on_packet(0xAA, 65534, 0);
        assert_eq!(t.highest_extended(), 65534);
        t.on_packet(0xAA, 1, 1); // wrap: extended = 65537
        assert_eq!(t.highest_extended(), 65537);
    }

    #[test]
    fn depacketizer_rejects_foreign_pt_and_short_payload() {
        let mut dep = RtxDepacketizer::new(0xAA, 96, 117);
        // Non-RTX payload type → passthrough (None).
        assert!(dep.process(&pkt(1)).is_none());
        // Short payload (OSN missing) → None, but SSRC got learned.
        let bad = RtpPacket::new(117, 5, 1, 0xBB, false, Bytes::from_static(b"x"));
        assert!(dep.process(&bad).is_none());
        // Pinned SSRC mismatch → None even with the right payload type.
        dep.set_rtx_ssrc(0xBB);
        let foreign_ssrc = RtpPacket::new(117, 5, 1, 0xCC, false, Bytes::from_static(b"abcd"));
        assert!(dep.process(&foreign_ssrc).is_none());
        // Right PT + right SSRC + valid OSN decodes.
        let ok = RtpPacket::new(
            117,
            5,
            1,
            0xBB,
            false,
            Bytes::from_static(&[0xAB, 0xCD, 0x11]),
        );
        let restored = dep.process(&ok).unwrap();
        assert_eq!(restored.sequence(), 0xABCD);
        assert_eq!(restored.payload.as_ref(), &[0x11]);
    }
}
