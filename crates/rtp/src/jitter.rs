//! Adaptive de-jitter buffer with a virtual-time API.
//!
//! Design highlights (see docs/DESIGN.md §5.2):
//! - Extended sequence numbers with wraparound handling; SSRC changes require
//!   MIN_SEQUENTIAL in-order packets (RFC 3550 §A.1 probation) before reset
//! - RFC 3550 §A.8 interarrival jitter estimation drives an adaptive target
//!   delay, clamped to `[min_delay_ms, max_delay_ms]`
//! - Timestamp-anchored playout: each frame's due time is
//!   `anchor_ms + (ext_ts - anchor_ts)/clock*1000 + target_ms`
//! - Pop path is driven purely by caller-supplied `now_ms` (virtual time) so
//!   all behavior is deterministic and unit-testable without sleeping
//! - Bounded memory and sequence-jump guards make it safe against
//!   malformed/malicious packet streams
//! - Pluggable PLC hook for concealment frames

use bytes::Bytes;
use std::collections::BTreeMap;

/// Buffer configuration.
#[derive(Debug, Clone)]
pub struct JitterConfig {
    /// Codec clock rate (Hz), e.g. 8000 for G.711.
    pub clock_hz: u32,
    /// Nominal frame duration (ms), e.g. 20.
    pub frame_ms: u32,
    /// Minimum target delay (ms).
    pub min_delay_ms: u32,
    /// Maximum target delay (ms).
    pub max_delay_ms: u32,
    /// Jitter multiplier: desired delay ≈ min + k·J.
    pub jitter_k: f64,
    /// Interval between target adaptations (ms, virtual time).
    pub adapt_interval_ms: u64,
    /// Max target change per adaptation step (ms).
    pub adapt_step_ms: u32,
    /// How many frame slots overdue before PLC fires (1 = one frame grace).
    pub conceal_grace_frames: u32,
}

impl Default for JitterConfig {
    fn default() -> Self {
        JitterConfig {
            clock_hz: 8000,
            frame_ms: 20,
            min_delay_ms: 30,
            max_delay_ms: 300,
            jitter_k: 2.0,
            adapt_interval_ms: 250,
            adapt_step_ms: 10,
            conceal_grace_frames: 1,
        }
    }
}

impl JitterConfig {
    pub fn for_clock(clock_hz: u32) -> JitterConfig {
        JitterConfig {
            clock_hz,
            ..JitterConfig::default()
        }
    }
}

/// Result of pushing a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    /// Stored for playout.
    Buffered,
    /// Older than the next expected frame slot (already played or concealed).
    Late,
    /// A packet with this sequence number is already buffered.
    Duplicate,
    /// Packet counted toward SSRC probation (not buffered).
    Probation,
}

/// Output frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpFrame {
    /// Extended sequence number (u16 wire value + wrap count).
    pub seq: i64,
    /// RTP timestamp as transmitted.
    pub timestamp: u32,
    pub marker: bool,
    pub payload_type: u8,
    pub payload: Bytes,
    /// True when produced by the PLC/concealment path.
    pub concealed: bool,
}

/// Counters for observability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JbStats {
    pub frames_in: u64,
    pub frames_out: u64,
    pub concealed: u64,
    pub late: u64,
    pub duplicates: u64,
    pub resets: u64,
    pub resyncs: u64,
}

struct Anchor {
    /// Virtual wall time at which `ts` was received.
    ms: f64,
    ts: i64,
}

struct Entry {
    frame: RtpFrame,
    ext_ts: i64,
}

const MIN_SEQUENTIAL: u32 = 2;
const MAX_ENTRIES: usize = 4096;
/// Sequence jumps beyond this are treated as a stream restart.
const MAX_SEQ_JUMP: i64 = 1000;

/// The adaptive jitter buffer.
pub struct JitterBuffer {
    cfg: JitterConfig,
    entries: BTreeMap<i64, Entry>,
    ssrc: u32,
    probation_ssrc: u32,
    probation_count: u32,
    probation_last_seq: u16,
    highest_ext_seq: i64,
    /// Next expected extended sequence number (playout cursor).
    next_seq: i64,
    /// RTP timestamp of the next expected slot (playout cursor).
    next_ts: i64,
    last_pt: u8,
    anchor: Option<Anchor>,
    target_ms: f64,
    jitter_samples: f64,
    transit_prev: Option<f64>,
    last_adapt_ms: u64,
    pub stats: JbStats,
    conceal_fn: Option<Box<dyn FnMut(u32) -> Vec<u8> + Send>>,
}

fn wrap_diff(new: u16, old: u16) -> i64 {
    let d = new as i64 - old as i64;
    if d > 32768 {
        d - 65536
    } else if d < -32768 {
        d + 65536
    } else {
        d
    }
}

impl JitterBuffer {
    pub fn new(cfg: JitterConfig) -> JitterBuffer {
        JitterBuffer {
            target_ms: cfg.min_delay_ms as f64,
            cfg,
            entries: BTreeMap::new(),
            ssrc: 0,
            probation_ssrc: 0,
            probation_count: 0,
            probation_last_seq: 0,
            highest_ext_seq: 0,
            next_seq: 0,
            next_ts: 0,
            last_pt: 0,
            anchor: None,
            jitter_samples: 0.0,
            transit_prev: None,
            last_adapt_ms: 0,
            stats: JbStats::default(),
            conceal_fn: None,
        }
    }

    /// Install a PLC hook: `FnMut(n_samples) -> payload`.
    pub fn set_concealment(&mut self, f: Box<dyn FnMut(u32) -> Vec<u8> + Send>) {
        self.conceal_fn = Some(f);
    }

    fn frame_samples(&self) -> i64 {
        (self.cfg.clock_hz as i64 * self.cfg.frame_ms as i64) / 1000
    }

    fn samples_to_ms(&self, samples: i64) -> f64 {
        samples as f64 * 1000.0 / self.cfg.clock_hz as f64
    }

    fn due_ms(&self, a: &Anchor, ext_ts: i64) -> f64 {
        a.ms + self.samples_to_ms(ext_ts - a.ts) + self.target_ms
    }

    /// Due time (virtual ms) of the next expected slot.
    fn next_due_ms(&self) -> Option<f64> {
        let a = self.anchor.as_ref()?;
        let grace = self.samples_to_ms(self.frame_samples() * self.cfg.conceal_grace_frames as i64);
        Some(self.due_ms(a, self.next_ts) + grace)
    }

    /// Number of buffered frames.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current adaptive target delay (ms).
    pub fn target_delay_ms(&self) -> f64 {
        self.target_ms
    }

    /// Current estimated interarrival jitter (ms).
    pub fn jitter_ms(&self) -> f64 {
        self.samples_to_ms(self.jitter_samples as i64)
    }

    /// Queue depth in ms relative to `now_ms` (0 if empty).
    pub fn depth_ms(&self, now_ms: u64) -> f64 {
        match self.entries.values().next() {
            Some(e) => {
                let a = self.anchor.as_ref().expect("anchor present with entries");
                (self.due_ms(a, e.ext_ts) - now_ms as f64).max(0.0)
            }
            None => 0.0,
        }
    }

    /// Re-initialize the buffer around a newly (re)discovered stream.
    fn full_reset(&mut self, ssrc: u32, seq: u16, ts: u32, now_ms: u64) {
        self.entries.clear();
        self.ssrc = ssrc;
        self.highest_ext_seq = seq as i64;
        self.next_seq = seq as i64;
        self.next_ts = ts as i64;
        self.last_pt = 0;
        self.anchor = Some(Anchor {
            ms: now_ms as f64,
            ts: ts as i64,
        });
        self.jitter_samples = 0.0;
        self.transit_prev = None;
        self.target_ms = self.cfg.min_delay_ms as f64;
        self.probation_count = 0;
        self.stats.resets += 1;
    }

    /// Push a packet into the buffer. `now_ms` is virtual time in milliseconds.
    ///
    /// The argument list mirrors the RTP header + arrival time 1:1 on purpose;
    /// callers already have those fields unpacked.
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        ssrc: u32,
        seq: u16,
        ts: u32,
        marker: bool,
        pt: u8,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> PushResult {
        // ---- stream acquisition ----
        if self.anchor.is_none() {
            // first packet ever (or after defensive clear): initialize directly
            self.full_reset(ssrc, seq, ts, now_ms);
        } else if ssrc != self.ssrc {
            // candidate new stream: require MIN_SEQUENTIAL in-order packets
            if self.probation_ssrc == ssrc && wrap_diff(seq, self.probation_last_seq) == 1 {
                self.probation_count += 1;
                self.probation_last_seq = seq;
            } else {
                self.probation_ssrc = ssrc;
                self.probation_count = 1;
                self.probation_last_seq = seq;
                return PushResult::Probation;
            }
            if self.probation_count >= MIN_SEQUENTIAL {
                self.full_reset(ssrc, seq, ts, now_ms);
            } else {
                return PushResult::Probation;
            }
        }

        // ---- sequence extension ----
        let d = wrap_diff(seq, (self.highest_ext_seq & 0xFFFF) as u16);
        if d.abs() > MAX_SEQ_JUMP {
            // absurd jump: treat as stream restart; the packet seeds the new stream
            self.full_reset(ssrc, seq, ts, now_ms);
            return PushResult::Probation;
        }
        let ext = self.highest_ext_seq + d;
        if ext < self.next_seq {
            self.stats.late += 1;
            return PushResult::Late;
        }
        if self.entries.contains_key(&ext) {
            self.stats.duplicates += 1;
            return PushResult::Duplicate;
        }

        // RFC 3550 §A.8 interarrival jitter (accepted packets only)
        let arrival_samples = now_ms as f64 * self.cfg.clock_hz as f64 / 1000.0;
        let transit = arrival_samples - ts as f64;
        if let Some(prev) = self.transit_prev {
            let delta = (transit - prev).abs();
            self.jitter_samples += (delta - self.jitter_samples) / 16.0;
        }
        self.transit_prev = Some(transit);

        self.highest_ext_seq = self.highest_ext_seq.max(ext);

        // resync guard: head scheduled way too far in the future (drift/silence)
        if let (Some(a), Some(head)) = (self.anchor.as_ref(), self.entries.values().next()) {
            if self.due_ms(a, head.ext_ts) - now_ms as f64 > self.target_ms + 1000.0 {
                self.anchor = Some(Anchor {
                    ms: now_ms as f64,
                    ts: head.ext_ts,
                });
                self.stats.resyncs += 1;
            }
        }

        self.entries.insert(
            ext,
            Entry {
                frame: RtpFrame {
                    seq: ext,
                    timestamp: ts,
                    marker,
                    payload_type: pt,
                    payload: Bytes::from(payload),
                    concealed: false,
                },
                ext_ts: ts as i64,
            },
        );
        self.stats.frames_in += 1;
        self.last_pt = pt;

        // bounded memory (defensive against malformed sequence storms)
        if self.entries.len() > MAX_ENTRIES {
            self.entries.clear();
            self.anchor = None;
            self.probation_count = 0;
        }

        self.maybe_adapt(now_ms);
        PushResult::Buffered
    }

    fn maybe_adapt(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_adapt_ms) < self.cfg.adapt_interval_ms {
            return;
        }
        self.last_adapt_ms = now_ms;
        let j_ms = self.samples_to_ms(self.jitter_samples as i64);
        let desired = (self.cfg.min_delay_ms as f64 + self.cfg.jitter_k * j_ms)
            .clamp(self.cfg.min_delay_ms as f64, self.cfg.max_delay_ms as f64);
        let step = self.cfg.adapt_step_ms as f64;
        if desired > self.target_ms {
            self.target_ms += (desired - self.target_ms).min(step);
        } else if desired < self.target_ms {
            self.target_ms -= (self.target_ms - desired).min(step);
        }
    }

    /// Pop the next frame if it is due for playout at `now_ms`.
    pub fn pop_ready(&mut self, now_ms: u64) -> Option<RtpFrame> {
        let a = self.anchor.as_ref()?;
        let (&seq, entry) = self.entries.iter().next()?;
        if self.due_ms(a, entry.ext_ts) > now_ms as f64 {
            return None;
        }
        let entry = self.entries.remove(&seq).expect("just checked");
        self.next_seq = seq + 1;
        self.next_ts = entry.ext_ts + self.frame_samples();
        self.stats.frames_out += 1;
        Some(entry.frame)
    }

    /// Produce a concealment (PLC) frame when the next expected slot is
    /// overdue and no real frame is ready for it.
    pub fn conceal(&mut self, now_ms: u64) -> Option<RtpFrame> {
        let due = self.next_due_ms()?;
        if due > now_ms as f64 {
            return None;
        }
        // a real frame that occupies the cursor slot itself wins over concealment
        if let Some(e) = self.entries.values().next() {
            if e.ext_ts <= self.next_ts {
                return None;
            }
        }
        let seq = self.next_seq;
        let ts = self.next_ts as u32;
        self.next_seq += 1;
        self.next_ts += self.frame_samples();
        self.stats.concealed += 1;
        self.stats.frames_out += 1;
        let n = self.frame_samples() as u32;
        let payload = match self.conceal_fn.as_mut() {
            Some(f) => Bytes::from(f(n)),
            None => Bytes::from(vec![0u8; n as usize]),
        };
        Some(RtpFrame {
            seq,
            timestamp: ts,
            marker: false,
            payload_type: self.last_pt,
            payload,
            concealed: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jb() -> JitterBuffer {
        JitterBuffer::new(JitterConfig::for_clock(8000))
    }

    fn push(b: &mut JitterBuffer, seq: u16, ts: u32, now: u64) -> PushResult {
        b.push(0xAAAA, seq, ts, false, 0, vec![0xABu8; 160], now)
    }

    #[test]
    fn init_then_inorder_playout() {
        let mut b = jb();
        assert_eq!(push(&mut b, 100, 1600, 0), PushResult::Buffered);
        assert_eq!(push(&mut b, 101, 1760, 20), PushResult::Buffered);
        assert_eq!(push(&mut b, 102, 1920, 40), PushResult::Buffered);
        assert_eq!(b.len(), 3);
        // target = min_delay (30ms): frame 100 due at 0 + 30
        assert!(b.pop_ready(29).is_none());
        let f = b.pop_ready(30).unwrap();
        assert_eq!(f.seq, 100);
        assert!(!f.concealed);
        assert_eq!(b.pop_ready(50).unwrap().seq, 101);
        assert!(b.pop_ready(69).is_none());
        assert_eq!(b.pop_ready(70).unwrap().seq, 102);
        assert_eq!(b.stats.frames_out, 3);
    }

    #[test]
    fn reordering_stays_in_sequence() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        push(&mut b, 2, 320, 40);
        push(&mut b, 4, 640, 80);
        push(&mut b, 3, 480, 60);
        let mut played = Vec::new();
        for t in 30..200 {
            while let Some(f) = b.pop_ready(t) {
                played.push((t, f.seq));
            }
        }
        let seqs: Vec<i64> = played.iter().map(|(_, s)| *s).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn loss_with_conceal_covered_by_concealment() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        // seq 2 lost, seq 3 arrives normally
        push(&mut b, 3, 480, 60);
        let f0 = b.pop_ready(30).unwrap();
        assert_eq!(f0.seq, 0);
        let f1 = b.pop_ready(50).unwrap();
        assert_eq!(f1.seq, 1);
        // slot for seq2 (ts 320) due at 70; grace pushes PLC to 90
        assert!(b.pop_ready(70).is_none());
        assert!(b.conceal(70).is_none());
        // at 90 the missing slot is covered by concealment, then frame 3 plays
        let c = b.conceal(90).unwrap();
        assert!(c.concealed);
        assert_eq!(c.seq, 2);
        let f3 = b.pop_ready(90).unwrap();
        assert_eq!(f3.seq, 3);
        assert_eq!(b.stats.concealed, 1);
    }

    #[test]
    fn extended_loss_triggers_concealment() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        // seq 2 and 3 lost, seq 4 arrives
        push(&mut b, 4, 640, 80);
        let f0 = b.pop_ready(30).unwrap();
        assert_eq!(f0.seq, 0);
        let f1 = b.pop_ready(50).unwrap();
        assert_eq!(f1.seq, 1);
        // slot for seq2: due 70 + grace 20 = 90; frame 4 due at 110
        assert!(b.conceal(89).is_none());
        let c = b.conceal(90).unwrap();
        assert!(c.concealed);
        assert_eq!(c.seq, 2);
        assert_eq!(c.timestamp, 320);
        // slot for seq3 (ts 480) due 90 + grace = 110; frame 4 due at 110 too:
        // concealment covers slot 3, then frame 4 pops
        let c2 = b.conceal(110).unwrap();
        assert_eq!(c2.seq, 3);
        let f4 = b.pop_ready(110).unwrap();
        assert_eq!(f4.seq, 4);
        assert_eq!(b.stats.concealed, 2);
    }

    #[test]
    fn double_loss_conceals_two_slots() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        // everything else lost until seq 3
        push(&mut b, 3, 480, 60);
        let f0 = b.pop_ready(30).unwrap();
        assert_eq!(f0.seq, 0);
        // slot1 due 50+20=70 -> conceal; slot2 due 70+20=90 -> conceal
        assert!(b.conceal(69).is_none());
        let c1 = b.conceal(70).unwrap();
        assert_eq!(c1.seq, 1);
        let c2 = b.conceal(90).unwrap();
        assert_eq!(c2.seq, 2);
        // slot3 == frame 3's slot; frame due at 90 pops instead
        assert!(b.conceal(90).is_none());
        let f3 = b.pop_ready(90).unwrap();
        assert_eq!(f3.seq, 3);
        assert_eq!(b.stats.concealed, 2);
    }

    #[test]
    fn sequence_wraparound() {
        let mut b = jb();
        push(&mut b, 65534, 0, 0);
        push(&mut b, 65535, 160, 20);
        push(&mut b, 0, 320, 40);
        push(&mut b, 1, 480, 60);
        let mut seqs = Vec::new();
        for t in 30..130 {
            while let Some(f) = b.pop_ready(t) {
                seqs.push(f.seq);
            }
        }
        assert_eq!(seqs, vec![65534, 65535, 65536, 65537]);
    }

    #[test]
    fn late_and_duplicate_packets() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        push(&mut b, 2, 320, 40);
        let f0 = b.pop_ready(30).unwrap();
        assert_eq!(f0.seq, 0);
        // re-send seq 0: already played
        assert_eq!(push(&mut b, 0, 0, 45), PushResult::Late);
        // re-send seq 1: still buffered
        assert_eq!(push(&mut b, 1, 160, 45), PushResult::Duplicate);
        assert_eq!(b.stats.late, 1);
        assert_eq!(b.stats.duplicates, 1);
    }

    #[test]
    fn ssrc_change_requires_probation_and_resets() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        push(&mut b, 2, 320, 40);
        assert_eq!(b.stats.resets, 1);
        // new SSRC: first packet starts probation
        assert_eq!(
            b.push(0xBBBB, 500, 8000, false, 0, vec![0; 160], 60),
            PushResult::Probation
        );
        // second in-order confirms and seeds the new stream
        assert_eq!(
            b.push(0xBBBB, 501, 8160, false, 0, vec![0; 160], 80),
            PushResult::Buffered
        );
        assert_eq!(b.stats.resets, 2);
        // a stray packet from the old SSRC starts a fresh probation
        assert_eq!(
            b.push(0xAAAA, 3, 480, false, 0, vec![0; 160], 120),
            PushResult::Probation
        );
    }

    #[test]
    fn adaptive_target_grows_with_jitter_then_shrinks() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        push(&mut b, 2, 320, 40);
        let base_target = b.target_delay_ms();

        // high arrival jitter: alternate +60ms / on-time arrivals
        let mut seq = 3u16;
        let mut ts = 480u32;
        let mut t = 60u64;
        for i in 0..40 {
            let offset = if i % 2 == 0 { 60 } else { 0 };
            push(&mut b, seq, ts, t + offset);
            seq += 1;
            ts += 160;
            t += 20;
        }
        // force an adaptation pass
        push(&mut b, seq, ts, t + 300);
        let grown = b.target_delay_ms();
        assert!(grown > base_target + 5.0, "target did not grow: {}", grown);

        // stable arrivals shrink it back (bounded by step size)
        let mut seq = seq + 1;
        let mut ts = ts + 160;
        let mut t = t + 340;
        for _ in 0..80 {
            push(&mut b, seq, ts, t);
            seq += 1;
            ts += 160;
            t += 20;
        }
        push(&mut b, seq, ts, t + 300);
        let shrunk = b.target_delay_ms();
        assert!(
            shrunk < grown - 5.0,
            "target did not shrink: {} -> {}",
            grown,
            shrunk
        );
        assert!(shrunk >= b.cfg.min_delay_ms as f64);
        assert!(grown <= b.cfg.max_delay_ms as f64);
    }

    #[test]
    fn conceal_payload_uses_hook() {
        let mut b = jb();
        b.set_concealment(Box::new(|n| vec![0x7Fu8; n as usize]));
        push(&mut b, 0, 0, 0);
        push(&mut b, 3, 480, 60);
        let f0 = b.pop_ready(30).unwrap();
        assert_eq!(f0.seq, 0);
        let c = b.conceal(70).unwrap();
        assert_eq!(c.payload.len(), 160);
        assert!(c.payload.iter().all(|&x| x == 0x7F));
        // next slot (seq 2) concealed at its own grace deadline
        let c2 = b.conceal(90).unwrap();
        assert_eq!(c2.seq, 2);
        let f3 = b.pop_ready(90).unwrap();
        assert!(!f3.concealed);
    }

    #[test]
    fn malicious_sequence_storm_is_bounded() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        for i in 0..(MAX_ENTRIES * 3) {
            let seq = (1000u32 + i as u32) as u16;
            push(&mut b, seq, 100_000 + i as u32 * 160, 60 + i as u64);
        }
        assert!(b.len() <= MAX_ENTRIES + 1);
    }

    #[test]
    fn absurd_jump_resets() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        push(&mut b, 2, 320, 40);
        let r = push(&mut b, 30000, 999_999, 60);
        assert_eq!(r, PushResult::Probation);
        assert!(b.is_empty());
        // stream resumes around the jumped packet
        assert_eq!(push(&mut b, 30001, 1_000_159, 80), PushResult::Buffered);
    }

    #[test]
    fn depth_reports_queue() {
        let mut b = jb();
        push(&mut b, 0, 0, 0);
        push(&mut b, 1, 160, 20);
        push(&mut b, 2, 320, 40);
        // head due at 30: depth = 30 at t=0
        assert!((b.depth_ms(0) - 30.0).abs() < 0.001);
        assert_eq!(b.depth_ms(100), 0.0);
    }
}
