//! Sliding-window replay protection ([RFC 3711 §3.3.3]).
//!
//! Bit `i` of the bitmask means "the packet at `highest - i` was accepted"
//! (libsrtp's relative-bit rolling-database semantics), so sliding the
//! window is a simple shift and index lookups never depend on the window
//! position within the 48-bit index space.

/// Replay window for a single SSRC, keyed by the 48-bit packet index
/// (or the 31-bit SRTCP index).
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    window_size: u64,
    highest: Option<u64>,
    bitmask: u64,
}

/// Maximum supported window size: the bitmask is a single `u64`.
pub const MAX_WINDOW_SIZE: u64 = 64;

impl ReplayWindow {
    /// Create a window of `window_size` entries (clamped to 64).
    pub fn new(window_size: u64) -> Self {
        ReplayWindow {
            window_size: window_size.clamp(1, MAX_WINDOW_SIZE),
            highest: None,
            bitmask: 0,
        }
    }

    /// Window size in packets.
    pub fn window_size(&self) -> u64 {
        self.window_size
    }

    /// Highest accepted index, if any packet has been accepted yet.
    pub fn last_index(&self) -> Option<u64> {
        self.highest
    }

    /// Would this index be accepted without recording it?
    ///
    /// Returns `false` when the packet is a replay: older than the window,
    /// or its relative bit is already set.
    pub fn check(&self, index: u64) -> bool {
        match self.highest {
            None => true,
            Some(h) => {
                if index > h {
                    true
                } else {
                    let delta = h - index;
                    if delta >= self.window_size {
                        false
                    } else {
                        self.bitmask & (1 << delta) == 0
                    }
                }
            }
        }
    }

    /// Record the index as seen.  Call only after the packet has been
    /// authenticated (RFC 3711 §3.3: the replay list is updated on
    /// successful verification).
    pub fn mark(&mut self, index: u64) {
        match self.highest {
            None => {
                self.highest = Some(index);
                self.bitmask = 1;
            }
            Some(h) => {
                if index > h {
                    let delta = index - h;
                    self.bitmask = if delta >= self.window_size {
                        0
                    } else {
                        (self.bitmask << delta) & mask_for(self.window_size)
                    };
                    self.bitmask |= 1; // bit 0 = the new highest packet
                    self.highest = Some(index);
                } else {
                    let delta = h - index;
                    if delta < self.window_size {
                        self.bitmask |= 1 << delta;
                    }
                }
            }
        }
    }

    /// Combined check + mark, returning whether the index was accepted.
    pub fn check_and_mark(&mut self, index: u64) -> bool {
        if self.check(index) {
            self.mark(index);
            true
        } else {
            false
        }
    }

    /// Reset to the initial (empty) state.
    pub fn reset(&mut self) {
        self.highest = None;
        self.bitmask = 0;
    }
}

fn mask_for(window_size: u64) -> u64 {
    if window_size >= 64 {
        u64::MAX
    } else {
        (1u64 << window_size) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order_and_rejects_duplicates() {
        let mut w = ReplayWindow::new(64);
        for i in 0..200u64 {
            assert!(w.check_and_mark(i), "index {i} should be fresh");
            assert!(!w.check_and_mark(i), "index {i} replayed");
        }
    }

    #[test]
    fn accepts_reordering_inside_window() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check_and_mark(0));
        assert!(w.check_and_mark(2));
        assert!(w.check_and_mark(1)); // late but inside window
        assert!(!w.check(1));
        assert!(!w.check(0));
        assert!(w.check(3));
    }

    #[test]
    fn rejects_old_outside_window() {
        let mut w = ReplayWindow::new(64);
        for i in 0..100u64 {
            assert!(w.check(i), "index {i} should be fresh before marking");
            w.mark(i);
            assert!(!w.check(i), "index {i} must replay right after marking");
        }
        // highest = 99; every marked index replays, index 100 is fresh.
        assert!(!w.check(99));
        assert!(!w.check(35)); // outside the window
        assert!(w.check(100));
    }

    #[test]
    fn sliding_keeps_trailing_bits() {
        let mut w = ReplayWindow::new(64);
        w.mark(10);
        w.mark(20); // 11..19 unseen but inside the window
        assert!(w.check(15));
        w.mark(70); // slide: window now covers 7..70
        assert!(!w.check(6)); // outside (delta 64)
        assert!(w.check(7)); // inside, never seen
        assert!(w.check(15)); // inside, never seen
        assert!(!w.check(10)); // seen (relative bit preserved by shift)
        assert!(!w.check(20));
        assert!(!w.check(70));
    }

    #[test]
    fn window_size_clamped() {
        let w = ReplayWindow::new(128);
        assert_eq!(w.window_size(), 64);
        let w = ReplayWindow::new(0);
        assert_eq!(w.window_size(), 1);
    }

    #[test]
    fn seq_wrap_indexes_are_distinct() {
        let mut w = ReplayWindow::new(64);
        // ROC 0 seq 65535 → index 65535; ROC 1 seq 0 → index 65536.
        assert!(w.check_and_mark(0xFFFF));
        assert!(w.check_and_mark(0x1_0000));
        assert!(!w.check(0xFFFF));
    }

    #[test]
    fn reset_clears_state() {
        let mut w = ReplayWindow::new(64);
        w.mark(5);
        assert!(!w.check(5));
        w.reset();
        assert!(w.check(5));
        assert_eq!(w.last_index(), None);
    }
}
