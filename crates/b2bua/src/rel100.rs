//! RFC 3262 (`100rel` / PRACK) rules and clocks, mirroring the shape of the
//! RFC 4028 `timers` module: no I/O, so the retransmission backoff and the
//! PRACK decision matrix are unit-testable with a fake clock.
//!
//! Two sides:
//!
//! * **UAS side** (leg A): when the caller advertises `100rel`, our 180 is
//!   sent reliably (`Require: 100rel` + `RSeq`) and retransmitted with
//!   Timer-G-style backoff until the caller's `PRACK` acknowledges it via
//!   `RAck` — or until we give up on the dialog attempt. The final response
//!   to the INVITE must not go out while the reliable 1xx is unacknowledged
//!   (RFC 3262 §3).
//! * **UAC side** (leg B): a provisional response is acknowledged with a
//!   `PRACK` carrying `RAck: RSeq CSeq INVITE` only when it is a 101–199
//!   carrying BOTH `Require: 100rel` and `RSeq` (§4 — never a 100). A
//!   retransmitted 1xx (same `RSeq`) means our PRACK was lost and is
//!   answered by resending the SAME PRACK (same CSeq and branch, RFC 3261
//!   §17.1.2).

use sip_core::headers::{RAckValue, TokenList};
use sip_core::message::Method;
use std::time::{Duration, Instant};

/// Base retransmission interval (RFC 3261 §17.1.1.1 T1).
pub const T1: Duration = Duration::from_millis(500);
/// Cap for the retransmission backoff (RFC 3261 §17.1.1.1 T2).
pub const T2: Duration = Duration::from_millis(4000);
/// Give-up budget for an unacknowledged reliable 1xx: after 64·T1 without a
/// PRACK the dialog attempt is abandoned, the same budget an INVITE server
/// transaction allows for its final response to be confirmed.
pub const PRACK_GIVEUP: Duration = Duration::from_millis(64 * T1.as_millis() as u64);

/// Timer-G-style backoff before the `attempt`-th retransmission (1-based):
/// T1 doubling up to T2 (RFC 3262 §5 borrows the 2xx retransmission rules).
pub fn backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(3);
    Duration::from_millis((T1.as_millis() as u64) << shift)
}

/// UAS-side state for one outstanding reliable provisional response.
#[derive(Debug)]
pub struct Reliable1xx {
    /// The `RSeq` we put on the response (constant across retransmissions).
    pub rseq: u32,
    /// When the first transmission went out.
    pub sent_at: Instant,
    /// When the next retransmission is due.
    pub next_at: Instant,
    /// Retransmissions sent so far.
    pub attempts: u32,
}

impl Reliable1xx {
    /// Fresh state for a response first transmitted at `now`.
    pub fn new(rseq: u32, now: Instant) -> Self {
        Self {
            rseq,
            sent_at: now,
            next_at: now + T1,
            attempts: 0,
        }
    }

    /// A retransmission is due.
    pub fn retransmit_due(&self, now: Instant) -> bool {
        now >= self.next_at
    }

    /// Books a retransmission at `now` and schedules the next one.
    pub fn advance(&mut self, now: Instant) {
        self.attempts += 1;
        self.next_at = now + backoff(self.attempts);
    }

    /// The PRACK never came: abandon the dialog attempt (RFC 3262 §3).
    pub fn give_up(&self, now: Instant) -> bool {
        now.duration_since(self.sent_at) >= PRACK_GIVEUP
    }
}

/// What a UAC does with a 1xx that may be reliable (RFC 3262 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrackAction {
    /// Not PRACKable at all: 100, a 1xx without `Require: 100rel`, no
    /// `RSeq`, or a stale (older than acknowledged) `RSeq`. Nothing to do.
    Ignore,
    /// A NEW reliable 1xx (first, or `RSeq` advanced): send a fresh PRACK
    /// with `RAck` for this `RSeq` (new dialog CSeq, new branch).
    Send { rseq: u32 },
    /// The 1xx is a retransmission of the one we already PRACKed (same
    /// `RSeq`): our PRACK was lost — resend the stored PRACK verbatim
    /// (same CSeq number and same branch, RFC 3261 §17.1.2).
    Retransmit,
}

/// Decision matrix for an incoming provisional response given the last
/// `RSeq` we PRACKed. A PRACK is generated only for a 101–199 that carries
/// BOTH `Require: 100rel` and an `RSeq` (RFC 3262 §4).
pub fn prack_action(
    code: u16,
    require_100rel: bool,
    incoming_rseq: Option<u32>,
    last_acked: Option<u32>,
) -> PrackAction {
    if !(101..=199).contains(&code) || !require_100rel {
        return PrackAction::Ignore;
    }
    match (incoming_rseq, last_acked) {
        (None, _) => PrackAction::Ignore,
        (Some(r), None) => PrackAction::Send { rseq: r },
        (Some(r), Some(last)) if r > last => PrackAction::Send { rseq: r },
        (Some(r), Some(last)) if r == last => PrackAction::Retransmit,
        (Some(_), Some(_)) => PrackAction::Ignore,
    }
}

/// Merges the extensions a 421 `Extension Required` demanded into our
/// `Supported` header value (RFC 3262 §3): union of both token lists,
/// deduplicated case-insensitively, existing order kept first.
pub fn merge_supported(existing: &str, require_tokens: &str) -> String {
    let mut out = TokenList::parse(existing).0;
    for t in TokenList::parse(require_tokens).0 {
        if !out.iter().any(|e| e.eq_ignore_ascii_case(&t)) {
            out.push(t);
        }
    }
    out.join(", ")
}

/// Whether a PRACK's `RAck` matches the outstanding reliable 1xx (§4): the
/// `RSeq` must be the one we sent, and the CSeq must identify the INVITE.
pub fn rack_matches(rack: &RAckValue, rseq: u32, invite_cseq: u32) -> bool {
    rack.rseq == rseq && rack.cseq == invite_cseq && rack.method == Method::Invite
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps_at_t2() {
        assert_eq!(backoff(1), T1);
        assert_eq!(backoff(2), Duration::from_millis(1000));
        assert_eq!(backoff(3), Duration::from_millis(2000));
        assert_eq!(backoff(4), T2);
        assert_eq!(backoff(9), T2, "capped at T2");
        assert_eq!(backoff(0), T1, "no attempt yet behaves like the first");
    }

    #[test]
    fn reliable_1xx_clock_retransmits_then_gives_up() {
        // One anchor for the whole test: every `t(ms)` shares it, so
        // equality between two `t()`-derived Instants is exact.
        let base = Instant::now();
        let t = |ms: u64| base + Duration::from_millis(ms);
        let mut rel = Reliable1xx::new(4242, t(0));
        // First retransmission after T1.
        assert!(!rel.retransmit_due(t(400)));
        assert!(rel.retransmit_due(t(500)));
        rel.advance(t(500));
        assert_eq!(rel.attempts, 1);
        // Then 2·T1.
        assert!(!rel.retransmit_due(t(900)));
        assert!(rel.retransmit_due(t(1000)));
        rel.advance(t(1000));
        assert_eq!(rel.attempts, 2);
        // Then 4·T1.
        assert!(!rel.retransmit_due(t(1900)));
        assert!(rel.retransmit_due(t(2000)));
        rel.advance(t(2000));
        assert_eq!(rel.attempts, 3);
        // From the fourth attempt on the backoff is capped at T2 (8·T1).
        assert!(!rel.retransmit_due(t(3900)));
        assert!(rel.retransmit_due(t(4000)));
        rel.advance(t(4000));
        assert_eq!(rel.next_at, t(4000) + T2, "backoff is capped at T2");
        assert!(!rel.give_up(t(31_000)));
        assert!(rel.give_up(t(32_000)));
    }

    #[test]
    fn prack_action_matrix() {
        const REQ: bool = true;
        // No RSeq → nothing to acknowledge.
        assert_eq!(prack_action(180, REQ, None, None), PrackAction::Ignore);
        assert_eq!(prack_action(180, REQ, None, Some(9)), PrackAction::Ignore);
        // First reliable 1xx → PRACK.
        assert_eq!(
            prack_action(180, REQ, Some(7), None),
            PrackAction::Send { rseq: 7 }
        );
        // New RSeq → PRACK.
        assert_eq!(
            prack_action(180, REQ, Some(8), Some(7)),
            PrackAction::Send { rseq: 8 }
        );
        // Same RSeq again → the 1xx was retransmitted: our PRACK was lost,
        // so the STORED PRACK is resent (same CSeq and branch).
        assert_eq!(
            prack_action(180, REQ, Some(7), Some(7)),
            PrackAction::Retransmit
        );
        // Older RSeq → stale, ignore.
        assert_eq!(
            prack_action(180, REQ, Some(6), Some(7)),
            PrackAction::Ignore
        );
    }

    #[test]
    fn prack_action_gates_per_rfc3262_section4() {
        const RSEQ: Option<u32> = Some(9);
        // 100 is never PRACKed, even with Require + RSeq.
        assert_eq!(prack_action(100, true, RSEQ, None), PrackAction::Ignore);
        // Final responses are not provisional.
        assert_eq!(prack_action(200, true, RSEQ, None), PrackAction::Ignore);
        // 1xx without `Require: 100rel` is unreliable.
        assert_eq!(prack_action(183, false, RSEQ, None), PrackAction::Ignore);
        assert_eq!(prack_action(180, false, RSEQ, None), PrackAction::Ignore);
        // 101–199 with both markers is PRACKable (bounds included).
        assert_eq!(
            prack_action(101, true, RSEQ, None),
            PrackAction::Send { rseq: 9 }
        );
        assert_eq!(
            prack_action(199, true, RSEQ, None),
            PrackAction::Send { rseq: 9 }
        );
        // Retransmission decision still applies above 100.
        assert_eq!(prack_action(183, true, RSEQ, RSEQ), PrackAction::Retransmit);
    }

    #[test]
    fn merge_supported_unions_and_dedupes() {
        // The 421's tokens are folded into the retry's Supported header.
        assert_eq!(merge_supported("100rel", "100rel"), "100rel");
        assert_eq!(merge_supported("100rel", "100rel, timer"), "100rel, timer");
        assert_eq!(merge_supported("100rel", "timer, 100rel"), "100rel, timer");
        // Case-insensitive dedup, existing order kept first.
        assert_eq!(merge_supported("100rel", "100REL, foo"), "100rel, foo");
        // Empty Require changes nothing; empty Supported adopts the tokens.
        assert_eq!(merge_supported("100rel", ""), "100rel");
        assert_eq!(merge_supported("", "precondition"), "precondition");
        // Whitespace tolerated on both sides.
        assert_eq!(
            merge_supported(" 100rel , timer ", "precondition"),
            "100rel, timer, precondition"
        );
    }

    #[test]
    fn rack_matching() {
        let good = RAckValue::parse("10 1 INVITE").unwrap();
        assert!(rack_matches(&good, 10, 1));
        assert!(!rack_matches(&good, 11, 1), "wrong RSeq");
        assert!(!rack_matches(&good, 10, 2), "wrong INVITE CSeq");
        let wrong_method = RAckValue::parse("10 1 UPDATE").unwrap();
        assert!(!rack_matches(&wrong_method, 10, 1));
        // Case-insensitive method token still matches INVITE.
        let lower = RAckValue::parse("10 1 invite").unwrap();
        assert!(rack_matches(&lower, 10, 1));
    }
}
