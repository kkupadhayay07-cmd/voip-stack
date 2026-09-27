//! RFC 4028 session timers: negotiation rules and per-leg refresh state.
//!
//! A dialog with session timers stays up only while refreshes (no-change
//! re-INVITEs or UPDATEs) keep arriving. Negotiation happens on the initial
//! INVITE (§5/§6/§9); afterwards every engaged leg runs two clocks:
//!
//! * the **refresh** clock (only when we are the refresher): a refresh is
//!   sent once half the negotiated interval has elapsed (§9 recommends
//!   half-interval refreshes);
//! * the **expiry** clock: the leg is dead — and the B2BUA tears the call
//!   down — once a full interval passes without a confirmed refresh (§10).
//!
//! The module is I/O-free so the negotiation matrix and the clock math are
//! unit-testable without sockets.

use sip_core::headers::Refresher;
use sip_core::message::Request;
use std::time::{Duration, Instant};

/// Smallest session interval this B2BUA accepts; smaller requested intervals
/// are answered with `422` carrying this value as `Min-SE` (RFC 4028 §5).
pub const DEFAULT_MIN_SE: u64 = 90;

/// Interval assumed when a request carries `Require: timer` but no
/// `Session-Expires` (RFC 4028 §6).
pub const DEFAULT_SE: u64 = 1800;

/// Our side of the refresh bargain on one leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We originate the refresh re-INVITEs before expiry.
    Refresher,
    /// The peer must refresh; we terminate the leg if it lets the clock run
    /// out (RFC 4028 §10).
    Refreshee,
}

/// Result of UAS-side negotiation for an inbound INVITE (RFC 4028 §5/§6/§9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UasNegotiation {
    /// No session timers on this leg (peer sent no `Session-Expires`).
    Off,
    /// Peer's interval is below our `Min-SE`; answer `422` carrying this
    /// value in a `Min-SE` header.
    TooSmall(u64),
    /// Timers engaged with the given interval and role.
    On {
        /// Negotiated session interval in seconds.
        interval: u64,
        /// Which side refreshes.
        role: Role,
    },
}

/// Maps a request's `refresher` parameter to our role on a leg.
///
/// `we_are_uas` selects the leg perspective (leg A) or the UAC perspective
/// (leg B). An absent parameter defaults to the UAC being the refresher
/// (RFC 4028 §9), so a B2BUA that echoes no `refresher` still ends up
/// refreshing its own outgoing leg.
pub fn role_for(refresher: Option<Refresher>, we_are_uas: bool) -> Role {
    let uac_refreshes = match refresher {
        Some(Refresher::Uac) => true,
        Some(Refresher::Uas) => false,
        // RFC 4028 §9: the default refresher is the UAC.
        None => true,
    };
    if uac_refreshes == we_are_uas {
        Role::Refreshee
    } else {
        Role::Refresher
    }
}

/// Inverse of [`role_for`]: the `refresher` parameter value to advertise for
/// a leg where we hold `role` (`we_are_uas` selects the leg perspective).
pub fn refresher_for(role: Role, we_are_uas: bool) -> Refresher {
    match (role, we_are_uas) {
        (Role::Refresher, true) | (Role::Refreshee, false) => Refresher::Uas,
        _ => Refresher::Uac,
    }
}

/// UAS-side negotiation for an inbound INVITE (RFC 4028 §5/§6/§9).
pub fn negotiate_uas(req: &Request, min_se: u64, default_se: u64) -> UasNegotiation {
    let h = &req.headers;
    let require_timer = h.require().has("timer");
    if h.session_expires_raw().is_none() {
        return if require_timer {
            // `Require: timer` without `Session-Expires` is malformed (§6);
            // be liberal and engage with the default interval.
            UasNegotiation::On {
                interval: default_se.max(min_se),
                role: role_for(None, true),
            }
        } else {
            UasNegotiation::Off
        };
    };
    // Present but unparseable: timers cannot be honored, run without them.
    let Some(se) = h.session_expires() else {
        return UasNegotiation::Off;
    };
    if se < min_se {
        return UasNegotiation::TooSmall(min_se);
    }
    UasNegotiation::On {
        interval: se,
        role: role_for(h.session_refresher(), true),
    }
}

/// Runtime refresh state for one confirmed leg (RFC 4028 §9/§10).
#[derive(Debug)]
pub struct LegTimers {
    /// Negotiated session interval (seconds).
    pub interval: u64,
    /// Which side sends the refreshes on this leg.
    pub role: Role,
    /// Anchor of the last confirmed refresh: the 2xx to our refresh
    /// ([`Role::Refresher`]) or the receipt of the peer's refresh
    /// ([`Role::Refreshee`]).
    pub anchored: Instant,
    /// CSeq of a refresh re-INVITE we have in flight, if any.
    pub pending: Option<u32>,
}

impl LegTimers {
    /// Fresh state anchored at `now` (call again at the moment the dialog
    /// is confirmed so the first interval starts there).
    pub fn new(interval: u64, role: Role) -> Self {
        Self {
            interval,
            role,
            anchored: Instant::now(),
            pending: None,
        }
    }

    /// Half-interval refresh threshold (§9), floored at one second so very
    /// small negotiated intervals still leave a realistic refresh window.
    pub fn refresh_after(&self) -> Duration {
        Duration::from_secs((self.interval / 2).max(1))
    }

    /// We owe a refresh: we are the refresher, nothing is in flight, and
    /// half the interval has elapsed since the anchor.
    pub fn refresh_due(&self, now: Instant) -> bool {
        self.role == Role::Refresher
            && self.pending.is_none()
            && now.duration_since(self.anchored) >= self.refresh_after()
    }

    /// The leg expired (§10): a full interval passed without a confirmed
    /// refresh. An in-flight refresh of our own is granted grace — the
    /// transaction timers will surface its failure instead.
    pub fn expired(&self, now: Instant) -> bool {
        if self.role == Role::Refresher && self.pending.is_some() {
            return false;
        }
        now.duration_since(self.anchored) >= Duration::from_secs(self.interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::builder::RequestBuilder;
    use sip_core::message::Method;
    use sip_core::uri::{SipUri, TransportKind};

    fn invite(se: Option<&str>, require: Option<&str>) -> Request {
        let b = RequestBuilder::new(Method::Invite, SipUri::parse("sip:a@b").unwrap())
            .via(TransportKind::Udp, "h", Some("z9hG4bKx"))
            .from("<sip:c@x>;tag=t1")
            .to("<sip:a@b>");
        let b = match require {
            Some(r) => b.header("Require", r),
            None => b,
        };
        let b = match se {
            Some(se) => b.header("Session-Expires", se),
            None => b,
        };
        b.build()
    }

    #[test]
    fn negotiate_uas_matrix() {
        // No session timer requested → off.
        assert_eq!(negotiate_uas(&invite(None, None), 90, 1800), UasNegotiation::Off);
        // Plain engage, default refresher (UAC) → we (UAS) are the refreshee.
        assert_eq!(
            negotiate_uas(&invite(Some("600"), None), 90, 1800),
            UasNegotiation::On {
                interval: 600,
                role: Role::Refreshee
            }
        );
        // Peer asks us to refresh.
        assert_eq!(
            negotiate_uas(&invite(Some("600;refresher=uas"), None), 90, 1800),
            UasNegotiation::On {
                interval: 600,
                role: Role::Refresher
            }
        );
        // Below our Min-SE → 422 carrying it.
        assert_eq!(
            negotiate_uas(&invite(Some("30"), None), 90, 1800),
            UasNegotiation::TooSmall(90)
        );
        // Min-SE floor of 1 lets tiny intervals through (tests/demos).
        // `refresher=uac` means the peer refreshes; we (UAS) are refreshee.
        assert_eq!(
            negotiate_uas(&invite(Some("2;refresher=uac"), None), 1, 1800),
            UasNegotiation::On {
                interval: 2,
                role: Role::Refreshee
            }
        );
        // Require: timer without Session-Expires → default interval.
        assert_eq!(
            negotiate_uas(&invite(None, Some("timer")), 90, 1800),
            UasNegotiation::On {
                interval: 1800,
                role: Role::Refreshee
            }
        );
        // Garbage interval: timers cannot be honored → off.
        assert_eq!(
            negotiate_uas(&invite(Some("soon"), None), 90, 1800),
            UasNegotiation::Off
        );
    }

    #[test]
    fn role_roundtrip_both_perspectives() {
        for r in [Some(Refresher::Uac), Some(Refresher::Uas), None] {
            for uas in [true, false] {
                let role = role_for(r, uas);
                assert_eq!(refresher_for(role, uas), r.unwrap_or(Refresher::Uac));
                // The peer's perspective mirrors ours.
                let peer = role_for(refresher_for(role, uas).into(), !uas);
                assert_ne!(peer, role, "exactly one side refreshes");
            }
        }
    }

    #[test]
    fn leg_clocks_fire_at_the_right_time() {
        let t = LegTimers::new(10, Role::Refresher);
        assert!(!t.refresh_due(t.anchored + Duration::from_secs(4)));
        assert!(t.refresh_due(t.anchored + Duration::from_secs(5)));
        // Half-interval floor for tiny intervals.
        let small = LegTimers::new(1, Role::Refresher);
        assert_eq!(small.refresh_after(), Duration::from_secs(1));

        // Expiry at a full interval.
        assert!(!t.expired(t.anchored + Duration::from_secs(9)));
        assert!(t.expired(t.anchored + Duration::from_secs(10)));

        // An in-flight refresh of our own defers expiry.
        let mut pending = LegTimers::new(10, Role::Refresher);
        pending.pending = Some(7);
        assert!(!pending.expired(pending.anchored + Duration::from_secs(30)));

        // The refreshee expires even while nothing is pending on our side.
        let refreshee = LegTimers::new(10, Role::Refreshee);
        assert!(refreshee.expired(refreshee.anchored + Duration::from_secs(10)));
        assert!(!refreshee.refresh_due(refreshee.anchored + Duration::from_secs(60)));
    }
}
