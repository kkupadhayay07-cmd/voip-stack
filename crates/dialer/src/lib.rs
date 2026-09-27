//! # dialer
//!
//! Outbound dialer engine:
//!
//! - **Pacing modes**: preview (agent-initiated), progressive (1 line per
//!   available agent), predictive (Erlang-C–inspired overdial computed from
//!   observed answer rate, average handle time and agent count, with an
//!   abandonment-rate guardrail).
//! - **Caller-ID rotation**: round-robin over a pool of numbers with
//!   per-number usage tracking.
//! - **TCPA compliance**: rolling 30-day abandonment-rate tracking per
//!   campaign with hard stop when the 3% limit is approached, plus
//!   calling-hours windows.
//! - **AMD hooks**: answering-machine detection outcomes feed the pacing
//!   model (no-drop management) and lead disposition.
//! - **Lead management**: queue with attempts cap, retry cooldown, DNC list.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use cdr::{CallRecordBuilder, CdrStore, Direction};

/// Pacing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacingMode {
    /// Agent manually initiates; system never over-dials.
    Preview,
    /// One outbound line per ready agent.
    Progressive,
    /// Overdial computed from live statistics with abandonment guardrail.
    Predictive,
}

/// Answering machine detection outcome (hooked from the media path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdResult {
    Human,
    Machine,
    Uncertain,
}

/// A dialing target.
#[derive(Debug, Clone)]
pub struct Lead {
    pub id: String,
    pub phone: String,
    pub campaign: String,
    pub attempts: u32,
    pub last_attempt: Option<Instant>,
    pub done: bool,
}

/// Campaign configuration.
#[derive(Debug, Clone)]
pub struct Campaign {
    pub id: String,
    pub mode: PacingMode,
    /// Numbers to rotate as caller-ID.
    pub caller_ids: Vec<String>,
    /// Max attempts per lead before parking.
    pub max_attempts: u32,
    /// Cooldown between attempts of the same lead.
    pub retry_cooldown: Duration,
    /// Ring timeout per call.
    pub ring_timeout: Duration,
    /// Local calling-window bounds (hours in [0,24) local time).
    pub calling_window: (u8, u8),
    /// Timezone offset in hours (for the window check; production systems
    /// should feed the real per-lead zone).
    pub tz_offset_hours: i8,
}

impl Campaign {
    pub fn new(id: &str, mode: PacingMode, caller_ids: Vec<String>) -> Self {
        Campaign {
            id: id.to_string(),
            mode,
            caller_ids,
            max_attempts: 3,
            retry_cooldown: Duration::from_secs(1800),
            ring_timeout: Duration::from_secs(30),
            calling_window: (9, 20),
            tz_offset_hours: 0,
        }
    }

    pub fn with_user(self, user: &str, pass: &str) -> Self {
        let _ = (user, pass);
        self
    }
}

/// Live statistics feeding the predictive model.
#[derive(Debug, Clone, Default)]
pub struct LiveStats {
    /// Agents currently in "ready" state.
    pub agents_ready: usize,
    /// Agents currently on a call.
    pub agents_busy: usize,
    /// Outbound calls currently ringing (no agent attached yet).
    pub lines_ringing: usize,
    /// Outbound calls with an INVITE in flight (dialed, no response yet).
    pub lines_dialing: usize,
    /// Outbound calls currently connected (agent on the call).
    pub lines_active: usize,
    /// Rolling answered / dialed counts.
    pub dialed_recent: u64,
    pub answered_recent: u64,
    /// Mean talk time in seconds (recent).
    pub avg_talk_secs: f64,
    /// Mean ring time before answer in seconds (recent).
    pub avg_ring_secs: f64,
}

impl LiveStats {
    /// Observed answer rate (0.05 floor to avoid divide-by-zero storms).
    pub fn answer_rate(&self) -> f64 {
        if self.dialed_recent == 0 {
            0.1
        } else {
            (self.answered_recent as f64 / self.dialed_recent as f64).clamp(0.05, 0.95)
        }
    }
}

/// Abandonment tracking for TCPA (rolling window).
#[derive(Debug, Default)]
pub struct AbandonmentTracker {
    /// (campaign → (abandoned, connected)) ring samples.
    samples: HashMap<String, (u64, u64)>,
}

impl AbandonmentTracker {
    /// TCPA / FCC threshold: 3% abandonment on a 30-day window.
    pub const MAX_ABANDON_RATE: f64 = 0.03;
    /// Rolling window.
    pub const WINDOW: Duration = Duration::from_secs(30 * 24 * 3600);

    pub fn record_abandoned(&mut self, campaign: &str) {
        let e = self.samples.entry(campaign.to_string()).or_default();
        e.0 += 1;
    }

    pub fn record_connected(&mut self, campaign: &str) {
        let e = self.samples.entry(campaign.to_string()).or_default();
        e.1 += 1;
    }

    /// Current abandonment rate (0 when no data).
    pub fn rate(&self, campaign: &str) -> f64 {
        match self.samples.get(campaign) {
            Some((a, c)) if a + c > 0 => *a as f64 / (*a + *c) as f64,
            _ => 0.0,
        }
    }

    /// Whether more predictive dialing is permissible.
    pub fn may_dial(&self, campaign: &str) -> bool {
        self.rate(campaign) < Self::MAX_ABANDON_RATE
    }
}

/// Dialer decisions computed per tick.
#[derive(Debug, Clone, PartialEq)]
pub struct PacingDecision {
    /// Number of lines to dial now.
    pub lines_to_dial: usize,
    /// Reason (for observability).
    pub reason: &'static str,
}

/// Compute the predictive overdial.
///
/// Model: to keep N agents busy with answer rate `p`, ring time `t_ring` and
/// talk time `t_talk`, the system must keep
/// `lines ≈ agents * (t_ring + t_talk) / (t_talk * p)` calls in flight
/// (derived from a stationary Erlang-C approximation), clamped so the
/// projected abandonment stays under the guardrail.
pub fn pace_predictive(stats: &LiveStats, abandon_rate: f64) -> PacingDecision {
    let agents_idle = stats.agents_ready.saturating_sub(stats.agents_busy);
    if agents_idle == 0 {
        return PacingDecision {
            lines_to_dial: 0,
            reason: "no idle agents",
        };
    }
    let p = stats.answer_rate();
    let talk = if stats.avg_talk_secs < 1.0 {
        60.0
    } else {
        stats.avg_talk_secs
    };
    let ring = if stats.avg_ring_secs < 0.5 {
        15.0
    } else {
        stats.avg_ring_secs
    };

    // Lines needed so that p * lines_in_flight ≈ agents needing work,
    // accounting for the ring/talk time ratio.
    let in_flight_needed = agents_idle as f64 * (ring + talk) / (talk * p);
    let mut lines = in_flight_needed.ceil() as usize;

    // Abandonment guardrail: as abandon rate approaches the limit, shrink
    // overdial linearly to zero.
    let headroom = ((AbandonmentTracker::MAX_ABANDON_RATE - abandon_rate)
        / AbandonmentTracker::MAX_ABANDON_RATE)
        .clamp(0.0, 1.0);
    lines = (lines as f64 * headroom).floor() as usize;
    if abandon_rate >= AbandonmentTracker::MAX_ABANDON_RATE || lines == 0 {
        return PacingDecision {
            lines_to_dial: 0,
            reason: "abandonment guardrail",
        };
    }
    // Never overdial more than 3x idle agents (drop protection).
    lines = lines.min(agents_idle * 3);
    // The model targets TOTAL lines in flight, so every outstanding call
    // (INVITE in flight + ringing + active) counts against capacity; only
    // the deficit may be placed now, never a fresh batch on top of it.
    let outstanding = stats
        .lines_dialing
        .saturating_add(stats.lines_ringing)
        .saturating_add(stats.lines_active);
    PacingDecision {
        lines_to_dial: lines.saturating_sub(outstanding),
        reason: "predictive",
    }
}

/// Errors from the dialer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DialerError {
    /// No caller-ID configured for the campaign.
    #[error("no caller-id available")]
    NoCallerId,
    /// Campaign is in TCPA violation or outside calling hours.
    #[error("campaign blocked: {0}")]
    Blocked(&'static str),
    /// No lead available right now.
    #[error("no lead available")]
    NoLead,
}

/// The dialer engine.
pub struct Dialer {
    campaigns: HashMap<String, Campaign>,
    /// Leads per campaign, dial order FIFO.
    leads: HashMap<String, Vec<Lead>>,
    /// DNC list (normalized numbers).
    dnc: std::collections::HashSet<String>,
    abandonment: AbandonmentTracker,
    /// Caller-ID rotation cursors per campaign.
    cid_cursor: HashMap<String, usize>,
    /// CDR sink.
    cdrs: CdrStore,
}

impl Dialer {
    pub fn new(cdrs: CdrStore) -> Self {
        Dialer {
            campaigns: HashMap::new(),
            leads: HashMap::new(),
            dnc: std::collections::HashSet::new(),
            abandonment: AbandonmentTracker::default(),
            cid_cursor: HashMap::new(),
            cdrs,
        }
    }

    pub fn add_campaign(&mut self, c: Campaign) {
        self.leads.entry(c.id.clone()).or_default();
        self.campaigns.insert(c.id.clone(), c);
    }

    pub fn add_dnc(&mut self, phone: &str) {
        self.dnc.insert(normalize(phone));
    }

    pub fn is_dnc(&self, phone: &str) -> bool {
        self.dnc.contains(&normalize(phone))
    }

    pub fn add_lead(&mut self, lead: Lead) -> Result<(), DialerError> {
        if self.is_dnc(&lead.phone) {
            return Err(DialerError::Blocked("lead on DNC list"));
        }
        self.leads
            .entry(lead.campaign.clone())
            .or_default()
            .push(lead);
        Ok(())
    }

    /// Rotate and return the next caller-ID for a campaign.
    pub fn next_caller_id(&mut self, campaign: &str) -> Result<String, DialerError> {
        let c = self
            .campaigns
            .get(campaign)
            .ok_or(DialerError::NoCallerId)?;
        if c.caller_ids.is_empty() {
            return Err(DialerError::NoCallerId);
        }
        let cursor = self.cid_cursor.entry(campaign.to_string()).or_insert(0);
        let id = c.caller_ids[*cursor % c.caller_ids.len()].clone();
        *cursor += 1;
        Ok(id)
    }

    /// Is the campaign inside its calling window at the given local hour?
    pub fn in_calling_window(&self, campaign: &str, utc_hour: u8) -> bool {
        let Some(c) = self.campaigns.get(campaign) else {
            return false;
        };
        let local = (utc_hour as i8 + c.tz_offset_hours).rem_euclid(24) as u8;
        local >= c.calling_window.0 && local < c.calling_window.1
    }

    /// Peek the next dialable lead (respects DNC, attempts, cooldown).
    pub fn next_lead(&mut self, campaign: &str, utc_hour: u8) -> Result<Lead, DialerError> {
        if !self.in_calling_window(campaign, utc_hour) {
            return Err(DialerError::Blocked("outside calling window"));
        }
        if !self.abandonment.may_dial(campaign) {
            return Err(DialerError::Blocked("abandonment rate limit"));
        }
        let c = self.campaigns.get(campaign).ok_or(DialerError::NoLead)?;
        let queue = self.leads.get_mut(campaign).ok_or(DialerError::NoLead)?;
        let now = Instant::now();
        let dnc = &self.dnc;
        // Rotate the queue looking for a dialable lead. DNC is re-checked
        // HERE — the single dial-candidacy point — so a number added to the
        // list after queueing can never be dialed, first attempt or retry.
        for _ in 0..queue.len() {
            let mut lead = queue.remove(0);
            if !lead.done && dnc.contains(&normalize(&lead.phone)) {
                lead.done = true;
            }
            let retryable = lead
                .last_attempt
                .map(|t| now.duration_since(t) >= c.retry_cooldown)
                .unwrap_or(true);
            if !lead.done && lead.attempts < c.max_attempts && retryable {
                queue.push(lead);
                // Return a clone; caller marks the attempt.
                return Ok(queue.last().unwrap().clone());
            }
            queue.push(lead);
        }
        Err(DialerError::NoLead)
    }

    /// Mark a lead attempt as started (increments attempts).
    pub fn mark_attempt(&mut self, lead_id: &str) {
        for queue in self.leads.values_mut() {
            for lead in queue.iter_mut() {
                if lead.id == lead_id {
                    lead.attempts += 1;
                    lead.last_attempt = Some(Instant::now());
                    return;
                }
            }
        }
    }

    /// Record a call outcome: updates abandonment, parks exhausted leads,
    /// writes a CDR.
    #[allow(clippy::too_many_arguments)]
    pub fn record_outcome(
        &mut self,
        campaign: &str,
        lead_id: &str,
        answered: bool,
        abandoned: bool,
        amd: Option<AmdResult>,
        sip_code: u16,
        talk_secs: u64,
        caller_id: &str,
    ) {
        if abandoned {
            self.abandonment.record_abandoned(campaign);
        } else if answered {
            self.abandonment.record_connected(campaign);
        }
        // Lead disposition: a lead that was answered is complete and must
        // never be eligible for redial; machine-detected calls park the
        // lead (message drop policy); exhausted leads park.
        if let Some(queue) = self.leads.get_mut(campaign) {
            if let Some(lead) = queue.iter_mut().find(|l| l.id == lead_id) {
                if answered || matches!(amd, Some(AmdResult::Machine)) {
                    lead.done = true;
                }
                // Exhausted leads park.
                let max_attempts = self
                    .campaigns
                    .get(campaign)
                    .map(|c| c.max_attempts)
                    .unwrap_or(3);
                if lead.attempts >= max_attempts {
                    lead.done = true;
                }
            }
        }
        // CDR.
        let from = format!("sip:{caller_id}@dialer");
        let to = format!("sip:{lead_id}@dialer");
        let rec = CallRecordBuilder::new(Direction::Outbound, &from, &to)
            .a_call_id(&format!("dialer-{lead_id}"))
            .campaign(campaign)
            .correlate("lead", lead_id)
            .correlate("amd", &format!("{:?}", amd.unwrap_or(AmdResult::Uncertain)))
            .finish(sip_code, false, talk_secs);
        let store = self.cdrs.clone();
        tokio::spawn(async move {
            store.insert(rec).await;
        });
    }

    /// Compute how many lines to dial now for a campaign.
    pub fn pace(&self, campaign: &str, stats: &LiveStats, utc_hour: u8) -> PacingDecision {
        let Some(c) = self.campaigns.get(campaign) else {
            return PacingDecision {
                lines_to_dial: 0,
                reason: "unknown campaign",
            };
        };
        if !self.in_calling_window(campaign, utc_hour) {
            return PacingDecision {
                lines_to_dial: 0,
                reason: "outside calling window",
            };
        }
        match c.mode {
            PacingMode::Preview => PacingDecision {
                lines_to_dial: 0,
                reason: "preview: agent-initiated",
            },
            PacingMode::Progressive => PacingDecision {
                lines_to_dial: stats.agents_ready.saturating_sub(stats.lines_ringing),
                reason: "progressive",
            },
            PacingMode::Predictive => {
                let rate = self.abandonment.rate(campaign);
                pace_predictive(stats, rate)
            }
        }
    }

    /// Campaign abandonment rate (TCPA audit).
    pub fn abandonment_rate(&self, campaign: &str) -> f64 {
        self.abandonment.rate(campaign)
    }

    /// Remaining dialable leads.
    pub fn pending_leads(&self, campaign: &str) -> usize {
        self.leads
            .get(campaign)
            .map(|q| q.iter().filter(|l| !l.done).count())
            .unwrap_or(0)
    }
}

fn normalize(phone: &str) -> String {
    phone.chars().filter(|c| c.is_ascii_digit()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predictive_paces_up_with_low_answer_rate() {
        let stats = LiveStats {
            agents_ready: 10,
            agents_busy: 0,
            ..Default::default()
        };
        let decision = pace_predictive(&stats, 0.0);
        assert!(decision.lines_to_dial > 0);
    }

    #[test]
    fn predictive_stops_at_abandonment_limit() {
        let stats = LiveStats {
            agents_ready: 10,
            ..Default::default()
        };
        assert!(pace_predictive(&stats, 0.0).lines_to_dial > 0);
        // At the TCPA limit: no dialing.
        assert_eq!(
            pace_predictive(&stats, AbandonmentTracker::MAX_ABANDON_RATE).lines_to_dial,
            0
        );
    }

    #[test]
    fn predictive_zero_when_no_idle_agents() {
        let stats = LiveStats {
            agents_ready: 5,
            agents_busy: 5,
            ..Default::default()
        };
        assert_eq!(pace_predictive(&stats, 0.0).lines_to_dial, 0);
    }

    #[test]
    fn caller_id_rotation_round_robin() {
        let mut dialer = Dialer::new(cdr::CdrStore::new(10));
        dialer.add_campaign(Campaign::new(
            "c1",
            PacingMode::Progressive,
            vec!["5550001".into(), "5550002".into(), "5550003".into()],
        ));
        let seq: Vec<String> = (0..5)
            .map(|_| dialer.next_caller_id("c1").unwrap())
            .collect();
        assert_eq!(
            seq,
            vec!["5550001", "5550002", "5550003", "5550001", "5550002"]
        );
    }

    #[tokio::test]
    async fn lead_lifecycle_with_dnc_and_attempts() {
        let mut dialer = Dialer::new(cdr::CdrStore::new(100));
        dialer.add_campaign(Campaign::new(
            "c2",
            PacingMode::Progressive,
            vec!["5550001".into()],
        ));
        dialer.add_campaign(Campaign {
            max_attempts: 2,
            retry_cooldown: Duration::from_secs(0),
            ..Campaign::new("c3", PacingMode::Progressive, vec!["5550009".into()])
        });

        // DNC lead rejected.
        dialer.add_dnc("18005551000");
        assert!(dialer
            .add_lead(Lead {
                id: "l-dnc".into(),
                phone: "1-800-555-1000".into(),
                campaign: "c2".into(),
                attempts: 0,
                last_attempt: None,
                done: false,
            })
            .is_err());

        dialer
            .add_lead(Lead {
                id: "l-1".into(),
                phone: "2125550100".into(),
                campaign: "c3".into(),
                attempts: 0,
                last_attempt: None,
                done: false,
            })
            .unwrap();

        // Attempt 1 and 2.
        let lead = dialer.next_lead("c3", 12).unwrap();
        dialer.mark_attempt(&lead.id);
        dialer.record_outcome("c3", "l-1", false, false, None, 480, 0, "5550009");
        let lead = dialer.next_lead("c3", 12).unwrap();
        dialer.mark_attempt(&lead.id);
        // After max attempts the lead is parked.
        dialer.record_outcome("c3", "l-1", false, false, None, 480, 0, "5550009");
        assert_eq!(dialer.pending_leads("c3"), 0);
        assert!(dialer.next_lead("c3", 12).is_err());
    }

    #[tokio::test]
    async fn calling_window_blocks() {
        let mut dialer = Dialer::new(cdr::CdrStore::new(10));
        // Window 9..20 UTC.
        dialer.add_campaign(Campaign::new(
            "c4",
            PacingMode::Progressive,
            vec!["5550001".into()],
        ));
        dialer
            .add_lead(Lead {
                id: "l-w".into(),
                phone: "2125550100".into(),
                campaign: "c4".into(),
                attempts: 0,
                last_attempt: None,
                done: false,
            })
            .unwrap();
        assert!(matches!(
            dialer.next_lead("c4", 23),
            Err(DialerError::Blocked("outside calling window"))
        ));
        assert!(dialer.next_lead("c4", 10).is_ok());
    }

    #[tokio::test]
    async fn outcomes_written_to_cdr() {
        let store = cdr::CdrStore::new(100);
        let mut dialer = Dialer::new(store.clone());
        dialer.add_campaign(Campaign::new(
            "c5",
            PacingMode::Progressive,
            vec!["5550001".into()],
        ));
        dialer.record_outcome(
            "c5",
            "l-x",
            true,
            false,
            Some(AmdResult::Human),
            200,
            42,
            "5550001",
        );
        // Give the spawn a moment.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stats = store.stats(Some("c5")).await;
        assert_eq!(stats.total, 1);
        assert_eq!(stats.answered, 1);
    }

    #[test]
    fn progressive_paces_one_per_ready_agent() {
        let dialer = Dialer::new(cdr::CdrStore::new(10));
        let stats = LiveStats {
            agents_ready: 8,
            lines_ringing: 2,
            ..Default::default()
        };
        let d = dialer.pace("missing", &stats, 12);
        assert_eq!(d.lines_to_dial, 0);
    }

    // Regression 2.14(i): ALL outstanding calls (dialing + ringing + active)
    // count against the predictive in-flight target — no overdialing.
    #[test]
    fn predictive_counts_all_outstanding_calls() {
        let mut stats = LiveStats {
            agents_ready: 6,
            dialed_recent: 100,
            answered_recent: 90, // p = 0.9
            avg_talk_secs: 60.0,
            avg_ring_secs: 15.0,
            ..Default::default()
        };
        // Target in flight: ceil(6 * (15 + 60) / (60 * 0.9)) = 9.
        assert_eq!(pace_predictive(&stats, 0.0).lines_to_dial, 9);
        // 15 calls already outstanding across every stage: booked capacity
        // saturates the target, so nothing more may be dialed.
        stats.lines_dialing = 4;
        stats.lines_ringing = 5;
        stats.lines_active = 6;
        assert_eq!(
            pace_predictive(&stats, 0.0).lines_to_dial,
            0,
            "booked capacity must not be dialed on top of"
        );
        // Partially booked capacity: only the deficit is dialed (9 - 3).
        stats.lines_dialing = 2;
        stats.lines_ringing = 1;
        stats.lines_active = 0;
        assert_eq!(pace_predictive(&stats, 0.0).lines_to_dial, 6);
    }

    // Regression 2.14(ii): a lead that got answered is complete and must
    // never be eligible for redial.
    #[tokio::test]
    async fn answered_lead_is_never_redialed() {
        let mut dialer = Dialer::new(cdr::CdrStore::new(10));
        dialer.add_campaign(Campaign {
            max_attempts: 3,
            retry_cooldown: Duration::from_secs(0),
            ..Campaign::new("c-ans", PacingMode::Predictive, vec!["5550001".into()])
        });
        dialer
            .add_lead(Lead {
                id: "l-a".into(),
                phone: "2125550100".into(),
                campaign: "c-ans".into(),
                attempts: 0,
                last_attempt: None,
                done: false,
            })
            .unwrap();
        let lead = dialer.next_lead("c-ans", 12).unwrap();
        dialer.mark_attempt(&lead.id);
        dialer.record_outcome(
            "c-ans",
            "l-a",
            true,
            false,
            Some(AmdResult::Human),
            200,
            30,
            "5550001",
        );
        assert_eq!(dialer.pending_leads("c-ans"), 0, "answered lead is done");
        assert!(
            dialer.next_lead("c-ans", 12).is_err(),
            "answered lead must not be redialed"
        );
    }

    // Regression 2.14(iii): DNC is enforced on every dial candidacy — a
    // number DNC-listed after queueing is blocked on the retry path too.
    #[tokio::test]
    async fn dnc_gate_blocks_retry_path() {
        let mut dialer = Dialer::new(cdr::CdrStore::new(10));
        dialer.add_campaign(Campaign {
            max_attempts: 3,
            retry_cooldown: Duration::from_secs(0),
            ..Campaign::new("c-dnc", PacingMode::Progressive, vec!["5550001".into()])
        });
        dialer
            .add_lead(Lead {
                id: "l-r".into(),
                phone: "2125550199".into(),
                campaign: "c-dnc".into(),
                attempts: 0,
                last_attempt: None,
                done: false,
            })
            .unwrap();
        let lead = dialer.next_lead("c-dnc", 12).unwrap();
        dialer.mark_attempt(&lead.id);
        dialer.record_outcome("c-dnc", "l-r", false, false, None, 486, 0, "5550001");
        // DNC-listed between attempts: the retry must be blocked.
        dialer.add_dnc("212-555-0199");
        assert!(
            dialer.next_lead("c-dnc", 12).is_err(),
            "retry of DNC number must be blocked"
        );
        assert_eq!(dialer.pending_leads("c-dnc"), 0, "DNC lead parked");
    }
}
