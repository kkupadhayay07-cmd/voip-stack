//! # cdr
//!
//! Call Detail Records: a typed record covering the full call lifecycle,
//! an in-memory store with bounded capacity, query API and JSON export.
//!
//! The store is the single source of truth for billing/compliance queries:
//! every call that reaches the platform produces exactly one CDR with a
//! unique id, correlation ids for both legs, timing, disposition and
//! quality metrics.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// High-level call disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Call answered and connected.
    Answered,
    /// Callee busy (486).
    Busy,
    /// No answer within the ring timeout (480/408).
    NoAnswer,
    /// Rejected by the callee (603).
    Rejected,
    /// Failed before ringing (4xx/5xx).
    Failed,
    /// Canceled by the caller before answer.
    Canceled,
    /// Blocked by policy (ACL/DNC).
    Blocked,
}

impl Disposition {
    pub fn from_sip_code(code: u16, canceled: bool) -> Self {
        if canceled {
            return Disposition::Canceled;
        }
        match code {
            200 => Disposition::Answered,
            486 => Disposition::Busy,
            480 | 408 => Disposition::NoAnswer,
            603 => Disposition::Rejected,
            _ => Disposition::Failed,
        }
    }
}

/// One complete call record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    /// Unique record id.
    pub id: String,
    /// A-leg (caller) identifiers.
    pub a_call_id: String,
    /// B-leg (callee) identifiers when the platform originated it.
    pub b_call_id: Option<String>,
    pub direction: Direction,
    pub from_uri: String,
    pub to_uri: String,
    pub from_ip: Option<String>,
    pub to_ip: Option<String>,
    /// SIP response code that terminated the setup (e.g. 200, 486).
    pub sip_code: Option<u16>,
    pub disposition: Disposition,
    /// Milliseconds from INVITE to first SIP response.
    pub setup_ms: Option<u64>,
    /// Milliseconds from INVITE to final response.
    pub ring_ms: Option<u64>,
    /// Connected duration in seconds.
    pub talk_secs: u64,
    /// Media metrics captured during the call.
    pub media: MediaStats,
    /// Campaign association when originated by the dialer.
    pub campaign_id: Option<String>,
    /// Arbitrary correlation (agent id, lead id, AI session id).
    pub correlation: HashMap<String, String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

/// Media quality snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MediaStats {
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub packets_lost: u64,
    pub avg_jitter_ms: f32,
    pub plc_events: u64,
    pub codec: Option<String>,
}

/// Call direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Builder for incrementally-built CDRs.
#[derive(Debug, Clone)]
pub struct CallRecordBuilder {
    record: CallRecord,
}

impl CallRecordBuilder {
    pub fn new(direction: Direction, from_uri: &str, to_uri: &str) -> Self {
        CallRecordBuilder {
            record: CallRecord {
                id: uuid::Uuid::new_v4().to_string(),
                a_call_id: String::new(),
                b_call_id: None,
                direction,
                from_uri: from_uri.to_string(),
                to_uri: to_uri.to_string(),
                from_ip: None,
                to_ip: None,
                sip_code: None,
                disposition: Disposition::Failed,
                setup_ms: None,
                ring_ms: None,
                talk_secs: 0,
                media: MediaStats::default(),
                campaign_id: None,
                correlation: HashMap::new(),
                started_at: now_iso(),
                finished_at: None,
            },
        }
    }

    pub fn a_call_id(mut self, v: &str) -> Self {
        self.record.a_call_id = v.to_string();
        self
    }

    pub fn b_call_id(mut self, v: Option<&str>) -> Self {
        self.record.b_call_id = v.map(|s| s.to_string());
        self
    }

    pub fn ips(mut self, from: Option<&str>, to: Option<&str>) -> Self {
        self.record.from_ip = from.map(|s| s.to_string());
        self.record.to_ip = to.map(|s| s.to_string());
        self
    }

    pub fn campaign(mut self, id: &str) -> Self {
        self.record.campaign_id = Some(id.to_string());
        self
    }

    pub fn correlate(mut self, key: &str, value: &str) -> Self {
        self.record
            .correlation
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn finish(mut self, sip_code: u16, canceled: bool, talk_secs: u64) -> CallRecord {
        self.record.sip_code = Some(sip_code);
        self.record.disposition = Disposition::from_sip_code(sip_code, canceled);
        self.record.talk_secs = talk_secs;
        self.record.finished_at = Some(now_iso());
        self.record
    }

    pub fn build_unfinished(self) -> CallRecord {
        self.record
    }
}

fn now_iso() -> String {
    // RFC 3339 UTC timestamp without external dependencies.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    epoch_to_iso(now.as_secs() as i64, now.subsec_millis())
}

/// Convert unix seconds to a UTC ISO-8601 string (civil-from-days algorithm).
fn epoch_to_iso(secs: i64, millis: u32) -> String {
    let days = secs.div_euclid(86400);
    let secs_of_day = secs.rem_euclid(86400);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // Howard Hinnant's civil_from_days.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Query filters.
#[derive(Debug, Clone, Default)]
pub struct CdrQuery {
    pub campaign_id: Option<String>,
    pub disposition: Option<Disposition>,
    pub direction: Option<Direction>,
    pub min_talk_secs: Option<u64>,
    pub limit: Option<usize>,
}

/// Thread-safe in-memory CDR store.
#[derive(Debug, Clone, Default)]
pub struct CdrStore {
    inner: Arc<RwLock<CdrStoreInner>>,
}

#[derive(Debug, Default)]
struct CdrStoreInner {
    records: Vec<CallRecord>,
    /// Bounded capacity: oldest records are dropped beyond this.
    capacity: usize,
}

impl CdrStore {
    pub fn new(capacity: usize) -> Self {
        CdrStore {
            inner: Arc::new(RwLock::new(CdrStoreInner {
                records: Vec::new(),
                capacity,
            })),
        }
    }

    /// Persist a finished record.
    pub async fn insert(&self, record: CallRecord) {
        // cdr hook: announce the finished record on the observability bus
        observ::session::emit_for(
            &record.a_call_id,
            observ::EventKind::CdrWritten {
                record: serde_json::to_value(&record).unwrap_or_default(),
            },
        );
        let mut inner = self.inner.write().await;
        if inner.records.len() >= inner.capacity {
            let overflow = inner.records.len() + 1 - inner.capacity;
            inner.records.drain(..overflow);
        }
        inner.records.push(record);
    }

    /// Query with filters, newest first.
    pub async fn query(&self, q: &CdrQuery) -> Vec<CallRecord> {
        let inner = self.inner.read().await;
        let mut out: Vec<CallRecord> = inner
            .records
            .iter()
            .filter(|r| {
                if let Some(c) = &q.campaign_id {
                    if r.campaign_id.as_deref() != Some(c.as_str()) {
                        return false;
                    }
                }
                if let Some(d) = &q.disposition {
                    if &r.disposition != d {
                        return false;
                    }
                }
                if let Some(d) = &q.direction {
                    if &r.direction != d {
                        return false;
                    }
                }
                if let Some(mt) = q.min_talk_secs {
                    if r.talk_secs < mt {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        out.reverse(); // newest first
        if let Some(limit) = q.limit {
            out.truncate(limit);
        }
        out
    }

    /// Fetch a single record by id.
    pub async fn get(&self, id: &str) -> Option<CallRecord> {
        self.inner
            .read()
            .await
            .records
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    /// Aggregate campaign statistics (answer rate, talk time).
    pub async fn stats(&self, campaign_id: Option<&str>) -> StoreStats {
        let inner = self.inner.read().await;
        let relevant: Vec<&CallRecord> = inner
            .records
            .iter()
            .filter(|r| match campaign_id {
                Some(c) => r.campaign_id.as_deref() == Some(c),
                None => true,
            })
            .collect();
        let total = relevant.len() as u64;
        let answered = relevant
            .iter()
            .filter(|r| r.disposition == Disposition::Answered)
            .count() as u64;
        let talk: u64 = relevant.iter().map(|r| r.talk_secs).sum();
        StoreStats {
            total,
            answered,
            answer_rate: if total > 0 {
                answered as f64 / total as f64
            } else {
                0.0
            },
            total_talk_secs: talk,
        }
    }
}

/// Aggregate statistics.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct StoreStats {
    pub total: u64,
    pub answered: u64,
    pub answer_rate: f64,
    pub total_talk_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_mapping() {
        assert_eq!(
            Disposition::from_sip_code(200, false),
            Disposition::Answered
        );
        assert_eq!(Disposition::from_sip_code(486, false), Disposition::Busy);
        assert_eq!(
            Disposition::from_sip_code(480, false),
            Disposition::NoAnswer
        );
        assert_eq!(
            Disposition::from_sip_code(603, false),
            Disposition::Rejected
        );
        assert_eq!(Disposition::from_sip_code(200, true), Disposition::Canceled);
        assert_eq!(Disposition::from_sip_code(500, false), Disposition::Failed);
    }

    #[test]
    fn iso_timestamp_shape() {
        let ts = now_iso();
        // 2024-01-01T00:00:00.000Z style
        assert!(ts.contains('T') && ts.ends_with('Z'), "{ts}");
        assert_eq!(ts.len(), 24, "{ts}");
    }

    #[tokio::test]
    async fn store_capacity_and_query() {
        let store = CdrStore::new(5);
        for i in 0..10 {
            let rec = CallRecordBuilder::new(Direction::Outbound, "sip:a@x", "sip:b@y")
                .a_call_id(&format!("cid-{i}"))
                .campaign("camp-1")
                .finish(200, false, i);
            store.insert(rec).await;
        }
        // Capacity bound keeps the newest 5.
        let all = store.query(&CdrQuery::default()).await;
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].a_call_id, "cid-9", "newest first");

        let by_campaign = store
            .query(&CdrQuery {
                campaign_id: Some("camp-1".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(by_campaign.len(), 5);
    }

    #[tokio::test]
    async fn stats_aggregation() {
        let store = CdrStore::new(100);
        for (code, talk) in [(200u16, 60u64), (200, 120), (486, 0), (480, 0)] {
            let rec = CallRecordBuilder::new(Direction::Outbound, "sip:a@x", "sip:b@y")
                .campaign("camp-x")
                .finish(code, false, talk);
            store.insert(rec).await;
        }
        let stats = store.stats(Some("camp-x")).await;
        assert_eq!(stats.total, 4);
        assert_eq!(stats.answered, 2);
        assert!((stats.answer_rate - 0.5).abs() < 1e-9);
        assert_eq!(stats.total_talk_secs, 180);
    }

    #[tokio::test]
    async fn json_roundtrip() {
        let rec = CallRecordBuilder::new(Direction::Inbound, "sip:x@y", "sip:z@w")
            .a_call_id("abc")
            .correlate("agent", "42")
            .finish(200, false, 30);
        let json = serde_json::to_string(&rec).unwrap();
        let back: CallRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, rec.id);
        assert_eq!(back.disposition, Disposition::Answered);
        assert_eq!(
            back.correlation.get("agent").map(|s| s.as_str()),
            Some("42")
        );
    }

    #[tokio::test]
    async fn single_record_get() {
        let store = CdrStore::new(10);
        let rec = CallRecordBuilder::new(Direction::Outbound, "a", "b").finish(200, false, 5);
        let id = rec.id.clone();
        store.insert(rec).await;
        assert!(store.get(&id).await.is_some());
        assert!(store.get("missing").await.is_none());
    }
}
