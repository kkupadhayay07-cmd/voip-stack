//! CDR finalization: consumes the b2bua's per-call event stream and writes
//! one finished `cdr::CallRecord` per call into the store the REST API
//! serves. The record lands exactly when the call tears down (BYE on both
//! legs, Timer B expiry, or CANCEL).

use std::collections::HashMap;

use b2bua::{CdrEvent, Side};
use cdr::{CallRecordBuilder, CallRecord, CdrStore, Direction, MediaStats};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::core::OutboundIds;

struct CallState {
    from: String,
    to: String,
    answered: bool,
    codec: Option<String>,
}

pub async fn run(mut rx: UnboundedReceiver<CdrEvent>, store: CdrStore, outbound: OutboundIds) {
    let mut open: HashMap<String, CallState> = HashMap::new();
    while let Some(ev) = rx.recv().await {
        match ev {
            CdrEvent::LegInvited {
                call_id, from, to, ..
            } => {
                open.entry(call_id.clone()).or_insert(CallState {
                    from,
                    to,
                    answered: false,
                    codec: None,
                });
            }
            CdrEvent::LegAnswered {
                call_id,
                side,
                codec,
                ..
            } => {
                if let Some(st) = open.get_mut(&call_id) {
                    st.answered = true;
                    if side == Side::A {
                        st.codec = Some(codec);
                    }
                }
            }
            CdrEvent::CallEnded {
                call_id,
                duration_ms,
                frames_a_to_b,
                frames_b_to_a,
                ..
            } => {
                let direction = if outbound.lock().expect("outbound ids").contains(&call_id) {
                    Direction::Outbound
                } else {
                    Direction::Inbound
                };
                let st = open.remove(&call_id).unwrap_or(CallState {
                    from: String::new(),
                    to: String::new(),
                    answered: false,
                    codec: None,
                });
                let record = build_record(
                    direction,
                    &call_id,
                    &st,
                    duration_ms,
                    frames_a_to_b,
                    frames_b_to_a,
                );
                tracing::info!(
                    call_id = %call_id,
                    id = %record.id,
                    direction = ?direction,
                    disposition = ?record.disposition,
                    talk_secs = record.talk_secs,
                    "cdr written"
                );
                store.insert(record).await;
            }
            _ => {}
        }
    }
}

fn build_record(
    direction: Direction,
    call_id: &str,
    st: &CallState,
    duration_ms: u64,
    frames_a_to_b: u64,
    frames_b_to_a: u64,
) -> CallRecord {
    let talk_secs = duration_ms / 1000;
    let (code, canceled) = if st.answered { (200u16, false) } else { (487, false) };
    let mut rec = CallRecordBuilder::new(direction, &st.from, &st.to)
        .a_call_id(call_id)
        .correlate("frames_a_to_b", &frames_a_to_b.to_string())
        .correlate("frames_b_to_a", &frames_b_to_a.to_string())
        .finish(code, canceled, talk_secs);
    rec.media = MediaStats {
        packets_rx: frames_a_to_b,
        packets_tx: frames_b_to_a,
        packets_lost: 0,
        avg_jitter_ms: 0.0,
        plc_events: 0,
        codec: st.codec.clone(),
    };
    rec
}
