//! Human-readable + jsonl trace writer.
//!
//! One line per event lands in `trace-YYYYMMDD.log` (human) and
//! `trace-YYYYMMDD.jsonl` (machine, consumed by the zrtc CLI). Per-packet
//! media events (`RtpRx`/`RtpTx`) are captured by the pcap sinks only and
//! never reach the trace files — the trace keeps signaling, media
//! lifecycle/stats, pipeline and error events. Every event is buffered per
//! Call-ID; when `cdr-written` arrives the whole per-call block is dumped
//! (header + ordered events + media + timing) and the call leaves memory.
//! Also maintains `status.json` for `zrtc capture status`.

use crate::event::{ts_iso, Event, EventKind, Leg};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Shared counters the three writer tasks update for `status.json`.
#[derive(Debug, Default)]
pub struct StatusShared {
    pub sip_packets: AtomicU64,
    pub sip_bytes: AtomicU64,
    pub rtp_packets: AtomicU64,
    pub rtp_bytes: AtomicU64,
    pub pcap_stopped: AtomicBool,
    pub trace_events: AtomicU64,
    pub trace_lagged: AtomicU64,
}

impl StatusShared {
    pub fn to_json(&self, started_at_ms: i64) -> serde_json::Value {
        serde_json::json!({
            "started_at_ms": started_at_ms,
            "sip_packets": self.sip_packets.load(Ordering::Relaxed),
            "sip_bytes": self.sip_bytes.load(Ordering::Relaxed),
            "rtp_packets": self.rtp_packets.load(Ordering::Relaxed),
            "rtp_bytes": self.rtp_bytes.load(Ordering::Relaxed),
            "pcap_stopped": self.pcap_stopped.load(Ordering::Relaxed),
            "trace_events": self.trace_events.load(Ordering::Relaxed),
            "trace_lagged": self.trace_lagged.load(Ordering::Relaxed),
        })
    }
}

/// What the per-call buffer keeps until the CDR lands.
struct CallBuf {
    events: Vec<Event>,
    truncated: bool,
}

const MAX_CALLS: usize = 10_000;
const MAX_EVENTS_PER_CALL: usize = 4_000;

/// Trace writer state (owned by the trace task).
pub struct TraceSink {
    dir: PathBuf,
    include_sdp: bool,
    include_sip_bodies: bool,
    day: String,
    log: Option<io::BufWriter<std::fs::File>>,
    jsonl: Option<io::BufWriter<std::fs::File>>,
    calls: HashMap<String, CallBuf>,
    status: Arc<StatusShared>,
    started_at_ms: i64,
    status_path: PathBuf,
    pub log_file: PathBuf,
    pub jsonl_file: PathBuf,
}

impl TraceSink {
    pub fn new(
        dir: PathBuf,
        include_sdp: bool,
        include_sip_bodies: bool,
        status: Arc<StatusShared>,
    ) -> Self {
        let started_at_ms = crate::event::now_ms();
        TraceSink {
            status_path: dir.join("status.json"),
            log_file: dir.join("trace.log"),
            jsonl_file: dir.join("trace.jsonl"),
            dir,
            include_sdp,
            include_sip_bodies,
            day: String::new(),
            log: None,
            jsonl: None,
            calls: HashMap::new(),
            status,
            started_at_ms,
        }
    }

    /// Consumes events forever; rotates files at UTC midnight.
    pub async fn run(
        mut self,
        mut rx: broadcast::Receiver<Event>,
        flush_interval_ms: u64,
    ) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(
            flush_interval_ms.max(10),
        ));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Ok(ev) => self.on_event(ev),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        self.status.trace_lagged.fetch_add(n, Ordering::Relaxed);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = ticker.tick() => self.write_status(),
            }
        }
        self.write_status();
    }

    fn on_event(&mut self, ev: Event) {
        // Per-packet media goes to the pcap sinks (they subscribe to the
        // same bus); the trace only carries media lifecycle/stats events.
        if matches!(ev.kind, EventKind::RtpRx { .. } | EventKind::RtpTx { .. }) {
            return;
        }
        if let Err(e) = self.roll_day() {
            tracing::error!("trace sink: {e}");
            return;
        }
        self.status.trace_events.fetch_add(1, Ordering::Relaxed);

        let line = fmt_event(&ev, self.include_sdp, self.include_sip_bodies);
        if let Some(f) = self.log.as_mut() {
            let _ = writeln!(f, "{line}");
        }
        if let Some(f) = self.jsonl.as_mut() {
            if let Ok(json) = serde_json::to_string(&ev) {
                let _ = writeln!(f, "{json}");
            }
        }

        // Per-call buffer.
        if ev.call_id.is_empty() {
            return;
        }
        let is_cdr = matches!(ev.kind, EventKind::CdrWritten { .. });
        let buf = self
            .calls
            .entry(ev.call_id.clone())
            .or_insert_with(|| CallBuf { events: Vec::new(), truncated: false });
        if buf.events.len() < MAX_EVENTS_PER_CALL {
            buf.events.push(ev.clone());
        } else {
            buf.truncated = true;
        }
        if is_cdr {
            if let Some(buf) = self.calls.remove(&ev.call_id) {
                if let Some(f) = self.log.as_mut() {
                    let _ = dump_block(f, &ev.call_id, &buf, &ev);
                }
            }
        }
        // Bound memory: drop the oldest unfinished calls.
        if self.calls.len() > MAX_CALLS {
            let oldest = self
                .calls
                .keys()
                .next()
                .cloned();
            if let Some(k) = oldest {
                self.calls.remove(&k);
            }
        }
    }

    fn roll_day(&mut self) -> std::io::Result<()> {
        let today = chrono::Utc::now().format("%Y%m%d").to_string();
        if self.day == today && self.log.is_some() {
            return Ok(());
        }
        self.log_file = self.dir.join(format!("trace-{today}.log"));
        self.jsonl_file = self.dir.join(format!("trace-{today}.jsonl"));
        self.day = today;
        self.log = Some(io::BufWriter::new(std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)?));
        self.jsonl = Some(io::BufWriter::new(std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.jsonl_file)?));
        Ok(())
    }

    fn write_status(&mut self) {
        self.flush_files();
        let json = self.status.to_json(self.started_at_ms);
        if let Ok(tmp) = serde_json::to_string_pretty(&json) {
            let path = self.status_path.clone();
            let _ = std::fs::write(&path, tmp);
        }
    }

    fn flush_files(&mut self) {
        if let Some(f) = self.log.as_mut() {
            let _ = f.flush();
        }
        if let Some(f) = self.jsonl.as_mut() {
            let _ = f.flush();
        }
    }
}

/// One human-readable line per event.
pub fn fmt_event(ev: &Event, include_sdp: bool, include_sip_bodies: bool) -> String {
    let ts = ts_iso(ev.ts_ms);
    let cid = if ev.call_id.is_empty() { "-" } else { &ev.call_id };
    let head = format!("{ts} cid={cid} leg={} {}", ev.leg.as_str(), ev.kind_name());
    match &ev.kind {
        EventKind::SipRx { peer, bytes, .. } | EventKind::SipTx { peer, bytes, .. } => {
            let first_line = String::from_utf8_lossy(
                bytes.split(|&b| b == b'\r').next().unwrap_or(bytes),
            );
            let mut s = format!("{head} peer={} bytes={} {first_line}", peer.addr, bytes.len());
            if include_sip_bodies {
                if let Some(sdp_len) = body_summary(bytes, b"v=0") {
                    if include_sdp {
                        s.push_str(&format!(" sdp_bytes={sdp_len}"));
                    }
                }
            }
            s
        }
        EventKind::RtpRx { src, dst, bytes, ssrc, seq, pt, .. }
        | EventKind::RtpTx { src, dst, bytes, ssrc, seq, pt, .. } => {
            format!(
                "{head} {src}->{dst} ssrc={ssrc:#x} seq={seq} pt={pt} bytes={}",
                bytes.len()
            )
        }
        EventKind::SbcDecision { verdict, reason, method, source } => {
            format!("{head} verdict={verdict} reason={reason} method={method} source={source}")
        }
        EventKind::ProxyFork { method, targets } => {
            format!("{head} method={method} targets={targets:?}")
        }
        EventKind::RegistrarLookup { aor, found, bindings } => {
            format!("{head} aor={aor} found={found} bindings={bindings}")
        }
        EventKind::B2buaLegUp { side, peer, codec } => {
            format!("{head} side={side} peer={peer} codec={codec}")
        }
        EventKind::B2buaLegDown { side, reason } => {
            format!("{head} side={side} reason={reason}")
        }
        EventKind::MediaStart { pump_leg, local, rx_codec, tx_codec } => {
            format!("{head} local={local} rx_codec={rx_codec} tx_codec={tx_codec} pump_leg={}", pump_leg.as_str())
        }
        EventKind::MediaStats { pump_leg, rx, tx, lost, jitter_ms, concealed }
        | EventKind::MediaEnd { pump_leg, rx, tx, lost, jitter_ms, concealed, .. } => {
            let mut s = format!(
                "{head} pump_leg={} rx={rx} tx={tx} lost={lost} jitter_ms={jitter_ms:.1} concealed={concealed}",
                pump_leg.as_str()
            );
            if let EventKind::MediaEnd { talk_ms, remote, .. } = &ev.kind {
                s.push_str(&format!(" talk_ms={talk_ms}"));
                if let Some(r) = remote {
                    s.push_str(&format!(" remote={r}"));
                }
            }
            s
        }
        EventKind::Vad { state } => format!("{head} state={state}"),
        EventKind::Stt { state, text } => format!("{head} state={state} text=\"{text}\""),
        EventKind::Llm { state, ms } => format!("{head} state={state} ms={ms}"),
        EventKind::Tts { state, bytes } => format!("{head} state={state} bytes={bytes}"),
        EventKind::CdrWritten { record } => {
            let id = record.get("id").and_then(|v| v.as_str()).unwrap_or("-");
            let disp = record.get("disposition").and_then(|v| v.as_str()).unwrap_or("-");
            format!("{head} cdr_id={id} disposition={disp}")
        }
    }
}

fn body_summary(bytes: &[u8], marker: &[u8]) -> Option<usize> {
    let idx = bytes.windows(marker.len()).position(|w| w == marker)?;
    Some(bytes.len() - idx)
}

/// End-of-call block appended to the human log when the CDR lands.
fn dump_block(
    f: &mut impl Write,
    call_id: &str,
    buf: &CallBuf,
    cdr: &Event,
) -> std::io::Result<()> {
    writeln!(f, "════ CALL {call_id} ════")?;
    for ev in &buf.events {
        // The full human lines were already appended above; the block keeps
        // a compact ordered summary.
        writeln!(f, "  {} {}", ts_iso(ev.ts_ms), compact(ev))?;
    }
    if buf.truncated {
        writeln!(f, "  ... (buffer truncated at {MAX_EVENTS_PER_CALL} events)")?;
    }
    if let EventKind::CdrWritten { record } = &cdr.kind {
        let media = record.get("media");
        writeln!(f, "  cdr: id={} disposition={} talk_secs={} media={}",
            record.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
            serde_json::to_string(record.get("disposition").unwrap_or(&serde_json::Value::Null)).unwrap_or_default(),
            record.get("talk_secs").and_then(|v| v.as_u64()).unwrap_or(0),
            media.map(|m| m.to_string()).unwrap_or_else(|| "null".into()),
        )?;
    }
    writeln!(f, "──── end {call_id} ────")
}

/// Compact one-liner used inside the per-call dump block.
fn compact(ev: &Event) -> String {
    match &ev.kind {
        EventKind::SipRx { bytes, .. } | EventKind::SipTx { bytes, .. } => {
            let first = String::from_utf8_lossy(bytes.split(|&b| b == b'\r').next().unwrap_or(bytes));
            format!("{}", first.trim_end())
        }
        EventKind::RtpRx { ssrc, seq, pt, .. } | EventKind::RtpTx { ssrc, seq, pt, .. } => {
            format!("rtp ssrc={ssrc:#x} seq={seq} pt={pt}")
        }
        _ => fmt_event(ev, false, false)
            .splitn(4, ' ')
            .nth(3)
            .unwrap_or("")
            .to_string(),
    }
}

/// Aggregates the per-leg media totals from a buffered call (used by the
/// dump block and the CLI's media summary logic lives in zrtc; kept here
/// only for the sink's own tests).
pub fn last_stats(events: &[Event], leg: Leg) -> Option<(u64, u64, u64, f64, u64)> {
    events.iter().rev().find_map(|ev| match &ev.kind {
        EventKind::MediaStats { pump_leg: l, rx, tx, lost, jitter_ms, concealed }
        | EventKind::MediaEnd { pump_leg: l, rx, tx, lost, jitter_ms, concealed, .. } if *l == leg => {
            Some((*rx, *tx, *lost, *jitter_ms, *concealed))
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Direction, Peer, Transport};

    fn ev(call: &str, kind: EventKind) -> Event {
        Event { ts_ms: 1_700_000_000_000, call_id: call.into(), trunk: None, direction: Some(Direction::Inbound), leg: Leg::Core, kind }
    }

    #[test]
    fn human_line_shape() {
        let e = ev("c9", EventKind::SipRx {
            peer: Peer { addr: "127.0.0.1:5060".parse().unwrap(), transport: Transport::Udp },
            bytes: b"INVITE sip:1000@zrtc.local SIP/2.0\r\nCall-ID: c9\r\n\r\n".to_vec(),
            plaintext: true,
        });
        let line = fmt_event(&e, true, true);
        assert!(line.starts_with("2023-11-14T22:13:20.000Z cid=c9 leg=core sip-rx"), "{line}");
        assert!(line.contains("INVITE sip:1000@zrtc.local SIP/2.0"), "{line}");
        assert!(line.contains("sdp_bytes=") == false, "no SDP in this message");
    }

    #[test]
    fn cdr_block_dump_and_memory_removal() {
        let dir = std::env::temp_dir().join(format!("observ-trace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let status = Arc::new(StatusShared::default());
        let mut sink = TraceSink::new(dir.clone(), true, true, status.clone());

        sink.on_event(ev("cA", EventKind::B2buaLegUp { side: "A".into(), peer: "127.0.0.1:5060".parse().unwrap(), codec: "PCMU".into() }));
        sink.on_event(ev("cA", EventKind::MediaStart { pump_leg: Leg::A, local: "127.0.0.1:40000".parse().unwrap(), rx_codec: "PCMU".into(), tx_codec: "PCMU".into() }));
        sink.on_event(ev("cA", EventKind::CdrWritten { record: serde_json::json!({"id": "r1", "disposition": "answered", "talk_secs": 2, "media": {"packets_rx": 74}}) }));
        // Call must be gone from memory after CDR.
        assert!(sink.calls.get("cA").is_none());
        // A call without a CDR stays buffered (active).
        sink.on_event(ev("cB", EventKind::Vad { state: "speech_start".into() }));
        assert!(sink.calls.get("cB").is_some());
        sink.flush_files();
        let log = std::fs::read_to_string(sink.log_file).unwrap();
        assert!(log.contains("════ CALL cA ════"), "{log}");
        assert!(log.contains("media={\"packets_rx\":74}"), "{log}");
        assert!(log.contains("cid=cB"), "{log}");
        let jsonl = std::fs::read_to_string(sink.jsonl_file).unwrap();
        assert_eq!(jsonl.lines().count(), 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn last_stats_picks_latest_per_leg() {
        let mk = |rx: u64| ev("c", EventKind::MediaStats { pump_leg: Leg::A, rx, tx: 1, lost: 0, jitter_ms: 1.0, concealed: 0 });
        let events = vec![mk(10), mk(20)];
        assert_eq!(last_stats(&events, Leg::A).map(|(rx, _, _, _, _)| rx), Some(20));
        assert_eq!(last_stats(&events, Leg::B), None);
    }

    #[test]
    fn per_packet_rtp_never_reaches_the_trace() {
        let dir = std::env::temp_dir().join(format!("observ-trace-rtp-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let status = Arc::new(StatusShared::default());
        let mut sink = TraceSink::new(dir.clone(), true, true, status.clone());

        sink.on_event(ev("cR", EventKind::RtpRx {
            src: "127.0.0.1:40000".parse().unwrap(),
            dst: "127.0.0.1:40002".parse().unwrap(),
            pump_leg: Leg::A,
            bytes: vec![0x80, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 0xaa],
            ssrc: 0x01020304,
            seq: 1,
            pt: 0,
        }));
        sink.on_event(ev("cR", EventKind::RtpTx {
            src: "127.0.0.1:40002".parse().unwrap(),
            dst: "127.0.0.1:40000".parse().unwrap(),
            pump_leg: Leg::A,
            bytes: vec![0x80, 0, 0, 2, 0, 0, 0, 161, 1, 2, 3, 4, 0xbb],
            ssrc: 0x01020304,
            seq: 2,
            pt: 0,
        }));
        sink.on_event(ev("cR", EventKind::MediaEnd {
            pump_leg: Leg::A,
            rx: 1,
            tx: 1,
            lost: 0,
            jitter_ms: 0.4,
            concealed: 0,
            talk_ms: 40,
            remote: Some("127.0.0.1:40000".parse().unwrap()),
        }));
        sink.flush_files();

        let log = std::fs::read_to_string(sink.log_file).unwrap();
        assert!(!log.contains("rtp-rx") && !log.contains("rtp-tx"), "{log}");
        assert!(log.contains("media-end"), "{log}");
        assert!(log.contains("remote=127.0.0.1:40000"), "{log}");
        let jsonl = std::fs::read_to_string(sink.jsonl_file).unwrap();
        assert_eq!(jsonl.lines().count(), 1, "only the media-end event: {jsonl}");
        assert!(sink.calls.get("cR").map(|b| b.events.len()) == Some(1));
        std::fs::remove_dir_all(&dir).ok();
    }
}
