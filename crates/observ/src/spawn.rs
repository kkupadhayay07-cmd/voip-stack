//! Wires the bus to the sinks: `spawn_writers` starts the three writer
//! tasks (sip pcap, rtp pcap, trace+status).

use crate::bus::EventBus;
use crate::event::{Event, EventKind};
use crate::pcap_sink::PcapWriter;
use crate::trace_sink::{StatusShared, TraceSink};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Everything the writers need, derived from the `[observ]` config by the
/// caller (keeps this crate free of the zrtc config types).
#[derive(Debug, Clone)]
pub struct WriterConfig {
    pub log_dir: PathBuf,
    pub pcap_enabled: bool,
    pub sip_file: String,
    pub rtp_file: String,
    pub include_payload: bool,
    pub max_file_mb: u64,
    pub trace_enabled: bool,
    pub include_sdp: bool,
    pub include_sip_bodies: bool,
    pub flush_interval_ms: u64,
}

/// Spawns the 3 writer tasks on the tokio runtime. Returns the handles so
/// the daemon can shut them down implicitly on exit.
pub fn spawn_writers(bus: Arc<EventBus>, cfg: WriterConfig) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    if let Err(e) = std::fs::create_dir_all(&cfg.log_dir) {
        tracing::error!(
            dir = %cfg.log_dir.display(),
            "observ: cannot create log_dir ({e}); pcap and trace writers disabled"
        );
        return handles;
    }
    let status = Arc::new(StatusShared::default());

    if cfg.pcap_enabled {
        // ---- task 1: sip.pcap ------------------------------------------------
        {
            let (path, max) = pcap_paths(&cfg, &cfg.sip_file);
            match PcapWriter::create(&path, max) {
                Ok(mut w) => {
                    let rx = bus.subscribe();
                    let status = status.clone();
                    let include_payload = cfg.include_payload;
                    handles.push(tokio::spawn(async move {
                        pcap_task(rx, &mut w, sip_payload_len, include_payload, &status, true).await;
                    }));
                }
                Err(e) => tracing::error!("observ: cannot open {}: {e}", path.display()),
            }
        }
        // ---- task 2: rtp.pcap ------------------------------------------------
        {
            let (path, max) = pcap_paths(&cfg, &cfg.rtp_file);
            match PcapWriter::create(&path, max) {
                Ok(mut w) => {
                    let rx = bus.subscribe();
                    let status = status.clone();
                    let include_payload = cfg.include_payload;
                    handles.push(tokio::spawn(async move {
                        pcap_task(rx, &mut w, rtp_payload_len, include_payload, &status, false).await;
                    }));
                }
                Err(e) => tracing::error!("observ: cannot open {}: {e}", path.display()),
            }
        }
    }

    if cfg.trace_enabled {
        // ---- task 3: trace-YYYYMMDD.log/.jsonl + status.json ------------------
        let sink = TraceSink::new(
            cfg.log_dir.clone(),
            cfg.include_sdp,
            cfg.include_sip_bodies,
            status,
        );
        let rx = bus.subscribe();
        handles.push(tokio::spawn(async move {
            sink.run(rx, cfg.flush_interval_ms).await;
        }));
    }

    handles
}

fn pcap_paths(cfg: &WriterConfig, file: &str) -> (PathBuf, u64) {
    (
        cfg.log_dir.join(file),
        cfg.max_file_mb.saturating_mul(1024 * 1024),
    )
}

/// Payload selector: `include_payload=false` keeps headers only (SIP: the
/// header block; RTP: the 12-byte fixed header).
fn sip_payload_len(ev: &Event) -> usize {
    let (EventKind::SipRx { bytes, .. } | EventKind::SipTx { bytes, .. }) = &ev.kind else {
        return 0;
    };
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(bytes.len())
}

fn rtp_payload_len(ev: &Event) -> usize {
    let (EventKind::RtpRx { bytes, .. } | EventKind::RtpTx { bytes, .. }) = &ev.kind else {
        return 0;
    };
    let header = 12 + 4 * (bytes.first().copied().unwrap_or(0) as usize & 0x0f);
    header.min(bytes.len())
}

async fn pcap_task(
    mut rx: broadcast::Receiver<Event>,
    w: &mut PcapWriter,
    payload_len: fn(&Event) -> usize,
    include_payload: bool,
    status: &StatusShared,
    sip: bool,
) {
    loop {
        match rx.recv().await {
            Ok(ev) => {
                let (src, dst, bytes, ts_ms) = match &ev.kind {
                    EventKind::SipRx { peer, bytes, .. } if sip => (peer.addr, peer.addr, bytes, ev.ts_ms),
                    EventKind::SipTx { peer, bytes, .. } if sip => (peer.addr, peer.addr, bytes, ev.ts_ms),
                    EventKind::RtpRx { src, dst, bytes, .. } if !sip => (*src, *dst, bytes, ev.ts_ms),
                    EventKind::RtpTx { src, dst, bytes, .. } if !sip => (*src, *dst, bytes, ev.ts_ms),
                    _ => continue,
                };
                let kept = if include_payload {
                    bytes.len()
                } else {
                    payload_len(&ev)
                };
                // Synthetic capture: UDP has no true dst for SIP (via the
                // shared socket both directions appear peer-addr↔local-addr);
                // we record peer↔peer as seen by the tapper so Wireshark's
                // SIP/RTP dissection works on the payload alone.
                let _ = w.write_udp(ts_ms * 1_000, src, dst, &bytes[..kept]);
                w.flush();
                if sip {
                    status.sip_packets.fetch_add(1, Ordering::Relaxed);
                    status.sip_bytes.fetch_add(kept as u64, Ordering::Relaxed);
                } else {
                    status.rtp_packets.fetch_add(1, Ordering::Relaxed);
                    status.rtp_bytes.fetch_add(kept as u64, Ordering::Relaxed);
                }
                if w.stopped {
                    status.pcap_stopped.store(true, Ordering::Relaxed);
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(n, "pcap writer lagged; packets dropped from capture");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Peer, Transport};

    #[tokio::test]
    async fn writers_split_sip_and_rtp_files() {
        let dir = std::env::temp_dir().join(format!("observ-spawn-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let bus = Arc::new(EventBus::new(64));
        crate::bus::install_global(bus.clone());
        let cfg = WriterConfig {
            log_dir: dir.clone(),
            pcap_enabled: true,
            sip_file: "sip.pcap".into(),
            rtp_file: "rtp.pcap".into(),
            include_payload: true,
            max_file_mb: 8,
            trace_enabled: true,
            include_sdp: true,
            include_sip_bodies: true,
            flush_interval_ms: 10,
        };
        let hs = spawn_writers(bus.clone(), cfg);
        assert_eq!(hs.len(), 3, "sip pcap + rtp pcap + trace");

        bus.publish(Event::now("cx", EventKind::SipRx {
            peer: Peer { addr: "127.0.0.1:5060".parse().unwrap(), transport: Transport::Udp },
            bytes: b"INVITE sip:1000@x SIP/2.0\r\nCall-ID: cx\r\n\r\n".to_vec(),
            plaintext: true,
        }));
        bus.publish(Event::now("cx", EventKind::RtpRx {
            src: "127.0.0.1:40000".parse().unwrap(),
            dst: "127.0.0.1:40002".parse().unwrap(),
            pump_leg: crate::event::Leg::A,
            bytes: vec![0x80, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 0xaa],
            ssrc: 0x01020304,
            seq: 1,
            pt: 0,
        }));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let sip = crate::pcap_sink::read_frames(&dir.join("sip.pcap")).unwrap();
        assert_eq!(sip.len(), 1);
        assert!(sip[0].payload.starts_with(b"INVITE"));
        let rtp = crate::pcap_sink::read_frames(&dir.join("rtp.pcap")).unwrap();
        assert_eq!(rtp.len(), 1);
        assert_eq!(rtp[0].payload.len(), 13);
        // trace jsonl only got the SIP event; the RTP packet went to the
        // rtp.pcap writer alone (per-packet media never reaches the trace)
        let jsonl: String = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("trace-")
                && e.file_name().to_string_lossy().ends_with(".jsonl"))
            .map(|e| std::fs::read_to_string(e.path()).unwrap())
            .expect("trace jsonl exists");
        assert_eq!(jsonl.lines().count(), 1, "RTP packets must stay out of the trace: {jsonl}");
        assert!(jsonl.contains("\"kind\":\"sip_rx\""), "{jsonl}");
        let files: Vec<_> = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        assert!(files.iter().any(|f| f.starts_with("trace-") && f.ends_with(".jsonl")), "{files:?}");
        assert!(files.iter().any(|f| f == "status.json"), "{files:?}");
    }
}
