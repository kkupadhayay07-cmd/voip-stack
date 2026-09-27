//! Read-only observability CLI: `zrtc trace | calls | diag | capture | metrics`.
//!
//! Everything reads the artifacts the daemon writes under `[observ].log_dir`:
//! `trace-YYYYMMDD.jsonl` (events), `sip.pcap`/`rtp.pcap` (raw frames) and
//! `status.json` (writer counters). No daemon connection required.

use crate::config::Config;
use observ::event::{Event, EventKind};
use observ::pcap_sink::{self, PcapWriter, RawFrame};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Log dir resolution order: --config's [observ].log_dir, $ZRTC_LOG_DIR,
/// /var/log/zrtc when it exists, ./log.
pub fn resolve_log_dir(cfg: Option<&Config>) -> PathBuf {
    if let Some(cfg) = cfg {
        return PathBuf::from(&cfg.observ.log_dir);
    }
    if let Ok(dir) = std::env::var("ZRTC_LOG_DIR") {
        return PathBuf::from(dir);
    }
    let var = PathBuf::from("/var/log/zrtc");
    if var.is_dir() {
        return var;
    }
    PathBuf::from("log")
}

pub fn run(cmd: &str, args: &[String], log_dir: &Path) -> Result<(), String> {
    // Read-only commands are often piped (e.g. `zrtc diag ... | head`);
    // a closed stdout must exit quietly instead of panicking on EPIPE.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.to_string().contains("Broken pipe") {
            std::process::exit(0);
        }
        prev(info);
    }));
    match cmd {
        "trace" => trace_cmd(args, log_dir),
        "calls" => calls_cmd(args, log_dir),
        "diag" => diag_cmd(args, log_dir),
        "capture" => capture_cmd(args, log_dir),
        "metrics" => metrics_cmd(args, log_dir),
        other => Err(format!("unknown observ command '{other}'")),
    }
}

// ------------------------------------------------------------- helpers ----

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// `--since 5m` → unix millis cutoff.
fn since_ms(args: &[String]) -> Option<i64> {
    let v = flag_value(args, "--since")?;
    let (num, unit) = v.split_at(v.len() - 1);
    let n: i64 = num.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => return None,
    };
    Some(observ::event::now_ms() - secs * 1000)
}

/// All jsonl event files, oldest first.
fn jsonl_files(log_dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(log_dir)
        .ok()
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.file_name()
                        .map(|f| {
                            let f = f.to_string_lossy();
                            f.starts_with("trace-") && f.ends_with(".jsonl")
                        })
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

fn load_events(log_dir: &Path) -> Result<Vec<Event>, String> {
    let files = jsonl_files(log_dir);
    if files.is_empty() {
        return Err(format!(
            "no trace-*.jsonl under {} (is the daemon running with [observ] enabled?)",
            log_dir.display()
        ));
    }
    let mut events = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f)
            .map_err(|e| format!("read {}: {e}", f.display()))?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Event>(line) {
                Ok(ev) => events.push(ev),
                Err(_) => continue, // tolerate torn tails
            }
        }
    }
    events.sort_by_key(|e| e.ts_ms);
    Ok(events)
}

fn ts_hms(ms: i64) -> String {
    observ::event::ts_iso(ms)
}

fn human_line(ev: &Event) -> String {
    observ::trace_sink::fmt_event(ev, true, true)
}

// --------------------------------------------------------------- trace ----

fn trace_cmd(args: &[String], log_dir: &Path) -> Result<(), String> {
    let call_id = args
        .iter()
        .find(|a| !a.starts_with('-') && a.as_str() != "trace")
        .cloned();
    let json = has_flag(args, "--json");
    let follow = has_flag(args, "--follow");
    let cutoff = since_ms(args);

    let print_from = |files: &[PathBuf]| -> Result<usize, String> {
        let mut n = 0usize;
        for f in files {
            let text = std::fs::read_to_string(f).map_err(|e| e.to_string())?;
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let ev: Event = match serde_json::from_str(line) {
                    Ok(ev) => ev,
                    Err(_) => continue,
                };
                if let Some(c) = cutoff {
                    if ev.ts_ms < c {
                        continue;
                    }
                }
                if let Some(id) = &call_id {
                    if &ev.call_id != id {
                        continue;
                    }
                }
                if json {
                    println!("{line}");
                } else {
                    println!("{}", human_line(&ev));
                }
                n += 1;
            }
        }
        Ok(n)
    };

    let files = jsonl_files(log_dir);
    if files.is_empty() {
        return Err(format!(
            "no trace-*.jsonl under {} (daemon observability disabled?)",
            log_dir.display()
        ));
    }
    let printed = print_from(&files)?;
    if follow {
        // Tail: poll the newest file for growth until interrupted.
        let newest = files.last().unwrap().clone();
        let mut len = std::fs::metadata(&newest).map(|m| m.len()).unwrap_or(0);
        eprintln!("(following {newest:?} — ctrl-c to stop)");
        loop {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let new_len = std::fs::metadata(&newest).map(|m| m.len()).unwrap_or(len);
            if new_len > len {
                if let Ok(text) = std::fs::read(&newest) {
                    let chunk = &text[len as usize..];
                    for line in String::from_utf8_lossy(chunk).lines() {
                        if line.trim().is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<Event>(line) {
                            Ok(ev) => {
                                if let Some(id) = &call_id {
                                    if &ev.call_id != id {
                                        continue;
                                    }
                                }
                                if json {
                                    println!("{line}");
                                } else {
                                    println!("{}", human_line(&ev));
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
                len = new_len;
                let _ = printed;
            }
        }
    }
    if printed == 0 {
        eprintln!("(no matching events)");
    }
    Ok(())
}

// --------------------------------------------------------------- calls ----

struct CallIndex {
    events: Vec<Event>,
    cdr: Option<serde_json::Value>,
    first_ms: i64,
    last_ms: i64,
}

fn index_calls(events: Vec<Event>) -> Vec<(String, CallIndex)> {
    let mut map: HashMap<String, CallIndex> = HashMap::new();
    for ev in events {
        if ev.call_id.is_empty() {
            continue;
        }
        let entry = map.entry(ev.call_id.clone()).or_insert_with(|| CallIndex {
            events: Vec::new(),
            cdr: None,
            first_ms: ev.ts_ms,
            last_ms: ev.ts_ms,
        });
        entry.last_ms = entry.last_ms.max(ev.ts_ms);
        if let EventKind::CdrWritten { record } = &ev.kind {
            entry.cdr = Some(record.clone());
        }
        entry.events.push(ev);
    }
    let mut calls: Vec<(String, CallIndex)> = map.into_iter().collect();
    calls.sort_by_key(|(_, c)| c.first_ms);
    calls
}

fn calls_cmd(args: &[String], log_dir: &Path) -> Result<(), String> {
    // `zrtc calls show CALL_ID`
    if let Some(i) = args.iter().position(|a| a == "show") {
        let id = args
            .get(i + 1)
            .ok_or("usage: zrtc calls show CALL_ID")?;
        return calls_show(id, log_dir);
    }
    let recent: Option<usize> = args
        .iter()
        .position(|a| a == "--recent")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            if has_flag(args, "--recent") {
                Some(10)
            } else {
                None
            }
        });
    let active = has_flag(args, "--active");

    let events = load_events(log_dir)?;
    let calls = index_calls(events);
    println!(
        "{:<38} {:<9} {:<12} {:<8} {:<24}",
        "CALL-ID", "DIR", "DISPOSITION", "SECS", "LAST ACTIVITY"
    );
    let mut shown = 0usize;
    for (id, c) in calls.iter().rev() {
        let finished = c.cdr.is_some();
        if active && finished {
            continue;
        }
        if !active && !finished && recent.is_none() {
            continue;
        }
        if let Some(n) = recent {
            if !finished || shown >= n {
                continue;
            }
        }
        let (dir, disp, secs) = c.cdr.as_ref().map_or(
            ("—".to_string(), "active".to_string(), "—".to_string()),
            |r| {
                (
                    r.get("direction").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                    r.get("disposition").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                    r.get("talk_secs").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
                )
            },
        );
        println!("{id:<38} {dir:<9} {disp:<12} {secs:<8} {}", ts_hms(c.last_ms));
        shown += 1;
        if active || recent.is_none() {
            if shown >= 25 {
                break;
            }
        }
    }
    if shown == 0 {
        println!("(no calls match)");
    }
    Ok(())
}

/// `zrtc calls show CALL_ID`
pub fn calls_show(call_id: &str, log_dir: &Path) -> Result<(), String> {
    let events = load_events(log_dir)?;
    let calls = index_calls(events);
    let (_, c) = calls
        .into_iter()
        .find(|(id, _)| id == call_id)
        .ok_or_else(|| format!("no events for call {call_id}"))?;
    for ev in &c.events {
        println!("{}", human_line(ev));
    }
    Ok(())
}

// ---------------------------------------------------------------- diag ----

fn first_ts(events: &[Event], pred: impl Fn(&Event) -> bool) -> Option<i64> {
    events.iter().find(|e| pred(e)).map(|e| e.ts_ms)
}

fn diag_cmd(args: &[String], log_dir: &Path) -> Result<(), String> {
    let Some(call_id) = flag_value(args, "--call-id") else {
        return Err("usage: zrtc diag --call-id <ID> [--config <path>]".into());
    };
    let events = load_events(log_dir)?;
    let calls = index_calls(events);
    let (_, c) = calls
        .iter()
        .find(|(id, _)| id == &call_id)
        .ok_or_else(|| format!("no events for call {call_id} under {}", log_dir.display()))?;

    // 1. Call header.
    println!("═══ CALL DIAGNOSTIC: {call_id} ═══");
    match &c.cdr {
        Some(r) => {
            println!(
                "  from:          {}",
                r.get("from_uri").and_then(|v| v.as_str()).unwrap_or("-")
            );
            println!(
                "  to:            {}",
                r.get("to_uri").and_then(|v| v.as_str()).unwrap_or("-")
            );
            println!(
                "  direction:     {}",
                r.get("direction").and_then(|v| v.as_str()).unwrap_or("-")
            );
            println!(
                "  codec:         {}",
                r.get("media")
                    .and_then(|m| m.get("codec"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
            );
            println!(
                "  disposition:   {}",
                r.get("disposition").and_then(|v| v.as_str()).unwrap_or("-")
            );
            println!(
                "  duration:      {}s (talk)",
                r.get("talk_secs").and_then(|v| v.as_u64()).unwrap_or(0)
            );
        }
        None => {
            println!("  (no CDR yet — call still active or not finalized)");
            let inv = c.events.iter().find(|e| {
                matches!(&e.kind, EventKind::SipRx { bytes, .. } if bytes.starts_with(b"INVITE"))
            });
            if let Some(inv) = inv {
                println!("  first seen:    {}", ts_hms(inv.ts_ms));
            }
        }
    }

    // 2. Full ordered trace block.
    println!("\n── trace ({}) ──", c.events.len());
    for ev in &c.events {
        println!("  {}", human_line(ev));
    }

    // 3. Media summary.
    println!("\n── media summary ──");
    let mut printed_leg: Vec<observ::event::Leg> = Vec::new();
    for ev in c.events.iter().rev() {
        if let EventKind::MediaEnd { pump_leg: leg, rx, tx, lost, jitter_ms, plc, talk_ms } = &ev.kind {
                if !printed_leg.contains(leg) {
                    printed_leg.push(*leg);
                    println!(
                        "  leg {}: rx={rx} tx={tx} lost={lost} jitter={jitter_ms:.1}ms plc={plc} talk_ms={talk_ms}",
                        leg.as_str()
                    );
                }
        }
    }
    if let Some(r) = &c.cdr {
        if let Some(m) = r.get("media") {
            println!("  cdr media:     {m}");
        }
    }
    if printed_leg.is_empty() {
        println!("  (no media events)");
    }

    // 4. Pipeline timing.
    println!("\n── pipeline timing ──");
    let t_inv = first_ts(&c.events, |e| {
        matches!(&e.kind, EventKind::SipRx { bytes, .. } if bytes.starts_with(b"INVITE"))
    });
    let t_sbc = first_ts(&c.events, |e| matches!(&e.kind, EventKind::SbcDecision { .. }));
    let t_fork = first_ts(&c.events, |e| matches!(&e.kind, EventKind::ProxyFork { .. }));
    let t_leg = first_ts(&c.events, |e| matches!(&e.kind, EventKind::B2buaLegUp { .. }));
    let t_media = first_ts(&c.events, |e| matches!(&e.kind, EventKind::MediaStart { .. }));
    let delta = |base: Option<i64>, t: Option<i64>, label: &str| {
        if let (Some(b), Some(t)) = (base, t) {
            println!("  {label:<18} +{}ms", t - b);
        } else {
            println!("  {label:<18} n/a");
        }
    };
    if let Some(t) = t_inv {
        println!("  INVITE at        {}", ts_hms(t));
    }
    delta(t_inv, t_sbc, "sbc decision");
    delta(t_inv, t_fork, "proxy fork");
    delta(t_inv, t_leg, "b2bua setup");
    delta(t_inv, t_media, "media setup");

    // 5. CDR reference.
    println!("\n── cdr reference ──");
    match &c.cdr {
        Some(r) => println!(
            "  id={} (GET /cdrs on the api port; written {})",
            r.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
            r.get("finished_at").and_then(|v| v.as_str()).unwrap_or("-")
        ),
        None => println!("  none (call not finalized)"),
    }

    // 6. Suggested Wireshark filter.
    let mut rtp_ports: BTreeSet<u16> = BTreeSet::new();
    for ev in &c.events {
        match &ev.kind {
            EventKind::RtpRx { src, dst, .. } | EventKind::RtpTx { src, dst, .. } => {
                rtp_ports.insert(src.port());
                rtp_ports.insert(dst.port());
            }
            _ => {}
        }
    }
    println!("\n── wireshark filter ──");
    let mut filter = format!("sip.Call-ID == \"{call_id}\"");
    for p in &rtp_ports {
        filter.push_str(&format!(" || udp.port == {p}"));
    }
    println!("  {filter}");

    // 7. File paths.
    println!("\n── capture files ──");
    println!("  sip pcap: {}", log_dir.join("sip.pcap").display());
    println!("  rtp pcap: {}", log_dir.join("rtp.pcap").display());
    println!("  dump:     zrtc capture dump --call-id {call_id} --out FILE");
    Ok(())
}

// ------------------------------------------------------------- capture ----

fn capture_cmd(args: &[String], log_dir: &Path) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("status");
    match sub {
        "status" => {
            let status_path = log_dir.join("status.json");
            println!("log dir: {}", log_dir.display());
            for f in ["sip.pcap", "rtp.pcap", "status.json"] {
                let p = log_dir.join(f);
                let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                println!("  {f:<12} {:>10} bytes{}", size, if size == 0 { "  (missing)" } else { "" });
            }
            for f in jsonl_files(log_dir) {
                let size = std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
                println!(
                    "  {:<12} {:>10} bytes",
                    f.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
                    size
                );
            }
            if let Ok(text) = std::fs::read_to_string(&status_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    println!(
                        "  bus: published-so-far trace_events={} trace_lagged={} pcap_stopped={}",
                        v.get("trace_events").and_then(|x| x.as_u64()).unwrap_or(0),
                        v.get("trace_lagged").and_then(|x| x.as_u64()).unwrap_or(0),
                        v.get("pcap_stopped").and_then(|x| x.as_bool()).unwrap_or(false),
                    );
                }
            }
            Ok(())
        }
        "dump" => {
            if !has_flag(args, "--out") {
                return Err("usage: zrtc capture dump --call-id ID --out FILE [--type sip|rtp|both]".into());
            }
            let call_id = flag_value(args, "--call-id")
                .ok_or("missing --call-id <ID>")?;
            let out = flag_value(args, "--out").unwrap();
            let kind = flag_value(args, "--type").unwrap_or_else(|| "both".into());
            let events = load_events(log_dir)?;

            // RTP endpoints for this call (from the trace stream).
            let mut endpoints: BTreeSet<(u32, u16, u32, u16)> = BTreeSet::new();
            for ev in &events {
                if ev.call_id != call_id {
                    continue;
                }
                match &ev.kind {
                    EventKind::RtpRx { src, dst, .. } | EventKind::RtpTx { src, dst, .. } => {
                        if let (Some(s), Some(d)) = (parse_v4(*src), parse_v4(*dst)) {
                            endpoints.insert((s, src.port(), d, dst.port()));
                        }
                    }
                    _ => {}
                }
            }

            let mut writer = PcapWriter::create(
                Path::new(&out),
                512 * 1024 * 1024,
            )
            .map_err(|e| format!("create {out}: {e}"))?;
            let mut n_sip = 0usize;
            let mut n_rtp = 0usize;
            let needle = call_id.as_bytes();

            let write_matching = |w: &mut PcapWriter,
                                  file: &Path,
                                  sip: bool,
                                  n_sip: &mut usize,
                                  n_rtp: &mut usize|
             -> Result<(), String> {
                let frames: Vec<RawFrame> = pcap_sink::read_frames(file)
                    .map_err(|e| format!("read {}: {e}", file.display()))?;
                for f in frames {
                    let take = if sip {
                        find_sub(&f.payload, needle)
                    } else {
                        match (parse_v4(f.src), parse_v4(f.dst)) {
                            (Some(s), Some(d)) => endpoints.contains(&(s, f.src.port(), d, f.dst.port())),
                            _ => false,
                        }
                    };
                    if take {
                        let _ = w.write_udp(f.ts_us, f.src, f.dst, &f.payload);
                        if sip {
                            *n_sip += 1;
                        } else {
                            *n_rtp += 1;
                        }
                    }
                }
                Ok(())
            };

            if kind == "sip" || kind == "both" {
                write_matching(&mut writer, &log_dir.join("sip.pcap"), true, &mut n_sip, &mut n_rtp)?;
            }
            if kind == "rtp" || kind == "both" {
                write_matching(&mut writer, &log_dir.join("rtp.pcap"), false, &mut n_sip, &mut n_rtp)?;
            }
            writer.flush();
            let (packets, bytes) = writer.stats();
            println!(
                "wrote {out}: {packets} packets ({bytes} bytes) — sip={n_sip} rtp={n_rtp} (call {call_id})"
            );
            if packets == 0 {
                return Err("no matching frames (was the call captured? try --type sip)".into());
            }
            Ok(())
        }
        other => Err(format!("unknown capture subcommand '{other}' (status|dump)")),
    }
}

fn find_sub(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len().max(1)).any(|w| w == needle)
}

fn parse_v4(a: SocketAddr) -> Option<u32> {
    match a {
        SocketAddr::V4(v4) => Some(u32::from(*v4.ip())),
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().map(u32::from),
    }
}

// ------------------------------------------------------------- metrics ----

fn metrics_cmd(args: &[String], log_dir: &Path) -> Result<(), String> {
    let call_id = flag_value(args, "--call-id");
    let cutoff = since_ms(args);
    let events = load_events(log_dir)?;
    let mut calls: BTreeSet<String> = BTreeSet::new();
    let (mut rx, mut tx, mut lost, mut plc) = (0u64, 0u64, 0u64, 0u64);
    let mut jitter_sum = 0.0f64;
    let mut jitter_n = 0usize;
    let mut saw_media = false;

    for ev in &events {
        if let Some(c) = cutoff {
            if ev.ts_ms < c {
                continue;
            }
        }
        if let Some(id) = &call_id {
            if &ev.call_id != id {
                continue;
            }
        }
        match &ev.kind {
            EventKind::MediaEnd { pump_leg: _, rx: r, tx: t, lost: l, jitter_ms: j, plc: p, .. } => {
                saw_media = true;
                calls.insert(ev.call_id.clone());
                rx += r;
                tx += t;
                lost += l;
                plc += p;
                if *j > 0.0 {
                    jitter_sum += j;
                    jitter_n += 1;
                }
            }
            EventKind::MediaStats { .. } => {
                saw_media = true;
            }
            _ => {}
        }
    }
    let scope = call_id.as_deref().unwrap_or("all calls");
    println!("metrics for {scope}{}:", cutoff.map(|_| " (since window)").unwrap_or(""));
    if calls.is_empty() && !saw_media {
        println!("  (no media events found)");
        return Ok(());
    }
    println!("  calls with media: {}", calls.len());
    println!("  packets rx:  {rx}");
    println!("  packets tx:  {tx}");
    println!("  packets lost: {lost}");
    if jitter_n > 0 {
        println!("  avg jitter:  {:.1} ms", jitter_sum / jitter_n as f64);
    }
    println!("  plc events:  {plc}");
    if lost + rx > 0 {
        println!("  loss rate:   {:.2}%", 100.0 * lost as f64 / (lost + rx) as f64);
    }
    Ok(())
}
