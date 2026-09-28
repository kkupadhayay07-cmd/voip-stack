//! Load harness: concurrent UAC call generator with a latency report.
//!
//! Places `calls` total calls (bounded by `concurrency` in flight) through
//! the full daemon pipeline (listener → SBC → proxy → B2BUA → sink →
//! media), measures the per-call INVITE → 200 setup latency and prints a
//! summary (mean / p50 / p95 / p99 / max, calls-per-second, failure
//! breakdown). Pure statistics helpers are unit-tested; the call loop
//! itself is exercised by `demo/soak.sh`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use crate::uac::{self, Transport, UacOpts};

#[derive(Debug, Clone)]
pub struct LoadOpts {
    pub target: SocketAddr,
    pub transport: Transport,
    /// Request-URI / To header for every call.
    pub to: String,
    pub from: String,
    /// Total number of call attempts.
    pub calls: usize,
    /// Maximum calls in flight (fd budget: ~5 sockets per in-flight call
    /// across the two processes — keep well under the ulimit).
    pub concurrency: usize,
    /// Delay between consecutive call launches in ms (0 = launch as slots
    /// free up).
    pub pace_ms: u64,
    /// RTP media duration per call, ms.
    pub rtp_ms: u64,
    /// Post-RTP tail before BYE, ms.
    pub tail_ms: u64,
    /// Per-call overall timeout.
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub ok: bool,
    /// INVITE → 200 in ms (0 when the call failed before the 200).
    pub setup_ms: f64,
    /// Whole call attempt (connect + setup + RTP + BYE) in ms.
    pub total_ms: f64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoadReport {
    pub requested: usize,
    pub answered: usize,
    pub failed: usize,
    pub wall_secs: f64,
    /// Answered calls per wall-clock second.
    pub cps: f64,
    pub setup_mean_ms: f64,
    pub setup_p50_ms: f64,
    pub setup_p95_ms: f64,
    pub setup_p99_ms: f64,
    pub setup_max_ms: f64,
    /// Mean whole-call holding time (connect + setup + RTP + BYE).
    pub total_mean_ms: f64,
    /// Distinct failure reasons with counts, most frequent first (capped).
    pub errors: Vec<(String, usize)>,
}

/// Place the calls and aggregate the report. Launches one tokio task per
/// call, gated by a semaphore so at most `concurrency` run at once; with
/// `pace_ms > 0` launches are additionally throttled.
pub async fn run_load(opts: LoadOpts) -> Result<LoadReport, String> {
    if opts.calls == 0 {
        return Err("no calls requested (--calls 0)".into());
    }
    if opts.concurrency == 0 {
        return Err("concurrency must be at least 1".into());
    }
    let started = Instant::now();
    let sem = Arc::new(Semaphore::new(opts.concurrency));
    let launched = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(opts.calls);
    for _ in 0..opts.calls {
        if opts.pace_ms > 0 {
            tokio::time::sleep(Duration::from_millis(opts.pace_ms)).await;
        }
        // Blocks until an in-flight call finishes when the cap is reached.
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| format!("semaphore: {e}"))?;
        let i = launched.fetch_add(1, Ordering::Relaxed);
        let o = UacOpts {
            target: opts.target,
            transport: opts.transport,
            to: opts.to.clone(),
            from: opts.from.clone(),
            // Globally unique per run: wall-clock start + launch index.
            call_id: format!("load-{}-{i}@zrtc-load", started.elapsed().as_millis()),
            rtp_ms: opts.rtp_ms,
            probe: false,
            timeout: opts.timeout,
            tail_ms: opts.tail_ms,
            tls_identity: None,
        };
        handles.push(tokio::spawn(async move {
            // Held for the whole call: the slot frees when the task ends.
            let _permit = permit;
            let t0 = Instant::now();
            match uac::run_call(o).await {
                Ok(pc) => CallOutcome {
                    ok: true,
                    setup_ms: pc.setup.as_secs_f64() * 1000.0,
                    total_ms: t0.elapsed().as_secs_f64() * 1000.0,
                    error: None,
                },
                Err(e) => CallOutcome {
                    ok: false,
                    setup_ms: 0.0,
                    total_ms: t0.elapsed().as_secs_f64() * 1000.0,
                    error: Some(e),
                },
            }
            // `permit` drops here: the slot frees when the call is done.
        }));
    }
    let mut outcomes = Vec::with_capacity(handles.len());
    for h in handles {
        outcomes.push(h.await.map_err(|e| format!("task join: {e}"))?);
    }
    Ok(aggregate(opts.calls, started.elapsed(), &outcomes))
}

/// Nearest-rank percentile of a sorted slice.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = sorted.len();
    let rank = ((p / 100.0) * n as f64).ceil() as usize;
    let idx = rank.clamp(1, n) - 1;
    sorted[idx]
}

/// Aggregate per-call outcomes into the summary report.
pub(crate) fn aggregate(requested: usize, wall: Duration, outcomes: &[CallOutcome]) -> LoadReport {
    let answered = outcomes.iter().filter(|o| o.ok).count();
    let failed = outcomes.len() - answered;
    let setups: Vec<f64> = outcomes
        .iter()
        .filter(|o| o.ok)
        .map(|o| o.setup_ms)
        .collect();
    let mean = if setups.is_empty() {
        0.0
    } else {
        setups.iter().sum::<f64>() / setups.len() as f64
    };
    let total_mean = if outcomes.is_empty() {
        0.0
    } else {
        outcomes.iter().map(|o| o.total_ms).sum::<f64>() / outcomes.len() as f64
    };
    let mut error_counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in outcomes.iter().filter_map(|o| o.error.as_deref()) {
        *error_counts.entry(e.to_owned()).or_insert(0) += 1;
    }
    let mut errors: Vec<(String, usize)> = error_counts.into_iter().collect();
    errors.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    errors.truncate(5);
    let mut sorted_setups = setups.clone();
    sorted_setups.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let wall_secs = wall.as_secs_f64();
    LoadReport {
        requested,
        answered,
        failed,
        wall_secs,
        cps: if wall_secs > 0.0 {
            answered as f64 / wall_secs
        } else {
            0.0
        },
        setup_mean_ms: mean,
        setup_p50_ms: percentile(&sorted_setups, 50.0),
        setup_p95_ms: percentile(&sorted_setups, 95.0),
        setup_p99_ms: percentile(&sorted_setups, 99.0),
        setup_max_ms: percentile(&sorted_setups, 100.0),
        total_mean_ms: total_mean,
        errors,
    }
}

/// Human-readable multi-line report.
pub fn render(r: &LoadReport, opts: &LoadOpts) -> String {
    let mut out = String::with_capacity(512);
    out.push_str(&format!(
        "load: {} calls, concurrency {}, {} -> {} (rtp {} ms, tail {} ms)\n",
        r.requested,
        opts.concurrency,
        opts.transport.name(),
        opts.target,
        opts.rtp_ms,
        opts.tail_ms
    ));
    out.push_str(&format!(
        "wall {:.2}s — {:.1} answered calls/s\n",
        r.wall_secs, r.cps
    ));
    out.push_str(&format!("answered {}  failed {}\n", r.answered, r.failed));
    out.push_str(&format!(
        "setup ms: mean {:.1}  p50 {:.1}  p95 {:.1}  p99 {:.1}  max {:.1}  (mean call hold {:.0} ms)\n",
        r.setup_mean_ms,
        r.setup_p50_ms,
        r.setup_p95_ms,
        r.setup_p99_ms,
        r.setup_max_ms,
        r.total_mean_ms
    ));
    if r.errors.is_empty() {
        out.push_str("errors: (none)\n");
    } else {
        out.push_str("errors:\n");
        for (msg, n) in &r.errors {
            out.push_str(&format!("  {n}× {msg}\n"));
        }
    }
    out
}

/// Single-line JSON report (hand-built — stable field order, no floats in
/// scientific notation).
pub fn report_json(r: &LoadReport, opts: &LoadOpts) -> String {
    let mut errors = String::from("{");
    for (i, (msg, n)) in r.errors.iter().enumerate() {
        if i > 0 {
            errors.push(',');
        }
        let esc = msg.replace('\\', "\\\\").replace('"', "\\\"");
        errors.push_str(&format!("\"{}\":{}", esc, n));
    }
    errors.push('}');
    format!(
        "{{\"target\":\"{}\",\"transport\":\"{}\",\"calls\":{},\"concurrency\":{},\"rtp_ms\":{},\"tail_ms\":{},\"wall_secs\":{:.3},\"cps\":{:.2},\"answered\":{},\"failed\":{},\"setup_ms\":{{\"mean\":{:.2},\"p50\":{:.2},\"p95\":{:.2},\"p99\":{:.2},\"max\":{:.2}}},\"total_mean_ms\":{:.2},\"errors\":{}}}",
        opts.target,
        opts.transport.name(),
        r.requested,
        opts.concurrency,
        opts.rtp_ms,
        opts.tail_ms,
        r.wall_secs,
        r.cps,
        r.answered,
        r.failed,
        r.setup_mean_ms,
        r.setup_p50_ms,
        r.setup_p95_ms,
        r.setup_p99_ms,
        r.setup_max_ms,
        r.total_mean_ms,
        errors
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(setup_ms: f64, total_ms: f64) -> CallOutcome {
        CallOutcome {
            ok: true,
            setup_ms,
            total_ms,
            error: None,
        }
    }

    fn failed(err: &str) -> CallOutcome {
        CallOutcome {
            ok: false,
            setup_ms: 0.0,
            total_ms: 100.0,
            error: Some(err.to_owned()),
        }
    }

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&v, 50.0), 50.0);
        assert_eq!(percentile(&v, 95.0), 95.0);
        assert_eq!(percentile(&v, 99.0), 99.0);
        assert_eq!(percentile(&v, 100.0), 100.0);
        assert_eq!(percentile(&v, 0.0), 1.0);
        // non-exact ranks round up to the nearest-rank element
        let ten: Vec<f64> = (1..=10).map(f64::from).collect();
        assert_eq!(percentile(&ten, 95.0), 10.0, "ceil(0.95*10)=10 → idx 9");
        assert_eq!(percentile(&ten, 50.0), 5.0, "ceil(0.5*10)=5 → idx 4");
    }

    #[test]
    fn percentile_edge_cases() {
        assert_eq!(percentile(&[], 50.0), 0.0);
        let one = vec![42.5];
        assert_eq!(percentile(&one, 0.0), 42.5);
        assert_eq!(percentile(&one, 99.9), 42.5);
    }

    #[test]
    fn aggregate_counts_and_percentiles() {
        // 90 answered with setups 1..=90 ms, 10 failed with 2 reasons.
        let mut outcomes: Vec<CallOutcome> = (1..=90)
            .map(|ms| ok(f64::from(ms), f64::from(ms) + 500.0))
            .collect();
        for _ in 0..7 {
            outcomes.push(failed("uac timed out after 20s"));
        }
        for _ in 0..3 {
            outcomes.push(failed("INVITE rejected with 486"));
        }
        let r = aggregate(100, Duration::from_secs(10), &outcomes);
        assert_eq!(r.answered, 90);
        assert_eq!(r.failed, 10);
        assert_eq!(r.cps, 9.0);
        assert_eq!(r.setup_p50_ms, 45.0);
        assert_eq!(r.setup_p95_ms, 86.0, "ceil(0.95*90)=86");
        assert_eq!(r.setup_p99_ms, 90.0);
        assert_eq!(r.setup_max_ms, 90.0);
        assert_eq!(r.setup_mean_ms, 45.5);
        // mean holding time: 90 answered at setup+500 ms, 10 failed at 100 ms
        let want_total = (45.5 * 90.0 + 500.0 * 90.0 + 100.0 * 10.0) / 100.0;
        assert!((r.total_mean_ms - want_total).abs() < 1e-9);
        // errors sorted by count desc, capped at 5
        assert_eq!(
            r.errors,
            vec![
                ("uac timed out after 20s".to_owned(), 7),
                ("INVITE rejected with 486".to_owned(), 3)
            ]
        );
    }

    #[test]
    fn aggregate_empty_report_stays_zero() {
        let r = aggregate(0, Duration::from_secs(1), &[]);
        assert_eq!(
            r,
            LoadReport {
                requested: 0,
                answered: 0,
                failed: 0,
                wall_secs: 1.0,
                cps: 0.0,
                setup_mean_ms: 0.0,
                setup_p50_ms: 0.0,
                setup_p95_ms: 0.0,
                setup_p99_ms: 0.0,
                setup_max_ms: 0.0,
                total_mean_ms: 0.0,
                errors: vec![],
            }
        );
    }

    #[test]
    fn json_report_is_valid_json() {
        let outcomes = vec![ok(12.5, 800.0), ok(20.0, 810.0), failed("boom")];
        let r = aggregate(3, Duration::from_millis(1500), &outcomes);
        let opts = LoadOpts {
            target: "127.0.0.1:5060".parse().unwrap(),
            transport: Transport::Udp,
            to: "sip:1000@zrtc.local".into(),
            from: "sip:demo@zrtc.local".into(),
            calls: 3,
            concurrency: 2,
            pace_ms: 0,
            rtp_ms: 500,
            tail_ms: 150,
            timeout: Duration::from_secs(20),
        };
        let j = report_json(&r, &opts);
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid JSON");
        assert_eq!(v["calls"], 3);
        assert_eq!(v["concurrency"], 2);
        assert_eq!(v["answered"], 2);
        assert_eq!(v["failed"], 1);
        assert_eq!(
            v["setup_ms"]["p50"], 12.5,
            "nearest-rank p50 of [12.5, 20.0]"
        );
        assert_eq!(v["errors"]["boom"], 1);
        // render includes the failure breakdown
        let human = render(&r, &opts);
        assert!(human.contains("answered 2  failed 1"));
        assert!(human.contains("1× boom"));
    }

    #[test]
    fn run_load_rejects_zero_args() {
        // run_load's validation path is synchronous up to the first await;
        // exercise it inside a tiny runtime.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let base = LoadOpts {
            target: "127.0.0.1:5060".parse().unwrap(),
            transport: Transport::Udp,
            to: "sip:1000@zrtc.local".into(),
            from: "sip:demo@zrtc.local".into(),
            calls: 0,
            concurrency: 1,
            pace_ms: 0,
            rtp_ms: 1,
            tail_ms: 1,
            timeout: Duration::from_secs(1),
        };
        assert!(rt.block_on(run_load(base.clone())).is_err());
        let zero_conc = LoadOpts {
            calls: 1,
            concurrency: 0,
            ..base
        };
        assert!(rt.block_on(run_load(zero_conc)).is_err());
    }
}
