//! zrtc — one daemon wiring the native SIP + media library stack into a
//! runnable voice service.
//!
//! Usage:
//!   zrtc [--config <path>]     run the daemon (config also via $ZRTC_CONFIG)
//!   zrtc daemon [--config <path>]
//!   zrtc uac [options]         in-repo SIP client (demo calls / probes)
//!   zrtc call <e164> [options] place one call out the configured [trunk]
//!
//! UAC options:
//!   --target HOST:PORT     listener address          (default 127.0.0.1:5060)
//!   --transport NAME       udp | tcp | tls | wss     (default udp)
//!   --to URI               request-URI / To          (default sip:1000@zrtc.local)
//!   --from URI             From URI                  (default sip:demo@zrtc.local)
//!   --call-id ID           explicit Call-ID
//!   --rtp-ms N             RTP duration in ms        (default 1000)
//!   --probe                OPTIONS keepalive instead of a call
//!   --timeout-secs N       overall timeout           (default 15)
//!
//! Call options:
//!   --config PATH          config with the [trunk] section
//!   --rtp-ms N             RTP duration in ms        (default 1000)
//!   --timeout-secs N       overall timeout           (default 15)

mod auth;
mod cdr_task;
mod cli_observ;
mod config;
mod core;
mod daemon;
mod sink;
mod tls;
mod transport;
mod trunk;
mod uac;

use config::Config;
use std::time::Duration;
use uac::{Transport, UacOpts};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(args) {
        eprintln!("zrtc: {e}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut it = args.iter();
    let first = it.next().map(String::as_str).unwrap_or("daemon");

    match first {
        "daemon" => {
            let cfg = load_config(&args[1..])?;
            init_tracing(&cfg.daemon.log_level, Some(&cfg.observ.log_level));
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("runtime: {e}"))?;
            rt.block_on(daemon::run(cfg))
        }
        "--config" => {
            // `zrtc --config path` == `zrtc daemon --config path`
            let cfg = load_config(&args)?;
            init_tracing(&cfg.daemon.log_level, Some(&cfg.observ.log_level));
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("runtime: {e}"))?;
            rt.block_on(daemon::run(cfg))
        }
        "uac" => {
            let opts = parse_uac(&args[1..])?;
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .try_init();
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("runtime: {e}"))?;
            rt.block_on(uac::run(opts))
        }
        "call" => {
            // zrtc call <e164> [--config path] [--rtp-ms N] [--timeout-secs N]
            let rest = &args[1..];
            let e164 = rest
                .iter()
                .find(|a| !a.starts_with('-'))
                .ok_or("usage: zrtc call <e164> [--config path]")?
                .clone();
            let cfg = load_config(rest)?;
            init_tracing(&cfg.daemon.log_level, Some(&cfg.observ.log_level));
            let mut cfg = cfg;
            cfg.apply_trunk_env();
            let rtp_ms: u64 = flag_or(rest, "--rtp-ms", "1000")
                .parse()
                .map_err(|_| "bad --rtp-ms")?;
            let secs: u64 = flag_or(rest, "--timeout-secs", "15")
                .parse()
                .map_err(|_| "bad --timeout-secs")?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("runtime: {e}"))?;
            rt.block_on(async move {
                tokio::time::timeout(
                    std::time::Duration::from_secs(secs),
                    trunk::call::run(&cfg, &e164, rtp_ms),
                )
                .await
                .map_err(|_| format!("trunk call timed out after {secs}s"))?
            })
        }
        other if matches!(other, "trace" | "calls" | "diag" | "capture" | "metrics") => {
            let cfg = load_config_optional(&args[1..]);
            let log_dir = cli_observ::resolve_log_dir(cfg.as_ref());
            cli_observ::run(other, &args[1..], &log_dir)
        }
        other => Err(format!(
            "unknown subcommand '{other}' (expected daemon, uac, call, trace, calls, diag, capture or metrics)"
        )),
    }
}

fn load_config(rest: &[String]) -> Result<Config, String> {
    let path = flag_value(rest, "--config")
        .or_else(|| std::env::var("ZRTC_CONFIG").ok())
        .ok_or_else(|| "no config: pass --config <path> or set $ZRTC_CONFIG".to_string())?;
    Config::load(std::path::Path::new(&path)).map_err(|e| format!("{e} (from {path})"))
}

/// Best-effort config load for read-only CLI commands (trace/calls/...).
fn load_config_optional(rest: &[String]) -> Option<Config> {
    load_config(rest).ok()
}

fn init_tracing(level: &str, observ_level: Option<&str>) {
    let obs = observ_level.unwrap_or("info");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(format!(
                    "{level},observ={obs},hyper=warn,h2=warn,rustls=warn"
                ))
            }),
        )
        .try_init();
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn flag_or(args: &[String], flag: &str, default: &str) -> String {
    flag_value(args, flag).unwrap_or_else(|| default.to_string())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn parse_uac(args: &[String]) -> Result<UacOpts, String> {
    let mut opts = UacOpts::default();
    if let Some(t) = flag_value(args, "--target") {
        opts.target = t
            .parse()
            .map_err(|_| format!("bad --target '{t}' (HOST:PORT)"))?;
    }
    opts.transport = Transport::parse(&flag_or(args, "--transport", "udp"))?;
    opts.to = flag_or(args, "--to", &opts.to);
    opts.from = flag_or(args, "--from", &opts.from);
    if let Some(id) = flag_value(args, "--call-id") {
        opts.call_id = id;
    }
    opts.rtp_ms = flag_or(args, "--rtp-ms", "1000")
        .parse()
        .map_err(|_| "bad --rtp-ms")?;
    opts.probe = has_flag(args, "--probe");
    let secs: u64 = flag_or(args, "--timeout-secs", "15")
        .parse()
        .map_err(|_| "bad --timeout-secs")?;
    opts.timeout = Duration::from_secs(secs);
    Ok(opts)
}
