//! zrtc — one daemon wiring the native SIP + media library stack into a
//! runnable voice service.
//!
//! Usage:
//!   zrtc [--config <path>]     run the daemon (config also via $ZRTC_CONFIG)
//!   zrtc daemon [--config <path>]
//!   zrtc uac [options]         in-repo SIP client (demo calls / probes)
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

mod cdr_task;
mod config;
mod core;
mod daemon;
mod sink;
mod tls;
mod transport;
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
            init_tracing(&cfg.daemon.log_level);
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("runtime: {e}"))?;
            rt.block_on(daemon::run(cfg))
        }
        "--config" => {
            // `zrtc --config path` == `zrtc daemon --config path`
            let cfg = load_config(&args)?;
            init_tracing(&cfg.daemon.log_level);
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
        other => Err(format!(
            "unknown subcommand '{other}' (expected daemon or uac)"
        )),
    }
}

fn load_config(rest: &[String]) -> Result<Config, String> {
    let path = flag_value(rest, "--config")
        .or_else(|| std::env::var("ZRTC_CONFIG").ok())
        .ok_or_else(|| {
            "no config: pass --config <path> or set $ZRTC_CONFIG".to_string()
        })?;
    Config::load(std::path::Path::new(&path)).map_err(|e| format!("{e} (from {path})"))
}

fn init_tracing(level: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new(format!(
                        "{level},hyper=warn,h2=warn,rustls=warn"
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
    opts.rtp_ms = flag_or(args, "--rtp-ms", "1000").parse().map_err(|_| "bad --rtp-ms")?;
    opts.probe = has_flag(args, "--probe");
    let secs: u64 = flag_or(args, "--timeout-secs", "15").parse().map_err(|_| "bad --timeout-secs")?;
    opts.timeout = Duration::from_secs(secs);
    Ok(opts)
}
