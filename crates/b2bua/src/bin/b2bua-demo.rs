//! b2bua-demo: run the B2BUA engine with env configuration.
//!
//! Env vars:
//! * `B2BUA_SIP_BIND`   — SIP UDP bind addr (default `0.0.0.0:5060`)
//! * `B2BUA_TARGET`     — default outbound target URI
//! * `B2BUA_MEDIA_HOST` — SDP c= host (default `127.0.0.1`)
//!
//! Every CDR event is logged at INFO under the `cdr` target.

use b2bua::{log_cdr_task, B2bua, B2buaConfig};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,b2bua=debug,cdr=info".into()),
        )
        .init();

    let sip_bind: SocketAddr = std::env::var("B2BUA_SIP_BIND")
        .unwrap_or_else(|_| "0.0.0.0:5060".into())
        .parse()?;
    let target =
        std::env::var("B2BUA_TARGET").unwrap_or_else(|_| "sip:b2bua@127.0.0.1:5062".into());
    let media_host = std::env::var("B2BUA_MEDIA_HOST").unwrap_or_else(|_| "127.0.0.1".into());

    let cfg = B2buaConfig {
        sip_bind,
        media_host,
        media_base_port: 0,
        codecs: vec![
            codecs::CodecId::Pcmu,
            codecs::CodecId::Pcma,
            codecs::CodecId::G722,
            codecs::CodecId::G729,
            codecs::CodecId::Opus,
        ],
        routes: Vec::new(),
        default_target: target,
        session_timer_min_se: b2bua::timers::DEFAULT_MIN_SE,
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    log_cdr_task(rx);
    tracing::info!(?cfg.sip_bind, "starting b2bua-demo");
    B2bua::new(cfg, tx).run().await?;
    Ok(())
}
