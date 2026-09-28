//! The zrtc daemon: wires every library into one supervised voice service.
//!
//! Components (all in-process, each restarted with backoff on failure):
//!   - SIP listeners: UDP, TCP, TLS, WSS
//!   - core pump: SBC → registrar/proxy routing + response paths
//!   - B2BUA engine on a loopback UDP socket (dual-leg media bridge)
//!   - loopback sink UAS (leg B target) feeding the ai-bridge tap
//!   - CDR finalizer: b2bua events → cdr store (served by the REST API)
//!   - startup REGISTER of the configured AoR through the live pipeline
//!   - one originated outbound INVITE to the configured target

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use b2bua::{B2bua, B2buaConfig, CdrEvent};
use cdr::CdrStore;
use codecs::CodecId;
use dialer::Dialer;
use registrar::{Registrar, RegistrarConfig};
use sbc::{Acl, Cidr, RateLimit, Sbc, SbcConfig};
use sip_core::ids::{new_branch, new_call_id, new_tag};
use sip_core::message::{Method, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{builder::RequestBuilder, serialize};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::cdr_task;
use crate::config::Config;
use crate::core::{Core, Incoming, OutboundIds, Responder};
use crate::tls::TlsIdentity;
use crate::transport::{self, ListenerCtx};
use crate::{auth, trunk, uac};

/// All codecs the platform bridges (full matrix via the media pumps).
const PLATFORM_CODECS: [CodecId; 5] = [
    CodecId::Pcmu,
    CodecId::Pcma,
    CodecId::G722,
    CodecId::G729,
    CodecId::Opus,
];

pub async fn run(mut cfg: Config) -> Result<(), String> {
    // Environment overrides win over file values; never logged.
    cfg.apply_trunk_env();
    let host = cfg.sip.host.clone();
    let udp_bind = cfg.sip.bind_addr(cfg.sip.udp_port);
    let tcp_bind = cfg.sip.bind_addr(cfg.sip.tcp_port);
    let tls_bind = cfg.sip.bind_addr(cfg.sip.tls_port);
    let wss_bind = cfg.sip.bind_addr(cfg.sip.wss_port);
    let b2bua_bind = cfg.sip.bind_addr(cfg.b2bua.port);
    let sink_bind = cfg.sip.bind_addr(cfg.sink.port);
    let api_addr: SocketAddr = format!("{}:{}", host, cfg.api.port)
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:8080".parse().unwrap());

    // TLS identity for the TLS and WSS listeners (self-signed, in-memory).
    let identity = TlsIdentity::generate("zrtc.local")?;
    let tls_acceptor = identity.acceptor()?;
    let wss_acceptor = identity.acceptor()?;

    // ---- observability ---------------------------------------------------
    if cfg.observ.enabled {
        let bus = std::sync::Arc::new(observ::EventBus::new(8192));
        observ::bus::install_global(bus.clone());
        let o = &cfg.observ;
        let handles = observ::spawn::spawn_writers(
            bus,
            observ::spawn::WriterConfig {
                log_dir: o.log_dir.clone().into(),
                pcap_enabled: o.pcap.enabled,
                sip_file: o.pcap.sip_file.clone(),
                rtp_file: o.pcap.rtp_file.clone(),
                include_payload: o.pcap.include_payload,
                max_file_mb: o.pcap.max_file_mb,
                trace_enabled: o.trace.enabled,
                include_sdp: o.trace.include_sdp,
                include_sip_bodies: o.trace.include_sip_bodies,
                flush_interval_ms: o.trace.flush_interval_ms,
            },
        );
        tracing::info!(
            "observ: log_dir={} pcap={} trace={} ({} writers)",
            o.log_dir,
            o.pcap.enabled,
            o.trace.enabled,
            handles.len()
        );
    }

    // ---- CDR store + REST API -------------------------------------------
    let cdr_store = CdrStore::new(10_000);
    let dialer = Dialer::new(cdr_store.clone());
    let api_state = api::new_state(cdr_store.clone(), dialer);
    // Cloned before api_state is moved into the server task: the CDR
    // finalizer increments the Prometheus call counters through it.
    let api_metrics = api_state.metrics.clone();
    {
        let addr = api_addr;
        tokio::spawn(async move {
            loop {
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => {
                        tracing::info!("rest api listening on http://{addr} (GET /cdrs)");
                        let router = api::build_router(api_state.clone());
                        match axum::serve(listener, router).await {
                            Ok(()) => break,
                            Err(e) => tracing::error!("api server error: {e}; restarting"),
                        }
                    }
                    Err(e) => {
                        tracing::error!("api bind {addr} failed: {e}; retry in 1s");
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // ---- shared UDP socket (listener + core outbound path) --------------
    let udp = Arc::new(
        UdpSocket::bind(udp_bind)
            .await
            .map_err(|e| format!("bind {udp_bind}: {e}"))?,
    );
    tracing::info!("sip/udp listening on {udp_bind}");

    let registry: crate::core::ConnRegistry = Arc::new(Mutex::new(HashMap::new()));
    // Bounded: when the core pump falls behind, listener tasks back-pressure
    // instead of queueing attacker-supplied messages without limit.
    let (core_tx, core_rx) = mpsc::channel::<Incoming>(1024);
    let ctx = ListenerCtx {
        core: core_tx.clone(),
        registry: registry.clone(),
        idle: transport::STREAM_IDLE,
        handshake: transport::HANDSHAKE,
    };

    // ---- core pump -------------------------------------------------------
    let sbc = build_sbc(&cfg, udp_bind);
    let proxy = build_proxy(&cfg);
    let registrar = build_registrar(&cfg);
    let core = Core::new(
        sbc,
        proxy,
        registrar,
        udp.clone(),
        registry.clone(),
        b2bua_bind,
    );
    tokio::spawn(async move {
        core.pump(core_rx).await;
    });

    // ---- listeners (each supervised with 1 s backoff) --------------------
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            while let Err(e) = transport::run_tcp(tcp_bind, ctx.clone()).await {
                tracing::error!("sip/tcp listener failed: {e}; restarting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            while let Err(e) = transport::run_tls(tls_bind, tls_acceptor.clone(), ctx.clone()).await
            {
                tracing::error!("sip/tls listener failed: {e}; restarting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            while let Err(e) = transport::run_wss(wss_bind, wss_acceptor.clone(), ctx.clone()).await
            {
                tracing::error!("sip/wss listener failed: {e}; restarting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
    {
        // UDP listener on the pre-bound socket.
        let ctx = ctx.clone();
        let udp = udp.clone();
        tokio::spawn(async move {
            while let Err(e) = udp_listener(udp.clone(), ctx.clone()).await {
                tracing::error!("sip/udp listener failed: {e}; restarting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // ---- B2BUA engine -----------------------------------------------------
    let (cdr_tx, cdr_rx) = mpsc::unbounded_channel::<CdrEvent>();
    {
        let bcfg = B2buaConfig {
            sip_bind: b2bua_bind,
            media_host: cfg.b2bua.media_host.clone(),
            media_base_port: 0,
            codecs: PLATFORM_CODECS.to_vec(),
            routes: cfg
                .b2bua
                .routes
                .iter()
                .map(|r| b2bua::Route {
                    prefix: r.prefix.clone(),
                    target: r.target.clone(),
                })
                .collect(),
            default_target: cfg.b2bua.default_target.clone(),
            session_timer_min_se: b2bua::timers::DEFAULT_MIN_SE,
        };
        let engine_sock = Arc::new(
            UdpSocket::bind(b2bua_bind)
                .await
                .map_err(|e| format!("bind b2bua {b2bua_bind}: {e}"))?,
        );
        tracing::info!("b2bua engine listening on {b2bua_bind}");
        tokio::spawn(async move {
            while let Err(e) = B2bua::new(bcfg.clone(), cdr_tx.clone())
                .run_on(engine_sock.clone())
                .await
            {
                tracing::error!("b2bua engine failed: {e}; restarting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // ---- CDR finalizer ----------------------------------------------------
    let outbound_ids: OutboundIds = Arc::new(Mutex::new(HashSet::new()));
    {
        let store = cdr_store.clone();
        let outbound = outbound_ids.clone();
        let metrics = api_metrics;
        tokio::spawn(async move {
            cdr_task::run(cdr_rx, store, outbound, metrics).await;
        });
    }

    // ---- loopback sink ----------------------------------------------------
    {
        let host = host.clone();
        let ai_enabled = cfg.ai_bridge.enabled;
        tokio::spawn(async move {
            while let Err(e) = crate::sink::run(sink_bind, host.clone(), ai_enabled).await {
                tracing::error!("loopback sink failed: {e}; restarting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    // ---- startup REGISTER through the live pipeline -----------------------
    {
        let listener = udp_bind;
        let aor = cfg.registrar.aor.clone();
        let contact = format!("sip:zrtc@{}:{}", host, cfg.b2bua.port);
        let expires = cfg.registrar.expires;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            match register_aor(listener, &aor, &contact, expires).await {
                Ok(()) => tracing::info!("aor {aor} registered (contact {contact})"),
                Err(e) => tracing::error!("aor registration failed: {e}"),
            }
        });
    }

    // ---- vendor trunk ------------------------------------------------------
    if cfg.trunk.address.as_deref().is_some_and(|a| !a.is_empty()) {
        let ep = trunk::Endpoint::from_config(&cfg)?;
        let mut trunk_auth = auth::build(&cfg.trunk)?;
        tracing::info!(
            "trunk configured: {} transport={} auth={}",
            cfg.trunk.address.as_deref().unwrap_or(""),
            ep.transport.name(),
            trunk_auth.mode()
        );
        if cfg.trunk.register {
            // Fail fast: a trunk that cannot register is a fatal config
            // error (the raw challenge is logged inside register::run).
            let mut sess = trunk::connect(&ep).await?;
            let code = trunk::register::run(
                &mut sess,
                &ep,
                trunk_auth.as_mut(),
                cfg.registrar.expires.max(300),
            )
            .await?;
            tracing::info!("trunk ready (REGISTER {})", code);
            if ep.keepalive_secs > 0 {
                tokio::spawn(trunk::keepalive_loop(sess, ep, trunk_auth));
            }
        } else if ep.keepalive_secs > 0 {
            let sess = trunk::connect(&ep).await?;
            tokio::spawn(trunk::keepalive_loop(sess, ep, trunk_auth));
        }
    }

    // ---- one originated outbound call -------------------------------------
    if cfg.outbound.enabled {
        let listener = udp_bind;
        let from = cfg.registrar.aor.clone();
        let to = cfg.outbound.target.clone();
        let rtp_ms = cfg.outbound.rtp_ms;
        let delay = cfg.outbound.delay_ms;
        let outbound = outbound_ids.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            let call_id = new_call_id("zrtc-outbound");
            outbound
                .lock()
                .expect("outbound ids")
                .insert(call_id.clone());
            tracing::info!(%call_id, "originating outbound call to {to}");
            let opts = uac::UacOpts {
                target: listener,
                transport: uac::Transport::Udp,
                to,
                from,
                call_id,
                rtp_ms,
                ..Default::default()
            };
            match uac::run(opts).await {
                Ok(()) => tracing::info!("outbound call completed"),
                Err(e) => tracing::error!("outbound call failed: {e}"),
            }
        });
    }

    tracing::info!(
        "zrtc up: sip udp:{}/tcp:{}/tls:{}/wss:{} api:{} b2bua:{} sink:{}",
        cfg.sip.udp_port,
        cfg.sip.tcp_port,
        cfg.sip.tls_port,
        cfg.sip.wss_port,
        cfg.api.port,
        cfg.b2bua.port,
        cfg.sink.port
    );

    // Supervise: block until ctrl-c (listeners restart themselves).
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("ctrl-c: {e}"))?;
    tracing::info!("shutdown signal received");
    Ok(())
}

async fn udp_listener(udp: Arc<UdpSocket>, ctx: ListenerCtx) -> Result<(), String> {
    use sip_core::parse::parse_message;
    let local = udp.local_addr().map_err(|e| e.to_string())?;
    tracing::debug!("udp listener active on {local}");
    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, src) = udp
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("udp recv: {e}"))?;
        match parse_message(&buf[..n]) {
            Ok(msg) => {
                // socket-boundary tap (SipRx)
                observ::session::sip_tap(&buf[..n], src, observ::event::Transport::Udp, true);
                let _ = ctx
                    .core
                    .send(Incoming {
                        msg,
                        resp: Responder { src, conn: None },
                    })
                    .await;
            }
            Err(e) => tracing::debug!(%src, "udp unparseable: {e}"),
        }
    }
}

fn build_sbc(cfg: &Config, internal: SocketAddr) -> Sbc {
    fn parse_cidrs(items: &[String]) -> Vec<Cidr> {
        items
            .iter()
            .filter_map(|s| {
                let (ip, prefix) = s.split_once('/')?;
                let addr: std::net::IpAddr = ip.parse().ok()?;
                Some(Cidr {
                    addr,
                    prefix: prefix.parse().ok()?,
                })
            })
            .collect()
    }
    let config = SbcConfig {
        acl: Acl {
            allow: parse_cidrs(&cfg.sbc.allow),
            deny: parse_cidrs(&cfg.sbc.deny),
        },
        rate: RateLimit {
            per_second: cfg.sbc.rate_per_second,
            burst: cfg.sbc.rate_burst,
        },
        external: format!("{}:{}", cfg.sip.host, cfg.sip.udp_port),
        internal_target: internal,
        topology_hiding: cfg.sbc.topology_hiding,
    };
    Sbc::new(config)
}

fn build_proxy(cfg: &Config) -> proxy::Proxy {
    let config = proxy::ProxyConfig {
        record_route: Some(format!("{}:{}", cfg.sip.host, cfg.sip.udp_port)),
        record_route_invites: true,
        default_port: cfg.b2bua.port,
        fork_wait_ms: 500,
    };
    let mut p = proxy::Proxy::new(config);
    p.routes.default = vec![format!("{}:{}", cfg.sip.host, cfg.b2bua.port)];
    p
}

fn build_registrar(cfg: &Config) -> Registrar {
    let config = RegistrarConfig {
        domain: Some(cfg.registrar.domain.clone()),
        min_expires: 30,
        max_expires: cfg.registrar.expires.max(3600),
        require_auth: cfg.registrar.require_auth,
    };
    let mut registrar = Registrar::new(config);
    if cfg.registrar.require_auth {
        let realm = cfg
            .registrar
            .auth_realm
            .clone()
            .unwrap_or_else(|| cfg.registrar.domain.clone());
        let mut store = registrar::AuthStore::new(&realm);
        let user = cfg.registrar.auth_user.as_deref().unwrap_or("1000");
        let pass = cfg.registrar.auth_pass.as_deref().unwrap_or("1000");
        store.add_user(user, pass);
        registrar = registrar.with_auth(store);
    }
    registrar
}

/// Registers the daemon's AoR by sending a real REGISTER through the UDP
/// listener (exercising listener → SBC → registrar end to end).
async fn register_aor(
    listener: SocketAddr,
    aor: &str,
    contact: &str,
    expires: u32,
) -> Result<(), String> {
    let sock = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| e.to_string())?;
    sock.connect(listener).await.map_err(|e| e.to_string())?;
    let local = sock.local_addr().map_err(|e| e.to_string())?;

    let uri = SipUri::parse(aor).map_err(|e| e.to_string())?;
    for attempt in 1..=5u32 {
        let register = RequestBuilder::new(Method::Register, uri.clone())
            .via(TransportKind::Udp, &local.to_string(), Some(&new_branch()))
            .from(&format!("<{aor}>;tag={}", new_tag()))
            .to(&format!("<{aor}>"))
            .call_id(Some(&new_call_id("zrtc-reg")))
            .cseq(attempt)
            .contact(&format!("<{contact}>"))
            .header("Expires", &expires.to_string())
            .header("Max-Forwards", "70")
            .build();
        sock.send(&serialize(&SipMessage::Request(register)))
            .await
            .map_err(|e| e.to_string())?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut buf = vec![0u8; 65_535];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let n = match tokio::time::timeout(remaining, sock.recv(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                Ok(_) => break,
                Err(_) => break,
            };
            if let Ok(SipMessage::Response(resp)) = sip_core::parse_message(&buf[..n]) {
                if resp.code == 200 {
                    return Ok(());
                }
                tracing::debug!("register attempt {attempt}: response {}", resp.code);
            }
        }
        tracing::debug!("register attempt {attempt} timed out; retrying");
    }
    Err("no 200 OK for REGISTER after 5 attempts".into())
}
