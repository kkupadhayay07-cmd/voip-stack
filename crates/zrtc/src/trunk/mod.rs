//! Vendor trunk client: connects out to the provider over UDP/TCP/TLS,
//! drives the startup REGISTER (with 401/407 auth), runs OPTIONS
//! keepalives, and places calls (`zrtc call <e164>`).

pub mod call;
pub mod register;

use std::net::SocketAddr;
use std::time::Duration;

use sip_core::builder::RequestBuilder;
use sip_core::ids::{new_call_id, new_tag};
use sip_core::message::{Method, SipMessage};
use sip_core::uri::SipUri;

use crate::auth::{KeepaliveCtx, TrunkAuth};
use crate::config::Config;
use crate::uac;

/// A resolved vendor trunk endpoint.
pub struct Endpoint {
    pub target: SocketAddr,
    pub transport: uac::Transport,
    /// SIP identity used for REGISTER (From/To of the REGISTER).
    pub aor: String,
    /// Contact for REGISTER (host part mirrors the daemon's sip.host).
    pub contact: String,
    pub keepalive_secs: u64,
    /// Client identity for mTLS (tls_client_cert mode).
    pub identity: Option<crate::tls::TlsClientIdentity>,
}

impl Endpoint {
    /// Resolves the endpoint from `[trunk]` config (address, transport,
    /// aor, keepalive). Errors when the address is missing or unresolvable.
    pub fn from_config(cfg: &Config) -> Result<Endpoint, String> {
        let t = &cfg.trunk;
        let address = t
            .address
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or("trunk not configured: [trunk] address is missing")?
            .to_string();

        // Accept HOST, HOST:PORT or a full "sip:...@HOST:PORT" — extract the
        // host:port part and resolve it (DNS allowed).
        let hostport = address
            .strip_prefix("sip:")
            .or_else(|| address.strip_prefix("sips:"))
            .unwrap_or(&address)
            .split(';')
            .next()
            .unwrap_or(&address)
            .to_string();
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("trunk address '{hostport}': bad port"))?,
            ),
            None => (hostport.clone(), 5060),
        };
        // Blocking resolve is fine at startup/call setup (one-shot).
        let target: SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
            .map_err(|e| format!("trunk address '{hostport}': cannot resolve: {e}"))?
            .next()
            .ok_or_else(|| format!("trunk address '{hostport}': no addresses"))?;

        let transport = uac::Transport::parse(&t.transport)?;
        let user = t
            .auth_user
            .clone()
            .unwrap_or_else(|| "trunk".to_string());
        let aor = t.aor.clone().unwrap_or_else(|| format!("sip:{user}@{host}"));
        let contact = format!("sip:{user}@{}", cfg.sip.host);
        Ok(Endpoint {
            target,
            transport,
            aor,
            contact,
            keepalive_secs: t.keepalive_secs,
            identity: if transport == uac::Transport::Tls && t.tls_cert_path.is_some() {
                Some(crate::tls::TlsClientIdentity {
                    cert_path: t.tls_cert_path.clone().unwrap_or_default(),
                    key_path: t.tls_key_path.clone().unwrap_or_default(),
                    ca_path: t.tls_ca_path.clone(),
                })
            } else {
                None
            },
        })
    }

    /// Host portion of the trunk address (for request-URIs).
    pub fn host(&self) -> String {
        self.target.ip().to_string()
    }

    /// Keepalive request-URI (points at the trunk itself).
    pub fn keepalive_uri(&self) -> String {
        format!("sip:{}@{}", self.host(), self.target.port())
    }
}

/// Opens a client session to the trunk.
pub(crate) async fn connect(ep: &Endpoint) -> Result<uac::Session, String> {
    let opts = uac::UacOpts {
        target: ep.target,
        transport: ep.transport,
        to: ep.aor.clone(),
        from: ep.aor.clone(),
        tls_identity: ep.identity.clone(),
        ..Default::default()
    };
    uac::Session::connect(&opts).await
}

/// Builds a request with the endpoint's standard header set plus `extra`
/// (auth) headers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn request(
    method: Method,
    uri: &str,
    ep: &Endpoint,
    via: &str,
    call_id: &str,
    cseq: u32,
    from_tag: &str,
    to_tag: Option<&str>,
    contact: bool,
    extra: &[(String, String)],
) -> Result<sip_core::message::Request, String> {
    let mut b = RequestBuilder::new(method, SipUri::parse(uri).map_err(|e| e.to_string())?)
        .via(ep.transport.kind(), via, Some(&sip_core::ids::new_branch()))
        .from(&format!("<{}>;tag={from_tag}", ep.aor))
        .to(&match to_tag {
            Some(t) => format!("<{uri}>;tag={t}"),
            None => format!("<{uri}>"),
        })
        .call_id(Some(call_id))
        .cseq(cseq)
        .header("Max-Forwards", "70");
    if contact {
        b = b.contact(&format!("<{}>", ep.contact));
    }
    for (name, value) in extra {
        b = b.header(name, value);
    }
    Ok(b.build())
}

/// Receives the next response, answering stray in-dialog requests with 200
/// so the transaction stays clean.
pub(crate) async fn recv_response(
    sess: &mut uac::Session,
) -> Result<sip_core::message::Response, String> {
    loop {
        match sess.recv_msg().await? {
            SipMessage::Response(r) => return Ok(r),
            SipMessage::Request(req) => {
                let ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                sess.send_msg(&SipMessage::Response(ok)).await?;
            }
        }
    }
}

/// Long-running OPTIONS keepalive toward the trunk. Every tick asks the
/// auth mode for credential headers (`on_keepalive`), then sends OPTIONS.
pub(crate) async fn keepalive_loop(
    mut sess: uac::Session,
    ep: Endpoint,
    mut auth: Box<dyn TrunkAuth>,
) {
    let secs = ep.keepalive_secs.max(1);
    tracing::info!("trunk keepalive: OPTIONS every {secs}s to {}", ep.target);
    let mut tick = tokio::time::interval(Duration::from_secs(secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let uri = ep.keepalive_uri();
        let mut ctx = KeepaliveCtx {
            uri: uri.clone(),
            headers: Vec::new(),
        };
        auth.on_keepalive(&mut ctx);
        let req = match request(
            Method::Options,
            &uri,
            &ep,
            &sess.via(),
            &new_call_id("zrtc-ka"),
            1,
            &new_tag(),
            None,
            false,
            &ctx.headers,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("trunk keepalive build failed: {e}");
                continue;
            }
        };
        if let Err(e) = sess.send_msg(&SipMessage::Request(req)).await {
            tracing::warn!("trunk keepalive send failed: {e}");
            continue;
        }
        match tokio::time::timeout(Duration::from_secs(2), recv_response(&mut sess)).await {
            Ok(Ok(resp)) => {
                tracing::debug!("trunk keepalive OPTIONS -> {}", resp.code);
                if resp.code == 401 || resp.code == 407 {
                    // Vendor started challenging keepalives mid-flight.
                    let www = resp.headers.get("WWW-Authenticate").map(str::to_string);
                    let proxy = resp.headers.get("Proxy-Authenticate").map(str::to_string);
                    let _ = auth.on_challenge(resp.code, www.as_deref(), proxy.as_deref());
                }
            }
            Ok(Err(e)) => tracing::warn!("trunk keepalive recv failed: {e}"),
            Err(_) => tracing::warn!("trunk keepalive: no response within 2s"),
        }
    }
}
