//! Vendor trunk client: connects out to the provider over UDP/TCP/TLS,
//! drives the startup REGISTER (with 401/407 auth), runs OPTIONS
//! keepalives, and places calls (`zrtc call <e164>`).

pub mod call;
pub mod register;

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use sip_core::builder::RequestBuilder;
use sip_core::ids::{new_call_id, new_tag};
use sip_core::message::{Method, SipMessage};
use sip_core::uri::SipUri;

use crate::auth::{KeepaliveCtx, TrunkAuth};
use crate::config::Config;
use crate::uac;

/// A resolved vendor trunk endpoint.
#[derive(Debug)]
pub struct Endpoint {
    /// Primary SIP target (equals `targets[0]`).
    pub target: SocketAddr,
    /// Full candidate list in RFC 3263 priority order (SRV priority/weight,
    /// then A/AAAA per target). `connect` walks it in order and pins
    /// `target` to the candidate that actually accepted the connection.
    pub targets: Vec<SocketAddr>,
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

        // Accept HOST, HOST:PORT, "sip:...@HOST:PORT", or IPv6 literals
        // ("[2001:db8::1]" or "[2001:db8::1]:5060"). A user@ part is
        // stripped: "sip:user@host:port" must resolve host:port, not
        // "user@host".
        let hostport = address
            .strip_prefix("sip:")
            .or_else(|| address.strip_prefix("sips:"))
            .unwrap_or(&address)
            .split(';')
            .next()
            .unwrap_or(&address)
            .rsplit('@')
            .next()
            .unwrap_or(&address)
            .to_string();
        let (host, explicit_port) = split_host_port(&hostport)?;

        let transport = uac::Transport::parse(&t.transport)?;
        // Blocking resolve is fine at startup/call setup (one-shot).
        let targets = resolve_trunk_targets(&host, explicit_port, transport, &hostport)?;
        tracing::debug!(trunk = %hostport, candidates = targets.len(),
            primary = %targets[0], "trunk targets resolved (RFC 3263 order)");
        let target = targets[0];

        let user = t.auth_user.clone().unwrap_or_else(|| "trunk".to_string());
        let aor = t
            .aor
            .clone()
            .unwrap_or_else(|| format!("sip:{user}@{}", uri_host(&host)));
        let contact = format!("sip:{user}@{}", cfg.sip.host);
        Ok(Endpoint {
            target,
            targets,
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
    ///
    /// Bare form — use for SDP `c=` lines (RFC 4566 requires the bare IP).
    /// For SIP URIs use [`Endpoint::host_uri`], which brackets IPv6
    /// literals (RFC 3261 §19.1.2).
    pub fn host(&self) -> String {
        self.target.ip().to_string()
    }

    /// Host portion for use inside SIP URIs: IPv6 literals are bracketed
    /// (RFC 3261 §19.1.2 — a bare literal makes the URI unparseable because
    /// the first colon is mistaken for the port separator), IPv4 stays bare.
    pub fn host_uri(&self) -> String {
        let ip = self.target.ip();
        if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        }
    }

    /// Keepalive request-URI (points at the trunk itself).
    pub fn keepalive_uri(&self) -> String {
        format!("sip:{}:{}", self.host_uri(), self.target.port())
    }
}

/// Brackets a config-provided host for use inside a SIP URI. A host that is
/// already bracketed passes through untouched.
fn uri_host(host: &str) -> String {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if trimmed.contains(':') {
        format!("[{trimmed}]")
    } else {
        trimmed.to_string()
    }
}

/// Splits a trunk "hostport" token into (host, explicit port). Handles
/// bracketed and bare IPv6 literals; the default port is applied later by
/// the transport (RFC 3263: a port-less target goes through SRV).
fn split_host_port(hostport: &str) -> Result<(String, Option<u16>), String> {
    if hostport.starts_with('[') {
        let (h6, rest) = hostport
            .split_once(']')
            .ok_or_else(|| format!("trunk address '{hostport}': unclosed '['"))?;
        let host = h6.trim_start_matches('[').to_string();
        if host.is_empty() {
            return Err(format!("trunk address '{hostport}': empty host"));
        }
        // Only "" or ":port" may follow the closing bracket — anything else
        // is a malformed address, not silently ignored junk.
        let port = match rest {
            "" => None,
            r if r.starts_with(':') => {
                let p: u16 = r[1..]
                    .parse()
                    .map_err(|_| format!("trunk address '{hostport}': bad port"))?;
                if p == 0 {
                    return Err(format!(
                        "trunk address '{hostport}': port 0 is not a valid SIP port"
                    ));
                }
                Some(p)
            }
            _ => {
                return Err(format!(
                    "trunk address '{hostport}': unexpected characters after ']'"
                ))
            }
        };
        return Ok((host, port));
    }
    if hostport.matches(':').count() > 1 {
        // Bare IPv6 literal (no brackets, no port).
        return Ok((hostport.to_string(), None));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => {
            if h.is_empty() {
                return Err(format!("trunk address '{hostport}': empty host"));
            }
            let port: u16 = p
                .parse()
                .map_err(|_| format!("trunk address '{hostport}': bad port"))?;
            if port == 0 {
                return Err(format!(
                    "trunk address '{hostport}': port 0 is not a valid SIP port"
                ));
            }
            Ok((h.to_string(), Some(port)))
        }
        None => {
            if hostport.is_empty() {
                return Err("trunk address is empty".to_string());
            }
            Ok((hostport.to_string(), None))
        }
    }
}

/// Resolves the trunk host into an ordered candidate list.
///
/// RFC 3263 discovery first (NAPTR/SRV/A/AAAA via the system resolver on
/// :53): an explicit port pins the endpoint, a transport selects the SRV
/// key (`_sip._udp.host` / `_sip._tcp` / `_sips._tcp`), and SRV records
/// give prioritized, load-weighted failover candidates. When the system
/// resolver is unavailable or discovery yields nothing, falls back to the
/// libc resolver with the explicit or transport-default port.
fn resolve_trunk_targets(
    host: &str,
    explicit_port: Option<u16>,
    transport: uac::Transport,
    addr_label: &str,
) -> Result<Vec<SocketAddr>, String> {
    let sip_transport = match transport {
        uac::Transport::Udp => rfc3263::SipTransport::Udp,
        uac::Transport::Tcp => rfc3263::SipTransport::Tcp,
        uac::Transport::Tls => rfc3263::SipTransport::Tls,
        // RFC 3263 predates WebSocket: WSS rides on TCP, so use the TCP SRV
        // key (there is no SIP+D2W service token).
        uac::Transport::Wss => rfc3263::SipTransport::Tcp,
    };
    match rfc3263::Resolver::system() {
        Ok(resolver) => match resolver.resolve(host, Some(sip_transport), explicit_port) {
            Ok(list) if !list.is_empty() => return Ok(list),
            Ok(_) => {
                tracing::warn!(trunk = %addr_label, "RFC 3263 discovery returned no addresses")
            }
            Err(e) => tracing::warn!(trunk = %addr_label, error = %e,
                "RFC 3263 discovery failed; falling back to libc resolver"),
        },
        Err(e) => tracing::warn!(trunk = %addr_label, error = %e,
            "no DNS nameserver available; falling back to libc resolver"),
    }
    let port = explicit_port.unwrap_or(sip_transport.default_port());
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("trunk address '{addr_label}': cannot resolve: {e}"))?
        .collect();
    if addrs.is_empty() {
        Err(format!("trunk address '{addr_label}': no addresses"))
    } else {
        Ok(addrs)
    }
}

/// Per-candidate connect timeout. Bounds a dead TCP/TLS/WSS candidate so
/// the remaining RFC 3263 candidates still get a chance (UDP "connects"
/// are instant — they only pin the default destination, so the first
/// candidate always wins there, which is correct: UDP has no connection).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Opens a client session to the trunk, walking the RFC 3263 candidate
/// list in priority order (connection-time failover). On success `ep.target`
/// is pinned to the candidate that actually accepted the connection, so
/// keepalives, request-URIs and RTP all address the winning server.
pub(crate) async fn connect(ep: &mut Endpoint) -> Result<uac::Session, String> {
    let mut attempts: Vec<String> = Vec::new();
    for (i, &candidate) in ep.targets.iter().enumerate() {
        let opts = uac::UacOpts {
            target: candidate,
            transport: ep.transport,
            to: ep.aor.clone(),
            from: ep.aor.clone(),
            tls_identity: ep.identity.clone(),
            ..Default::default()
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, uac::Session::connect(&opts)).await {
            Ok(Ok(sess)) => {
                if i > 0 {
                    tracing::warn!(
                        candidate = %candidate,
                        attempt = i + 1,
                        total = ep.targets.len(),
                        "trunk failover: primary unreachable, connected to candidate"
                    );
                } else {
                    tracing::debug!(target = %candidate, "trunk connected");
                }
                ep.target = candidate;
                return Ok(sess);
            }
            Ok(Err(e)) => attempts.push(format!("{candidate}: {e}")),
            Err(_) => attempts.push(format!("{candidate}: timed out after {CONNECT_TIMEOUT:?}")),
        }
    }
    Err(format!(
        "trunk connect failed for {} candidate(s): {}",
        attempts.len(),
        attempts.join("; ")
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(address: &str, transport: &str) -> Config {
        toml::from_str(&format!(
            "[trunk]\naddress = \"{address}\"\ntransport = \"{transport}\"\n"
        ))
        .expect("test config")
    }

    #[test]
    fn split_host_port_handles_v4_v6_and_sip_uris() {
        assert_eq!(
            split_host_port("pbx.example.com").unwrap(),
            ("pbx.example.com".to_string(), None)
        );
        assert_eq!(
            split_host_port("pbx.example.com:5070").unwrap(),
            ("pbx.example.com".to_string(), Some(5070))
        );
        assert_eq!(
            split_host_port("2001:db8::1").unwrap(),
            ("2001:db8::1".to_string(), None)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:5061").unwrap(),
            ("2001:db8::1".to_string(), Some(5061))
        );
        assert!(split_host_port("host:notaport").is_err());
        assert!(split_host_port("[2001:db8::1").is_err());
        // Hardening: port 0 is not a SIP port, junk after ']' is a malformed
        // address, and an empty host is rejected outright.
        assert!(split_host_port("host:0").is_err());
        assert!(split_host_port("[2001:db8::1]:0").is_err());
        assert!(split_host_port("[2001:db8::1]garbage").is_err());
        assert!(split_host_port("[]:5060").is_err());
        assert!(split_host_port(":5060").is_err());
        assert!(split_host_port("host:").is_err());
    }

    #[test]
    fn ipv6_targets_are_bracketed_in_uris_but_bare_in_sdp() {
        // Regression: a bare IPv6 literal in a SIP URI is unparseable (the
        // first colon is mistaken for the port separator); URIs must bracket
        // the host while the SDP c= fallback keeps the bare form (RFC 4566).
        let mut ep = Endpoint::from_config(&cfg("[2001:db8::1]:5070", "udp")).unwrap();
        assert_eq!(ep.host(), "2001:db8::1", "SDP c= form stays bare");
        assert_eq!(ep.host_uri(), "[2001:db8::1]");
        assert_eq!(ep.keepalive_uri(), "sip:[2001:db8::1]:5070");
        assert_eq!(ep.aor, "sip:trunk@[2001:db8::1]");
        // And the request-URI form used by `zrtc call` parses back cleanly.
        let ruri = format!("sip:15551234567@{}", ep.host_uri());
        assert!(
            SipUri::parse(&ruri).is_ok(),
            "bracketed R-URI parses: {ruri}"
        );
        // Failover pinning replaces the target: URIs must follow the winner.
        ep.target = "[2001:db8::99]:5080".parse::<SocketAddr>().unwrap();
        assert_eq!(ep.keepalive_uri(), "sip:[2001:db8::99]:5080");
        // IPv4 URIs stay bracket-free.
        ep.target = "127.0.0.1:5070".parse::<SocketAddr>().unwrap();
        assert_eq!(ep.keepalive_uri(), "sip:127.0.0.1:5070");
    }

    #[test]
    fn endpoint_resolves_ip_literal_target_with_explicit_port() {
        // IP literal + explicit port: RFC 3263 fast path, no DNS at all.
        let ep = Endpoint::from_config(&cfg("127.0.0.1:5070", "udp")).unwrap();
        assert_eq!(ep.target.port(), 5070);
        assert_eq!(ep.targets.len(), 1);
        assert_eq!(ep.targets[0], ep.target);
        assert_eq!(ep.transport, uac::Transport::Udp);
        assert_eq!(ep.host(), "127.0.0.1");
        assert_eq!(ep.keepalive_uri(), "sip:127.0.0.1:5070");
    }

    #[test]
    fn endpoint_accepts_sip_uri_address_form_and_strips_params() {
        // "sip:trunk@127.0.0.1:6060;transport=udp" — user part and params
        // are stripped before resolution.
        let ep =
            Endpoint::from_config(&cfg("sip:trunk@127.0.0.1:6060;transport=udp", "udp")).unwrap();
        assert_eq!(ep.target, "127.0.0.1:6060".parse::<SocketAddr>().unwrap());
        assert_eq!(ep.aor, "sip:trunk@127.0.0.1");
    }

    #[test]
    fn endpoint_resolves_bracketed_ipv6_literal() {
        let ep = Endpoint::from_config(&cfg("[::1]:5080", "tcp")).unwrap();
        assert_eq!(ep.target, "[::1]:5080".parse::<SocketAddr>().unwrap());
        assert_eq!(ep.transport, uac::Transport::Tcp);
    }

    #[test]
    fn endpoint_errors_on_missing_address_and_bad_transport() {
        assert!(Endpoint::from_config(&cfg("", "udp"))
            .unwrap_err()
            .contains("address is missing"));
        assert!(Endpoint::from_config(&cfg("127.0.0.1:5060", "sctp"))
            .unwrap_err()
            .contains("transport"));
    }

    fn manual_endpoint(targets: Vec<SocketAddr>, transport: uac::Transport) -> Endpoint {
        Endpoint {
            target: targets[0],
            targets,
            transport,
            aor: "sip:trunk@127.0.0.1".into(),
            contact: "sip:trunk@127.0.0.1".into(),
            keepalive_secs: 0,
            identity: None,
        }
    }

    #[tokio::test]
    async fn connect_fails_over_to_next_candidate_and_pins_it() {
        // Candidate 1: a port with no listener (instant ECONNREFUSED).
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        let mut ep = manual_endpoint(vec![dead, live_addr], uac::Transport::Tcp);

        let _sess = connect(&mut ep).await.expect("failover connect succeeds");
        assert_eq!(
            ep.target, live_addr,
            "target pinned to the candidate that accepted"
        );
        // Keepalive request-URI follows the winner.
        assert_eq!(
            ep.keepalive_uri(),
            format!("sip:127.0.0.1:{}", live_addr.port())
        );
    }

    #[tokio::test]
    async fn connect_reports_every_failed_candidate() {
        let dead1: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let dead2: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let mut ep = manual_endpoint(vec![dead1, dead2], uac::Transport::Tcp);

        // `Session` is not Debug, so match instead of unwrap_err().
        let err = match connect(&mut ep).await {
            Err(e) => e,
            Ok(_) => panic!("expected every candidate to fail"),
        };
        assert!(
            err.contains(&dead1.to_string()) && err.contains(&dead2.to_string()),
            "both candidates listed: {err}"
        );
        assert_eq!(ep.target, dead1, "target unchanged on total failure");
    }

    #[tokio::test]
    async fn connect_single_candidate_behaves_as_before() {
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = live.local_addr().unwrap();
        let mut ep = manual_endpoint(vec![addr], uac::Transport::Tcp);

        let _sess = connect(&mut ep).await.expect("direct connect");
        assert_eq!(ep.target, addr);
    }
}
