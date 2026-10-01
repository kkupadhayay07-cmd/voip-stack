//! zrtc configuration: a single TOML file describing every supervised
//! component. Loaded from `--config <path>` or `$ZRTC_CONFIG`.

use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub daemon: Daemon,
    #[serde(default)]
    pub sip: Sip,
    #[serde(default)]
    pub sbc: Sbc,
    #[serde(default)]
    pub registrar: Registrar,
    #[serde(default)]
    pub b2bua: B2bua,
    #[serde(default)]
    pub sink: Sink,
    #[serde(default)]
    pub outbound: Outbound,
    #[serde(default)]
    pub trunk: Trunk,
    #[serde(default)]
    pub ai_bridge: AiBridge,
    #[serde(default)]
    pub api: Api,
    #[serde(default)]
    pub observ: Observ,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Daemon {
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for Daemon {
    fn default() -> Self {
        Daemon {
            log_level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sip {
    /// Advertised host and bind address for every SIP listener.
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,
    #[serde(default = "default_tcp_port")]
    pub tcp_port: u16,
    #[serde(default = "default_tls_port")]
    pub tls_port: u16,
    #[serde(default = "default_wss_port")]
    pub wss_port: u16,
}

impl Default for Sip {
    fn default() -> Self {
        Sip {
            host: default_host(),
            udp_port: default_udp_port(),
            tcp_port: default_tcp_port(),
            tls_port: default_tls_port(),
            wss_port: default_wss_port(),
        }
    }
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_udp_port() -> u16 {
    5060
}
fn default_tcp_port() -> u16 {
    5060
}
fn default_tls_port() -> u16 {
    5061
}
fn default_wss_port() -> u16 {
    5063
}

impl Sip {
    pub fn bind_addr(&self, port: u16) -> SocketAddr {
        format!("{}:{}", self.host, port)
            .parse()
            .unwrap_or_else(|_| format!("127.0.0.1:{port}").parse().expect("fallback bind"))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sbc {
    /// CIDR ranges admitted through the border (allowlist; deny is
    /// configured as `deny = [...]`).
    #[serde(default = "default_acl_allow")]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default = "default_rate")]
    pub rate_per_second: f64,
    #[serde(default = "default_rate_burst")]
    pub rate_burst: f64,
    #[serde(default)]
    pub topology_hiding: bool,
}

impl Default for Sbc {
    fn default() -> Self {
        Sbc {
            allow: default_acl_allow(),
            deny: Vec::new(),
            rate_per_second: default_rate(),
            rate_burst: default_rate_burst(),
            topology_hiding: false,
        }
    }
}

fn default_acl_allow() -> Vec<String> {
    vec!["127.0.0.0/8".into(), "::1/128".into()]
}
fn default_rate() -> f64 {
    50.0
}
fn default_rate_burst() -> f64 {
    100.0
}

#[derive(Debug, Clone, Deserialize)]
pub struct Registrar {
    /// Domain the served AoRs live under (Request-URI host check).
    #[serde(default = "default_domain")]
    pub domain: String,
    /// The one AoR the daemon registers on startup.
    #[serde(default = "default_aor")]
    pub aor: String,
    #[serde(default = "default_expires")]
    pub expires: u32,
    /// Challenge REGISTERs with Digest (401 → credentials → 200).
    #[serde(default)]
    pub require_auth: bool,
    /// Digest user/pass accepted when `require_auth` is on.
    #[serde(default)]
    pub auth_user: Option<String>,
    #[serde(default)]
    pub auth_pass: Option<String>,
    /// Challenge realm (defaults to `domain`).
    #[serde(default)]
    pub auth_realm: Option<String>,
}

impl Default for Registrar {
    fn default() -> Self {
        Registrar {
            domain: default_domain(),
            aor: default_aor(),
            expires: default_expires(),
            require_auth: false,
            auth_user: None,
            auth_pass: None,
            auth_realm: None,
        }
    }
}

fn default_domain() -> String {
    "zrtc.local".into()
}
fn default_aor() -> String {
    "sip:1000@zrtc.local".into()
}
fn default_expires() -> u32 {
    300
}

#[derive(Debug, Clone, Deserialize)]
pub struct B2bua {
    #[serde(default = "default_b2bua_port")]
    pub port: u16,
    #[serde(default = "default_host")]
    pub media_host: String,
    /// Dial-plan routes: longest matching prefix on the INVITE user part.
    #[serde(default)]
    pub routes: Vec<B2buaRoute>,
    /// Target used when no route prefix matches.
    #[serde(default = "default_b2bua_target")]
    pub default_target: String,
}

impl Default for B2bua {
    fn default() -> Self {
        B2bua {
            port: default_b2bua_port(),
            media_host: default_host(),
            routes: Vec::new(),
            default_target: default_b2bua_target(),
        }
    }
}

fn default_b2bua_port() -> u16 {
    5070
}
fn default_b2bua_target() -> String {
    "sip:sink@127.0.0.1:5090".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct B2buaRoute {
    pub prefix: String,
    pub target: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sink {
    #[serde(default = "default_sink_port")]
    pub port: u16,
}

impl Default for Sink {
    fn default() -> Self {
        Sink {
            port: default_sink_port(),
        }
    }
}

fn default_sink_port() -> u16 {
    5090
}

#[derive(Debug, Clone, Deserialize)]
pub struct Outbound {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Delay after startup before the daemon originates its outbound call.
    #[serde(default = "default_outbound_delay_ms")]
    pub delay_ms: u64,
    /// SIP URI the outbound INVITE is placed to.
    #[serde(default = "default_b2bua_target")]
    pub target: String,
    /// RTP duration of the originated call (milliseconds).
    #[serde(default = "default_rtp_ms")]
    pub rtp_ms: u64,
}

impl Default for Outbound {
    fn default() -> Self {
        Outbound {
            enabled: default_true(),
            delay_ms: default_outbound_delay_ms(),
            target: default_b2bua_target(),
            rtp_ms: default_rtp_ms(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_outbound_delay_ms() -> u64 {
    3500
}
fn default_rtp_ms() -> u64 {
    1000
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiBridge {
    /// Tap decoded sink audio into ai-bridge sessions (VAD / barge-in).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for AiBridge {
    fn default() -> Self {
        AiBridge { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Api {
    #[serde(default = "default_api_port")]
    pub port: u16,
}

impl Default for Api {
    fn default() -> Self {
        Api {
            port: default_api_port(),
        }
    }
}

fn default_api_port() -> u16 {
    8080
}

// --------------------------------------------------------------- observ --

/// In-process observability: event bus writers (pcap + per-call traces).
#[derive(Debug, Clone, Deserialize)]
pub struct Observ {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Directory for pcap files, trace logs and status.json.
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub pcap: ObservPcap,
    #[serde(default)]
    pub trace: ObservTrace,
}

impl Default for Observ {
    fn default() -> Self {
        Observ {
            enabled: true,
            log_dir: default_log_dir(),
            log_level: default_log_level(),
            pcap: ObservPcap::default(),
            trace: ObservTrace::default(),
        }
    }
}

fn default_log_dir() -> String {
    "/var/log/zrtc".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObservPcap {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_sip_file")]
    pub sip_file: String,
    #[serde(default = "default_rtp_file")]
    pub rtp_file: String,
    #[serde(default = "default_true")]
    pub include_payload: bool,
    #[serde(default = "default_max_file_mb")]
    pub max_file_mb: u64,
}

impl Default for ObservPcap {
    fn default() -> Self {
        ObservPcap {
            enabled: true,
            sip_file: default_sip_file(),
            rtp_file: default_rtp_file(),
            include_payload: true,
            max_file_mb: default_max_file_mb(),
        }
    }
}

fn default_sip_file() -> String {
    "sip.pcap".into()
}
fn default_rtp_file() -> String {
    "rtp.pcap".into()
}
fn default_max_file_mb() -> u64 {
    512
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObservTrace {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub include_sdp: bool,
    #[serde(default = "default_true")]
    pub include_sip_bodies: bool,
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
}

impl Default for ObservTrace {
    fn default() -> Self {
        ObservTrace {
            enabled: true,
            include_sdp: true,
            include_sip_bodies: true,
            flush_interval_ms: default_flush_interval_ms(),
        }
    }
}

fn default_flush_interval_ms() -> u64 {
    100
}

// ------------------------------------------------------------------ trunk --

/// Vendor trunk peering: where to reach the provider and how to
/// authenticate. All auth fields are optional; the mode is picked by
/// `auth` (ip | digest | bearer | tls_client_cert), defaulting to `ip`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Trunk {
    /// Provider endpoint "HOST:PORT" (or "HOST" for the default port 5060).
    /// Absent/empty disables the trunk layer entirely.
    #[serde(default)]
    pub address: Option<String>,
    /// Outbound transport toward the provider: udp | tcp | tls.
    #[serde(default = "default_trunk_transport")]
    pub transport: String,
    /// Send a REGISTER on startup (register-on-start trunks).
    #[serde(default)]
    pub register: bool,
    /// SIP identity used for REGISTER (e.g. "sip:user@vendor.example").
    /// Derived from `auth_user` and the address host when absent.
    #[serde(default)]
    pub aor: Option<String>,
    /// Auth mode selector: ip | digest | bearer | tls_client_cert.
    #[serde(default)]
    pub auth: Option<String>,
    /// Digest username (also the REGISTER user part when `aor` is absent).
    #[serde(default)]
    pub auth_user: Option<String>,
    /// Digest password.
    #[serde(default)]
    pub auth_pass: Option<String>,
    /// Expected realm; used as fallback when a challenge omits it.
    #[serde(default)]
    pub auth_realm: Option<String>,
    /// Bearer mode: raw Authorization value override (sent verbatim instead
    /// of `Bearer <auth_token>`). Never logged.
    #[serde(default)]
    pub auth_header: Option<String>,
    /// Bearer token (overridable via ZRTC_TRUNK_TOKEN). Never logged.
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Client certificate for tls_client_cert mode (PEM).
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    /// Client private key for tls_client_cert mode (PEM).
    #[serde(default)]
    pub tls_key_path: Option<String>,
    /// Optional CA bundle for the client connection (PEM).
    #[serde(default)]
    pub tls_ca_path: Option<String>,
    /// OPTIONS keepalive interval in seconds; 0 disables keepalives.
    #[serde(default)]
    pub keepalive_secs: u64,
    /// Stable `+sip.instance` URN for RFC 5626 Outbound registrations
    /// (e.g. "urn:uuid:0b1e2d3c-..."). Generated per process when absent
    /// and `register = true` (a warning is logged: Outbound semantics
    /// expect the instance to survive restarts, so set this explicitly in
    /// production).
    #[serde(default)]
    pub instance_id: Option<String>,
}

fn default_trunk_transport() -> String {
    "udp".into()
}

impl Config {
    /// Applies environment overrides on top of the file config. The values
    /// are secrets and must never be logged.
    pub fn apply_trunk_env(&mut self) {
        if let Ok(v) = std::env::var("ZRTC_TRUNK_USER") {
            self.trunk.auth_user = Some(v);
        }
        if let Ok(v) = std::env::var("ZRTC_TRUNK_PASS") {
            self.trunk.auth_pass = Some(v);
        }
        if let Ok(v) = std::env::var("ZRTC_TRUNK_TOKEN") {
            self.trunk.auth_token = Some(v);
        }
    }
}

impl Config {
    /// Parses the TOML text.
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("config parse error: {e}"))
    }

    /// Loads from an explicit path.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        Self::parse(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_demo_shape() {
        let text = r#"
[sip]
udp_port = 6060
[registrar]
aor = "sip:42@x.test"
[b2bua]
routes = [{ prefix = "42", target = "sip:sink@127.0.0.1:6000" }]
"#;
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.sip.udp_port, 6060);
        assert_eq!(cfg.registrar.aor, "sip:42@x.test");
        assert_eq!(cfg.b2bua.routes[0].prefix, "42");
        assert_eq!(cfg.outbound.delay_ms, 3500, "defaults apply");
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::parse("[nope]\nx = 1\n").is_err());
    }
}
