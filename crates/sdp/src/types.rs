//! SDP data model + serializer.

use std::fmt;

/// Media direction (RFC 4566 §6 / RFC 3264).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum Direction {
    #[default]
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        }
    }

    pub fn parse(s: &str) -> Option<Direction> {
        Some(match s {
            "sendrecv" => Direction::SendRecv,
            "sendonly" => Direction::SendOnly,
            "recvonly" => Direction::RecvOnly,
            "inactive" => Direction::Inactive,
            _ => return None,
        })
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// DTLS setup role (RFC 5763 / RFC 4145).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupRole {
    Active,
    Passive,
    Actpass,
    Holdconn,
}

impl SetupRole {
    pub fn as_str(self) -> &'static str {
        match self {
            SetupRole::Active => "active",
            SetupRole::Passive => "passive",
            SetupRole::Actpass => "actpass",
            SetupRole::Holdconn => "holdconn",
        }
    }

    pub fn parse(s: &str) -> Option<SetupRole> {
        Some(match s {
            "active" => SetupRole::Active,
            "passive" => SetupRole::Passive,
            "actpass" => SetupRole::Actpass,
            "holdconn" => SetupRole::Holdconn,
            _ => return None,
        })
    }
}

/// `o=` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub username: String,
    pub sess_id: String,
    pub sess_version: String,
    pub net_type: String,
    pub addr_type: String,
    pub address: String,
}

/// `c=` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub net_type: String,
    pub addr_type: String,
    pub address: String,
}

impl Connection {
    /// Base address with any multicast TTL/count suffix (`a.b.c.d/ttl[/n]`) removed.
    pub fn base_address(&self) -> &str {
        match self.address.find('/') {
            Some(i) => &self.address[..i],
            None => &self.address,
        }
    }
}

/// `b=` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bandwidth {
    pub modifier: String,
    pub value: u64,
}

/// `t=` line plus its `r=` repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timing {
    pub start: u64,
    pub stop: u64,
    pub repeats: Vec<String>,
}

/// Raw `a=` attribute (`a=name` or `a=name:value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub value: Option<String>,
}

impl Attribute {
    pub fn new(name: &str, value: Option<String>) -> Attribute {
        Attribute {
            name: name.to_owned(),
            value,
        }
    }
}

/// Typed `a=rtpmap:<pt> <enc>/<clock>[/<channels>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpMap {
    pub payload: u8,
    pub encoding: String,
    pub clock_rate: u32,
    pub channels: Option<u16>,
}

/// Typed `a=fingerprint:<hash> <value>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub hash_func: String,
    pub value: String,
}

/// Typed `a=extmap:<id>[/<dir>] <uri> [<config>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtMap {
    pub id: u8,
    pub direction: Option<Direction>,
    pub uri: String,
    pub config: Option<String>,
}

/// Typed `a=ssrc:<ssrc> <attr>[:<value>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrcInfo {
    pub ssrc: u32,
    pub attr: String,
    pub value: Option<String>,
}

/// Typed `a=group:BUNDLE 0 1 2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleGroup {
    pub mids: Vec<String>,
}

/// One media description (m= section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDescription {
    pub media: String,
    pub port: u16,
    pub port_count: u16,
    pub proto: String,
    pub formats: Vec<String>,
    pub info: Option<String>,
    pub connection: Option<Connection>,
    pub bandwidths: Vec<Bandwidth>,
    /// All raw `a=` lines in encounter order (used verbatim by the serializer).
    pub attributes: Vec<Attribute>,
    /// Preserved non-attribute media lines (`i=`, `k=`).
    pub extras: Vec<(char, String)>,

    // ---- typed mirrors built during parsing ----
    pub rtpmaps: std::collections::BTreeMap<u8, RtpMap>,
    pub fmtps: std::collections::BTreeMap<u8, String>,
    pub rtcp_fb: std::collections::BTreeMap<u8, Vec<String>>,
    pub direction: Option<Direction>,
    pub rtcp_mux: bool,
    pub mid: Option<String>,
    pub ptime: Option<u16>,
    pub maxptime: Option<u16>,
    pub ice_ufrag: Option<String>,
    pub ice_pwd: Option<String>,
    pub ice_options: Option<String>,
    pub ice_candidates: Vec<String>,
    pub fingerprint: Option<Fingerprint>,
    pub setup: Option<SetupRole>,
    pub rtcp_addr: Option<(u16, String)>,
    pub extmaps: Vec<ExtMap>,
    pub ssrcs: Vec<SsrcInfo>,
}

impl MediaDescription {
    pub fn payload_types(&self) -> Vec<u8> {
        self.formats.iter().filter_map(|f| f.parse().ok()).collect()
    }

    /// Media-level attribute lookup, falling back to a session-level attribute.
    pub fn attr<'a>(&'a self, session: &'a Session, name: &str) -> Option<&'a str> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.value.as_deref())
            .or_else(|| session.attr_value(name))
    }

    pub fn has_attr(&self, session: &Session, name: &str) -> bool {
        self.attributes.iter().any(|a| a.name == name) || session.has_attr(name)
    }

    /// Effective direction: media-level overrides session-level, default sendrecv.
    pub fn effective_direction(&self, session: &Session) -> Direction {
        self.direction
            .or(session.direction)
            .unwrap_or(Direction::SendRecv)
    }
}

/// A full SDP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub version: u32,
    pub origin: Origin,
    pub name: String,
    pub info: Option<String>,
    pub connection: Option<Connection>,
    pub bandwidths: Vec<Bandwidth>,
    pub timings: Vec<Timing>,
    pub attributes: Vec<Attribute>,
    /// Preserved session-level non-attribute lines (`u=`,`e=`,`p=`,`k=`,`z=`).
    pub extras: Vec<(char, String)>,

    // ---- typed mirrors ----
    pub direction: Option<Direction>,
    pub ice_ufrag: Option<String>,
    pub ice_pwd: Option<String>,
    pub ice_options: Option<String>,
    pub fingerprint: Option<Fingerprint>,
    pub setup: Option<SetupRole>,
    pub bundle: Option<BundleGroup>,
    pub medias: Vec<MediaDescription>,
}

impl Session {
    pub fn attr_value(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.value.as_deref())
    }

    pub fn has_attr(&self, name: &str) -> bool {
        self.attributes.iter().any(|a| a.name == name)
    }
}

fn write_attr(out: &mut String, a: &Attribute) {
    out.push_str("a=");
    out.push_str(&a.name);
    if let Some(v) = &a.value {
        out.push(':');
        out.push_str(v);
    }
    out.push_str("\r\n");
}

fn write_connection(out: &mut String, c: &Connection) {
    out.push_str(&format!("c={} {} {}\r\n", c.net_type, c.addr_type, c.address));
}

fn write_bandwidths(out: &mut String, bws: &[Bandwidth]) {
    for b in bws {
        out.push_str(&format!("b={}:{}\r\n", b.modifier, b.value));
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::with_capacity(512);
        out.push_str(&format!("v={}\r\n", self.version));
        out.push_str(&format!(
            "o={} {} {} {} {} {}\r\n",
            self.origin.username,
            self.origin.sess_id,
            self.origin.sess_version,
            self.origin.net_type,
            self.origin.addr_type,
            self.origin.address
        ));
        out.push_str(&format!("s={}\r\n", self.name));
        if let Some(i) = &self.info {
            out.push_str(&format!("i={}\r\n", i));
        }
        for (_, raw) in &self.extras {
            out.push_str(raw);
            out.push_str("\r\n");
        }
        if let Some(c) = &self.connection {
            write_connection(&mut out, c);
        }
        write_bandwidths(&mut out, &self.bandwidths);
        if self.timings.is_empty() {
            out.push_str("t=0 0\r\n");
        }
        for t in &self.timings {
            out.push_str(&format!("t={} {}\r\n", t.start, t.stop));
            for r in &t.repeats {
                out.push_str(&format!("r={}\r\n", r));
            }
        }
        for a in &self.attributes {
            write_attr(&mut out, a);
        }
        for m in &self.medias {
            let port = if m.port_count > 1 {
                format!("{}/{}", m.port, m.port_count)
            } else {
                m.port.to_string()
            };
            out.push_str(&format!(
                "m={} {} {} {}\r\n",
                m.media,
                port,
                m.proto,
                m.formats.join(" ")
            ));
            if let Some(i) = &m.info {
                out.push_str(&format!("i={}\r\n", i));
            }
            for (_, raw) in &m.extras {
                out.push_str(raw);
                out.push_str("\r\n");
            }
            if let Some(c) = &m.connection {
                write_connection(&mut out, c);
            }
            write_bandwidths(&mut out, &m.bandwidths);
            for a in &m.attributes {
                write_attr(&mut out, a);
            }
        }
        f.write_str(&out)
    }
}

impl Session {
    pub fn serialize(&self) -> String {
        self.to_string()
    }
}
