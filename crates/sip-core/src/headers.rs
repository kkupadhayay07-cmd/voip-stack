//! Typed SIP header views over an ordered header map (RFC 3261 §20 plus
//! common extension headers). Compact forms are expanded at parse time and
//! canonical names are used in serialization.

use crate::error::{ParseError, Result};
use crate::message::Method;
use crate::uri::{Host, NameAddr, Param, TransportKind};
use std::fmt;

/// `Allow` header (token list).
pub type Allow = TokenList;
/// `Allow-Events` header (token list).
pub type AllowEvents = TokenList;
/// `Require` header (token list).
pub type Require = TokenList;
/// `Proxy-Require` header (token list).
pub type ProxyRequire = TokenList;
/// `Supported` header (token list).
pub type Supported = TokenList;
/// `Content-Type` value.
pub type ContentType = String;
/// `Content-Length` value.
pub type ContentLength = usize;
/// `Expires` value (delta-seconds).
pub type Expires = u64;
/// `Max-Forwards` value.
pub type MaxForwards = u32;
/// `Min-SE` value.
pub type MinSe = u64;
/// `Session-Expires` value.
pub type SessionExpires = u64;
/// `Retry-After` value.
pub type RetryAfter = u64;
/// `Reason` value.
pub type Reason = String;
/// `Event` value.
pub type Event = String;
/// `RAck` value.
pub type RAck = String;
/// `Subscription-State` value.
pub type SubscriptionState = String;
/// `Refer-To` value.
pub type ReferTo = NameAddr;

/// One raw header: canonical name + raw value text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Canonical header name (e.g. `Call-ID`, compact `i` expanded).
    pub name: String,
    /// Raw value (everything after the colon, trimmed).
    pub value: String,
}

/// Equality is name/value multiset equality with one order-sensitive
/// exception: the `Via` stack must match exactly (its order is protocol
/// meaningful). This makes parse(serialize(msg)) == msg hold even though
/// serialization reorders headers canonically.
impl PartialEq for HeaderMap {
    fn eq(&self, other: &Self) -> bool {
        let av: Vec<&str> = self.get_all("Via");
        let bv: Vec<&str> = other.get_all("Via");
        if av != bv {
            return false;
        }
        let mut a: Vec<&Header> = self.headers.iter().filter(|h| h.name != "Via").collect();
        let mut b: Vec<&Header> = other.headers.iter().filter(|h| h.name != "Via").collect();
        a.sort_by(|x, y| {
            (x.name.as_str(), x.value.as_str()).cmp(&(y.name.as_str(), y.value.as_str()))
        });
        b.sort_by(|x, y| {
            (x.name.as_str(), x.value.as_str()).cmp(&(y.name.as_str(), y.value.as_str()))
        });
        a == b
    }
}

/// Expands a compact header name to its canonical form (RFC 3261 §20).
pub fn canonical_name(name: &str) -> String {
    let canonical = match name.to_ascii_lowercase().as_str() {
        "i" | "call-id" => "Call-ID",
        "m" | "contact" => "Contact",
        "f" | "from" => "From",
        "t" | "to" => "To",
        "v" | "via" => "Via",
        "c" | "content-type" => "Content-Type",
        "e" | "content-encoding" => "Content-Encoding",
        "k" | "supported" => "Supported",
        "s" | "subject" => "Subject",
        "l" | "content-length" => "Content-Length",
        "cseq" => "CSeq",
        "max-forwards" => "Max-Forwards",
        "expires" => "Expires",
        "require" => "Require",
        "proxy-require" => "Proxy-Require",
        "allow" => "Allow",
        "allow-events" => "Allow-Events",
        "event" => "Event",
        "reason" => "Reason",
        "rack" => "RAck",
        "refer-to" => "Refer-To",
        "session-expires" => "Session-Expires",
        "min-se" => "Min-SE",
        "subscription-state" => "Subscription-State",
        "retry-after" => "Retry-After",
        "route" => "Route",
        "record-route" => "Record-Route",
        "authorization" => "Authorization",
        "proxy-authorization" => "Proxy-Authorization",
        "www-authenticate" => "WWW-Authenticate",
        "proxy-authenticate" => "Proxy-Authenticate",
        "user-agent" => "User-Agent",
        "server" => "Server",
        "accept" => "Accept",
        "accept-encoding" => "Accept-Encoding",
        "accept-language" => "Accept-Language",
        "date" => "Date",
        "timestamp" => "Timestamp",
        "mime-version" => "MIME-Version",
        "priority" => "Priority",
        "organization" => "Organization",
        "in-reply-to" => "In-Reply-To",
        _ => return name.to_string(),
    };
    canonical.to_string()
}

/// Ordered header section of a message.
#[derive(Debug, Clone, Eq, Default)]
pub struct HeaderMap {
    /// Raw ordered header list (crate-visible for the parser).
    pub(crate) headers: Vec<Header>,
}

impl HeaderMap {
    /// Empty map.
    pub fn new() -> HeaderMap {
        HeaderMap::default()
    }

    /// Appends a header (canonicalizing the name).
    pub fn add(&mut self, name: &str, value: impl Into<String>) {
        self.headers.push(Header {
            name: canonical_name(name),
            value: value.into(),
        });
    }

    /// Iterator over raw headers.
    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.headers.iter()
    }

    /// Number of headers.
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// First value for a (case-insensitive) header name.
    pub fn get(&self, name: &str) -> Option<&str> {
        let c = canonical_name(name);
        self.headers
            .iter()
            .find(|h| h.name == c)
            .map(|h| h.value.as_str())
    }

    /// All values for a name, in order (multi-value headers like Via).
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let c = canonical_name(name);
        self.headers
            .iter()
            .filter(|h| h.name == c)
            .map(|h| h.value.as_str())
            .collect()
    }

    /// Removes every occurrence of a name.
    pub fn remove_all(&mut self, name: &str) {
        let c = canonical_name(name);
        self.headers.retain(|h| h.name != c);
    }

    // -- typed accessors ---------------------------------------------------

    /// All `Via` headers, parsed, top first.
    pub fn via_all(&self) -> Vec<Via> {
        self.get_all("Via")
            .iter()
            .filter_map(|v| Via::parse(v).ok())
            .collect()
    }

    /// Top `Via` header.
    pub fn first_via(&self) -> Option<Via> {
        self.get("Via").and_then(|v| Via::parse(v).ok())
    }

    /// Adds a `Via` header on top (pushes to the end of the map; the map
    /// keeps insertion order and Via values are consumed top-down).
    pub fn push_via(&mut self, via: &Via) {
        self.add("Via", via.to_string());
    }

    /// `From` header.
    pub fn from(&self) -> Option<FromTo> {
        self.get("From").and_then(|v| FromTo::parse(v).ok())
    }

    /// `To` header.
    pub fn to(&self) -> Option<FromTo> {
        self.get("To").and_then(|v| FromTo::parse(v).ok())
    }

    /// `Call-ID` value.
    pub fn call_id(&self) -> Option<&str> {
        self.get("Call-ID")
    }

    /// `CSeq` header.
    pub fn cseq(&self) -> Option<CSeq> {
        self.get("CSeq").and_then(|v| CSeq::parse(v).ok())
    }

    /// Sets or replaces `CSeq`.
    pub fn set_cseq(&mut self, cseq: CSeq) {
        self.remove_all("CSeq");
        self.add("CSeq", cseq.to_string());
    }

    /// All `Contact` values as a parsed list.
    pub fn contacts(&self) -> ContactList {
        let mut list = ContactList::default();
        for v in self.get_all("Contact") {
            if let Ok(cl) = ContactList::parse(v) {
                list.addresses.extend(cl.addresses);
                list.star |= cl.star;
                list.expires_param |= cl.expires_param;
            }
        }
        list
    }

    /// `Content-Type` value.
    pub fn content_type(&self) -> Option<&str> {
        self.get("Content-Type")
    }

    /// `Content-Length` as a number.
    pub fn content_length(&self) -> Option<usize> {
        self.get("Content-Length")
            .and_then(|v| v.trim().parse().ok())
    }

    /// Replaces `Content-Length`.
    pub fn set_content_length(&mut self, len: usize) {
        self.remove_all("Content-Length");
        self.add("Content-Length", len.to_string());
    }

    /// `Max-Forwards` as a number.
    pub fn max_forwards(&self) -> Option<u32> {
        self.get("Max-Forwards").and_then(|v| v.trim().parse().ok())
    }

    /// `Expires` as a number (delta-seconds form only).
    pub fn expires(&self) -> Option<u64> {
        self.get("Expires").and_then(|v| v.trim().parse().ok())
    }

    /// `Supported` list.
    pub fn supported(&self) -> TokenList {
        self.get("Supported")
            .map(|v| TokenList::parse(v))
            .unwrap_or_default()
    }

    /// `Require` list.
    pub fn require(&self) -> TokenList {
        self.get("Require")
            .map(|v| TokenList::parse(v))
            .unwrap_or_default()
    }

    /// `Proxy-Require` list.
    pub fn proxy_require(&self) -> TokenList {
        self.get("Proxy-Require")
            .map(|v| TokenList::parse(v))
            .unwrap_or_default()
    }

    /// `Allow` list.
    pub fn allow(&self) -> TokenList {
        self.get("Allow")
            .map(|v| TokenList::parse(v))
            .unwrap_or_default()
    }

    /// `Allow-Events` (k) list.
    pub fn allow_events(&self) -> TokenList {
        self.get("Allow-Events")
            .map(|v| TokenList::parse(v))
            .unwrap_or_default()
    }

    /// `Event` header raw value.
    pub fn event(&self) -> Option<&str> {
        self.get("Event")
    }

    /// `Reason` header raw value.
    pub fn reason(&self) -> Option<&str> {
        self.get("Reason")
    }

    /// `RAck` header raw value.
    pub fn rack(&self) -> Option<&str> {
        self.get("RAck")
    }

    /// `Refer-To` header parsed as a name-addr.
    pub fn refer_to(&self) -> Option<NameAddr> {
        self.get("Refer-To").and_then(|v| NameAddr::parse(v).ok())
    }

    /// `Session-Expires` numeric value.
    pub fn session_expires(&self) -> Option<u64> {
        self.get("Session-Expires")
            .and_then(|v| v.split(';').next().unwrap_or("").trim().parse().ok())
    }

    /// `Min-SE` numeric value.
    pub fn min_se(&self) -> Option<u64> {
        self.get("Min-SE").and_then(|v| v.trim().parse().ok())
    }

    /// `Subscription-State` raw value.
    pub fn subscription_state(&self) -> Option<&str> {
        self.get("Subscription-State")
    }

    /// `Retry-After` numeric value.
    pub fn retry_after(&self) -> Option<u64> {
        self.get("Retry-After")
            .and_then(|v| v.split(';').next().unwrap_or("").trim().parse().ok())
    }

    /// `Route` set (parsed name-addrs), request order.
    pub fn route_set(&self) -> RouteSet {
        let mut routes = Vec::new();
        for v in self.get_all("Route") {
            if let Ok(n) = NameAddr::parse(v) {
                routes.push(n);
            }
        }
        RouteSet { routes }
    }

    /// `Record-Route` set (parsed name-addrs), response order.
    pub fn record_route(&self) -> RouteSet {
        let mut routes = Vec::new();
        for v in self.get_all("Record-Route") {
            if let Ok(n) = NameAddr::parse(v) {
                routes.push(n);
            }
        }
        RouteSet { routes }
    }

    /// `Authorization` / `Proxy-Authorization` (first one).
    pub fn authorization(&self) -> Option<AuthResponse> {
        self.get("Authorization")
            .or_else(|| self.get("Proxy-Authorization"))
            .and_then(|v| AuthResponse::parse(v).ok())
    }

    /// `WWW-Authenticate` / `Proxy-Authenticate` (first one).
    pub fn www_authenticate(&self) -> Option<AuthChallenge> {
        self.get("WWW-Authenticate")
            .or_else(|| self.get("Proxy-Authenticate"))
            .and_then(|v| AuthChallenge::parse(v).ok())
    }
}

// ---------------------------------------------------------------------------
// Typed header values
// ---------------------------------------------------------------------------

/// `host:port` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    /// Host part.
    pub host: Host,
    /// Optional port.
    pub port: Option<u16>,
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        Ok(())
    }
}

/// One `Via` header value (RFC 3261 §20.42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    /// Transport protocol of this hop.
    pub transport: TransportKind,
    /// `sent-by` host:port.
    pub sent_by: HostPort,
    /// `branch` parameter (must start with `z9hG4bK` on new requests).
    pub branch: Option<String>,
    /// `received` parameter (set by transports on the response path).
    pub received: Option<String>,
    /// `rport` parameter: `None` = absent, `Some(None)` = bare `rport`,
    /// `Some(Some(p))` = `rport=port`.
    pub rport: Option<Option<u16>>,
    /// Other parameters, in order.
    pub params: Vec<Param>,
}

impl Via {
    /// Parses a Via value.
    pub fn parse(s: &str) -> Result<Via> {
        let s = s.trim();
        let rest = s
            .strip_prefix("SIP/2.0/")
            .ok_or_else(|| ParseError::malformed("Via must start with SIP/2.0/"))?;
        let (proto, rest) = split_ws(rest);
        let transport = match proto.to_ascii_lowercase().as_str() {
            "udp" => TransportKind::Udp,
            "tcp" => TransportKind::Tcp,
            "tls" => TransportKind::Tls,
            "ws" => TransportKind::Ws,
            "wss" => TransportKind::Wss,
            _ => {
                return Err(ParseError::malformed(format!(
                    "unknown Via transport {proto:?}"
                )))
            }
        };
        let (hostport, params_str) = match rest.find(';') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        if hostport.is_empty() {
            return Err(ParseError::malformed("Via without sent-by"));
        }
        let (host_str, port_str) = if hostport.starts_with('[') {
            match hostport.find(']') {
                Some(close) => {
                    let h = &hostport[1..close];
                    let tail = &hostport[close + 1..];
                    (h, tail.strip_prefix(':'))
                }
                None => return Err(ParseError::malformed("unterminated IPv6 in Via")),
            }
        } else {
            match hostport.find(':') {
                Some(i) => (&hostport[..i], Some(&hostport[i + 1..])),
                None => (hostport, None),
            }
        };
        let host = Host::parse(host_str, hostport.starts_with('['))?;
        let port = match port_str {
            Some(p) if !p.is_empty() => Some(
                p.parse::<u16>()
                    .map_err(|_| ParseError::malformed("bad Via port"))?,
            ),
            _ => None,
        };
        let mut via = Via {
            transport,
            sent_by: HostPort { host, port },
            branch: None,
            received: None,
            rport: None,
            params: Vec::new(),
        };
        for p in parse_param_list(params_str)? {
            if p.name_eq("branch") {
                via.branch = p.value.clone();
            } else if p.name_eq("received") {
                via.received = p.value.clone();
            } else if p.name_eq("rport") {
                via.rport = Some(match &p.value {
                    Some(v) => v.parse().ok(),
                    None => None,
                });
            } else {
                via.params.push(p);
            }
        }
        Ok(via)
    }

    /// Effective rport value: explicit, else the sent-by port.
    pub fn effective_rport(&self) -> Option<u16> {
        self.rport.unwrap_or(None).or(self.sent_by.port)
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIP/2.0/{} {}", self.transport.via_str(), self.sent_by)?;
        if let Some(b) = &self.branch {
            write!(f, ";branch={b}")?;
        }
        if let Some(r) = &self.received {
            write!(f, ";received={r}")?;
        }
        match self.rport {
            Some(Some(p)) => write!(f, ";rport={p}")?,
            Some(None) => write!(f, ";rport")?,
            None => {}
        }
        for p in &self.params {
            write!(f, ";{p}")?;
        }
        Ok(())
    }
}

/// `From`/`To` header: name-addr with a tag (RFC 3261 §20.10/20.39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromTo {
    /// Parsed name-addr (display + URI + other params).
    pub addr: NameAddr,
    /// Tag parameter (`None` on un-tagged requests' To header).
    pub tag: Option<String>,
}

impl FromTo {
    /// Parses a From/To value.
    pub fn parse(s: &str) -> Result<FromTo> {
        let mut n = NameAddr::parse(s)?;
        let tag = n.tag.take();
        Ok(FromTo { addr: n, tag })
    }
}

impl fmt::Display for FromTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)?;
        if let Some(t) = &self.tag {
            write!(f, ";tag={t}")?;
        }
        Ok(())
    }
}

/// `CSeq` header (RFC 3261 §20.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSeq {
    /// Sequence number.
    pub seq: u32,
    /// Associated method.
    pub method: Method,
}

impl CSeq {
    /// Parses `CSeq: 314159 INVITE`.
    pub fn parse(s: &str) -> Result<CSeq> {
        let s = s.trim();
        let (num, method) = s
            .split_once(char::is_whitespace)
            .ok_or_else(|| ParseError::malformed("CSeq needs a method"))?;
        let seq = num
            .trim()
            .parse::<u32>()
            .map_err(|_| ParseError::malformed("bad CSeq number"))?;
        Ok(CSeq {
            seq,
            method: Method::parse(method.trim()),
        })
    }
}

impl fmt::Display for CSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.seq, self.method)
    }
}

/// `Contact` list (RFC 3261 §20.10): one or more name-addrs or `*`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContactList {
    /// Parsed contacts.
    pub addresses: Vec<NameAddr>,
    /// Wildcard `*` (REGISTER with expire 0).
    pub star: bool,
    /// At least one contact carried an `expires` parameter.
    pub expires_param: bool,
}

impl ContactList {
    /// Parses a Contact value (comma-separated).
    pub fn parse(s: &str) -> Result<ContactList> {
        let mut list = ContactList::default();
        let s = s.trim();
        if s == "*" {
            list.star = true;
            return Ok(list);
        }
        for part in split_commas_outside_quotes(s) {
            if part.trim() == "*" {
                list.star = true;
                continue;
            }
            list.addresses.push(NameAddr::parse(part.trim())?);
            if list
                .addresses
                .last()
                .unwrap()
                .params
                .iter()
                .any(|p| p.name_eq("expires"))
            {
                list.expires_param = true;
            }
        }
        Ok(list)
    }
}

/// Comma-separated token list (`Allow`, `Supported`, ...).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenList(pub Vec<String>);

impl TokenList {
    /// Parses a comma-separated token list.
    pub fn parse(s: &str) -> TokenList {
        TokenList(
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect(),
        )
    }

    /// Contains a token (case-insensitive)?
    pub fn has(&self, token: &str) -> bool {
        self.0.iter().any(|t| t.eq_ignore_ascii_case(token))
    }
}

impl fmt::Display for TokenList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join(", "))
    }
}

/// `Route`/`Record-Route` set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteSet {
    /// Ordered route entries.
    pub routes: Vec<NameAddr>,
}

impl RouteSet {
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Loose-routing (`;lr`) on the first route?
    pub fn first_is_lr(&self) -> bool {
        self.routes
            .first()
            .and_then(|r| r.sip_uri())
            .map(|u| u.is_lr())
            .unwrap_or(false)
    }
}

/// Digest challenge parameters (RFC 2617/7616 §`WWW-Authenticate`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthChallenge {
    /// Realm string.
    pub realm: Option<String>,
    /// Nonce string.
    pub nonce: Option<String>,
    /// Opaque string (passed through).
    pub opaque: Option<String>,
    /// Algorithm token (`MD5`, `SHA-256`, ...).
    pub algorithm: Option<String>,
    /// Qop options (comma-separated tokens).
    pub qop: Vec<String>,
    /// `stale=true` marker (nonce expired, credentials OK).
    pub stale: bool,
    /// Domain list (raw).
    pub domain: Option<String>,
    /// `userhash` flag.
    pub userhash: Option<bool>,
}

impl AuthChallenge {
    /// Parses `Digest realm="x", nonce="y", ...` (scheme token stripped).
    pub fn parse(s: &str) -> Result<AuthChallenge> {
        let mut c = AuthChallenge::default();
        let body = s.trim();
        let body = body
            .strip_prefix("Digest ")
            .or_else(|| body.strip_prefix("digest "))
            .unwrap_or(body);
        for (k, v) in parse_auth_pairs(body)? {
            match k.to_ascii_lowercase().as_str() {
                "realm" => c.realm = Some(v),
                "nonce" => c.nonce = Some(v),
                "opaque" => c.opaque = Some(v),
                "algorithm" => c.algorithm = Some(v),
                "qop" => {
                    c.qop = v
                        .split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect()
                }
                "stale" => c.stale = v.eq_ignore_ascii_case("true"),
                "domain" => c.domain = Some(v),
                "userhash" => c.userhash = Some(v.eq_ignore_ascii_case("true")),
                _ => {}
            }
        }
        Ok(c)
    }
}

/// Digest response parameters (`Authorization` header).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthResponse {
    /// Username (or hashed username when `userhash=true`).
    pub username: Option<String>,
    /// Realm.
    pub realm: Option<String>,
    /// Nonce.
    pub nonce: Option<String>,
    /// Digest URI (raw text).
    pub uri: Option<String>,
    /// The hex response digest.
    pub response: Option<String>,
    /// Algorithm token.
    pub algorithm: Option<String>,
    /// Client nonce.
    pub cnonce: Option<String>,
    /// Nonce count (`00000001`).
    pub nc: Option<String>,
    /// Chosen qop (`auth`/`auth-int`).
    pub qop: Option<String>,
    /// Opaque (echoed).
    pub opaque: Option<String>,
}

impl AuthResponse {
    /// Parses `Digest username="...", response="...", ...`.
    pub fn parse(s: &str) -> Result<AuthResponse> {
        let mut r = AuthResponse::default();
        let body = s.trim();
        let body = body
            .strip_prefix("Digest ")
            .or_else(|| body.strip_prefix("digest "))
            .unwrap_or(body);
        for (k, v) in parse_auth_pairs(body)? {
            match k.to_ascii_lowercase().as_str() {
                "username" => r.username = Some(v),
                "realm" => r.realm = Some(v),
                "nonce" => r.nonce = Some(v),
                "uri" => r.uri = Some(v),
                "response" => r.response = Some(v),
                "algorithm" => r.algorithm = Some(v),
                "cnonce" => r.cnonce = Some(v),
                "nc" => r.nc = Some(v),
                "qop" => r.qop = Some(v),
                "opaque" => r.opaque = Some(v),
                _ => {}
            }
        }
        Ok(r)
    }
}

impl fmt::Display for AuthResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn put(f: &mut fmt::Formatter<'_>, k: &str, v: &Option<String>) -> fmt::Result {
            if let Some(v) = v {
                write!(f, ", {k}=\"{v}\"")?;
            }
            Ok(())
        }
        write!(f, "Digest")?;
        put(f, "username", &self.username)?;
        put(f, "realm", &self.realm)?;
        put(f, "nonce", &self.nonce)?;
        put(f, "uri", &self.uri)?;
        put(f, "response", &self.response)?;
        if let Some(a) = &self.algorithm {
            write!(f, ", algorithm={a}")?;
        }
        put(f, "cnonce", &self.cnonce)?;
        if let Some(nc) = &self.nc {
            write!(f, ", nc={nc}")?;
        }
        if let Some(q) = &self.qop {
            write!(f, ", qop={q}")?;
        }
        put(f, "opaque", &self.opaque)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// shared low-level helpers
// ---------------------------------------------------------------------------

pub(crate) fn split_ws(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

/// Splits on commas that are outside quoted strings and angle brackets.
pub(crate) fn split_commas_outside_quotes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth_angle = 0usize;
    let mut in_quotes = false;
    let mut start = 0usize;
    let b = s.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'"' if i == 0 || b[i - 1] != b'\\' => in_quotes = !in_quotes,
            b'<' if !in_quotes => depth_angle += 1,
            b'>' if !in_quotes => depth_angle = depth_angle.saturating_sub(1),
            b',' if !in_quotes && depth_angle == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

fn parse_param_list(s: &str) -> Result<Vec<Param>> {
    let mut params = Vec::new();
    if s.is_empty() {
        return Ok(params);
    }
    for part in split_commas_outside_quotes(s) {
        for seg in part.split(';') {
            if seg.is_empty() {
                continue;
            }
            let (name, value) = match seg.find('=') {
                Some(i) => (&seg[..i], Some(seg[i + 1..].trim_matches('"').to_string())),
                None => (seg, None),
            };
            #[allow(clippy_manual_map)]
            if name.is_empty() {
                return Err(ParseError::malformed("empty parameter name"));
            }
            params.push(Param {
                name: name.to_string(),
                value,
            });
        }
    }
    Ok(params)
}

/// Parses `key="value", key2=value2` auth parameter pairs.
fn parse_auth_pairs(s: &str) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for part in split_commas_outside_quotes(s) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.find('=') {
            Some(i) => (&part[..i], part[i + 1..].trim()),
            None => (part, ""),
        };
        let v = v.trim_matches('"').to_string();
        pairs.push((k.trim().to_string(), v));
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_and_compact_forms() {
        assert_eq!(canonical_name("i"), "Call-ID");
        assert_eq!(canonical_name("m"), "Contact");
        assert_eq!(canonical_name("v"), "Via");
        assert_eq!(canonical_name("l"), "Content-Length");
        assert_eq!(canonical_name("call-id"), "Call-ID");
        assert_eq!(canonical_name("X-Custom"), "X-Custom");
    }

    #[test]
    fn via_parse_display_roundtrip() {
        let v =
            Via::parse("SIP/2.0/UDP pc33.atlanta.com:5060;branch=z9hG4bK776asdhds;rport").unwrap();
        assert_eq!(v.transport, TransportKind::Udp);
        assert_eq!(v.sent_by.host, Host::Domain("pc33.atlanta.com".into()));
        assert_eq!(v.sent_by.port, Some(5060));
        assert_eq!(v.branch.as_deref(), Some("z9hG4bK776asdhds"));
        assert_eq!(v.rport, Some(None));
        assert_eq!(
            v.to_string(),
            "SIP/2.0/UDP pc33.atlanta.com:5060;branch=z9hG4bK776asdhds;rport"
        );
        let v6 = Via::parse("SIP/2.0/TLS [2001:db8::2]:5061;branch=z9hG4bKx").unwrap();
        assert_eq!(v6.transport, TransportKind::Tls);
        assert_eq!(v6.sent_by.port, Some(5061));
        assert!(v6.to_string().starts_with("SIP/2.0/TLS [2001:db8::2]:5061"));
    }

    #[test]
    fn via_bad_inputs_rejected() {
        assert!(Via::parse("").is_err());
        assert!(Via::parse("SIP/1.0/UDP h").is_err());
        assert!(Via::parse("SIP/2.0/SMTP h").is_err());
        assert!(Via::parse("SIP/2.0/UDP").is_err());
    }

    #[test]
    fn from_to_parse() {
        let f = FromTo::parse("<sip:bob@biloxi.com>;tag=1928301774").unwrap();
        assert_eq!(f.tag.as_deref(), Some("1928301774"));
        assert_eq!(f.addr.display, None);
        let t = FromTo::parse("Alice <sip:alice@atlanta.com>").unwrap();
        assert_eq!(t.tag, None);
        assert_eq!(t.addr.display.as_deref(), Some("Alice"));
    }

    #[test]
    fn cseq_parse() {
        let c = CSeq::parse("314159 INVITE").unwrap();
        assert_eq!(c.seq, 314159);
        assert_eq!(c.method, Method::Invite);
        assert_eq!(c.to_string(), "314159 INVITE");
        assert!(CSeq::parse("abc INVITE").is_err());
        assert!(CSeq::parse("314159").is_err());
    }

    #[test]
    fn contact_list_parse() {
        let c = ContactList::parse("<sip:a@x.com>, <sip:b@y.com>;expires=3600").unwrap();
        assert_eq!(c.addresses.len(), 2);
        assert!(c.expires_param);
        assert!(ContactList::parse("*").unwrap().star);
    }

    #[test]
    fn token_list_and_helpers() {
        let t = TokenList::parse("100rel, timer, FOO");
        assert!(t.has("100rel"));
        assert!(t.has("timer"));
        assert!(t.has("foo"));
        assert_eq!(t.to_string(), "100rel, timer, FOO");
    }

    #[test]
    fn auth_challenge_parse() {
        let c = AuthChallenge::parse(
            "Digest realm=\"atlanta.com\", nonce=\"abc123\", opaque=\"zyx\", qop=\"auth,auth-int\", stale=FALSE",
        )
        .unwrap();
        assert_eq!(c.realm.as_deref(), Some("atlanta.com"));
        assert_eq!(c.nonce.as_deref(), Some("abc123"));
        assert_eq!(c.opaque.as_deref(), Some("zyx"));
        assert_eq!(c.qop, vec!["auth", "auth-int"]);
        assert!(!c.stale);
    }

    #[test]
    fn auth_response_roundtrip() {
        let r = AuthResponse {
            username: Some("bob".into()),
            realm: Some("x".into()),
            nonce: Some("n".into()),
            uri: Some("sip:a@b".into()),
            response: Some("deadbeef".into()),
            algorithm: Some("MD5".into()),
            cnonce: Some("cn".into()),
            nc: Some("00000001".into()),
            qop: Some("auth".into()),
            opaque: Some("op".into()),
        };
        let text = r.to_string();
        let r2 = AuthResponse::parse(&text).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn header_map_typed_accessors() {
        let mut m = HeaderMap::new();
        m.add("v", "SIP/2.0/UDP h1;branch=z9hG4bKa");
        m.add("Via", "SIP/2.0/TCP h2;branch=z9hG4bKb");
        m.add("f", "\"X\" <sip:x@y.com>;tag=t");
        m.add("Call-ID", "abc@def");
        m.add("CSeq", "1 INVITE");
        m.add("l", "0");
        assert_eq!(m.via_all().len(), 2);
        assert_eq!(m.first_via().unwrap().transport, TransportKind::Udp);
        assert_eq!(m.from().unwrap().tag.as_deref(), Some("t"));
        assert_eq!(m.call_id(), Some("abc@def"));
        assert_eq!(m.cseq().unwrap().seq, 1);
        assert_eq!(m.content_length(), Some(0));
        m.set_content_length(12);
        assert_eq!(m.content_length(), Some(12));
        m.set_cseq(CSeq {
            seq: 2,
            method: Method::Ack,
        });
        assert_eq!(m.cseq().unwrap().method, Method::Ack);
    }

    #[test]
    fn split_commas_respects_quotes_and_brackets() {
        let parts = split_commas_outside_quotes("\"a,b\" <sip:x@y.com>;q=0.5, <sip:z@w.com>");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "\"a,b\" <sip:x@y.com>;q=0.5");
    }
}
