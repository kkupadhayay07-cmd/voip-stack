//! SIP/SIPS/Tel URI model (RFC 3261 §19) with a panic-free parser.

use crate::error::{ParseError, Result};
use std::fmt;

/// URI scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `sip:`
    Sip,
    /// `sips:` (secure).
    Sips,
    /// `tel:` (RFC 3966).
    Tel,
}

impl Scheme {
    /// Scheme text form.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Sip => "sip",
            Scheme::Sips => "sips",
            Scheme::Tel => "tel",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Host: domain name, IPv4 or IPv6 address (RFC 3261 §25.1 `host`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// Registered domain or hostname.
    Domain(String),
    /// Dotted-quad IPv4.
    Ipv4(std::net::Ipv4Addr),
    /// Bracketed IPv6 reference.
    Ipv6(std::net::Ipv6Addr),
}

impl Host {
    /// Parses a host token. `bracketed` must be true when the text came
    /// enclosed in `[...]` (IPv6 reference form).
    pub fn parse(s: &str, bracketed: bool) -> Result<Host> {
        if s.is_empty() {
            return Err(ParseError::malformed("empty host"));
        }
        if bracketed || s.contains(':') {
            let inner = if bracketed {
                s
            } else {
                s.trim_start_matches('[').trim_end_matches(']')
            };
            let addr: std::net::Ipv6Addr = inner
                .parse()
                .map_err(|_| ParseError::malformed(format!("bad IPv6 host {s:?}")))?;
            return Ok(Host::Ipv6(addr));
        }
        if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
            return Ok(Host::Ipv4(v4));
        }
        // Domain: keep permissive (tokens, dots, hyphens); reject whitespace
        // and separators that would break serialization.
        if s.bytes()
            .any(|b| b.is_ascii_whitespace() || b == b',' || b == b';')
        {
            return Err(ParseError::malformed(format!("invalid domain {s:?}")));
        }
        Ok(Host::Domain(s.to_string()))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Domain(d) => f.write_str(d),
            Host::Ipv4(v) => write!(f, "{v}"),
            Host::Ipv6(v) => write!(f, "[{v}]"),
        }
    }
}

/// Transport parameter value (RFC 3261 §18; WS/WSS per RFC 7118).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// Default UDP transport.
    Udp,
    /// TCP.
    Tcp,
    /// TLS over TCP.
    Tls,
    /// WebSocket (RFC 7118).
    Ws,
    /// Secure WebSocket (RFC 7118).
    Wss,
}

impl TransportKind {
    /// Parameter text form (`transport=udp` etc.).
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::Udp => "udp",
            TransportKind::Tcp => "tcp",
            TransportKind::Tls => "tls",
            TransportKind::Ws => "ws",
            TransportKind::Wss => "wss",
        }
    }

    /// Uppercase form used in Via headers (`SIP/2.0/UDP`).
    pub fn via_str(self) -> &'static str {
        match self {
            TransportKind::Udp => "UDP",
            TransportKind::Tcp => "TCP",
            TransportKind::Tls => "TLS",
            TransportKind::Ws => "WS",
            TransportKind::Wss => "WSS",
        }
    }

    /// Default port for this transport (RFC 3261 §27.1 / RFC 7118 §5.3).
    pub fn default_port(self) -> u16 {
        match self {
            TransportKind::Udp | TransportKind::Tcp | TransportKind::Ws => 5060,
            TransportKind::Tls => 5061,
            TransportKind::Wss => 443,
        }
    }
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A generic URI/header parameter `name` or `name=value`.
/// Values keep their raw (possibly quoted) text; comparison is textual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// Parameter name (case-insensitive per RFC 3261; preserved as given).
    pub name: String,
    /// Raw value (without quotes) when present.
    pub value: Option<String>,
}

impl Param {
    /// Builds `name=value` (or bare `name` when `value` is `None`).
    pub fn new(name: impl Into<String>, value: Option<impl Into<String>>) -> Param {
        Param {
            name: name.into(),
            value: value.map(Into::into),
        }
    }

    /// Case-insensitive name lookup helper.
    pub fn name_eq(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

impl fmt::Display for Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Re-quote any value that is not a legal RFC 3261 `token`. The
        // angle brackets matter in practice: `+sip.instance="<urn:uuid:..>"`
        // parses to `<urn:uuid:..>` and MUST be emitted quoted again — an
        // unquoted `<` is not a generic-param value and strict peers
        // (RFC 5626/5627 implementations) reject the header outright.
        match &self.value {
            Some(v) if v.is_empty() || v.contains([';', ',', '?', '"', '<', '>']) => {
                write!(f, "{}=\"{}\"", self.name, v)
            }
            Some(v) => write!(f, "{}={}", self.name, v),
            None => f.write_str(&self.name),
        }
    }
}

/// `sip:`/`sips:` URI (RFC 3261 §19.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipUri {
    /// `sip` or `sips`.
    pub scheme: Scheme,
    /// User part (unescaped form; percent-decoding is left to the caller).
    pub user: Option<String>,
    /// Password (`user:password@`), rarely used, preserved when present.
    pub password: Option<String>,
    /// Host part.
    pub host: Host,
    /// Explicit port (transport default applied via [`SipUri::effective_port`]).
    pub port: Option<u16>,
    /// URI parameters (`transport`, `lr`, `user`, `method`, `maddr`, `ttl`, ...).
    pub params: Vec<Param>,
    /// URI headers (`?name=value&...`).
    pub headers: Vec<(String, String)>,
}

impl SipUri {
    /// Parses a full `sip:`/`sips:` URI (no display name, no angle brackets).
    pub fn parse(s: &str) -> Result<SipUri> {
        parse_sip_uri(s)
    }

    /// Whether this is a SIPS URI.
    pub fn is_secure(&self) -> bool {
        self.scheme == Scheme::Sips
    }

    /// Resolves the transport: explicit `transport=` param wins, else the
    /// scheme default (`sips` → TLS).
    pub fn transport(&self) -> TransportKind {
        if let Some(p) = self.params.iter().find(|p| p.name_eq("transport")) {
            if let Some(v) = &p.value {
                match v.to_ascii_lowercase().as_str() {
                    "udp" => return TransportKind::Udp,
                    "tcp" => return TransportKind::Tcp,
                    "tls" => return TransportKind::Tls,
                    "ws" => return TransportKind::Ws,
                    "wss" => return TransportKind::Wss,
                    _ => {}
                }
            }
        }
        if self.is_secure() {
            TransportKind::Tls
        } else {
            TransportKind::Udp
        }
    }

    /// Port to use for a request to this URI (explicit port or the
    /// transport default).
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.transport().default_port())
    }

    /// `lr` (loose routing) parameter present?
    pub fn is_lr(&self) -> bool {
        self.params.iter().any(|p| p.name_eq("lr"))
    }

    /// Host as display text (brackets IPv6).
    pub fn host_str(&self) -> String {
        self.host.to_string()
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;
        if let Some(u) = &self.user {
            write!(f, "{u}")?;
            if let Some(p) = &self.password {
                write!(f, ":{p}")?;
            }
            f.write_str("@")?;
        }
        write!(f, "{}", self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        for p in &self.params {
            write!(f, ";{p}")?;
        }
        if !self.headers.is_empty() {
            let hs: Vec<String> = self
                .headers
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            write!(f, "?{}", hs.join("&"))?;
        }
        Ok(())
    }
}

/// `tel:` URI (RFC 3966) — subscriber number plus parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelUri {
    /// Subscriber number (visual separators preserved).
    pub number: String,
    /// Parameters (`phone-context`, `extension`, ...).
    pub params: Vec<Param>,
}

impl TelUri {
    /// Parses a `tel:` URI.
    pub fn parse(s: &str) -> Result<TelUri> {
        let rest = s
            .strip_prefix("tel:")
            .ok_or_else(|| ParseError::malformed("not a tel URI"))?;
        let (number, params_str) = split_once(rest, ';');
        if number.is_empty() {
            return Err(ParseError::malformed("empty tel subscriber number"));
        }
        Ok(TelUri {
            number: percent_decode(number),
            params: parse_params(params_str)?,
        })
    }
}

impl fmt::Display for TelUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tel:{}", self.number)?;
        for p in &self.params {
            write!(f, ";{p}")?;
        }
        Ok(())
    }
}

/// Either a SIP(S) or a Tel URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    /// SIP or SIPS URI.
    Sip(SipUri),
    /// TEL URI.
    Tel(TelUri),
}

impl Addr {
    /// Parses any scheme-less-checked URI text.
    pub fn parse(s: &str) -> Result<Addr> {
        if s.len() >= 4 && s[..4].eq_ignore_ascii_case("tel:") {
            Ok(Addr::Tel(TelUri::parse(s)?))
        } else {
            Ok(Addr::Sip(SipUri::parse(s)?))
        }
    }

    /// Display host/part for routing decisions.
    pub fn host_str(&self) -> String {
        match self {
            Addr::Sip(u) => u.host_str(),
            Addr::Tel(t) => t.number.clone(),
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::Sip(u) => write!(f, "{u}"),
            Addr::Tel(t) => write!(f, "{t}"),
        }
    }
}

/// A display name with an address: `"Bob" <sip:bob@example.com>;tag=x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAddr {
    /// Optional display name (quotes stripped, escapes preserved raw).
    pub display: Option<String>,
    /// The URI.
    pub addr: Addr,
    /// `tag` parameter (From/To semantics; not part of the URI).
    pub tag: Option<String>,
    /// Additional parameters after the URI (`tag` excluded).
    pub params: Vec<Param>,
}

impl NameAddr {
    /// Parses a name-addr / addr-spec (both forms accepted).
    pub fn parse(s: &str) -> Result<NameAddr> {
        parse_name_addr(s)
    }

    /// Extracts just the URI if it is a SIP URI.
    pub fn sip_uri(&self) -> Option<&SipUri> {
        match &self.addr {
            Addr::Sip(u) => Some(u),
            Addr::Tel(_) => None,
        }
    }
}

impl fmt::Display for NameAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(d) = &self.display {
            let needs_quotes = d.contains(['"', ',', ';', '<', '>']) || d.is_empty();
            if needs_quotes {
                write!(f, "\"{}\" ", d.replace('"', "\\\""))?;
            } else {
                write!(f, "{d} ")?;
            }
        }
        write!(f, "<{}>", self.addr)?;
        for p in &self.params {
            write!(f, ";{p}")?;
        }
        if let Some(t) = &self.tag {
            write!(f, ";tag={t}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn split_once(s: &str, sep: char) -> (&str, &str) {
    match s.find(sep) {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    }
}

fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // %XX decoding is byte-wise: slicing the &str here would panic on
        // multi-byte UTF-8 following the '%' (untrusted input, RFC 3261
        // allows any octet percent-encoded).
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits `s` on `sep` occurring OUTSIDE double-quoted strings (RFC 3261
/// generic-param: a quoted-string value may contain `;`, `,` …). Backslash
/// escapes inside quotes are honored; a never-closed quote keeps consuming
/// to the end (defensive on malformed input).
fn split_outside_quotes(s: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            c if c == sep && !in_quotes => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

fn parse_params(s: &str) -> Result<Vec<Param>> {
    let mut params = Vec::new();
    if s.is_empty() {
        return Ok(params);
    }
    // Quote-aware split: `pub-gruu="sip:x@y;gr=urn:..."` must survive as
    // ONE parameter (a blind split(';') produced a phantom `gr` param and
    // destroyed the GRUU value).
    for part in split_outside_quotes(s, ';') {
        if part.is_empty() {
            continue;
        }
        let (name, value) = split_once(part, '=');
        if name.is_empty() {
            return Err(ParseError::malformed(format!(
                "empty parameter name in {part:?}"
            )));
        }
        let value = if value.is_empty() {
            None
        } else {
            Some(percent_decode(value.trim_matches('"')))
        };
        params.push(Param {
            name: name.to_string(),
            value,
        });
    }
    Ok(params)
}

fn parse_sip_uri(s: &str) -> Result<SipUri> {
    let lower = s.to_ascii_lowercase();
    let scheme = if lower.starts_with("sips:") {
        Scheme::Sips
    } else if lower.starts_with("sip:") {
        Scheme::Sip
    } else {
        return Err(ParseError::malformed(format!("not a SIP URI: {s:?}")));
    };
    if s.len() > 2048 {
        return Err(ParseError::TooLarge { limit: 2048 });
    }
    let rest = &s[if scheme == Scheme::Sips { 5 } else { 4 }..];
    // Split off ?headers first, then ;params, then userinfo@hostport.
    let (main, hdr) = split_once(rest, '?');
    let (userinfo_hostport, params_str) = split_once(main, ';');
    // Host-only URIs (`sip:atlanta.com`, no userinfo) are valid per RFC 3261
    // §19.1, so the split must only happen when an `@` is actually present —
    // and it happens at the LAST `@`, since an unescaped `@` in the user part
    // must not swallow the host.
    let (userinfo, hostport) = match userinfo_hostport.rfind('@') {
        Some(at) => (&userinfo_hostport[..at], &userinfo_hostport[at + 1..]),
        None => ("", userinfo_hostport),
    };
    let (user, password) = if userinfo_hostport.contains('@') {
        let (u, p) = split_once(userinfo, ':');
        (
            Some(u.to_string()),
            if p.is_empty() {
                None
            } else {
                Some(p.to_string())
            },
        )
    } else {
        (None, None)
    };
    // hostport: host[:port] — IPv6 must respect the bracket.
    let (host_str, port) = if hostport.starts_with('[') {
        let close = hostport
            .find(']')
            .ok_or_else(|| ParseError::malformed("unterminated IPv6 bracket"))?;
        let host = &hostport[1..close];
        let after = &hostport[close + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(
                p.parse::<u16>()
                    .map_err(|_| ParseError::malformed("bad port"))?,
            )
        } else {
            None
        };
        (host.to_string(), port)
    } else {
        let (h, p) = split_once(hostport, ':');
        let port = if p.is_empty() {
            None
        } else {
            Some(
                p.parse::<u16>()
                    .map_err(|_| ParseError::malformed("bad port"))?,
            )
        };
        (h.to_string(), port)
    };
    let host = Host::parse(
        &host_str,
        host_str.contains(':') || hostport.starts_with('['),
    )?;
    let headers = if hdr.is_empty() {
        Vec::new()
    } else {
        hdr.split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| {
                let (k, v) = split_once(kv, '=');
                (k.to_string(), v.to_string())
            })
            .collect()
    };
    Ok(SipUri {
        scheme,
        user,
        password,
        host,
        port,
        params: parse_params(params_str)?,
        headers,
    })
}

fn parse_name_addr(s: &str) -> Result<NameAddr> {
    let s = s.trim();
    // The closing '>' is searched AFTER the opening '<': a '>' inside the
    // display name or before the '<' (e.g. `"a>b" <sip:x@y>` or `><`) must
    // never make the slice bounds inverted (untrusted input).
    let (display, uri_and_params, params_str) = match s.find('<') {
        Some(lt) => {
            let close = s[lt..]
                .find('>')
                .map(|off| lt + off)
                .ok_or_else(|| ParseError::malformed("unterminated < in name-addr"))?;
            let display = s[..lt].trim();
            let display =
                if display.starts_with('"') && display.ends_with('"') && display.len() >= 2 {
                    display[1..display.len() - 1].to_string()
                } else {
                    display.to_string()
                };
            let display = if display.is_empty() {
                None
            } else {
                Some(display)
            };
            (display, &s[lt + 1..close], &s[close + 1..])
        }
        None => (None, s, ""),
    };
    let addr = Addr::parse(uri_and_params.trim())?;
    let mut params = parse_params(params_str)?;
    let mut tag = None;
    params.retain(|p| {
        if p.name_eq("tag") {
            tag = p.value.clone();
            false
        } else {
            true
        }
    });
    if display.is_none() {
        // Preserve a bare display-less form.
    }
    Ok(NameAddr {
        display,
        addr,
        tag,
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_sip_uri() {
        let u = SipUri::parse("sip:alice@atlanta.com").unwrap();
        assert_eq!(u.scheme, Scheme::Sip);
        assert_eq!(u.user.as_deref(), Some("alice"));
        assert_eq!(u.host, Host::Domain("atlanta.com".into()));
        assert_eq!(u.port, None);
        assert_eq!(u.effective_port(), 5060);
        assert_eq!(u.transport(), TransportKind::Udp);
    }

    #[test]
    fn parse_full_sip_uri() {
        let u = SipUri::parse("sips:bob:secret@192.0.2.4:5061;transport=tcp;lr?X=1&Y=2").unwrap();
        assert_eq!(u.scheme, Scheme::Sips);
        assert_eq!(u.user.as_deref(), Some("bob"));
        assert_eq!(u.password.as_deref(), Some("secret"));
        assert_eq!(u.host, Host::Ipv4("192.0.2.4".parse().unwrap()));
        assert_eq!(u.port, Some(5061));
        assert!(u.is_lr());
        assert_eq!(u.transport(), TransportKind::Tcp);
        assert_eq!(
            u.headers,
            vec![
                ("X".to_string(), "1".to_string()),
                ("Y".to_string(), "2".to_string())
            ]
        );
        assert_eq!(u.effective_port(), 5061);
    }

    #[test]
    fn parse_ipv6_uri() {
        let u = SipUri::parse("sip:alice@[2001:db8::1]:5070").unwrap();
        assert_eq!(u.host, Host::Ipv6("2001:db8::1".parse().unwrap()));
        assert_eq!(u.port, Some(5070));
        assert_eq!(u.to_string(), "sip:alice@[2001:db8::1]:5070");
    }

    #[test]
    fn parse_host_only_uri() {
        // RFC 3261 §19.1: userinfo is optional — `sip:host` must parse.
        let u = SipUri::parse("sip:atlanta.com").unwrap();
        assert_eq!(u.user, None);
        assert_eq!(u.host, Host::Domain("atlanta.com".into()));
        assert_eq!(u.port, None);
        assert_eq!(u.to_string(), "sip:atlanta.com");
        // With port / params / URI headers, still host-only.
        let u2 = SipUri::parse("sips:atlanta.com:5061;transport=tcp;lr").unwrap();
        assert_eq!(u2.user, None);
        assert_eq!(u2.port, Some(5061));
        assert_eq!(u2.transport(), TransportKind::Tcp);
        assert!(u2.is_lr());
        let u3 = SipUri::parse("sip:example.com?X=1").unwrap();
        assert_eq!(u3.user, None);
        assert_eq!(u3.headers, vec![("X".to_string(), "1".to_string())]);
        // Host-only inside a name-addr (carriers send these in To/From).
        let n = NameAddr::parse("<sip:atlanta.com>").unwrap();
        assert!(n.sip_uri().is_some());
        assert_eq!(n.addr.host_str(), "atlanta.com");
        // Unescaped `@` in the user part must not swallow the host.
        let u4 = SipUri::parse("sip:al@ice@atlanta.com").unwrap();
        assert_eq!(u4.user.as_deref(), Some("al@ice"));
        assert_eq!(u4.host, Host::Domain("atlanta.com".into()));
    }

    #[test]
    fn uri_roundtrip() {
        for s in [
            "sip:atlanta.com",
            "sip:alice@atlanta.com",
            "sips:bob@biloxi.com;transport=tls",
            "sip:+15551234567@pstn.example.com;user=phone",
            "sip:carol@[2001:db8::9]",
            "sip:dave@example.com:5080;transport=udp;lr?route=on",
            "sip:eve@example.com;method=INVITE",
        ] {
            assert_eq!(SipUri::parse(s).unwrap().to_string(), s, "roundtrip {s}");
        }
    }

    #[test]
    fn rejects_bad_uris() {
        assert!(SipUri::parse("http://example.com").is_err());
        assert!(SipUri::parse("sip:").is_err());
        assert!(SipUri::parse("sip:alice@").is_err());
        assert!(SipUri::parse("sip:@").is_err());
        assert!(SipUri::parse("sip:alice@[2001:db8::x]").is_err());
        assert!(SipUri::parse("sip:alice@example.com:notaport").is_err());
    }

    #[test]
    fn instance_and_gruu_params_roundtrip_quoted() {
        // RFC 5626 §9.1 / RFC 5627: `+sip.instance` carries a URN and is
        // emitted as a quoted string. A parse→serialize cycle must keep it
        // quoted (an unquoted `<` is not a legal generic-param value).
        let n =
            NameAddr::parse("<sip:alice@example.com>;+sip.instance=\"<urn:uuid:f81d>\";reg-id=1")
                .expect("instance contact parses");
        let out = n.to_string();
        assert!(
            out.contains("+sip.instance=\"<urn:uuid:f81d>\""),
            "instance stays quoted: {out}"
        );
        assert!(out.contains("reg-id=1"));
        assert_eq!(
            NameAddr::parse(&out).expect("re-parse").params,
            n.params,
            "params survive the roundtrip unchanged"
        );
        // `gr` (GRUU URI param) keeps its unquoted form both ways.
        let g = SipUri::parse("sip:alice@example.com;gr=urn:uuid:f81d").unwrap();
        assert_eq!(
            g.to_string(),
            "sip:alice@example.com;gr=urn:uuid:f81d",
            "gr round-trips verbatim"
        );
        // pub-gruu values contain `;`, so they must re-quote as well.
        let p = NameAddr::parse(
            "<sip:alice@example.com>;pub-gruu=\"sip:alice@example.com;gr=urn:uuid:f81d\"",
        )
        .expect("pub-gruu contact parses");
        let pout = p.to_string();
        assert!(
            pout.contains("pub-gruu=\"sip:alice@example.com;gr=urn:uuid:f81d\""),
            "pub-gruu stays quoted: {pout}"
        );
    }

    #[test]
    fn tel_uri_parse_and_display() {
        let t = TelUri::parse("tel:+15551234;phone-context=+1").unwrap();
        assert_eq!(t.number, "+15551234");
        assert_eq!(t.params.len(), 1);
        assert_eq!(t.to_string(), "tel:+15551234;phone-context=+1");
        assert!(matches!(Addr::parse("tel:123").unwrap(), Addr::Tel(_)));
    }

    #[test]
    fn name_addr_forms() {
        let n = NameAddr::parse("\"Bob\" <sip:bob@biloxi.com>;tag=a84b4c").unwrap();
        assert_eq!(n.display.as_deref(), Some("Bob"));
        assert_eq!(n.tag.as_deref(), Some("a84b4c"));
        assert_eq!(n.addr.host_str(), "biloxi.com");
        let n2 = NameAddr::parse("<sip:x@y.com>;tag=t1").unwrap();
        assert_eq!(n2.display, None);
        assert_eq!(n2.tag.as_deref(), Some("t1"));
        let bare = NameAddr::parse("sip:bare@example.com").unwrap();
        assert_eq!(bare.display, None);
        assert_eq!(bare.tag, None);
        assert_eq!(n.to_string(), "Bob <sip:bob@biloxi.com>;tag=a84b4c");
    }

    #[test]
    fn quoted_param_values() {
        let u = SipUri::parse("sip:a@b.c;method=\"INVITE\"").unwrap();
        assert_eq!(u.params[0].value.as_deref(), Some("INVITE"));
    }

    /// Regression: `To: ><` used to make `s[lt+1..close]` slice with
    /// `close < lt+1` and panic on a single unauthenticated packet.
    #[test]
    fn name_addr_inverted_angle_brackets_is_an_error_not_a_panic() {
        assert!(NameAddr::parse("><").is_err());
        assert!(NameAddr::parse("> <").is_err());
        // Stray '>' before the display is tolerated leniently (no panic).
        assert!(NameAddr::parse(">\"x\" <sip:a@b>").is_ok());
        // Unterminated '<' stays a clean error.
        assert!(NameAddr::parse("<sip:a@b").is_err());
    }

    /// Regression: a '>' inside a quoted display name must not defeat the
    /// closing-bracket search.
    #[test]
    fn name_addr_gt_inside_display_quotes() {
        let n = NameAddr::parse("\"a>b\" <sip:x@y>").unwrap();
        assert_eq!(n.display.as_deref(), Some("a>b"));
        assert_eq!(n.addr.host_str(), "y");
    }

    /// Regression: percent-decoding is byte-wise — a '%' followed by
    /// multi-byte UTF-8 used to slice inside a char boundary and panic.
    #[test]
    fn percent_decode_multibyte_after_percent_does_not_panic() {
        // '%' + multi-byte é (0xC3 0xA9): neither a panic nor a mangled decode.
        let s = "p=%a\u{e9}";
        let out = percent_decode(s);
        assert!(out.contains('\u{FFFD}') || out.starts_with("p="), "{out:?}");
        // Valid escapes still decode; trailing garbage passes through.
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%41%42"), "AB");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("end%4"), "end%4");
        // High bytes round-trip through the lossy conversion untouched.
        assert_eq!(percent_decode("caf\u{e9}"), "café");
    }
}
