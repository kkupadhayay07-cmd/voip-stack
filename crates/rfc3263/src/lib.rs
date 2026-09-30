//! # rfc3263
//!
//! SIP server discovery per [RFC 3263]: locate the host and port a SIP
//! request should be sent to, using DNS NAPTR, SRV and A/AAAA records.
//!
//! Resolution policy (`Resolver::resolve`), matching RFC 3263 §4.2:
//!
//! 1. IP-literal target → no DNS at all.
//! 2. Explicit port → SRV is skipped (an explicit port pins the endpoint);
//!    A/AAAA on the target with that port.
//! 3. No transport known → NAPTR (RFC 2915) selects the protocol from the
//!    service field ("SIP+D2U" / "SIP+D2T" / "SIPS+D2T"), S-flag records
//!    only; the replacement key becomes the SRV query name.
//! 4. Transport known, no port → SRV `_sip._udp.<host>` (or the tcp/sips
//!    variants); records are ordered by RFC 2782 (priority, then weighted
//!    random with zero-weight records last) and each target's A/AAAA is
//!    returned in order.
//! 5. No SRV/NAPTR data → plain A/AAAA with the default port (5060, or
//!    5061 for TLS).
//!
//! Deliberate gaps (documented): NAPTR regexp rewriting is parsed but not
//! applied (regexp-only NAPTRs are skipped); A-flag NAPTRs are not followed;
//! no DNSSEC validation. Failover *within one resolve* is automatic (SRV
//! targets whose A/AAAA fail are skipped); re-resolving on connection
//! timeouts belongs to the calling transaction layer.
//!
//! Zero dependencies: blocking std sockets only, so the crate drops into
//! any component of the stack.
//!
//! [RFC 3263]: https://datatracker.ietf.org/doc/html/rfc3263
//! [RFC 2915]: https://datatracker.ietf.org/doc/html/rfc2915

#![forbid(unsafe_code)]

pub mod client;
pub mod wire;

pub use client::DnsClient;
pub use wire::{
    encode_query, parse_response, DnsError, Message, NaptrRecord, Record, SrvRecord, QTYPE_A,
    QTYPE_AAAA, QTYPE_NAPTR, QTYPE_SRV,
};

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// SIP transport for discovery purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipTransport {
    Udp,
    Tcp,
    Tls,
}

impl SipTransport {
    /// Default port when nothing else pins one (RFC 3261 §19.1.2).
    pub fn default_port(self) -> u16 {
        match self {
            SipTransport::Tls => 5061,
            _ => 5060,
        }
    }

    /// RFC 3263 §4.1 service token for NAPTR matching.
    pub fn naptr_service(self) -> &'static str {
        match self {
            SipTransport::Udp => "SIP+D2U",
            SipTransport::Tcp => "SIP+D2T",
            SipTransport::Tls => "SIPS+D2T",
        }
    }

    /// RFC 2782 SRV key prefix: `_sip._udp.host` / `_sip._tcp` / `_sips._tcp`.
    pub fn srv_prefix(self) -> &'static str {
        match self {
            SipTransport::Udp => "_sip._udp",
            SipTransport::Tcp => "_sip._tcp",
            SipTransport::Tls => "_sips._tcp",
        }
    }

    /// Full SRV query name for this transport and host (lowercased: DNS
    /// names are case-insensitive and resolvers standardize on lowercase).
    pub fn srv_name(self, host: &str) -> String {
        format!(
            "{}.{}",
            self.srv_prefix(),
            host.trim_end_matches('.').to_ascii_lowercase()
        )
    }
}

/// Maps a NAPTR service string onto a SIP transport (RFC 3263 §4.1).
fn naptr_service_transport(service: &str) -> Option<SipTransport> {
    match service.to_ascii_uppercase().as_str() {
        "SIP+D2U" => Some(SipTransport::Udp),
        "SIP+D2T" => Some(SipTransport::Tcp),
        "SIPS+D2T" => Some(SipTransport::Tls),
        _ => None,
    }
}

/// Why a resolution failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The system resolver configuration has no usable nameserver.
    NoResolver(String),
    /// Socket/transport failure; carries the DNS or I/O error text.
    Transport(String),
    /// The server answered with a non-zero RCODE (3 = NXDOMAIN, 2 = SERVFAIL).
    Rcode(u8),
    /// Every candidate path produced zero usable addresses.
    NoAddresses,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::NoResolver(e) => write!(f, "no nameserver available: {e}"),
            ResolveError::Transport(e) => write!(f, "dns transport failure: {e}"),
            ResolveError::Rcode(rc) => write!(f, "dns server refused (rcode {rc})"),
            ResolveError::NoAddresses => write!(f, "no addresses found for target"),
        }
    }
}

impl std::error::Error for ResolveError {}

fn transport_err(e: DnsError) -> ResolveError {
    ResolveError::Transport(e.to_string())
}

/// RFC 2782 ordering: ascending priority; within one priority a weighted
/// random shuffle where weight-0 records run last.
fn order_srv(records: &mut [SrvRecord], seed: u64) {
    records.sort_by_key(|r| r.priority);
    let mut rng = XorShift(seed | 1);
    let mut start = 0;
    while start < records.len() {
        let mut end = start + 1;
        while end < records.len() && records[end].priority == records[start].priority {
            end += 1;
        }
        shuffle_weighted(&mut records[start..end], &mut rng);
        start = end;
    }
}

/// Weighted shuffle (RFC 2782 §"Weight" field): repeatedly pick a record
/// with probability weight/total among the remaining non-zero-weight
/// records; zero-weight records run last in their original order.
fn shuffle_weighted(group: &mut [SrvRecord], rng: &mut XorShift) {
    let mut remaining: Vec<SrvRecord> = group.to_vec();
    let mut picked = Vec::with_capacity(group.len());
    while !remaining.is_empty() {
        let total: u64 = remaining.iter().map(|r| r.weight as u64).sum();
        if total == 0 {
            break; // only zero-weight records left: keep their order (run last)
        }
        let mut dart = rng.next() % total;
        let mut chosen = remaining.len();
        for (i, r) in remaining.iter().enumerate() {
            if r.weight == 0 {
                continue;
            }
            if dart < r.weight as u64 {
                chosen = i;
                break;
            }
            dart -= r.weight as u64;
        }
        if chosen == remaining.len() {
            // Defensive: land on the first non-zero-weight record.
            chosen = remaining.iter().position(|r| r.weight > 0).unwrap_or(0);
        }
        picked.push(remaining.remove(chosen));
    }
    picked.extend(remaining);
    group.clone_from_slice(&picked);
}

/// Tiny xorshift64 PRNG so RFC 2782 weighting needs no external rand dep
/// and tests can pin a seed for deterministic orderings.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// SIP server discovery resolver. Cloning is cheap ([`DnsClient`] is a
/// plain struct); resolution is blocking.
#[derive(Debug, Clone)]
pub struct Resolver {
    client: DnsClient,
    /// Seed for RFC 2782 weighted ordering. Fixed in tests, clock-derived
    /// otherwise.
    seed: u64,
}

impl Resolver {
    pub fn with_server(server: SocketAddr) -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
            .unwrap_or(1);
        Resolver {
            client: DnsClient::new(server, client::DEFAULT_TIMEOUT),
            seed,
        }
    }

    /// Test-friendly constructor: explicit server, timeout and PRNG seed.
    pub fn with_server_timeout(server: SocketAddr, timeout: Duration, seed: u64) -> Self {
        Resolver {
            client: DnsClient::new(server, timeout),
            seed,
        }
    }

    /// Builds a resolver from the system configuration: the first
    /// `nameserver` entry of /etc/resolv.conf on port 53. Errors when none
    /// can be found — callers should then fall back to the libc resolver.
    pub fn system() -> Result<Self, ResolveError> {
        let text = std::fs::read_to_string("/etc/resolv.conf")
            .map_err(|e| ResolveError::NoResolver(format!("cannot read /etc/resolv.conf: {e}")))?;
        let ns = parse_resolv_conf(&text)
            .ok_or_else(|| ResolveError::NoResolver("no nameserver line".to_string()))?;
        Ok(Resolver::with_server(SocketAddr::new(ns, 53)))
    }

    /// Queries SRV at a FULL SRV query name (e.g. `_sip._udp.example.com`
    /// — build one with [`SipTransport::srv_name`]), drops "." targets, and
    /// returns the records in RFC 2782 order.
    pub fn lookup_srv(&self, srv_query_name: &str) -> Result<Vec<SrvRecord>, ResolveError> {
        let msg = self
            .client
            .query(srv_query_name.trim_end_matches('.'), QTYPE_SRV)
            .map_err(transport_err)?;
        if msg.rcode != 0 {
            return Err(ResolveError::Rcode(msg.rcode));
        }
        let mut srvs: Vec<SrvRecord> = msg
            .records
            .into_iter()
            .filter_map(|r| match r {
                Record::Srv(s) if !s.target.is_empty() => Some(s),
                _ => None,
            })
            .collect();
        order_srv(&mut srvs, self.seed);
        Ok(srvs)
    }

    /// Queries NAPTR for a host, returning SIP-relevant records sorted by
    /// (order, preference) per RFC 2915.
    pub fn lookup_naptr(&self, host: &str) -> Result<Vec<NaptrRecord>, ResolveError> {
        let msg = self
            .client
            .query(host.trim_end_matches('.'), QTYPE_NAPTR)
            .map_err(transport_err)?;
        if msg.rcode != 0 {
            return Err(ResolveError::Rcode(msg.rcode));
        }
        let mut naptrs: Vec<NaptrRecord> = msg
            .records
            .into_iter()
            .filter_map(|r| match r {
                Record::Naptr(n) => Some(n),
                _ => None,
            })
            .collect();
        naptrs.sort_by_key(|n| (n.order, n.preference));
        Ok(naptrs)
    }

    /// Queries A and AAAA for a host. One failing family is tolerated when
    /// the other answers; both failing surfaces the error.
    pub fn lookup_ips(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let host = host.trim_end_matches('.');
        let mut ips = Vec::new();
        let mut last_err: Option<ResolveError> = None;
        match self.client.query(host, QTYPE_A) {
            Ok(m) if m.rcode == 0 => ips.extend(m.records.into_iter().filter_map(|r| match r {
                Record::A { addr, .. } => Some(IpAddr::V4(addr)),
                _ => None,
            })),
            Ok(m) => last_err = Some(ResolveError::Rcode(m.rcode)),
            Err(e) => last_err = Some(transport_err(e)),
        }
        match self.client.query(host, QTYPE_AAAA) {
            Ok(m) if m.rcode == 0 => ips.extend(m.records.into_iter().filter_map(|r| match r {
                Record::Aaaa { addr, .. } => Some(IpAddr::V6(addr)),
                _ => None,
            })),
            Ok(m) if ips.is_empty() => last_err = Some(ResolveError::Rcode(m.rcode)),
            Ok(_) => {}
            Err(e) if ips.is_empty() => return Err(transport_err(e)),
            Err(_) => {}
        }
        if ips.is_empty() {
            Err(last_err.unwrap_or(ResolveError::NoAddresses))
        } else {
            Ok(ips)
        }
    }

    /// Full RFC 3263 resolution. Returns the ordered candidate list.
    ///
    /// - `transport == None` triggers NAPTR protocol selection.
    /// - `port == Some(p)` skips NAPTR/SRV and resolves the host directly.
    pub fn resolve(
        &self,
        host: &str,
        transport: Option<SipTransport>,
        port: Option<u16>,
    ) -> Result<Vec<SocketAddr>, ResolveError> {
        let host = host.trim_end_matches('.');
        let default_port = |t: Option<SipTransport>| match t {
            Some(SipTransport::Tls) => 5061u16,
            _ => 5060u16,
        };

        // 1. IP literal: never consult DNS. Bracketed IPv6 ("[2001:db8::1]")
        // and bare forms both parse.
        let literal = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = literal.parse::<IpAddr>() {
            let p = port.unwrap_or_else(|| default_port(transport));
            return Ok(vec![SocketAddr::new(ip, p)]);
        }

        // 2. Explicit port pins the endpoint: A/AAAA only.
        if let Some(p) = port {
            let ips = self.lookup_ips(host)?;
            if ips.is_empty() {
                return Err(ResolveError::NoAddresses);
            }
            return Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, p)).collect());
        }

        // 3. No transport: NAPTR selects the protocol (S-flag records only).
        if transport.is_none() {
            let naptrs = self.lookup_naptr(host).unwrap_or_default();
            for n in &naptrs {
                if !n.flags.eq_ignore_ascii_case("s") {
                    continue; // A/U-flag NAPTRs unsupported (documented gap)
                }
                let Some(t) = naptr_service_transport(&n.service) else {
                    continue;
                };
                // RFC 2915/3263: a non-"." replacement IS the next query
                // key (already a full SRV name for S-flag records); when the
                // field is empty (or "." — RFC 2782 "service decidedly not
                // available"), we synthesize the RFC 3263 SRV key for the
                // selected transport instead of using the owner name.
                let srv_key = if n.replacement.is_empty() || n.replacement == "." {
                    t.srv_name(host)
                } else {
                    n.replacement.trim_end_matches('.').to_string()
                };
                if let Ok(srvs) = self.lookup_srv(&srv_key) {
                    if !srvs.is_empty() {
                        if let Ok(addrs) = self.srv_to_addrs(&srvs) {
                            return Ok(addrs);
                        }
                    }
                }
            }
            // NAPTR produced nothing usable: fall through with UDP.
        }

        // 4. SRV for the known (or defaulted) transport.
        let t = transport.unwrap_or(SipTransport::Udp);
        let srvs = self.lookup_srv(&t.srv_name(host)).unwrap_or_default();
        if !srvs.is_empty() {
            return self.srv_to_addrs(&srvs);
        }

        // 5. Plain A/AAAA fallback with the default port.
        let ips = self.lookup_ips(host)?;
        if ips.is_empty() {
            return Err(ResolveError::NoAddresses);
        }
        let p = default_port(transport);
        Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, p)).collect())
    }

    /// Resolves each SRV target; targets whose A/AAAA fail are skipped
    /// (failover to the next candidate), matching RFC 3263's client-side
    /// server-selection intent.
    fn srv_to_addrs(&self, srvs: &[SrvRecord]) -> Result<Vec<SocketAddr>, ResolveError> {
        let mut out = Vec::new();
        for s in srvs {
            if s.target.is_empty() || s.target == "." {
                continue;
            }
            if let Ok(ips) = self.lookup_ips(&s.target) {
                for ip in ips {
                    out.push(SocketAddr::new(ip, s.port));
                }
            }
        }
        if out.is_empty() {
            Err(ResolveError::NoAddresses)
        } else {
            Ok(out)
        }
    }
}

/// Extracts the first `nameserver` address from resolv.conf content.
pub fn parse_resolv_conf(text: &str) -> Option<IpAddr> {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            let ip = rest.trim();
            if let Ok(addr) = ip.parse::<IpAddr>() {
                return Some(addr);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::fake::FakeDns;
    use crate::wire::canned::{response, Rr};
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SEED: u64 = 0x5EED_5EED_5EED_5EED;

    fn route_a(routes: &mut HashMap<(String, u16), Vec<u8>>, name: &str, ip: Ipv4Addr) {
        routes.insert(
            (name.to_string(), QTYPE_A),
            response(0, name, QTYPE_A, &[(name, Rr::A(ip))]),
        );
    }

    #[test]
    fn ip_literal_never_queries_dns() {
        let dns = FakeDns::spawn(HashMap::new(), None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);
        let out = r
            .resolve("198.51.100.5", Some(SipTransport::Udp), Some(6060))
            .unwrap();
        assert_eq!(
            out,
            vec!["198.51.100.5:6060".parse::<SocketAddr>().unwrap()]
        );
        let out = r.resolve("[2001:db8::9]", None, None).unwrap();
        assert_eq!(
            out,
            vec!["[2001:db8::9]:5060".parse::<SocketAddr>().unwrap()]
        );
        let out = r
            .resolve("2001:db8::7", Some(SipTransport::Tls), None)
            .unwrap();
        assert_eq!(
            out,
            vec!["[2001:db8::7]:5061".parse::<SocketAddr>().unwrap()]
        );
        assert!(dns.queries.lock().unwrap().is_empty());
        dns.shutdown();
    }

    #[test]
    fn explicit_port_resolves_a_records_without_srv() {
        let mut routes = HashMap::new();
        route_a(&mut routes, "pbx.example.net", Ipv4Addr::new(192, 0, 2, 10));
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        let out = r
            .resolve("pbx.example.net", Some(SipTransport::Udp), Some(6070))
            .unwrap();
        assert_eq!(out, vec!["192.0.2.10:6070".parse::<SocketAddr>().unwrap()]);

        let seen = dns.queries.lock().unwrap().clone();
        assert!(!seen.iter().any(|(n, _)| n.starts_with("_sip.")));
        assert!(seen.contains(&("pbx.example.net".to_string(), QTYPE_A)));
        dns.shutdown();
    }

    #[test]
    fn srv_path_orders_by_priority_and_resolves_targets() {
        let mut routes = HashMap::new();
        routes.insert(
            ("_sip._udp.example.com".to_string(), QTYPE_SRV),
            response(
                0,
                "_sip._udp.example.com",
                QTYPE_SRV,
                &[
                    (
                        "_sip._udp.example.com",
                        Rr::Srv {
                            priority: 20,
                            weight: 0,
                            port: 5070,
                            target: "backup.example.net".into(),
                            ttl: 60,
                        },
                    ),
                    (
                        "_sip._udp.example.com",
                        Rr::Srv {
                            priority: 10,
                            weight: 0,
                            port: 5060,
                            target: "primary.example.net".into(),
                            ttl: 60,
                        },
                    ),
                ],
            ),
        );
        route_a(
            &mut routes,
            "primary.example.net",
            Ipv4Addr::new(192, 0, 2, 1),
        );
        route_a(
            &mut routes,
            "backup.example.net",
            Ipv4Addr::new(192, 0, 2, 2),
        );
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        let out = r
            .resolve("example.com", Some(SipTransport::Udp), None)
            .unwrap();
        assert_eq!(
            out,
            vec![
                "192.0.2.1:5060".parse::<SocketAddr>().unwrap(),
                "192.0.2.2:5070".parse::<SocketAddr>().unwrap(),
            ]
        );
        dns.shutdown();
    }

    #[test]
    fn srv_weight_zero_records_run_last_within_priority() {
        let mut routes = HashMap::new();
        routes.insert(
            ("_sip._tcp.example.com".to_string(), QTYPE_SRV),
            response(
                0,
                "_sip._tcp.example.com",
                QTYPE_SRV,
                &[
                    (
                        "_sip._tcp.example.com",
                        Rr::Srv {
                            priority: 1,
                            weight: 0,
                            port: 5060,
                            target: "w0.example.net".into(),
                            ttl: 60,
                        },
                    ),
                    (
                        "_sip._tcp.example.com",
                        Rr::Srv {
                            priority: 1,
                            weight: 1,
                            port: 5061,
                            target: "w1.example.net".into(),
                            ttl: 60,
                        },
                    ),
                ],
            ),
        );
        route_a(&mut routes, "w0.example.net", Ipv4Addr::new(192, 0, 2, 3));
        route_a(&mut routes, "w1.example.net", Ipv4Addr::new(192, 0, 2, 4));
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        let srvs = r
            .lookup_srv(&SipTransport::Tcp.srv_name("example.com"))
            .unwrap();
        assert_eq!(srvs[0].target, "w1.example.net"); // weight 1 first
        assert_eq!(srvs[1].target, "w0.example.net"); // weight 0 last
        dns.shutdown();
    }

    #[test]
    fn srv_unresolvable_targets_are_skipped_failover_to_next() {
        let mut routes = HashMap::new();
        routes.insert(
            ("_sip._udp.example.com".to_string(), QTYPE_SRV),
            response(
                0,
                "_sip._udp.example.com",
                QTYPE_SRV,
                &[
                    (
                        "_sip._udp.example.com",
                        Rr::Srv {
                            priority: 1,
                            weight: 0,
                            port: 5060,
                            target: "dead.example.net".into(),
                            ttl: 60,
                        },
                    ),
                    (
                        "_sip._udp.example.com",
                        Rr::Srv {
                            priority: 2,
                            weight: 0,
                            port: 5060,
                            target: "alive.example.net".into(),
                            ttl: 60,
                        },
                    ),
                ],
            ),
        );
        route_a(
            &mut routes,
            "alive.example.net",
            Ipv4Addr::new(192, 0, 2, 9),
        );
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        let out = r
            .resolve("example.com", Some(SipTransport::Udp), None)
            .unwrap();
        assert_eq!(out, vec!["192.0.2.9:5060".parse::<SocketAddr>().unwrap()]);
        dns.shutdown();
    }

    #[test]
    fn srv_absent_falls_back_to_a_with_default_port() {
        let mut routes = HashMap::new();
        route_a(&mut routes, "example.com", Ipv4Addr::new(192, 0, 2, 20));
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        let out = r
            .resolve("example.com", Some(SipTransport::Udp), None)
            .unwrap();
        assert_eq!(out, vec!["192.0.2.20:5060".parse::<SocketAddr>().unwrap()]);

        let out = r
            .resolve("example.com", Some(SipTransport::Tls), None)
            .unwrap();
        assert_eq!(out, vec!["192.0.2.20:5061".parse::<SocketAddr>().unwrap()]);
        dns.shutdown();
    }

    #[test]
    fn aaaa_only_host_resolves_over_ipv6() {
        let mut routes = HashMap::new();
        routes.insert(
            ("example.com".to_string(), QTYPE_AAAA),
            response(
                0,
                "example.com",
                QTYPE_AAAA,
                &[(
                    "example.com",
                    Rr::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42)),
                )],
            ),
        );
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        let out = r
            .resolve("example.com", Some(SipTransport::Tcp), None)
            .unwrap();
        assert_eq!(
            out,
            vec!["[2001:db8::42]:5060".parse::<SocketAddr>().unwrap()]
        );
        dns.shutdown();
    }

    #[test]
    fn naptr_s_flag_selects_transport_and_replacement() {
        let mut routes = HashMap::new();
        routes.insert(
            ("example.com".to_string(), QTYPE_NAPTR),
            response(
                0,
                "example.com",
                QTYPE_NAPTR,
                &[
                    (
                        "example.com",
                        Rr::Naptr {
                            order: 10,
                            preference: 20,
                            flags: "S",
                            service: "SIP+D2U",
                            regexp: "",
                            replacement: "_sip._udp.trunk.example.net",
                            ttl: 300,
                        },
                    ),
                    (
                        "example.com",
                        Rr::Naptr {
                            order: 5,
                            preference: 10,
                            flags: "S",
                            service: "SIP+D2T",
                            regexp: "",
                            replacement: "_sip._tcp.trunk.example.net",
                            ttl: 300,
                        },
                    ),
                ],
            ),
        );
        routes.insert(
            ("_sip._tcp.trunk.example.net".to_string(), QTYPE_SRV),
            response(
                0,
                "_sip._tcp.trunk.example.net",
                QTYPE_SRV,
                &[(
                    "_sip._tcp.trunk.example.net",
                    Rr::Srv {
                        priority: 1,
                        weight: 0,
                        port: 5060,
                        target: "tcp-gw.example.net".into(),
                        ttl: 60,
                    },
                )],
            ),
        );
        routes.insert(
            ("_sip._udp.trunk.example.net".to_string(), QTYPE_SRV),
            response(
                0,
                "_sip._udp.trunk.example.net",
                QTYPE_SRV,
                &[(
                    "_sip._udp.trunk.example.net",
                    Rr::Srv {
                        priority: 1,
                        weight: 0,
                        port: 6060,
                        target: "udp-gw.example.net".into(),
                        ttl: 60,
                    },
                )],
            ),
        );
        route_a(
            &mut routes,
            "tcp-gw.example.net",
            Ipv4Addr::new(192, 0, 2, 30),
        );
        route_a(
            &mut routes,
            "udp-gw.example.net",
            Ipv4Addr::new(192, 0, 2, 31),
        );
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        // transport=None: NAPTR drives selection; order 5 (SIP+D2T) wins.
        let out = r.resolve("example.com", None, None).unwrap();
        assert_eq!(out, vec!["192.0.2.30:5060".parse::<SocketAddr>().unwrap()]);
        {
            let seen = dns.queries.lock().unwrap();
            assert!(seen.contains(&("example.com".to_string(), QTYPE_NAPTR)));
            // UDP SRV was never queried: the order-5 TCP NAPTR won first.
            assert!(!seen.iter().any(|(n, _)| n == "_sip._udp.trunk.example.net"));
        }
        dns.shutdown();
    }

    #[test]
    fn naptr_regexp_only_and_non_sip_records_are_skipped() {
        let mut routes = HashMap::new();
        routes.insert(
            ("example.com".to_string(), QTYPE_NAPTR),
            response(
                0,
                "example.com",
                QTYPE_NAPTR,
                &[
                    (
                        "example.com",
                        Rr::Naptr {
                            order: 1,
                            preference: 1,
                            flags: "S",
                            service: "E2U+sip", // ENUM service, not RFC 3263
                            regexp: "",
                            replacement: "_sip._udp.enum.example.net",
                            ttl: 300,
                        },
                    ),
                    (
                        "example.com",
                        Rr::Naptr {
                            order: 2,
                            preference: 1,
                            flags: "A", // A-flag: unsupported (documented)
                            service: "SIP+D2U",
                            regexp: "",
                            replacement: "",
                            ttl: 300,
                        },
                    ),
                ],
            ),
        );
        route_a(&mut routes, "example.com", Ipv4Addr::new(192, 0, 2, 40));
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        // Nothing usable from NAPTR -> SRV (absent) -> A fallback.
        let out = r.resolve("example.com", None, None).unwrap();
        assert_eq!(out, vec!["192.0.2.40:5060".parse::<SocketAddr>().unwrap()]);
        dns.shutdown();
    }

    #[test]
    fn naptr_without_replacement_uses_owner_name_for_srv() {
        let mut routes = HashMap::new();
        routes.insert(
            ("example.com".to_string(), QTYPE_NAPTR),
            response(
                0,
                "example.com",
                QTYPE_NAPTR,
                &[(
                    "example.com",
                    Rr::Naptr {
                        order: 1,
                        preference: 1,
                        flags: "S",
                        service: "SIP+D2U",
                        regexp: "",
                        replacement: ".",
                        ttl: 300,
                    },
                )],
            ),
        );
        routes.insert(
            ("_sip._udp.example.com".to_string(), QTYPE_SRV),
            response(
                0,
                "_sip._udp.example.com",
                QTYPE_SRV,
                &[(
                    "_sip._udp.example.com",
                    Rr::Srv {
                        priority: 1,
                        weight: 0,
                        port: 5080,
                        target: "gw.example.net".into(),
                        ttl: 60,
                    },
                )],
            ),
        );
        route_a(&mut routes, "gw.example.net", Ipv4Addr::new(192, 0, 2, 50));
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(200), SEED);

        let out = r.resolve("example.com", None, None).unwrap();
        assert_eq!(out, vec!["192.0.2.50:5080".parse::<SocketAddr>().unwrap()]);
        dns.shutdown();
    }

    #[test]
    fn all_paths_dead_yields_no_addresses() {
        let mut routes = HashMap::new();
        routes.insert(
            ("_sip._udp.example.com".to_string(), QTYPE_SRV),
            response(
                0,
                "_sip._udp.example.com",
                QTYPE_SRV,
                &[(
                    "_sip._udp.example.com",
                    Rr::Srv {
                        priority: 1,
                        weight: 0,
                        port: 5060,
                        target: "ghost.example.net".into(),
                        ttl: 60,
                    },
                )],
            ),
        );
        // ghost.example.net has no A/AAAA route -> SERVFAIL from the fake.
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(150), SEED);
        assert_eq!(
            r.resolve("example.com", Some(SipTransport::Udp), None),
            Err(ResolveError::NoAddresses)
        );
        dns.shutdown();
    }

    #[test]
    fn lookup_ips_survives_one_failing_family() {
        let mut routes = HashMap::new();
        // A present, AAAA routed to SERVFAIL (missing route).
        route_a(&mut routes, "example.com", Ipv4Addr::new(192, 0, 2, 60));
        let dns = FakeDns::spawn(routes, None);
        let r = Resolver::with_server_timeout(dns.addr, Duration::from_millis(150), SEED);
        let ips = r.lookup_ips("example.com").unwrap();
        assert_eq!(ips, vec!["192.0.2.60".parse::<IpAddr>().unwrap()]);
        dns.shutdown();
    }

    #[test]
    fn srv_ordering_priority_then_weights() {
        // Zero-weight records keep their original order (they run last).
        let mut v = vec![
            SrvRecord {
                name: "x".into(),
                ttl: 0,
                priority: 1,
                weight: 0,
                port: 1,
                target: "z1".into(),
            },
            SrvRecord {
                name: "x".into(),
                ttl: 0,
                priority: 1,
                weight: 0,
                port: 2,
                target: "z2".into(),
            },
        ];
        order_srv(&mut v, 7);
        assert_eq!((v[0].target.as_str(), v[1].target.as_str()), ("z1", "z2"));

        // Priority dominates weight: p1 before p10 even with weight 0.
        let mut v = vec![
            SrvRecord {
                name: "x".into(),
                ttl: 0,
                priority: 10,
                weight: 100,
                port: 1,
                target: "hi-p".into(),
            },
            SrvRecord {
                name: "x".into(),
                ttl: 0,
                priority: 1,
                weight: 0,
                port: 2,
                target: "lo-p".into(),
            },
        ];
        order_srv(&mut v, 42);
        assert_eq!(v[0].target, "lo-p");

        // Equal nonzero weights: weighted-random, so any order is legal —
        // only the multiset is guaranteed.
        let mut v = vec![
            SrvRecord {
                name: "x".into(),
                ttl: 0,
                priority: 1,
                weight: 10,
                port: 1,
                target: "a".into(),
            },
            SrvRecord {
                name: "x".into(),
                ttl: 0,
                priority: 1,
                weight: 10,
                port: 1,
                target: "b".into(),
            },
        ];
        for seed in [0u64, 1, 0xDEAD_BEEF, u64::MAX] {
            order_srv(&mut v, seed);
            let mut targets: Vec<&str> = v.iter().map(|r| r.target.as_str()).collect();
            targets.sort_unstable();
            assert_eq!(targets, ["a", "b"]);
        }
    }

    #[test]
    fn naptr_service_and_srv_names_map_correctly() {
        assert_eq!(SipTransport::Udp.naptr_service(), "SIP+D2U");
        assert_eq!(SipTransport::Tcp.naptr_service(), "SIP+D2T");
        assert_eq!(SipTransport::Tls.naptr_service(), "SIPS+D2T");
        assert_eq!(
            SipTransport::Udp.srv_name("Example.COM."),
            "_sip._udp.example.com"
        );
        assert_eq!(SipTransport::Tcp.srv_name("h"), "_sip._tcp.h");
        assert_eq!(SipTransport::Tls.srv_name("h"), "_sips._tcp.h");
        assert_eq!(SipTransport::Tls.default_port(), 5061);
        assert_eq!(naptr_service_transport("sip+d2u"), Some(SipTransport::Udp));
        assert_eq!(naptr_service_transport("E2U+sip"), None);
    }

    #[test]
    fn resolv_conf_parser_takes_first_nameserver() {
        let text = "# comment\noptions timeout:1\nnameserver 192.0.2.53\nnameserver 192.0.2.54\n";
        assert_eq!(
            parse_resolv_conf(text),
            Some("192.0.2.53".parse::<IpAddr>().unwrap())
        );
        assert_eq!(parse_resolv_conf("search lan\n"), None);
    }

    #[test]
    fn weighted_shuffle_distributes_proportionally() {
        // Statistical sanity: over many shuffles the first slot frequency
        // should roughly match the weights.
        let mut firsts = [0usize; 3];
        let mut rng = XorShift(7);
        for _ in 0..30_000 {
            let mut group = vec![
                SrvRecord {
                    name: String::new(),
                    ttl: 0,
                    priority: 1,
                    weight: 70,
                    port: 0,
                    target: "a".into(),
                },
                SrvRecord {
                    name: String::new(),
                    ttl: 0,
                    priority: 1,
                    weight: 20,
                    port: 0,
                    target: "b".into(),
                },
                SrvRecord {
                    name: String::new(),
                    ttl: 0,
                    priority: 1,
                    weight: 10,
                    port: 0,
                    target: "c".into(),
                },
            ];
            shuffle_weighted(&mut group, &mut rng);
            let idx = ["a", "b", "c"]
                .iter()
                .position(|t| group[0].target == *t)
                .unwrap();
            firsts[idx] += 1;
        }
        // 70% ± a few percent, monotone in weight.
        let a_frac = firsts[0] as f64 / 30_000.0;
        assert!(
            a_frac > 0.66 && a_frac < 0.74,
            "a first-run fraction {a_frac}"
        );
        assert!(firsts[0] > firsts[1] && firsts[1] > firsts[2]);
    }

    #[test]
    fn weighted_shuffle_moves_all_zero_weights_to_the_end() {
        let mut rng = XorShift(3);
        let mut group = vec![
            SrvRecord {
                name: String::new(),
                ttl: 0,
                priority: 1,
                weight: 0,
                port: 0,
                target: "z1".into(),
            },
            SrvRecord {
                name: String::new(),
                ttl: 0,
                priority: 1,
                weight: 5,
                port: 0,
                target: "live".into(),
            },
            SrvRecord {
                name: String::new(),
                ttl: 0,
                priority: 1,
                weight: 0,
                port: 0,
                target: "z2".into(),
            },
        ];
        shuffle_weighted(&mut group, &mut rng);
        assert_eq!(group[0].target, "live");
        assert_eq!(group[1].target, "z1"); // original order preserved
        assert_eq!(group[2].target, "z2");
    }
}
