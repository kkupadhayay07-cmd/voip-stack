//! Session border controller: the policy and screening layer placed
//! between untrusted peer networks and the core.
//!
//! Layers (applied in order to every request):
//!
//! 1. **ACL** — CIDR allow/deny lists (source IP screening)
//! 2. **Rate limit** — token bucket per source address
//! 3. **NAT latch** — learn the public source:port of registered peers
//!    (RFC 3581 `rport`/`received` marking + binding table)
//! 4. **Topology hiding** — rewrite Call-ID / Via host / Contact /
//!    Record-Route crossing the border so internal hosts stay invisible
//!
//! Transport-agnostic: [`Sbc::process_request`] returns the (possibly
//! rewritten) request plus the internal destination, or a refusal response.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use sip_core::builder::respond_to;
use sip_core::ids::new_call_id;
use sip_core::{Request, Response};

/// A CIDR range for ACL rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Self {
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefix,
        }
    }

    /// Does `ip` fall inside the range?
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(base), IpAddr::V4(other)) => {
                let base = u32::from(base);
                let other = u32::from(other);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix as u32)
                };
                base & mask == other & mask
            }
            (IpAddr::V6(base), IpAddr::V6(other)) => {
                let base = u128::from(base);
                let other = u128::from(other);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix as u32)
                };
                base & mask == other & mask
            }
            _ => false,
        }
    }
}

/// Access control policy.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    /// If non-empty, only these ranges are admitted.
    pub allow: Vec<Cidr>,
    /// Always rejected ranges (checked after allow).
    pub deny: Vec<Cidr>,
}

impl Acl {
    pub fn admits(&self, ip: IpAddr) -> bool {
        if !self.allow.is_empty() && !self.allow.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if self.deny.iter().any(|c| c.contains(ip)) {
            return false;
        }
        true
    }
}

/// Token-bucket rate limiter per source address.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Rate limiting configuration (sustained rate + burst capacity).
#[derive(Debug, Clone)]
pub struct RateLimit {
    pub per_second: f64,
    pub burst: f64,
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit {
            per_second: 50.0,
            burst: 100.0,
        }
    }
}

/// SBC configuration.
#[derive(Clone)]
pub struct SbcConfig {
    pub acl: Acl,
    pub rate: RateLimit,
    /// External (public) address advertised in rewritten headers.
    pub external: String,
    /// Internal core address messages are relayed to.
    pub internal_target: SocketAddr,
    /// Enable topology hiding rewrites.
    pub topology_hiding: bool,
}

/// SBC decision for a request.
#[derive(Debug)]
pub enum SbcAction {
    /// Forward the (rewritten) request to the internal target.
    Relay(Request),
    /// Refuse with a local response (403/503).
    Refuse(Response),
}

/// NAT latching table: AOR/contact key → latched public address.
#[derive(Debug, Default, Clone)]
pub struct LatchTable {
    pub entries: HashMap<String, (SocketAddr, Instant)>,
}

impl LatchTable {
    const TTL: Duration = Duration::from_secs(300);

    pub fn latch(&mut self, key: &str, addr: SocketAddr) {
        self.entries
            .insert(key.to_string(), (addr, Instant::now() + Self::TTL));
    }

    pub fn lookup(&self, key: &str) -> Option<SocketAddr> {
        let (addr, expiry) = self.entries.get(key)?;
        if Instant::now() < *expiry {
            Some(*addr)
        } else {
            None
        }
    }

    pub fn sweep(&mut self) {
        self.entries.retain(|_, (_, exp)| Instant::now() < *exp);
    }
}

/// The session border controller.
pub struct Sbc {
    pub config: SbcConfig,
    buckets: HashMap<IpAddr, Bucket>,
    latches: LatchTable,
    /// Call-ID rewrite map: real (internal) id → hidden (external) id.
    call_map: HashMap<String, String>,
    /// Reverse map: hidden id → real id (upstream lookups).
    call_map_rev: HashMap<String, String>,
}

impl Sbc {
    pub fn new(config: SbcConfig) -> Self {
        Sbc {
            config,
            buckets: HashMap::new(),
            latches: LatchTable::default(),
            call_map: HashMap::new(),
            call_map_rev: HashMap::new(),
        }
    }

    pub fn latches(&self) -> &LatchTable {
        &self.latches
    }

    fn check_rate(&mut self, source: SocketAddr) -> bool {
        let now = Instant::now();
        let bucket = self.buckets.entry(source.ip()).or_insert(Bucket {
            tokens: self.config.rate.burst,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens =
            (bucket.tokens + elapsed * self.config.rate.per_second).min(self.config.rate.burst);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Screen and relay a request from an external source.
    pub fn process_request(&mut self, req: &Request, source: SocketAddr) -> SbcAction {
        // 1. ACL.
        if !self.config.acl.admits(source.ip()) {
            return SbcAction::Refuse(respond_to(req, 403, "Forbidden", Vec::new(), None));
        }
        // 2. Rate limit.
        if !self.check_rate(source) {
            return SbcAction::Refuse(respond_to(
                req,
                503,
                "Service Unavailable",
                Vec::new(),
                None,
            ));
        }
        // 3. NAT latch: remember the public source for this peer keyed by
        //    the bare contact URI, so responses and in-dialog requests find
        //    the right path.
        if let Some(contact) = req.headers.get("Contact") {
            let key = contact
                .trim()
                .trim_start_matches('<')
                .split('>')
                .next()
                .unwrap_or(contact);
            self.latches.latch(key, source);
        }
        // RFC 3581: mark rport on the top Via so responses can come back.
        let mut req = req.clone();
        if let Some(mut via) = req.headers.first_via() {
            if via.rport.is_none() {
                via.rport = Some(None);
                let all: Vec<String> = req
                    .headers
                    .get_all("Via")
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect();
                req.headers.remove_all("Via");
                for (i, v) in all.iter().enumerate() {
                    if i == 0 {
                        req.headers.add("Via", via.to_string());
                    } else {
                        req.headers.add("Via", v.clone());
                    }
                }
            }
        }

        // 4. Topology hiding.
        if self.config.topology_hiding {
            let real_call_id = req.headers.call_id().unwrap_or("").to_string();
            let hidden = self
                .call_map
                .entry(real_call_id.clone())
                .or_insert_with(|| format!("h-{}/{}", new_call_id("sbc"), self.config.external));
            let hidden = hidden.clone();
            req.headers.remove_all("Call-ID");
            req.headers.add("Call-ID", hidden.clone());
            self.call_map_rev.insert(hidden, real_call_id);

            // Hide internal Contact hosts behind the external address.
            if let Some(contact) = req.headers.get("Contact") {
                let rewritten = rewrite_hosts(
                    contact,
                    &self.config.internal_target.to_string(),
                    &self.config.external,
                );
                req.headers.remove_all("Contact");
                req.headers.add("Contact", rewritten);
            }
        }

        SbcAction::Relay(req)
    }

    /// Screen a response from the internal core before it leaves to the peer.
    pub fn process_response(&mut self, resp: &Response) -> Response {
        let mut resp = resp.clone();
        if self.config.topology_hiding {
            if let Some(cid) = resp.headers.call_id().map(|s| s.to_string()) {
                if let Some(hidden) = self.call_map.get(&cid) {
                    resp.headers.remove_all("Call-ID");
                    resp.headers.add("Call-ID", hidden.clone());
                }
            }
        }
        resp
    }

    /// Reverse-map a hidden Call-ID back to the internal one (upstream
    /// requests arriving on the internal side).
    pub fn unmap_call_id(&self, hidden: &str) -> Option<&String> {
        self.call_map_rev.get(hidden)
    }

    /// Number of tracked Call-ID rewrites.
    pub fn tracked_calls(&self) -> usize {
        self.call_map.len()
    }
}

/// Replace occurrences of `from_host` with `to_host` in a header value
/// (host:port aware — only rewrites the host part inside <> or addr-spec).
fn rewrite_hosts(value: &str, from_host: &str, to_host: &str) -> String {
    if value.contains(from_host) {
        value.replace(from_host, to_host)
    } else {
        value.to_string()
    }
}
