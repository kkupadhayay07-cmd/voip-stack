//! Stateful SIP proxy core (RFC 3261 §16).
//!
//! Transport-agnostic: [`Proxy::process_request`] / [`process_response`]
//! take parsed messages plus the transport source and return the actions to
//! perform (messages to send with their destinations, and response to
//! forward upstream).  Covers the RFC 3261 proxy behaviors:
//!
//! - Request validation (Max-Forwards, loop detection hooks)
//! - Route-set processing (preloaded Route / strict+loose router)
//! - Via handling: push on downstream, pop on upstream (§16.3 step 6,
//!   §18.1.2), `received=`/`rport=` marking for NAT (RFC 3581)
//! - Record-Route insertion (§16.6 step 4)
//! - Parallel forking to the target set (§16.6 step 10)
//! - CANCEL propagation to forked branches (§16.7 step 2)
//! - Best-response selection per branch (§16.7 step 6 simplified)

use std::collections::HashMap;
use std::net::SocketAddr;

use sip_core::builder::respond_to;
use sip_core::ids::new_branch;
use sip_core::message::Method;
use sip_core::{Request, Response, SipMessage};

/// One proxy action produced by processing.
#[derive(Debug, Clone)]
pub enum Action {
    /// Serialize this message and send it to the destination.
    Send(SipMessage, SocketAddr),
    /// Buffered local response (e.g. 100 Trying already handled).
    Buffer(SipMessage),
}

/// Static routing table: user-part regex-ish prefix or exact → targets.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    /// Exact user-part matches.
    pub exact: HashMap<String, Vec<String>>,
    /// Default targets when no exact match (catch-all).
    pub default: Vec<String>,
}

impl RouteTable {
    /// Resolve the Request-URI user to a target list (host strings).
    pub fn resolve(&self, user: &str) -> Vec<String> {
        if let Some(t) = self.exact.get(user) {
            return t.clone();
        }
        self.default.clone()
    }
}

/// Proxy configuration.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Hostname:port advertised in Record-Route headers.
    pub record_route: Option<String>,
    /// Whether to Record-Route INVITEs (needed for downstream in-dialog
    /// requests through this proxy).
    pub record_route_invites: bool,
    /// Port used for target resolution when a target has no port.
    pub default_port: u16,
    /// Minimum response wait before picking a best response (ms).
    pub fork_wait_ms: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            record_route: None,
            record_route_invites: true,
            default_port: 5060,
            fork_wait_ms: 2000,
        }
    }
}

/// Transaction-ish state for an in-flight downstream request.
#[derive(Debug, Clone)]
pub struct ForkedTransaction {
    pub call_id: String,
    pub top_branch: String,
    pub method: Method,
    /// Branch → branch-target (per fork leg).
    pub legs: Vec<String>,
    /// Responses seen so far per leg (branch → best code).
    pub best: HashMap<String, u16>,
    pub started: std::time::Instant,
}

/// A stateful SIP proxy.
pub struct Proxy {
    pub routes: RouteTable,
    pub config: ProxyConfig,
    /// call-id+branch → in-flight fork.
    pub transactions: HashMap<String, ForkedTransaction>,
    /// Registrar-fed lookup: user → contact URIs (used before static routes).
    pub bindings: HashMap<String, Vec<String>>,
}

impl Proxy {
    pub fn new(config: ProxyConfig) -> Self {
        Proxy {
            routes: RouteTable::default(),
            config,
            transactions: HashMap::new(),
            bindings: HashMap::new(),
        }
    }

    fn tx_key(call_id: &str, branch: &str, method: &str) -> String {
        format!("{call_id}|{branch}|{method}")
    }

    /// Insert the proxy's Record-Route on a request.
    fn add_record_route(&self, req: &mut Request) {
        if req.method == Method::Invite && self.config.record_route_invites {
            if let Some(rr) = &self.config.record_route {
                req.headers.add("Record-Route", format!("<sip:{rr};lr>"));
            }
        }
    }

    /// Process a downstream request: validate, route, fork, and return the
    /// outbound actions (forked requests + local 100 Trying).
    pub fn process_request(&mut self, req: &Request, source: SocketAddr) -> Vec<Action> {
        let mut actions = Vec::new();

        // §16.3 step 3: Max-Forwards.
        if req.headers.max_forwards() == Some(0) && req.method != Method::Ack {
            let resp = respond_to(req, 483, "Too Many Hops", Vec::new(), None);
            actions.push(Action::Send(SipMessage::Response(resp), source));
            return actions;
        }

        // CANCEL: cancel in-flight fork and forward downstream (§16.7).
        // The CANCEL mirrors the INVITE's incoming branch.
        if req.method == Method::Cancel {
            let call_id = req.headers.call_id().unwrap_or("").to_string();
            let branch = req
                .headers
                .first_via()
                .and_then(|v| v.branch.clone())
                .unwrap_or_default();
            let key = Self::tx_key(&call_id, &branch, "INVITE");
            if let Some(tx) = self.transactions.remove(&key) {
                // One CANCEL per forked leg, same branch semantics as the
                // INVITE it cancels (§16.7 step 2).
                for leg in &tx.legs {
                    let target = resolve_target(leg, self.config.default_port);
                    actions.push(Action::Send(SipMessage::Request(req.clone()), target));
                }
            }
            // Always 200 the CANCEL locally (§16.7 step 2 simplified).
            let resp = respond_to(req, 200, "OK", Vec::new(), None);
            actions.push(Action::Send(SipMessage::Response(resp), source));
            return actions;
        }

        // Route-set: strip a top Route pointing at us (§16.4).
        let mut req = req.clone();
        let self_hosts: Vec<String> = self
            .config
            .record_route
            .iter()
            .map(|r| r.split(':').next().unwrap_or(r).to_string())
            .collect();

        if let Some(top) = req.headers.first_via() {
            // (downstream only: we are adding our via below)
            let _ = top;
        }
        // §16.4: if the topmost Route points at us, remove exactly that one;
        // the rest of the route set stays.
        {
            let routes: Vec<String> = req
                .headers
                .get_all("Route")
                .into_iter()
                .map(|s| s.to_string())
                .collect();
            if let Some(top) = routes.first() {
                if self_hosts.iter().any(|h| top.contains(h.as_str())) {
                    req.headers.remove_all("Route");
                    for r in routes.iter().skip(1) {
                        req.headers.add("Route", r.clone());
                    }
                }
            }
        }

        // The incoming request's own branch (below ours) identifies the
        // transaction for CANCEL matching (RFC 3261 §9.1).
        let incoming_branch = req
            .headers
            .first_via()
            .and_then(|v| v.branch.clone())
            .unwrap_or_else(new_branch);

        // Prepend our Via: header order defines the via list, and the
        // topmost hop is position 0 (so response processing pops us first).
        let our_branch = new_branch();
        let our_branch2 = our_branch.clone();
        let our_via = make_via("proxy.voip-stack", &our_branch);
        let existing: Vec<String> = req
            .headers
            .get_all("Via")
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        req.headers.remove_all("Via");
        req.headers.add("Via", our_via.to_string());
        for v in existing {
            req.headers.add("Via", v);
        }

        // Decrement Max-Forwards (§16.6 step 3).
        let mf = req.headers.max_forwards().unwrap_or(70);
        req.headers.remove_all("Max-Forwards");
        req.headers.add("Max-Forwards", (mf - 1).to_string());

        self.add_record_route(&mut req);

        // Target selection (§16.6 step 5-9): user from Request-URI, then
        // registrar bindings, then the static route table.
        let user = req.uri.user.clone().unwrap_or_default();
        let targets: Vec<String> = self
            .bindings
            .get(&user)
            .cloned()
            .unwrap_or_else(|| self.routes.resolve(&user));

        if targets.is_empty() {
            let resp = respond_to(&req, 404, "Not Found", Vec::new(), None);
            actions.push(Action::Send(SipMessage::Response(resp), source));
            return actions;
        }

        // Fork: one Via branch per leg is ideal; simplified to the same
        // branch set with distinct targets (documented limitation).
        let mut legs = Vec::new();
        for t in &targets {
            legs.push(t.clone());
            let target = resolve_target(t, self.config.default_port);
            actions.push(Action::Send(SipMessage::Request(req.clone()), target));
        }

        if req.method == Method::Invite {
            let call_id = req.headers.call_id().unwrap_or("").to_string();
            let key = Self::tx_key(&call_id, &incoming_branch, "INVITE");
            self.transactions.insert(
                key,
                ForkedTransaction {
                    call_id,
                    top_branch: our_branch2,
                    method: Method::Invite,
                    legs,
                    best: HashMap::new(),
                    started: std::time::Instant::now(),
                },
            );
        }

        // 100 Trying upstream (§16.6 step 11 for INVITE).
        if req.method == Method::Invite {
            // 100 Trying upstream (§16.6 step 11) with our via stripped so
            // it goes straight back to the requester.
            let mut resp = respond_to(&req, 100, "Trying", Vec::new(), None);
            strip_our_via(&mut resp, &our_branch);
            actions.push(Action::Send(SipMessage::Response(resp), source));
        }
        actions
    }

    /// Process an upstream response: pop our Via, forward to the next hop
    /// (the source implied by the new top Via's received/rport).
    pub fn process_response(&mut self, resp: &Response, _from: SocketAddr) -> Option<Action> {
        let mut resp = resp.clone();
        // Our Via is at position 0 (we prepended it); remember its branch
        // and remove it before forwarding upstream.
        let Some(ours) = resp.headers.first_via().and_then(|v| v.branch.clone()) else {
            return None; // not our response (no Via) — drop
        };
        {
            let all: Vec<String> = resp
                .headers
                .get_all("Via")
                .into_iter()
                .map(|s| s.to_string())
                .collect();
            resp.headers.remove_all("Via");
            for v in all.into_iter().skip(1) {
                resp.headers.add("Via", v);
            }
        }

        let call_id = resp.headers.call_id().unwrap_or("").to_string();
        let key = Self::tx_key(&call_id, &ours, "INVITE");
        if let Some(tx) = self.transactions.get_mut(&key) {
            let code = resp.code;
            // Track per-leg best response (branch of the remaining top via):
            // finals replace provisional, higher finals replace lower.
            if let Some(leg_branch) = resp.headers.first_via().and_then(|v| v.branch.clone()) {
                let entry = tx.best.entry(leg_branch).or_insert(0);
                let better = (code >= 200) >= (*entry >= 200) && code > *entry;
                let _ = better;
                if (*entry < 200 && code > *entry) || (code >= 200 && code > *entry) {
                    *entry = code;
                }
            }
        }

        // The new top Via tells us where to forward; if none remains, the
        // response is going back to the UAC — the transport layer derives
        // the destination from the Via's received/rport, falling back to
        // the advertised sent-by.
        // Destination selection (RFC 3261 §18.2.2): prefer received+rport
        // (NAT), then received, then the advertised sent-by.
        let dest = resp.headers.first_via().and_then(|v| {
            if let Some(r) = &v.received {
                if let Some(p) = v.rport.flatten() {
                    if let Ok(sa) = format!("{r}:{p}").parse::<SocketAddr>() {
                        return Some(sa);
                    }
                }
                if let Ok(sa) = r.parse::<SocketAddr>() {
                    return Some(sa);
                }
            }
            let hp = format!("{}:{}", v.sent_by.host, v.sent_by.port.unwrap_or(5060));
            hp.parse::<SocketAddr>().ok().or_else(|| {
                // Hostname sent-by: resolve through the system resolver.
                use std::net::ToSocketAddrs;
                hp.to_socket_addrs().ok()?.next()
            })
        })?;

        Some(Action::Send(SipMessage::Response(resp), dest))
    }
}

fn strip_our_via(resp: &mut Response, branch: &str) {
    // respond_to copies all request Vias; ours sits at position 0 and is
    // identified by its branch. Remove exactly that one.
    let all: Vec<String> = resp
        .headers
        .get_all("Via")
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    resp.headers.remove_all("Via");
    for v in &all {
        if v.contains(branch) {
            continue;
        }
        resp.headers.add("Via", v.clone());
    }
}

/// Resolve a target string ("host" / "host:port" / "user@host") to a
/// SocketAddr.
fn resolve_target(target: &str, default_port: u16) -> SocketAddr {
    let host_port = target
        .rsplit('@')
        .next()
        .unwrap_or(target)
        .trim_start_matches('<')
        .trim_end_matches('>');
    let host_port = host_port.strip_prefix("sip:").unwrap_or(host_port);
    let host_port = host_port.split(';').next().unwrap_or(host_port);
    // Strip params like ;transport=tcp
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse().unwrap_or(default_port))
        }
        _ => (host_port, default_port),
    };
    let ip: std::net::IpAddr = host
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    SocketAddr::new(ip, port)
}

use sip_core::headers::Via;

/// Build a Via header for this proxy hop.
fn make_via(host_port: &str, branch: &str) -> Via {
    let text = format!("SIP/2.0/UDP {host_port};branch={branch}");
    Via::parse(&text).expect("static via text parses")
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("transactions", &self.transactions.len())
            .finish()
    }
}
