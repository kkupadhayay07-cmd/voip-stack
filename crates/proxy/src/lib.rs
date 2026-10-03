//! Stateful SIP proxy core (RFC 3261 §16) on the [`sip_tx`] transaction
//! layer (RFC 3261 §17).
//!
//! Transport-agnostic: [`Proxy::process_request`] / [`process_response`]
//! take parsed messages plus the transport source and return the actions to
//! perform (messages to send with their destinations), and [`Proxy::poll`]
//! advances every pending transaction timer.  Covers the RFC 3261 proxy
//! behaviors:
//!
//! - Request validation (Max-Forwards, loop detection hooks)
//! - Route-set processing (preloaded Route / strict+loose router)
//! - Via handling: push on downstream, pop on upstream (§16.3 step 6,
//!   §18.1.2), `received=`/`rport=` marking for NAT (RFC 3581)
//! - Record-Route insertion (§16.6 step 4)
//! - Parallel forking with a DISTINCT Via branch per fork leg (§16.6
//!   step 10), each leg driven by a real client transaction (§17.1): Timer
//!   A/E retransmissions, Timer B/F timeouts, non-2xx ACK generation
//! - Server transactions for every incoming request (§17.2): retransmitted
//!   requests are absorbed instead of re-forked, and locally generated /
//!   forwarded final responses are retransmitted (Timer G/J) until the
//!   upstream ACK (Timer H/I/J cleanup)
//! - CANCEL propagation to forked branches (§16.7 step 2): the per-leg
//!   CANCEL is BUILT from the forked INVITE so its top Via branch matches
//!   the INVITE the leg received (RFC 3261 §9.1)
//! - Best-response selection (§16.7 step 6): non-2xx finals are stored in
//!   a response context and forwarded as the "best" final once every leg
//!   terminates (6xx class first, then the lowest class, preferring
//!   401/407/415/420/484; a 503-only fork generates 500; no finals → 408).
//!   Provisionals (non-100) and 2xx forward immediately; a 6xx cancels the
//!   still-pending legs; Timer C (§16.6 bullet 11) bounds each proxied
//!   INVITE leg (>3 min, reset per non-100 provisional, §16.7 step 2) — a
//!   Timer-C fire CANCELs a leg that rang (§16.8)
//!
//! Time is explicit (`now: Instant` parameters, like `sip_tx`), so every
//! timer path is unit-testable with a fake clock and the caller's event
//! loop drives retransmissions through [`Proxy::poll`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use sip_core::builder::respond_to;
use sip_core::ids::new_branch;
use sip_core::message::{Method, Request, Response, SipMessage};
use sip_tx::{
    ClientInviteTx, ClientNonInviteTx, ServerInviteTx, ServerNonInviteTx, Transport, TxAction,
    TxEvent, TxState,
};

/// The Via host this proxy stamps on every hop it adds; responses carrying
/// it on top belong to this proxy's transactions.
pub const PROXY_VIA_HOST: &str = "proxy.voip-stack";

/// One proxy action produced by processing.
#[derive(Debug, Clone)]
pub enum Action {
    /// Serialize this message and send it to the destination.
    Send(SipMessage, SocketAddr),
}

/// Static routing table: user-part prefix or exact → targets.
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
    /// Timer C for proxied INVITE client transactions (RFC 3261 §16.6
    /// bullet 11): the total time a leg may stay pending, reset per non-100
    /// provisional (§16.7 step 2). The RFC requires the value to be larger
    /// than 3 minutes.
    pub timer_c: std::time::Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            record_route: None,
            record_route_invites: true,
            default_port: 5060,
            timer_c: std::time::Duration::from_secs(240),
        }
    }
}

/// A downstream fork leg: one real client transaction per leg (§16.6 step
/// 10 gives each leg its own Via branch, §17.1.1/§17.1.2 drive it).
struct Leg {
    /// Call-ID of the forked request (for CANCEL matching).
    call_id: String,
    target: SocketAddr,
    /// Branch of the incoming request's top Via (below ours). CANCELs mirror
    /// the upstream Via stack (RFC 3261 §9.1), so they are matched against
    /// this — not against the leg's own branch, which is ours.
    incoming_branch: String,
    /// Key of the upstream-facing server transaction this leg belongs to.
    server_key: Option<String>,
    /// A non-100 provisional was seen (drives §16.8: Timer C fire on a leg
    /// that rang MUST be CANCELed, not just abandoned).
    got_provisional: bool,
    tx: ClientTx,
}

/// Client-side transaction wrapper (INVITE vs. everything else).
enum ClientTx {
    Invite(ClientInviteTx),
    NonInvite(ClientNonInviteTx),
}

impl ClientTx {
    fn on_event(&mut self, ev: TxEvent, now: Instant) -> Vec<TxAction> {
        match self {
            ClientTx::Invite(t) => t.on_event(ev, now),
            ClientTx::NonInvite(t) => t.on_event(ev, now),
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        match self {
            ClientTx::Invite(t) => t.next_deadline(),
            ClientTx::NonInvite(t) => t.next_deadline(),
        }
    }

    fn state(&self) -> TxState {
        match self {
            ClientTx::Invite(t) => t.state(),
            ClientTx::NonInvite(t) => t.state(),
        }
    }

    /// §16.7 step 2: reset Timer C on a non-100 provisional (INVITE legs
    /// only — Timer C does not apply to non-INVITE client transactions).
    fn reset_timer_c(&mut self, now: Instant, d: std::time::Duration) {
        if let ClientTx::Invite(t) = self {
            t.reset_timer_c(now, d);
        }
    }

    fn is_invite(&self) -> bool {
        matches!(self, ClientTx::Invite(_))
    }

    fn request(&self) -> &Request {
        match self {
            ClientTx::Invite(t) => t.request(),
            ClientTx::NonInvite(t) => t.request(),
        }
    }
}

/// An upstream-facing server transaction (§17.2) plus the address its
/// retransmissions go to (the source the original request arrived from).
struct ServerSide {
    tx: ServerTx,
    upstream: SocketAddr,
}

/// Server-side transaction wrapper.
enum ServerTx {
    Invite(ServerInviteTx),
    NonInvite(ServerNonInviteTx),
}

impl ServerTx {
    fn stage(&mut self, resp: Response) {
        match self {
            ServerTx::Invite(t) => t.stage(resp),
            ServerTx::NonInvite(t) => t.stage(resp),
        }
    }

    fn on_event(&mut self, ev: TxEvent, now: Instant) -> Vec<TxAction> {
        match self {
            ServerTx::Invite(t) => t.on_event(ev, now),
            ServerTx::NonInvite(t) => t.on_event(ev, now),
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        match self {
            ServerTx::Invite(t) => t.next_deadline(),
            ServerTx::NonInvite(t) => t.next_deadline(),
        }
    }

    /// The RFC state of the wrapped server transaction.
    fn state(&self) -> TxState {
        match self {
            ServerTx::Invite(t) => t.state(),
            ServerTx::NonInvite(t) => t.state(),
        }
    }

    /// The stored request the transaction was created for (for building a
    /// fork-timeout response that mirrors the upstream Via stack).
    fn request(&self) -> &Request {
        match self {
            ServerTx::Invite(t) => t.request(),
            ServerTx::NonInvite(t) => t.request(),
        }
    }
}

/// A stateful SIP proxy.
pub struct Proxy {
    pub routes: RouteTable,
    pub config: ProxyConfig,
    /// Downstream fork legs keyed by `{call_id}|{our per-leg branch}|{method}`.
    legs: HashMap<String, Leg>,
    /// Upstream-facing server transactions keyed by
    /// `{call_id}|{incoming branch}|{method}|{seq}`.
    server_txs: HashMap<String, ServerSide>,
    /// §16.7 step 4 response contexts: the non-2xx finals each fork has
    /// received (popped form — what would go upstream), keyed by the fork's
    /// server-transaction key. Forwarded as the "best" final once every leg
    /// terminates (§16.7 step 6).
    contexts: HashMap<String, Vec<Response>>,
    /// Registrar-fed lookup: user → contact URIs (used before static routes).
    pub bindings: HashMap<String, Vec<String>>,
}

impl Proxy {
    pub fn new(config: ProxyConfig) -> Self {
        Proxy {
            routes: RouteTable::default(),
            config,
            legs: HashMap::new(),
            server_txs: HashMap::new(),
            contexts: HashMap::new(),
            bindings: HashMap::new(),
        }
    }

    /// Number of live downstream fork legs (per-leg client transactions).
    pub fn leg_count(&self) -> usize {
        self.legs.len()
    }

    /// Number of live upstream-facing server transactions.
    pub fn server_tx_count(&self) -> usize {
        self.server_txs.len()
    }

    /// The per-leg Via branches of every live fork for `call_id`.
    pub fn leg_branches(&self, call_id: &str) -> Vec<String> {
        self.legs
            .keys()
            .filter(|k| k.starts_with(&format!("{call_id}|")))
            .filter_map(|k| k.split('|').nth(1).map(str::to_string))
            .collect()
    }

    /// The ONE leg key builder, shared by the fork path (insert) and the
    /// response/ACK paths (lookup): call-id + our per-leg branch + method.
    fn leg_key(call_id: &str, branch: &str, method: &Method) -> String {
        format!("{call_id}|{branch}|{method}")
    }

    /// The server-transaction key builder from the incoming request's own
    /// identity (its top Via branch — NOT ours — plus call-id, method, seq).
    fn server_key_from_req(req: &Request) -> Option<String> {
        let branch = req.headers.first_via().and_then(|v| v.branch.clone())?;
        let call_id = req.headers.call_id()?;
        let seq = req.headers.cseq()?.seq;
        Some(format!("{call_id}|{branch}|{}|{seq}", req.method))
    }

    /// Insert the proxy's Record-Route on a request.
    fn add_record_route(&self, req: &mut Request) {
        if req.method == Method::Invite && self.config.record_route_invites {
            if let Some(rr) = &self.config.record_route {
                req.headers.add("Record-Route", format!("<sip:{rr};lr>"));
            }
        }
    }

    /// Create the upstream-facing server transaction for an incoming
    /// request (§17.2). `reliable` selects the transport class for the
    /// timer config (reliable transports suppress retransmission timers).
    fn create_server_tx(&mut self, req: &Request, source: SocketAddr, reliable: bool) {
        let Some(key) = Self::server_key_from_req(req) else {
            return;
        };
        let transport = if reliable {
            Transport::Tcp
        } else {
            Transport::Udp
        };
        let tx = if req.method == Method::Invite {
            ServerTx::Invite(ServerInviteTx::new(req.clone(), transport))
        } else {
            ServerTx::NonInvite(ServerNonInviteTx::new(req.clone(), transport))
        };
        self.server_txs.insert(
            key,
            ServerSide {
                tx,
                upstream: source,
            },
        );
    }

    /// Build a local response for `req` and send it THROUGH the request's
    /// server transaction, so a retransmitted request is answered with it
    /// again (§17.2.1/§17.2.2) and a lost response is retransmitted
    /// (Timer G/J) via [`Proxy::poll`].
    fn respond_local(
        &mut self,
        req: &Request,
        source: SocketAddr,
        code: u16,
        reason: &str,
        now: Instant,
    ) -> Vec<Action> {
        let resp = respond_to(req, code, reason, Vec::new(), None);
        let key = Self::server_key_from_req(req);
        let mut actions = Vec::new();
        let mut deleted = false;
        if let Some(k) = key.as_ref() {
            if let Some(sv) = self.server_txs.get_mut(k) {
                sv.tx.stage(resp.clone());
                for a in sv.tx.on_event(TxEvent::Send, now) {
                    match a {
                        TxAction::SendResponse(r) => {
                            actions.push(Action::Send(SipMessage::Response(r), source))
                        }
                        TxAction::DeleteTransaction => deleted = true,
                        _ => {}
                    }
                }
            }
        }
        if actions.is_empty() && !deleted {
            actions.push(Action::Send(SipMessage::Response(resp), source));
        }
        if deleted {
            if let Some(k) = key {
                self.server_txs.remove(&k);
            }
        }
        actions
    }

    /// Absorb a retransmission of an already-tracked incoming request
    /// (§17.2): the transaction re-sends the last staged response instead of
    /// the proxy re-forking the request downstream. Returns `None` when the
    /// request does not match any live server transaction.
    fn absorb_retransmission(
        &mut self,
        req: &Request,
        _source: SocketAddr,
        now: Instant,
    ) -> Option<Vec<Action>> {
        let key = Self::server_key_from_req(req)?;
        let sv = self.server_txs.get_mut(&key)?;
        let mut actions = Vec::new();
        let mut deleted = false;
        for a in sv.tx.on_event(TxEvent::ReceivedRequest(req.clone()), now) {
            match a {
                TxAction::SendResponse(r) => {
                    actions.push(Action::Send(SipMessage::Response(r), sv.upstream))
                }
                TxAction::DeleteTransaction => deleted = true,
                _ => {}
            }
        }
        if deleted {
            self.server_txs.remove(&key);
        }
        Some(actions)
    }

    /// ACK routing (§17.2.3 — an ACK never creates a transaction):
    /// 1. an ACK for a non-2xx final we forwarded upstream is absorbed by
    ///    the upstream-facing server INVITE transaction (which then cleans
    ///    up via Timer I through [`Proxy::poll`], or immediately on a
    ///    reliable transport);
    /// 2. an ACK whose top Via branch is one of OUR per-leg branches is
    ///    forwarded straight to that leg;
    /// 3. anything else falls through to the generic request path (routed
    ///    by bindings/routes, sent without transaction state).
    fn route_ack(&mut self, req: &Request, now: Instant) -> Option<Vec<Action>> {
        // (a) upstream-facing server INVITE transaction (§17.2.3).
        let match_key = self.server_txs.iter().find_map(|(k, sv)| match &sv.tx {
            ServerTx::Invite(inv) => {
                sip_tx::matching::ack_matches_invite(req, inv.request()).then(|| k.clone())
            }
            _ => None,
        });
        if let Some(key) = match_key {
            if let Some(sv) = self.server_txs.get_mut(&key) {
                if let ServerTx::Invite(inv) = &mut sv.tx {
                    let mut deleted = false;
                    for a in inv.on_event(TxEvent::ReceivedRequest(req.clone()), now) {
                        if matches!(a, TxAction::DeleteTransaction) {
                            deleted = true;
                        }
                    }
                    if deleted {
                        self.server_txs.remove(&key);
                    }
                    return Some(Vec::new());
                }
            }
        }
        // (b) our per-leg branch on top → forward to that leg's target.
        if let Some(branch) = req.headers.first_via().and_then(|v| v.branch.clone()) {
            let call_id = req.headers.call_id().unwrap_or("");
            let key = Self::leg_key(call_id, &branch, &Method::Invite);
            if let Some(leg) = self.legs.get(&key) {
                return Some(vec![Action::Send(
                    SipMessage::Request(req.clone()),
                    leg.target,
                )]);
            }
        }
        None
    }

    /// CANCEL processing (§16.7 step 2): one generated CANCEL per pending
    /// fork leg — built from the leg's forked INVITE so the top Via branch
    /// matches what the leg received (RFC 3261 §9.1) — plus a 200 for the
    /// CANCEL itself, sent through the CANCEL's own server transaction so
    /// retransmitted CANCELs are absorbed and re-answered.
    fn process_cancel(
        &mut self,
        req: &Request,
        source: SocketAddr,
        reliable: bool,
        now: Instant,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        let call_id = req.headers.call_id().unwrap_or("").to_string();
        let incoming_branch = req
            .headers
            .first_via()
            .and_then(|v| v.branch.clone())
            .unwrap_or_default();

        // One CANCEL per forked leg, generated from THAT leg's forked
        // INVITE (same branch/Route/Request-URI/Call-ID/From/To/CSeq-seq,
        // method CANCEL — §16.7 step 2 + §9.1).
        let leg_keys: Vec<String> = self
            .legs
            .iter()
            .filter(|(_, l)| {
                l.call_id == call_id && l.incoming_branch == incoming_branch && l.tx.is_invite()
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in &leg_keys {
            let Some(leg) = self.legs.get(k) else {
                continue;
            };
            let cancel = build_leg_cancel(leg.tx.request());
            actions.push(Action::Send(SipMessage::Request(cancel), leg.target));
        }

        // 200 the CANCEL locally (§16.7 step 2), through its server
        // transaction so retransmissions are absorbed and re-answered.
        self.create_server_tx(req, source, reliable);
        actions.extend(self.respond_local(req, source, 200, "OK", now));
        actions
    }

    /// Strip a top Route pointing at us (§16.4), add Record-Route (§16.6
    /// step 4) and decrement Max-Forwards (§16.6 step 3) on a fresh copy;
    /// returns the base the per-leg forked requests are built from, plus
    /// the incoming request's own top-Via branch (below ours — recorded on
    /// every leg for CANCEL matching).
    fn prepare_base(&self, req: &Request) -> (Request, String) {
        let mut base = req.clone();
        let incoming_branch = req
            .headers
            .first_via()
            .and_then(|v| v.branch.clone())
            .unwrap_or_else(new_branch);

        let self_hosts: Vec<String> = self
            .config
            .record_route
            .iter()
            .map(|r| r.split(':').next().unwrap_or(r).to_string())
            .collect();

        // §16.4: if the topmost Route points at us, remove exactly that one;
        // the rest of the route set stays.
        let routes: Vec<String> = base
            .headers
            .get_all("Route")
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        if let Some(top) = routes.first() {
            if self_hosts.iter().any(|h| top.contains(h.as_str())) {
                base.headers.remove_all("Route");
                for r in routes.iter().skip(1) {
                    base.headers.add("Route", r.clone());
                }
            }
        }

        self.add_record_route(&mut base);

        // Decrement Max-Forwards (§16.6 step 3).
        let mf = base.headers.max_forwards().unwrap_or(70);
        base.headers.remove_all("Max-Forwards");
        base.headers.add("Max-Forwards", (mf - 1).to_string());

        (base, incoming_branch)
    }

    /// Process a downstream request: validate, route, fork, and return the
    /// outbound actions (forked requests + local 100 Trying). `reliable`
    /// selects the arriving transport's timer class for the server
    /// transaction (reliable transports suppress retransmission timers).
    pub fn process_request(
        &mut self,
        req: &Request,
        source: SocketAddr,
        reliable: bool,
        now: Instant,
    ) -> Vec<Action> {
        let is_ack = req.method == Method::Ack;

        // ACK: routed by transaction identity, never forked with new
        // transaction state (§17.2.3).
        if is_ack {
            if let Some(actions) = self.route_ack(req, now) {
                return actions;
            }
            // fall through: generic routing without transaction state
        }

        // §16.3 step 3: Max-Forwards.
        if !is_ack && req.headers.max_forwards() == Some(0) {
            self.create_server_tx(req, source, reliable);
            return self.respond_local(req, source, 483, "Too Many Hops", now);
        }

        // Retransmission absorption (§17.2): a repeated request must NOT
        // fork again — its server transaction re-sends the staged response.
        if !is_ack {
            if let Some(actions) = self.absorb_retransmission(req, source, now) {
                return actions;
            }
        }

        // CANCEL (§16.7 step 2).
        if !is_ack && req.method == Method::Cancel {
            return self.process_cancel(req, source, reliable, now);
        }

        // Upstream-facing server transaction for THIS request.
        if !is_ack {
            self.create_server_tx(req, source, reliable);
        }

        let (base, incoming_branch) = self.prepare_base(req);

        // Target selection (§16.6 step 5-9): user from Request-URI, then
        // registrar bindings, then the static route table.
        let user = req.uri.user.clone().unwrap_or_default();
        let targets: Vec<String> = self
            .bindings
            .get(&user)
            .cloned()
            .unwrap_or_else(|| self.routes.resolve(&user));

        if targets.is_empty() {
            if !is_ack {
                return self.respond_local(req, source, 404, "Not Found", now);
            }
            return Vec::new();
        }

        let call_id = req.headers.call_id().unwrap_or("").to_string();
        let server_key = Self::server_key_from_req(req);
        let mut actions = Vec::new();

        // Fork (§16.6 step 10): one request copy per leg, each with its OWN
        // Via branch, driven by a real client transaction (§17.1). An ACK
        // is forwarded without transaction state (§17.1: no ACK
        // transactions).
        for t in &targets {
            let target = resolve_target(t, self.config.default_port);
            let branch = new_branch();
            let fwd = prepend_via(base.clone(), &make_via(PROXY_VIA_HOST, &branch).to_string());

            if is_ack {
                actions.push(Action::Send(SipMessage::Request(fwd), target));
                continue;
            }

            let (tx, key) = if req.method == Method::Invite {
                let mut tx = ClientInviteTx::new(fwd.clone(), Transport::Udp);
                for a in tx.on_event(TxEvent::Send, now) {
                    if let TxAction::SendRequest(r) = a {
                        actions.push(Action::Send(SipMessage::Request(r), target));
                    }
                }
                (
                    ClientTx::Invite(tx),
                    Self::leg_key(&call_id, &branch, &Method::Invite),
                )
            } else {
                let mut tx = ClientNonInviteTx::new(fwd.clone(), Transport::Udp);
                for a in tx.on_event(TxEvent::Send, now) {
                    if let TxAction::SendRequest(r) = a {
                        actions.push(Action::Send(SipMessage::Request(r), target));
                    }
                }
                (
                    ClientTx::NonInvite(tx),
                    Self::leg_key(&call_id, &branch, &req.method),
                )
            };
            self.legs.insert(
                key,
                Leg {
                    call_id: call_id.clone(),
                    target,
                    incoming_branch: incoming_branch.clone(),
                    server_key: server_key.clone(),
                    got_provisional: false,
                    tx,
                },
            );
        }

        // fork tap (after forking)
        if !is_ack {
            observ::session::emit_for(
                req.headers.call_id().unwrap_or(""),
                observ::EventKind::ProxyFork {
                    method: req.method.to_string(),
                    targets: targets.clone(),
                },
            );
        }

        // 100 Trying upstream (§16.6 step 11 for INVITE), through the
        // server transaction so a retransmitted INVITE re-gets it (and the
        // response is built from the RAW request — the upstream's Via
        // stack, never ours).
        if req.method == Method::Invite {
            if let Some(k) = &server_key {
                if let Some(sv) = self.server_txs.get_mut(k) {
                    sv.tx
                        .stage(respond_to(req, 100, "Trying", Vec::new(), None));
                    for a in sv.tx.on_event(TxEvent::Send, now) {
                        if let TxAction::SendResponse(r) = a {
                            actions.push(Action::Send(SipMessage::Response(r), source));
                        }
                    }
                }
            }
        }
        actions
    }

    /// Process an upstream response: feed the fork leg's client transaction
    /// (retransmission absorption, non-2xx ACK generation — §17.1), pop our
    /// Via, then forward per §16.7 step 5 — provisionals (non-100) and 2xx
    /// go immediately (staged into the upstream-facing server transaction
    /// so a lost final retransmits, §17.2), non-2xx finals are stored in
    /// the response context and forwarded as the best final when the fork
    /// completes (§16.7 step 6). The destination is the source implied by
    /// the new top Via's received/rport.
    pub fn process_response(
        &mut self,
        resp: &Response,
        _from: SocketAddr,
        now: Instant,
    ) -> Vec<Action> {
        let Some(ours) = resp.headers.first_via().and_then(|v| v.branch.clone()) else {
            return Vec::new(); // not ours (no Via branch) — drop
        };
        let call_id = resp.headers.call_id().unwrap_or("").to_string();
        let method = resp
            .headers
            .cseq()
            .map(|c| c.method)
            .unwrap_or(Method::Invite);
        let leg_key = Self::leg_key(&call_id, &ours, &method);

        // 1) Feed the leg's client transaction with the response AS
        //    RECEIVED (our Via on top echoes the leg's identity, §17.1.3).
        //    The tx owns retransmission absorption and the non-2xx ACK.
        let mut ack_to_leg: Option<(Request, SocketAddr)> = None;
        let mut drop_leg = false;
        let mut server_key: Option<String> = None;
        let code = resp.code;
        if let Some(leg) = self.legs.get_mut(&leg_key) {
            server_key = leg.server_key.clone();
            // §16.7 step 2: a non-100 provisional resets Timer C (INVITE).
            // MUST run AFTER the feed — before it, the tx is still in
            // Trying and the reset would silently no-op (caught by test).
            let provisional = code > 100 && code < 200;
            for a in leg.tx.on_event(TxEvent::Received(resp.clone()), now) {
                match a {
                    TxAction::SendRequest(ack) => ack_to_leg = Some((ack, leg.target)),
                    TxAction::DeleteTransaction => drop_leg = true,
                    _ => {}
                }
            }
            if provisional {
                leg.got_provisional = true;
                leg.tx.reset_timer_c(now, self.config.timer_c);
            }
        }
        if drop_leg {
            self.legs.remove(&leg_key);
        }

        // 2) Pop our Via (position 0 by construction) before forwarding.
        let mut resp = resp.clone();
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

        // Destination selection (RFC 3261 §18.2.2): prefer received+rport
        // (NAT), then received, then the advertised sent-by.
        let Some(dest) = dest_from_via(&resp) else {
            return Vec::new();
        };

        // The server tx may also be derived from the POPPED response (its
        // top Via is now the upstream's own — the server key's branch).
        let derived_key = Self::server_key_from_popped(&resp, &method);

        // 3) Forward per §16.7 step 5:
        //    - any provisional other than 100 → immediately
        //    - any 2xx → immediately
        //    - non-2xx finals (incl. 6xx) → stored in the response context;
        //      6xx additionally CANCELs the still-pending sibling legs
        //    - once a final was forwarded on the server tx, ONLY a 2xx to an
        //      INVITE still forwards (a stray late non-2xx is dropped)
        let mut actions = Vec::new();
        let is_2xx = (200..300).contains(&code);
        let is_final = code >= 200;
        let mut dead_server: Option<String> = None;
        if is_final && !is_2xx {
            // §16.7 step 4: store the final as a best-response candidate —
            // but only when the fork is real (a live server tx exists for
            // the key). A stray final with no transaction behind it falls
            // through to the pass-through forward below.
            let store_key = server_key
                .as_ref()
                .or(derived_key.as_ref())
                .filter(|k| self.server_txs.contains_key(*k))
                .cloned();
            if let Some(k) = store_key {
                self.contexts.entry(k).or_default().push(resp.clone());
                // §16.7 step 5: on 6xx, cancel the still-pending siblings.
                if code >= 600 {
                    if let Some(sk) = server_key.as_ref() {
                        for cancel in self.pending_leg_cancels(sk) {
                            let (msg, target) = cancel;
                            actions.push(Action::Send(msg, target));
                        }
                    }
                }
                // §16.7 step 6: if every leg has now terminated and no
                // final was forwarded yet, forward the best one now.
                if let Some(sk) = server_key.as_ref() {
                    if let Some(mut acts) = self.maybe_complete_fork(sk, now) {
                        actions.append(&mut acts);
                    }
                }
                // The leg ACK still goes downstream immediately (§17.1.1).
                if let Some((ack, target)) = ack_to_leg {
                    actions.push(Action::Send(SipMessage::Request(ack), target));
                }
                return actions;
            }
        }

        // Immediate-forward path (provisional non-100, 2xx, or a stray
        // final with no context): stage + send through the upstream-facing
        // server transaction when it is live.
        let mut staged = false;
        if let Some(k) = server_key.as_ref().or(derived_key.as_ref()) {
            if let Some(sv) = self.server_txs.get_mut(k) {
                // After a final was sent on the server tx, only a 2xx to an
                // INVITE forwards (§16.7 step 5).
                let final_already =
                    matches!(sv.tx.state(), TxState::Completed | TxState::Terminated);
                let forwards_now = (!final_already || is_2xx) && code != 100;
                if forwards_now {
                    sv.tx.stage(resp.clone());
                    for a in sv.tx.on_event(TxEvent::Send, now) {
                        match a {
                            TxAction::SendResponse(r) => {
                                actions.push(Action::Send(SipMessage::Response(r), dest))
                            }
                            TxAction::DeleteTransaction => dead_server = Some(k.clone()),
                            _ => {}
                        }
                    }
                    staged = true;
                }
            }
        }
        if dead_server.is_some() {
            if let Some(k) = dead_server {
                self.server_txs.remove(&k);
            }
        }
        if !staged && code != 100 {
            // No live server tx (late stray response after cleanup): a 2xx
            // still flows (dialog layer owns the 2xx-ACK dance); a non-2xx
            // with no context and no tx forwards once — same as before the
            // fork ever existed.
            actions.push(Action::Send(SipMessage::Response(resp), dest));
        }

        // 4) The ACK the leg's client transaction generated for a non-2xx
        //    final goes to the leg that sent it (§17.1.1).
        if let Some((ack, target)) = ack_to_leg {
            actions.push(Action::Send(SipMessage::Request(ack), target));
        }
        actions
    }

    /// The server-transaction key derived from a response whose OUR via has
    /// already been popped: the new top via is the upstream's own hop.
    fn server_key_from_popped(resp: &Response, method: &Method) -> Option<String> {
        let branch = resp.headers.first_via().and_then(|v| v.branch.clone())?;
        let call_id = resp.headers.call_id()?;
        let seq = resp.headers.cseq()?.seq;
        Some(format!("{call_id}|{branch}|{method}|{seq}"))
    }

    /// §16.7 step 5: CANCEL requests for every still-pending leg of a fork
    /// (tx in Trying/Proceeding). Used when a 6xx final arrives and when a
    /// Timer-C-fired leg is abandoned (§16.8).
    fn pending_leg_cancels(&mut self, server_key: &str) -> Vec<(SipMessage, SocketAddr)> {
        let keys: Vec<String> = self
            .legs
            .iter()
            .filter(|(_, l)| l.server_key.as_deref() == Some(server_key))
            .filter(|(_, l)| matches!(l.tx.state(), TxState::Trying | TxState::Proceeding))
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::new();
        for k in keys {
            let Some(leg) = self.legs.get(&k) else {
                continue;
            };
            let cancel = build_leg_cancel(leg.tx.request());
            out.push((SipMessage::Request(cancel), leg.target));
        }
        out
    }

    /// §16.7 step 6: once every client transaction of the fork has
    /// terminated and no final has been forwarded on the server transaction
    /// yet, choose and forward the best final (6xx first, then the lowest
    /// class, preferring 401/407/415/420/484; 503 is never forwarded — a
    /// 503-only context generates 500). With no stored finals: 408.
    /// Returns `None` while legs are still pending or the fork was already
    /// completed.
    fn maybe_complete_fork(&mut self, server_key: &str, now: Instant) -> Option<Vec<Action>> {
        let all_done = self
            .legs
            .values()
            .filter(|l| l.server_key.as_deref() == Some(server_key))
            .all(|l| matches!(l.tx.state(), TxState::Completed | TxState::Terminated));
        let none_left = !self
            .legs
            .values()
            .any(|l| l.server_key.as_deref() == Some(server_key));
        if !(all_done || none_left) {
            return None;
        }
        let Some(sv) = self.server_txs.get_mut(server_key) else {
            self.contexts.remove(server_key);
            return None;
        };
        if !matches!(sv.tx.state(), TxState::Trying | TxState::Proceeding) {
            // A final was already forwarded (or the tx ended with a 2xx).
            self.contexts.remove(server_key);
            return None;
        }
        let finals = self.contexts.remove(server_key).unwrap_or_default();
        let resp = match choose_best_final(&finals) {
            BestFinal::Response(r) => r,
            // §16.7 step 6: a 503-only context generates a 500 instead of
            // forwarding the 503 upstream.
            BestFinal::Generate500 => respond_to(
                sv.tx.request(),
                500,
                "Server Internal Error",
                Vec::new(),
                None,
            ),
            // §16.7 step 6: no final response in the context → 408.
            BestFinal::None408 => {
                respond_to(sv.tx.request(), 408, "Request Timeout", Vec::new(), None)
            }
        };
        sv.tx.stage(resp);
        let mut actions = Vec::new();
        for a in sv.tx.on_event(TxEvent::Send, now) {
            if let TxAction::SendResponse(r) = a {
                actions.push(Action::Send(SipMessage::Response(r), sv.upstream));
            }
        }
        Some(actions)
    }

    /// Advance every pending transaction timer whose deadline has passed:
    /// client transactions retransmit their requests to their leg targets
    /// (Timer A/E) and clean up (Timer B/F/D/K); server transactions
    /// retransmit staged responses upstream (Timer G/J) and clean up
    /// (Timer H/I/J). Returns the actions to execute.
    pub fn poll(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();

        // Upstream-facing server transactions.
        let mut dead: Vec<String> = Vec::new();
        for (key, sv) in self.server_txs.iter_mut() {
            let due = sv.tx.next_deadline().is_some_and(|d| now >= d);
            if !due {
                continue;
            }
            for a in sv.tx.on_event(TxEvent::Timeout, now) {
                match a {
                    TxAction::SendResponse(r) => {
                        actions.push(Action::Send(SipMessage::Response(r), sv.upstream))
                    }
                    TxAction::SendRequest(r) => {
                        actions.push(Action::Send(SipMessage::Request(r), sv.upstream))
                    }
                    TxAction::DeleteTransaction => dead.push(key.clone()),
                    _ => {}
                }
            }
        }
        for k in dead {
            self.server_txs.remove(&k);
            // The fork's response context has nothing to wait for anymore.
            self.contexts.remove(&k);
        }

        // Downstream fork legs.
        let mut dead_legs: Vec<String> = Vec::new();
        for (key, leg) in self.legs.iter_mut() {
            let due = leg.tx.next_deadline().is_some_and(|d| now >= d);
            if !due {
                continue;
            }
            for a in leg.tx.on_event(TxEvent::Timeout, now) {
                match a {
                    TxAction::SendRequest(r) => {
                        actions.push(Action::Send(SipMessage::Request(r), leg.target))
                    }
                    TxAction::DeleteTransaction => dead_legs.push(key.clone()),
                    _ => {}
                }
            }
        }
        // §16.8: a Timer-C (Timer B) fire on a leg that RANG (got a
        // provisional) must be CANCELed; one that never rang is abandoned
        // as a 408. Then §16.7 step 6: every leg of the fork done and no
        // final forwarded yet → forward the best stored final (or 408).
        let mut touched_servers: Vec<String> = Vec::new();
        for k in &dead_legs {
            let Some(leg) = self.legs.remove(k) else {
                continue;
            };
            if leg.got_provisional {
                let cancel = build_leg_cancel(leg.tx.request());
                actions.push(Action::Send(SipMessage::Request(cancel), leg.target));
            }
            if let Some(sk) = leg.server_key {
                if !touched_servers.contains(&sk) {
                    touched_servers.push(sk);
                }
            }
        }
        for sk in touched_servers {
            if let Some(mut acts) = self.maybe_complete_fork(&sk, now) {
                actions.append(&mut acts);
            }
        }
        actions
    }
}

/// §16.7 step 6 best-response choice: prefer the 6xx class (MUST choose
/// from it if any exist), otherwise the LOWEST class present; within the
/// chosen class, prefer responses that help resubmission (401/407/415/420/
/// 484) in the 4xx case. A 503 is never forwarded upstream: a 503-only
/// context yields [`BestFinal::Generate500`] (the caller generates a 500),
/// and when 5xx wins the class choice a 500 is preferred over a 503.
enum BestFinal {
    Response(Response),
    Generate500,
    None408,
}

fn choose_best_final(finals: &[Response]) -> BestFinal {
    if finals.is_empty() {
        return BestFinal::None408;
    }
    // 503 should not be forwarded — drop it in favor of anything else.
    let all_503 = finals.iter().all(|r| r.code == 503);
    let candidates: Vec<&Response> = if all_503 {
        Vec::new()
    } else {
        finals.iter().filter(|r| r.code != 503).collect()
    };
    if candidates.is_empty() {
        return BestFinal::Generate500; // 503-only → generate 500
    }
    let in_class = |r: &Response, class: u16| r.code / 100 == class;
    // 6xx first.
    if let Some(&r) = candidates.iter().find(|r| in_class(r, 6)) {
        return BestFinal::Response(r.clone());
    }
    // Lowest class present.
    let lowest = candidates.iter().map(|r| r.code / 100).min().unwrap();
    let in_lowest: Vec<&Response> = candidates
        .iter()
        .copied()
        .filter(|r| in_class(r, lowest))
        .collect();
    // Resubmission-helpful 4xx codes get preference.
    const HELPFUL: [u16; 5] = [401, 407, 415, 420, 484];
    for want in HELPFUL {
        if let Some(&r) = in_lowest.iter().find(|r| r.code == want) {
            return BestFinal::Response(r.clone());
        }
    }
    match in_lowest.first() {
        Some(r) => BestFinal::Response((*r).clone()),
        None => BestFinal::None408,
    }
}

/// Build the CANCEL a proxy sends to one fork leg (RFC 3261 §16.7 step 2 +
/// §9.1): same Request-URI, Call-ID, From, To and CSeq seq as the forked
/// INVITE, with the FORKED request's Via stack (so the top branch is the
/// leg's own branch — the INVITE the leg received) and Route set, method
/// CANCEL, Max-Forwards 70, Content-Length 0.
fn build_leg_cancel(forked: &Request) -> Request {
    let cseq = forked.headers.cseq();
    let mut headers = sip_core::headers::HeaderMap::new();
    for v in forked.headers.get_all("Via") {
        headers.add("Via", v);
    }
    for r in forked.headers.get_all("Route") {
        headers.add("Route", r);
    }
    if let Some(f) = forked.headers.get("From") {
        headers.add("From", f);
    }
    if let Some(t) = forked.headers.get("To") {
        headers.add("To", t);
    }
    if let Some(c) = forked.headers.get("Call-ID") {
        headers.add("Call-ID", c);
    }
    headers.set_cseq(sip_core::headers::CSeq {
        seq: cseq.map(|c| c.seq).unwrap_or(0),
        method: Method::Cancel,
    });
    headers.add("Max-Forwards", "70");
    headers.set_content_length(0);
    Request {
        method: Method::Cancel,
        uri: forked.uri.clone(),
        headers,
        body: Vec::new(),
    }
}

/// Push `via` to the top of the request's Via list (header order defines
/// the via list; the topmost hop is position 0).
fn prepend_via(mut req: Request, via: &str) -> Request {
    let existing: Vec<String> = req
        .headers
        .get_all("Via")
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    req.headers.remove_all("Via");
    req.headers.add("Via", via.to_string());
    for v in existing {
        req.headers.add("Via", v);
    }
    req
}

/// Destination selection for a response whose OUR via has already been
/// popped (RFC 3261 §18.2.2): prefer received+rport (NAT), then received,
/// then the advertised sent-by.
fn dest_from_via(resp: &Response) -> Option<SocketAddr> {
    resp.headers.first_via().and_then(|v| {
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
    })
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
            .field("legs", &self.legs.len())
            .field("server_txs", &self.server_txs.len())
            .finish()
    }
}
