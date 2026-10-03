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
//! - Best-response selection per branch (§16.7 step 6 simplified: every
//!   response forwards upstream immediately; the upstream client
//!   transaction absorbs the extra finals as retransmissions)
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
    /// Reserved for §16.7 step 6 best-response buffering (not yet
    /// implemented — responses forward immediately, and the upstream client
    /// transaction absorbs the extra finals as retransmissions).
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
    /// Via, stage the response into the upstream-facing server transaction
    /// (so a lost final is retransmitted upstream, §17.2) and forward it to
    /// the next hop (the source implied by the new top Via's
    /// received/rport).
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
        let mut ack_to_leg: Option<(Request, SocketAddr)> = None;
        let mut drop_leg = false;
        let mut server_key: Option<String> = None;
        if let Some(leg) = self.legs.get_mut(&leg_key) {
            server_key = leg.server_key.clone();
            for a in leg.tx.on_event(TxEvent::Received(resp.clone()), now) {
                match a {
                    TxAction::SendRequest(ack) => ack_to_leg = Some((ack, leg.target)),
                    TxAction::DeleteTransaction => drop_leg = true,
                    _ => {}
                }
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

        // 3) Stage + send through the upstream-facing server transaction
        //    (INVITE: provisionals and finals — §17.2.1; non-INVITE:
        //    finals only — §17.2.2). Without a live server tx (late stray
        //    response after cleanup) the response still forwards once.
        let mut actions = Vec::new();
        let is_final = resp.code >= 200;
        let mut dead_server: Option<String> = None;
        let mut staged = false;
        if let Some(k) = server_key.as_ref() {
            if let Some(sv) = self.server_txs.get_mut(k) {
                let invite = matches!(sv.tx, ServerTx::Invite(_));
                if is_final || invite {
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
        if !staged {
            actions.push(Action::Send(SipMessage::Response(resp), dest));
        }

        // 4) The ACK the leg's client transaction generated for a non-2xx
        //    final goes to the leg that sent it (§17.1.1).
        if let Some((ack, target)) = ack_to_leg {
            actions.push(Action::Send(SipMessage::Request(ack), target));
        }
        actions
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
        // Fork-wide timeout (§16.7 step 6): when every leg of a fork is gone
        // and its upstream-facing server transaction never reached a final
        // response, generate a 408 through it so the upstream client
        // transaction completes and the tx cleans up (Timer H/I) instead of
        // lingering in Trying/Proceeding forever.
        let mut timed_out_servers: Vec<String> = Vec::new();
        for k in &dead_legs {
            let Some(leg) = self.legs.remove(k) else {
                continue;
            };
            if let Some(sk) = leg.server_key {
                let still_forking = self
                    .legs
                    .values()
                    .any(|l| l.server_key.as_ref() == Some(&sk));
                if !still_forking {
                    timed_out_servers.push(sk);
                }
            }
        }
        for sk in timed_out_servers {
            let Some(sv) = self.server_txs.get_mut(&sk) else {
                continue;
            };
            if matches!(sv.tx.state(), TxState::Trying | TxState::Proceeding) {
                let timeout = respond_to(sv.tx.request(), 408, "Request Timeout", Vec::new(), None);
                sv.tx.stage(timeout);
                for a in sv.tx.on_event(TxEvent::Send, now) {
                    if let TxAction::SendResponse(r) = a {
                        actions.push(Action::Send(SipMessage::Response(r), sv.upstream));
                    }
                }
            }
        }
        actions
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
