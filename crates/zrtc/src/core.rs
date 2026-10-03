//! The zrtc request pipeline: every parsed SIP message from any listener is
//! fed through here.
//!
//! ```text
//! listeners (UDP/TCP/TLS/WSS)
//!      │
//!      ▼
//!    SBC  ── ACL / rate limit / rport / topology hiding
//!      │
//!      ▼
//!   core router ── REGISTER ──▶ registrar (bindings feed the proxy)
//!               └─ INVITE/ACK/BYE/CANCEL ──▶ proxy ──▶ b2bua (loopback UDP)
//!      ▲
//!      └── responses from the b2bua come back through proxy.process_response
//!          and are forwarded to the originating transport (UDP socket or the
//!          exact TCP/TLS/WSS connection the request arrived on).
//! ```

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use registrar::Registrar;
use sbc::{Sbc, SbcAction};
use sip_core::builder::respond_to;
use sip_core::message::{Method, Request, Response, SipMessage};
use sip_core::serialize;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};

/// The Via host the `proxy` crate stamps on every hop it adds (see
/// `proxy::make_via`); responses carrying it on top are routed by the proxy.
pub const PROXY_VIA_HOST: &str = "proxy.voip-stack";

/// One message handed from a listener into the core pump.
pub struct Incoming {
    pub msg: SipMessage,
    pub resp: Responder,
}

/// How to answer the source of an incoming message.
#[derive(Clone)]
pub struct Responder {
    pub src: SocketAddr,
    /// Present for connection-oriented transports: pushes serialized bytes
    /// onto that connection's writer task (bounded: when a peer stops
    /// reading, responses are dropped instead of buffering without limit).
    pub conn: Option<Sender<Vec<u8>>>,
}

/// Registry of live connection-oriented transports (TCP/TLS/WSS), keyed by
/// the peer socket address.
pub type ConnRegistry = Arc<Mutex<HashMap<SocketAddr, Sender<Vec<u8>>>>>;

/// The core pipeline: SBC → router → registrar/proxy plus the response path.
pub struct Core {
    pub sbc: Sbc,
    pub proxy: proxy::Proxy,
    pub registrar: Registrar,
    udp: Arc<UdpSocket>,
    registry: ConnRegistry,
    /// Socket address the b2bua engine listens on (in-process, loopback).
    b2bua_addr: SocketAddr,
    /// Call-ID → client endpoint, learned when proxying requests so core
    /// originated in-dialog requests (e.g. a callee-side BYE) reach the
    /// right client connection.
    clients: HashMap<String, Responder>,
}

impl Core {
    pub fn new(
        sbc: Sbc,
        proxy: proxy::Proxy,
        registrar: Registrar,
        udp: Arc<UdpSocket>,
        registry: ConnRegistry,
        b2bua_addr: SocketAddr,
    ) -> Self {
        Core {
            sbc,
            proxy,
            registrar,
            udp,
            registry,
            b2bua_addr,
            clients: HashMap::new(),
        }
    }

    /// The core pump: consumes every incoming message forever, sweeping
    /// expired registrar bindings every 30 s and advancing the proxy's
    /// RFC 3261 §17 transaction timers every 500 ms (Timer T1). The input
    /// channel is bounded: listener tasks back-pressure when the pump falls
    /// behind.
    pub async fn pump(mut self, mut rx: Receiver<Incoming>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut tx_ticker = tokio::time::interval(std::time::Duration::from_millis(500));
        tx_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                item = rx.recv() => {
                    let Some(Incoming { msg, resp }) = item else {
                        tracing::warn!("core pump input closed");
                        break;
                    };
                    self.handle(msg, resp).await;
                }
                _ = ticker.tick() => self.sweep(),
                _ = tx_ticker.tick() => {
                    // Transaction-timer sweep: Timer A/E/G retransmissions,
                    // Timer B/F/H/I/J/K cleanup (leak-free by construction).
                    let now = std::time::Instant::now();
                    for action in self.proxy.poll(now) {
                        match action {
                            proxy::Action::Send(SipMessage::Request(r), dst) => {
                                let bytes = serialize(&SipMessage::Request(r));
                                self.send_datagram(&bytes, dst).await;
                            }
                            proxy::Action::Send(msg, dst) => {
                                self.send_routed_response(msg, dst).await;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn handle(&mut self, msg: SipMessage, resp: Responder) {
        match msg {
            SipMessage::Request(req) => self.handle_request(req, resp).await,
            SipMessage::Response(r) => self.handle_response(r, resp).await,
        }
    }

    async fn handle_request(&mut self, req: Request, resp: Responder) {
        // Requests arriving FROM the in-process b2bua are core→client
        // in-dialog requests; route them to the client we learned.
        if resp.src == self.b2bua_addr {
            let Some(call_id) = req.headers.call_id().map(str::to_string) else {
                return;
            };
            if let Some(client) = self.clients.get(&call_id).cloned() {
                let bytes = serialize(&SipMessage::Request(req));
                self.send_to_responder(&bytes, &client).await;
            } else {
                tracing::debug!(%call_id, "no client endpoint for core request; dropped");
            }
            return;
        }

        // Border screening.
        match self.sbc.process_request(&req, resp.src) {
            SbcAction::Refuse(refusal) => {
                let screened = self.sbc.process_response(&refusal);
                let bytes = serialize(&SipMessage::Response(screened));
                self.send_to_responder(&bytes, &resp).await;
            }
            SbcAction::Relay(relayed) => self.route(relayed, resp).await,
        }
    }

    /// Post-SBC routing: REGISTER to the registrar, everything else through
    /// the stateful proxy.
    async fn route(&mut self, req: Request, resp: Responder) {
        match req.method {
            Method::Register => {
                let src = resp.src.to_string();
                match self.registrar.process(&req, &src) {
                    Ok(ok) => {
                        self.sync_bindings();
                        let screened = self.sbc.process_response(&ok);
                        let bytes = serialize(&SipMessage::Response(screened));
                        self.send_to_responder(&bytes, &resp).await;
                    }
                    Err(e) => {
                        tracing::info!(source = %src, "registrar rejected REGISTER: {e}");
                        let bad = respond_to(&req, 400, "Bad Request", Vec::new(), None);
                        let bytes = serialize(&SipMessage::Response(bad));
                        self.send_to_responder(&bytes, &resp).await;
                    }
                }
            }
            Method::Options => {
                // Local keepalive: terminate at the edge.
                let ok = respond_to(&req, 200, "OK", Vec::new(), None);
                let screened = self.sbc.process_response(&ok);
                let bytes = serialize(&SipMessage::Response(screened));
                self.send_to_responder(&bytes, &resp).await;
            }
            _ => {
                let src = resp.src;
                let call_id = req.headers.call_id().unwrap_or("").to_string();
                if !call_id.is_empty() {
                    // Learn where this call's client lives (for core→client
                    // in-dialog requests later); a BYE/CANCEL ends the call —
                    // drop the learned endpoint so the map cannot grow
                    // without bound.
                    if matches!(req.method, Method::Bye | Method::Cancel) {
                        self.clients.remove(&call_id);
                    } else {
                        self.clients.insert(call_id, resp.clone());
                    }
                }
                for action in self.proxy.process_request(
                    &req,
                    src,
                    resp.conn.is_some(),
                    std::time::Instant::now(),
                ) {
                    match action {
                        proxy::Action::Send(msg, dst) => {
                            // The proxy's local provisional responses target
                            // the requester: keep them on the arriving
                            // transport; everything else routes by address.
                            if dst == resp.src {
                                let bytes = serialize(&msg);
                                self.send_to_responder(&bytes, &resp).await;
                            } else if let SipMessage::Request(fwd) = &msg {
                                self.remember_client(fwd, resp.clone());
                                let bytes = serialize(&msg);
                                self.send_datagram(&bytes, dst).await;
                            } else {
                                self.send_routed_response(msg, dst).await;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Requests forked downstream carry the original client Via stack; use
    /// them to refresh the client endpoint table.
    fn remember_client(&mut self, fwd: &Request, resp: Responder) {
        let Some(call_id) = fwd.headers.call_id().map(str::to_string) else {
            return;
        };
        self.clients.insert(call_id, resp);
    }

    async fn handle_response(&mut self, resp: Response, from: Responder) {
        // The top Via host says who owns this response: the proxy (responses
        // to proxied requests) or the in-process b2bua (responses to its own
        // in-dialog requests, which the core relays transparently).
        let ours = resp
            .headers
            .first_via()
            .map(|v| v.sent_by.host.to_string())
            .unwrap_or_default();
        let b2bua = ours == self.b2bua_addr.ip().to_string();
        if ours != PROXY_VIA_HOST && !b2bua {
            // Late stray response (e.g. from a torn-down transaction): drop.
            tracing::debug!(src = %from.src, "unmatched response dropped");
            return;
        }
        if b2bua {
            // The b2bua is a dialog-level UA here: its Via was never touched
            // by the proxy, so hand the response straight back to it.
            let bytes = serialize(&SipMessage::Response(resp));
            self.send_datagram(&bytes, self.b2bua_addr).await;
            return;
        }

        // SBC response processing first: unhide rewritten Call-IDs so the
        // learned-client lookup (keyed by the real Call-ID) can match.
        let resp = self.sbc.process_response(&resp);
        // §16.7: pop the proxy's own Via (this used to be skipped entirely
        // when a client endpoint was known, leaving the proxy Via unpopped
        // and making proxy.process_response unreachable dead code).
        let forwarded = self
            .proxy
            .process_response(&resp, from.src, std::time::Instant::now());

        // RFC 3261 §18.2.2: prefer the learned per-call endpoint for the
        // upstream-bound responses; downstream requests (the leg-ACK the
        // client tx generated) route by address.
        let call_id = resp.headers.call_id().unwrap_or("").to_string();
        let client = self.clients.get(&call_id).cloned();
        for action in forwarded {
            let proxy::Action::Send(msg, dst) = action;
            match &msg {
                SipMessage::Request(req) => {
                    let bytes = serialize(&SipMessage::Request(req.clone()));
                    self.send_datagram(&bytes, dst).await;
                }
                SipMessage::Response(_) => {
                    if let Some(client) = &client {
                        let bytes = serialize(&msg);
                        self.send_to_responder(&bytes, client).await;
                    } else {
                        self.send_routed_response(msg, dst).await;
                    }
                }
            }
        }
    }

    /// Sends a response to the destination implied by its top Via: reliable
    /// transports go back over the exact registered connection, UDP over the
    /// shared socket (RFC 3261 §18.2.2).
    async fn send_routed_response(&self, msg: SipMessage, dst: SocketAddr) {
        let bytes = serialize(&msg);
        if let SipMessage::Response(r) = &msg {
            if let Some(via) = r.headers.first_via() {
                match via.transport {
                    sip_core::uri::TransportKind::Udp => {}
                    _ => {
                        let tx = self
                            .registry
                            .lock()
                            .expect("registry lock")
                            .get(&dst)
                            .cloned();
                        match tx {
                            Some(tx) => {
                                if let Err(e) = tx.try_send(bytes) {
                                    tracing::warn!(%dst, "reliable response dropped: {e}");
                                }
                                return;
                            }
                            None => {
                                tracing::warn!(%dst, "no live connection for reliable response; dropped");
                                return;
                            }
                        }
                    }
                }
            }
        }
        self.send_datagram(&bytes, dst).await;
    }

    async fn send_to_responder(&self, bytes: &[u8], resp: &Responder) {
        match &resp.conn {
            Some(tx) => {
                if let Err(e) = tx.try_send(bytes.to_vec()) {
                    tracing::warn!(src = %resp.src, "connection write dropped: {e}");
                }
            }
            None => self.send_datagram(bytes, resp.src).await,
        }
    }

    async fn send_datagram(&self, bytes: &[u8], dst: SocketAddr) {
        // socket-boundary tap (SipTx over the shared UDP socket)
        observ::session::sip_tap(bytes, dst, observ::event::Transport::Udp, false);
        if let Err(e) = self.udp.send_to(bytes, dst).await {
            tracing::warn!(%dst, "udp send failed: {e}");
        }
    }

    /// Mirrors registrar bindings into the proxy's routing table so INVITEs
    /// to a registered AoR fork to the bound contact (the in-process b2bua).
    fn sync_bindings(&mut self) {
        self.proxy.bindings.clear();
        for (aor, entry) in &self.registrar.aors {
            // Aors are "sip:<user>@<domain>" — the proxy keys bindings by
            // the bare user part (request-URI user), not "sip:<user>".
            let user = aor
                .trim_start_matches("sips:")
                .trim_start_matches("sip:")
                .split('@')
                .next()
                .unwrap_or(aor)
                .to_string();
            let contacts: Vec<String> = entry
                .active()
                .into_iter()
                .map(|b| b.contact.clone())
                .collect();
            if !contacts.is_empty() {
                self.proxy.bindings.insert(user, contacts);
            }
        }
    }

    /// Periodic housekeeping (expired bindings).
    pub fn sweep(&mut self) {
        self.registrar.sweep_expired();
    }
}

/// Call-IDs the daemon itself originated (used to label CDR direction).
pub type OutboundIds = Arc<Mutex<HashSet<String>>>;
