//! Client transactions (RFC 3261 §17.1).
//!
//! [`ClientInviteTx`] implements the exact §17.1.1.2 state diagram: Timer
//! A retransmissions doubling without a cap, Timer B total timeout,
//! Timer D dwell after a final response. [`ClientNonInviteTx`] implements
//! §17.1.2.2: Timer E doubling capped at T2, Timer F total timeout,
//! Timer K dwell.

use crate::matching::{self, TxKey};
use crate::{add, earliest, TimerConfig, Transport, TxAction, TxEvent, TxState};
use sip_core::headers::HeaderMap;
use sip_core::message::{Method, Request, Response, SipMessage};
use std::time::Instant;

/// Client transaction for an INVITE (RFC 3261 §17.1.1).
#[derive(Debug)]
pub struct ClientInviteTx {
    req: Request,
    key: TxKey,
    transport: Transport,
    cfg: TimerConfig,
    state: TxState,
    sent: bool,
    /// Current Timer A interval (doubles per fire, no cap for INVITE).
    a_interval: std::time::Duration,
    timer_a: Option<Instant>,
    timer_b: Option<Instant>,
    timer_d: Option<Instant>,
}

impl ClientInviteTx {
    /// Creates the transaction for `req`; call
    /// [`on_event`](Self::on_event) with [`TxEvent::Send`] to start it.
    pub fn new(req: Request, transport: Transport) -> Self {
        let key = TxKey::from_request(&req).unwrap_or(TxKey {
            method: req.method.clone(),
            branch: String::new(),
            sent_by: String::new(),
            seq: req.headers.cseq().map(|c| c.seq).unwrap_or(0),
        });
        ClientInviteTx {
            req,
            key,
            transport,
            cfg: TimerConfig::default(),
            state: TxState::Trying,
            sent: false,
            a_interval: TimerConfig::default().t1,
            timer_a: None,
            timer_b: None,
            timer_d: None,
        }
    }

    /// Overrides the default timer configuration.
    pub fn with_timers(mut self, cfg: TimerConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// Current state.
    pub fn state(&self) -> TxState {
        self.state
    }

    /// The request this transaction was created for.
    pub fn request(&self) -> &Request {
        &self.req
    }

    /// Earliest pending timer, if any. Deliver [`TxEvent::Timeout`] when
    /// this instant passes.
    pub fn next_deadline(&self) -> Option<Instant> {
        earliest(self.timer_a, earliest(self.timer_b, self.timer_d))
    }

    /// Processes one event, returning the actions to execute in order.
    pub fn on_event(&mut self, ev: TxEvent, now: Instant) -> Vec<TxAction> {
        match ev {
            TxEvent::Send => self.on_send(now),
            TxEvent::Timeout => self.on_timeout(now),
            TxEvent::Delivered => {
                // Transport confirmed delivery; retransmissions stop but
                // the timeout timer keeps guarding the transaction.
                self.timer_a = None;
                Vec::new()
            }
            TxEvent::Received(resp) => self.on_response(resp, now),
            TxEvent::ReceivedRequest(_) => Vec::new(),
            TxEvent::TransportError => {
                self.terminate();
                vec![TxAction::DeleteTransaction]
            }
        }
    }

    fn on_send(&mut self, now: Instant) -> Vec<TxAction> {
        if self.sent || self.state != TxState::Trying {
            return Vec::new();
        }
        self.sent = true;
        // Timer B (INVITE) / F (non-INVITE) apply on EVERY transport
        // (§17.1.1.2/§17.1.2.2); only the retransmission timers A/E are
        // UDP-only. Without Timer B a TCP/TLS/WSS peer that stalls would
        // hang the transaction forever.
        self.timer_b = Some(add(now, self.cfg.timer_bfh()));
        if !self.transport.is_reliable() {
            self.a_interval = self.cfg.t1;
            self.timer_a = Some(add(now, self.cfg.t1));
        }
        vec![TxAction::SendRequest(self.req.clone())]
    }

    fn on_timeout(&mut self, now: Instant) -> Vec<TxAction> {
        match self.state {
            TxState::Trying | TxState::Proceeding => {
                if self.timer_b.is_some_and(|t| now >= t) {
                    // Timer B: the transaction timed out; the TU learns of
                    // it because it fired this Timeout itself.
                    self.terminate();
                    return vec![TxAction::DeleteTransaction];
                }
                if self.timer_a.is_some_and(|t| now >= t) {
                    // Timer A: retransmit, double, no cap (§17.1.1.2).
                    self.a_interval *= 2;
                    self.timer_a = Some(add(now, self.a_interval));
                    return vec![TxAction::SendRequest(self.req.clone())];
                }
                Vec::new()
            }
            TxState::Completed | TxState::Terminated => {
                if self.timer_d.is_some_and(|t| now >= t) {
                    self.timer_d = None;
                    return vec![TxAction::DeleteTransaction];
                }
                Vec::new()
            }
        }
    }

    fn on_response(&mut self, resp: Response, now: Instant) -> Vec<TxAction> {
        if !matching::response_matches(&self.key, &resp) {
            return Vec::new();
        }
        match self.state {
            TxState::Trying | TxState::Proceeding => {
                if resp.is_provisional() {
                    // Timer A stops, Timer B keeps running (§17.1.1.2).
                    self.state = TxState::Proceeding;
                    self.timer_a = None;
                    return vec![TxAction::PassToTu(SipMessage::Response(resp))];
                }
                self.timer_a = None;
                self.timer_b = None;
                if resp.class() == 2 {
                    // 2xx: the transaction ends; the dialog layer owns ACK
                    // retransmission. Timer D only gates memory release.
                    self.state = TxState::Terminated;
                    if self.transport.is_reliable() {
                        return vec![TxAction::PassToTu(SipMessage::Response(resp))];
                    }
                    self.timer_d = Some(add(now, self.cfg.timer_d()));
                    return vec![TxAction::PassToTu(SipMessage::Response(resp))];
                }
                // Non-2xx final: pass up, generate the ACK here (§17.1.1)
                // and dwell in Completed for Timer D.
                self.state = TxState::Completed;
                let ack = build_non2xx_ack(&self.req, &resp);
                let mut out = vec![TxAction::PassToTu(SipMessage::Response(resp))];
                if let Some(ack) = ack {
                    out.push(TxAction::SendRequest(ack));
                }
                if self.transport.is_reliable() {
                    out.push(TxAction::DeleteTransaction);
                } else {
                    self.timer_d = Some(add(now, self.cfg.timer_d()));
                }
                out
            }
            TxState::Completed => {
                // Retransmitted final response: re-ACK, do not pass to TU
                // again (§17.1.1.1).
                if resp.is_final() {
                    return build_non2xx_ack(&self.req, &resp)
                        .map(|ack| vec![TxAction::SendRequest(ack)])
                        .unwrap_or_default();
                }
                Vec::new()
            }
            TxState::Terminated => Vec::new(),
        }
    }

    fn terminate(&mut self) {
        self.state = TxState::Terminated;
        self.timer_a = None;
        self.timer_b = None;
        self.timer_d = None;
    }
}

/// Client transaction for everything but INVITE (RFC 3261 §17.1.2).
#[derive(Debug)]
pub struct ClientNonInviteTx {
    req: Request,
    key: TxKey,
    transport: Transport,
    cfg: TimerConfig,
    state: TxState,
    sent: bool,
    /// Current Timer E interval (doubles, capped at T2).
    e_interval: std::time::Duration,
    timer_e: Option<Instant>,
    timer_f: Option<Instant>,
    timer_k: Option<Instant>,
}

impl ClientNonInviteTx {
    /// Creates the transaction for `req`.
    pub fn new(req: Request, transport: Transport) -> Self {
        let key = TxKey::from_request(&req).unwrap_or(TxKey {
            method: req.method.clone(),
            branch: String::new(),
            sent_by: String::new(),
            seq: req.headers.cseq().map(|c| c.seq).unwrap_or(0),
        });
        ClientNonInviteTx {
            req,
            key,
            transport,
            cfg: TimerConfig::default(),
            state: TxState::Trying,
            sent: false,
            e_interval: TimerConfig::default().t1,
            timer_e: None,
            timer_f: None,
            timer_k: None,
        }
    }

    /// Overrides the default timer configuration.
    pub fn with_timers(mut self, cfg: TimerConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// Current state.
    pub fn state(&self) -> TxState {
        self.state
    }

    /// The request this transaction was created for.
    pub fn request(&self) -> &Request {
        &self.req
    }

    /// Earliest pending timer, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        earliest(self.timer_e, earliest(self.timer_f, self.timer_k))
    }

    /// Processes one event, returning the actions to execute in order.
    pub fn on_event(&mut self, ev: TxEvent, now: Instant) -> Vec<TxAction> {
        match ev {
            TxEvent::Send => self.on_send(now),
            TxEvent::Timeout => self.on_timeout(now),
            TxEvent::Delivered => {
                self.timer_e = None;
                Vec::new()
            }
            TxEvent::Received(resp) => self.on_response(resp, now),
            TxEvent::ReceivedRequest(_) => Vec::new(),
            TxEvent::TransportError => {
                self.terminate();
                vec![TxAction::DeleteTransaction]
            }
        }
    }

    fn on_send(&mut self, now: Instant) -> Vec<TxAction> {
        if self.sent || self.state != TxState::Trying {
            return Vec::new();
        }
        self.sent = true;
        // Timer F applies on every transport (§17.1.2.2); Timer E is
        // UDP-only retransmission.
        self.timer_f = Some(add(now, self.cfg.timer_bfh()));
        if !self.transport.is_reliable() {
            self.e_interval = self.cfg.t1;
            self.timer_e = Some(add(now, self.cfg.t1));
        }
        vec![TxAction::SendRequest(self.req.clone())]
    }

    fn on_timeout(&mut self, now: Instant) -> Vec<TxAction> {
        match self.state {
            TxState::Trying | TxState::Proceeding => {
                if self.timer_f.is_some_and(|t| now >= t) {
                    self.terminate();
                    return vec![TxAction::DeleteTransaction];
                }
                if self.timer_e.is_some_and(|t| now >= t) {
                    // Doubling in Trying, fixed T2 in Proceeding (§17.1.2.2).
                    if self.state == TxState::Trying {
                        self.e_interval = std::cmp::min(self.e_interval * 2, self.cfg.t2);
                    } else {
                        self.e_interval = self.cfg.t2;
                    }
                    self.timer_e = Some(add(now, self.e_interval));
                    return vec![TxAction::SendRequest(self.req.clone())];
                }
                Vec::new()
            }
            TxState::Completed | TxState::Terminated => {
                if self.timer_k.is_some_and(|t| now >= t) {
                    self.timer_k = None;
                    return vec![TxAction::DeleteTransaction];
                }
                Vec::new()
            }
        }
    }

    fn on_response(&mut self, resp: Response, now: Instant) -> Vec<TxAction> {
        if !matching::response_matches(&self.key, &resp) {
            return Vec::new();
        }
        match self.state {
            TxState::Trying | TxState::Proceeding => {
                if resp.is_provisional() {
                    self.state = TxState::Proceeding;
                    self.e_interval = self.cfg.t2;
                    self.timer_e = Some(add(now, self.cfg.t2));
                    return vec![TxAction::PassToTu(SipMessage::Response(resp))];
                }
                self.timer_e = None;
                self.timer_f = None;
                self.state = TxState::Completed;
                if self.transport.is_reliable() {
                    return vec![
                        TxAction::PassToTu(SipMessage::Response(resp)),
                        TxAction::DeleteTransaction,
                    ];
                }
                self.timer_k = Some(add(now, self.cfg.t4));
                vec![TxAction::PassToTu(SipMessage::Response(resp))]
            }
            TxState::Completed | TxState::Terminated => Vec::new(),
        }
    }

    fn terminate(&mut self) {
        self.state = TxState::Terminated;
        self.timer_e = None;
        self.timer_f = None;
        self.timer_k = None;
    }
}

/// Builds the ACK a client INVITE transaction sends for a non-2xx final
/// response (RFC 3261 §17.1.1): same request-URI, From/Call-ID mirrored,
/// To taken from the response (carries its tag), CSeq number kept with
/// method ACK. Per §17.1.1.2 the ACK carries a SINGLE Via — equal to the
/// top Via of the original request, so the branch matches the server
/// transaction — and the same Route set as the original request so it
/// traverses the same proxies (copying the whole Via stack pointed the
/// server transaction at a branch that is not the top).
pub fn build_non2xx_ack(req: &Request, resp: &Response) -> Option<Request> {
    let cseq = resp.headers.cseq()?;
    let mut headers = HeaderMap::new();
    if let Some(top) = req.headers.get("Via") {
        headers.add("Via", top);
    }
    for route in req.headers.get_all("Route") {
        headers.add("Route", route);
    }
    if let Some(f) = resp.headers.get("From") {
        headers.add("From", f);
    }
    if let Some(t) = resp.headers.get("To") {
        headers.add("To", t);
    }
    if let Some(c) = resp.headers.get("Call-ID") {
        headers.add("Call-ID", c);
    }
    headers.set_cseq(sip_core::headers::CSeq {
        seq: cseq.seq,
        method: Method::Ack,
    });
    headers.add("Max-Forwards", "70");
    headers.set_content_length(0);
    Some(Request {
        method: Method::Ack,
        uri: req.uri.clone(),
        headers,
        body: Vec::new(),
    })
}
