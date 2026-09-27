//! Server transactions (RFC 3261 §17.2).
//!
//! [`ServerInviteTx`] implements the exact §17.2.1 state diagram: Timer G
//! final-response retransmissions doubling capped at T2, Timer H ACK
//! timeout, Timer I dwell after the ACK. The RFC's `Confirmed` state maps
//! to [`TxState::Completed`] with [`ServerInviteTx::is_confirmed`] set.
//! [`ServerNonInviteTx`] implements §17.2.2: Timer J after the final
//! response. Responses are handed in via [`ServerInviteTx::stage`] /
//! [`ServerNonInviteTx::stage`] and transmitted by
//! [`TxEvent::Send`].

use crate::matching::{self, TxKey};
use crate::{add, earliest, TimerConfig, Transport, TxAction, TxEvent, TxState};
use sip_core::message::{Method, Request, Response};
use std::time::Instant;

/// Server transaction for an INVITE (RFC 3261 §17.2.1).
#[derive(Debug)]
pub struct ServerInviteTx {
    invite: Request,
    key: TxKey,
    transport: Transport,
    cfg: TimerConfig,
    state: TxState,
    confirmed: bool,
    /// Last provisional response (retransmitted on INVITE retransmission).
    last_provisional: Option<Response>,
    /// Final non-2xx response (retransmitted by Timer G / on request
    /// retransmission).
    final_resp: Option<Response>,
    staged: Option<Response>,
    g_interval: std::time::Duration,
    timer_g: Option<Instant>,
    timer_h: Option<Instant>,
    timer_i: Option<Instant>,
}

impl ServerInviteTx {
    /// Creates the transaction for the INVITE just received.
    pub fn new(invite: Request, transport: Transport) -> Self {
        let key = TxKey::from_request(&invite).unwrap_or(TxKey {
            method: invite.method.clone(),
            branch: String::new(),
            sent_by: String::new(),
            seq: invite.headers.cseq().map(|c| c.seq).unwrap_or(0),
        });
        ServerInviteTx {
            invite,
            key,
            transport,
            cfg: TimerConfig::default(),
            state: TxState::Trying,
            confirmed: false,
            last_provisional: None,
            final_resp: None,
            staged: None,
            g_interval: TimerConfig::default().t1,
            timer_g: None,
            timer_h: None,
            timer_i: None,
        }
    }

    /// Overrides the default timer configuration.
    pub fn with_timers(mut self, cfg: TimerConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// Stages the response the TU wants sent; the next
    /// [`TxEvent::Send`](crate::TxEvent::Send) transmits it.
    pub fn stage(&mut self, resp: Response) {
        self.staged = Some(resp);
    }

    /// Current state.
    pub fn state(&self) -> TxState {
        self.state
    }

    /// Whether the matching ACK has been seen (RFC `Confirmed` state).
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// The INVITE this transaction was created for.
    pub fn request(&self) -> &Request {
        &self.invite
    }

    /// Earliest pending timer, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        earliest(self.timer_g, earliest(self.timer_h, self.timer_i))
    }

    /// Processes one event, returning the actions to execute in order.
    pub fn on_event(&mut self, ev: TxEvent, now: Instant) -> Vec<TxAction> {
        match ev {
            TxEvent::Send => self.on_send(now),
            TxEvent::Timeout => self.on_timeout(now),
            TxEvent::Delivered => {
                // Final delivered by the transport; Timer G stops, Timer H
                // still waits for the ACK.
                self.timer_g = None;
                Vec::new()
            }
            TxEvent::ReceivedRequest(req) => self.on_request(&req, now),
            TxEvent::Received(_) => Vec::new(),
            TxEvent::TransportError => {
                self.terminate();
                vec![TxAction::DeleteTransaction]
            }
        }
    }

    fn on_send(&mut self, now: Instant) -> Vec<TxAction> {
        let Some(resp) = self.staged.take() else {
            return Vec::new();
        };
        if self.state == TxState::Terminated {
            return Vec::new();
        }
        if resp.is_provisional() {
            self.last_provisional = Some(resp.clone());
            if self.state == TxState::Trying {
                self.state = TxState::Proceeding;
            }
            return vec![TxAction::SendResponse(resp)];
        }
        if resp.class() == 2 {
            // The INVITE server transaction ends with the 2xx: the ACK for
            // a 2xx is a separate, dialog-level transaction (§17.2.1).
            self.terminate();
            return vec![
                TxAction::SendResponse(resp),
                TxAction::DeleteTransaction,
            ];
        }
        // Non-2xx final: Completed, Timer G (unreliable) + Timer H.
        self.final_resp = Some(resp.clone());
        self.state = TxState::Completed;
        if !self.transport.is_reliable() {
            self.g_interval = self.cfg.t1;
            self.timer_g = Some(add(now, self.cfg.t1));
        }
        self.timer_h = Some(add(now, self.cfg.timer_bfh()));
        vec![TxAction::SendResponse(resp)]
    }

    fn on_timeout(&mut self, now: Instant) -> Vec<TxAction> {
        match self.state {
            TxState::Completed => {
                if self.timer_i.is_some_and(|t| now >= t) {
                    // ACK seen; Timer I dwell elapsed → release.
                    self.terminate();
                    return vec![TxAction::DeleteTransaction];
                }
                if self.timer_h.is_some_and(|t| now >= t) {
                    // No ACK arrived: report to the TU by terminating.
                    self.terminate();
                    return vec![TxAction::DeleteTransaction];
                }
                if self.timer_g.is_some_and(|t| now >= t) {
                    // Retransmit the final, doubling capped at T2 (§17.2.1).
                    self.g_interval = std::cmp::min(self.g_interval * 2, self.cfg.t2);
                    self.timer_g = Some(add(now, self.g_interval));
                    return self
                        .final_resp
                        .clone()
                        .map(|r| vec![TxAction::SendResponse(r)])
                        .unwrap_or_default();
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn on_request(&mut self, req: &Request, now: Instant) -> Vec<TxAction> {
        if self.state == TxState::Terminated {
            // After the 2xx the transaction is gone: an ACK here belongs to
            // the dialog layer, not to this state machine (§17.2.3).
            return Vec::new();
        }
        if matching::ack_matches_invite(req, &self.invite) {
            if self.state == TxState::Completed && !self.confirmed {
                self.confirmed = true;
                self.timer_g = None;
                self.timer_h = None;
                if self.transport.is_reliable() {
                    self.state = TxState::Terminated;
                    return vec![TxAction::DeleteTransaction];
                }
                self.timer_i = Some(add(now, self.cfg.t4));
            }
            // Repeated ACKs and ACKs in Trying/Proceeding are absorbed.
            return Vec::new();
        }
        // Retransmission of the original INVITE (§17.2.1)? Same key except
        // the method must be INVITE.
        if req.method != Method::Invite {
            return Vec::new();
        }
        if !self.request_retransmission_matches(req) {
            return Vec::new();
        }
        match self.state {
            TxState::Trying => Vec::new(), // nothing sent yet: absorb
            TxState::Proceeding => self
                .last_provisional
                .clone()
                .map(|r| vec![TxAction::SendResponse(r)])
                .unwrap_or_default(),
            TxState::Completed => self
                .final_resp
                .clone()
                .map(|r| vec![TxAction::SendResponse(r)])
                .unwrap_or_default(),
            TxState::Terminated => Vec::new(),
        }
    }

    /// Branch/sent-by/CSeq match for a retransmitted original request.
    fn request_retransmission_matches(&self, req: &Request) -> bool {
        let Some(via) = req.headers.first_via() else {
            return false;
        };
        if via.sent_by.to_string() != self.key.sent_by {
            return false;
        }
        if crate::matching::magic_branch(req).as_deref() != Some(self.key.branch.as_str()) {
            return false;
        }
        req.headers.cseq().is_some_and(|c| c.seq == self.key.seq)
    }

    fn terminate(&mut self) {
        self.state = TxState::Terminated;
        self.timer_g = None;
        self.timer_h = None;
        self.timer_i = None;
    }
}

/// Server transaction for everything but INVITE (RFC 3261 §17.2.2).
#[derive(Debug)]
pub struct ServerNonInviteTx {
    req: Request,
    key: TxKey,
    transport: Transport,
    cfg: TimerConfig,
    state: TxState,
    last_provisional: Option<Response>,
    final_resp: Option<Response>,
    staged: Option<Response>,
    timer_j: Option<Instant>,
}

impl ServerNonInviteTx {
    /// Creates the transaction for the request just received.
    pub fn new(req: Request, transport: Transport) -> Self {
        let key = TxKey::from_request(&req).unwrap_or(TxKey {
            method: req.method.clone(),
            branch: String::new(),
            sent_by: String::new(),
            seq: req.headers.cseq().map(|c| c.seq).unwrap_or(0),
        });
        ServerNonInviteTx {
            req,
            key,
            transport,
            cfg: TimerConfig::default(),
            state: TxState::Trying,
            last_provisional: None,
            final_resp: None,
            staged: None,
            timer_j: None,
        }
    }

    /// Overrides the default timer configuration.
    pub fn with_timers(mut self, cfg: TimerConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// Stages the response the TU wants sent.
    pub fn stage(&mut self, resp: Response) {
        self.staged = Some(resp);
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
        self.timer_j
    }

    /// Processes one event, returning the actions to execute in order.
    pub fn on_event(&mut self, ev: TxEvent, now: Instant) -> Vec<TxAction> {
        match ev {
            TxEvent::Send => self.on_send(now),
            TxEvent::Timeout => self.on_timeout(),
            TxEvent::ReceivedRequest(req) => self.on_request(&req),
            TxEvent::Delivered => Vec::new(),
            TxEvent::Received(_) => Vec::new(),
            TxEvent::TransportError => {
                self.state = TxState::Terminated;
                self.timer_j = None;
                vec![TxAction::DeleteTransaction]
            }
        }
    }

    fn on_send(&mut self, now: Instant) -> Vec<TxAction> {
        let Some(resp) = self.staged.take() else {
            return Vec::new();
        };
        if self.state == TxState::Terminated {
            return Vec::new();
        }
        if resp.is_provisional() {
            self.last_provisional = Some(resp.clone());
            return vec![TxAction::SendResponse(resp)];
        }
        self.final_resp = Some(resp.clone());
        self.state = TxState::Completed;
        if self.transport.is_reliable() {
            return vec![
                TxAction::SendResponse(resp),
                TxAction::DeleteTransaction,
            ];
        }
        self.timer_j = Some(add(now, self.cfg.timer_j()));
        vec![TxAction::SendResponse(resp)]
    }

    fn on_timeout(&mut self) -> Vec<TxAction> {
        if self.state == TxState::Completed && self.timer_j.is_some() {
            self.state = TxState::Terminated;
            self.timer_j = None;
            return vec![TxAction::DeleteTransaction];
        }
        Vec::new()
    }

    fn on_request(&mut self, req: &Request) -> Vec<TxAction> {
        if self.state == TxState::Terminated {
            return Vec::new();
        }
        // Original-request retransmission? Same branch, sent-by, CSeq seq.
        let Some(via) = req.headers.first_via() else {
            return Vec::new();
        };
        if via.sent_by.to_string() != self.key.sent_by
            || crate::matching::magic_branch(req).as_deref() != Some(self.key.branch.as_str())
            || !req.headers.cseq().is_some_and(|c| c.seq == self.key.seq)
        {
            return Vec::new();
        }
        match self.state {
            TxState::Trying => self
                .last_provisional
                .clone()
                .map(|r| vec![TxAction::SendResponse(r)])
                .unwrap_or_default(),
            TxState::Completed => self
                .final_resp
                .clone()
                .map(|r| vec![TxAction::SendResponse(r)])
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}
