//! Transaction matching (RFC 3261 §17.1.3, §17.2.3).
//!
//! A response matches a client transaction when the top Via branch (with
//! the magic cookie), the sent-by host:port and the CSeq (method and
//! number) all agree. An ACK for a non-2xx final response matches its
//! INVITE transaction directly; an ACK for a 2xx is a *separate*
//! transaction at the dialog layer and never matches.

use sip_core::headers::{HostPort, Via};
use sip_core::message::{Method, Request, Response};

/// Identity of a transaction as seen from its own Via/CSeq headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxKey {
    /// Method of the request that created the transaction.
    pub method: Method,
    /// Top Via branch (magic-cookie prefixed).
    pub branch: String,
    /// Top Via sent-by as canonical text (`host` or `host:port`).
    pub sent_by: String,
    /// CSeq number of the request.
    pub seq: u32,
}

impl TxKey {
    /// Derives the transaction key from a request; `None` when the request
    /// has no usable top Via branch (RFC 3261 clients always add one).
    pub fn from_request(req: &Request) -> Option<TxKey> {
        let via = req.headers.first_via()?;
        let branch = magic_branch(req)?;
        Some(TxKey {
            method: req.method.clone(),
            branch,
            sent_by: via.sent_by.to_string(),
            seq: req.headers.cseq()?.seq,
        })
    }

    /// Sent-by text of the transaction's own Via hop.
    pub fn sent_by_of(via: &Via) -> String {
        via.sent_by.to_string()
    }
}

/// Top-Via branch with the RFC 3261 magic cookie, header-level view.
pub(crate) fn magic_branch(req: &Request) -> Option<String> {
    req.headers
        .first_via()
        .and_then(|v| v.branch)
        .filter(|b| b.starts_with("z9hG4bK"))
}

/// Whether `resp` belongs to the transaction identified by `key`
/// (RFC 3261 §17.1.3).
pub fn response_matches(key: &TxKey, resp: &Response) -> bool {
    let Some(via) = resp.headers.first_via() else {
        return false;
    };
    if via.sent_by.to_string() != key.sent_by {
        return false;
    }
    let Some(branch) = resp
        .headers
        .first_via()
        .and_then(|v| v.branch)
        .filter(|b| b.starts_with("z9hG4bK"))
    else {
        return false;
    };
    if branch != key.branch {
        return false;
    }
    match resp.headers.cseq() {
        Some(c) => c.method == key.method && c.seq == key.seq,
        None => false,
    }
}

/// Whether `ack` is *the* ACK for the non-2xx final response of the INVITE
/// transaction created by `invite` (RFC 3261 §17.2.3): equal branch,
/// sent-by, Call-ID, From-tag and CSeq number, with method ACK. An ACK for
/// a 2xx response is a separate transaction and must not be fed through
/// the INVITE server state machine.
pub fn ack_matches_invite(ack: &Request, invite: &Request) -> bool {
    if ack.method != Method::Ack {
        return false;
    }
    let Some(a_via) = ack.headers.first_via() else {
        return false;
    };
    let Some(i_via) = invite.headers.first_via() else {
        return false;
    };
    if a_via.sent_by.to_string() != i_via.sent_by.to_string() {
        return false;
    }
    match (magic_branch(ack), magic_branch(invite)) {
        (Some(a), Some(i)) if a == i => {}
        _ => return false,
    }
    if ack.headers.call_id() != invite.headers.call_id() {
        return false;
    }
    let from_tag = |r: &Request| r.headers.from().and_then(|f| f.tag);
    if from_tag(ack) != from_tag(invite) {
        return false;
    }
    match (ack.headers.cseq(), invite.headers.cseq()) {
        (Some(a), Some(i)) => a.seq == i.seq && i.method == Method::Invite,
        _ => false,
    }
}

/// Host:port text of a Via sent-by, exposed for callers that compare
/// top-hop identities directly.
pub fn sent_by_text(hp: &HostPort) -> String {
    hp.to_string()
}
