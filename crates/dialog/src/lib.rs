//! RFC 3261 §12 dialog state, extracted from the B2BUA's per-leg fields
//! into a reusable package.
//!
//! A [`Dialog`] models one side of a dialog: its identity (Call-ID + local
//! and remote tags), its lifecycle ([`DialogState::Early`] →
//! [`DialogState::Confirmed`]), the CSeq sequences in BOTH directions
//! (§12.2.1.1 for what we send, §12.2.2 for what we receive), the current
//! remote target (the peer's Contact, refreshed per §12.2.1.2 on responses
//! and §12.2.2 on in-dialog requests) and the transport address the dialog
//! rides on.
//!
//! The package is transport- and transaction-agnostic: the owner (the B2BUA
//! engine today) builds and sends messages; the dialog owns only the state
//! that MUST be tracked per RFC 3261 §12 and the request-routing decision
//! (§12.2 request-URI = remote target, falling back to the dialog address).

use sip_core::uri::SipUri;
use std::net::SocketAddr;

/// RFC 3261 §12.1 dialog lifecycle.
///
/// `Terminated` is set when the dialog ends (BYE or teardown); owners
/// normally drop the dialog shortly after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    /// Established by a provisional or a 2xx response but not yet
    /// confirmed (the dialog is usable for in-dialog requests only after
    /// confirmation on the UAS side; the UAC may use it from the 2xx).
    Early,
    /// Confirmed by the 2xx/ACK exchange.
    Confirmed,
    /// Ended (BYE sent or received).
    Terminated,
}

/// Result of feeding a response's To tag into the dialog (UAC side,
/// RFC 3261 §12.2.1.1).
///
/// A fork that answers with a DIFFERENT To tag creates a different dialog;
/// this package models a single dialog per owner, so a mismatched tag is
/// reported for the owner to IGNORE (the response belongs to another fork).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogMatch {
    /// First tag seen: adopted into the dialog.
    New,
    /// Same tag as the one already adopted (retransmission of the
    /// establishing response, or an in-dialog response): proceed idempotently.
    Same,
    /// A different tag: not this dialog (a fork). The owner must ignore the
    /// message rather than clobber the adopted tag.
    Mismatch,
}

/// Result of comparing an in-dialog request's CSeq with the last one
/// received from the peer (UAS side, RFC 3261 §12.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqCheck {
    /// Higher than anything seen: the highest water mark is adopted.
    New,
    /// Equal to the last one seen: a retransmission. State is untouched;
    /// the owner answers idempotently.
    Retransmission,
    /// LOWER than the last one seen: out of order. RFC 3261 §12.2.2 — the
    /// UAS MUST respond with 500 Server Internal Error.
    OutOfOrder,
}

/// One side of an RFC 3261 §12 dialog.
#[derive(Debug, Clone)]
pub struct Dialog {
    call_id: String,
    local_tag: String,
    remote_tag: Option<String>,
    state: DialogState,
    /// Next CSeq WE send on this dialog (our UAC-side space, §12.2.1.1).
    /// Always above every CSeq this dialog has already carried.
    local_cseq: u32,
    /// Highest CSeq received from the peer (UAS-side ordering, §12.2.2).
    remote_cseq: u32,
    /// Current remote target: the peer's Contact header value, kept
    /// verbatim (raw-value rule — parsed on use in [`Dialog::request_uri`]).
    /// `None` until the first Contact arrives (the initial target lives
    /// here for a UAC dialog from dial time).
    remote_target: Option<String>,
    /// Where the dialog's messages are exchanged (the latched source of the
    /// first exchange; the fallback request-URI host when no usable
    /// Contact is present).
    remote_addr: SocketAddr,
}

impl Dialog {
    /// Creates the UAC side of a dialog: we are about to send (or just
    /// sent) a new INVITE with `initial_local_cseq` as its CSeq. The dialog
    /// starts [`DialogState::Early`] with no remote tag; `target` is the
    /// initial remote target (the dial request-URI text) until the peer's
    /// Contact replaces it.
    pub fn uac(
        call_id: impl Into<String>,
        local_tag: impl Into<String>,
        target: impl Into<String>,
        remote_addr: SocketAddr,
        initial_local_cseq: u32,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            local_tag: local_tag.into(),
            remote_tag: None,
            state: DialogState::Early,
            local_cseq: initial_local_cseq,
            remote_cseq: 0,
            remote_target: Some(target.into()),
            remote_addr,
        }
    }

    /// Creates the UAS side of a dialog after receiving an INVITE: the
    /// remote tag is the request's From tag, the remote target is the
    /// request's Contact (when present), the remote CSeq is the request's
    /// CSeq (0 when absent) and OUR CSeq space starts above it (§12.2.2 —
    /// "the UAS's next CSeq MUST be higher than any received").
    pub fn uas(
        call_id: impl Into<String>,
        local_tag: impl Into<String>,
        remote_tag: Option<String>,
        target: Option<String>,
        remote_addr: SocketAddr,
        request_cseq: u32,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            local_tag: local_tag.into(),
            remote_tag,
            state: DialogState::Early,
            local_cseq: request_cseq.saturating_add(1),
            remote_cseq: request_cseq,
            remote_target: target,
            remote_addr,
        }
    }

    // -- identity ---------------------------------------------------------

    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn local_tag(&self) -> &str {
        &self.local_tag
    }

    pub fn remote_tag(&self) -> Option<&str> {
        self.remote_tag.as_deref()
    }

    /// The remote tag for To-header construction: `""` while absent (the
    /// established pattern renders `<sip:peer>;tag=` with an empty tag on
    /// early dialogs).
    pub fn remote_tag_value(&self) -> &str {
        self.remote_tag.as_deref().unwrap_or_default()
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn remote_target(&self) -> Option<&str> {
        self.remote_target.as_deref()
    }

    pub fn state(&self) -> DialogState {
        self.state
    }

    pub fn is_confirmed(&self) -> bool {
        self.state == DialogState::Confirmed
    }

    // -- lifecycle ---------------------------------------------------------

    /// Feeds the To tag of a response received on this dialog (UAC side,
    /// §12.2.1.1). The FIRST tag is adopted; a retransmission of the
    /// establishing response matches; a different tag is a fork this
    /// package does not model — [`DialogMatch::Mismatch`], owner ignores.
    pub fn on_response(&mut self, to_tag: Option<&str>) -> DialogMatch {
        match (&self.remote_tag, to_tag) {
            (None, Some(t)) => {
                self.remote_tag = Some(t.to_string());
                DialogMatch::New
            }
            (Some(have), Some(t)) if have == t => DialogMatch::Same,
            _ => DialogMatch::Mismatch,
        }
    }

    /// Confirms the dialog (2xx on the UAC side; ACK on the UAS side).
    pub fn confirm(&mut self) {
        self.state = DialogState::Confirmed;
    }

    /// Marks the dialog terminated (BYE sent or received).
    pub fn terminate(&mut self) {
        self.state = DialogState::Terminated;
    }

    // -- CSeq sequencing ----------------------------------------------------

    /// Consumes the next CSeq for a request we originate on this dialog
    /// (post-increment, §12.2.1.1).
    pub fn take_cseq(&mut self) -> u32 {
        let c = self.local_cseq;
        self.local_cseq = c.saturating_add(1);
        c
    }

    /// The next CSeq we would consume (read-only; for gap accounting).
    pub fn next_cseq(&self) -> u32 {
        self.local_cseq
    }

    /// Compares an in-dialog request's CSeq against the peer's high-water
    /// mark (§12.2.2). `New` adopts the sequence number; `Retransmission`
    /// and `OutOfOrder` leave the state untouched.
    pub fn check_remote_seq(&mut self, seq: u32) -> SeqCheck {
        if seq > self.remote_cseq {
            self.remote_cseq = seq;
            SeqCheck::New
        } else if seq == self.remote_cseq {
            SeqCheck::Retransmission
        } else {
            SeqCheck::OutOfOrder
        }
    }

    /// The highest CSeq seen from the peer.
    pub fn remote_cseq(&self) -> u32 {
        self.remote_cseq
    }

    // -- remote target -------------------------------------------------------

    /// Updates the remote target from a Contact header value (§12.2.1.2 on
    /// responses, §12.2.2 on in-dialog requests). The value is kept
    /// verbatim; parsing happens on use.
    pub fn refresh_target(&mut self, contact: impl Into<String>) {
        self.remote_target = Some(contact.into());
    }

    /// The request-URI for an in-dialog request on this dialog (§12.2): the
    /// remote target parsed as a URI, falling back to `sip:peer@` + the
    /// dialog address when no usable target is present.
    ///
    /// Accepts the Contact header value in the shapes peers actually send:
    /// `<sip:bob@h:5060>`, bare `sip:bob@h:5060` and `"Bob" <sip:bob@h>`.
    pub fn request_uri(&self) -> SipUri {
        self.remote_target
            .as_deref()
            .and_then(contact_uri)
            .unwrap_or_else(|| {
                SipUri::parse(&format!("sip:peer@{}", self.remote_addr))
                    .expect("sip:peer@<socket-addr> is a parseable URI")
            })
    }
}

/// Extracts a SIP URI from a Contact header value: the angle-quoted form,
/// the bare URI, or the display-name form (the last `<...>` wins).
fn contact_uri(contact: &str) -> Option<SipUri> {
    let inner = contact.trim().trim_start_matches('<').trim_end_matches('>');
    match SipUri::parse(inner) {
        Ok(u) => Some(u),
        Err(_) => contact
            .split('<')
            .nth(1)
            .and_then(|rest| rest.split('>').next())
            .and_then(|u| SipUri::parse(u).ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    // -- UAC lifecycle -------------------------------------------------------

    #[test]
    fn uac_dialog_adopts_tag_and_confirms() {
        let mut d = Dialog::uac("call-1", "tagA", "<sip:bob@h>", addr(5060), 2);
        assert_eq!(d.state(), DialogState::Early);
        assert_eq!(d.remote_tag(), None);
        assert_eq!(d.remote_tag_value(), "");
        assert_eq!(d.on_response(Some("tagB")), DialogMatch::New);
        assert_eq!(d.remote_tag(), Some("tagB"));
        assert!(!d.is_confirmed());
        d.confirm();
        assert_eq!(d.state(), DialogState::Confirmed);
        assert!(d.is_confirmed());
    }

    #[test]
    fn uac_response_without_tag_is_a_mismatch() {
        let mut d = Dialog::uac("call-1", "tagA", "<sip:bob@h>", addr(5060), 2);
        // RFC 3261 §13.2.2.1: every 1xx+ from the UAS carries a To tag; a
        // response without one cannot establish a dialog.
        assert_eq!(d.on_response(None), DialogMatch::Mismatch);
        assert_eq!(d.remote_tag(), None);
    }

    #[test]
    fn uac_retransmitted_response_matches_and_fork_is_ignored() {
        let mut d = Dialog::uac("call-1", "tagA", "<sip:bob@h>", addr(5060), 2);
        assert_eq!(d.on_response(Some("tagB")), DialogMatch::New);
        // Retransmitted 200 (UDP): same tag → Same, state untouched.
        assert_eq!(d.on_response(Some("tagB")), DialogMatch::Same);
        assert_eq!(d.remote_tag(), Some("tagB"));
        // A fork answering with a different tag: ignore, do NOT clobber.
        assert_eq!(d.on_response(Some("tagC")), DialogMatch::Mismatch);
        assert_eq!(d.remote_tag(), Some("tagB"));
    }

    #[test]
    fn uac_cseq_sequence_starts_at_the_dial_cseq_plus_one() {
        // The dial INVITE consumed CSeq 1; the next request is CSeq 2.
        let mut d = Dialog::uac("call-1", "tagA", "<sip:bob@h>", addr(5060), 2);
        assert_eq!(d.take_cseq(), 2);
        assert_eq!(d.take_cseq(), 3);
        assert_eq!(d.take_cseq(), 4);
        assert_eq!(d.next_cseq(), 5);
        assert_eq!(d.remote_cseq(), 0);
    }

    // -- UAS lifecycle -------------------------------------------------------

    #[test]
    fn uas_dialog_seeds_both_cseq_spaces_from_the_request() {
        // INVITE with CSeq 7: remote high-water = 7, our next = 8 (§12.2.2).
        let mut d = Dialog::uas(
            "call-1",
            "tagS",
            Some("tagC".to_string()),
            Some("<sip:caller@h>".to_string()),
            addr(5060),
            7,
        );
        assert_eq!(d.remote_cseq(), 7);
        assert_eq!(d.next_cseq(), 8);
        assert_eq!(d.remote_tag(), Some("tagC"));
        d.confirm();
        assert!(d.is_confirmed());
    }

    #[test]
    fn uas_dialog_without_request_cseq_starts_at_one() {
        let d = Dialog::uas(
            "call-1",
            "tagS",
            Some("tagC".to_string()),
            None,
            addr(5060),
            0,
        );
        assert_eq!(d.remote_cseq(), 0);
        assert_eq!(d.next_cseq(), 1);
    }

    #[test]
    fn remote_seq_check_new_retransmission_out_of_order() {
        let mut d = Dialog::uas(
            "call-1",
            "tagS",
            Some("tagC".to_string()),
            None,
            addr(5060),
            1,
        );
        // Higher: adopted.
        assert_eq!(d.check_remote_seq(5), SeqCheck::New);
        assert_eq!(d.remote_cseq(), 5);
        // Equal: retransmission, high-water untouched.
        assert_eq!(d.check_remote_seq(5), SeqCheck::Retransmission);
        assert_eq!(d.remote_cseq(), 5);
        // Lower: out of order → 500 (§12.2.2), high-water untouched.
        assert_eq!(d.check_remote_seq(4), SeqCheck::OutOfOrder);
        assert_eq!(d.remote_cseq(), 5);
        // A gap (higher) is still New — retransmission detection keys on
        // equality with the LAST seen value, not on contiguity.
        assert_eq!(d.check_remote_seq(9), SeqCheck::New);
        assert_eq!(d.remote_cseq(), 9);
        // CSeq 0 cannot ever exceed the initial INVITE's mark.
        let mut d0 = Dialog::uas("call-1", "tagS", None, None, addr(5060), 0);
        assert_eq!(d0.check_remote_seq(0), SeqCheck::Retransmission);
        assert_eq!(d0.check_remote_seq(1), SeqCheck::New);
    }

    #[test]
    fn uas_confirm_without_remote_tag_is_valid() {
        // The UAS confirms at ACK time; the remote tag came with the INVITE
        // (From), but the state machine must not depend on it being set.
        let mut d = Dialog::uas("call-1", "tagS", None, None, addr(5060), 1);
        assert_eq!(d.on_response(None), DialogMatch::Mismatch);
        d.confirm();
        assert!(d.is_confirmed());
    }

    // -- remote target -------------------------------------------------------

    #[test]
    fn target_refresh_replaces_and_request_uri_tracks_it() {
        let mut d = Dialog::uac("call-1", "tagA", "<sip:bob@old:5060>", addr(5060), 2);
        let uri = d.request_uri();
        assert_eq!(uri.user.as_deref(), Some("bob"));
        assert_eq!(uri.port, Some(5060));
        // §12.2.2 target refresh: the new Contact becomes the request-URI.
        d.refresh_target("<sip:bob@new:7070>");
        let uri = d.request_uri();
        assert_eq!(uri.user.as_deref(), Some("bob"));
        assert_eq!(uri.port, Some(7070));
    }

    #[test]
    fn request_uri_accepts_the_contact_shapes_peers_send() {
        let base = addr(5060);
        // Angle-quoted.
        let mut d = Dialog::uac("c", "t", "<sip:bob@1.2.3.4:5060>", base, 2);
        assert_eq!(d.request_uri().user.as_deref(), Some("bob"));
        // Bare URI.
        d.refresh_target("sip:alice@5.6.7.8");
        assert_eq!(d.request_uri().user.as_deref(), Some("alice"));
        // Display-name form.
        d.refresh_target("\"Alice A.\" <sip:alice@5.6.7.8:9999>");
        let u = d.request_uri();
        assert_eq!(u.user.as_deref(), Some("alice"));
        assert_eq!(u.port, Some(9999));
    }

    #[test]
    fn request_uri_falls_back_to_the_dialog_address() {
        // No target at all (a UAS dialog whose INVITE carried no Contact).
        let d = Dialog::uas("c", "t", None, None, addr(5060), 1);
        let u = d.request_uri();
        assert_eq!(u.user.as_deref(), Some("peer"));
        // An unparseable target falls back the same way.
        let mut d = Dialog::uac("c", "t", "<garbage-not-a-uri>", addr(5060), 2);
        d.refresh_target("nonsense");
        let u = d.request_uri();
        assert_eq!(u.user.as_deref(), Some("peer"));
    }

    #[test]
    fn terminate_marks_the_state() {
        let mut d = Dialog::uac("c", "t", "<sip:bob@h>", addr(5060), 2);
        d.confirm();
        d.terminate();
        assert_eq!(d.state(), DialogState::Terminated);
        assert!(!d.is_confirmed());
    }
}
