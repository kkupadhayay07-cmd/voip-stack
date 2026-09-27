//! Fake-clock tests: every timer fire instant is asserted exactly. No
//! real sleeping — the clock is a fixed base `Instant` and events are fed
//! at explicit offsets, so the suite is deterministic and fast.

use crate::{
    ClientInviteTx, ClientNonInviteTx, ServerInviteTx, ServerNonInviteTx, TimerConfig, Transport,
    TxAction, TxEvent, TxState,
};
use sip_core::builder::RequestBuilder;
use sip_core::headers::{CSeq, HeaderMap};
use sip_core::message::{Method, Request, Response};
use sip_core::uri::{SipUri, TransportKind};
use std::time::{Duration, Instant};

/// Hand-rolled fake clock: a fixed base plus explicit offsets. All
/// instants the state machines see come from here.
struct Clock(Instant);

impl Clock {
    fn new() -> Clock {
        Clock(Instant::now())
    }
    fn at(&self, ms: u64) -> Instant {
        self.0.checked_add(Duration::from_millis(ms)).unwrap()
    }
}

const BRANCH: &str = "z9hG4bKfixedbranch";
const OTHER_BRANCH: &str = "z9hG4bKotherbranch";

fn base_req(method: Method) -> Request {
    RequestBuilder::new(method, SipUri::parse("sip:callee@atlanta.com").unwrap())
        .via(TransportKind::Udp, "caller.example:5060", Some(BRANCH))
        .from("<sip:caller@atlanta.com>;tag=ctag1")
        .to("<sip:callee@atlanta.com>")
        .call_id(Some("tx-test-call@caller.example"))
        .cseq(1)
        .build()
}

/// Mirrors `req` into a response, optionally rewriting the top Via branch
/// (wrong-branch tests) and tagging To.
fn resp_for(req: &Request, code: u16, branch: &str, to_tag: Option<&str>) -> Response {
    let mut headers = HeaderMap::new();
    let mut via = req.headers.first_via().expect("via");
    via.branch = Some(branch.to_string());
    headers.add("Via", via.to_string());
    if let Some(f) = req.headers.get("From") {
        headers.add("From", f);
    }
    let mut to = req.headers.get("To").unwrap_or("").to_string();
    if let Some(t) = to_tag {
        if !to.contains(";tag=") {
            to = format!("{to};tag={t}");
        }
    }
    headers.add("To", to);
    if let Some(c) = req.headers.get("Call-ID") {
        headers.add("Call-ID", c);
    }
    if let Some(c) = req.headers.get("CSeq") {
        headers.add("CSeq", c);
    }
    Response {
        code,
        reason: sip_core::message::reason_for_code(code).to_string(),
        headers,
        body: Vec::new(),
    }
}

fn resp_with_cseq(req: &Request, code: u16, seq: u32, method: Method) -> Response {
    let mut r = resp_for(req, code, BRANCH, None);
    r.headers.remove_all("CSeq");
    r.headers.add("CSeq", format!("{seq} {method}"));
    r
}

fn ack_for(invite: &Request) -> Request {
    let mut headers = HeaderMap::new();
    headers.add("Via", invite.headers.first_via().expect("via").to_string());
    if let Some(f) = invite.headers.get("From") {
        headers.add("From", f);
    }
    if let Some(t) = invite.headers.get("To") {
        headers.add("To", t);
    }
    if let Some(c) = invite.headers.get("Call-ID") {
        headers.add("Call-ID", c);
    }
    headers.set_cseq(CSeq {
        seq: invite.headers.cseq().expect("cseq").seq,
        method: Method::Ack,
    });
    Request {
        method: Method::Ack,
        uri: invite.uri.clone(),
        headers,
        body: Vec::new(),
    }
}

fn assert_send_request(actions: &[TxAction], n: usize) {
    assert_eq!(actions.len(), n, "expected {n} SendRequest actions");
    for a in actions {
        assert!(matches!(a, TxAction::SendRequest(_)), "{a:?}");
    }
}

fn assert_pass_to_tu(actions: &[TxAction], code: u16) {
    assert!(actions.iter().any(|a| matches!(
        a,
        TxAction::PassToTu(sip_core::message::SipMessage::Response(r)) if r.code == code
    )));
}

// 1. INVITE client retransmission instants: intervals of exactly
//    T1, 2·T1, 4·T1, 8·T1, 16·T1 (0, 500, 1000, 2000, 4000, 8000 ms).
#[test]
fn invite_client_retransmits_at_exact_doubling_instants() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
    assert_eq!(tx.state(), TxState::Trying);
    assert_send_request(&tx.on_event(TxEvent::Send, c.at(0)), 1);

    // Fires at 500, 1500, 3500, 7500, 15500, 31500 (doubled intervals).
    for fire in [500u64, 1500, 3500, 7500, 15500, 31500] {
        assert_eq!(
            tx.next_deadline(),
            Some(c.at(fire)),
            "deadline before {fire}"
        );
        assert_send_request(&tx.on_event(TxEvent::Timeout, c.at(fire)), 1);
    }
    // Timer B (64·T1 = 32 s) is the next and final deadline.
    assert_eq!(tx.next_deadline(), Some(c.at(32_000)));
    assert_eq!(
        tx.on_event(TxEvent::Timeout, c.at(32_000)),
        vec![TxAction::DeleteTransaction]
    );
    assert_eq!(tx.state(), TxState::Terminated);
    assert_eq!(tx.next_deadline(), None);
}

// 2. 200 OK at 10 s → transaction terminates, Timer D scheduled at +32 s.
#[test]
fn invite_client_200_at_10s_terminates_and_schedules_timer_d() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
    tx.on_event(TxEvent::Send, c.at(0));
    tx.on_event(TxEvent::Timeout, c.at(500)); // one retransmission

    let actions = tx.on_event(
        TxEvent::Received(resp_for(tx.request(), 200, BRANCH, Some("stag"))),
        c.at(10_000),
    );
    assert_pass_to_tu(&actions, 200);
    assert_eq!(tx.state(), TxState::Terminated);
    assert_eq!(
        tx.next_deadline(),
        Some(c.at(42_000)),
        "10s + Timer D (32s)"
    );
    // Retransmission timers are gone: a stray Timeout before Timer D is inert.
    assert!(tx.on_event(TxEvent::Timeout, c.at(11_000)).is_empty());
    assert_eq!(
        tx.on_event(TxEvent::Timeout, c.at(42_000)),
        vec![TxAction::DeleteTransaction]
    );
    assert_eq!(tx.next_deadline(), None);
}

// 3. 100 Trying stops Timer A but Timer B keeps running.
#[test]
fn invite_client_100_stops_timer_a_keeps_timer_b() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
    tx.on_event(TxEvent::Send, c.at(0));
    let actions = tx.on_event(
        TxEvent::Received(resp_for(tx.request(), 100, BRANCH, None)),
        c.at(2_000),
    );
    assert_pass_to_tu(&actions, 100);
    assert_eq!(tx.state(), TxState::Proceeding);
    // Only Timer B remains: exactly 32 s from the initial send.
    assert_eq!(tx.next_deadline(), Some(c.at(32_000)));
    // No retransmissions happen while proceeding.
    assert!(tx.on_event(TxEvent::Timeout, c.at(4_000)).is_empty());
    assert!(tx.on_event(TxEvent::Timeout, c.at(16_000)).is_empty());
    assert_eq!(
        tx.on_event(TxEvent::Timeout, c.at(32_000)),
        vec![TxAction::DeleteTransaction]
    );
}

// 4. Non-INVITE client: Timer E doubles but is capped at T2; Timer F times out.
#[test]
fn non_invite_client_timer_e_capped_at_t2() {
    let c = Clock::new();
    let mut tx = ClientNonInviteTx::new(base_req(Method::Options), Transport::Udp);
    assert_send_request(&tx.on_event(TxEvent::Send, c.at(0)), 1);

    // E fires: 500, 1500, 3500, then caps — every later fire is 4 s apart.
    for fire in [500u64, 1500, 3500] {
        assert_eq!(tx.next_deadline(), Some(c.at(fire)));
        assert_send_request(&tx.on_event(TxEvent::Timeout, c.at(fire)), 1);
    }
    for fire in [7500u64, 11500, 15500, 19500, 23500, 27500, 31500] {
        assert_eq!(
            tx.next_deadline(),
            Some(c.at(fire)),
            "T2-capped E deadline expected at {fire}"
        );
        assert_send_request(&tx.on_event(TxEvent::Timeout, c.at(fire)), 1);
    }
    // Timer F (64·T1) is next and terminates the transaction.
    assert_eq!(tx.next_deadline(), Some(c.at(32_000)));
    assert_eq!(
        tx.on_event(TxEvent::Timeout, c.at(32_000)),
        vec![TxAction::DeleteTransaction]
    );
}

// 5. Server INVITE: 100 sent, INVITE retransmission re-sends it, 486 arms
//    Timer G (retransmit, doubling capped at T2), ACK confirms → Timer I.
#[test]
fn server_invite_100_retransmit_final_timer_g_ack_timer_i() {
    let c = Clock::new();
    let invite = base_req(Method::Invite);
    let mut tx = ServerInviteTx::new(invite.clone(), Transport::Udp);
    assert_eq!(tx.state(), TxState::Trying);

    tx.stage(resp_for(&invite, 100, BRANCH, None));
    let actions = tx.on_event(TxEvent::Send, c.at(0));
    assert!(matches!(&actions[0], TxAction::SendResponse(r) if r.code == 100));
    assert_eq!(tx.state(), TxState::Proceeding);

    // Retransmitted INVITE in Proceeding → last provisional re-sent.
    let actions = tx.on_event(TxEvent::ReceivedRequest(invite.clone()), c.at(1_000));
    assert!(matches!(&actions[0], TxAction::SendResponse(r) if r.code == 100));

    // Final 486 → Completed, Timer G at +T1, Timer H at +64·T1.
    tx.stage(resp_for(&invite, 486, BRANCH, Some("stag")));
    let actions = tx.on_event(TxEvent::Send, c.at(2_000));
    assert!(matches!(&actions[0], TxAction::SendResponse(r) if r.code == 486));
    assert_eq!(tx.state(), TxState::Completed);
    assert_eq!(tx.next_deadline(), Some(c.at(2_500)), "Timer G");

    // Timer G retransmits the 486, doubling: 2500 → 3500 → 5500 (capped at
    // T2 from then on).
    for fire in [2500u64, 3500, 5500] {
        let actions = tx.on_event(TxEvent::Timeout, c.at(fire));
        assert!(matches!(&actions[0], TxAction::SendResponse(r) if r.code == 486));
    }
    assert_eq!(tx.next_deadline(), Some(c.at(9_500)), "G capped at T2");

    // ACK arrives (matches the INVITE directly, §17.2.3) → Confirmed,
    // Timer G/H cancelled, Timer I at +T4.
    let actions = tx.on_event(TxEvent::ReceivedRequest(ack_for(&invite)), c.at(4_000));
    assert!(actions.is_empty(), "ACK is absorbed, {actions:?}");
    assert!(tx.is_confirmed());
    assert_eq!(tx.next_deadline(), Some(c.at(9_000)), "Timer I = 4s + T4");
    assert_eq!(
        tx.on_event(TxEvent::Timeout, c.at(9_000)),
        vec![TxAction::DeleteTransaction]
    );
    assert_eq!(tx.state(), TxState::Terminated);
}

// 6. Server non-INVITE: final re-sent on request retransmission; Timer J fires.
#[test]
fn server_non_invite_timer_j_fires() {
    let c = Clock::new();
    let req = base_req(Method::Options);
    let mut tx = ServerNonInviteTx::new(req.clone(), Transport::Udp);
    tx.stage(resp_for(&req, 200, BRANCH, None));
    let actions = tx.on_event(TxEvent::Send, c.at(0));
    assert!(matches!(&actions[0], TxAction::SendResponse(r) if r.code == 200));
    assert_eq!(tx.state(), TxState::Completed);
    assert_eq!(tx.next_deadline(), Some(c.at(32_000)), "Timer J = 64·T1");

    // Retransmitted request in Completed → final re-sent.
    let actions = tx.on_event(TxEvent::ReceivedRequest(req), c.at(1_000));
    assert!(matches!(&actions[0], TxAction::SendResponse(r) if r.code == 200));

    let actions = tx.on_event(TxEvent::Timeout, c.at(32_000));
    assert_eq!(actions, vec![TxAction::DeleteTransaction]);
    assert_eq!(tx.next_deadline(), None);
}

// 7. A response with the wrong top-Via branch is ignored.
#[test]
fn wrong_branch_response_ignored() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
    tx.on_event(TxEvent::Send, c.at(0));

    let actions = tx.on_event(
        TxEvent::Received(resp_for(tx.request(), 180, OTHER_BRANCH, Some("t"))),
        c.at(300),
    );
    assert!(actions.is_empty());
    assert_eq!(tx.state(), TxState::Trying, "state must not move");
    // Timers untouched: Timer A still due at exactly 500.
    assert_eq!(tx.next_deadline(), Some(c.at(500)));

    // Server side: a retransmitted INVITE with a different branch is ignored.
    let invite = base_req(Method::Invite);
    let mut stx = ServerInviteTx::new(invite.clone(), Transport::Udp);
    stx.stage(resp_for(&invite, 180, BRANCH, None));
    stx.on_event(TxEvent::Send, c.at(0));
    let mut other = invite.clone();
    other.headers.remove_all("Via");
    let mut via = invite.headers.first_via().unwrap();
    via.branch = Some(OTHER_BRANCH.to_string());
    other.headers.add("Via", via.to_string());
    assert!(stx
        .on_event(TxEvent::ReceivedRequest(other), c.at(100))
        .is_empty());
}

// 8. A response with the wrong CSeq (method or number) is ignored.
#[test]
fn wrong_cseq_response_ignored() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
    tx.on_event(TxEvent::Send, c.at(0));

    for (seq, method) in [(1u32, Method::Bye), (2u32, Method::Invite)] {
        let actions = tx.on_event(
            TxEvent::Received(resp_with_cseq(tx.request(), 200, seq, method.clone())),
            c.at(300),
        );
        assert!(actions.is_empty(), "CSeq {seq} {method} must not match");
        assert_eq!(tx.state(), TxState::Trying);
    }
    assert_eq!(tx.next_deadline(), Some(c.at(500)));
}

// 9. ACK for a 2xx is a separate transaction: it never matches the INVITE
//    server state machine.
#[test]
fn ack_for_2xx_does_not_match_invite_tx() {
    let c = Clock::new();
    let invite = base_req(Method::Invite);
    let mut tx = ServerInviteTx::new(invite.clone(), Transport::Udp);

    // 2xx terminates the INVITE transaction immediately (§17.2.1).
    tx.stage(resp_for(&invite, 200, BRANCH, Some("stag")));
    let actions = tx.on_event(TxEvent::Send, c.at(0));
    assert!(matches!(&actions[0], TxAction::SendResponse(r) if r.code == 200));
    assert!(actions.contains(&TxAction::DeleteTransaction));
    assert_eq!(tx.state(), TxState::Terminated);

    // The dialog-level ACK arrives; the transaction must not react to it.
    let ack = ack_for(&invite);
    assert!(
        crate::matching::ack_matches_invite(&ack, &invite),
        "branch-level match is true — termination is what stops the machine"
    );
    assert!(tx
        .on_event(TxEvent::ReceivedRequest(ack), c.at(100))
        .is_empty());
    assert_eq!(tx.state(), TxState::Terminated);
    assert_eq!(tx.next_deadline(), None);
}

// 10. Fake clock drives every timer across one full INVITE client timeline;
//     all fire instants asserted exactly.
#[test]
fn fake_clock_full_invite_client_timeline_exact_instants() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);

    assert_send_request(&tx.on_event(TxEvent::Send, c.at(0)), 1);
    assert_eq!(tx.next_deadline(), Some(c.at(500)));

    // Retransmissions at 500 and 1500 (Timer A doubles).
    assert_send_request(&tx.on_event(TxEvent::Timeout, c.at(500)), 1);
    assert_eq!(tx.next_deadline(), Some(c.at(1_500)));
    assert_send_request(&tx.on_event(TxEvent::Timeout, c.at(1_500)), 1);
    assert_eq!(tx.next_deadline(), Some(c.at(3_500)));

    // 180 Ringing at 2.0 s: Timer A stops, Timer B (32 s) continues.
    let actions = tx.on_event(
        TxEvent::Received(resp_for(tx.request(), 180, BRANCH, None)),
        c.at(2_000),
    );
    assert_pass_to_tu(&actions, 180);
    assert_eq!(tx.next_deadline(), Some(c.at(32_000)));

    // 486 Busy at 5.0 s: pass up + ACK generated by the transaction,
    // Timer D at exactly 5 s + 32 s.
    let actions = tx.on_event(
        TxEvent::Received(resp_for(tx.request(), 486, BRANCH, Some("stag"))),
        c.at(5_000),
    );
    assert_pass_to_tu(&actions, 486);
    assert!(matches!(
        &actions[1],
        TxAction::SendRequest(r) if r.method == Method::Ack
    ));
    assert_eq!(tx.state(), TxState::Completed);
    assert_eq!(tx.next_deadline(), Some(c.at(37_000)));

    // Retransmitted 486 in Completed → re-ACK, no second PassToTu.
    let actions = tx.on_event(
        TxEvent::Received(resp_for(tx.request(), 486, BRANCH, Some("stag"))),
        c.at(6_000),
    );
    assert_eq!(actions.len(), 1);
    assert!(matches!(&actions[0], TxAction::SendRequest(r) if r.method == Method::Ack));

    // The generated ACK carries the INVITE's branch so the server matches it.
    if let TxAction::SendRequest(ack) = &actions[0] {
        assert_eq!(
            ack.headers.first_via().and_then(|v| v.branch).as_deref(),
            Some(BRANCH)
        );
        assert_eq!(ack.headers.cseq().map(|cs| cs.seq), Some(1));
    }
    // Timer D fires exactly at 37 s → release.
    assert!(tx.on_event(TxEvent::Timeout, c.at(36_999)).is_empty());
    assert_eq!(
        tx.on_event(TxEvent::Timeout, c.at(37_000)),
        vec![TxAction::DeleteTransaction]
    );
}

// 11. Reliable transports suppress retransmission timers and collapse the
//     dwell timers to zero.
#[test]
fn reliable_transport_has_no_retransmit_timers() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Tls);
    assert_send_request(&tx.on_event(TxEvent::Send, c.at(0)), 1);
    assert_eq!(
        tx.next_deadline(),
        Some(c.at(32_000)),
        "no Timer A on TCP, but Timer B must still guard the request"
    );

    let actions = tx.on_event(
        TxEvent::Received(resp_for(tx.request(), 486, BRANCH, Some("t"))),
        c.at(100),
    );
    assert_pass_to_tu(&actions, 486);
    assert!(
        matches!(&actions[1], TxAction::SendRequest(r) if r.method == Method::Ack),
        "client transaction generates the ACK itself"
    );
    assert!(
        actions.contains(&TxAction::DeleteTransaction),
        "Timer D = 0"
    );
    assert_eq!(tx.next_deadline(), None);

    // Server INVITE over TCP: no Timer G; the ACK ends the transaction at once.
    let invite = base_req(Method::Invite);
    let mut stx = ServerInviteTx::new(invite.clone(), Transport::Tls);
    stx.stage(resp_for(&invite, 486, BRANCH, Some("t")));
    stx.on_event(TxEvent::Send, c.at(0));
    assert!(
        stx.next_deadline().is_some(),
        "Timer H still guards Completed"
    );
    stx.on_event(TxEvent::ReceivedRequest(ack_for(&invite)), c.at(200));
    assert!(stx.is_confirmed());
    assert_eq!(stx.state(), TxState::Terminated, "Timer I = 0 on TCP");
}

// 12. Timer B expiry terminates an unanswered client INVITE transaction.
#[test]
fn timer_b_expiry_deletes_transaction() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
    tx.on_event(TxEvent::Send, c.at(0));
    // Timer A fires at the doubling instants until Timer B cuts it off.
    for fire in [500u64, 1500, 3500, 7500, 15500, 31500] {
        assert_send_request(&tx.on_event(TxEvent::Timeout, c.at(fire)), 1);
    }
    // Between the last Timer A fire (31.5 s) and Timer B (32 s): nothing due.
    assert!(tx.on_event(TxEvent::Timeout, c.at(31_999)).is_empty());
    let actions = tx.on_event(TxEvent::Timeout, c.at(32_000));
    assert_eq!(actions, vec![TxAction::DeleteTransaction]);
    assert_eq!(tx.state(), TxState::Terminated);
}

// 13. Transport errors terminate immediately from any state.
#[test]
fn transport_error_terminates() {
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
    tx.on_event(TxEvent::Send, c.at(0));
    tx.on_event(
        TxEvent::Received(resp_for(tx.request(), 100, BRANCH, None)),
        c.at(100),
    );
    assert_eq!(tx.state(), TxState::Proceeding);
    assert_eq!(
        tx.on_event(TxEvent::TransportError, c.at(200)),
        vec![TxAction::DeleteTransaction]
    );
    assert_eq!(tx.next_deadline(), None);
}

// 14. TimerConfig derivations match RFC 3261 §17.1.1.2 / §17.1.2.2.
#[test]
fn timer_config_derivations() {
    let cfg = TimerConfig::default();
    assert_eq!(cfg.timer_bfh(), Duration::from_millis(32_000));
    assert_eq!(cfg.timer_d(), Duration::from_secs(32));
    assert_eq!(cfg.timer_j(), Duration::from_millis(32_000));
    // Timer D never drops below 32 s even with a tiny T1.
    let fast = TimerConfig {
        t1: Duration::from_millis(100),
        ..TimerConfig::default()
    };
    assert_eq!(fast.timer_bfh(), Duration::from_millis(6_400));
    assert_eq!(fast.timer_d(), Duration::from_secs(32));

    // Delivered stops retransmissions but keeps the timeout guard armed.
    let c = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
    tx.on_event(TxEvent::Send, c.at(0));
    assert!(tx.on_event(TxEvent::Delivered, c.at(100)).is_empty());
    assert_eq!(tx.next_deadline(), Some(c.at(32_000)));
}

// 15. Audit 2.4 regression: Timer B is armed and fires on reliable
//     transports too (§17.1.1.1/§17.1.1.2 apply B to every transport; only
//     retransmissions are unreliable-transport-only). A live TCP/TLS/WS/WSS
//     connection that never yields a response must time out at exactly
//     64·T1 with the same terminal outcome as the UDP path.
#[test]
fn timer_b_fires_on_reliable_transport() {
    let c = Clock::new();
    for transport in [
        Transport::Tcp,
        Transport::Tls,
        Transport::Ws,
        Transport::Wss,
    ] {
        // UDP control: same send instant; the reliable outcome at Timer B
        // must be identical to what the UDP path produces (test 12).
        let mut udp_ctrl = ClientInviteTx::new(base_req(Method::Invite), Transport::Udp);
        assert_send_request(&udp_ctrl.on_event(TxEvent::Send, c.at(0)), 1);

        let mut tx = ClientInviteTx::new(base_req(Method::Invite), transport);
        assert_send_request(&tx.on_event(TxEvent::Send, c.at(0)), 1);

        // No retransmissions and no premature timeout before Timer B:
        // Timer A must not exist on reliable transports.
        for probe in [500u64, 1_000, 4_000, 16_000, 31_999] {
            assert!(
                tx.on_event(TxEvent::Timeout, c.at(probe)).is_empty(),
                "{transport:?}: nothing may be due at {probe} ms"
            );
        }
        assert_eq!(
            tx.next_deadline(),
            Some(c.at(32_000)),
            "{transport:?}: Timer B due at exactly 64·T1"
        );

        let actions = tx.on_event(TxEvent::Timeout, c.at(32_000));
        assert_eq!(
            actions,
            udp_ctrl.on_event(TxEvent::Timeout, c.at(32_000)),
            "{transport:?}: same timeout outcome as the UDP path"
        );
        assert_eq!(actions, vec![TxAction::DeleteTransaction]);
        assert_eq!(tx.state(), TxState::Terminated);
        assert_eq!(udp_ctrl.state(), TxState::Terminated);
        assert_eq!(tx.next_deadline(), None);
    }

    // Transport-level delivery confirmation must not disarm Timer B either.
    let c2 = Clock::new();
    let mut tx = ClientInviteTx::new(base_req(Method::Invite), Transport::Wss);
    tx.on_event(TxEvent::Send, c2.at(0));
    assert!(tx.on_event(TxEvent::Delivered, c2.at(50)).is_empty());
    assert_eq!(tx.next_deadline(), Some(c2.at(32_000)));
    assert_eq!(
        tx.on_event(TxEvent::Timeout, c2.at(32_000)),
        vec![TxAction::DeleteTransaction]
    );
    assert_eq!(tx.state(), TxState::Terminated);
}

// 16. Audit 2.4 regression: Timer F is armed and fires on reliable
//     transports too (§17.1.2 applies F to every transport); only Timer E
//     is unreliable-transport-only. Same terminal outcome as the UDP path
//     at exactly 64·T1.
#[test]
fn timer_f_fires_on_reliable_transport() {
    let c = Clock::new();
    for transport in [
        Transport::Tcp,
        Transport::Tls,
        Transport::Ws,
        Transport::Wss,
    ] {
        let mut udp_ctrl = ClientNonInviteTx::new(base_req(Method::Options), Transport::Udp);
        assert_send_request(&udp_ctrl.on_event(TxEvent::Send, c.at(0)), 1);

        let mut tx = ClientNonInviteTx::new(base_req(Method::Options), transport);
        assert_send_request(&tx.on_event(TxEvent::Send, c.at(0)), 1);

        // No retransmissions and no premature timeout before Timer F.
        for probe in [500u64, 1_000, 4_000, 16_000, 31_999] {
            assert!(
                tx.on_event(TxEvent::Timeout, c.at(probe)).is_empty(),
                "{transport:?}: nothing may be due at {probe} ms"
            );
        }
        assert_eq!(
            tx.next_deadline(),
            Some(c.at(32_000)),
            "{transport:?}: Timer F due at exactly 64·T1"
        );

        let actions = tx.on_event(TxEvent::Timeout, c.at(32_000));
        assert_eq!(
            actions,
            udp_ctrl.on_event(TxEvent::Timeout, c.at(32_000)),
            "{transport:?}: same timeout outcome as the UDP path"
        );
        assert_eq!(actions, vec![TxAction::DeleteTransaction]);
        assert_eq!(tx.state(), TxState::Terminated);
        assert_eq!(udp_ctrl.state(), TxState::Terminated);
        assert_eq!(tx.next_deadline(), None);
    }

    // Delivered stops Timer E (none armed on reliable anyway) but keeps
    // Timer F: a confirmed TCP send still times out at 64·T1.
    let c2 = Clock::new();
    let mut tx = ClientNonInviteTx::new(base_req(Method::Options), Transport::Tcp);
    tx.on_event(TxEvent::Send, c2.at(0));
    assert!(tx.on_event(TxEvent::Delivered, c2.at(50)).is_empty());
    assert_eq!(tx.next_deadline(), Some(c2.at(32_000)));
    assert_eq!(
        tx.on_event(TxEvent::Timeout, c2.at(32_000)),
        vec![TxAction::DeleteTransaction]
    );
    assert_eq!(tx.state(), TxState::Terminated);
}
