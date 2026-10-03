//! Proxy behavior tests: routing, Via handling, Max-Forwards, Record-Route,
//! forking, CANCEL, response forwarding — and the sip-tx (RFC 3261 §17)
//! transaction behaviors: per-leg branches, retransmission absorption,
//! Timer A retransmit + Timer B cleanup, non-2xx ACK to the leg, server-tx
//! response retransmission, and leak-free teardown via `poll`.

use proxy::{Action, Proxy, ProxyConfig};
use sip_core::builder::{respond_to, RequestBuilder};
use sip_core::message::Method;
use sip_core::parse::parse_message;
use sip_core::serialize;
use sip_core::uri::{SipUri, TransportKind};
use sip_core::SipMessage;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const SRC: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9)),
    5060,
);

const T1: Duration = Duration::from_millis(500);
const T64: Duration = Duration::from_millis(32_000);

fn invite_req(uri: &str, user: &str) -> sip_core::Request {
    RequestBuilder::new(Method::Invite, SipUri::parse(uri).unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKp1"))
        .from(&format!("<sip:{user}@example.com>;tag=c1"))
        .to(&format!("<sip:{user}@example.com>"))
        .call_id(Some("pcall-1"))
        .cseq(1)
        .build()
}

fn two_targets(proxy: &mut Proxy) {
    proxy.routes.exact.insert(
        "bob".into(),
        vec!["192.168.1.10:5060".into(), "192.168.1.11:5060".into()],
    );
}

fn forked_requests(actions: &[Action]) -> Vec<sip_core::Request> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(SipMessage::Request(r), _) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

fn fork_targets(actions: &[Action]) -> Vec<SocketAddr> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(SipMessage::Request(_), d) => Some(*d),
            _ => None,
        })
        .collect()
}

#[test]
fn invite_forks_to_targets_and_adds_via() {
    let mut proxy = Proxy::new(ProxyConfig {
        record_route: Some("proxy.voip-stack".into()),
        ..Default::default()
    });
    two_targets(&mut proxy);

    let req = invite_req("sip:bob@example.com", "bob");
    let actions = proxy.process_request(&req, SRC, false, Instant::now());

    let sends = fork_targets(&actions);
    assert_eq!(sends.len(), 2, "forked to two targets");
    let want: SocketAddr = "192.168.1.10:5060".parse().unwrap();
    assert!(sends.contains(&want));

    // 100 Trying upstream.
    let trying = actions
        .iter()
        .any(|a| matches!(a, Action::Send(SipMessage::Response(r), _) if r.code == 100));
    assert!(trying);

    // The forwarded request carries our Via on top + Record-Route + reduced
    // Max-Forwards.
    let fwd = forked_requests(&actions).remove(0);
    let vias = fwd.headers.get_all("Via");
    assert_eq!(vias.len(), 2);
    assert!(vias[0].contains("proxy.voip-stack"), "our via is on top");
    assert_eq!(fwd.headers.max_forwards(), Some(69));
    assert!(fwd.headers.get("Record-Route").is_some());

    // §16.6 step 10: each fork leg carries a DISTINCT Via branch.
    let branches: Vec<String> = proxy.leg_branches("pcall-1");
    assert_eq!(branches.len(), 2);
    assert_ne!(branches[0], branches[1], "per-leg branches are unique");
}

#[test]
fn max_forwards_zero_rejected_with_483_and_absorbed() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    let mut req = invite_req("sip:bob@example.com", "bob");
    req.headers.remove_all("Max-Forwards");
    req.headers.add("Max-Forwards", "0");
    let t0 = Instant::now();
    let actions = proxy.process_request(&req, SRC, false, t0);
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        Action::Send(m, dest) => {
            assert_eq!(*dest, SRC);
            match m {
                SipMessage::Response(r) => assert_eq!(r.code, 483),
                _ => panic!("expected response"),
            }
        }
    }

    // The retransmitted INVITE is answered with the staged 483 again
    // (§17.2.1), not re-processed.
    let actions = proxy.process_request(&req, SRC, false, t0);
    assert_eq!(
        actions.len(),
        1,
        "retransmission answered from the server tx"
    );
    assert!(matches!(
        &actions[0],
        Action::Send(SipMessage::Response(r), _) if r.code == 483
    ));

    // The upstream ACK confirms the tx; Timer I cleans it up (no leak).
    let mut ack = RequestBuilder::new(Method::Ack, SipUri::parse("sip:bob@example.com").unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKp1"))
        .from("<sip:bob@example.com>;tag=c1")
        .to("<sip:bob@example.com>")
        .call_id(Some("pcall-1"))
        .cseq(1)
        .build();
    ack.headers.remove_all("Max-Forwards");
    ack.headers.add("Max-Forwards", "70");
    let actions = proxy.process_request(&ack, SRC, false, t0);
    assert!(actions.is_empty(), "ACK absorbed, no fork");
    assert_eq!(proxy.server_tx_count(), 1, "Timer I still pending");
    proxy.poll(t0 + Duration::from_secs(5));
    assert_eq!(proxy.server_tx_count(), 0, "Timer I released the tx");
}

#[test]
fn unknown_target_404() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    let req = invite_req("sip:nobody@example.com", "nobody");
    let actions = proxy.process_request(&req, SRC, false, Instant::now());
    match &actions[0] {
        Action::Send(SipMessage::Response(r), _) => assert_eq!(r.code, 404),
        _ => panic!("expected a response send"),
    }
}

#[test]
fn registrar_bindings_take_precedence() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    proxy
        .routes
        .exact
        .insert("bob".into(), vec!["1.1.1.1:5060".into()]);
    proxy
        .bindings
        .insert("bob".into(), vec!["10.9.9.9:5060".into()]);

    let req = invite_req("sip:bob@example.com", "bob");
    let actions = proxy.process_request(&req, SRC, false, Instant::now());
    assert_eq!(
        fork_targets(&actions),
        vec!["10.9.9.9:5060".parse().unwrap()]
    );
}

#[test]
fn cancel_cancels_fork_and_is_200ed_locally() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    two_targets(&mut proxy);
    let req = invite_req("sip:bob@example.com", "bob");
    let t0 = Instant::now();
    let forked = forked_requests(&proxy.process_request(&req, SRC, false, t0));
    assert_eq!(proxy.leg_count(), 2);

    // The CANCEL mirrors the INVITE's incoming Via stack (upstream branch).
    let cancel = RequestBuilder::new(
        Method::Cancel,
        SipUri::parse("sip:bob@example.com").unwrap(),
    )
    .via(TransportKind::Udp, "uac.example:5060", Some("z9hG4bKp1"))
    .from("<sip:bob@example.com>;tag=c1")
    .to("<sip:bob@example.com>")
    .call_id(Some("pcall-1"))
    .cseq(1)
    .build();
    let actions = proxy.process_request(&cancel, SRC, false, t0);

    // One GENERATED CANCEL per leg + a 200 to the CANCELer. Each CANCEL's
    // top Via branch equals the branch of the forked INVITE that leg
    // received (RFC 3261 §9.1 — the old verbatim forward carried the
    // upstream's branch and could never match at the UAS).
    let cancels = forked_requests(&actions);
    assert_eq!(cancels.len(), 2, "one generated CANCEL per leg");
    let fork_branches: Vec<String> = forked
        .iter()
        .map(|r| {
            r.headers
                .first_via()
                .and_then(|v| v.branch.clone())
                .unwrap()
        })
        .collect();
    for c in &cancels {
        assert_eq!(c.method, Method::Cancel);
        let branch = c
            .headers
            .first_via()
            .and_then(|v| v.branch.clone())
            .unwrap();
        assert!(
            fork_branches.contains(&branch),
            "CANCEL branch {branch} matches a forked INVITE branch"
        );
    }
    let ok200 = actions.iter().any(|a| match a {
        Action::Send(SipMessage::Response(r), _) => r.code == 200,
        _ => false,
    });
    assert!(ok200);

    // A retransmitted CANCEL is absorbed by its server tx (200 again, no
    // duplicate downstream CANCELs).
    let actions = proxy.process_request(&cancel, SRC, false, t0);
    assert_eq!(forked_requests(&actions).len(), 0, "absorbed");
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::Send(SipMessage::Response(r), _) if r.code == 200)));
}

#[test]
fn response_path_pops_via_and_targets_next_hop() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    proxy
        .routes
        .exact
        .insert("bob".into(), vec!["10.5.5.5:5060".into()]);
    let req = invite_req("sip:bob@example.com", "bob");
    let actions = proxy.process_request(&req, SRC, false, Instant::now());

    // Take the forwarded request, serialize it, reparse (like the wire), and
    // fabricate the UAS's 200 which mirrors the vias.
    let fwd = serialize(&SipMessage::Request(forked_requests(&actions).remove(0)));
    let reparsed = match parse_message(&fwd).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!(),
    };
    let resp200 = respond_to(&reparsed, 200, "OK", Vec::new(), Some("t1"));
    let wire = serialize(&SipMessage::Response(resp200));

    // Proxy receives the response (from the leg).
    let resp = match parse_message(&wire).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!(),
    };
    let acts = proxy.process_response(&resp, "10.5.5.5:5060".parse().unwrap(), Instant::now());
    assert_eq!(acts.len(), 1, "2xx forwards upstream, no ACK");
    match &acts[0] {
        Action::Send(m, dest) => {
            // The next hop is the UAC via (no received/rport) → sent-by.
            assert_eq!(dest.to_string(), "10.0.0.9:5060");
            match m {
                SipMessage::Response(r) => {
                    // Our proxy via is gone; only the UAC via remains.
                    assert_eq!(r.headers.get_all("Via").len(), 1);
                    assert!(!r.headers.get_all("Via")[0].contains("proxy.voip-stack"));
                }
                _ => panic!(),
            }
        }
    }
    // The 2xx terminated the INVITE server tx immediately (§17.2.1) and the
    // client tx's Timer D release via poll (no leak).
    assert_eq!(proxy.server_tx_count(), 0, "server tx ended with the 2xx");
    assert_eq!(proxy.leg_count(), 1, "Timer D still pending");
    proxy.poll(Instant::now() + Duration::from_secs(33));
    assert_eq!(proxy.leg_count(), 0, "Timer D released the leg");
}

#[test]
fn loose_route_stripped_when_pointing_at_us() {
    let mut proxy = Proxy::new(ProxyConfig {
        record_route: Some("proxy.voip-stack".into()),
        ..Default::default()
    });
    proxy
        .routes
        .exact
        .insert("bob".into(), vec!["10.5.5.5:5060".into()]);
    let mut req = invite_req("sip:bob@example.com", "bob");
    req.headers.add("Route", "<sip:proxy.voip-stack;lr>");
    req.headers.add("Route", "<sip:downstream.voip-stack;lr>");
    let actions = proxy.process_request(&req, SRC, false, Instant::now());
    let fwd = forked_requests(&actions).remove(0);
    let routes = fwd.headers.get_all("Route");
    assert_eq!(routes.len(), 1, "our Route removed");
    assert!(routes[0].contains("downstream"));
}

/// Build a response exactly as a downstream leg would: mirror the forwarded
/// request's Via stack (so the proxy's own via is on top), serialize, and
/// reparse like the wire does.
fn leg_response(fwd_request: &sip_core::Request, code: u16, reason: &str) -> sip_core::Response {
    let resp = respond_to(fwd_request, code, reason, Vec::new(), None);
    let wire = serialize(&SipMessage::Response(resp));
    match parse_message(&wire).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected a response"),
    }
}

#[test]
fn leg_transaction_drives_200_and_cleans_up() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    proxy
        .routes
        .exact
        .insert("bob".into(), vec!["10.5.5.5:5060".into()]);
    let req = invite_req("sip:bob@example.com", "bob");
    let actions = proxy.process_request(&req, SRC, false, Instant::now());
    let fwd = forked_requests(&actions).remove(0);

    // A provisional forwards upstream and the leg survives.
    let resp = leg_response(&fwd, 183, "Session Progress");
    let acts = proxy.process_response(&resp, "10.5.5.5:5060".parse().unwrap(), Instant::now());
    assert_eq!(acts.len(), 1);
    assert!(matches!(&acts[0], Action::Send(SipMessage::Response(r), _) if r.code == 183));
    assert_eq!(proxy.leg_count(), 1, "leg survives provisional");

    // The 200 forwards upstream; the leg's INVITE tx is Terminated and
    // Timer D only gates memory release.
    let resp200 = leg_response(&fwd, 200, "OK");
    let acts = proxy.process_response(&resp200, "10.5.5.5:5060".parse().unwrap(), Instant::now());
    assert_eq!(acts.len(), 1);
    assert!(matches!(&acts[0], Action::Send(SipMessage::Response(r), _) if r.code == 200));

    // A retransmitted 200: the client tx feeds it to the Terminated state
    // (no duplicate ACK), but §16.7 pass-through still forwards it — the
    // upstream dialog layer owns duplicate-2xx absorption.
    let acts = proxy.process_response(&resp200, "10.5.5.5:5060".parse().unwrap(), Instant::now());
    assert_eq!(acts.len(), 1, "pass-through forward of the duplicate 200");

    // Timer D releases the leg (leak regression).
    proxy.poll(Instant::now() + Duration::from_secs(33));
    assert_eq!(proxy.leg_count(), 0);
}

#[test]
fn non2xx_final_acks_the_leg_and_upstream_ack_confirms() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    proxy
        .routes
        .exact
        .insert("bob".into(), vec!["10.5.5.5:5060".into()]);
    let req = invite_req("sip:bob@example.com", "bob");
    let t0 = Instant::now();
    let actions = proxy.process_request(&req, SRC, false, t0);
    let fwd = forked_requests(&actions).remove(0);

    // The leg's 486: the client tx generates the ACK toward the leg (§17.1.1)
    // and the 486 forwards upstream.
    let resp486 = leg_response(&fwd, 486, "Busy Here");
    let acts = proxy.process_response(&resp486, "10.5.5.5:5060".parse().unwrap(), t0);
    assert_eq!(acts.len(), 2, "forward + ACK to the leg");
    let mut forwarded = false;
    let mut acked = false;
    for a in &acts {
        match a {
            Action::Send(SipMessage::Response(r), _) => {
                assert_eq!(r.code, 486);
                forwarded = true;
            }
            Action::Send(SipMessage::Request(r), dst) => {
                assert_eq!(r.method, Method::Ack);
                assert_eq!(*dst, "10.5.5.5:5060".parse().unwrap());
                // §17.1.1: the ACK carries a SINGLE Via — the forked
                // request's top via (our leg branch).
                assert_eq!(r.headers.get_all("Via").len(), 1);
                acked = true;
            }
        }
    }
    assert!(forwarded && acked);

    // The upstream ACK of the forwarded 486 is absorbed by the
    // upstream-facing server tx (§17.2.3).
    let ack = RequestBuilder::new(Method::Ack, SipUri::parse("sip:bob@example.com").unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKp1"))
        .from("<sip:bob@example.com>;tag=c1")
        .to("<sip:bob@example.com>;tag=t1")
        .call_id(Some("pcall-1"))
        .cseq(1)
        .build();
    let acts = proxy.process_request(&ack, SRC, false, t0);
    assert!(acts.is_empty(), "upstream ACK absorbed");

    // Timer I + Timer D release everything (leak regression).
    proxy.poll(t0 + Duration::from_secs(33));
    assert_eq!(proxy.server_tx_count(), 0);
    assert_eq!(proxy.leg_count(), 0);
}

#[test]
fn retransmitted_invite_does_not_refork() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    two_targets(&mut proxy);
    let req = invite_req("sip:bob@example.com", "bob");
    let t0 = Instant::now();
    let actions = proxy.process_request(&req, SRC, false, t0);
    assert_eq!(fork_targets(&actions).len(), 2);

    // A UDP retransmission of the same INVITE (same branch/seq): absorbed
    // by the server tx — the 100 re-sends, no second fork.
    let actions = proxy.process_request(&req, SRC, false, t0);
    assert_eq!(fork_targets(&actions).len(), 0, "no re-fork");
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::Send(SipMessage::Response(r), _) if r.code == 100)));
    assert_eq!(proxy.leg_count(), 2, "legs untouched");
}

#[test]
fn timer_a_retransmits_per_leg_and_timer_b_cleans_up() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    two_targets(&mut proxy);
    let req = invite_req("sip:bob@example.com", "bob");
    let t0 = Instant::now();
    let actions = proxy.process_request(&req, SRC, false, t0);
    assert_eq!(fork_targets(&actions).len(), 2);

    // No response from either leg: Timer A retransmits BOTH legs at T1.
    let actions = proxy.poll(t0 + T1);
    assert_eq!(fork_targets(&actions).len(), 2, "one retransmit per leg");

    // Timer B (64·T1): both legs time out and are deleted — and since NO
    // final response was ever forwarded, §16.7 step 6 fires: a 408 goes
    // upstream through the server tx.
    let t1 = t0 + T64 + T1;
    let actions = proxy.poll(t1);
    assert_eq!(actions.len(), 1, "one fork-timeout 408");
    assert!(matches!(&actions[0], Action::Send(SipMessage::Response(r), _) if r.code == 408));
    assert_eq!(proxy.leg_count(), 0, "both legs released");
    // The 408's own server-tx lifecycle (Timer G/H) cleans it up after the
    // ACK window; no ACK came → Timer H.
    assert_eq!(proxy.server_tx_count(), 1);
    proxy.poll(t1 + Duration::from_secs(33));
    assert_eq!(proxy.server_tx_count(), 0, "Timer H released the tx");
    // Polling a drained proxy is a no-op.
    assert_eq!(proxy.poll(t1 + Duration::from_secs(40)).len(), 0);
}

#[test]
fn bye_retransmission_absorbed_and_final_retransmitted() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    proxy
        .routes
        .exact
        .insert("bob".into(), vec!["10.5.5.5:5060".into()]);
    let bye = RequestBuilder::new(Method::Bye, SipUri::parse("sip:bob@example.com").unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKbye"))
        .from("<sip:bob@example.com>;tag=c1")
        .to("<sip:bob@example.com>;tag=t9")
        .call_id(Some("pcall-1"))
        .cseq(2)
        .build();
    let t0 = Instant::now();

    let actions = proxy.process_request(&bye, SRC, false, t0);
    assert_eq!(fork_targets(&actions).len(), 1, "forwarded once");
    assert_eq!(proxy.leg_count(), 1, "non-INVITE leg tracked too");
    let fwd = forked_requests(&actions).remove(0);

    // Retransmitted BYE: absorbed (no second downstream send).
    let actions = proxy.process_request(&bye, SRC, false, t0);
    assert_eq!(fork_targets(&actions).len(), 0, "absorbed");

    // The leg's 200 comes back (mirroring the forked BYE's via stack),
    // forwards upstream through the server tx.
    let resp200 = leg_response(&fwd, 200, "OK");
    let acts = proxy.process_response(&resp200, "10.5.5.5:5060".parse().unwrap(), t0);
    assert_eq!(acts.len(), 1, "200 forwarded upstream");
    assert!(matches!(&acts[0], Action::Send(SipMessage::Response(r), _) if r.code == 200));

    // A retransmitted BYE now hits the Completed server tx → the staged 200
    // re-sends (§17.2.2).
    let acts = proxy.process_request(&bye, SRC, false, t0);
    assert_eq!(acts.len(), 1);
    assert!(matches!(&acts[0], Action::Send(SipMessage::Response(r), _) if r.code == 200));

    // Timer J releases the tx and the leg (leak regression).
    proxy.poll(t0 + T64 + Duration::from_secs(6));
    assert_eq!(proxy.server_tx_count(), 0);
    assert_eq!(proxy.leg_count(), 0);
}

#[test]
fn response_method_scopes_transaction_match() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    proxy
        .routes
        .exact
        .insert("bob".into(), vec!["10.5.5.5:5060".into()]);
    let req = invite_req("sip:bob@example.com", "bob");
    let actions = proxy.process_request(&req, SRC, false, Instant::now());
    let fwd = forked_requests(&actions).remove(0);

    // A response whose CSeq names a different method (e.g. a stray BYE
    // response) must not be folded into the INVITE fork: the method is part
    // of the transaction key.
    let mut resp = leg_response(&fwd, 480, "Temporarily Unavailable");
    resp.headers.remove_all("CSeq");
    resp.headers.add("CSeq", "2 BYE");
    let wire = serialize(&SipMessage::Response(resp));
    let resp = match parse_message(&wire).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!(),
    };
    let acts = proxy.process_response(&resp, "10.5.5.5:5060".parse().unwrap(), Instant::now());
    assert_eq!(acts.len(), 1, "response still forwards upstream");
    // No ACK was generated: the INVITE leg was never fed a final.
    assert!(acts
        .iter()
        .all(|a| matches!(a, Action::Send(SipMessage::Response(_), _))));
}

#[test]
fn lost_483_is_retransmitted_by_poll() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    let mut req = invite_req("sip:bob@example.com", "bob");
    req.headers.remove_all("Max-Forwards");
    req.headers.add("Max-Forwards", "0");
    let t0 = Instant::now();
    let _ = proxy.process_request(&req, SRC, false, t0);

    // Timer G retransmits the staged 483 upstream, doubling: fires at T1,
    // then at +2·T1 (deadline t0+3·T1)...
    let actions = proxy.poll(t0 + T1);
    assert_eq!(actions.len(), 1);
    assert!(matches!(&actions[0], Action::Send(SipMessage::Response(r), _) if r.code == 483));
    assert_eq!(proxy.poll(t0 + T1 * 2).len(), 0, "not due yet");
    let actions = proxy.poll(t0 + T1 * 3);
    assert_eq!(actions.len(), 1);
    assert!(matches!(&actions[0], Action::Send(SipMessage::Response(r), _) if r.code == 483));
    // ...until Timer H (no ACK ever) releases the tx.
    let actions = proxy.poll(t0 + T64);
    assert_eq!(actions.len(), 0);
    assert_eq!(proxy.server_tx_count(), 0, "Timer H released the tx");
}

#[test]
fn reliable_transport_suppresses_retransmissions() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    let req = invite_req("sip:bob@example.com", "bob");
    proxy
        .bindings
        .insert("bob".into(), vec!["10.9.9.9:5060".into()]);
    let t0 = Instant::now();

    // Arrived over a reliable transport: the 100 forwards once...
    let actions = proxy.process_request(&req, SRC, true, t0);
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::Send(SipMessage::Response(r), _) if r.code == 100)));
    assert_eq!(proxy.leg_count(), 1, "fork leg still tracked (UDP out)");
    let fwd = forked_requests(&actions).remove(0);

    // ...and NO server-tx response retransmission ever fires (Timer G
    // suppressed); the only retransmits are the fork leg's own Timer A
    // (downstream is UDP) — assert requests only.
    let actions = proxy.poll(t0 + T1);
    assert!(actions
        .iter()
        .all(|a| matches!(a, Action::Send(SipMessage::Request(_), _))));

    // The leg's 200 ends the INVITE server tx immediately (§17.2.1 — the
    // 2xx is dialog-level; reliable → no Timer D either).
    let resp200 = leg_response(&fwd, 200, "OK");
    let acts = proxy.process_response(&resp200, "10.9.9.9:5060".parse().unwrap(), t0);
    assert_eq!(acts.len(), 1);
    assert!(matches!(&acts[0], Action::Send(SipMessage::Response(r), _) if r.code == 200));
    assert_eq!(proxy.server_tx_count(), 0, "2xx ends the server tx at once");
}
