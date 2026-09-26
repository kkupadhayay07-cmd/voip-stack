//! Proxy behavior tests: routing, Via handling, Max-Forwards, Record-Route,
//! forking, CANCEL, and response forwarding.

use proxy::{Action, Proxy, ProxyConfig};
use sip_core::builder::RequestBuilder;
use sip_core::message::Method;
use sip_core::parse::parse_message;
use sip_core::serialize;
use sip_core::uri::{SipUri, TransportKind};
use sip_core::SipMessage;
use std::net::SocketAddr;

const SRC: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9)),
    5060,
);

fn invite_req(uri: &str, user: &str) -> sip_core::Request {
    RequestBuilder::new(Method::Invite, SipUri::parse(uri).unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKp1"))
        .from(&format!("<sip:{user}@example.com>;tag=c1"))
        .to(&format!("<sip:{user}@example.com>"))
        .call_id(Some("pcall-1"))
        .cseq(1)
        .build()
}

#[test]
fn invite_forks_to_targets_and_adds_via() {
    let mut proxy = Proxy::new(ProxyConfig {
        record_route: Some("proxy.voip-stack".into()),
        ..Default::default()
    });
    proxy.routes.exact.insert(
        "bob".into(),
        vec!["192.168.1.10:5060".into(), "192.168.1.11:5060".into()],
    );

    let req = invite_req("sip:bob@example.com", "bob");
    let actions = proxy.process_request(&req, SRC);

    let sends: Vec<&SocketAddr> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(m, d) => match m {
                SipMessage::Request(_) => Some(d),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(sends.len(), 2, "forked to two targets");
    let want: SocketAddr = "192.168.1.10:5060".parse().unwrap();
    assert!(sends.contains(&&want));

    // 100 Trying upstream.
    let trying = actions.iter().any(|a| match a {
        Action::Send(m, _) => match m {
            SipMessage::Response(r) => r.code == 100,
            _ => false,
        },
        _ => false,
    });
    assert!(trying);

    // The forwarded request carries our Via on top + Record-Route + reduced
    // Max-Forwards.
    let fwd = match &actions[0] {
        Action::Send(m, _) => match m {
            SipMessage::Request(r) => r.clone(),
            _ => panic!(),
        },
        _ => panic!(),
    };
    let vias = fwd.headers.get_all("Via");
    assert_eq!(vias.len(), 2);
    assert!(vias[0].contains("proxy.voip-stack"), "our via is on top");
    assert_eq!(fwd.headers.max_forwards(), Some(69));
    assert!(fwd.headers.get("Record-Route").is_some());
}

#[test]
fn max_forwards_zero_rejected_with_483() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    let mut req = invite_req("sip:bob@example.com", "bob");
    req.headers.remove_all("Max-Forwards");
    req.headers.add("Max-Forwards", "0");
    let actions = proxy.process_request(&req, SRC);
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        Action::Send(m, dest) => {
            assert_eq!(*dest, SRC);
            match m {
                SipMessage::Response(r) => assert_eq!(r.code, 483),
                _ => panic!("expected response"),
            }
        }
        _ => panic!("expected a send"),
    }
}

#[test]
fn unknown_target_404() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    let req = invite_req("sip:nobody@example.com", "nobody");
    let actions = proxy.process_request(&req, SRC);
    match &actions[0] {
        Action::Send(m, _) => match m {
            SipMessage::Response(r) => assert_eq!(r.code, 404),
            _ => panic!(),
        },
        _ => panic!(),
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
    let actions = proxy.process_request(&req, SRC);
    let sends: Vec<&SocketAddr> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(SipMessage::Request(_), d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(sends, vec![&"10.9.9.9:5060".parse().unwrap()]);
}

#[test]
fn cancel_cancels_fork_and_is_200ed_locally() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    proxy.routes.exact.insert(
        "bob".into(),
        vec!["192.168.1.10:5060".into(), "192.168.1.11:5060".into()],
    );
    let req = invite_req("sip:bob@example.com", "bob");
    let _ = proxy.process_request(&req, SRC);
    assert_eq!(proxy.transactions.len(), 1);

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
    let actions = proxy.process_request(&cancel, SRC);
    assert_eq!(proxy.transactions.len(), 0, "fork torn down");

    // One CANCEL per leg + a 200 to the CANCELer.
    let reqs = actions
        .iter()
        .filter(|a| matches!(a, Action::Send(SipMessage::Request(_), _)))
        .count();
    let ok200 = actions.iter().any(|a| match a {
        Action::Send(SipMessage::Response(r), _) => r.code == 200,
        _ => false,
    });
    assert_eq!(reqs, 2);
    assert!(ok200);
}

#[test]
fn response_path_pops_via_and_targets_next_hop() {
    let mut proxy = Proxy::new(ProxyConfig::default());
    proxy
        .routes
        .exact
        .insert("bob".into(), vec!["10.5.5.5:5060".into()]);
    let req = invite_req("sip:bob@example.com", "bob");
    let actions = proxy.process_request(&req, SRC);

    // Take the forwarded request, serialize it, reparse (like the wire), and
    // fabricate the UAS's 200 which mirrors the vias.
    let fwd = match &actions[0] {
        Action::Send(m, _) => match m {
            SipMessage::Request(r) => serialize(&SipMessage::Request(r.clone())),
            _ => panic!(),
        },
        _ => panic!(),
    };
    let reparsed = match parse_message(&fwd).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!(),
    };
    let resp200 = sip_core::builder::respond_to(&reparsed, 200, "OK", Vec::new(), Some("t1"));
    let wire = serialize(&SipMessage::Response(resp200));

    // Proxy receives the response (from the leg).
    let resp = match parse_message(&wire).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!(),
    };
    let act = proxy.process_response(&resp, "10.5.5.5:5060".parse().unwrap());
    let act = act.expect("response must forward");
    match act {
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
        _ => panic!(),
    }
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
    let actions = proxy.process_request(&req, SRC);
    let fwd = actions
        .iter()
        .find_map(|a| match a {
            Action::Send(SipMessage::Request(r), _) => Some(r.clone()),
            _ => None,
        })
        .unwrap();
    let routes = fwd.headers.get_all("Route");
    assert_eq!(routes.len(), 1, "our Route removed");
    assert!(routes[0].contains("downstream"));
}
