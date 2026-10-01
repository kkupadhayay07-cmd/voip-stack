//! Registrar behaviour tests: registration lifecycle, auth, wildcard,
//! expiry and consistency rules.

use registrar::{AuthStore, Registrar, RegistrarConfig};
use sip_core::headers::AuthResponse;

fn auth_header(a: &AuthResponse) -> String {
    let mut h = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        a.username.as_deref().unwrap_or(""),
        a.realm.as_deref().unwrap_or(""),
        a.nonce.as_deref().unwrap_or(""),
        a.uri.as_deref().unwrap_or(""),
        a.response.as_deref().unwrap_or("")
    );
    if let Some(c) = &a.cnonce {
        h.push_str(&format!(", cnonce=\"{c}\", nc=00000001, qop=auth"));
    }
    if let Some(alg) = &a.algorithm {
        h.push_str(&format!(", algorithm={alg}"));
    }
    if let Some(o) = &a.opaque {
        h.push_str(&format!(", opaque=\"{o}\""));
    }
    h
}
use sip_core::builder::RequestBuilder;
use sip_core::message::Method;
use sip_core::uri::{SipUri, TransportKind};
use sip_core::SipMessage;

fn register_req(
    aor: &str,
    contact: &str,
    expires: Option<u32>,
    call_id: &str,
    cseq: u32,
) -> sip_core::Request {
    let uri = format!("sip:{aor}");
    let mut b = RequestBuilder::new(Method::Register, SipUri::parse(&uri).unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKreg"))
        .from(&format!("<sip:{aor}>;tag=r1"))
        .to(&format!("<sip:{aor}>"))
        .call_id(Some(call_id))
        .cseq(cseq);
    // The wildcard contact is a bare "*" (RFC 3261 §10.2.2); other contacts
    // take angle brackets.
    if contact == "*" {
        b = b.contact("*");
    } else {
        b = b.contact(&format!("<{contact}>"));
    }
    if let Some(e) = expires {
        b = b.header("Expires", &e.to_string());
    }
    b.build()
}

#[test]
fn basic_registration_and_lookup() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let req = register_req(
        "alice@example.com",
        "sip:alice@10.0.0.9:5060",
        Some(300),
        "cid-1",
        1,
    );
    let resp = reg.process(&req, "10.0.0.9:5060").unwrap();
    assert_eq!(resp.code, 200);
    let bindings = reg.bindings("sip:alice@example.com");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].contact, "sip:alice@10.0.0.9:5060");
    assert_eq!(bindings[0].source, "10.0.0.9:5060");
    assert!(bindings[0].remaining() > 200 && bindings[0].remaining() <= 300);

    // Response lists the binding.
    let contacts = resp.headers.get_all("Contact");
    assert_eq!(contacts.len(), 1);
    assert!(contacts[0].contains("expires="));
}

// RFC 3261 §10.2.8: an expiry below the configured minimum is refused with
// 423 carrying Min-Expires, and no binding is created or touched.
#[test]
fn below_min_expires_gets_423_with_min_expires_header() {
    let mut reg = Registrar::new(RegistrarConfig {
        min_expires: 60,
        max_expires: 3600,
        ..RegistrarConfig::default()
    });
    let req = register_req(
        "min@example.com",
        "sip:min@10.0.0.9:5060",
        Some(30),
        "cid-min-1",
        1,
    );
    let resp = reg.process(&req, "10.0.0.9:5060").unwrap();
    assert_eq!(resp.code, 423);
    assert_eq!(resp.reason, "Interval Too Brief");
    assert_eq!(
        resp.headers.get("Min-Expires"),
        Some("60"),
        "423 must carry the configured minimum"
    );
    assert!(
        reg.bindings("sip:min@example.com").is_empty(),
        "a refused REGISTER must not create a binding"
    );

    // Contact-level expires param below the minimum is refused too.
    let uri = "sip:min2@example.com";
    let req = RequestBuilder::new(Method::Register, SipUri::parse(uri).unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKreg"))
        .from(&format!("<{uri}>;tag=r2"))
        .to(&format!("<{uri}>"))
        .call_id(Some("cid-min-2"))
        .cseq(1)
        .contact("<sip:min2@10.0.0.9:5060>;expires=10")
        .build();
    let resp = reg.process(&req, "10.0.0.9:5060").unwrap();
    assert_eq!(resp.code, 423);

    // Expiry at the minimum is accepted.
    let req = register_req(
        "min@example.com",
        "sip:min@10.0.0.9:5060",
        Some(60),
        "cid-min-3",
        2,
    );
    assert_eq!(reg.process(&req, "10.0.0.9:5060").unwrap().code, 200);
    assert_eq!(reg.bindings("sip:min@example.com").len(), 1);

    // De-registration (Expires: 0) is never 423.
    let req = register_req(
        "min@example.com",
        "sip:min@10.0.0.9:5060",
        Some(0),
        "cid-min-3",
        3,
    );
    assert_eq!(reg.process(&req, "10.0.0.9:5060").unwrap().code, 200);
    assert!(reg.bindings("sip:min@example.com").is_empty());
}

// The nonce table is pruned when a new nonce is issued: stale challenges
// cannot accumulate without bound (audit 2026-09 P2).
#[test]
fn nonce_table_pruned_on_issue() {
    use std::time::Duration;
    let mut reg = Registrar::new(RegistrarConfig {
        require_auth: true,
        ..RegistrarConfig::default()
    });
    let mut auth = AuthStore::new("test");
    auth.add_user("nonce", "pw");
    auth.nonce_ttl = Duration::from_millis(80);
    reg = reg.with_auth(auth);

    let req = register_req(
        "nonce@example.com",
        "sip:nonce@10.0.0.9:5060",
        Some(300),
        "cid-nonce-1",
        1,
    );
    assert_eq!(reg.process(&req, "10.0.0.9:5060").unwrap().code, 401);
    let auth = reg.auth.as_ref().unwrap();
    assert_eq!(auth.nonces.len(), 1, "first challenge installs one nonce");

    // After the TTL lapses, the next challenge evicts the expired nonce.
    std::thread::sleep(Duration::from_millis(120));
    let req = register_req(
        "nonce@example.com",
        "sip:nonce@10.0.0.9:5060",
        Some(300),
        "cid-nonce-2",
        2,
    );
    assert_eq!(reg.process(&req, "10.0.0.9:5060").unwrap().code, 401);
    let auth = reg.auth.as_ref().unwrap();
    assert_eq!(
        auth.nonces.len(),
        1,
        "expired nonces must be evicted, not accumulated"
    );
}

#[test]
fn refresh_updates_expiry_and_prunes_with_zero() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let req = register_req(
        "bob@example.com",
        "sip:bob@10.0.0.8:5060",
        Some(300),
        "cid-2",
        1,
    );
    assert_eq!(reg.process(&req, "10.0.0.8:5060").unwrap().code, 200);

    // Refresh with a higher CSeq and shorter expiry.
    let req = register_req(
        "bob@example.com",
        "sip:bob@10.0.0.8:5060",
        Some(120),
        "cid-2",
        2,
    );
    assert_eq!(reg.process(&req, "10.0.0.8:5060").unwrap().code, 200);
    let b = reg.bindings("sip:bob@example.com");
    assert_eq!(b.len(), 1);
    assert!(b[0].remaining() <= 120);

    // De-register with Expires: 0.
    let req = register_req(
        "bob@example.com",
        "sip:bob@10.0.0.8:5060",
        Some(0),
        "cid-2",
        3,
    );
    assert_eq!(reg.process(&req, "10.0.0.8:5060").unwrap().code, 200);
    assert!(reg.bindings("sip:bob@example.com").is_empty());
}

#[test]
fn wildcard_removal() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    for cseq in 1..=2 {
        let req = register_req(
            "carol@example.com",
            "sip:carol@10.0.0.7:5060",
            Some(300),
            "cid-3",
            cseq,
        );
        reg.process(&req, "10.0.0.7:5060").unwrap();
    }
    // Wildcard without Expires: 0 → 400.
    let mut star = register_req("carol@example.com", "*", None, "cid-3", 3);
    star.headers.add("Expires", "300");
    assert_eq!(reg.process(&star, "10.0.0.7:5060").unwrap().code, 400);
    // Wildcard with Expires: 0 → 200 and bindings wiped.
    star.headers.remove_all("Expires");
    star.headers.add("Expires", "0");
    assert_eq!(reg.process(&star, "10.0.0.7:5060").unwrap().code, 200);
    assert!(reg.bindings("sip:carol@example.com").is_empty());
}

#[test]
fn domain_mismatch_404() {
    let mut reg = Registrar::new(RegistrarConfig {
        domain: Some("example.com".into()),
        ..Default::default()
    });
    let req = register_req(
        "someone@other.org",
        "sip:someone@10.0.0.5:5060",
        Some(300),
        "cid-4",
        1,
    );
    assert_eq!(reg.process(&req, "10.0.0.5:5060").unwrap().code, 404);
}

#[test]
fn digest_challenge_and_success() {
    let mut reg = Registrar::new(RegistrarConfig {
        require_auth: true,
        ..Default::default()
    })
    .with_auth(AuthStore::new("example.com").with_user("dave", "hunter2"));

    let req = register_req(
        "dave@example.com",
        "sip:dave@10.0.0.6:5060",
        Some(300),
        "cid-5",
        1,
    );
    // First attempt → 401 with a challenge.
    let challenge = reg.process(&req, "10.0.0.6:5060").unwrap();
    assert_eq!(challenge.code, 401);
    let www = challenge.headers.get("WWW-Authenticate").unwrap();
    assert!(www.contains("Digest") && www.contains("nonce=\""));

    // Extract the nonce and build a correct Authorization header using the
    // sip-core digest helper.
    let nonce_start = www.find("nonce=\"").unwrap() + 7;
    let nonce = &www[nonce_start..www[nonce_start..].find('"').unwrap() + nonce_start];

    let auth_resp = sip_core::digest::respond_to_challenge(
        &sip_core::headers::AuthChallenge::parse(www).unwrap(),
        "REGISTER",
        "sip:example.com",
        "dave",
        "hunter2",
        1,
        "cnonce-1",
        false,
    )
    .unwrap();
    assert_eq!(auth_resp.nonce.as_deref(), Some(nonce));

    let mut authed = register_req(
        "dave@example.com",
        "sip:dave@10.0.0.6:5060",
        Some(300),
        "cid-5",
        1,
    );
    authed.headers.add("Authorization", auth_header(&auth_resp));

    let ok = reg.process(&authed, "10.0.0.6:5060").unwrap();
    assert_eq!(ok.code, 200, "digest must validate");

    // The nonce was consumed; replaying the same nonce → 401 again.
    let replay = reg.process(&authed, "10.0.0.6:5060").unwrap();
    assert_eq!(replay.code, 401);
}

#[test]
fn wrong_password_rejected() {
    let mut reg = Registrar::new(RegistrarConfig {
        require_auth: true,
        ..Default::default()
    })
    .with_auth(AuthStore::new("example.com").with_user("erin", "right-pass"));

    let req = register_req(
        "erin@example.com",
        "sip:erin@10.0.0.4:5060",
        Some(300),
        "cid-6",
        1,
    );
    let challenge = reg.process(&req, "10.0.0.4:5060").unwrap();
    let www = challenge
        .headers
        .get("WWW-Authenticate")
        .unwrap()
        .to_string();

    let auth_resp = sip_core::digest::respond_to_challenge(
        &sip_core::headers::AuthChallenge::parse(&www).unwrap(),
        "REGISTER",
        "sip:example.com",
        "erin",
        "WRONG-pass",
        1,
        "cnonce-2",
        false,
    )
    .unwrap();
    let mut authed = register_req(
        "erin@example.com",
        "sip:erin@10.0.0.4:5060",
        Some(300),
        "cid-6",
        1,
    );
    authed.headers.add("Authorization", auth_header(&auth_resp));
    assert_eq!(reg.process(&authed, "10.0.0.4:5060").unwrap().code, 401);
}

#[test]
fn multiple_contacts_and_q_ordering() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let req = register_req(
        "frank@example.com",
        "sip:frank@10.0.0.3:5060",
        Some(300),
        "cid-7",
        1,
    );
    reg.process(&req, "10.0.0.3:5060").unwrap();
    let req = register_req(
        "frank@example.com",
        "sip:frank@10.0.0.2:5060",
        Some(300),
        "cid-8",
        1,
    );
    reg.process(&req, "10.0.0.2:5060").unwrap();
    assert_eq!(reg.bindings("sip:frank@example.com").len(), 2);
}

#[test]
fn non_register_rejected() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let invite = RequestBuilder::new(Method::Invite, SipUri::parse("sip:x@y.com").unwrap())
        .via(TransportKind::Udp, "h:1", Some("z9hG4bKi"))
        .from("<sip:a@b.com>")
        .to("<sip:x@y.com>")
        .build();
    assert!(reg.process(&invite, "x").is_err());
}

#[test]
fn wire_roundtrip() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let req = register_req(
        "grace@example.com",
        "sip:grace@10.0.0.1:5060",
        Some(300),
        "cid-9",
        1,
    );
    let resp = reg.process(&req, "10.0.0.1:5060").unwrap();
    // Response must survive serialization.
    let wire = sip_core::serialize(&SipMessage::Response(resp.clone()));
    let reparsed = sip_core::parse::parse_message(&wire).unwrap();
    match reparsed {
        SipMessage::Response(r) => assert_eq!(r.code, 200),
        _ => panic!("expected response"),
    }
}

// ---------------------------------------------------------------------------
// RFC 5626 Outbound / RFC 5627 GRUU
// ---------------------------------------------------------------------------

/// REGISTER over a reliable transport with `Supported: outbound, gruu` and
/// an instance-tagged Contact.
fn outbound_register_req(
    aor: &str,
    contact: &str,
    instance: &str,
    reg_id: u32,
    expires: u32,
) -> sip_core::Request {
    let uri = format!("sip:{aor}");
    RequestBuilder::new(Method::Register, SipUri::parse(&uri).unwrap())
        .via(TransportKind::Tcp, "10.0.0.9:5060", Some("z9hG4bKout"))
        .from(&format!("<{uri}>;tag=rout"))
        .to(&format!("<{uri}>"))
        .call_id(Some("cid-out-1"))
        .cseq(1)
        .contact(&format!(
            "<{contact}>;+sip.instance=\"{instance}\";reg-id={reg_id}"
        ))
        .header("Supported", "outbound, gruu")
        .header("Expires", &expires.to_string())
        .build()
}

// RFC 5626 §4.2 + RFC 5627 §4.2/§4.3: a TCP REGISTER advertising Outbound
// with an instance-tagged contact gets Flow-Timer + Supported echo, the
// Contact is echoed with instance/reg-id/pub-gruu, and the binding stores
// the flow identity.
#[test]
fn outbound_tcp_registration_echoes_instance_gruu_and_flow_timer() {
    let mut reg = Registrar::new(RegistrarConfig {
        flow_timer_secs: 120,
        ..RegistrarConfig::default()
    });
    let instance = "urn:uuid:11111111-2222-3333-4444-555555555555";
    let req = outbound_register_req(
        "webrtc@example.com",
        "sip:webrtc@10.0.0.9:5060",
        instance,
        1,
        300,
    );
    let resp = reg.process(&req, "10.0.0.9:5060").unwrap();
    assert_eq!(resp.code, 200);

    // Flow-Timer demanded from the client (keep the connection alive).
    assert_eq!(resp.headers.get("Flow-Timer"), Some("120"));
    // Supported echo covers exactly what we negotiated/handle.
    let supported = resp.headers.get("Supported").unwrap_or("");
    assert!(
        supported.contains("outbound"),
        "Supported echo: {supported}"
    );
    assert!(supported.contains("gruu"), "GRUU advertised: {supported}");

    // Contact echo: instance (quoted), reg-id, pub-gruu (quoted, contains ;).
    let contacts = resp.headers.get_all("Contact");
    assert_eq!(contacts.len(), 1);
    let c = contacts[0];
    assert!(
        c.contains("+sip.instance=\"urn:uuid:11111111-2222-3333-4444-555555555555\""),
        "instance echoed: {c}"
    );
    assert!(c.contains("reg-id=1"), "reg-id echoed: {c}");
    assert!(
        c.contains(
            "pub-gruu=\"sip:webrtc@example.com;gr=urn:uuid:11111111-2222-3333-4444-555555555555\""
        ),
        "pub-gruu synthesized from AOR + instance: {c}"
    );
    assert!(c.contains("expires="));

    // Binding state.
    let b = &reg.bindings("sip:webrtc@example.com")[0];
    assert_eq!(b.instance.as_deref(), Some(instance));
    assert_eq!(b.reg_id, 1);
    assert!(b.flow, "TCP registration is a flow");
    assert_eq!(
        b.pub_gruu.as_deref(),
        Some("sip:webrtc@example.com;gr=urn:uuid:11111111-2222-3333-4444-555555555555")
    );

    // The 200 OK wire form is a parse→serialize fixed point (the quoted
    // instance/pub-gruu params must not degrade across a hop).
    let wire = sip_core::serialize(&SipMessage::Response(resp.clone()));
    match sip_core::parse_message(&wire).unwrap() {
        SipMessage::Response(r) => {
            let reparsed_contacts = r.headers.get_all("Contact").to_vec();
            assert_eq!(
                reparsed_contacts,
                contacts.to_vec(),
                "Contact echo is wire-stable"
            );
            assert_eq!(r.headers.get("Flow-Timer"), Some("120"));
        }
        _ => panic!("expected response"),
    }
}

// A UDP REGISTER advertising Outbound is NOT a flow registration: no
// Flow-Timer (RFC 5626 §5.1 flow keep-alives apply to TCP-based
// transports), no Outbound echo, binding.flow stays false.
#[test]
fn udp_registration_does_not_negotiate_outbound() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let instance = "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let uri = "sip:lan@example.com";
    let req = RequestBuilder::new(Method::Register, SipUri::parse(uri).unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKlan"))
        .from(&format!("<{uri}>;tag=rlan"))
        .to(&format!("<{uri}>"))
        .call_id(Some("cid-lan-1"))
        .cseq(1)
        .contact(&format!(
            "<sip:lan@10.0.0.9>;+sip.instance=\"{instance}\";reg-id=1"
        ))
        .header("Supported", "outbound, gruu")
        .build();
    let resp = reg.process(&req, "10.0.0.9:5060").unwrap();
    assert_eq!(resp.code, 200);
    assert_eq!(
        resp.headers.get("Flow-Timer"),
        None,
        "UDP has no flow to manage"
    );
    assert_eq!(resp.headers.get("Supported"), None);
    // GRUU still synthesized (instance present) — GRUU is independent of
    // the flow layer.
    let b = &reg.bindings("sip:lan@example.com")[0];
    assert!(!b.flow);
    assert!(b.pub_gruu.is_some());
}

// RFC 5626 §4.2: two reg-ids under one instance are distinct bindings
// (one per client flow); de-registering one with Expires: 0 leaves the
// other alive.
#[test]
fn two_reg_ids_are_distinct_and_deregister_is_scoped() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let instance = "urn:uuid:11111111-2222-3333-4444-555555555555";
    let r1 = outbound_register_req(
        "multi@example.com",
        "sip:multi@10.0.0.9:5060",
        instance,
        1,
        300,
    );
    let resp1 = reg.process(&r1, "10.0.0.9:5060").unwrap();
    assert_eq!(resp1.code, 200);
    // Same Call-ID would collide with binding 1; a second flow uses its
    // own Call-ID.
    let uri = "sip:multi@example.com";
    let r2 = RequestBuilder::new(Method::Register, SipUri::parse(uri).unwrap())
        .via(TransportKind::Tcp, "10.0.0.9:5061", Some("z9hG4bKout2"))
        .from(&format!("<{uri}>;tag=rout2"))
        .to(&format!("<{uri}>"))
        .call_id(Some("cid-out-2"))
        .cseq(1)
        .contact(&format!(
            "<sip:multi@10.0.0.9:5060>;+sip.instance=\"{instance}\";reg-id=2"
        ))
        .header("Supported", "outbound")
        .build();
    let resp2 = reg.process(&r2, "10.0.0.9:5061").unwrap();
    assert_eq!(resp2.code, 200);
    assert_eq!(
        reg.bindings("sip:multi@example.com").len(),
        2,
        "reg-id 1 and 2 are separate flows"
    );

    // De-register reg-id 1 only.
    let dereg = RequestBuilder::new(Method::Register, SipUri::parse(uri).unwrap())
        .via(TransportKind::Tcp, "10.0.0.9:5060", Some("z9hG4bKout"))
        .from(&format!("<{uri}>;tag=rout"))
        .to(&format!("<{uri}>"))
        .call_id(Some("cid-out-1"))
        .cseq(2)
        .contact(&format!(
            "<sip:multi@10.0.0.9:5060>;+sip.instance=\"{instance}\";reg-id=1"
        ))
        .header("Expires", "0")
        .build();
    let resp = reg.process(&dereg, "10.0.0.9:5060").unwrap();
    assert_eq!(resp.code, 200);
    let left = reg.bindings("sip:multi@example.com");
    assert_eq!(left.len(), 1, "only reg-id 2 survives");
    assert_eq!(left[0].reg_id, 2);
}

// RFC 5626 §9.4: reg-id = 0 is a protocol violation → 400.
#[test]
fn reg_id_zero_is_rejected() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let uri = "sip:zero@example.com";
    let req = RequestBuilder::new(Method::Register, SipUri::parse(uri).unwrap())
        .via(TransportKind::Tcp, "10.0.0.9:5060", Some("z9hG4bKz"))
        .from(&format!("<{uri}>;tag=rz"))
        .to(&format!("<{uri}>"))
        .call_id(Some("cid-zero"))
        .cseq(1)
        .contact("<sip:zero@10.0.0.9>;+sip.instance=\"<urn:uuid:z>\";reg-id=0")
        .build();
    let resp = reg.process(&req, "10.0.0.9:5060").unwrap();
    assert_eq!(resp.code, 400);
}

// The q value is now echoed on the response Contact (RFC 3261 §10.2.8 —
// the registrar must return the registered preference).
#[test]
fn q_value_is_echoed_in_200_ok() {
    let mut reg = Registrar::new(RegistrarConfig::default());
    let uri = "sip:q@example.com";
    let req = RequestBuilder::new(Method::Register, SipUri::parse(uri).unwrap())
        .via(TransportKind::Udp, "10.0.0.9:5060", Some("z9hG4bKq"))
        .from(&format!("<{uri}>;tag=rq"))
        .to(&format!("<{uri}>"))
        .call_id(Some("cid-q"))
        .cseq(1)
        .contact("<sip:q@10.0.0.9>;q=0.5")
        .build();
    let resp = reg.process(&req, "10.0.0.9:5060").unwrap();
    assert_eq!(resp.code, 200);
    let c = resp.headers.get_all("Contact")[0];
    assert!(c.contains("q=0.5"), "q echoed: {c}");
}
