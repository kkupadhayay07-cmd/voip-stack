//! RFC 3262 (100rel / PRACK) integration tests over a live B2BUA engine:
//! reliable 180 on leg A with the final parked until PRACK (§3), Timer-G
//! retransmission until the PRACK, RAck matching (481/400/488 verdicts),
//! plain 180 without 100rel support, PRACKing leg B's reliable 1xx (§4) and
//! the 421 Extension-Required dial retry.

use b2bua::{B2bua, B2buaConfig};
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, Response, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

// ---- shared fixtures (mirroring session_timers.rs) --------------------------

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, s: impl Into<String>) {
        self.0.lock().unwrap().push(s.into());
    }
    fn contains(&self, needle: &str) -> bool {
        self.0.lock().unwrap().iter().any(|s| s.contains(needle))
    }
    fn snapshot(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

fn offer_sdp(port: u16) -> String {
    format!(
        "v=0\r\n\
         o=caller 1 1 IN IP4 127.0.0.1\r\n\
         s=rel100-test\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=sendrecv\r\n"
    )
}

fn answer_sdp(port: u16) -> String {
    format!(
        "v=0\r\n\
         o=uas 2 2 IN IP4 127.0.0.1\r\n\
         s=leg-b\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=sendrecv\r\n"
    )
}

async fn spawn_engine(uas: SocketAddr) -> SocketAddr {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let cfg = B2buaConfig {
        sip_bind: "127.0.0.1:0".parse().unwrap(),
        media_host: "127.0.0.1".into(),
        media_base_port: 0,
        codecs: vec![codecs::CodecId::Pcmu],
        routes: Vec::new(),
        default_target: format!("sip:1000@{uas}"),
        session_timer_min_se: 1,
    };
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = B2bua::new(cfg, tx).run_on(Arc::new(sock)).await;
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    addr
}

/// Leg B fake UAS: answers every INVITE with 100 + 200 (no 100rel needed).
async fn run_plain_uas(sock: UdpSocket, rtp_port: u16, log: Log) {
    let mut buf = vec![0u8; 65_535];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, src))) = recv else { break };
        let Ok(msg) = parse_message(&buf[..n]) else {
            continue;
        };
        let SipMessage::Request(req) = msg else {
            continue;
        };
        match req.method {
            Method::Invite => {
                log.push(format!(
                    "INVITE cseq={}",
                    req.headers.cseq().map(|c| c.seq).unwrap_or(0)
                ));
                let trying = sip_core::builder::respond_to(&req, 100, "Trying", Vec::new(), None);
                let _ = sock
                    .send_to(&serialize(&SipMessage::Response(trying)), src)
                    .await;
                let mut ok = sip_core::builder::respond_to(
                    &req,
                    200,
                    "OK",
                    answer_sdp(rtp_port).into_bytes(),
                    Some("tagB"),
                );
                ok.headers.add("Contact", "<sip:uas@127.0.0.1>");
                let _ = sock
                    .send_to(&serialize(&SipMessage::Response(ok)), src)
                    .await;
            }
            Method::Ack => log.push("ACK"),
            Method::Prack => {
                log.push(format!(
                    "PRACK rack={}",
                    req.headers.get("RAck").unwrap_or("-")
                ));
                let ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                let _ = sock
                    .send_to(&serialize(&SipMessage::Response(ok)), src)
                    .await;
            }
            Method::Bye => {
                log.push("BYE");
                let ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                let _ = sock
                    .send_to(&serialize(&SipMessage::Response(ok)), src)
                    .await;
                break;
            }
            _ => {}
        }
    }
}

/// Leg B fake UAS that speaks 100rel: every INVITE is answered with a
/// reliable 180 (`Require: 100rel` + `RSeq: 77` + To tag), then it waits for
/// the PRACK (validating `RAck`), answers it, retransmits the same 180 once
/// (recovery path) and finally answers the INVITE with 200.
async fn run_rel100_uas(sock: UdpSocket, rtp_port: u16, log: Log) {
    let mut buf = vec![0u8; 65_535];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut ringing: Option<Vec<u8>> = None;
    let mut invite: Option<sip_core::message::Request> = None;
    let mut pracks_seen = 0;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, src))) = recv else { break };
        let Ok(msg) = parse_message(&buf[..n]) else {
            continue;
        };
        match msg {
            SipMessage::Request(req) => match req.method {
                Method::Invite => {
                    log.push("INVITE");
                    let trying =
                        sip_core::builder::respond_to(&req, 100, "Trying", Vec::new(), None);
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(trying)), src)
                        .await;
                    let mut ring = sip_core::builder::respond_to(
                        &req,
                        180,
                        "Ringing",
                        Vec::new(),
                        Some("tagB"),
                    );
                    ring.headers.add("Require", "100rel");
                    ring.headers.add("RSeq", "77");
                    let bytes = serialize(&SipMessage::Response(ring));
                    let _ = sock.send_to(&bytes, src).await;
                    ringing = Some(bytes);
                    invite = Some(req);
                }
                Method::Prack => {
                    pracks_seen += 1;
                    log.push(format!(
                        "PRACK{} rack={}",
                        pracks_seen,
                        req.headers.get("RAck").unwrap_or("-")
                    ));
                    let ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(ok)), src)
                        .await;
                    if pracks_seen == 2 {
                        // Both PRACKs in; answer the INVITE — built from the
                        // original INVITE so Via/CSeq match its transaction.
                        if let Some(inv) = &invite {
                            let mut ok = sip_core::builder::respond_to(
                                inv,
                                200,
                                "OK",
                                answer_sdp(rtp_port).into_bytes(),
                                Some("tagB"),
                            );
                            ok.headers.add("Contact", "<sip:uas@127.0.0.1>");
                            ok.headers.add("Supported", "100rel");
                            let _ = sock
                                .send_to(&serialize(&SipMessage::Response(ok)), src)
                                .await;
                        }
                    } else {
                        // Retransmit the same reliable 180 (our view: the
                        // first PRACK's 200 was lost).
                        if let Some(bytes) = ringing.clone() {
                            let _ = sock.send_to(&bytes, src).await;
                        }
                    }
                }
                Method::Ack => log.push("ACK"),
                Method::Bye => {
                    log.push("BYE");
                    let ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(ok)), src)
                        .await;
                    break;
                }
                _ => {}
            },
            SipMessage::Response(resp) => {
                // 200 for our reliable 180 arrives as a PRACK response —
                // nothing to do; the PRACK request itself is the signal.
                let _ = resp;
            }
        }
    }
}

/// Leg B fake UAS that rejects the first INVITE with 421 Extension Required
/// (RFC 3262 §3) and answers the second normally.
async fn run_421_uas(sock: UdpSocket, rtp_port: u16, log: Log) {
    let mut buf = vec![0u8; 65_535];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut first = true;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, src))) = recv else { break };
        let Ok(msg) = parse_message(&buf[..n]) else {
            continue;
        };
        let SipMessage::Request(req) = msg else {
            continue;
        };
        match req.method {
            Method::Invite => {
                let supported = req.headers.get("Supported").unwrap_or("").to_string();
                let cseq = req.headers.cseq().map(|c| c.seq).unwrap_or(0);
                log.push(format!("INVITE cseq={cseq} supported={supported}"));
                if first {
                    first = false;
                    let mut resp = sip_core::builder::respond_to(
                        &req,
                        421,
                        "Extension Required",
                        Vec::new(),
                        None,
                    );
                    resp.headers.add("Require", "100rel");
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(resp)), src)
                        .await;
                    continue;
                }
                let trying = sip_core::builder::respond_to(&req, 100, "Trying", Vec::new(), None);
                let _ = sock
                    .send_to(&serialize(&SipMessage::Response(trying)), src)
                    .await;
                let mut ok = sip_core::builder::respond_to(
                    &req,
                    200,
                    "OK",
                    answer_sdp(rtp_port).into_bytes(),
                    Some("tagB"),
                );
                ok.headers.add("Contact", "<sip:uas@127.0.0.1>");
                let _ = sock
                    .send_to(&serialize(&SipMessage::Response(ok)), src)
                    .await;
            }
            Method::Ack => log.push("ACK"),
            Method::Bye => {
                log.push("BYE");
                let ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                let _ = sock
                    .send_to(&serialize(&SipMessage::Response(ok)), src)
                    .await;
                break;
            }
            _ => {}
        }
    }
}

async fn recv_on(sock: &UdpSocket, buf: &mut [u8], secs: u64) -> Option<SipMessage> {
    match timeout(Duration::from_secs(secs), sock.recv_from(buf)).await {
        Ok(Ok((n, _))) => parse_message(&buf[..n]).ok(),
        _ => None,
    }
}

fn as_response(msg: &SipMessage) -> Option<&Response> {
    match msg {
        SipMessage::Response(r) => Some(r),
        _ => None,
    }
}

fn to_tag_of(resp: &Response) -> String {
    resp.headers
        .get("To")
        .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
        .and_then(|n| n.tag)
        .unwrap_or_default()
}

fn rseq_of(resp: &Response) -> Option<u32> {
    resp.headers.rseq()
}

/// Caller INVITE with or without `Supported: 100rel`.
async fn send_invite(
    a: &UdpSocket,
    a_addr: SocketAddr,
    engine: SocketAddr,
    rel100: bool,
    call_id: &str,
) {
    let mut b = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&format!("sip:1000@{engine}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), Some("z9hG4bKr1"))
    .from("<sip:caller@dev>;tag=tagA")
    .to("<sip:1000@dev>")
    .call_id(Some(call_id))
    .cseq(1)
    .contact(&format!("<sip:caller@{a_addr}>"))
    .body("application/sdp", offer_sdp(49210).into_bytes());
    if rel100 {
        b = b.header("Supported", "100rel");
    }
    a.send_to(&serialize(&SipMessage::Request(b.build())), engine)
        .await
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
async fn send_prack(
    a: &UdpSocket,
    a_addr: SocketAddr,
    engine: SocketAddr,
    call_id: &str,
    to_tag: &str,
    rack: &str,
    cseq: u32,
    body: bool,
) {
    let mut b = RequestBuilder::new(
        Method::Prack,
        SipUri::parse(&format!("sip:1000@{engine}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), Some("z9hG4bKr2"))
    .from("<sip:caller@dev>;tag=tagA")
    .to(&format!("<sip:1000@dev>;tag={to_tag}"))
    .call_id(Some(call_id))
    .cseq(cseq)
    .header("RAck", rack);
    if body {
        b = b.body("application/sdp", offer_sdp(49211).into_bytes());
    }
    a.send_to(&serialize(&SipMessage::Request(b.build())), engine)
        .await
        .unwrap();
}

async fn send_ack(
    a: &UdpSocket,
    a_addr: SocketAddr,
    engine: SocketAddr,
    call_id: &str,
    to_tag: &str,
    cseq: u32,
) {
    let ack = RequestBuilder::new(
        Method::Ack,
        SipUri::parse(&format!("sip:1000@{engine}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), Some("z9hG4bKr3"))
    .from("<sip:caller@dev>;tag=tagA")
    .to(&format!("<sip:1000@dev>;tag={to_tag}"))
    .call_id(Some(call_id))
    .cseq(cseq)
    .build();
    a.send_to(&serialize(&SipMessage::Request(ack)), engine)
        .await
        .unwrap();
}

/// Reads messages until the 200 OK to the INVITE (CSeq method INVITE),
/// answering nothing on the way; returns it.
async fn await_invite_200(a: &UdpSocket, buf: &mut [u8]) -> Response {
    for _ in 0..10 {
        let Some(msg) = recv_on(a, buf, 5).await else {
            break;
        };
        if let Some(r) = as_response(&msg) {
            if r.code == 200 && r.headers.cseq().map(|c| c.method) == Some(Method::Invite) {
                return r.clone();
            }
        }
    }
    panic!("no 200 OK to the INVITE");
}

fn init_log(filter: &str) {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .try_init();
}

// ---- tests ------------------------------------------------------------------

/// Caller supports 100rel: the 180 is reliable (Require + RSeq + To tag) and
/// the 200 to the INVITE is parked until the PRACK (RFC 3262 §3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reliable_180_and_answer_waits_for_prack() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(uas).await;
    let uas_task = tokio::spawn(run_plain_uas(uas_sock, 49220, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, true, "rl-1").await;

    // The reliable 180.
    let mut ring = None;
    for _ in 0..6 {
        let Some(msg) = recv_on(&a, &mut buf, 4).await else {
            break;
        };
        if let Some(r) = as_response(&msg) {
            if r.code == 180 {
                ring = Some(r.clone());
                break;
            }
        }
    }
    let ring = ring.expect("no 180 received");
    assert_eq!(
        ring.headers.get("Require"),
        Some("100rel"),
        "180 must be reliable"
    );
    let rseq = rseq_of(&ring).expect("180 must carry RSeq");
    assert!(
        (1..=i32::MAX as u32).contains(&rseq),
        "RSeq must start in [1, 2^31-1] (RFC 3262 §3): {rseq}"
    );
    let to_tag = to_tag_of(&ring);
    assert!(
        !to_tag.is_empty(),
        "reliable 1xx must carry a To tag (early dialog)"
    );

    // RFC 3262 §3: no final while the reliable 1xx is unacknowledged. The
    // leg B UAS answers instantly, so without the hold the 200 would already
    // be here. Tolerate only 180 retransmissions in this window.
    let deadline = Instant::now() + Duration::from_millis(1100);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "200 arrived before the PRACK (§3 violated)"
        );
        match timeout(remaining, a.recv_from(&mut buf)).await {
            Err(_) => break, // quiet window: no 200 was sent
            Ok(Ok((n, _))) => {
                if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                    assert_ne!(r.code, 200, "200 must not precede the PRACK (RFC 3262 §3)");
                    assert_eq!(r.code, 180, "only 180 retransmissions expected");
                }
            }
            Ok(Err(e)) => panic!("recv error: {e}"),
        }
    }

    // PRACK with the matching RAck; CSeq 2 (PRACK owns its own CSeq space
    // increment in the dialog).
    send_prack(
        &a,
        a_addr,
        engine,
        "rl-1",
        &to_tag,
        &format!("{rseq} 1 INVITE"),
        2,
        false,
    )
    .await;

    // 200 for the PRACK, then the parked 200 for the INVITE.
    let mut prack_ok = false;
    let invite_200 = loop {
        let msg = recv_on(&a, &mut buf, 5)
            .await
            .expect("no response after PRACK");
        let Some(r) = as_response(&msg) else { continue };
        match (r.code, r.headers.cseq().map(|c| c.method)) {
            (200, Some(Method::Prack)) => {
                prack_ok = true;
            }
            (200, Some(Method::Invite)) => break r.clone(),
            _ => {}
        }
    };
    assert!(prack_ok, "PRACK must be answered 200");
    assert!(
        !invite_200.body.is_empty(),
        "the INVITE 200 carries the negotiated answer"
    );
    send_ack(&a, a_addr, engine, "rl-1", &to_tag_of(&invite_200), 1).await;
    let _ = timeout(Duration::from_secs(6), uas_task).await;
    assert!(
        log.contains("INVITE"),
        "leg B must have been dialed: {:?}",
        log.snapshot()
    );
}

/// No PRACK: the reliable 180 is retransmitted with Timer-G-style backoff
/// (same RSeq, same bytes) — at least twice within ~1.9 s (§5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retransmits_reliable_180_until_prack() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(uas).await;
    let uas_task = tokio::spawn(run_plain_uas(uas_sock, 49222, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, true, "rl-2").await;

    let first = loop {
        let msg = recv_on(&a, &mut buf, 4).await.expect("no 180");
        if let Some(r) = as_response(&msg) {
            if r.code == 180 {
                break r.clone();
            }
        }
    };
    let rseq = rseq_of(&first).expect("RSeq on reliable 180");

    // Collect copies for ~1.9 s: retransmissions land at ~+0.5 s and ~+1.5 s.
    let mut copies = 1;
    let deadline = Instant::now() + Duration::from_millis(1900);
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match timeout(remaining, a.recv_from(&mut buf)).await {
            Err(_) => break,
            Ok(Ok((n, _))) => {
                if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                    if r.code == 180 && rseq_of(&r) == Some(rseq) {
                        copies += 1;
                    }
                }
            }
            Ok(Err(e)) => panic!("recv error: {e}"),
        }
    }
    assert!(
        copies >= 3,
        "expected the original plus >=2 retransmissions with the same RSeq, got {copies}"
    );

    // A late PRACK still completes the call.
    let to_tag = to_tag_of(&first);
    send_prack(
        &a,
        a_addr,
        engine,
        "rl-2",
        &to_tag,
        &format!("{rseq} 1 INVITE"),
        2,
        false,
    )
    .await;
    let _ = await_invite_200(&a, &mut buf).await;
    let _ = timeout(Duration::from_secs(6), uas_task).await;
}

/// A PRACK whose RAck does not match the outstanding RSeq gets 481; a PRACK
/// carrying an offer gets 488 (renegotiation unsupported); the correct PRACK
/// then completes the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prack_verdicts_wrong_rack_offer_then_correct() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(uas).await;
    let uas_task = tokio::spawn(run_plain_uas(uas_sock, 49224, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, true, "rl-3").await;
    let ring = loop {
        let msg = recv_on(&a, &mut buf, 4).await.expect("no 180");
        if let Some(r) = as_response(&msg) {
            if r.code == 180 {
                break r.clone();
            }
        }
    };
    let rseq = rseq_of(&ring).expect("RSeq");
    let to_tag = to_tag_of(&ring);

    // Wrong RSeq → 481 (RFC 3262 §4).
    send_prack(
        &a,
        a_addr,
        engine,
        "rl-3",
        &to_tag,
        &format!("{} 1 INVITE", rseq.wrapping_add(1)),
        2,
        false,
    )
    .await;
    let mut got_481 = false;
    for _ in 0..4 {
        let Some(msg) = recv_on(&a, &mut buf, 3).await else {
            break;
        };
        if let Some(r) = as_response(&msg) {
            if r.code == 481 && r.headers.cseq().map(|c| c.method) == Some(Method::Prack) {
                got_481 = true;
                break;
            }
        }
    }
    assert!(got_481, "PRACK with a wrong RAck must get 481");

    // PRACK with an SDP offer → 488 (early renegotiation unsupported).
    send_prack(
        &a,
        a_addr,
        engine,
        "rl-3",
        &to_tag,
        &format!("{rseq} 1 INVITE"),
        3,
        true,
    )
    .await;
    let mut got_488 = false;
    for _ in 0..4 {
        let Some(msg) = recv_on(&a, &mut buf, 3).await else {
            break;
        };
        if let Some(r) = as_response(&msg) {
            if r.code == 488 && r.headers.cseq().map(|c| c.method) == Some(Method::Prack) {
                got_488 = true;
                break;
            }
        }
    }
    assert!(got_488, "PRACK with an offer must get 488");

    // The correct, bodyless PRACK → 200 and the parked INVITE 200.
    send_prack(
        &a,
        a_addr,
        engine,
        "rl-3",
        &to_tag,
        &format!("{rseq} 1 INVITE"),
        4,
        false,
    )
    .await;
    let invite_200 = await_invite_200(&a, &mut buf).await;
    send_ack(&a, a_addr, engine, "rl-3", &to_tag_of(&invite_200), 1).await;
    let _ = timeout(Duration::from_secs(6), uas_task).await;
}

/// Caller without 100rel: plain 180 (no RSeq, no Require: 100rel); an
/// unsolicited PRACK gets 481 and the call completes normally without any
/// parked final.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_180_without_support_and_unsolicited_prack() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(uas).await;
    let uas_task = tokio::spawn(run_plain_uas(uas_sock, 49226, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, false, "rl-4").await;
    let mut ring = None;
    for _ in 0..6 {
        let Some(msg) = recv_on(&a, &mut buf, 4).await else {
            break;
        };
        if let Some(r) = as_response(&msg) {
            if r.code == 180 {
                ring = Some(r.clone());
                break;
            }
        }
    }
    let ring = ring.expect("no 180");
    assert_eq!(
        rseq_of(&ring),
        None,
        "180 must be unreliable without 100rel"
    );
    assert_ne!(ring.headers.get("Require"), Some("100rel"));

    // Unsolicited PRACK → 481. The 200 to the INVITE is NOT parked here
    // (plain 180), so it may race in ahead of the 481 — capture it too.
    let to_tag = to_tag_of(&ring);
    send_prack(
        &a,
        a_addr,
        engine,
        "rl-4",
        &to_tag,
        "999 1 INVITE",
        2,
        false,
    )
    .await;
    let mut got_481 = false;
    let mut early_invite_200: Option<Response> = None;
    for _ in 0..4 {
        let Some(msg) = recv_on(&a, &mut buf, 3).await else {
            break;
        };
        if let Some(r) = as_response(&msg) {
            match (r.code, r.headers.cseq().map(|c| c.method)) {
                (481, Some(Method::Prack)) => {
                    got_481 = true;
                    break;
                }
                (200, Some(Method::Invite)) => early_invite_200 = Some(r.clone()),
                _ => {}
            }
        }
    }
    assert!(got_481, "unsolicited PRACK must get 481");

    // The call completes normally: no parked final here.
    let invite_200 = match early_invite_200 {
        Some(r) => r,
        None => await_invite_200(&a, &mut buf).await,
    };
    send_ack(&a, a_addr, engine, "rl-4", &to_tag_of(&invite_200), 1).await;
    let _ = timeout(Duration::from_secs(6), uas_task).await;
    assert!(
        log.contains("ACK"),
        "call must be fully established: {:?}",
        log.snapshot()
    );
}

/// Both legs speak 100rel end-to-end: the fake UAS's reliable 180 (RSeq 77)
/// is PRACKed by the engine — twice, because the UAS retransmits the 180 —
/// while the engine's own reliable 180 towards the caller is PRACKed too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pracks_leg_b_reliable_180_including_retransmission() {
    init_log("debug,b2bua=trace");
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(uas).await;
    let uas_task = tokio::spawn(run_rel100_uas(uas_sock, 49228, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, true, "rl-5").await;

    // Engine's reliable 180 towards us: PRACK it.
    let ring = loop {
        let msg = recv_on(&a, &mut buf, 5).await.expect("no 180 from engine");
        if let Some(r) = as_response(&msg) {
            if r.code == 180 {
                break r.clone();
            }
        }
    };
    let rseq = rseq_of(&ring).expect("engine 180 must be reliable");
    send_prack(
        &a,
        a_addr,
        engine,
        "rl-5",
        &to_tag_of(&ring),
        &format!("{rseq} 1 INVITE"),
        2,
        false,
    )
    .await;
    let invite_200 = await_invite_200(&a, &mut buf).await;
    send_ack(&a, a_addr, engine, "rl-5", &to_tag_of(&invite_200), 1).await;

    let _ = timeout(Duration::from_secs(10), uas_task).await;

    // The engine PRACKed the fake UAS twice (original + retransmitted 180),
    // both with RAck "77 1 INVITE".
    let events = log.snapshot();
    let prack_count = events.iter().filter(|e| e.contains("PRACK")).count();
    assert_eq!(
        prack_count, 2,
        "engine must PRACK the reliable 180 and its retransmission: {events:?}"
    );
    assert!(
        events
            .iter()
            .all(|e| !e.contains("PRACK") || e.contains("rack=77 1 INVITE")),
        "every PRACK must carry RAck for RSeq 77 / INVITE CSeq 1: {events:?}"
    );
    assert!(log.contains("ACK"), "leg B must be confirmed: {events:?}");
}

/// The leg B UAS answers the dial with 421 Extension Required: the engine
/// retries once with `Supported: 100rel` and the call completes (RFC 3262
/// §3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_leg_b_after_421() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(uas).await;
    let uas_task = tokio::spawn(run_421_uas(uas_sock, 49230, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, false, "rl-6").await;
    let invite_200 = await_invite_200(&a, &mut buf).await;
    send_ack(&a, a_addr, engine, "rl-6", &to_tag_of(&invite_200), 1).await;
    let _ = timeout(Duration::from_secs(10), uas_task).await;

    let events = log.snapshot();
    assert!(
        events.iter().any(|e| e.contains("INVITE cseq=1")),
        "first dial attempt must be recorded: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.contains("INVITE cseq=2") && e.contains("supported=100rel")),
        "retry must carry Supported: 100rel: {events:?}"
    );
    assert!(log.contains("ACK"), "retry must be confirmed: {events:?}");
}
