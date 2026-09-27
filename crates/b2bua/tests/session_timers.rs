//! RFC 4028 session-timer integration tests over a live B2BUA engine:
//! negotiation on the 200, the `Min-SE`/422 floor, half-interval refresh
//! re-INVITEs, UPDATE refreshes and expiry teardown with BYEs on both legs.

use b2bua::{B2bua, B2buaConfig};
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, Response, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

// ---- shared fixtures --------------------------------------------------------

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
         s=session-timer-test\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0 8 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
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

/// Starts the engine with the given `Min-SE` floor, targeting `uas`.
async fn spawn_engine(min_se: u64, uas: SocketAddr) -> SocketAddr {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let cfg = B2buaConfig {
        sip_bind: "127.0.0.1:0".parse().unwrap(),
        media_host: "127.0.0.1".into(),
        media_base_port: 0,
        codecs: vec![codecs::CodecId::Pcmu, codecs::CodecId::Pcma],
        routes: Vec::new(),
        default_target: format!("sip:1000@{uas}"),
        session_timer_min_se: min_se,
    };
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = B2bua::new(cfg, tx).run_on(Arc::new(sock)).await;
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    addr
}

/// Leg B fake UAS: answers INVITEs with 200 (echoing Session-Expires, as a
/// RFC 4028 UAS must), ACKs are recorded, BYE ends the task. When
/// `first_reject` is set, the FIRST INVITE is answered with that code plus a
/// `Min-SE` header (422 path) instead.
async fn run_uas(sock: UdpSocket, rtp_port: u16, first_reject: Option<(u16, u64)>, log: Log) {
    let mut buf = vec![0u8; 65_535];
    let mut first = true;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
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
                let se = req
                    .headers
                    .get("Session-Expires")
                    .unwrap_or("-")
                    .to_string();
                let cseq = req.headers.cseq().map(|c| c.seq).unwrap_or(0);
                log.push(format!("INVITE cseq={cseq} se={se}"));
                if first {
                    first = false;
                    if let Some((code, min_se)) = first_reject {
                        let mut resp = sip_core::builder::respond_to(
                            &req,
                            code,
                            "Session Interval Too Small",
                            Vec::new(),
                            None,
                        );
                        resp.headers.add("Min-SE", min_se.to_string());
                        resp.headers.add("Supported", "timer");
                        let _ = sock
                            .send_to(&serialize(&SipMessage::Response(resp)), src)
                            .await;
                        continue;
                    }
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
                if let Some(se) = req.headers.get("Session-Expires") {
                    ok.headers.add("Session-Expires", se.to_string());
                    ok.headers.add("Supported", "timer");
                }
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

async fn send_invite(
    a: &UdpSocket,
    a_addr: SocketAddr,
    engine: SocketAddr,
    session_expires: Option<&str>,
    call_id: &str,
) {
    let mut b = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&format!("sip:1000@{engine}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), Some("z9hG4bKt1"))
    .from("<sip:caller@dev>;tag=tagA")
    .to("<sip:1000@dev>")
    .call_id(Some(call_id))
    .cseq(1)
    .contact(&format!("<sip:caller@{a_addr}>"))
    .header("Supported", "timer")
    .body("application/sdp", offer_sdp(49180).into_bytes());
    if let Some(se) = session_expires {
        b = b.header("Session-Expires", se);
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
    .via(TransportKind::Udp, &a_addr.to_string(), Some("z9hG4bKa"))
    .from("<sip:caller@dev>;tag=tagA")
    .to(&format!("<sip:1000@dev>;tag={to_tag}"))
    .call_id(Some(call_id))
    .cseq(cseq)
    .build();
    a.send_to(&serialize(&SipMessage::Request(ack)), engine)
        .await
        .unwrap();
}

fn to_tag_of(resp: &Response) -> String {
    resp.headers
        .get("To")
        .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
        .and_then(|n| n.tag)
        .unwrap_or_default()
}

/// Reads UAC messages until the 200 OK of the initial INVITE.
async fn await_200(a: &UdpSocket, buf: &mut [u8]) -> Response {
    for _ in 0..8 {
        let Some(msg) = recv_on(a, buf, 5).await else {
            break;
        };
        if let Some(r) = as_response(&msg) {
            if r.code == 200 {
                return r.clone();
            }
        }
    }
    panic!("no 200 OK from B2BUA");
}

// ---- tests ------------------------------------------------------------------

/// Tests that attach a tracing subscriber see engine logs under --nocapture.
fn init_log(filter: &str) {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .try_init();
}

/// Peer requests `SE=2;refresher=uac` (they refresh leg A) and never does:
/// the B2BUA must mirror the negotiation on the 200, refresh leg B itself at
/// half-interval, and BYE both legs at expiry (§10).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engages_refreshes_downstream_and_expires() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(1, uas).await;
    let uas_task = tokio::spawn(run_uas(uas_sock, 49200, None, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, Some("2;refresher=uac"), "st-1").await;
    let ok200 = await_200(&a, &mut buf).await;
    assert_eq!(
        ok200.headers.get("Session-Expires"),
        Some("2;refresher=uac"),
        "200 must mirror the negotiated interval and refresher"
    );
    assert!(ok200
        .headers
        .get("Supported")
        .unwrap_or_default()
        .contains("timer"));
    send_ack(&a, a_addr, engine, "st-1", &to_tag_of(&ok200), 1).await;

    // We never refresh leg A. At anchor+2s the engine must BYE us.
    let mut got_bye = false;
    for _ in 0..10 {
        let Some(msg) = recv_on(&a, &mut buf, 4).await else {
            break;
        };
        match msg {
            SipMessage::Request(r) if r.method == Method::Bye => {
                got_bye = true;
                let ok = sip_core::builder::respond_to(&r, 200, "OK", Vec::new(), None);
                a.send_to(&serialize(&SipMessage::Response(ok)), engine)
                    .await
                    .unwrap();
                break;
            }
            SipMessage::Request(r) if r.method == Method::Invite => {
                // Unexpected re-INVITE towards the refreshee: answer anyway.
                let ok = sip_core::builder::respond_to(
                    &r,
                    200,
                    "OK",
                    answer_sdp(49181).into_bytes(),
                    None,
                );
                a.send_to(&serialize(&SipMessage::Response(ok)), engine)
                    .await
                    .unwrap();
            }
            _ => {}
        }
    }
    assert!(got_bye, "engine must BYE the expired leg A");
    let _ = timeout(Duration::from_secs(6), uas_task).await;

    // Leg B carried the mirrored negotiation and was refreshed downstream.
    let events = log.snapshot();
    assert!(
        events
            .iter()
            .any(|e| e.contains("INVITE cseq=1") && e.contains("se=2;refresher=uac")),
        "leg B INVITE must mirror the session timer: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("INVITE cseq=2")),
        "engine must refresh leg B at half-interval: {events:?}"
    );
    assert!(
        log.contains("BYE"),
        "engine must BYE leg B at expiry: {events:?}"
    );
}

/// `SE=4;refresher=uas`: the B2BUA is the leg-A refresher and must send a
/// no-change re-INVITE (original offer, next CSeq) at half-interval, and must
/// NOT tear the session down while refreshes succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn we_refresh_leg_a_when_elected() {
    init_log("debug,b2bua=trace");
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(1, uas).await;
    let _uas_task = tokio::spawn(run_uas(uas_sock, 49202, None, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, Some("4;refresher=uas"), "st-2").await;
    let ok200 = await_200(&a, &mut buf).await;
    assert_eq!(
        ok200.headers.get("Session-Expires"),
        Some("4;refresher=uas"),
        "we elected ourselves refresher on leg A"
    );
    send_ack(&a, a_addr, engine, "st-2", &to_tag_of(&ok200), 1).await;

    // Half-interval refresh arrives as a re-INVITE carrying the original
    // offer; answer it and keep answering anything else except BYE.
    let mut first_reinvite_cseq = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        // Timeouts are fine — keep waiting until the overall deadline.
        let Some(msg) = recv_on(&a, &mut buf, 1).await else {
            continue;
        };
        match msg {
            SipMessage::Request(r) if r.method == Method::Invite => {
                let cseq = r.headers.cseq().map(|c| c.seq).unwrap_or(0);
                assert!(
                    !r.body.is_empty(),
                    "refresh re-INVITE must carry the unchanged offer"
                );
                if first_reinvite_cseq.is_none() {
                    first_reinvite_cseq = Some(cseq);
                }
                let ok = sip_core::builder::respond_to(
                    &r,
                    200,
                    "OK",
                    answer_sdp(49182).into_bytes(),
                    None,
                );
                a.send_to(&serialize(&SipMessage::Response(ok)), engine)
                    .await
                    .unwrap();
            }
            SipMessage::Request(r) if r.method == Method::Ack => {}
            SipMessage::Request(r) if r.method == Method::Bye => {
                panic!("no BYE expected while we are the refresher: {r:?}")
            }
            _ => {}
        }
    }
    assert_eq!(
        first_reinvite_cseq,
        Some(2),
        "leg-A refresh must be the next CSeq in our UAS space"
    );
    assert!(
        log.contains("INVITE cseq=2"),
        "leg B must be refreshed downstream as well: {:?}",
        log.snapshot()
    );
}

/// Interval below the configured Min-SE floor: 422 carrying Min-SE, and no
/// call may be originated downstream (§5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_interval_below_min_se() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(90, uas).await;
    let _uas_task = tokio::spawn(run_uas(uas_sock, 49204, None, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, Some("2;refresher=uac"), "st-3").await;
    let msg = recv_on(&a, &mut buf, 4).await.expect("no response at all");
    let resp = as_response(&msg).expect("expected a response");
    assert_eq!(resp.code, 422, "too-small interval must get 422");
    assert_eq!(resp.headers.get("Min-SE"), Some("90"));
    assert!(
        resp.headers.get("To").unwrap_or_default().contains("tag="),
        "422 for an INVITE still carries a To tag"
    );

    // Nothing may be dialed downstream.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !log.contains("INVITE"),
        "422 must not originate leg B: {:?}",
        log.snapshot()
    );
}

/// Leg B answers the dial with `422 Min-SE: 5`: the B2BUA must retry the
/// INVITE with the raised interval (§7) and complete the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_leg_b_after_422() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(1, uas).await;
    let uas_task = tokio::spawn(run_uas(uas_sock, 49206, Some((422, 5)), log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, Some("2;refresher=uac"), "st-4").await;
    let ok200 = await_200(&a, &mut buf).await;
    assert_eq!(
        ok200.headers.get("Session-Expires"),
        Some("2;refresher=uac"),
        "leg A negotiation is untouched by the leg B retry"
    );
    let _ = timeout(Duration::from_secs(6), uas_task).await;

    let events = log.snapshot();
    assert!(
        events.iter().any(|e| e.contains("INVITE cseq=1")),
        "first dial attempt must be recorded: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.contains("INVITE cseq=2") && e.contains("se=5;refresher=uac")),
        "retry must raise the interval to the peer's Min-SE: {events:?}"
    );
    assert!(log.contains("ACK"), "retry must be confirmed: {events:?}");
}

/// A bodyless in-dialog UPDATE refreshes the session (§7.3): the expiry that
/// would have fired at anchor+2s is pushed out and the leg only dies one full
/// interval after the UPDATE.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_refreshes_the_session() {
    let log = Log::default();
    let uas_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas = uas_sock.local_addr().unwrap();
    let engine = spawn_engine(1, uas).await;
    let uas_task = tokio::spawn(run_uas(uas_sock, 49208, None, log.clone()));

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    send_invite(&a, a_addr, engine, Some("2;refresher=uac"), "st-5").await;
    let ok200 = await_200(&a, &mut buf).await;
    let tag = to_tag_of(&ok200);
    send_ack(&a, a_addr, engine, "st-5", &tag, 1).await;

    // Refresh via UPDATE well before the 2 s expiry.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let update = RequestBuilder::new(
        Method::Update,
        SipUri::parse(&format!("sip:1000@{engine}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), Some("z9hG4bKu1"))
    .from("<sip:caller@dev>;tag=tagA")
    .to(&format!("<sip:1000@dev>;tag={tag}"))
    .call_id(Some("st-5"))
    .cseq(2)
    .build();
    a.send_to(&serialize(&SipMessage::Request(update)), engine)
        .await
        .unwrap();
    let mut got_update200 = false;
    for _ in 0..4 {
        let Some(msg) = recv_on(&a, &mut buf, 3).await else {
            break;
        };
        if let Some(r) = as_response(&msg) {
            if r.code == 200 {
                got_update200 = true;
                break;
            }
        }
    }
    assert!(got_update200, "UPDATE must be answered 200");

    // Without the UPDATE the leg would have expired at ~anchor+2s; it must
    // still be alive now (anchor moved to the UPDATE).
    tokio::time::sleep(Duration::from_millis(1700)).await;
    match timeout(Duration::from_millis(300), a.recv_from(&mut buf)).await {
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok((n, _))) => {
            let parsed = parse_message(&buf[..n]);
            if let Ok(SipMessage::Request(r)) = parsed {
                assert!(
                    r.method != Method::Bye,
                    "UPDATE must have re-anchored the session clock"
                );
            }
        }
    }
    // The leg dies exactly one interval after the UPDATE.
    let mut got_bye = false;
    for _ in 0..8 {
        let Some(msg) = recv_on(&a, &mut buf, 4).await else {
            break;
        };
        if let SipMessage::Request(r) = msg {
            if r.method == Method::Bye {
                got_bye = true;
                break;
            }
        }
    }
    assert!(
        got_bye,
        "session must still expire without further refreshes"
    );
    let _ = timeout(Duration::from_secs(6), uas_task).await;
}
