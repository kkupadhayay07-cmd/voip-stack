//! RFC 3261 §12 dialog-layer integration test (extracted `dialog` crate
//! live in the engine):
//! 1. in-dialog re-INVITE with a HIGHER CSeq → 200 (state adopted),
//! 2. re-INVITE with a LOWER CSeq → 500 Server Internal Error (§12.2.2 —
//!    out-of-order in-dialog requests are rejected),
//! 3. re-INVITE with an EQUAL CSeq → 200 (retransmission, answered
//!    idempotently — NOT 500),
//! 4. UPDATE below the high-water mark → 500, above it → 200,
//! 5. the dialog survives all of it and BYE + CDR trail complete.

use b2bua::{B2bua, B2buaConfig, CdrEvent};
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;

fn a_offer_sdp(port: u16) -> String {
    format!(
        "v=0\r\n\
         o=caller 1 1 IN IP4 127.0.0.1\r\n\
         s=dialog-test\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0 8 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=sendrecv\r\n"
    )
}

fn b_answer_sdp(port: u16) -> String {
    format!(
        "v=0\r\n\
         o=uas 2 2 IN IP4 127.0.0.1\r\n\
         s=leg-b\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 8 101\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=sendrecv\r\n"
    )
}

async fn recv_msg(sock: &UdpSocket, buf: &mut [u8]) -> Option<(SipMessage, SocketAddr)> {
    match timeout(Duration::from_secs(8), sock.recv_from(buf)).await {
        Ok(Ok((n, src))) => parse_message(&buf[..n]).ok().map(|m| (m, src)),
        _ => None,
    }
}

fn as_response(msg: &SipMessage) -> Option<&sip_core::message::Response> {
    match msg {
        SipMessage::Response(r) => Some(r),
        _ => None,
    }
}

/// Leg B: minimal UAS — answers the dial, ACKs, and answers the relayed BYE.
async fn run_leg_b(sock: UdpSocket, rtp_port: u16) -> u8 {
    let rtp = UdpSocket::bind(("127.0.0.1", rtp_port)).await.unwrap();
    let _ = rtp; // media is not exercised in this signaling test
    let mut buf = vec![0u8; 65_535];
    let mut flags = 0u8; // bit0 = ACK, bit1 = BYE
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        if flags == 0b11 || tokio::time::Instant::now() >= deadline {
            break;
        }
        let r = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, src))) = r else { break };
        let Ok(msg) = parse_message(&buf[..n]) else {
            continue;
        };
        if let SipMessage::Request(req) = msg {
            match req.method {
                Method::Invite => {
                    let ok = sip_core::builder::respond_to(
                        &req,
                        200,
                        "OK",
                        b_answer_sdp(rtp_port).into_bytes(),
                        Some("tagB"),
                    );
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(ok)), src)
                        .await;
                }
                Method::Ack => flags |= 1,
                Method::Bye => {
                    let ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(ok)), src)
                        .await;
                    flags |= 2;
                }
                _ => {}
            }
        }
    }
    flags
}

async fn drain_cdr(rx: &mut UnboundedReceiver<CdrEvent>) -> Vec<CdrEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

fn to_tag_of(resp: &sip_core::message::Response) -> String {
    resp.headers
        .get("To")
        .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
        .and_then(|n| n.tag)
        .unwrap_or_default()
}

/// Sends an in-dialog request and collects the final (non-1xx) response.
async fn in_dialog(
    a: &UdpSocket,
    engine: SocketAddr,
    method: Method,
    cseq: u32,
    to_tagged_to: &str,
    body: Option<(&str, Vec<u8>)>,
) -> Option<sip_core::message::Response> {
    let a_addr = a.local_addr().unwrap();
    let uri = SipUri::parse(&format!("sip:1000@{engine}")).unwrap();
    let mut builder = RequestBuilder::new(method, uri)
        .via(TransportKind::Udp, &a_addr.to_string(), None)
        .from("<sip:caller@dev>;tag=tagA")
        .to(to_tagged_to)
        .call_id(Some("dialog-cseq-1"))
        .cseq(cseq)
        .contact(&format!("<sip:caller@{a_addr}>"));
    if let Some((ctype, bytes)) = body {
        builder = builder.body(ctype, bytes);
    }
    let req = builder.build();
    a.send_to(&serialize(&SipMessage::Request(req)), engine)
        .await
        .unwrap();
    let mut buf = vec![0u8; 65_535];
    for _ in 0..4 {
        let Some((msg, _)) = recv_msg(a, &mut buf).await else {
            break;
        };
        if let Some(resp) = as_response(&msg) {
            if resp.code >= 200 {
                return Some(resp.clone());
            }
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dialog_cseq_ordering_and_target() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,b2bua=debug".into()),
        ))
        .try_init();

    let (tx, mut cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let b_sip = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_sip_addr = b_sip.local_addr().unwrap();
    let b_rtp_port = {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };
    let engine_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = engine_sock.local_addr().unwrap();
    let cfg = B2buaConfig {
        sip_bind: engine,
        media_host: "127.0.0.1".into(),
        media_base_port: 0,
        codecs: vec![codecs::CodecId::Pcmu, codecs::CodecId::Pcma],
        routes: Vec::new(),
        default_target: format!("sip:1000@{b_sip_addr}"),
        session_timer_min_se: b2bua::timers::DEFAULT_MIN_SE,
    };
    tokio::spawn(async move {
        let _ = B2bua::new(cfg, tx)
            .run_on(std::sync::Arc::new(engine_sock))
            .await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let b_task = tokio::spawn(run_leg_b(b_sip, b_rtp_port));

    // ---- leg A: initial INVITE CSeq 1 → 200 → ACK ----
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let invite = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&format!("sip:1000@{engine}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to("<sip:1000@dev>")
    .call_id(Some("dialog-cseq-1"))
    .cseq(1)
    .contact(&format!("<sip:caller@{a_addr}>"))
    .body("application/sdp", a_offer_sdp(49180).into_bytes())
    .build();
    a.send_to(&serialize(&SipMessage::Request(invite)), engine)
        .await
        .unwrap();
    let mut buf = vec![0u8; 65_535];
    let mut ok200 = None;
    for _ in 0..6 {
        let Some((msg, _)) = recv_msg(&a, &mut buf).await else {
            break;
        };
        if let Some(resp) = as_response(&msg) {
            if resp.code == 200 {
                ok200 = Some(resp.clone());
                break;
            }
        }
    }
    let ok200 = ok200.expect("no 200 OK for the initial INVITE");
    let to_tagged = format!("<sip:1000@dev>;tag={}", to_tag_of(&ok200));
    let ack = RequestBuilder::new(
        Method::Ack,
        SipUri::parse(&format!("sip:1000@{engine}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to(&to_tagged)
    .call_id(Some("dialog-cseq-1"))
    .cseq(1)
    .build();
    a.send_to(&serialize(&SipMessage::Request(ack)), engine)
        .await
        .unwrap();

    // ---- re-INVITE CSeq 5 (no body = refresh): New → 200, state adopted ----
    let resp = in_dialog(&a, engine, Method::Invite, 5, &to_tagged, None)
        .await
        .expect("no response to the first re-INVITE");
    assert_eq!(
        resp.code, 200,
        "higher CSeq re-INVITE must be a 200 refresh"
    );
    assert!(
        !resp.body.is_empty(),
        "refresh answer carries the cached SDP"
    );

    // ---- re-INVITE CSeq 4 (LOWER): out of order → 500 (§12.2.2) ----
    let resp = in_dialog(&a, engine, Method::Invite, 4, &to_tagged, None)
        .await
        .expect("no response to the out-of-order re-INVITE");
    assert_eq!(
        resp.code, 500,
        "a CSeq BELOW the high-water mark must be rejected 500"
    );
    assert_eq!(resp.reason, "Server Internal Error");

    // ---- re-INVITE CSeq 5 (EQUAL): retransmission → idempotent 200 ----
    let resp = in_dialog(&a, engine, Method::Invite, 5, &to_tagged, None)
        .await
        .expect("no response to the retransmitted re-INVITE");
    assert_eq!(resp.code, 200, "an EQUAL CSeq is a retransmission, not 500");

    // ---- UPDATE CSeq 2: out of order → 500; CSeq 6: New → 200 ----
    let resp = in_dialog(&a, engine, Method::Update, 2, &to_tagged, None)
        .await
        .expect("no response to the out-of-order UPDATE");
    assert_eq!(resp.code, 500, "UPDATE below the high-water mark must 500");
    let resp = in_dialog(&a, engine, Method::Update, 6, &to_tagged, None)
        .await
        .expect("no response to the in-order UPDATE");
    assert_eq!(resp.code, 200, "UPDATE above the high-water mark must 200");

    // ---- the dialog survived: BYE CSeq 7 → 200 + full CDR trail ----
    let bye = RequestBuilder::new(
        Method::Bye,
        SipUri::parse(&format!("sip:1000@{engine}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to(&to_tagged)
    .call_id(Some("dialog-cseq-1"))
    .cseq(7)
    .build();
    a.send_to(&serialize(&SipMessage::Request(bye)), engine)
        .await
        .unwrap();
    let mut got_bye200 = false;
    for _ in 0..3 {
        if let Some((msg, _)) = recv_msg(&a, &mut buf).await {
            if as_response(&msg).is_some_and(|r| r.code == 200) {
                got_bye200 = true;
                break;
            }
        }
    }
    assert!(got_bye200, "no 200 for BYE");

    let flags = timeout(Duration::from_secs(12), b_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flags & 1, 1, "leg B must have received the ACK");
    assert_eq!(flags & 2, 2, "leg B must have received the relayed BYE");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = drain_cdr(&mut cdr_rx).await;
    let kinds: Vec<String> = events
        .iter()
        .map(|e| match e {
            CdrEvent::LegInvited { side, .. } => format!("INVITED-{}", side.as_str()),
            CdrEvent::LegAnswered { side, .. } => format!("ANSWERED-{}", side.as_str()),
            CdrEvent::LegConfirmed { side, .. } => format!("CONFIRMED-{}", side.as_str()),
            CdrEvent::LegTerminated { side, .. } => format!("TERMINATED-{}", side.as_str()),
            CdrEvent::CallEnded { .. } => "CALL_ENDED".to_string(),
        })
        .collect();
    for expected in [
        "INVITED-A",
        "INVITED-B",
        "ANSWERED-B",
        "CONFIRMED-B",
        "CONFIRMED-A",
        "TERMINATED-A",
        "CALL_ENDED",
    ] {
        assert!(
            kinds.iter().any(|k| k == expected),
            "missing CDR {expected} in {kinds:?}"
        );
    }
}
