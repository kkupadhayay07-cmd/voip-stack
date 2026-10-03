//! RFC 3264 §8 in-dialog renegotiation over a live B2BUA engine:
//! a caller re-INVITE with a changed offer is relayed to leg B, the answer
//! comes back as the 200 body, the media-preserving gate rejects codec
//! changes with 488 (call survives), and the leg-A pump follows the
//! caller's MOVED media address (offer c=/m=), proven with a silent caller.

use b2bua::{B2bua, B2buaConfig};
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, SipMessage};
use sip_core::uri::TransportKind;
use sip_core::{parse_message, serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

// ---- shared fixtures --------------------------------------------------------

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, s: impl Into<String>) {
        self.0.lock().unwrap().push(s.into());
    }
    fn count(&self, needle: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.contains(needle))
            .count()
    }
}

/// Caller SDP offer. `port` is where the caller receives; the session id
/// differs per offer so a re-offer never byte-equals the original.
fn offer_sdp(port: u16, codecs: &str, session: u32) -> String {
    let rtpmaps = if codecs.contains('8') {
        "a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
    } else {
        "a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
    };
    format!(
        "v=0\r\n\
         o=caller {session} {session} IN IP4 127.0.0.1\r\n\
         s=renegotiation-test\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP {codecs}\r\n\
         {rtpmaps}\
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

/// Test request-URI targeting the engine.
fn engine_uri(engine: SocketAddr) -> sip_core::uri::SipUri {
    sip_core::uri::SipUri::parse(&format!("sip:1000@{engine}")).unwrap()
}

/// The `m=audio` port of an SDP body (string-level; test shapes only).
fn audio_port(sdp: &str) -> Option<u16> {
    let i = sdp.find("m=audio ")? + "m=audio ".len();
    let rest = &sdp[i..];
    let end = rest.find(' ').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

async fn spawn_engine(uas: SocketAddr) -> SocketAddr {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let cfg = B2buaConfig {
        sip_bind: "127.0.0.1:0".parse().unwrap(),
        media_host: "127.0.0.1".into(),
        media_base_port: 0,
        codecs: vec![codecs::CodecId::Pcmu, codecs::CodecId::Pcma],
        routes: Vec::new(),
        default_target: format!("sip:1000@{uas}"),
        session_timer_min_se: 90,
    };
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = B2bua::new(cfg, tx).run_on(Arc::new(sock)).await;
    });
    sleep(Duration::from_millis(120)).await;
    addr
}

/// Minimal PCMU RTP packet (static PT 0, 160-byte payload).
fn rtp_pcmu(seq: u16, ts: u32, ssrc: u32) -> Vec<u8> {
    let mut p = vec![0x80u8, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&[0xD5u8; 160]);
    p
}

/// Leg-B fake UAS: answers every in-dialog INVITE with the same 200/answer,
/// records the offered audio port per INVITE, and streams RTP toward the
/// port the engine's offer advertised.
async fn run_uas(sock: UdpSocket, rtp: Arc<UdpSocket>, log: Log) {
    let rtp_port = rtp.local_addr().unwrap().port();
    let mut buf = vec![0u8; 65_535];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    let mut invites = 0usize;
    let mut engine_rtp: Option<SocketAddr> = None;
    let mut seq = 1u16;
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
                    invites += 1;
                    let body = String::from_utf8_lossy(&req.body).to_string();
                    let offered = audio_port(&body).unwrap_or(0);
                    let cseq = req.headers.cseq().map(|c| c.seq).unwrap_or(0);
                    log.push(format!("INVITE#{invites} cseq={cseq} port={offered}"));
                    // The engine's leg-B media port rides in the offer.
                    engine_rtp = Some(SocketAddr::new(src.ip(), offered));
                    let resp = sip_core::builder::respond_to(
                        &req,
                        200,
                        "OK",
                        answer_sdp(rtp_port).into_bytes(),
                        Some("tagB"),
                    );
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(resp)), src)
                        .await;
                }
                Method::Ack => log.push("ACK"),
                Method::Bye => {
                    let resp = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                    let _ = sock
                        .send_to(&serialize(&SipMessage::Response(resp)), src)
                        .await;
                    log.push("BYE-ACKED");
                    break;
                }
                _ => {}
            },
            SipMessage::Response(_) => {}
        }
        // Stream RTP toward the engine's leg-B media port while it is known.
        if let Some(dst) = engine_rtp {
            for _ in 0..5 {
                seq = seq.wrapping_add(1);
                let _ = rtp
                    .send_to(&rtp_pcmu(seq, 160 * u32::from(seq), 0x0B0B0B0B), dst)
                    .await;
            }
        }
    }
}

/// Caller side: initial INVITE, wait for the 200, ACK, then (optionally)
/// renegotiate. Returns (a_tag, a_port) from the first 200.
async fn initial_call(
    sock: &UdpSocket,
    engine: SocketAddr,
    media_port: u16,
    call_id: &str,
    from_tag: &str,
) -> (String, u16) {
    let invite = RequestBuilder::new(Method::Invite, engine_uri(engine))
        .via(
            TransportKind::Udp,
            &sock.local_addr().unwrap().to_string(),
            Some("z9hG4bK-init"),
        )
        .from(&format!("<sip:caller@example>;tag={from_tag}"))
        .to("<sip:1000@example>")
        .call_id(Some(call_id))
        .cseq(1)
        .contact("<sip:caller@example>")
        .body(
            "application/sdp",
            offer_sdp(media_port, "0 8 101", 1).into_bytes(),
        )
        .build();
    sock.send_to(&serialize(&SipMessage::Request(invite)), engine)
        .await
        .unwrap();

    let mut buf = vec![0u8; 65_535];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "no final response to the initial INVITE"
        );
        let Ok(Ok((n, _))) = timeout(remaining, sock.recv_from(&mut buf)).await else {
            panic!("no final response to the initial INVITE");
        };
        let Ok(SipMessage::Response(resp)) = parse_message(&buf[..n]) else {
            continue;
        };
        if resp.code / 100 == 1 {
            continue;
        }
        assert_eq!(resp.code, 200, "initial INVITE failed");
        let to_tag = resp
            .headers
            .get("To")
            .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
            .and_then(|n| n.tag)
            .expect("200 carries the engine's tag");
        let body = String::from_utf8_lossy(&resp.body).to_string();
        let a_port = audio_port(&body).expect("200 answer carries an audio m-line");
        // ACK the 200 (dialog level).
        let ack = RequestBuilder::new(Method::Ack, engine_uri(engine))
            .via(
                TransportKind::Udp,
                &sock.local_addr().unwrap().to_string(),
                Some("z9hG4bK-ack1"),
            )
            .from(&format!("<sip:caller@example>;tag={from_tag}"))
            .to(&format!("<sip:1000@example>;tag={to_tag}"))
            .call_id(Some(call_id))
            .cseq(1)
            .build();
        sock.send_to(&serialize(&SipMessage::Request(ack)), engine)
            .await
            .unwrap();
        return (to_tag, a_port);
    }
}

// ---- tests ------------------------------------------------------------------

/// Tests that attach a tracing subscriber see engine logs under --nocapture.
fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .try_init();
}

/// The full renegotiation relay: caller re-INVITE with a MOVED media port →
/// leg B receives a re-INVITE with the engine's re-offer, the answer comes
/// back as the 200 body (same receive port), and — with the caller now
/// completely silent so latching cannot correct anything — bridged media
/// reaches the caller's NEW socket (the pump followed the offer's c=/m=).
#[tokio::test]
async fn renegotiation_relay_moves_media() {
    init_log();
    let uas_rtp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let uas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas_addr = uas.local_addr().unwrap();
    let engine = spawn_engine(uas_addr).await;
    let log = Log::default();

    tokio::spawn(run_uas(uas, uas_rtp.clone(), log.clone()));

    let a1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (to_tag, a_port) = initial_call(
        &a1,
        engine,
        a1.local_addr().unwrap().port(),
        "reneg-move",
        "tA1",
    )
    .await;

    // Baseline media: the caller streams from a1, the callee receives.
    let mut seq = 1u16;
    for i in 0..40u16 {
        seq = seq.wrapping_add(1);
        let _ = a1
            .send_to(
                &rtp_pcmu(seq, 160 * u32::from(i) + 1000, 0x0A0A0A0A),
                SocketAddr::from(([127, 0, 0, 1], a_port)),
            )
            .await;
        sleep(Duration::from_millis(15)).await;
    }
    let mut ubuf = vec![0u8; 2048];
    let got_baseline = timeout(Duration::from_secs(5), async {
        loop {
            let (n, _) = uas_rtp.recv_from(&mut ubuf).await.unwrap();
            if n > 12 {
                return true;
            }
        }
    })
    .await
    .expect("callee should receive bridged RTP before renegotiation");
    assert!(got_baseline);

    // Renegotiate: same codecs, NEW receive port (a2), new o= session.
    let reinvite = RequestBuilder::new(Method::Invite, engine_uri(engine))
        .via(
            TransportKind::Udp,
            &a1.local_addr().unwrap().to_string(),
            Some("z9hG4bK-reneg"),
        )
        .from("<sip:caller@example>;tag=tA1")
        .to(&format!("<sip:1000@example>;tag={to_tag}"))
        .call_id(Some("reneg-move"))
        .cseq(2)
        .contact("<sip:caller@example>")
        .body(
            "application/sdp",
            offer_sdp(a2.local_addr().unwrap().port(), "0 8 101", 2).into_bytes(),
        )
        .build();
    a1.send_to(&serialize(&SipMessage::Request(reinvite)), engine)
        .await
        .unwrap();

    // The callee must see the relayed re-INVITE (CSeq 2, same media port).
    let saw_b_reinvite = timeout(Duration::from_secs(5), async {
        loop {
            if log.count("INVITE#2 cseq=2") > 0 {
                return true;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("leg B never received the relayed renegotiation re-INVITE");
    assert!(saw_b_reinvite);

    // The caller gets the 200 with OUR answer: same receive port as the
    // initial answer (the socket is reused), PCMU negotiated.
    let mut cbuf = vec![0u8; 65_535];
    let (code, body) = timeout(Duration::from_secs(5), async {
        loop {
            let (n, _) = a1.recv_from(&mut cbuf).await.unwrap();
            if let Ok(SipMessage::Response(resp)) = parse_message(&cbuf[..n]) {
                if resp.code / 100 >= 2 && resp.code != 200 {
                    panic!("renegotiation failed unexpectedly: {}", resp.code);
                }
                if resp.code == 200 {
                    let hdr = resp.headers.get("CSeq").unwrap_or("");
                    if hdr.contains("INVITE") {
                        return (resp.code, String::from_utf8_lossy(&resp.body).to_string());
                    }
                }
            }
        }
    })
    .await
    .expect("no 200 to the renegotiation re-INVITE");
    assert_eq!(code, 200);
    assert_eq!(
        audio_port(&body),
        Some(a_port),
        "answer keeps the receive socket"
    );
    // Static PTs need no rtpmap; PCMU/PT 0 first in the m-line + the
    // telephone-event rtpmap is the correct RFC 3264 answer shape.
    assert!(
        body.contains(&format!("m=audio {a_port} RTP/AVP 0")),
        "answer still negotiates PCMU/PT 0 first: {body}"
    );
    assert!(
        body.contains("a=rtpmap:101 telephone-event/8000"),
        "answer keeps the telephone-event rtpmap: {body}"
    );
    // ACK the renegotiation 200.
    let ack = RequestBuilder::new(Method::Ack, engine_uri(engine))
        .via(
            TransportKind::Udp,
            &a1.local_addr().unwrap().to_string(),
            Some("z9hG4bK-ack2"),
        )
        .from("<sip:caller@example>;tag=tA1")
        .to(&format!("<sip:1000@example>;tag={to_tag}"))
        .call_id(Some("reneg-move"))
        .cseq(2)
        .build();
    a1.send_to(&serialize(&SipMessage::Request(ack)), engine)
        .await
        .unwrap();

    // The caller is now SILENT on both sockets (no latching can correct a
    // stale seed): the callee streams and the bridge must reach a2 — the
    // pump followed the renegotiated offer's c=/m= line.
    let moved = timeout(Duration::from_secs(8), async {
        let mut abuf = vec![0u8; 2048];
        loop {
            let (n, _) = tokio::select! {
                r = a2.recv_from(&mut abuf) => r.unwrap(),
                _ = sleep(Duration::from_millis(500)) => continue,
            };
            if n > 12 {
                return true;
            }
        }
    })
    .await
    .expect("bridged media never reached the caller's MOVED media socket");
    assert!(moved);

    // BYE ends the call cleanly on both legs.
    let bye = RequestBuilder::new(Method::Bye, engine_uri(engine))
        .via(
            TransportKind::Udp,
            &a1.local_addr().unwrap().to_string(),
            Some("z9hG4bK-bye"),
        )
        .from("<sip:caller@example>;tag=tA1")
        .to(&format!("<sip:1000@example>;tag={to_tag}"))
        .call_id(Some("reneg-move"))
        .cseq(3)
        .build();
    a1.send_to(&serialize(&SipMessage::Request(bye)), engine)
        .await
        .unwrap();
    let byed = timeout(Duration::from_secs(5), async {
        loop {
            if log.count("BYE-ACKED") > 0 {
                return true;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("callee never received the relayed BYE");
    assert!(byed);
}

/// A re-offer that changes the negotiated codec (PCMA-only, PT 8 vs the
/// running PCMU/PT 0) is rejected 488 — the pumps bake the codec — and the
/// call SURVIVES: a pure refresh afterwards still 200s, no downstream
/// re-INVITE was relayed, and BYE tears down cleanly.
#[tokio::test]
async fn renegotiation_media_change_rejected() {
    init_log();
    let uas_rtp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let uas = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uas_addr = uas.local_addr().unwrap();
    let engine = spawn_engine(uas_addr).await;
    let log = Log::default();

    tokio::spawn(run_uas(uas, uas_rtp.clone(), log.clone()));

    let a1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = a1.local_addr().unwrap().port();
    let (to_tag, _a_port) = initial_call(&a1, engine, port, "reneg-reject", "tR").await;

    // Codec-changing re-offer: PCMA only.
    let reinvite = RequestBuilder::new(Method::Invite, engine_uri(engine))
        .via(
            TransportKind::Udp,
            &a1.local_addr().unwrap().to_string(),
            Some("z9hG4bK-reneg2"),
        )
        .from("<sip:caller@example>;tag=tR")
        .to(&format!("<sip:1000@example>;tag={to_tag}"))
        .call_id(Some("reneg-reject"))
        .cseq(2)
        .contact("<sip:caller@example>")
        .body("application/sdp", offer_sdp(port, "8 101", 2).into_bytes())
        .build();
    a1.send_to(&serialize(&SipMessage::Request(reinvite)), engine)
        .await
        .unwrap();

    let mut cbuf = vec![0u8; 65_535];
    let code = timeout(Duration::from_secs(5), async {
        loop {
            let (n, _) = a1.recv_from(&mut cbuf).await.unwrap();
            if let Ok(SipMessage::Response(resp)) = parse_message(&cbuf[..n]) {
                let hdr = resp.headers.get("CSeq").unwrap_or("").to_string();
                if resp.code / 100 >= 2 && hdr.contains("INVITE") {
                    return resp.code;
                }
            }
        }
    })
    .await
    .expect("no final response to the codec-changing re-INVITE");
    assert_eq!(code, 488, "a media-changing re-offer must be rejected 488");

    // No downstream re-INVITE was relayed (only the initial dial INVITE).
    assert_eq!(
        log.count("INVITE#"),
        1,
        "a rejected renegotiation must not touch leg B: {:?}",
        log.0.lock().unwrap()
    );

    // The call survives: a pure refresh (original offer body) still 200s.
    let refresh = RequestBuilder::new(Method::Invite, engine_uri(engine))
        .via(
            TransportKind::Udp,
            &a1.local_addr().unwrap().to_string(),
            Some("z9hG4bK-refr"),
        )
        .from("<sip:caller@example>;tag=tR")
        .to(&format!("<sip:1000@example>;tag={to_tag}"))
        .call_id(Some("reneg-reject"))
        .cseq(3)
        .contact("<sip:caller@example>")
        .body(
            "application/sdp",
            offer_sdp(port, "0 8 101", 1).into_bytes(),
        )
        .build();
    a1.send_to(&serialize(&SipMessage::Request(refresh)), engine)
        .await
        .unwrap();
    let code = timeout(Duration::from_secs(5), async {
        loop {
            let (n, _) = a1.recv_from(&mut cbuf).await.unwrap();
            if let Ok(SipMessage::Response(resp)) = parse_message(&cbuf[..n]) {
                let hdr = resp.headers.get("CSeq").unwrap_or("").to_string();
                if resp.code / 100 >= 2 && hdr.contains("INVITE") {
                    return resp.code;
                }
            }
        }
    })
    .await
    .expect("no response to the refresh re-INVITE");
    assert_eq!(code, 200, "the call must survive a rejected renegotiation");

    // BYE still tears down both legs.
    let bye = RequestBuilder::new(Method::Bye, engine_uri(engine))
        .via(
            TransportKind::Udp,
            &a1.local_addr().unwrap().to_string(),
            Some("z9hG4bK-bye2"),
        )
        .from("<sip:caller@example>;tag=tR")
        .to(&format!("<sip:1000@example>;tag={to_tag}"))
        .call_id(Some("reneg-reject"))
        .cseq(4)
        .build();
    a1.send_to(&serialize(&SipMessage::Request(bye)), engine)
        .await
        .unwrap();
    let byed = timeout(Duration::from_secs(5), async {
        loop {
            if log.count("BYE-ACKED") > 0 {
                return true;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("callee never received the relayed BYE");
    assert!(byed);
}
