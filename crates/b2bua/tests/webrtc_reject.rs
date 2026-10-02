//! A SAVPF offer without ICE credentials must be rejected with 488 — never
//! answered, and never served with a plaintext fallback transport.
//!
//! (Own test binary: the engine's CDR sink is a process-global OnceLock, so
//! one engine per test process.)

use b2bua::{B2bua, B2buaConfig};
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use std::time::Duration;
use tokio::net::UdpSocket;

async fn recv_msg(sock: &UdpSocket, buf: &mut [u8]) -> Option<(SipMessage, std::net::SocketAddr)> {
    match tokio::time::timeout(Duration::from_secs(8), sock.recv_from(buf)).await {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn savpf_offer_without_ice_is_rejected() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let (tx, cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut cfg = B2buaConfig {
        sip_bind: "127.0.0.1:0".parse().unwrap(),
        media_host: "127.0.0.1".into(),
        media_base_port: 0,
        codecs: vec![codecs::CodecId::Pcmu],
        routes: Vec::new(),
        default_target: "sip:1000@127.0.0.1:5099".into(),
        session_timer_min_se: b2bua::timers::DEFAULT_MIN_SE,
    };
    let engine_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cfg.sip_bind = engine_sock.local_addr().unwrap();
    let engine_addr = cfg.sip_bind;
    tokio::spawn(async move {
        let _ = B2bua::new(cfg, tx)
            .run_on(std::sync::Arc::new(engine_sock))
            .await;
    });
    tokio::time::sleep(Duration::from_millis(120)).await;

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let offer = "v=0\r\n\
         o=caller 1 1 IN IP4 127.0.0.1\r\n\
         s=no-ice\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio 49172 UDP/TLS/RTP/SAVPF 0\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=setup:actpass\r\n\
         a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n\
         a=sendrecv\r\n";
    let invite = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&format!("sip:1000@{engine_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to("<sip:1000@dev>")
    .call_id(Some("no-ice-1"))
    .cseq(1)
    .contact(&format!("<sip:caller@{a_addr}>"))
    .body("application/sdp", offer.as_bytes().to_vec())
    .build();
    a.send_to(&serialize(&SipMessage::Request(invite)), engine_addr)
        .await
        .unwrap();

    let mut buf = vec![0u8; 65_535];
    let mut code = None;
    for _ in 0..4 {
        let Some((msg, _)) = recv_msg(&a, &mut buf).await else {
            break;
        };
        if let Some(resp) = as_response(&msg) {
            code = Some(resp.code);
            if resp.code >= 400 || resp.code == 200 {
                break;
            }
        }
    }
    assert_eq!(code, Some(488), "SAVPF without ICE must be rejected 488");
    let _ = cdr_rx; // CDR policy for rejected invites mirrors the bad-SDP path (no trail)
}
