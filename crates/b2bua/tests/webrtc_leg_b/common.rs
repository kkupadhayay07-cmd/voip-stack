//! Shared harness for the WebRTC leg B (offerer side) integration binaries:
//! mini WebRTC callee, plain caller, engine spawn, CDR helpers.
//!
//! One ENGINE per test binary: the engine's CDR sink is a process-global
//! OnceLock — a second engine in the same process silently loses its
//! CallEnded CDR to the first engine's channel (Task 48 lesson), so every
//! binary that asserts a CDR trail runs exactly one engine.

#![allow(dead_code)]

use b2bua::{B2bua, B2buaConfig, CdrEvent, Route};
use codecs::Registry;
use dtls::{DtlsEndpoint, DtlsRole, SrtpOffers};
use ice::agent::{AgentConfig, IceAgent};
use rtp::packet::RtpPacket;
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{timeout, Duration as TDuration};

pub fn tone_pcm(freq: f64, rate: u32, samples: usize) -> Vec<i16> {
    (0..samples)
        .map(|i| {
            (f64::from(i as u32) * freq * std::f64::consts::TAU / f64::from(rate)).sin() * 9000.0
        })
        .map(|v| v.clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16)
        .collect()
}

pub async fn recv_msg(sock: &UdpSocket, buf: &mut [u8]) -> Option<(SipMessage, SocketAddr)> {
    match timeout(TDuration::from_secs(8), sock.recv_from(buf)).await {
        Ok(Ok((n, src))) => parse_message(&buf[..n]).ok().map(|m| (m, src)),
        _ => None,
    }
}

pub fn as_response(msg: &SipMessage) -> Option<&sip_core::message::Response> {
    match msg {
        SipMessage::Response(r) => Some(r),
        _ => None,
    }
}

pub async fn drain_cdr(rx: &mut UnboundedReceiver<CdrEvent>) -> Vec<CdrEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// Drains the CDR channel, polling until `CALL_ENDED` has landed — the CDR
/// is emitted after the pumps unwind, a beat behind the BYE 200.
pub async fn drain_cdr_until_call_ended(rx: &mut UnboundedReceiver<CdrEvent>) -> Vec<CdrEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let events = drain_cdr(rx).await;
        if events
            .iter()
            .any(|e| matches!(e, CdrEvent::CallEnded { .. }))
            || tokio::time::Instant::now() > deadline
        {
            return events;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub fn local_tag_of(resp: &sip_core::message::Response) -> String {
    resp.headers
        .get("To")
        .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
        .and_then(|n| n.tag)
        .unwrap_or_default()
}

pub fn extract_audio_port(sdp: &str) -> Option<u16> {
    sdp.lines()
        .find(|l| l.starts_with("m=audio "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|p| p.parse().ok())
}

/// Spawns the engine with one `webrtc` route toward `callee_addr`.
pub async fn spawn_engine(
    callee_addr: SocketAddr,
    tx: tokio::sync::mpsc::UnboundedSender<CdrEvent>,
) -> SocketAddr {
    let engine_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine_addr = engine_sock.local_addr().unwrap();
    let cfg = B2buaConfig {
        sip_bind: engine_addr,
        media_host: "127.0.0.1".into(),
        media_base_port: 0,
        codecs: vec![
            codecs::CodecId::Pcmu,
            codecs::CodecId::Pcma,
            codecs::CodecId::G722,
            codecs::CodecId::G729,
            codecs::CodecId::Opus,
        ],
        routes: vec![Route {
            prefix: "1000".into(),
            target: format!("sip:callee@{callee_addr}"),
            webrtc: true,
        }],
        default_target: "sip:nowhere@127.0.0.1:59999".into(),
        session_timer_min_se: b2bua::timers::DEFAULT_MIN_SE,
    };
    tokio::spawn(async move {
        let _ = B2bua::new(cfg, tx)
            .run_on(std::sync::Arc::new(engine_sock))
            .await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    engine_addr
}

/// The callee's WebRTC answer: SAVPF + ICE + fingerprint + the given
/// `a=setup` role, PCMA (PT 8) audio.
pub fn callee_answer_sdp(
    port: u16,
    ufrag: &str,
    pwd: &str,
    fp: &str,
    cands: &[String],
    setup: &str,
) -> String {
    format!(
        "v=0\r\n\
         o=callee 7 7 IN IP4 127.0.0.1\r\n\
         s=webrtc-callee\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 8 101\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=rtcp-mux\r\n\
         a=setup:{setup}\r\n\
         a=fingerprint:sha-256 {fp}\r\n\
         a=ice-ufrag:{ufrag}\r\n\
         a=ice-pwd:{pwd}\r\n\
         {cands}\
         a=sendrecv\r\n",
        cands = cands
            .iter()
            .map(|c| format!("a={c}\r\n"))
            .collect::<String>(),
    )
}

/// A plain-RTP answer (the downgrade a `webrtc` route must reject).
pub fn plain_answer_sdp(port: u16) -> String {
    format!(
        "v=0\r\n\
         o=callee 7 7 IN IP4 127.0.0.1\r\n\
         s=plain-callee\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 8 101\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=sendrecv\r\n"
    )
}

/// The mini WebRTC callee (leg B answerer).  Validates the B2BUA's offer,
/// answers with `setup` from the parameter, then runs the matching ICE/DTLS
/// role and echoes SRTP PCMA back.
pub async fn run_webrtc_callee(sock: UdpSocket, setup: &'static str) -> (u64, Vec<i16>) {
    let mut buf = vec![0u8; 65_535];
    let mut got_ack = false;
    let mut got_bye = false;

    // Own transport, prepared up front (gathering is async-free).
    let mut agent = IceAgent::new(AgentConfig {
        controlling: Some(false),
        ..AgentConfig::default()
    })
    .await
    .unwrap();
    agent.gather_host().unwrap();
    let identity = dtls::Identity::generate("webrtc-callee").unwrap();
    let local_port = agent.local_addr().unwrap().port();
    let cands = agent.local_candidates_sdp();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut offer_fingerprint = String::new();
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            r = sock.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                let Ok(msg) = parse_message(&buf[..n]) else { continue };
                match msg {
                    SipMessage::Request(req) => match req.method {
                        Method::Invite => {
                            // ---- validate the B2BUA's WebRTC offer ----
                            let offer =
                                sdp::parse::parse(&String::from_utf8_lossy(&req.body)).unwrap();
                            let m = &offer.medias[0];
                            assert_eq!(
                                m.proto, "UDP/TLS/RTP/SAVPF",
                                "leg B offer must be SAVPF"
                            );
                            assert_eq!(m.setup, Some(sdp::types::SetupRole::Actpass));
                            let fp = m.fingerprint.as_ref().expect("offer fingerprint");
                            assert_eq!(fp.hash_func, "sha-256");
                            assert!(m.ice_ufrag.is_some() && m.ice_pwd.is_some());
                            assert!(!m.ice_candidates.is_empty(), "offer carries candidates");
                            assert!(m.rtcp_mux, "offer is rtcp-mux (the pump is mux-only)");
                            assert!(
                                m.rtcp_fb.contains_key(&0),
                                "offer advertises rtcp-fb for PCMU"
                            );
                            offer_fingerprint = format!("{} {}", fp.hash_func, fp.value);

                            // Adopt the offer's ICE side (the B2BUA's agent
                            // is the remote peer for this controlled agent)
                            // BEFORE answering — late checks are re-issued
                            // but the earlier they can be answered, the
                            // faster the nomination converges.
                            let remote_cands: Vec<ice::candidate::Candidate> = m
                                .ice_candidates
                                .iter()
                                .filter_map(|l| ice::candidate::Candidate::from_sdp(l).ok())
                                .collect();
                            agent.set_remote(
                                m.ice_ufrag.as_deref().unwrap_or(""),
                                m.ice_pwd.as_deref().unwrap_or(""),
                                &remote_cands,
                            );

                            let trying = sip_core::builder::respond_to(
                                &req, 100, "Trying", Vec::new(), None,
                            );
                            let _ = sock
                                .send_to(&serialize(&SipMessage::Response(trying)), src)
                                .await;
                            let answer = callee_answer_sdp(
                                local_port,
                                agent.local_ufrag(),
                                agent.local_pwd(),
                                identity.fingerprint(),
                                &cands,
                                setup,
                            );
                            let ok = sip_core::builder::respond_to(
                                &req,
                                200,
                                "OK",
                                answer.into_bytes(),
                                Some("tagCallee"),
                            );
                            let _ = sock
                                .send_to(&serialize(&SipMessage::Response(ok)), src)
                                .await;
                        }
                        Method::Ack => { got_ack = true; }
                        Method::Bye => {
                            let ok = sip_core::builder::respond_to(
                                &req, 200, "OK", Vec::new(), None,
                            );
                            let _ = sock
                                .send_to(&serialize(&SipMessage::Response(ok)), src)
                                .await;
                            got_bye = true;
                        }
                        _ => {}
                    },
                    SipMessage::Response(_) => {}
                }
            }
        }
        if got_ack {
            break;
        }
    }
    assert!(got_ack, "callee never received the ACK");

    // ---- ICE: the callee is controlled; the B2BUA nominates ----
    // (The offer's creds/candidates were adopted in the INVITE handler.)
    let pair = agent
        .connect(Duration::from_secs(8))
        .await
        .expect("callee ICE connectivity failed");
    let mut media_sock = agent.into_socket();

    // ---- DTLS: role per the answer's setup ----
    let role = match setup {
        // We answered active → we are the DTLS client (RFC 5763 §5).
        "active" => DtlsRole::Client,
        // We answered passive → the B2BUA drives as the client.
        "passive" => DtlsRole::Server,
        other => panic!("bad test setup role {other}"),
    };
    let mut dtls = DtlsEndpoint::new(identity, role, SrtpOffers::default_offer()).unwrap();
    dtls.pin_peer_fingerprint(offer_fingerprint);
    tokio::time::timeout(Duration::from_secs(10), async {
        dtls.handshake_udp(&mut media_sock, pair.remote, |_, _| {})
            .await
    })
    .await
    .expect("callee dtls handshake timed out")
    .expect("callee dtls handshake failed");

    let keying = dtls.export_srtp_keys().unwrap();
    let (mut tx_sess, mut rx_sess) = keying.sessions(role == DtlsRole::Client).unwrap();

    // ---- media echo: SRTP PCMA both ways ----
    let mut decoded = Vec::new();
    let mut dec = Registry::decoder(codecs::CodecId::Pcma, 8000, 1).unwrap();
    let mut echo_seq: u16 = 9000;
    let mut echo_ts: u32 = 70_000;
    let mut rbuf = vec![0u8; 2048];
    let media_deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while tokio::time::Instant::now() < media_deadline {
        tokio::select! {
            _ = tokio::time::sleep_until(media_deadline) => break,
            r = sock.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                let Ok(msg) = parse_message(&buf[..n]) else { continue };
                if let SipMessage::Request(req) = msg {
                    if req.method == Method::Bye {
                        let ok =
                            sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                        let _ = sock
                            .send_to(&serialize(&SipMessage::Response(ok)), src)
                            .await;
                        got_bye = true;
                    }
                }
            }
            r = media_sock.recv_from(&mut rbuf) => {
                let Ok((n, _)) = r else { break };
                if n == 0 {
                    continue;
                }
                let first = rbuf[0];
                if first <= 3 || (20..=63).contains(&first) {
                    continue; // STUN keepalive / stray DTLS
                }
                if rtp::looks_like_rtcp(&rbuf[..n]) {
                    continue;
                }
                let mut media = rbuf[..n].to_vec();
                if rx_sess.unprotect(&mut media).is_ok() {
                    if let Ok(pkt) = RtpPacket::parse(&media) {
                        if pkt.payload_type() == 8 {
                            let mut pcm: Vec<i16> = Vec::new();
                            let _ = dec.decode(&pkt.payload, &mut pcm);
                            decoded.extend_from_slice(&pcm);
                            // Echo back with own seq/ts/SSRC.
                            let echo = RtpPacket::new(
                                8,
                                echo_seq,
                                echo_ts,
                                0xB4C0_0001,
                                false,
                                pkt.payload.clone(),
                            );
                            echo_seq = echo_seq.wrapping_add(1);
                            echo_ts = echo_ts.wrapping_add(160);
                            let mut wire = echo.encode();
                            tx_sess.protect(&mut wire).unwrap();
                            let _ = media_sock.send_to(&wire, pair.remote).await;
                        }
                    }
                }
            }
        }
        if got_bye && decoded.len() > 1200 {
            break;
        }
    }
    (if got_ack { 1 } else { 0 }, decoded)
}

/// The leg-A plain caller: RTP/AVP PCMU offer, ACK, 1 s of 440 Hz tone,
/// drains the returned (PCMA-bridged → PCMU) audio, BYE.
pub async fn run_plain_caller(engine_addr: SocketAddr, call_id: &str) -> (Vec<i16>, bool) {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let rtp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rtp_port = rtp.local_addr().unwrap().port();
    let mut buf = vec![0u8; 65_535];

    let offer = format!(
        "v=0\r\n\
         o=caller 1 1 IN IP4 127.0.0.1\r\n\
         s=plain-caller\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} RTP/AVP 0 8 9 18 111 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=sendrecv\r\n"
    );
    let invite = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&format!("sip:1000@{engine_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to("<sip:1000@dev>")
    .call_id(Some(call_id))
    .cseq(1)
    .contact(&format!("<sip:caller@{a_addr}>"))
    .body("application/sdp", offer.into_bytes())
    .build();
    a.send_to(&serialize(&SipMessage::Request(invite)), engine_addr)
        .await
        .unwrap();

    let mut saw_100 = false;
    let mut saw_180 = false;
    let mut ok200 = None;
    for _ in 0..6 {
        let Some((msg, _)) = recv_msg(&a, &mut buf).await else {
            break;
        };
        if let Some(resp) = as_response(&msg) {
            match resp.code {
                100 => saw_100 = true,
                180 => {
                    assert!(saw_100, "180 must follow 100");
                    saw_180 = true;
                }
                200 => {
                    assert!(saw_180, "200 must follow 180");
                    ok200 = Some(resp.clone());
                    break;
                }
                _ => {}
            }
        }
    }
    let ok200 = ok200.expect("no 200 OK from B2BUA");
    let answer_sdp = String::from_utf8_lossy(&ok200.body).to_string();
    // Leg A stays PLAIN: the caller offered RTP/AVP and must get RTP/AVP.
    assert!(
        answer_sdp.contains("m=audio") && !answer_sdp.contains("UDP/TLS/RTP/SAVPF"),
        "leg A answer must remain plain RTP/AVP: {answer_sdp}"
    );
    let audio_port = extract_audio_port(&answer_sdp).expect("leg A answer audio port");
    assert!(audio_port > 0);

    let ack = RequestBuilder::new(
        Method::Ack,
        SipUri::parse(&format!("sip:1000@{engine_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to(&format!("<sip:1000@dev>;tag={}", local_tag_of(&ok200)))
    .call_id(Some(call_id))
    .cseq(1)
    .build();
    a.send_to(&serialize(&SipMessage::Request(ack)), engine_addr)
        .await
        .unwrap();

    // ---- media: 1 s of 440 Hz PCMU toward the engine ----
    let pcm = tone_pcm(440.0, 8000, 8000);
    let mut enc = Registry::encoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut dec = Registry::decoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut seq: u16 = 500;
    let mut ts: u32 = 1000;
    let mut decoded = Vec::new();
    let dst = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        audio_port,
    );
    let mut rbuf = vec![0u8; 2048];
    for frame in pcm.chunks(160) {
        let mut wire = Vec::new();
        enc.encode(frame, &mut wire).unwrap();
        let pkt = RtpPacket::new(0, seq, ts, 0xCA11BAC3, false, bytes::Bytes::from(wire));
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(160);
        let _ = rtp.send_to(&pkt.encode(), dst).await;

        // Interleave reception: the bridge returns PCMU once the callee's
        // echo crosses back.  Bounded drain per frame.
        let mut seen = 0usize;
        loop {
            seen += 1;
            if seen > 200 {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(20), rtp.recv_from(&mut rbuf)).await {
                Ok(Ok((n, _))) if n > 0 => {
                    if rtp::looks_like_rtcp(&rbuf[..n]) {
                        continue;
                    }
                    if let Ok(rp) = RtpPacket::parse(&rbuf[..n]) {
                        if rp.payload_type() == 0 {
                            let mut out = Vec::new();
                            let _ = dec.decode(rp.payload.as_ref(), &mut out);
                            decoded.extend_from_slice(&out);
                        }
                    }
                    if decoded.len() > 3200 {
                        break;
                    }
                }
                _ => break,
            }
        }
        if decoded.len() > 3200 {
            break;
        }
    }

    // Keep draining a moment for pump pacing.
    let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut seen = 0usize;
    while decoded.len() <= 3200 && tokio::time::Instant::now() < drain_deadline && seen < 200 {
        seen += 1;
        match tokio::time::timeout(Duration::from_millis(50), rtp.recv_from(&mut rbuf)).await {
            Ok(Ok((n, _))) if n > 0 => {
                if rtp::looks_like_rtcp(&rbuf[..n]) {
                    continue;
                }
                if let Ok(rp) = RtpPacket::parse(&rbuf[..n]) {
                    if rp.payload_type() == 0 {
                        let mut out = Vec::new();
                        let _ = dec.decode(rp.payload.as_ref(), &mut out);
                        decoded.extend_from_slice(&out);
                    }
                }
            }
            _ => break,
        }
    }

    // ---- BYE ----
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bye = RequestBuilder::new(
        Method::Bye,
        SipUri::parse(&format!("sip:1000@{engine_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to(&format!("<sip:1000@dev>;tag={}", local_tag_of(&ok200)))
    .call_id(Some(call_id))
    .cseq(2)
    .build();
    a.send_to(&serialize(&SipMessage::Request(bye)), engine_addr)
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
    (decoded, got_bye200)
}

/// The reject variant: the caller must receive 503 (never a confirmed 200)
/// when the `webrtc` route's downstream answers plaintext.
pub async fn run_plain_caller_expect_503(engine_addr: SocketAddr, call_id: &str) -> u16 {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let rtp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rtp_port = rtp.local_addr().unwrap().port();
    let mut buf = vec![0u8; 65_535];

    let offer = format!(
        "v=0\r\n\
         o=caller 1 1 IN IP4 127.0.0.1\r\n\
         s=plain-caller\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} RTP/AVP 0 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=sendrecv\r\n"
    );
    let invite = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&format!("sip:1000@{engine_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to("<sip:1000@dev>")
    .call_id(Some(call_id))
    .cseq(1)
    .contact(&format!("<sip:caller@{a_addr}>"))
    .body("application/sdp", offer.into_bytes())
    .build();
    a.send_to(&serialize(&SipMessage::Request(invite)), engine_addr)
        .await
        .unwrap();

    let mut last = 0u16;
    for _ in 0..6 {
        let Some((msg, _)) = recv_msg(&a, &mut buf).await else {
            break;
        };
        if let Some(resp) = as_response(&msg) {
            last = resp.code;
            if resp.code >= 400 || resp.code == 200 {
                break;
            }
        }
    }
    last
}

/// A plain-RTP callee that answers 200 (the downgrade trigger) and answers
/// the ACK/BYE so the engine's teardown is clean.
pub async fn run_plain_downgrade_callee(sock: UdpSocket) -> u64 {
    let mut buf = vec![0u8; 65_535];
    let mut got_bye = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            r = sock.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                let Ok(msg) = parse_message(&buf[..n]) else { continue };
                if let SipMessage::Request(req) = msg {
                    match req.method {
                        Method::Invite => {
                            let trying = sip_core::builder::respond_to(
                                &req, 100, "Trying", Vec::new(), None,
                            );
                            let _ = sock
                                .send_to(&serialize(&SipMessage::Response(trying)), src)
                                .await;
                            let ok = sip_core::builder::respond_to(
                                &req,
                                200,
                                "OK",
                                plain_answer_sdp(55000).into_bytes(),
                                Some("tagPlain"),
                            );
                            let _ = sock
                                .send_to(&serialize(&SipMessage::Response(ok)), src)
                                .await;
                        }
                        Method::Ack => {}
                        Method::Bye => {
                            let ok = sip_core::builder::respond_to(
                                &req, 200, "OK", Vec::new(), None,
                            );
                            let _ = sock
                                .send_to(&serialize(&SipMessage::Response(ok)), src)
                                .await;
                            got_bye = true;
                        }
                        _ => {}
                    }
                }
            }
        }
        if got_bye {
            break;
        }
    }
    if got_bye {
        1
    } else {
        0
    }
}

pub fn assert_cdr_trail(events: &[CdrEvent]) {
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

pub async fn init_log() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "info,b2bua=debug,ice=debug,dtls=debug".into()),
        ))
        .try_init();
}
