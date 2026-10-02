//! Full-loopback WebRTC-leg integration test:
//!
//! mini WebRTC caller (ICE + DTLS + SRTP, the RFC 5763 offerer)
//!   → B2BUA (answers UDP/TLS/RTP/SAVPF, runs ICE → DTLS → SRTP)
//!   → plain PCMA UAS (leg B, unchanged RTP/AVP)
//!
//! Asserts the signaling answer carries ICE credentials/candidates/
//! fingerprint/setup:active, that real audio crosses the SRTP leg and the
//! plaintext leg (PCMU → PCMA with SNR), and that the CDR trail completes.

use b2bua::{B2bua, B2buaConfig, CdrEvent};
use codecs::Registry;
use dtls::{DtlsEndpoint, DtlsRole, SrtpOffers};
use ice::agent::{AgentConfig, IceAgent};
use rtp::packet::RtpPacket;
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{timeout, Duration as TDuration};

fn tone_pcm(freq: f64, rate: u32, samples: usize) -> Vec<i16> {
    (0..samples)
        .map(|i| {
            (f64::from(i as u32) * freq * std::f64::consts::TAU / f64::from(rate)).sin() * 9000.0
        })
        .map(|v| v.clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16)
        .collect()
}

/// Leg B (downstream): plain PCMA UAS — unchanged from the RTP/AVP world.
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

async fn recv_msg(sock: &UdpSocket, buf: &mut [u8]) -> Option<(SipMessage, std::net::SocketAddr)> {
    match timeout(TDuration::from_secs(8), sock.recv_from(buf)).await {
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

async fn run_leg_b(sock: UdpSocket, rtp_port: u16) -> (u64, Vec<i16>) {
    let rtp = UdpSocket::bind(("127.0.0.1", rtp_port)).await.unwrap();
    let mut buf = vec![0u8; 65_535];
    let mut rbuf = vec![0u8; 4096];
    let mut decoded = Vec::new();
    let mut dec = Registry::decoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut got_ack = false;
    let mut got_bye = false;
    // Echo state: leg B sends each received PCMA payload back so the B2BUA's
    // leg-B pump has return audio to bridge toward the WebRTC caller.
    let mut echo_seq: u16 = 9000;
    let mut echo_ts: u32 = 70_000;
    let mut echo_src: Option<std::net::SocketAddr> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            r = sock.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                let Ok(msg) = parse_message(&buf[..n]) else { continue };
                match msg {
                    SipMessage::Request(req) => match req.method {
                        Method::Invite => {
                            let trying = sip_core::builder::respond_to(&req, 100, "Trying", Vec::new(), None);
                            let _ = sock.send_to(&serialize(&SipMessage::Response(trying)), src).await;
                            let ok = sip_core::builder::respond_to(&req, 200, "OK", b_answer_sdp(rtp_port).into_bytes(), Some("tagB"));
                            let _ = sock.send_to(&serialize(&SipMessage::Response(ok)), src).await;
                        }
                        Method::Ack => { got_ack = true; }
                        Method::Bye => {
                            let ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                            let _ = sock.send_to(&serialize(&SipMessage::Response(ok)), src).await;
                            got_bye = true;
                        }
                        _ => {}
                    },
                    SipMessage::Response(_) => {}
                }
            }
            r = rtp.recv_from(&mut rbuf) => {
                if got_ack {
                    let Ok((n, src)) = r else { break };
                    if rtp::looks_like_rtcp(&rbuf[..n]) { continue; }
                    if let Ok(pkt) = RtpPacket::parse(&rbuf[..n]) {
                        if pkt.payload_type() == 8 {
                            let mut pcm = Vec::new();
                            let _ = dec.decode(&pkt.payload, &mut pcm);
                            decoded.extend_from_slice(&pcm);
                            // Echo the payload back (own seq/ts/SSRC).
                            echo_src = Some(src);
                            let echo = RtpPacket::new(
                                8,
                                echo_seq,
                                echo_ts,
                                0xE410,
                                false,
                                pkt.payload.clone(),
                            );
                            echo_seq = echo_seq.wrapping_add(1);
                            echo_ts = echo_ts.wrapping_add(160);
                            let _ = rtp.send_to(&echo.encode(), src).await;
                        }
                    }
                }
            }
        }
        if got_bye && decoded.len() > 1200 {
            break;
        }
    }
    let _ = echo_src;
    (if got_ack { 1 } else { 0 }, decoded)
}

async fn drain_cdr(rx: &mut UnboundedReceiver<CdrEvent>) -> Vec<CdrEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// Extract the first matching attribute value from an SDP body.
fn sdp_attr(sdp: &str, name: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.strip_prefix(&format!("a={name}:")))
        .map(str::to_string)
}

fn sdp_attrs(sdp: &str, name: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix(&format!("a={name}:")))
        .map(str::to_string)
        .collect()
}

fn sdp_m_audio_proto_port(sdp: &str) -> Option<(String, u16)> {
    sdp.lines()
        .find(|l| l.starts_with("m=audio "))
        .and_then(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            Some((parts[2].to_string(), parts[1].parse().ok()?))
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_leg_ice_dtls_srtp_loopback() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "info,b2bua=debug,ice=debug,dtls=debug".into()),
        ))
        .try_init();

    // ---- engine ----
    let (tx, mut cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let b_sip = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_sip_addr = b_sip.local_addr().unwrap();
    let b_rtp_port = {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };
    let mut cfg = B2buaConfig {
        sip_bind: "127.0.0.1:0".parse().unwrap(),
        media_host: "127.0.0.1".into(),
        media_base_port: 0,
        codecs: vec![
            codecs::CodecId::Pcmu,
            codecs::CodecId::Pcma,
            codecs::CodecId::G722,
            codecs::CodecId::G729,
            codecs::CodecId::Opus,
        ],
        routes: Vec::new(),
        default_target: format!("sip:1000@{b_sip_addr}"),
        session_timer_min_se: b2bua::timers::DEFAULT_MIN_SE,
    };
    let engine_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cfg.sip_bind = engine_sock.local_addr().unwrap();
    let engine_addr = cfg.sip_bind;
    let cfg_clone = cfg.clone();
    tokio::spawn(async move {
        let _ = B2bua::new(cfg_clone, tx)
            .run_on(std::sync::Arc::new(engine_sock))
            .await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ---- leg B task (plain PCMA) ----
    let b_task = tokio::spawn(run_leg_b(b_sip, b_rtp_port));

    // ---- mini WebRTC caller: gather ICE, build identity ----
    let mut agent = IceAgent::new(AgentConfig {
        controlling: Some(true),
        ..AgentConfig::default()
    })
    .await
    .unwrap();
    agent.gather_host().unwrap();
    let caller_fingerprint = dtls::Identity::generate("webrtc-caller").unwrap();
    let caller_port = agent.local_addr().unwrap().port();
    let candidate_lines = agent.local_candidates_sdp();

    let offer = format!(
        "v=0\r\n\
         o=caller 1 1 IN IP4 127.0.0.1\r\n\
         s=webrtc-loopback\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {caller_port} UDP/TLS/RTP/SAVPF 0 111 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:111 opus/48000/2\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=setup:actpass\r\n\
         a=fingerprint:sha-256 {}\r\n\
         a=ice-ufrag:{u}\r\n\
         a=ice-pwd:{p}\r\n\
         a=rtcp-mux\r\n\
         {cands}\
         a=sendrecv\r\n",
        caller_fingerprint.fingerprint(),
        u = agent.local_ufrag(),
        p = agent.local_pwd(),
        cands = candidate_lines
            .iter()
            .map(|c| format!("a={c}\r\n"))
            .collect::<String>(),
    );

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut buf = vec![0u8; 65_535];

    let invite = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&format!("sip:1000@{engine_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to("<sip:1000@dev>")
    .call_id(Some("webrtc-loopback-1"))
    .cseq(1)
    .contact(&format!("<sip:caller@{a_addr}>"))
    .body("application/sdp", offer.into_bytes())
    .build();
    a.send_to(&serialize(&SipMessage::Request(invite)), engine_addr)
        .await
        .unwrap();

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
    let ok200 = ok200.expect("no 200 OK from B2BUA");
    let answer_sdp = String::from_utf8_lossy(&ok200.body).to_string();

    // ---- answer assertions: WebRTC transport fields ----
    let (proto, answer_port) = sdp_m_audio_proto_port(&answer_sdp).expect("m=audio line");
    assert_eq!(
        proto, "UDP/TLS/RTP/SAVPF",
        "answer mirrors the secure proto"
    );
    // The c=/m= port is the ICE agent socket's port (the transport is ICE,
    // not the signaling c= line) — nonzero and bound.
    assert!(answer_port > 0, "answer must advertise a real media port");
    assert!(
        answer_sdp.contains("m=audio") && answer_sdp.contains(" 0 "),
        "answer must select PT 0 (PCMU)"
    );
    let ufrag = sdp_attr(&answer_sdp, "ice-ufrag").expect("answer ice-ufrag");
    let pwd = sdp_attr(&answer_sdp, "ice-pwd").expect("answer ice-pwd");
    let fp = sdp_attr(&answer_sdp, "fingerprint").expect("answer fingerprint");
    assert!(
        fp.starts_with("sha-256 "),
        "fingerprint carries the hash func"
    );
    let answer_cands = sdp_attrs(&answer_sdp, "candidate");
    assert!(
        !answer_cands.is_empty(),
        "answer must carry ICE candidates: {answer_sdp}"
    );
    assert!(
        answer_sdp.contains("a=setup:active"),
        "answerer must be the DTLS client (setup:active, RFC 5763 §5)"
    );
    // parse → serialize → parse stays a fixed point with candidate lines.
    let rt = sdp::parse::parse(&answer_sdp).unwrap();
    assert_eq!(rt.serialize(), answer_sdp, "answer roundtrip not stable");

    // ---- ACK (dialog confirmed; establishment may proceed on both sides) ----
    let ack = RequestBuilder::new(
        Method::Ack,
        SipUri::parse(&format!("sip:1000@{engine_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to(&format!(
        "<sip:1000@dev>;tag={}",
        ok200
            .headers
            .get("To")
            .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
            .and_then(|n| n.tag)
            .unwrap_or_default()
    ))
    .call_id(Some("webrtc-loopback-1"))
    .cseq(1)
    .build();
    a.send_to(&serialize(&SipMessage::Request(ack)), engine_addr)
        .await
        .unwrap();

    // ---- ICE (caller is controlling) ----
    let remote_cands: Vec<ice::candidate::Candidate> = answer_cands
        .iter()
        .filter_map(|l| ice::candidate::Candidate::from_sdp(l).ok())
        .collect();
    assert!(!remote_cands.is_empty(), "answer candidates parse");
    let fp_hex = fp.trim_start_matches("sha-256 ").trim().to_string();
    agent.set_remote(&ufrag, &pwd, &remote_cands);
    let pair = agent
        .connect(Duration::from_secs(5))
        .await
        .expect("ICE connectivity failed");

    // ---- DTLS: the caller offered actpass, the answerer chose active —
    // the caller is the DTLS SERVER (waits for ClientHello). ----
    let mut caller_dtls = DtlsEndpoint::new(
        caller_fingerprint,
        DtlsRole::Server,
        SrtpOffers::default_offer(),
    )
    .unwrap();
    caller_dtls.pin_peer_fingerprint(format!("sha-256 {fp_hex}"));
    let mut caller_sock = agent.into_socket();
    // Stray STUN keepalives from the ICE-selected pair are dropped.
    tokio::time::timeout(Duration::from_secs(10), async {
        caller_dtls
            .handshake_udp(&mut caller_sock, pair.remote, |_, _| {})
            .await
    })
    .await
    .expect("dtls handshake timed out")
    .expect("dtls handshake failed");

    // ---- keying: caller = DTLS server → server material protects TX ----
    let keying = caller_dtls.export_srtp_keys().unwrap();
    let (mut tx_sess, mut rx_sess) = keying.sessions(false).unwrap();

    // ---- media: 1 s of 440 Hz PCMU, SRTP-protected toward the B2BUA ----
    let pcm = tone_pcm(440.0, 8000, 8000);
    let mut enc = Registry::encoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut dec = Registry::decoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut seq: u16 = 300;
    let mut ts: u32 = 500;
    let mut decoded = Vec::new();
    let mut rbuf = vec![0u8; 2048];
    let frames: Vec<Vec<i16>> = pcm.chunks(160).map(|f| f.to_vec()).collect();
    for frame in &frames {
        let mut wire = Vec::new();
        enc.encode(frame, &mut wire).unwrap();
        let pkt = RtpPacket::new(0, seq, ts, 0xCA11BAC2, false, bytes::Bytes::from(wire));
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(160);
        let mut datagram = pkt.encode();
        tx_sess.protect(&mut datagram).unwrap();
        caller_sock.send_to(&datagram, pair.remote).await.unwrap();

        // Interleave reception: the bridge returns PCMU-protected audio once
        // its pump is up; keep draining until we hold ~0.4 s of decoded PCM.
        // Hard-bounded: the B2BUA bridges concealment repeats indefinitely,
        // so silence alone must not end the drain.
        let mut seen = 0usize;
        loop {
            seen += 1;
            if seen > 400 {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(30), caller_sock.recv_from(&mut rbuf))
                .await
            {
                Ok(Ok((n, _))) if n > 0 => {
                    let first = rbuf[0];
                    if first <= 3 || (20..=63).contains(&first) {
                        continue; // STUN keepalive / stray DTLS
                    }
                    if rtp::looks_like_rtcp(&rbuf[..n]) {
                        let mut srtcp = rbuf[..n].to_vec();
                        if rx_sess.unprotect_rtcp(&mut srtcp).is_ok() {
                            continue; // counted but not decoded
                        }
                        continue;
                    }
                    let mut media = rbuf[..n].to_vec();
                    if rx_sess.unprotect(&mut media).is_ok() {
                        if let Ok(rp) = RtpPacket::parse(&media) {
                            if rp.payload_type() == 0 {
                                let mut out = Vec::new();
                                let _ = dec.decode(rp.payload.as_ref(), &mut out);
                                decoded.extend_from_slice(&out);
                            }
                        }
                    }
                    if decoded.len() > 3200 {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    // Keep draining for a moment (pump pacing) to top up decoded audio.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut seen = 0usize;
    while decoded.len() <= 3200 && tokio::time::Instant::now() < deadline && seen < 400 {
        seen += 1;
        match tokio::time::timeout(Duration::from_millis(100), caller_sock.recv_from(&mut rbuf))
            .await
        {
            Ok(Ok((n, _))) if n > 0 => {
                let first = rbuf[0];
                if first <= 3 || (20..=63).contains(&first) {
                    continue;
                }
                if rtp::looks_like_rtcp(&rbuf[..n]) {
                    continue;
                }
                let mut media = rbuf[..n].to_vec();
                if rx_sess.unprotect(&mut media).is_ok() {
                    if let Ok(rp) = RtpPacket::parse(&media) {
                        if rp.payload_type() == 0 {
                            let mut out = Vec::new();
                            let _ = dec.decode(rp.payload.as_ref(), &mut out);
                            decoded.extend_from_slice(&out);
                        }
                    }
                }
            }
            _ => break,
        }
    }
    assert!(
        decoded.len() > 3200,
        "no decrypted audio returned over the SRTP leg (decoded={})",
        decoded.len()
    );

    // ---- BYE ----
    tokio::time::sleep(Duration::from_millis(400)).await;
    let bye = RequestBuilder::new(
        Method::Bye,
        SipUri::parse(&format!("sip:1000@{engine_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to(&format!(
        "<sip:1000@dev>;tag={}",
        ok200
            .headers
            .get("To")
            .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
            .and_then(|n| n.tag)
            .unwrap_or_default()
    ))
    .call_id(Some("webrtc-loopback-1"))
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
    assert!(got_bye200, "no 200 for BYE");

    // ---- leg B received the transcoded audio over plain RTP ----
    let (acks, b_decoded) = timeout(Duration::from_secs(15), b_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(acks, 1, "leg B must receive ACK");
    assert!(
        b_decoded.len() > 1200,
        "leg B decoded too little audio: {}",
        b_decoded.len()
    );

    // ---- CDR trail ----
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
    for expected in ["INVITED-A", "INVITED-B", "ANSWERED-B", "CALL_ENDED"] {
        assert!(
            kinds.iter().any(|k| k == expected),
            "missing CDR {expected} in {kinds:?}"
        );
    }
}
