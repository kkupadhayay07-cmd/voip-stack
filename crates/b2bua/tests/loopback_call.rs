//! Full-loopback B2BUA integration test:
//! UAC (PCMU offer) → B2BUA → UAS (answers PCMA) → 1 s of RTP audio → BYE.
//!
//! Asserts signaling order (100/180/200/ACK), the forwarded INVITE at leg B,
//! real transcoded audio (PCMU in → PCMA out) with SNR, DTMF-free clean
//! teardown and a complete CDR event trail.

use b2bua::{B2bua, B2buaConfig, CdrEvent};
use codecs::Registry;
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

fn tone_pcm(freq: f64, rate: u32, samples: usize) -> Vec<i16> {
    (0..samples)
        .map(|i| {
            (f64::from(i as u32) * freq * std::f64::consts::TAU / f64::from(rate)).sin() * 9000.0
        })
        .map(|v| v.clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16)
        .collect()
}

fn a_offer_sdp(port: u16) -> String {
    format!(
        "v=0\r\n\
         o=caller 1 1 IN IP4 127.0.0.1\r\n\
         s=loopback-test\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP 0 8 9 18 111 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:9 G722/8000\r\n\
         a=rtpmap:18 G729/8000\r\n\
         a=rtpmap:111 opus/48000/2\r\n\
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

/// Leg B: minimal UAS that answers PCMA and echoes nothing else.
async fn run_leg_b(sock: UdpSocket, rtp_port: u16) -> (u64, Vec<i16>) {
    let rtp = UdpSocket::bind(("127.0.0.1", rtp_port)).await.unwrap();
    let mut buf = vec![0u8; 65_535];
    let mut rbuf = vec![0u8; 4096];
    let mut decoded = Vec::new();
    let mut dec = Registry::decoder(codecs::CodecId::Pcma, 8000, 1).unwrap();
    let mut got_ack = false;
    let mut got_bye = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
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
                    let Ok((n, _)) = r else { break };
                    if rtp::looks_like_rtcp(&rbuf[..n]) { continue; }
                    if let Ok(pkt) = RtpPacket::parse(&rbuf[..n]) {
                        if pkt.payload_type() == 8 {
                            let mut pcm = Vec::new();
                            let _ = dec.decode(&pkt.payload, &mut pcm);
                            decoded.extend_from_slice(&pcm);
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

async fn drain_cdr(rx: &mut UnboundedReceiver<CdrEvent>) -> Vec<CdrEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_call_pcmu_to_pcma() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,b2bua=debug".into()),
        ))
        .try_init();

    // ---- start engine ----
    let (tx, mut cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let cfg = B2buaConfig {
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
        default_target: "sip:placeholder".into(), // replaced below
    };

    let b_sip = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_sip_addr = b_sip.local_addr().unwrap();
    // Probe a free RTP port for leg B (socket is dropped immediately).
    let b_rtp_port = {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    let mut cfg = cfg;
    cfg.default_target = format!("sip:1000@{b_sip_addr}");

    let engine_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine_sock_addr = engine_sock.local_addr().unwrap();
    cfg.sip_bind = engine_sock_addr;

    let cfg_clone = cfg.clone();
    tokio::spawn(async move {
        let _ = B2bua::new(cfg_clone, tx)
            .run_on(std::sync::Arc::new(engine_sock))
            .await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ---- leg B task ----
    let b_task = tokio::spawn(run_leg_b(b_sip, b_rtp_port));

    // ---- leg A: UAC ----
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let a_rtp_port = 49170u16;
    let mut buf = vec![0u8; 65_535];

    let invite = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&format!("sip:1000@{engine_sock_addr}")).unwrap(),
    )
    .via(TransportKind::Udp, &a_addr.to_string(), None)
    .from("<sip:caller@dev>;tag=tagA")
    .to("<sip:1000@dev>")
    .call_id(Some("loopback-call-1"))
    .cseq(1)
    .contact(&format!("<sip:caller@{a_addr}>"))
    .body("application/sdp", a_offer_sdp(a_rtp_port).into_bytes())
    .build();
    a.send_to(&serialize(&SipMessage::Request(invite)), engine_sock_addr)
        .await
        .unwrap();

    // 100 Trying → 180 Ringing → 200 OK (order enforced).
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
    // PT 0 (PCMU) is a static payload type — its presence in the m= line is
    // the RFC 3551 answer; no a=rtpmap line is required.
    assert!(
        answer_sdp.contains("m=audio") && answer_sdp.contains(" 0 "),
        "answer must select PT 0 (PCMU): {answer_sdp}"
    );
    assert!(
        ok200.headers.get("To").unwrap_or("").contains("tag="),
        "To must carry our tag"
    );

    // Send ACK.
    let ack_uri = SipUri::parse(&format!("sip:1000@{engine_sock_addr}")).unwrap();
    let bye_uri = SipUri::parse(&format!("sip:1000@{engine_sock_addr}")).unwrap();
    let ack = RequestBuilder::new(Method::Ack, ack_uri)
        .via(TransportKind::Udp, &a_addr.to_string(), None)
        .from("<sip:caller@dev>;tag=tagA")
        .to(&format!("<sip:1000@dev>;tag={}", local_tag_of(&ok200)))
        .call_id(Some("loopback-call-1"))
        .cseq(1)
        .build();
    a.send_to(&serialize(&SipMessage::Request(ack)), engine_sock_addr)
        .await
        .unwrap();

    // ---- media: 1 s of 440 Hz PCMU (burst, jitter buffer paces it out) ----
    let pcm = tone_pcm(440.0, 8000, 8000);
    let mut enc = Registry::encoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut seq: u16 = 500;
    let mut ts: u32 = 1000;
    for frame in pcm.chunks(160) {
        let mut wire = Vec::new();
        enc.encode(frame, &mut wire).unwrap();
        let pkt = RtpPacket::new(0, seq, ts, 0xCA11BAC1, false, bytes::Bytes::from(wire));
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(160);
        let dst = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            extract_audio_port(&answer_sdp).expect("answer audio port"),
        );
        a.send_to(&pkt.encode(), dst).await.unwrap();
    }

    // ---- BYE (after ~1.2 s so all 50 frames playout through the bridge) ----
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let bye = RequestBuilder::new(Method::Bye, bye_uri)
        .via(TransportKind::Udp, &a_addr.to_string(), None)
        .from("<sip:caller@dev>;tag=tagA")
        .to(&format!("<sip:1000@dev>;tag={}", local_tag_of(&ok200)))
        .call_id(Some("loopback-call-1"))
        .cseq(2)
        .build();
    a.send_to(&serialize(&SipMessage::Request(bye)), engine_sock_addr)
        .await
        .unwrap();
    // 200 for BYE.
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

    // ---- assertions on leg B ----
    let (acks, decoded) = timeout(Duration::from_secs(12), b_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(acks, 1, "leg B must receive ACK");
    let skip = decoded.len().min(800); // skip JB ramp-up
                                       // Compare only the real-audio region: after the 50 sent frames the pump
                                       // legitimately emits post-stream comfort repeats until BYE, which must
                                       // be excluded from fidelity scoring.
    let window = &decoded[skip..decoded.len().min(skip + 4000)];
    let tail = window;
    let reference = {
        // PCMU→PCM→PCMA→PCM reference of the same tone (frame-wise).
        let mut e = Registry::encoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
        let mut d1 = Registry::decoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
        let mut e2 = Registry::encoder(codecs::CodecId::Pcma, 8000, 1).unwrap();
        let mut d2 = Registry::decoder(codecs::CodecId::Pcma, 8000, 1).unwrap();
        let mut lin_all = Vec::new();
        let mut out = Vec::new();
        for frame in tone_pcm(440.0, 8000, 8000).chunks(160) {
            let mut wire = Vec::new();
            e.encode(frame, &mut wire).unwrap();
            let mut lin = Vec::new();
            d1.decode(&wire, &mut lin).unwrap();
            lin_all.extend_from_slice(&lin);
        }
        for frame in lin_all.chunks(160) {
            let mut wire2 = Vec::new();
            e2.encode(frame, &mut wire2).unwrap();
            let mut pcm = Vec::new();
            d2.decode(&wire2, &mut pcm).unwrap();
            out.extend_from_slice(&pcm);
        }
        out
    };
    let n = tail.len().min(reference.len());
    // Lag-aligned SNR: resampler group delay shifts the waveform; find the
    // offset with maximum correlation before comparing.
    let mut best = (f64::NEG_INFINITY, 0i64);
    for lag in -64i64..=64 {
        let (mut sig, mut err) = (0f64, 0f64);
        let mut used = 0usize;
        for (i, &t) in tail.iter().enumerate().take(n) {
            let j = i as i64 + lag;
            if j < 0 || j >= reference.len() as i64 {
                continue;
            }
            let x = f64::from(reference[j as usize]);
            let y = f64::from(t);
            sig += x * x;
            err += (x - y) * (x - y);
            used += 1;
        }
        if used > 400 {
            let snr = 10.0 * (sig / err.max(1e-9)).log10();
            if snr > best.0 {
                best = (snr, lag);
            }
        }
    }
    let snr = best.0;
    assert!(
        snr >= 12.0,
        "transcoded audio SNR {snr:.1} dB at lag {} below threshold",
        best.1
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
    if let Some(CdrEvent::CallEnded {
        frames_a_to_b,
        duration_ms,
        ..
    }) = events
        .iter()
        .find(|e| matches!(e, CdrEvent::CallEnded { .. }))
    {
        assert!(
            *frames_a_to_b >= 30,
            "expected ≥ 30 transcoded frames, got {frames_a_to_b}"
        );
        assert!(*duration_ms > 0);
    } else {
        panic!("no CALL_ENDED CDR");
    }
}

fn local_tag_of(resp: &sip_core::message::Response) -> String {
    resp.headers
        .get("To")
        .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
        .and_then(|n| n.tag)
        .unwrap_or_default()
}

fn extract_audio_port(sdp: &str) -> Option<u16> {
    sdp.lines()
        .find(|l| l.starts_with("m=audio "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|p| p.parse().ok())
}
