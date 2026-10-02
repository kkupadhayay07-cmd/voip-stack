//! Full-loopback WebRTC data-channel integration test:
//!
//! mini WebRTC caller (ICE + DTLS server + SCTP responder, the RFC 5763
//! offerer)   →   B2BUA (answers SAVPF audio + RFC 8841 data channel, runs
//! ICE → DTLS → SRTP media pump AND the RFC 8261 SCTP association over the
//! same DTLS transport)   →   plain PCMA UAS (leg B, unchanged).
//!
//! Asserts the SDP answer carries the mirrored `m=application
//! UDP/DTLS/SCTP webrtc-datachannel` line with `a=sctp-port`, that DCEP
//! channel establishment crosses the B2BUA (ack), that user messages —
//! including one requiring SCTP fragmentation — echo back, that SRTP audio
//! still flows on the same socket while the association is up (RFC 7983
//! demux both directions), and that the CDR trail completes.

use b2bua::{B2bua, B2buaConfig, CdrEvent};
use codecs::Registry;
use dtls::{DtlsEndpoint, DtlsRole, SrtpOffers};
use ice::agent::{AgentConfig, IceAgent};
use rtp::packet::RtpPacket;
use sctp::{ChannelType, SctpConfig, SctpEndpoint, SctpEvent};
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use std::time::{Duration, Instant};
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

/// Leg B: plain PCMA UAS that ACKs and echoes audio (same contract as
/// webrtc_leg.rs, bounded here to what the audio coexistence check needs).
async fn run_leg_b(sock: UdpSocket, rtp_port: u16) -> (u64, usize) {
    let rtp = UdpSocket::bind(("127.0.0.1", rtp_port)).await.unwrap();
    let mut buf = vec![0u8; 65_535];
    let mut rbuf = vec![0u8; 4096];
    let mut dec = Registry::decoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut decoded = 0usize;
    let mut got_ack = false;
    let mut echo_seq: u16 = 9000;
    let mut echo_ts: u32 = 70_000;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            r = sock.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                let Ok(msg) = parse_message(&buf[..n]) else { continue };
                if let SipMessage::Request(req) = msg {
                    match req.method {
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
                            break;
                        }
                        _ => {}
                    }
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
                            decoded += 1;
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
        if decoded > 60 {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_datachannel_over_dtls_loopback() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,b2bua=debug".into()),
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
        codecs: vec![codecs::CodecId::Pcmu, codecs::CodecId::Pcma],
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

    let b_task = tokio::spawn(run_leg_b(b_sip, b_rtp_port));

    // ---- mini WebRTC caller ----
    let mut agent = IceAgent::new(AgentConfig {
        controlling: Some(true),
        ..AgentConfig::default()
    })
    .await
    .unwrap();
    agent.gather_host().unwrap();
    let caller_id = dtls::Identity::generate("webrtc-caller").unwrap();
    let caller_port = agent.local_addr().unwrap().port();
    let candidate_lines = agent.local_candidates_sdp();

    // Offer: audio SAVPF + RFC 8841 data channel (the browser shape).
    let cands = candidate_lines
        .iter()
        .map(|c| format!("a={c}\r\n"))
        .collect::<String>();
    let ufrag = agent.local_ufrag().to_string();
    let pwd = agent.local_pwd().to_string();
    let fp_line = format!("sha-256 {}", caller_id.fingerprint());
    let offer = format!(
        "v=0\r\n\
         o=caller 1 1 IN IP4 127.0.0.1\r\n\
         s=webrtc-datachan\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {caller_port} UDP/TLS/RTP/SAVPF 0 101\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=mid:0\r\n\
         a=setup:actpass\r\n\
         a=fingerprint:{fp_line}\r\n\
         a=ice-ufrag:{ufrag}\r\n\
         a=ice-pwd:{pwd}\r\n\
         a=rtcp-mux\r\n\
         {cands}\
         a=sendrecv\r\n\
         m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
         a=mid:1\r\n\
         a=sctp-port:5000\r\n\
         a=max-message-size:1073741823\r\n\
         a=setup:actpass\r\n\
         a=fingerprint:{fp_line}\r\n\
         a=ice-ufrag:{ufrag}\r\n\
         a=ice-pwd:{pwd}\r\n\
         {cands}"
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
    .call_id(Some("webrtc-datachan-1"))
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

    // ---- answer assertions: audio + application, in kind ----
    let app_line = answer_sdp
        .lines()
        .find(|l| l.starts_with("m=application "))
        .expect("answer must carry the application m-line")
        .to_string();
    let parts: Vec<&str> = app_line.split_whitespace().collect();
    assert_eq!(parts[2], "UDP/DTLS/SCTP", "proto mirrored: {app_line}");
    assert_eq!(parts[3], "webrtc-datachannel", "format mirrored");
    let app_port: u16 = parts[1].parse().unwrap();
    assert!(app_port > 0, "data channel must be accepted, not rejected");
    assert!(
        answer_sdp.contains("a=sctp-port:5000\r\n"),
        "answer must carry a=sctp-port: {answer_sdp}"
    );
    assert!(
        answer_sdp.contains("a=max-message-size:262144\r\n"),
        "answer must carry our max-message-size"
    );
    assert!(answer_sdp.contains("a=setup:active"));
    assert!(
        answer_sdp.contains("m=audio"),
        "audio m-line still answered"
    );
    // parse → serialize → parse stays a fixed point.
    let rt = sdp::parse::parse(&answer_sdp).unwrap();
    assert_eq!(rt.serialize(), answer_sdp, "answer roundtrip not stable");

    // ---- ACK ----
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
    .call_id(Some("webrtc-datachan-1"))
    .cseq(1)
    .build();
    a.send_to(&serialize(&SipMessage::Request(ack)), engine_addr)
        .await
        .unwrap();

    // ---- ICE (caller controlling) ----
    let ufrag = sdp_attr(&answer_sdp, "ice-ufrag").expect("answer ice-ufrag");
    let pwd = sdp_attr(&answer_sdp, "ice-pwd").expect("answer ice-pwd");
    let fp = sdp_attr(&answer_sdp, "fingerprint").expect("answer fingerprint");
    let answer_cands = sdp_attrs(&answer_sdp, "candidate");
    let remote_cands: Vec<ice::candidate::Candidate> = answer_cands
        .iter()
        .filter_map(|l| ice::candidate::Candidate::from_sdp(l).ok())
        .collect();
    assert!(!remote_cands.is_empty());
    let fp_hex = fp.trim_start_matches("sha-256 ").trim().to_string();
    agent.set_remote(&ufrag, &pwd, &remote_cands);
    let pair = agent
        .connect(Duration::from_secs(5))
        .await
        .expect("ICE connectivity failed");

    // ---- DTLS: caller is the SERVER (offered actpass, answer active) ----
    let mut caller_dtls =
        DtlsEndpoint::new(caller_id, DtlsRole::Server, SrtpOffers::default_offer()).unwrap();
    caller_dtls.pin_peer_fingerprint(format!("sha-256 {fp_hex}"));
    let mut caller_sock = agent.into_socket();
    tokio::time::timeout(Duration::from_secs(10), async {
        caller_dtls
            .handshake_udp(&mut caller_sock, pair.remote, |_, _| {})
            .await
    })
    .await
    .expect("dtls handshake timed out")
    .expect("dtls handshake failed");

    // ---- SCTP phase: caller = association responder (even streams) ----
    let sctp_cfg = SctpConfig {
        is_client: false,
        local_port: 5000,
        remote_port: 5000,
        mtu: 1200,
        ..SctpConfig::default()
    };
    let mut sctp = SctpEndpoint::new_server(sctp_cfg);
    let mut app_buf = vec![0u8; 65_535];
    let mut echoes: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut acked_streams: Vec<u16> = Vec::new();

    // Drive loop: inbound UDP → DTLS → SCTP; SCTP out → DTLS → UDP; timers.
    async fn sctp_out(
        sctp: &mut SctpEndpoint,
        dtls: &mut DtlsEndpoint,
        sock: &UdpSocket,
        remote: std::net::SocketAddr,
    ) {
        for pkt in sctp.drain_outbound() {
            if dtls.send_app_data(&pkt).is_ok() {
                for d in dtls.take_outbound() {
                    let _ = sock.send_to(&d, remote).await;
                }
            }
        }
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut established = false;
    let mut opened = false;
    let tests: Vec<(u32, Vec<u8>)> = vec![
        (51, b"hello-dc".to_vec()),
        (51, vec![0xABu8; 500]),
        // 2000 B > MTU 1200: the association fragments it (RFC 8261 §3.2),
        // the receiver reassembles — over the DTLS seam end to end.
        (53, (0..2000).map(|i| (i % 251) as u8).collect()),
    ];
    let mut sent: Vec<(u32, Vec<u8>)> = Vec::new();

    while Instant::now() < deadline && (echoes.len() < tests.len() || !established) {
        // Inbound: UDP → DTLS → SCTP events.
        let recv = timeout(Duration::from_millis(60), caller_sock.recv_from(&mut buf)).await;
        match recv {
            Ok(Ok((n, _))) if n > 0 => {
                match buf[0] {
                    0..=3 => {} // STUN keepalive
                    20..=63 => {
                        caller_dtls.push_datagram(buf[..n].to_vec());
                        loop {
                            match caller_dtls.recv_app_data(&mut app_buf) {
                                Ok(Some(k)) if k > 0 => {
                                    let now = Instant::now();
                                    for ev in sctp.handle_packet(&app_buf[..k], now) {
                                        match ev {
                                            SctpEvent::Established => established = true,
                                            SctpEvent::DataChannelAck { stream } => {
                                                acked_streams.push(stream);
                                            }
                                            SctpEvent::Message {
                                                stream: _,
                                                ppid,
                                                data,
                                                ..
                                            } => {
                                                echoes.push((ppid, data));
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                _ => break,
                            }
                        }
                    }
                    _ => {} // SRTP/RTCP — audio phase handles those later
                }
            }
            _ => {}
        }
        // Timers (association retransmissions if any early datagram strays).
        for ev in sctp.on_timeout(Instant::now()) {
            match ev {
                SctpEvent::Established => established = true,
                SctpEvent::Message {
                    stream: _,
                    ppid,
                    data,
                    ..
                } => {
                    echoes.push((ppid, data));
                }
                _ => {}
            }
        }
        sctp_out(&mut sctp, &mut caller_dtls, &caller_sock, pair.remote).await;

        // Established → open the channel (responder: first EVEN id), then
        // send the probe messages once the channel is acked.
        if established && !opened {
            let stream = sctp
                .open_data_channel("chat", "", ChannelType::Reliable, Instant::now())
                .expect("open data channel once established");
            assert_eq!(
                stream, 0,
                "association responder uses even ids (RFC 8832 §6)"
            );
            opened = true;
        }
        if opened && !acked_streams.is_empty() && sent.is_empty() {
            for (ppid, data) in &tests {
                sctp.send_message(0, *ppid, data.clone(), Instant::now())
                    .expect("send on the open channel");
                sent.push((*ppid, data.clone()));
            }
        }
    }

    assert!(established, "SCTP association never established");
    assert!(
        acked_streams.contains(&0),
        "peer must ack our DCEP OPEN: {acked_streams:?}"
    );
    assert_eq!(
        echoes.len(),
        tests.len(),
        "all messages must echo back: got {echoes:?}"
    );
    for ((ppid, data), (epid, edata)) in echoes.iter().zip(tests.iter()) {
        assert_eq!(ppid, epid, "echo preserves the PPID");
        assert_eq!(data, edata, "echo preserves the payload byte-for-byte");
    }

    // ---- audio phase: SRTP media coexists on the same socket ----
    let keying = caller_dtls.export_srtp_keys().unwrap();
    let (mut tx_sess, mut rx_sess) = keying.sessions(false).unwrap();
    let pcm = tone_pcm(440.0, 8000, 4800); // 600 ms
    let mut enc = Registry::encoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut dec = Registry::decoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut seq: u16 = 300;
    let mut ts: u32 = 500;
    let mut decoded = 0usize;
    let frames: Vec<Vec<i16>> = pcm.chunks(160).map(|f| f.to_vec()).collect();
    for frame in &frames {
        let mut wire = Vec::new();
        enc.encode(frame, &mut wire).unwrap();
        let pkt = RtpPacket::new(0, seq, ts, 0xDACEE, false, bytes::Bytes::from(wire));
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(160);
        let mut datagram = pkt.encode();
        tx_sess.protect(&mut datagram).unwrap();
        caller_sock.send_to(&datagram, pair.remote).await.unwrap();

        let mut seen = 0usize;
        while decoded < 400 && seen < 200 {
            seen += 1;
            match timeout(Duration::from_millis(30), caller_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) if n > 0 => {
                    match buf[0] {
                        0..=3 | 20..=63 => continue,
                        _ => {}
                    }
                    if rtp::looks_like_rtcp(&buf[..n]) {
                        continue;
                    }
                    let mut media = buf[..n].to_vec();
                    if rx_sess.unprotect(&mut media).is_ok() {
                        if let Ok(rp) = RtpPacket::parse(&media) {
                            if rp.payload_type() == 0 {
                                let mut out = Vec::new();
                                let _ = dec.decode(rp.payload.as_ref(), &mut out);
                                decoded += out.len();
                            }
                        }
                    }
                }
                _ => break,
            }
        }
    }
    assert!(
        decoded > 400,
        "SRTP audio must still flow while the data-channel association is up"
    );

    // ---- BYE ----
    tokio::time::sleep(Duration::from_millis(300)).await;
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
    .call_id(Some("webrtc-datachan-1"))
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

    let (acks, _b_frames) = timeout(Duration::from_secs(15), b_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(acks, 1, "leg B must receive ACK");

    // ---- CDR trail ----
    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = drain_cdr(&mut cdr_rx).await;
    let ended = events
        .iter()
        .any(|e| matches!(e, CdrEvent::CallEnded { .. }));
    assert!(ended, "CDR trail must complete: {} events", events.len());
}
