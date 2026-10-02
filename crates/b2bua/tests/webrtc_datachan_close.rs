//! RFC 8831 §6.7 data-channel CLOSE over the live B2BUA leg:
//!
//! mini WebRTC caller (ICE + DTLS server + SCTP responder, odd streams) →
//! B2BUA (answers SAVPF audio + RFC 8841 data channel, runs the RFC 8261
//! SCTP association over the same DTLS transport) → plain PCMA UAS (leg B).
//!
//! After the data channel comes up and echoes messages, the CALLER closes
//! its channel with an RFC 6525 stream reset (`SctpEndpoint::close_channel`).
//! The B2BUA's leg-A engine answers with a Re-configuration Response and
//! reciprocates with its own reset (RFC 8831 §6.7), both sides surface the
//! close, a post-close send is rejected, and — the point of the test — the
//! SCTP ASSOCIATION SURVIVES the channel close: SRTP audio still bridges and
//! the CDR trail completes.

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

/// Leg B: plain PCMA UAS that ACKs and echoes audio (bounded to what the
/// post-close audio check needs).
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
        if decoded > 40 {
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
        .collect::<Vec<_>>()
        .iter()
        .map(|l| l.strip_prefix("a=").unwrap_or(l).to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webrtc_datachannel_close_via_stream_reset() {
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
         s=webrtc-datachan-close\r\n\
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
    .call_id(Some("webrtc-datachan-close-1"))
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
    assert!(
        answer_sdp.contains("m=application "),
        "answer must carry the application m-line"
    );

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
    .call_id(Some("webrtc-datachan-close-1"))
    .cseq(1)
    .build();
    a.send_to(&serialize(&SipMessage::Request(ack)), engine_addr)
        .await
        .unwrap();

    // ---- ICE ----
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

    // ---- DTLS: caller is the SERVER ----
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

    // ---- SCTP phase: caller = association responder (odd streams) ----
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
    let mut acked = false;
    let mut opened = false;
    let mut sent = false;
    let mut close_requested = false;
    let mut closed: Vec<u16> = Vec::new();
    let close_err: Option<String> = None;

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

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut established = false;
    while Instant::now() < deadline
        && (!established || !acked || echoes.len() < 2 || closed.is_empty())
    {
        let recv = timeout(Duration::from_millis(60), caller_sock.recv_from(&mut buf)).await;
        if let Ok(Ok((n, _))) = recv {
            if n > 0 {
                match buf[0] {
                    0..=3 => {}
                    20..=63 => {
                        caller_dtls.push_datagram(buf[..n].to_vec());
                        loop {
                            match caller_dtls.recv_app_data(&mut app_buf) {
                                Ok(Some(k)) if k > 0 => {
                                    let now = Instant::now();
                                    for ev in sctp.handle_packet(&app_buf[..k], now) {
                                        match ev {
                                            SctpEvent::Established => established = true,
                                            SctpEvent::DataChannelAck { .. } => acked = true,
                                            SctpEvent::DataChannelClosed { stream } => {
                                                closed.push(stream);
                                            }
                                            SctpEvent::Message { ppid, data, .. } => {
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
                    _ => {}
                }
            }
        }
        for ev in sctp.on_timeout(Instant::now()) {
            match ev {
                SctpEvent::Established => established = true,
                SctpEvent::DataChannelClosed { stream } => closed.push(stream),
                SctpEvent::Message { ppid, data, .. } => echoes.push((ppid, data)),
                _ => {}
            }
        }
        sctp_out(&mut sctp, &mut caller_dtls, &caller_sock, pair.remote).await;

        // Established → open OUR channel (responder = odd id 1), echo probes.
        if established && !opened {
            let stream = sctp
                .open_data_channel("chat", "", ChannelType::Reliable, Instant::now())
                .expect("open data channel once established");
            assert_eq!(stream, 1, "responder opens odd ids (RFC 8832 §5.1/§6)");
            opened = true;
        }
        if acked && !sent {
            sctp.send_message(1, 51, b"probe-1".to_vec(), Instant::now())
                .expect("send probe 1");
            sctp.send_message(1, 53, b"probe-2".to_vec(), Instant::now())
                .expect("send probe 2");
            sent = true;
        }
        // Both probes echoed → close the channel (RFC 8831 §6.7).
        if !close_requested && echoes.len() >= 2 {
            sctp.close_channel(1, Instant::now())
                .expect("close the channel");
            close_requested = true;
        }
    }

    assert!(
        established && acked,
        "SCTP association/channel never came up"
    );
    assert_eq!(echoes.len(), 2, "both probes must echo back: {echoes:?}");
    assert!(
        close_requested,
        "the close must have been requested after the echoes"
    );
    // The close completed through the peer's response + reciprocal reset.
    assert_eq!(
        closed,
        vec![1],
        "the caller must see its channel closed exactly once: {closed:?}"
    );
    // A send on the closed channel is rejected; the close itself is
    // idempotent-rejected (ChannelClosing).
    let resend = sctp.send_message(1, 51, b"after-close".to_vec(), Instant::now());
    assert!(resend.is_err(), "sends on a closed channel must fail");
    // The ASSOCIATION is still up — that is the point of the test.
    assert!(
        sctp.is_established() && !sctp.is_closed(),
        "the association must survive the channel close"
    );
    assert_eq!(close_err, None);
    let _ = close_err;

    // ---- audio phase: SRTP media still flows after the close ----
    let keying = caller_dtls.export_srtp_keys().unwrap();
    let (mut tx_sess, mut rx_sess) = keying.sessions(false).unwrap();
    let pcm = tone_pcm(440.0, 8000, 3200); // 400 ms
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
        while decoded < 250 && seen < 200 {
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
        decoded > 250,
        "SRTP audio must still flow after the data-channel close: {decoded}"
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
    .call_id(Some("webrtc-datachan-close-1"))
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
    assert!(
        ended,
        "CDR trail must complete after the channel close: {} events",
        events.len()
    );
}
