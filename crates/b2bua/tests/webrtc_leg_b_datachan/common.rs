//! Shared harness for the leg-B data-channel (RFC 8841 offerer side)
//! integration binaries:
//!
//! mini WebRTC caller (leg A: SAVPF audio + m=application offer, ICE
//! controlling, DTLS server, SCTP responder opening ODD streams) → B2BUA
//! (mirrors the data channel into the leg-B offer per RFC 8841) → mini
//! WebRTC callee (leg B: answers both m-lines, DTLS client, SCTP INITIATOR
//! opening EVEN streams per RFC 8832 §5.1/§6).
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
use sctp::{ChannelType, SctpConfig, SctpEndpoint, SctpEvent};
use sip_core::builder::RequestBuilder;
use sip_core::message::{Method, SipMessage};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{parse_message, serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
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

pub fn local_tag_of(resp: &sip_core::message::Response) -> String {
    resp.headers
        .get("To")
        .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
        .and_then(|n| n.tag)
        .unwrap_or_default()
}

pub fn sdp_attr(sdp: &str, name: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.strip_prefix(&format!("a={name}:")))
        .map(str::to_string)
}

pub fn sdp_attrs(sdp: &str, name: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix(&format!("a={name}:")))
        .map(str::to_string)
        .collect()
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

/// What the leg-B callee does with the offered `m=application` m-line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcMode {
    /// Accept it: mirror proto/format + sctp-port/max-message-size.
    Accept,
    /// Reject it the RFC 3264 §6 way: port 0, audio continues.
    Reject,
}

/// The leg-B mini WebRTC callee with a data channel. Validates the B2BUA's
/// offer (audio + application m-lines, RFC 8841 attributes), answers both
/// m-lines, runs ICE (controlled) → DTLS (role per `setup`) → SRTP PCMA
/// echo, and — when `dc` is [`DcMode::Accept`] — drives the SCTP
/// association as the DTLS client / INITIATOR (opening EVEN streams, RFC
/// 8832 §5.1/§6) while the B2BUA's engine echoes our messages back.
pub struct CalleeResult {
    pub decoded_len: usize,
    /// (ppid, payload) of the echoes that came back over leg B's channel.
    pub echoes: Vec<(u32, Vec<u8>)>,
    pub dc_up: bool,
    pub got_bye: bool,
}

pub async fn run_webrtc_callee_dc(
    sock: UdpSocket,
    setup: &'static str,
    dc: DcMode,
) -> CalleeResult {
    let mut buf = vec![0u8; 65_535];
    let mut got_ack = false;
    let mut got_bye = false;
    let mut offer_fingerprint = String::new();

    // Own transport, prepared up front (gathering is async-free).
    let mut agent = IceAgent::new(AgentConfig {
        controlling: Some(false),
        ..AgentConfig::default()
    })
    .await
    .unwrap();
    agent.gather_host().unwrap();
    let identity = dtls::Identity::generate("webrtc-callee-dc").unwrap();
    let local_port = agent.local_addr().unwrap().port();
    let cands = agent.local_candidates_sdp();

    // ---- SIP: INVITE (validate the offer) → 200 (audio + application) ----
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            r = sock.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                let Ok(msg) = parse_message(&buf[..n]) else { continue };
                match msg {
                    SipMessage::Request(req) => match req.method {
                        Method::Invite => {
                            let offer =
                                sdp::parse::parse(&String::from_utf8_lossy(&req.body)).unwrap();
                            // Audio m-line: SAVPF + transport block.
                            let m = &offer.medias[0];
                            assert_eq!(m.proto, "UDP/TLS/RTP/SAVPF", "leg B offer must be SAVPF");
                            assert_eq!(m.setup, Some(sdp::types::SetupRole::Actpass));
                            let fp = m.fingerprint.as_ref().expect("offer fingerprint");
                            assert_eq!(fp.hash_func, "sha-256");
                            assert!(m.ice_ufrag.is_some() && m.ice_pwd.is_some());
                            assert!(!m.ice_candidates.is_empty());
                            assert!(m.rtcp_mux, "offer is rtcp-mux (the pump is mux-only)");
                            offer_fingerprint = format!("{} {}", fp.hash_func, fp.value);

                            // RFC 8841: the offer MUST carry the mirrored
                            // data-channel m-line (the caller offered one).
                            assert_eq!(offer.medias.len(), 2, "offer: audio + application");
                            let app = &offer.medias[1];
                            assert_eq!(app.media, "application");
                            assert_eq!(app.proto, "UDP/DTLS/SCTP");
                            assert_eq!(app.formats, vec!["webrtc-datachannel".to_string()]);
                            assert!(app.port > 0, "application m-line must be live");
                            let sctp_port = app
                                .attributes
                                .iter()
                                .find(|a| a.name == "sctp-port")
                                .and_then(|a| a.value.as_deref())
                                .expect("offer a=sctp-port");
                            assert_eq!(sctp_port, "5000");
                            assert!(
                                app.attributes
                                    .iter()
                                    .any(|a| a.name == "max-message-size"),
                                "offer a=max-message-size"
                            );
                            assert_eq!(app.setup, Some(sdp::types::SetupRole::Actpass));
                            assert!(app.fingerprint.is_some() && app.ice_ufrag.is_some());
                            // RFC 8843/5888: the bundled offer groups both
                            // m-lines with mids.
                            assert_eq!(app.mid.as_deref(), Some("1"));
                            assert_eq!(m.mid.as_deref(), Some("0"));
                            assert_eq!(
                                offer.bundle.as_ref().map(|g| g.mids.join(" ")),
                                Some("0 1".into())
                            );

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
                                dc,
                            );
                            let ok = sip_core::builder::respond_to(
                                &req, 200, "OK", answer.into_bytes(), Some("tagCallee"),
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

    // ---- ICE (controlled; the B2BUA nominates) + DTLS per the setup ----
    let pair = agent
        .connect(Duration::from_secs(8))
        .await
        .expect("callee ICE connectivity failed");
    let mut media_sock = agent.into_socket();
    let role = match setup {
        // We answered active → we are the DTLS client (RFC 5763 §5).
        "active" => DtlsRole::Client,
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

    // ---- SCTP: the DTLS client initiates the association and opens the
    // first EVEN channel (RFC 8832 §5.1/§6); the B2BUA's leg-B engine (DTLS
    // server) answers the INIT and acks our OPEN. ----
    let mut sctp = if dc == DcMode::Accept {
        let cfg = SctpConfig {
            is_client: true,
            local_port: 5000,
            remote_port: 5000,
            mtu: 1200,
            ..SctpConfig::default()
        };
        Some(SctpEndpoint::new_client(cfg, Instant::now()).unwrap())
    } else {
        None
    };
    // The INITIATOR must flush its queued INIT immediately — nothing else
    // drains the outbox before the association comes up.
    if let Some(s) = sctp.as_mut() {
        sctp_out(s, &mut dtls, &media_sock, pair.remote).await;
    }
    let mut app_buf = vec![0u8; 65_535];
    let mut echoes: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut dc_up = false;
    let mut opened = false;
    let mut acked = false;
    let mut sent = false;
    let tests: Vec<(u32, Vec<u8>)> = vec![
        (51, b"leg-b-dc-hello".to_vec()),
        // 2000 B > MTU 1200: fragmented by the association, reassembled at
        // the B2BUA, echoed back and reassembled here.
        (53, (0..2000).map(|i| (i % 251) as u8).collect()),
    ];

    // ---- combined media + data-channel loop ----
    let mut decoded: Vec<i16> = Vec::new();
    let mut dec = Registry::decoder(codecs::CodecId::Pcma, 8000, 1).unwrap();
    let mut echo_seq: u16 = 9000;
    let mut echo_ts: u32 = 70_000;
    let mut rbuf = vec![0u8; 4096];
    let media_deadline = tokio::time::Instant::now() + Duration::from_secs(14);
    // Periodic SCTP outbox drain (INIT retransmissions, delayed replies).
    let mut sctp_tick = tokio::time::interval(Duration::from_millis(200));
    sctp_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let need_more_audio = decoded.len() <= 1200;
        let dc_done = dc == DcMode::Reject || echoes.len() >= tests.len();
        if (got_bye && !need_more_audio && dc_done) || tokio::time::Instant::now() > media_deadline
        {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(media_deadline) => break,
            _ = sctp_tick.tick() => {
                if let Some(s) = sctp.as_mut() {
                    sctp_out(s, &mut dtls, &media_sock, pair.remote).await;
                }
            }
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
                match rbuf[0] {
                    // STUN keepalives.
                    0..=3 => continue,
                    // DTLS records: feed the association when one is open.
                    20..=63 => {
                        if let Some(s) = sctp.as_mut() {
                            dtls.push_datagram(rbuf[..n].to_vec());
                            loop {
                                match dtls.recv_app_data(&mut app_buf) {
                                    Ok(Some(k)) if k > 0 => {
                                        let now = Instant::now();
                                        for ev in s.handle_packet(&app_buf[..k], now) {
                                            match ev {
                                                SctpEvent::Established => dc_up = true,
                                                SctpEvent::DataChannelAck { stream } => {
                                                    assert_eq!(stream, 0, "our EVEN channel acked");
                                                    acked = true;
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
                            // Push the association forward + echo replies.
                            sctp_out(s, &mut dtls, &media_sock, pair.remote).await;
                        }
                    }
                    // SRTP/RTCP media.
                    _ => {
                        if rtp::looks_like_rtcp(&rbuf[..n]) {
                            continue;
                        }
                        let mut media = rbuf[..n].to_vec();
                        if rx_sess.unprotect(&mut media).is_ok() {
                            if let Ok(pkt) = RtpPacket::parse(&media) {
                                if pkt.payload_type() == 8 && need_more_audio {
                                    let mut pcm: Vec<i16> = Vec::new();
                                    let _ = dec.decode(&pkt.payload, &mut pcm);
                                    decoded.extend_from_slice(&pcm);
                                    let echo = RtpPacket::new(
                                        8,
                                        echo_seq,
                                        echo_ts,
                                        0xB4C0_00DC,
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
            }
        }
        // Drive the association: open the channel, then send the probes.
        if let Some(s) = sctp.as_mut() {
            if dc_up && !opened {
                let stream = s
                    .open_data_channel("chat", "", ChannelType::Reliable, Instant::now())
                    .expect("open data channel once established");
                assert_eq!(
                    stream, 0,
                    "DTLS client (association initiator) opens EVEN ids (RFC 8832 §5.1/§6)"
                );
                opened = true;
            }
            if opened && acked && !sent {
                for (ppid, data) in &tests {
                    s.send_message(0, *ppid, data.clone(), Instant::now())
                        .expect("send on the open channel");
                }
                sent = true;
                sctp_out(s, &mut dtls, &media_sock, pair.remote).await;
            }
        }
    }

    CalleeResult {
        decoded_len: decoded.len(),
        echoes,
        dc_up,
        got_bye,
    }
}

async fn sctp_out(
    sctp: &mut SctpEndpoint,
    dtls: &mut DtlsEndpoint,
    sock: &UdpSocket,
    remote: SocketAddr,
) {
    for pkt in sctp.drain_outbound() {
        if dtls.send_app_data(&pkt).is_ok() {
            for d in dtls.take_outbound() {
                let _ = sock.send_to(&d, remote).await;
            }
        }
    }
}

/// The callee's answer: SAVPF audio + the `m=application` m-line (accepted
/// or port-0-rejected per `dc`), `setup` per the parameter, PCMA audio.
pub fn callee_answer_sdp(
    port: u16,
    ufrag: &str,
    pwd: &str,
    fp: &str,
    cands: &[String],
    setup: &str,
    dc: DcMode,
) -> String {
    let app_port = match dc {
        DcMode::Accept => port,
        DcMode::Reject => 0,
    };
    let transport = format!(
        "a=setup:{setup}\r\n\
         a=fingerprint:sha-256 {fp}\r\n\
         a=ice-ufrag:{ufrag}\r\n\
         a=ice-pwd:{pwd}\r\n\
         {cands}",
        cands = cands
            .iter()
            .map(|c| format!("a={c}\r\n"))
            .collect::<String>(),
    );
    format!(
        "v=0\r\n\
         o=callee 7 7 IN IP4 127.0.0.1\r\n\
         s=webrtc-callee-dc\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 8 101\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=rtcp-mux\r\n\
         {transport}\
         a=sendrecv\r\n\
         m=application {app_port} UDP/DTLS/SCTP webrtc-datachannel\r\n\
         a=sctp-port:5000\r\n\
         a=max-message-size:262144\r\n\
         {transport}",
    )
}

/// The leg-A mini WebRTC caller: SAVPF audio + `m=application` offer (the
/// browser shape), SIP flow through the engine, ICE controlling, DTLS
/// SERVER (answer active), SCTP responder opening ODD streams, one probe
/// message echoed by the leg-A engine, then SRTP PCMU audio and BYE.
pub struct CallerResult {
    pub answer_sdp: String,
    pub echoes: Vec<(u32, Vec<u8>)>,
    pub dc_up: bool,
    pub decoded_len: usize,
    pub bye200: bool,
}

pub async fn run_webrtc_caller_dc(engine_addr: SocketAddr, call_id: &str) -> CallerResult {
    // ---- offer: audio SAVPF + RFC 8841 data channel ----
    let mut agent = IceAgent::new(AgentConfig {
        controlling: Some(true),
        ..AgentConfig::default()
    })
    .await
    .unwrap();
    agent.gather_host().unwrap();
    let caller_id = dtls::Identity::generate("webrtc-caller-dc").unwrap();
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
         s=webrtc-leg-b-dc\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         a=group:BUNDLE 0 1\r\n\
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
    .call_id(Some(call_id))
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

    // ---- ACK ----
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

    // ---- ICE + DTLS: caller is the SERVER (answer active) ----
    let ans_ufrag = sdp_attr(&answer_sdp, "ice-ufrag").expect("answer ice-ufrag");
    let ans_pwd = sdp_attr(&answer_sdp, "ice-pwd").expect("answer ice-pwd");
    let fp = sdp_attr(&answer_sdp, "fingerprint").expect("answer fingerprint");
    let answer_cands = sdp_attrs(&answer_sdp, "candidate");
    let remote_cands: Vec<ice::candidate::Candidate> = answer_cands
        .iter()
        .filter_map(|l| ice::candidate::Candidate::from_sdp(l).ok())
        .collect();
    assert!(!remote_cands.is_empty());
    let fp_hex = fp.trim_start_matches("sha-256 ").trim().to_string();
    agent.set_remote(&ans_ufrag, &ans_pwd, &remote_cands);
    let pair = agent
        .connect(Duration::from_secs(6))
        .await
        .expect("ICE connectivity failed");
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
    .expect("caller dtls handshake timed out")
    .expect("caller dtls handshake failed");

    // ---- SCTP: caller = association responder (DTLS server → ODD ids) ----
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
    let mut dc_up = false;
    let mut opened = false;
    let mut acked = false;
    let mut sent = false;

    async fn sctp_out(
        sctp: &mut SctpEndpoint,
        dtls: &mut DtlsEndpoint,
        sock: &UdpSocket,
        remote: SocketAddr,
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
    while Instant::now() < deadline && (echoes.is_empty() || !dc_up) {
        let recv = timeout(Duration::from_millis(60), caller_sock.recv_from(&mut buf)).await;
        if let Ok(Ok((n, _))) = recv {
            if n > 0 && (20..=63).contains(&buf[0]) {
                caller_dtls.push_datagram(buf[..n].to_vec());
                loop {
                    match caller_dtls.recv_app_data(&mut app_buf) {
                        Ok(Some(k)) if k > 0 => {
                            let now = Instant::now();
                            for ev in sctp.handle_packet(&app_buf[..k], now) {
                                match ev {
                                    SctpEvent::Established => dc_up = true,
                                    SctpEvent::DataChannelAck { stream } => {
                                        assert_eq!(stream, 1, "our ODD channel acked");
                                        acked = true;
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
        }
        for ev in sctp.on_timeout(Instant::now()) {
            match ev {
                SctpEvent::Established => dc_up = true,
                SctpEvent::Message { ppid, data, .. } => echoes.push((ppid, data)),
                _ => {}
            }
        }
        sctp_out(&mut sctp, &mut caller_dtls, &caller_sock, pair.remote).await;
        if dc_up && !opened {
            let stream = sctp
                .open_data_channel("chat", "", ChannelType::Reliable, Instant::now())
                .expect("open data channel once established");
            assert_eq!(
                stream, 1,
                "association responder (DTLS server) opens ODD ids (RFC 8832 §5.1/§6)"
            );
            opened = true;
        }
        if opened && acked && !sent {
            sctp.send_message(1, 51, b"leg-a-dc".to_vec(), Instant::now())
                .expect("send on the open channel");
            sent = true;
            sctp_out(&mut sctp, &mut caller_dtls, &caller_sock, pair.remote).await;
        }
    }

    // ---- audio phase: SRTP PCMU media coexists on the same socket ----
    let keying = caller_dtls.export_srtp_keys().unwrap();
    let (mut tx_sess, mut rx_sess) = keying.sessions(false).unwrap();
    let pcm = tone_pcm(440.0, 8000, 4800); // 600 ms
    let mut enc = Registry::encoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut dec = Registry::decoder(codecs::CodecId::Pcmu, 8000, 1).unwrap();
    let mut seq: u16 = 300;
    let mut ts: u32 = 500;
    let mut decoded = 0usize;
    for frame in pcm.chunks(160) {
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
                Ok(Ok((n, _))) if n > 0 => match buf[0] {
                    0..=3 | 20..=63 => continue,
                    _ if rtp::looks_like_rtcp(&buf[..n]) => continue,
                    _ => {
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
                },
                _ => break,
            }
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
    let mut bye200 = false;
    for _ in 0..3 {
        if let Some((msg, _)) = recv_msg(&a, &mut buf).await {
            if as_response(&msg).is_some_and(|r| r.code == 200) {
                bye200 = true;
                break;
            }
        }
    }

    // RFC 8843 §6.2: the leg-A answer echoes the caller's BUNDLE group
    // with the accepted mids, in offer order.
    assert!(
        answer_sdp.contains("a=group:BUNDLE 0 1\r\n"),
        "answer must echo the BUNDLE group: {answer_sdp}"
    );

    CallerResult {
        answer_sdp,
        echoes,
        dc_up,
        decoded_len: decoded,
        bye200,
    }
}
