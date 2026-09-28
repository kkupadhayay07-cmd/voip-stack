//! The loopback sink: a minimal in-process UAS that answers INVITEs (the
//! B2BUA's leg B target in the demo topology), receives the bridged RTP,
//! decodes it to linear PCM and taps every 20 ms frame into an `ai-bridge`
//! session (VAD / barge-in event stream). One CDR-relevant call can land
//! here at a time per Call-ID; multiple concurrent calls are supported.

use ai_bridge::{AiEvent, AiSession};
use codecs::{CodecId, Registry, Resampler};
use rtp::packet::RtpPacket;
use sdp::negotiate::stream_plans;
use sip_core::builder::respond_to;
use sip_core::ids::new_tag;
use sip_core::message::{Method, Request, SipMessage};
use sip_core::serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use b2bua::sdp_util;

/// Codecs the sink is willing to answer with (in preference order).
const SINK_CODECS: [CodecId; 5] = [
    CodecId::Pcmu,
    CodecId::Pcma,
    CodecId::G722,
    CodecId::G729,
    CodecId::Opus,
];

/// A call with no RTP on its media socket for this long (and no BYE) is
/// reaped: the call entry is dropped and the media task is stopped. Without
/// this, a peer that vanished without a BYE leaked the entry and the task
/// forever (audit 2.7).
const RTP_IDLE: Duration = Duration::from_secs(60);

/// How often the idle sweep runs.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

struct SinkCall {
    answer_sdp: String,
    tag: String,
    remote_sip: SocketAddr,
    stop: watch::Sender<bool>,
    /// Milliseconds since sink start of the last RTP datagram (0 = call
    /// answered, nothing received yet).
    last_rtp: Arc<AtomicU64>,
}

pub async fn run(bind: SocketAddr, host: String, ai_enabled: bool) -> Result<(), String> {
    run_with(bind, host, ai_enabled, RTP_IDLE, SWEEP_EVERY).await
}

/// Like [`run`] with the idle-reap windows injectable (test hook).
pub async fn run_with(
    bind: SocketAddr,
    host: String,
    ai_enabled: bool,
    rtp_idle: Duration,
    sweep_every: Duration,
) -> Result<(), String> {
    let sip = Arc::new(UdpSocket::bind(bind).await.map_err(|e| e.to_string())?);
    tracing::info!("loopback sink listening on {bind}");

    let mut buf = vec![0u8; 65_535];
    let mut calls: HashMap<String, SinkCall> = HashMap::new();
    let started = Instant::now();
    let mut sweep = tokio::time::interval(sweep_every);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            r = sip.recv_from(&mut buf) => {
                let (n, src) = r.map_err(|e| format!("sink recv: {e}"))?;
                let msg = match sip_core::parse_message(&buf[..n]) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!(%src, "sink unparseable: {e}");
                        continue;
                    }
                };
                let req = match msg {
                    SipMessage::Request(r) => r,
                    SipMessage::Response(_) => continue,
                };
                let call_id = req.headers.call_id().unwrap_or("").to_string();
                match req.method {
                    Method::Invite => {
                        handle_invite(
                            sip.as_ref(),
                            &req,
                            src,
                            call_id,
                            &host,
                            ai_enabled,
                            &mut calls,
                            &started,
                        )
                        .await;
                    }
                    Method::Ack => {
                        // Media already flowing (the RTP task starts with the 200).
                    }
                    Method::Bye => {
                        let ok = respond_to(&req, 200, "OK", Vec::new(), None);
                        let _ = sip
                            .send_to(&serialize(&SipMessage::Response(ok)), src)
                            .await;
                        if let Some(c) = calls.remove(&call_id) {
                            let _ = c.stop.send(true);
                            tracing::info!(%call_id, "sink call ended (BYE)");
                        }
                    }
                    Method::Cancel => {
                        let ok = respond_to(&req, 200, "OK", Vec::new(), None);
                        let _ = sip
                            .send_to(&serialize(&SipMessage::Response(ok)), src)
                            .await;
                        if let Some(c) = calls.remove(&call_id) {
                            let _ = c.stop.send(true);
                        }
                    }
                    Method::Options => {
                        let ok = respond_to(&req, 200, "OK", Vec::new(), None);
                        let _ = sip
                            .send_to(&serialize(&SipMessage::Response(ok)), src)
                            .await;
                    }
                    _ => {}
                }
            }
            _ = sweep.tick() => {
                // Reap calls whose media went silent without a BYE: drop
                // the entry and stop the media task (bounded resources).
                let now_ms = started.elapsed().as_millis() as u64;
                calls.retain(|id, c| {
                    let last = c.last_rtp.load(Ordering::Relaxed);
                    if now_ms.saturating_sub(last) > rtp_idle.as_millis() as u64 {
                        let _ = c.stop.send(true);
                        tracing::info!(%id, "sink call reaped (no RTP for {rtp_idle:?}, no BYE)");
                        false
                    } else {
                        true
                    }
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_invite(
    sip: &UdpSocket,
    req: &Request,
    src: SocketAddr,
    call_id: String,
    host: &str,
    ai_enabled: bool,
    calls: &mut HashMap<String, SinkCall>,
    started: &Instant,
) {
    // Retransmission: resend the cached 200.
    if let Some(c) = calls.get(&call_id) {
        if c.remote_sip == src {
            let mut ok = respond_to(
                req,
                200,
                "OK",
                c.answer_sdp.clone().into_bytes(),
                Some(&c.tag),
            );
            ok.headers.add("Contact", contact_value(host));
            let _ = sip
                .send_to(&serialize(&SipMessage::Response(ok)), src)
                .await;
            return;
        }
    }

    // SDP offer required.
    let offer = match sdp::parse::parse(&String::from_utf8_lossy(&req.body)) {
        Ok(o) => o,
        Err(e) => {
            tracing::info!(%call_id, "sink: INVITE without SDP: {e}");
            let bad = respond_to(req, 488, "Not Acceptable Here", Vec::new(), None);
            let _ = sip
                .send_to(&serialize(&SipMessage::Response(bad)), src)
                .await;
            return;
        }
    };

    // Bind the RTP socket and negotiate.
    let rtp = match UdpSocket::bind(("127.0.0.1", 0)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(%call_id, "sink rtp bind failed: {e}");
            return;
        }
    };
    let rtp_port = rtp.local_addr().map(|a| a.port()).unwrap_or(0);
    let answer = match sdp_util::answer(&offer, host, rtp_port, &SINK_CODECS) {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(%call_id, "sink: SDP negotiation failed: {e:?}");
            let bad = respond_to(req, 488, "Not Acceptable Here", Vec::new(), None);
            let _ = sip
                .send_to(&serialize(&SipMessage::Response(bad)), src)
                .await;
            return;
        }
    };
    let plan = match stream_plans(&answer).into_iter().next() {
        Some(p) => p,
        None => {
            let bad = respond_to(req, 488, "Not Acceptable Here", Vec::new(), None);
            let _ = sip
                .send_to(&serialize(&SipMessage::Response(bad)), src)
                .await;
            return;
        }
    };
    let answer_text = answer.serialize();

    let tag = new_tag();
    let mut ok = respond_to(req, 200, "OK", answer_text.clone().into_bytes(), Some(&tag));
    ok.headers.add("Contact", contact_value(host));
    let _ = sip
        .send_to(&serialize(&SipMessage::Response(ok)), src)
        .await;

    // Negotiated codec + its RTP clock drive the echo stream: the echo
    // timestamp step follows the clock (20 ms in samples — 160 @ 8 kHz,
    // 960 @ 48 kHz for Opus), not a hardcoded 8 kHz value.
    let negotiated = plan
        .codec
        .as_ref()
        .and_then(|(n, c, _)| sdp_util::codec_id_for(n, *c).map(|id| (id, *c)));
    let codec = negotiated.map(|(id, _)| id);
    let clock_hz = negotiated.map(|(_, c)| c).unwrap_or(8_000);
    let echo_step = (u64::from(clock_hz) * 20 / 1000) as u32;
    // Audio PT as offered in OUR answer — telephone-event / CN packets must
    // not enter (or corrupt) the echo stream.
    let audio_pt = if plan.codec.is_some() {
        Some(plan.local_pt)
    } else {
        None
    };

    // Spawn the media tap: RTP → decode → 16 kHz mono → ai-bridge session.
    let (stop_tx, stop) = watch::channel(false);
    let last_rtp = Arc::new(AtomicU64::new(0));
    calls.insert(
        call_id.clone(),
        SinkCall {
            answer_sdp: answer_text,
            tag,
            remote_sip: src,
            stop: stop_tx,
            last_rtp: Arc::clone(&last_rtp),
        },
    );
    tracing::info!(
        %call_id,
        "sink call answered (codec {codec:?}, rtp port {rtp_port})"
    );
    tokio::spawn(rtp_tap(
        call_id, rtp, codec, echo_step, audio_pt, ai_enabled, stop, last_rtp, *started,
    ));
}

/// Per-call RTP receiver feeding the ai-bridge session.
#[allow(clippy::too_many_arguments)]
async fn rtp_tap(
    call_id: String,
    rtp: Arc<UdpSocket>,
    codec: Option<CodecId>,
    echo_step: u32,
    audio_pt: Option<u8>,
    ai_enabled: bool,
    mut stop: watch::Receiver<bool>,
    last_rtp: Arc<AtomicU64>,
    started: Instant,
) {
    let mut dec = codec.and_then(|id| {
        let rate = match id {
            CodecId::G722 => 16_000,
            CodecId::Opus => 48_000,
            _ => 8_000,
        };
        Registry::decoder(id, rate, 1).ok().map(|d| (d, rate))
    });
    let mut resampler = dec.as_ref().and_then(|(_, rate)| {
        if *rate == 16_000 {
            None
        } else {
            Resampler::new(*rate, 16_000, 1).ok()
        }
    });
    let mut ai = if ai_enabled {
        let (s, ev) = AiSession::new(&call_id);
        Some((s, ev))
    } else {
        None
    };

    let mut buf = vec![0u8; 4096];
    let mut pcm_out = Vec::with_capacity(2048);
    // The sink is a distinct RTP endpoint with its own stream identity:
    // SSRC drawn once per task, seq/ts seeded randomly and advanced locally.
    let echo_ssrc: u32 = rand::random();
    let mut echo_seq: u16 = rand::random();
    let mut echo_ts: u32 = rand::random();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            r = rtp.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                // Any datagram on this call's media socket is activity.
                last_rtp.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                if rtp::looks_like_rtcp(&buf[..n]) {
                    continue;
                }
                let Ok(pkt) = RtpPacket::parse(&buf[..n]) else { continue };
                // PT filter FIRST (audit 2.7): only the negotiated audio
                // codec is echoed and advanced — telephone-event / CN
                // packets must not enter the echo stream (they used to be
                // echoed with the audio stream's seq/ts, corrupting it).
                if let Some(pt) = audio_pt {
                    if pkt.payload_type() != pt {
                        continue;
                    }
                }
                // Bi-directional echo: rebuild the packet with our own stream
                // identity (SSRC/seq/ts) and send it back to the pump's source
                // address. Never echo raw bytes — the peer's jitter buffer must
                // not see its own SSRC reflected back.
                let echo = RtpPacket::new(
                    pkt.payload_type(),
                    echo_seq,
                    echo_ts,
                    echo_ssrc,
                    pkt.header.marker,
                    bytes::Bytes::copy_from_slice(&pkt.payload),
                );
                echo_seq = echo_seq.wrapping_add(1);
                echo_ts = echo_ts.wrapping_add(echo_step); // 20 ms in stream clock
                let _ = rtp.send_to(&echo.encode(), src).await;
                let Some((dec, _)) = dec.as_mut() else {
                    continue;
                };
                let mut pcm = Vec::with_capacity(2048);
                if dec.decode(&pkt.payload, &mut pcm).is_err() {
                    continue;
                }
                pcm_out.clear();
                match resampler.as_mut() {
                    Some(rs) => {
                        rs.process(&pcm, &mut pcm_out);
                    }
                    None => pcm_out.extend_from_slice(&pcm),
                }
                if let Some((session, ev)) = ai.as_mut() {
                    session.caller_audio(&pcm_out).await;
                    while let Ok(event) = ev.try_recv() {
                        match event {
                            AiEvent::SpeechStart => {
                                tracing::info!(%call_id, "ai-bridge: caller speech start");
                            }
                            AiEvent::SpeechEnd => {
                                tracing::info!(%call_id, "ai-bridge: caller speech end");
                            }
                            AiEvent::BargeIn => {
                                tracing::info!(%call_id, "ai-bridge: barge-in");
                            }
                            AiEvent::Ended { reason } => {
                                tracing::info!(%call_id, "ai-bridge: ended ({reason})");
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    tracing::debug!(%call_id, "sink rtp tap stopped");
}

/// The sink's Contact header value: our own host, never the remote peer's
/// source address (audit 2.7 — in-dialog requests were pointed back at the
/// peer itself).
fn contact_value(host: &str) -> String {
    format!("<sip:sink@{host}>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_uses_our_host_not_the_peer() {
        assert_eq!(contact_value("zrtc.local"), "<sip:sink@zrtc.local>");
        assert_eq!(contact_value("127.0.0.1:5090"), "<sip:sink@127.0.0.1:5090>");
    }

    /// Echo timestamp step = 20 ms in the stream's clock: 160 @ 8 kHz,
    /// 960 @ 48 kHz (Opus) — the step used to be hardcoded to 160.
    #[test]
    fn echo_step_follows_negotiated_clock() {
        let step = |clock: u32| (u64::from(clock) * 20 / 1000) as u32;
        assert_eq!(step(8_000), 160);
        assert_eq!(step(48_000), 960);
    }

    const CALL_ID: &str = "sinktest@x";

    fn invite(local_port: u16, offer: &str) -> Vec<u8> {
        let mut sdp = String::new();
        for line in offer.lines() {
            sdp.push_str(line);
            sdp.push_str("\r\n");
        }
        let msg = format!(
            "INVITE sip:sink@127.0.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:{local_port};branch=z9hG4bKtest1\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:caller@example.com>;tag=caller1\r\n\
             To: <sip:sink@127.0.0.1>\r\n\
             Call-ID: {CALL_ID}\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:caller@127.0.0.1:{local_port}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n",
            sdp.len()
        );
        let mut out = msg.into_bytes();
        out.extend_from_slice(sdp.as_bytes());
        out
    }

    async fn recv_ok(sock: &UdpSocket) -> sip_core::message::Response {
        let mut buf = vec![0u8; 65_535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("response within 2s")
            .expect("recv ok");
        match sip_core::parse_message(&buf[..n]).expect("parse response") {
            SipMessage::Response(r) => r,
            SipMessage::Request(_) => panic!("expected a response"),
        }
    }

    fn to_tag(resp: &sip_core::message::Response) -> String {
        resp.headers
            .to()
            .and_then(|t| t.tag.clone())
            .expect("To tag in 200")
    }

    async fn read_echo(sock: &UdpSocket) -> RtpPacket {
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("echo within 2s")
            .expect("recv ok");
        RtpPacket::parse(&buf[..n]).expect("echo is RTP")
    }

    /// End-to-end sink behavior: Contact uses OUR host; INVITE
    /// retransmission gets the cached 200; only the negotiated audio PT is
    /// echoed (never telephone-event); the echo ts step follows the
    /// negotiated clock; a call with no RTP and no BYE is reaped.
    #[tokio::test]
    async fn sink_answer_echo_filter_and_reaper() {
        let host = "127.0.0.1:5099";
        // Take a free ephemeral port for the sink, then release it so
        // run_with can bind it.
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = probe.local_addr().unwrap();
        drop(probe);
        tokio::spawn(run_with(
            sink_addr,
            host.to_string(),
            false,
            Duration::from_millis(250),
            Duration::from_millis(50),
        ));

        let caller = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caller_addr = caller.local_addr().unwrap();

        let offer = |port: u16| {
            format!(
                "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=call\r\n\
                 c=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                 m=audio {port} RTP/AVP 0 101\r\n\
                 a=rtpmap:0 PCMU/8000\r\n\
                 a=rtpmap:101 telephone-event/8000\r\n\
                 a=sendrecv\r\n"
            )
        };

        // The offer advertises the CALLER's RTP port; bind it first so the
        // echo has somewhere to go.
        let media = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let media_port = media.local_addr().unwrap().port();
        let local_port = caller_addr.port();
        let wire = invite(local_port, &offer(media_port));
        caller.send_to(&wire, sink_addr).await.unwrap();

        let ok1 = recv_ok(&caller).await;
        assert_eq!(ok1.code, 200, "first INVITE answered");
        let contact = ok1.headers.get("Contact").expect("Contact present");
        assert!(
            contact.contains("sink@127.0.0.1:5099"),
            "Contact must use OUR host, was: {contact}"
        );
        let tag1 = to_tag(&ok1);

        // Answer SDP gives the sink's media port.
        let answer_text = String::from_utf8(ok1.body.clone()).unwrap();
        let answer = sdp::parse::parse(&answer_text).unwrap();
        let sink_media_port = answer.medias[0].port;

        // Retransmitted INVITE → cached 200, same tag.
        caller.send_to(&wire, sink_addr).await.unwrap();
        let ok2 = recv_ok(&caller).await;
        assert_eq!(to_tag(&ok2), tag1, "retransmission reuses the cached 200");

        // Audio (PT 0) echoes with our stream identity and the 8 kHz step.
        let send_rtp = |seq: u16, ts: u32, pt: u8| {
            let mut p = RtpPacket::new(
                pt,
                seq,
                ts,
                0x1234,
                false,
                bytes::Bytes::from(vec![0x55u8; 160]),
            );
            p.header.csrcs.clear();
            p.encode()
        };
        media
            .send_to(
                &send_rtp(1, 1000, 0),
                format!("127.0.0.1:{sink_media_port}")
                    .parse::<SocketAddr>()
                    .unwrap(),
            )
            .await
            .unwrap();
        media
            .send_to(
                &send_rtp(2, 1160, 0),
                format!("127.0.0.1:{sink_media_port}")
                    .parse::<SocketAddr>()
                    .unwrap(),
            )
            .await
            .unwrap();

        let e1 = read_echo(&media).await;
        let e2 = read_echo(&media).await;
        assert_eq!(e1.payload_type(), 0);
        assert_ne!(e1.header.ssrc, 0x1234, "echo uses the sink's own SSRC");
        assert_eq!(
            e2.header.timestamp.wrapping_sub(e1.header.timestamp),
            160,
            "echo ts step = 20 ms @ 8 kHz"
        );

        // telephone-event (PT 101) must NOT echo — PT filter first.
        media
            .send_to(
                &send_rtp(3, 5000, 101),
                format!("127.0.0.1:{sink_media_port}")
                    .parse::<SocketAddr>()
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(150), media.recv_from(&mut buf))
                .await
                .is_err(),
            "telephone-event must not be echoed"
        );

        // No RTP for the idle window + no BYE → the call is reaped; the
        // next INVITE is a NEW call with a fresh tag.
        tokio::time::sleep(Duration::from_millis(500)).await;
        caller.send_to(&wire, sink_addr).await.unwrap();
        let ok3 = recv_ok(&caller).await;
        assert_ne!(
            to_tag(&ok3),
            tag1,
            "reaped call must be answered as a new call"
        );
    }
}
