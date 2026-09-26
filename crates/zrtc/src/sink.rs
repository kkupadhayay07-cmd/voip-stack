//! The loopback sink: a minimal in-process UAS that answers INVITEs (the
//! B2BUA's leg B target in the demo topology), receives the bridged RTP,
//! decodes it to linear PCM and taps every 20 ms frame into an `ai-bridge`
//! session (VAD / barge-in event stream). One CDR-relevant call can land
//! here at a time per Call-ID; multiple concurrent calls are supported.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use ai_bridge::{AiEvent, AiSession};
use codecs::{CodecId, Registry, Resampler};
use rtp::packet::RtpPacket;
use sip_core::builder::respond_to;
use sip_core::ids::new_tag;
use sip_core::message::{Method, Request, SipMessage};
use sip_core::serialize;
use sdp::negotiate::stream_plans;
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

struct SinkCall {
    answer_sdp: String,
    tag: String,
    remote_sip: SocketAddr,
    stop: watch::Sender<bool>,
}

pub async fn run(bind: SocketAddr, host: String, ai_enabled: bool) -> Result<(), String> {
    let sip = Arc::new(UdpSocket::bind(bind).await.map_err(|e| e.to_string())?);
    tracing::info!("loopback sink listening on {bind}");

    let mut buf = vec![0u8; 65_535];
    let mut calls: HashMap<String, SinkCall> = HashMap::new();

    loop {
        let (n, src) = sip
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("sink recv: {e}"))?;
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
                handle_invite(sip.as_ref(), &req, src, call_id, &host, ai_enabled, &mut calls)
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
}

async fn handle_invite(
    sip: &UdpSocket,
    req: &Request,
    src: SocketAddr,
    call_id: String,
    host: &str,
    ai_enabled: bool,
    calls: &mut HashMap<String, SinkCall>,
) {
    // Retransmission: resend the cached 200.
    if let Some(c) = calls.get(&call_id) {
        if c.remote_sip == src {
            let mut ok = respond_to(req, 200, "OK", c.answer_sdp.clone().into_bytes(), Some(&c.tag));
            ok.headers
                .add("Contact", format!("<sip:sink@{src}>"));
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
    ok.headers.add("Contact", format!("<sip:sink@{src}>"));
    let _ = sip
        .send_to(&serialize(&SipMessage::Response(ok)), src)
        .await;

    // Spawn the media tap: RTP → decode → 16 kHz mono → ai-bridge session.
    let (stop_tx, stop) = watch::channel(false);
    calls.insert(
        call_id.clone(),
        SinkCall {
            answer_sdp: answer_text,
            tag,
            remote_sip: src,
            stop: stop_tx,
        },
    );
    let codec = plan
        .codec
        .as_ref()
        .and_then(|(n, c, _)| sdp_util::codec_id_for(n, *c));
    tracing::info!(%call_id, "sink call answered (codec {codec:?}, rtp port {rtp_port})");
    tokio::spawn(rtp_tap(call_id, rtp, codec, ai_enabled, stop));
}

/// Per-call RTP receiver feeding the ai-bridge session.
async fn rtp_tap(
    call_id: String,
    rtp: Arc<UdpSocket>,
    codec: Option<CodecId>,
    ai_enabled: bool,
    mut stop: watch::Receiver<bool>,
) {
    let mut dec = codec
        .and_then(|id| {
            let rate = match id {
                CodecId::G722 => 16_000,
                CodecId::Opus => 48_000,
                _ => 8_000,
            };
            Registry::decoder(id, rate, 1).ok().map(|d| (d, rate))
        });
    let mut resampler = dec
        .as_ref()
        .and_then(|(_, rate)| {
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
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            r = rtp.recv_from(&mut buf) => {
                let Ok((n, _)) = r else { break };
                if rtp::looks_like_rtcp(&buf[..n]) {
                    continue;
                }
                let Ok(pkt) = RtpPacket::parse(&buf[..n]) else { continue };
                let (Some((dec, _)), Some(id)) = (dec.as_mut(), codec) else {
                    continue;
                };
                if pkt.payload_type() != payload_type(id) {
                    // Skips telephone-event / comfort noise payloads.
                    continue;
                }
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

fn payload_type(id: CodecId) -> u8 {
    match id {
        CodecId::Pcmu => 0,
        CodecId::Pcma => 8,
        CodecId::G722 => 9,
        CodecId::G729 => 18,
        CodecId::Opus => 111,
        _ => 0,
    }
}
