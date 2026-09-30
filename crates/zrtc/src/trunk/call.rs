//! `zrtc call <e164>`: places one INVITE out the configured trunk, with
//! auth signing and a single 401/407 retry. On 200 the call completes
//! normally (ACK → paced RTP → BYE), exactly like the demo UAC flow.

use std::net::SocketAddr;
use std::time::Duration;

use codecs::{CodecId, Registry};
use rtp::packet::RtpPacket;
use sip_core::builder::RequestBuilder;
use sip_core::ids::{new_branch, new_call_id, new_tag};
use sip_core::message::{Method, Response, SipMessage};
use sip_core::uri::SipUri;
use tokio::net::UdpSocket;

use crate::auth::ChallengeOutcome;
use crate::config::Config;

use b2bua::sdp_util;

use super::{recv_response, Endpoint};

/// Places one outbound call through the trunk. Returns when the call has
/// been torn down (BYE 200) or on the first failure.
pub async fn run(cfg: &Config, e164: &str, rtp_ms: u64) -> Result<(), String> {
    let mut auth_boxed = crate::auth::build(&cfg.trunk)?;
    let mut ep = Endpoint::from_config(cfg)?;
    let mut sess = super::connect(&mut ep).await?;

    let ruri = format!("sip:{e164}@{}", ep.host());
    let call_id = new_call_id("zrtc-trunk-call");
    let from_tag = new_tag();

    // SDP offer: local RTP socket first so the offer carries its port. The
    // advertised media IP must be OUR address toward the trunk (a connected
    // probe asks the kernel which source IP the route uses) — advertising
    // the trunk's own IP told the carrier to send RTP to itself.
    let rtp = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| e.to_string())?;
    let rtp_port = rtp.local_addr().map(|a| a.port()).unwrap_or(0);
    let media_host = {
        let probe = UdpSocket::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| e.to_string())?;
        let _ = probe.connect(ep.target).await;
        probe
            .local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| ep.host())
    };
    let offer =
        sdp_util::build_offer(&media_host, rtp_port, &[CodecId::Pcmu], rand::random()).serialize();

    // ---- INVITE #1: auth signs (bearer attaches, digest records ctx) ----
    let mut extra: Vec<(String, String)> = Vec::new();
    auth_boxed.sign_request(Method::Invite, &ruri, &mut extra);
    let invite = invite_request(
        &ep, &mut sess, &ruri, 1, &call_id, &from_tag, &extra, &offer,
    )?;

    // INVITE first line + key headers (none of these are secrets).
    tracing::info!("trunk INVITE {ruri} SIP/2.0");
    tracing::info!(
        "trunk INVITE From: <{}>;tag={from_tag} | To: <{ruri}> | Contact: <{}>",
        ep.aor,
        ep.contact
    );
    sess.send_msg(&SipMessage::Request(invite)).await?;

    // ---- response loop: 1xx pass, 200 done, 401/407 one retry -----------
    let mut cseq: u32 = 1;
    let mut retried = false;
    let ok: Response = loop {
        let resp = recv_response(&mut sess).await?;
        tracing::info!("trunk response from vendor: {} {}", resp.code, resp.reason);
        match resp.code {
            100 | 180 | 183 => continue,
            200 => break resp,
            401 | 407 => {
                if retried {
                    return Err(format!(
                        "trunk INVITE still challenged after retry ({})",
                        resp.code
                    ));
                }
                retried = true;
                let www = resp.headers.get("WWW-Authenticate").map(str::to_string);
                let proxy = resp.headers.get("Proxy-Authenticate").map(str::to_string);
                let raw = if resp.code == 407 {
                    proxy.as_deref().or(www.as_deref())
                } else {
                    www.as_deref().or(proxy.as_deref())
                };
                tracing::info!(
                    "trunk INVITE challenged with {}: {}",
                    resp.code,
                    raw.unwrap_or("(no challenge header)")
                );
                match auth_boxed.on_challenge(resp.code, www.as_deref(), proxy.as_deref()) {
                    ChallengeOutcome::Retry => {
                        let Some((name, value)) = auth_boxed.pending_header() else {
                            return Err(
                                "trunk auth returned Retry without a credential header".into()
                            );
                        };
                        tracing::info!("trunk retrying INVITE with {name} header");
                        cseq += 1;
                        let retry = invite_request(
                            &ep,
                            &mut sess,
                            &ruri,
                            cseq,
                            &call_id,
                            &from_tag,
                            &[(name, value)],
                            &offer,
                        )?;
                        sess.send_msg(&SipMessage::Request(retry)).await?;
                    }
                    ChallengeOutcome::Fail(reason) => {
                        tracing::error!("trunk INVITE auth failed: {reason}");
                        tracing::error!("trunk INVITE challenge was: {}", raw.unwrap_or("(none)"));
                        return Err(format!(
                            "trunk INVITE failed after challenge ({}): {}",
                            resp.code, reason
                        ));
                    }
                }
            }
            _c => {
                return Err(format!(
                    "trunk INVITE rejected with {} {}",
                    resp.code, resp.reason
                ))
            }
        }
    };

    let answer = String::from_utf8_lossy(&ok.body).to_string();
    let audio_port = extract_audio_port(&answer).ok_or("no m=audio port in answer")?;
    let remote_tag = to_tag_of(&ok);
    tracing::info!("trunk INVITE answered 200 (answer audio port {audio_port})");

    // ---- ACK ---------------------------------------------------------------
    let ack = RequestBuilder::new(
        Method::Ack,
        SipUri::parse(&ruri).map_err(|e| e.to_string())?,
    )
    .via(ep.transport.kind(), &sess.via(), Some(&new_branch()))
    .from(&format!("<{}>;tag={from_tag}", ep.aor))
    .to(&format!("<{ruri}>;tag={remote_tag}"))
    .call_id(Some(&call_id))
    .cseq(cseq)
    .build();
    sess.send_msg(&SipMessage::Request(ack)).await?;

    // ---- paced RTP (20 ms PCMU tone), then BYE -----------------------------
    send_rtp(&rtp, rtp_ms, SocketAddr::new(ep.target.ip(), audio_port)).await?;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let bye = RequestBuilder::new(
        Method::Bye,
        SipUri::parse(&ruri).map_err(|e| e.to_string())?,
    )
    .via(ep.transport.kind(), &sess.via(), Some(&new_branch()))
    .from(&format!("<{}>;tag={from_tag}", ep.aor))
    .to(&format!("<{ruri}>;tag={remote_tag}"))
    .call_id(Some(&call_id))
    .cseq(cseq + 1)
    .build();
    sess.send_msg(&SipMessage::Request(bye)).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("no 200 for BYE on trunk call".into());
        }
        let msg = tokio::time::timeout(remaining, recv_response(&mut sess))
            .await
            .map_err(|_| "no 200 for BYE on trunk call")??;
        if msg.code == 200 {
            break;
        }
    }
    tracing::info!("trunk call complete (BYE 200)");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn invite_request(
    ep: &Endpoint,
    sess: &mut crate::uac::Session,
    ruri: &str,
    cseq: u32,
    call_id: &str,
    from_tag: &str,
    extra: &[(String, String)],
    offer: &str,
) -> Result<sip_core::message::Request, String> {
    let mut b = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(ruri).map_err(|e| e.to_string())?,
    )
    .via(ep.transport.kind(), &sess.via(), Some(&new_branch()))
    .from(&format!("<{}>;tag={from_tag}", ep.aor))
    .to(&format!("<{ruri}>"))
    .call_id(Some(call_id))
    .cseq(cseq)
    .contact(&format!("<{}>", ep.contact))
    .header("Max-Forwards", "70")
    .header("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS")
    .body("application/sdp", offer.as_bytes().to_vec());
    for (name, value) in extra {
        b = b.header(name, value);
    }
    Ok(b.build())
}

/// 20 ms PCMU pacing of a 440 Hz tone — mirrors the demo UAC media path.
async fn send_rtp(rtp: &UdpSocket, rtp_ms: u64, dst: SocketAddr) -> Result<(), String> {
    let mut enc = Registry::encoder(CodecId::Pcmu, 8000, 1).map_err(|e| e.to_string())?;
    let samples = (rtp_ms as usize) * 8; // 8 kHz
    let pcm: Vec<i16> = (0..samples)
        .map(|i| {
            let v = (f64::from(i as u32) * 440.0 * std::f64::consts::TAU / 8000.0).sin() * 9000.0;
            v.clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
        })
        .collect();
    let mut seq: u16 = rand::random();
    let mut ts: u32 = rand::random();
    let ssrc: u32 = rand::random();
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    for frame in pcm.chunks(160) {
        ticker.tick().await;
        let mut wire = Vec::with_capacity(200);
        enc.encode(frame, &mut wire).map_err(|e| e.to_string())?;
        let pkt = RtpPacket::new(0, seq, ts, ssrc, false, bytes::Bytes::from(wire));
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(160);
        rtp.send_to(&pkt.encode(), dst)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn to_tag_of(resp: &Response) -> String {
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
