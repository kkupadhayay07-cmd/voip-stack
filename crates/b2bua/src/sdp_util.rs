//! SDP helpers: local capability sets, offers and answers for both legs.

use codecs::{CodecId, FormatInfo, Registry};
use sdp::negotiate::{answer_session, CodecCap, MediaCaps, NegotiateError, StreamPlan};
use sdp::types::{Attribute, Connection, MediaDescription, Origin, Session, Timing};

/// Payload types we advertise for dynamic codecs.
pub const PT_OPUS: u8 = 111;
pub const PT_TELEPHONE_EVENT: u8 = 101;

/// Looks up the static `FormatInfo` for a codec (name/clock/channels).
pub fn format(id: CodecId) -> FormatInfo {
    Registry::formats()
        .iter()
        .find(|f| f.id == id)
        .copied()
        .unwrap_or(FormatInfo {
            id,
            name: match id {
                CodecId::Pcmu => "PCMU",
                CodecId::Pcma => "PCMA",
                CodecId::G722 => "G722",
                CodecId::G729 => "G729",
                CodecId::Opus => "opus",
                CodecId::L16 => "L16",
                CodecId::ComfortNoise => "CN",
                CodecId::TelephoneEvent => "telephone-event",
            },
            payload_type: match id {
                CodecId::Pcmu => 0,
                CodecId::Pcma => 8,
                CodecId::G722 => 9,
                CodecId::G729 => 18,
                _ => 96,
            },
            clock_rate: match id {
                CodecId::Opus => 48_000,
                _ => 8_000,
            },
            channels: 1,
            fmtp: None,
        })
}

/// Builds `CodecCap`s for the given codec list (static PTs + opus dynamic).
pub fn caps_for(codecs: &[CodecId]) -> Vec<CodecCap> {
    let mut caps = Vec::new();
    for &id in codecs {
        let f = format(id);
        let pt = if f.payload_type <= 35 {
            f.payload_type
        } else {
            PT_OPUS
        };
        let mut cap = CodecCap::new(f.name, f.clock_rate, pt);
        if let Some(fmtp) = &f.fmtp {
            cap = cap.with_fmtp(fmtp);
        }
        caps.push(cap);
    }
    caps
}

/// Local answer capabilities for one audio m-line.
pub fn audio_caps(host: &str, port: u16, codecs: &[CodecId]) -> MediaCaps {
    let mut caps = MediaCaps::audio(host, port, caps_for(codecs));
    caps.telephone_event = Some(CodecCap::new("telephone-event", 8000, PT_TELEPHONE_EVENT));
    caps
}

/// Builds a session-level SDP offer for the UAC leg (audio, all local codecs).
pub fn build_offer(host: &str, port: u16, codecs: &[CodecId], sess_id: u32) -> Session {
    let mut pts: Vec<String> = Vec::new();
    let mut attrs: Vec<Attribute> = Vec::new();
    for &id in codecs {
        let f = format(id);
        let pt = if f.payload_type <= 35 {
            f.payload_type
        } else {
            PT_OPUS
        };
        pts.push(pt.to_string());
        attrs.push(Attribute::new(
            "rtpmap",
            Some(format!("{pt} {}/{}", f.name, f.clock_rate)),
        ));
        if let Some(fmtp) = &f.fmtp {
            attrs.push(Attribute::new("fmtp", Some(format!("{pt} {fmtp}"))));
        }
    }
    pts.push(PT_TELEPHONE_EVENT.to_string());
    attrs.push(Attribute::new(
        "rtpmap",
        Some(format!("{PT_TELEPHONE_EVENT} telephone-event/8000")),
    ));
    attrs.push(Attribute::new("sendrecv", None));

    Session {
        version: 0,
        origin: Origin {
            username: "zrtc".into(),
            sess_id: sess_id.to_string(),
            sess_version: sess_id.to_string(),
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: host.into(),
        },
        name: "zrtc-b2bua".into(),
        info: None,
        connection: Some(Connection {
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: host.into(),
        }),
        bandwidths: Vec::new(),
        timings: vec![Timing {
            start: 0,
            stop: 0,
            repeats: Vec::new(),
        }],
        attributes: Vec::new(),
        extras: Vec::new(),
        direction: None,
        ice_ufrag: None,
        ice_pwd: None,
        ice_options: None,
        fingerprint: None,
        setup: None,
        bundle: None,
        medias: vec![MediaDescription {
            media: "audio".into(),
            port,
            port_count: 1,
            proto: "RTP/AVP".into(),
            formats: pts,
            info: None,
            connection: None,
            bandwidths: Vec::new(),
            attributes: attrs,
            extras: Vec::new(),
            rtpmaps: Default::default(),
            fmtps: Default::default(),
            rtcp_fb: Default::default(),
            direction: None,
            rtcp_mux: false,
            mid: None,
            ptime: None,
            maxptime: None,
            ice_ufrag: None,
            ice_pwd: None,
            ice_options: None,
            ice_candidates: Vec::new(),
            fingerprint: None,
            setup: None,
            rtcp_addr: None,
            extmaps: Vec::new(),
            ssrcs: Vec::new(),
        }],
    }
}

/// Builds the answer for an inbound offer using local capabilities.
pub fn answer(
    offer: &Session,
    host: &str,
    port: u16,
    codecs: &[CodecId],
) -> Result<Session, NegotiateError> {
    answer_session(offer, &[audio_caps(host, port, codecs)])
}

/// Extracts the (codec-name, clock, channels) and payload type the plan uses.
pub fn plan_codec(plan: &StreamPlan) -> Option<(String, u32, Option<u16>, u8)> {
    let (name, clock, ch) = plan.codec.as_ref()?;
    Some((name.clone(), *clock, *ch, plan.local_pt))
}

/// Maps (encoding name, clock) to the registry `CodecId`.
pub fn codec_id_for(name: &str, clock: u32) -> Option<CodecId> {
    Registry::codec_for_name(name, clock, 1)
        .or_else(|| Registry::codec_for_name(name, clock, 2))
        .or_else(|| {
            // Static table fallback for names the registry knows.
            let lower = name.to_ascii_lowercase();
            match lower.as_str() {
                "pcmu" => Some(CodecId::Pcmu),
                "pcma" => Some(CodecId::Pcma),
                "g722" => Some(CodecId::G722),
                "g729" => Some(CodecId::G729),
                "opus" => Some(CodecId::Opus),
                "l16" => Some(CodecId::L16),
                _ => None,
            }
        })
}

/// Sanity: our own offer parses back and the answer engine accepts a mirror offer.
#[cfg(test)]
mod tests {
    use super::*;
    use sdp::static_rtpmap;

    #[test]
    fn offer_roundtrip_and_self_answer() {
        let codecs = [
            CodecId::Pcmu,
            CodecId::Pcma,
            CodecId::G722,
            CodecId::G729,
            CodecId::Opus,
        ];
        let offer = build_offer("127.0.0.1", 30000, &codecs, 42);
        let text = offer.serialize();
        let parsed = sdp::parse::parse(&text).expect("offer parses");
        let ans = answer(&parsed, "127.0.0.1", 30001, &codecs).expect("self answer");
        let plans = sdp::negotiate::stream_plans(&ans);
        assert_eq!(plans.len(), 1);
        assert!(plans[0].active);
        let (name, clock, _ch, _pt) = plan_codec(&plans[0]).expect("codec");
        assert!(codec_id_for(&name, clock).is_some());
    }

    #[test]
    fn static_pt_lookup_matches_registry() {
        for pt in [0u8, 8, 9, 18] {
            let (name, clock) = static_rtpmap(pt).unwrap();
            assert!(codec_id_for(name, clock).is_some(), "{name}");
        }
    }
}
