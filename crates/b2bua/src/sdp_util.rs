//! SDP helpers: local capability sets, offers and answers for both legs.

use codecs::{CodecId, FormatInfo, Registry};
use sdp::negotiate::{answer_session, CodecCap, IceCreds, MediaCaps, NegotiateError, StreamPlan};
use sdp::types::{
    Attribute, Connection, ExtMap, Fingerprint, MediaDescription, Origin, Session, SetupRole,
    Timing,
};

/// Payload types we advertise for dynamic codecs.
pub const PT_OPUS: u8 = 111;
pub const PT_TELEPHONE_EVENT: u8 = 101;

/// transport-cc header-extension wire id we offer (draft-holmerberg form).
const TWCC_EXT_ID: u8 = 1;
const TWCC_URI: &str = "http://www.ietf.org/id/draft-holmerberg-avt-01";

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

/// WebRTC transport fields the answer carries when the leg negotiated
/// ICE + DTLS-SRTP (`webrtc::WebRtcMedia::answer_transport` output).
#[derive(Debug, Clone)]
pub struct WebrtcAnswerCaps {
    pub ufrag: String,
    pub pwd: String,
    /// Our certificate fingerprint, bare colon-hex (no `sha-256 ` prefix).
    pub fingerprint: String,
    /// Candidate lines in RFC 8839 form (without the `a=` prefix).
    pub candidates: Vec<String>,
}

impl WebrtcAnswerCaps {
    fn apply(self, caps: &mut MediaCaps) {
        caps.ice = Some(IceCreds {
            ufrag: self.ufrag,
            pwd: self.pwd,
        });
        caps.ice_candidates = self.candidates;
        caps.fingerprint = Some(Fingerprint {
            hash_func: "sha-256".to_owned(),
            value: self.fingerprint,
        });
        // caps.setup stays `Active`: we are the answerer and drive the DTLS
        // handshake as the client (RFC 5763 §5).
    }
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

    // RTCP feedback we implement, advertised per RFC 4585 §4.2 for every
    // audio payload: Generic NACK (loss recovery) and transport-cc
    // (congestion feedback), plus the transport-cc header extension the
    // receiver-side feedback keys on (RFC 8285 one-byte element).
    let mut rtcp_fb: std::collections::BTreeMap<u8, Vec<String>> = Default::default();
    for pt in &pts {
        if let Ok(pt) = pt.parse::<u8>() {
            if pt == PT_TELEPHONE_EVENT {
                continue;
            }
            rtcp_fb.insert(pt, vec!["nack".into(), "transport-cc".into()]);
            attrs.push(Attribute::new("rtcp-fb", Some(format!("{pt} nack"))));
            attrs.push(Attribute::new(
                "rtcp-fb",
                Some(format!("{pt} transport-cc")),
            ));
        }
    }
    attrs.push(Attribute::new(
        "extmap",
        Some(format!("{TWCC_EXT_ID} {TWCC_URI} transport-cc")),
    ));

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
            rtcp_fb,
            direction: None,
            // RFC 5761: the media pump is mux-only (one socket for RTP and
            // RTCP) — offer rtcp-mux so strict peers address RTCP at the
            // RTP port instead of a port we never bound.
            rtcp_mux: true,
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
            extmaps: vec![ExtMap {
                id: TWCC_EXT_ID,
                direction: None,
                uri: TWCC_URI.into(),
                config: Some("transport-cc".into()),
            }],
            ssrcs: Vec::new(),
        }],
    }
}

/// SCTP port the data-channel association answers with (RFC 8841
/// `a=sctp-port`; the m= line port is the UDP/ICE transport port). Matches
/// the `sctp::SctpConfig` default the data-channel engine runs with.
pub const SCTP_PORT: u16 = 5000;
/// `a=max-message-size` we answer with — mirrors the engine's
/// `SctpConfig::default().max_message_size` (256 KiB).
pub const MAX_MESSAGE_SIZE: u32 = 256 * 1024;

/// Transport fields OUR offer carries for a WebRTC leg (`webrtc::WebRtcOffer::offer_transport`
/// output): ICE credentials, the DTLS fingerprint and the candidate lines.
#[derive(Debug, Clone)]
pub struct WebrtcOfferCaps {
    pub ufrag: String,
    pub pwd: String,
    /// Our certificate fingerprint, bare colon-hex (no `sha-256 ` prefix).
    pub fingerprint: String,
    /// Candidate lines in RFC 8839 form (with the `candidate:` prefix,
    /// without the `a=` — the serializer's convention).
    pub candidates: Vec<String>,
}

/// Builds a session-level SDP offer for a WebRTC route (UAC leg B): the
/// plain audio offer upgraded to `UDP/TLS/RTP/SAVPF` with the ICE
/// credentials/candidates, the DTLS fingerprint and `a=setup:actpass`
/// (RFC 5763 §5 — the answer must pick `active` or `passive`).
///
/// `dc` (RFC 8841): when `Some`, an `m=application UDP/DTLS/SCTP
/// webrtc-datachannel` m-line is appended AFTER the audio m-line, carrying
/// the same ICE/DTLS transport block (one agent, one socket) plus the
/// `a=sctp-port` / `a=max-message-size` attributes. Like every construction
/// path here, the transport rides RAW attributes — the typed fields are
/// parse-side mirrors only (the Task 50 lesson).
pub fn build_webrtc_offer(
    host: &str,
    port: u16,
    codecs: &[CodecId],
    sess_id: u32,
    t: &WebrtcOfferCaps,
    dc: Option<sdp::DataChannelCaps>,
) -> Session {
    let mut session = build_offer(host, port, codecs, sess_id);
    let m = &mut session.medias[0];
    m.proto = "UDP/TLS/RTP/SAVPF".into();
    m.ice_ufrag = Some(t.ufrag.clone());
    m.ice_pwd = Some(t.pwd.clone());
    m.fingerprint = Some(Fingerprint {
        hash_func: "sha-256".to_owned(),
        value: t.fingerprint.clone(),
    });
    m.setup = Some(SetupRole::Actpass);
    // The serializer emits the m-line's raw `attributes` — the typed ICE/DTLS
    // fields above are parse-side mirrors only, so the transport block MUST
    // also be pushed as attributes (the same rule `answer_session` follows).
    m.attributes
        .push(Attribute::new("setup", Some("actpass".into())));
    m.attributes.push(Attribute::new(
        "fingerprint",
        Some(format!("sha-256 {}", t.fingerprint)),
    ));
    m.attributes
        .push(Attribute::new("ice-ufrag", Some(t.ufrag.clone())));
    m.attributes
        .push(Attribute::new("ice-pwd", Some(t.pwd.clone())));
    for line in &t.candidates {
        // `Candidate::to_sdp()` carries the `candidate:` prefix; the
        // attribute value must not (`a=candidate:<value>`, RFC 8839).
        let bare = line.strip_prefix("a=").unwrap_or(line);
        let bare = bare.strip_prefix("candidate:").unwrap_or(bare);
        m.ice_candidates.push(bare.to_owned());
        m.attributes
            .push(Attribute::new("candidate", Some(bare.to_owned())));
    }
    if let Some(dc) = dc {
        // RFC 8841 data-channel offer. Same transport block as the audio
        // m-line (the ICE/DTLS transport is shared), raw attributes only.
        let mut attrs = Vec::new();
        attrs.push(Attribute::new("sctp-port", Some(dc.sctp_port.to_string())));
        attrs.push(Attribute::new(
            "max-message-size",
            Some(dc.max_message_size.to_string()),
        ));
        attrs.push(Attribute::new("setup", Some("actpass".into())));
        attrs.push(Attribute::new(
            "fingerprint",
            Some(format!("sha-256 {}", t.fingerprint)),
        ));
        attrs.push(Attribute::new("ice-ufrag", Some(t.ufrag.clone())));
        attrs.push(Attribute::new("ice-pwd", Some(t.pwd.clone())));
        for line in &t.candidates {
            let bare = line.strip_prefix("a=").unwrap_or(line);
            let bare = bare.strip_prefix("candidate:").unwrap_or(bare);
            attrs.push(Attribute::new("candidate", Some(bare.to_owned())));
        }
        session.medias.push(MediaDescription {
            media: "application".into(),
            port,
            port_count: 1,
            proto: "UDP/DTLS/SCTP".into(),
            formats: vec!["webrtc-datachannel".into()],
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
            // Typed mirrors, kept in sync with the raw attributes above.
            ice_ufrag: Some(t.ufrag.clone()),
            ice_pwd: Some(t.pwd.clone()),
            ice_options: None,
            ice_candidates: Vec::new(),
            fingerprint: Some(Fingerprint {
                hash_func: "sha-256".to_owned(),
                value: t.fingerprint.clone(),
            }),
            setup: Some(SetupRole::Actpass),
            rtcp_addr: None,
            extmaps: Vec::new(),
            ssrcs: Vec::new(),
        });
    }
    session
}

/// Builds the answer for an inbound offer using local capabilities.
///
/// Every m-line is answered positionally (RFC 3264 §6 — an m-line is never
/// omitted): the FIRST audio m-line is accepted (port = `port`), the FIRST
/// `m=application` UDP/DTLS/SCTP line is accepted as an RFC 8841 data
/// channel ONLY when the leg negotiated WebRTC (`webrtc` present — SCTP
/// rides the same ICE/DTLS transport), and every other m-line (second
/// audio, video, exotic application transports) is rejected with port 0.
pub fn answer(
    offer: &Session,
    host: &str,
    port: u16,
    codecs: &[CodecId],
    webrtc: Option<WebrtcAnswerCaps>,
) -> Result<Session, NegotiateError> {
    let mut audio_taken = false;
    let mut app_taken = false;
    let caps: Vec<MediaCaps> = offer
        .medias
        .iter()
        .map(|m| match m.media.as_str() {
            "audio" if !audio_taken => {
                audio_taken = true;
                let mut caps = audio_caps(host, port, codecs);
                if let Some(w) = webrtc.clone() {
                    w.apply(&mut caps);
                }
                caps
            }
            "application" if !app_taken => {
                app_taken = true;
                let mut caps = MediaCaps::application(
                    host,
                    port,
                    sdp::DataChannelCaps {
                        sctp_port: SCTP_PORT,
                        max_message_size: MAX_MESSAGE_SIZE,
                    },
                );
                if let Some(w) = webrtc.clone() {
                    w.apply(&mut caps);
                }
                caps
            }
            // Second audio m-line, video, or any application offer on a
            // plain-RTP leg: build a kind-matching slot so answer_session
            // rejects it with port 0 instead of a caps-count error.
            "audio" => {
                let mut caps = audio_caps(host, 0, codecs);
                if let Some(w) = webrtc.clone() {
                    w.apply(&mut caps);
                }
                caps
            }
            "application" => {
                let mut caps = MediaCaps::application(
                    host,
                    0,
                    sdp::DataChannelCaps {
                        sctp_port: SCTP_PORT,
                        max_message_size: MAX_MESSAGE_SIZE,
                    },
                );
                if let Some(w) = webrtc.clone() {
                    w.apply(&mut caps);
                }
                caps
            }
            other => {
                let mut caps = MediaCaps::audio(host, 0, Vec::new());
                caps.media = other.to_owned();
                caps
            }
        })
        .collect();
    answer_session(offer, &caps)
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
        let ans = answer(&parsed, "127.0.0.1", 30001, &codecs, None).expect("self answer");
        let plans = sdp::negotiate::stream_plans(&ans);
        assert_eq!(plans.len(), 1);
        assert!(plans[0].active);
        let (name, clock, _ch, _pt) = plan_codec(&plans[0]).expect("codec");
        assert!(codec_id_for(&name, clock).is_some());
    }

    #[test]
    fn offer_advertises_rtcp_feedback_channels() {
        let offer = build_offer("127.0.0.1", 30000, &[CodecId::Pcmu], 7);
        let text = offer.serialize();
        assert!(text.contains("a=rtcp-fb:0 nack\r\n"), "{text}");
        assert!(text.contains("a=rtcp-fb:0 transport-cc\r\n"), "{text}");
        // The pump is mux-only: the offer must say so (RFC 5761).
        assert!(text.contains("a=rtcp-mux\r\n"), "{text}");
        assert!(
            text.contains(
                "a=extmap:1 http://www.ietf.org/id/draft-holmerberg-avt-01 transport-cc\r\n"
            ),
            "{text}"
        );
        // The parsed view carries the same capabilities...
        let parsed = sdp::parse::parse(&text).unwrap();
        let plans = sdp::negotiate::stream_plans(&parsed);
        assert!(plans[0].rtcp_fb_nack);
        assert_eq!(plans[0].twcc_ext_id, Some(1));
        // ...and the offer/answer loop preserves them end to end.
        let ans = answer(&parsed, "127.0.0.1", 30001, &[CodecId::Pcmu], None).unwrap();
        let ans_plans = sdp::negotiate::stream_plans(&sdp::parse::parse(&ans.serialize()).unwrap());
        assert!(ans_plans[0].rtcp_fb_nack);
        assert_eq!(ans_plans[0].twcc_ext_id, Some(1));
    }

    #[test]
    fn static_pt_lookup_matches_registry() {
        for pt in [0u8, 8, 9, 18] {
            let (name, clock) = static_rtpmap(pt).unwrap();
            assert!(codec_id_for(name, clock).is_some(), "{name}");
        }
    }

    #[test]
    fn webrtc_offer_carries_the_transport_block() {
        let offer = build_webrtc_offer(
            "127.0.0.1",
            31000,
            &[CodecId::Pcmu],
            9,
            &WebrtcOfferCaps {
                ufrag: "ufr7".into(),
                pwd: "pwdsixtysixcharsxxxxxpwdsixtysixcharsxxxxxpwdsixtysix".into(),
                fingerprint: vec!["AB"; 32].join(":"),
                candidates: vec!["candidate:1 1 UDP 2130706431 127.0.0.1 31000 typ host".into()],
            },
            None,
        );
        let text = offer.serialize();
        assert!(
            text.contains("m=audio 31000 UDP/TLS/RTP/SAVPF 0 101"),
            "{text}"
        );
        assert!(text.contains("a=setup:actpass"), "{text}");
        assert!(text.contains("a=fingerprint:sha-256 "), "{text}");
        assert!(text.contains("a=ice-ufrag:ufr7"), "{text}");
        assert!(text.contains("a=ice-pwd:"), "{text}");
        assert!(text.contains("a=candidate:1 1 UDP"), "{text}");
        // The codec/feedback block is inherited from the plain offer.
        assert!(text.contains("a=rtcp-mux"), "{text}");
        assert!(text.contains("a=rtcp-fb:0 nack"), "{text}");
        assert!(text.contains("a=rtcp-fb:0 transport-cc"), "{text}");
        // parse → serialize → parse is a fixed point.
        let parsed = sdp::parse::parse(&text).unwrap();
        assert_eq!(
            parsed.serialize(),
            text,
            "webrtc offer roundtrip not stable"
        );
        let m = &parsed.medias[0];
        assert_eq!(m.setup, Some(SetupRole::Actpass));
        assert_eq!(m.ice_ufrag.as_deref(), Some("ufr7"));
        assert_eq!(m.fingerprint.as_ref().unwrap().hash_func, "sha-256");
        assert_eq!(m.ice_candidates.len(), 1);
    }

    #[test]
    fn webrtc_offer_answers_like_a_webrtc_offer() {
        // Our own answer engine accepts the offer as a WebRTC offer: the
        // answer mirrors SAVPF and echoes setup (active, the answerer is
        // the DTLS client).
        let offer = build_webrtc_offer(
            "127.0.0.1",
            31000,
            &[CodecId::Pcmu],
            9,
            &WebrtcOfferCaps {
                ufrag: "ufr7".into(),
                pwd: "pwdsixtysixcharsxxxxxpwdsixtysixcharsxxxxxpwdsixtysix".into(),
                fingerprint: vec!["CD"; 32].join(":"),
                candidates: vec!["candidate:1 1 UDP 2130706431 127.0.0.1 31000 typ host".into()],
            },
            None,
        );
        let parsed = sdp::parse::parse(&offer.serialize()).unwrap();
        let ans = answer(
            &parsed,
            "127.0.0.1",
            31001,
            &[CodecId::Pcmu],
            Some(WebrtcAnswerCaps {
                ufrag: "ansu".into(),
                pwd: "anspwdsixtysixcharsxxxxxanspwdsixtysixcharsxxxxxansp".into(),
                fingerprint: vec!["EF"; 32].join(":"),
                candidates: vec!["candidate:2 1 UDP 2130706431 127.0.0.1 31001 typ host".into()],
            }),
        )
        .expect("webrtc offer self-answers");
        let text = ans.serialize();
        assert!(text.contains("UDP/TLS/RTP/SAVPF"), "{text}");
        assert!(text.contains("a=setup:active"), "{text}");
        assert!(text.contains("a=fingerprint:sha-256 EF:"), "{text}");
    }

    #[test]
    fn webrtc_offer_without_dc_has_no_application_mline() {
        let offer = build_webrtc_offer(
            "127.0.0.1",
            31000,
            &[CodecId::Pcmu],
            3,
            &WebrtcOfferCaps {
                ufrag: "ufr7".into(),
                pwd: "pwdsixtysixcharsxxxxxpwdsixtysixcharsxxxxxpwdsixtysix".into(),
                fingerprint: vec!["AB"; 32].join(":"),
                candidates: vec!["candidate:1 1 UDP 2130706431 127.0.0.1 31000 typ host".into()],
            },
            None,
        );
        let text = offer.serialize();
        assert!(!text.contains("m=application"), "{text}");
    }

    #[test]
    fn webrtc_offer_with_dc_carries_the_rfc8841_block() {
        let offer = build_webrtc_offer(
            "127.0.0.1",
            31000,
            &[CodecId::Pcmu],
            4,
            &WebrtcOfferCaps {
                ufrag: "ufr7".into(),
                pwd: "pwdsixtysixcharsxxxxxpwdsixtysixcharsxxxxxpwdsixtysix".into(),
                fingerprint: vec!["AB"; 32].join(":"),
                candidates: vec!["candidate:1 1 UDP 2130706431 127.0.0.1 31000 typ host".into()],
            },
            Some(sdp::DataChannelCaps {
                sctp_port: SCTP_PORT,
                max_message_size: MAX_MESSAGE_SIZE,
            }),
        );
        let text = offer.serialize();
        // The RFC 8841 m-line with our own SCTP port and message cap...
        assert!(
            text.contains("m=application 31000 UDP/DTLS/SCTP webrtc-datachannel\r\n"),
            "{text}"
        );
        assert!(text.contains("a=sctp-port:5000\r\n"), "{text}");
        assert!(text.contains("a=max-message-size:262144\r\n"), "{text}");
        // ...and the SAME transport block the audio m-line carries (one
        // agent, one socket — the raw-attributes rule applies to this
        // m-line too).
        assert_eq!(text.matches("a=setup:actpass").count(), 2, "{text}");
        assert_eq!(text.matches("a=fingerprint:sha-256 ").count(), 2, "{text}");
        assert_eq!(text.matches("a=ice-ufrag:ufr7").count(), 2, "{text}");
        assert_eq!(text.matches("a=candidate:1 1 UDP").count(), 2, "{text}");
        // parse → serialize → parse is a fixed point.
        let parsed = sdp::parse::parse(&text).unwrap();
        assert_eq!(
            parsed.serialize(),
            text,
            "webrtc dc offer roundtrip not stable"
        );
        let app = &parsed.medias[1];
        assert_eq!(app.media, "application");
        assert_eq!(app.proto, "UDP/DTLS/SCTP");
        assert_eq!(app.setup, Some(SetupRole::Actpass));
        assert_eq!(app.ice_ufrag.as_deref(), Some("ufr7"));
        assert_eq!(app.fingerprint.as_ref().unwrap().hash_func, "sha-256");
        // And our own answer engine accepts BOTH m-lines (the leg-A path
        // with webrtc caps, reused for symmetry).
        let ans = answer(
            &parsed,
            "127.0.0.1",
            31001,
            &[CodecId::Pcmu],
            Some(WebrtcAnswerCaps {
                ufrag: "ansu".into(),
                pwd: "anspwdsixtysixcharsxxxxxanspwdsixtysixcharsxxxxxansp".into(),
                fingerprint: vec!["EF"; 32].join(":"),
                candidates: vec!["candidate:2 1 UDP 2130706431 127.0.0.1 31001 typ host".into()],
            }),
        )
        .expect("webrtc dc offer self-answers");
        let ans_text = ans.serialize();
        assert!(
            ans_text.contains("m=application 31001 UDP/DTLS/SCTP webrtc-datachannel"),
            "{ans_text}"
        );
        assert!(ans_text.contains("a=sctp-port:5000"), "{ans_text}");
    }
}
