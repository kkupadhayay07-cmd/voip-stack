//! RFC 3264 offer/answer negotiation with WebRTC extension support
//! (rtcp-mux RFC 5761/6878, ICE RFC 5245/8445 fields, DTLS fingerprint RFC 8122,
//! setup RFC 4145/5763, mid/BUNDLE RFC 5888/8843).

use crate::types::*;
use crate::static_rtpmap;
use std::net::IpAddr;

/// A codec capability offered by the local side (ordered by preference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecCap {
    pub name: String,
    pub clock: u32,
    pub channels: Option<u16>,
    /// Payload type we advertise for this codec (for dynamic types ≥96).
    pub payload: u8,
    pub fmtp: Option<String>,
}

impl CodecCap {
    pub fn new(name: &str, clock: u32, payload: u8) -> CodecCap {
        CodecCap {
            name: name.to_owned(),
            clock,
            channels: None,
            payload,
            fmtp: None,
        }
    }

    pub fn with_channels(mut self, ch: u16) -> CodecCap {
        self.channels = Some(ch);
        self
    }

    pub fn with_fmtp(mut self, fmtp: &str) -> CodecCap {
        self.fmtp = Some(fmtp.to_owned());
        self
    }
}

/// ICE credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCreds {
    pub ufrag: String,
    pub pwd: String,
}

/// One per-m-line set of local capabilities used to build an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaCaps {
    /// Expected media kind ("audio"/"video"); mismatched m-lines are rejected.
    pub media: String,
    /// Our maximal direction for this m-line.
    pub direction: Direction,
    pub rtcp_mux: bool,
    pub codecs: Vec<CodecCap>,
    /// Optional telephone-event capability (event clock must match offer's).
    pub telephone_event: Option<CodecCap>,
    /// Local media host (goes into the answer `c=` line).
    pub host: String,
    /// Local RTP port for this m-line (0 = rejected even if codecs match).
    pub port: u16,
    pub mid: Option<String>,
    pub ice: Option<IceCreds>,
    pub fingerprint: Option<Fingerprint>,
    /// Role we assume when the offer says `actpass`.
    pub setup: SetupRole,
}

impl MediaCaps {
    pub fn audio(host: &str, port: u16, codecs: Vec<CodecCap>) -> MediaCaps {
        MediaCaps {
            media: "audio".to_owned(),
            direction: Direction::SendRecv,
            rtcp_mux: true,
            codecs,
            telephone_event: None,
            host: host.to_owned(),
            port,
            mid: None,
            ice: None,
            fingerprint: None,
            setup: SetupRole::Active,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiateError {
    CapsCountMismatch { offer_medias: usize, caps: usize },
    InvalidOffer(String),
}

impl std::fmt::Display for NegotiateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NegotiateError::CapsCountMismatch { offer_medias, caps } => write!(
                f,
                "capability count mismatch: offer has {} m-lines, {} caps given",
                offer_medias, caps
            ),
            NegotiateError::InvalidOffer(m) => write!(f, "invalid offer: {}", m),
        }
    }
}

impl std::error::Error for NegotiateError {}

/// Compute the answer direction given the offer direction and our maximal capability.
///
/// | offer    | caps     | answer   |
/// |----------|----------|----------|
/// | sendrecv | sendrecv | sendrecv |
/// | sendrecv | sendonly | sendonly |
/// | sendrecv | recvonly | recvonly |
/// | sendonly | *        | recvonly |
/// | recvonly | *        | sendonly |
/// | inactive | *        | inactive |
pub fn answer_direction(offer: Direction, caps: Direction) -> Direction {
    match offer {
        Direction::Inactive => Direction::Inactive,
        Direction::SendOnly => {
            if caps == Direction::Inactive {
                Direction::Inactive
            } else {
                Direction::RecvOnly
            }
        }
        Direction::RecvOnly => {
            if caps == Direction::Inactive {
                Direction::Inactive
            } else {
                Direction::SendOnly
            }
        }
        Direction::SendRecv => caps,
    }
}

/// Protocols accepted by the Phase-1 answer engine.
fn proto_supported(proto: &str) -> bool {
    matches!(
        proto,
        "RTP/AVP" | "RTP/AVPF" | "RTP/SAVP" | "RTP/SAVPF" | "UDP/TLS/RTP/SAVP" | "UDP/TLS/RTP/SAVPF"
    )
}

struct ResolvedFmt {
    pt: u8,
    cap: CodecCap,
    is_dynamic: bool,
    needs_rtpmap: bool,
}

fn resolve_formats(
    media: &MediaDescription,
    session: &Session,
    caps: &MediaCaps,
) -> Vec<ResolvedFmt> {
    let mut out = Vec::new();
    for fmt in &media.formats {
        let pt: u8 = match fmt.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // Resolve encoding name / clock / channels for this payload type.
        let (name, clock, channels, is_dynamic) = if let Some(rm) = media.rtpmaps.get(&pt) {
            (
                rm.encoding.clone(),
                rm.clock_rate,
                rm.channels.unwrap_or(1),
                pt >= 96,
            )
        } else if let Some((n, c)) = static_rtpmap(pt) {
            (n.to_owned(), c, 1u16, false)
        } else {
            continue;
        };
        // Match against capabilities. telephone-event matched separately.
        let matched = caps
            .codecs
            .iter()
            .find(|c| {
                c.name.eq_ignore_ascii_case(&name)
                    && c.clock == clock
                    && c.channels.unwrap_or(1) == channels
            })
            .cloned();
        if let Some(mut cap) = matched {
            if is_dynamic {
                // Answer must use the offer's payload type for dynamic formats.
                cap.payload = pt;
            }
            out.push(ResolvedFmt {
                pt,
                cap,
                is_dynamic,
                // dynamic types always need rtpmap; static never do
                needs_rtpmap: is_dynamic,
            });
        }
    }
    // telephone-event: optional secondary codec, clock must match.
    if let Some(te) = &caps.telephone_event {
        for fmt in &media.formats {
            let pt: u8 = match fmt.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Some(rm) = media.rtpmaps.get(&pt) {
                if rm.encoding.eq_ignore_ascii_case("telephone-event") && rm.clock_rate == te.clock
                {
                    out.push(ResolvedFmt {
                        pt,
                        cap: te.clone(),
                        is_dynamic: true,
                        needs_rtpmap: true,
                    });
                    break;
                }
            }
        }
    }
    // De-duplicate payload types (keep first).
    let mut seen = std::collections::BTreeSet::new();
    out.retain(|r| seen.insert(r.pt));
    // Silence unused warning for session param (kept for symmetry/future use).
    let _ = session;
    out
}

fn rejected_media(offer_m: &MediaDescription) -> MediaDescription {
    let first_fmt = offer_m.formats.first().cloned().unwrap_or_else(|| "0".into());
    MediaDescription {
        media: offer_m.media.clone(),
        port: 0,
        port_count: 1,
        proto: offer_m.proto.clone(),
        formats: vec![first_fmt],
        info: None,
        connection: None,
        bandwidths: Vec::new(),
        attributes: Vec::new(),
        extras: Vec::new(),
        rtpmaps: Default::default(),
        fmtps: Default::default(),
        rtcp_fb: Default::default(),
        direction: Some(Direction::Inactive),
        rtcp_mux: false,
        mid: offer_m.mid.clone(),
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
    }
}

/// Build an RFC 3264 answer for `offer` from the per-m-line `caps`.
pub fn answer_session(offer: &Session, caps: &[MediaCaps]) -> Result<Session, NegotiateError> {
    if caps.len() != offer.medias.len() {
        return Err(NegotiateError::CapsCountMismatch {
            offer_medias: offer.medias.len(),
            caps: caps.len(),
        });
    }
    if offer.medias.is_empty() {
        return Err(NegotiateError::InvalidOffer("offer has no m-lines".into()));
    }

    let mut answer = Session {
        version: 0,
        origin: Origin {
            username: "-".into(),
            sess_id: "0".into(),
            sess_version: "0".into(),
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: caps[0].host.clone(),
        },
        name: "-".into(),
        info: None,
        connection: Some(Connection {
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: caps[0].host.clone(),
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
        medias: Vec::with_capacity(offer.medias.len()),
    };

    for (i, offer_m) in offer.medias.iter().enumerate() {
        let caps_m = &caps[i];
        let rejected = MediaDescription {
            media: offer_m.media.clone(),
            port: 0,
            port_count: 1,
            proto: offer_m.proto.clone(),
            formats: vec![offer_m.formats.first().cloned().unwrap_or_else(|| "0".into())],
            info: None,
            connection: None,
            bandwidths: Vec::new(),
            attributes: Vec::new(),
            extras: Vec::new(),
            rtpmaps: Default::default(),
            fmtps: Default::default(),
            rtcp_fb: Default::default(),
            direction: Some(Direction::Inactive),
            rtcp_mux: false,
            mid: offer_m.mid.clone(),
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
        };

        let mut m = if caps_m.media == offer_m.media {
            rejected_media(offer_m)
        } else {
            answer.medias.push(rejected);
            continue;
        };

        if !proto_supported(&offer_m.proto) || caps_m.port == 0 {
            answer.medias.push(m);
            continue;
        }
        m.media = caps_m.media.clone();
        m.proto = offer_m.proto.clone();
        m.port = caps_m.port;

        let resolved = resolve_formats(offer_m, offer, caps_m);
        if resolved.is_empty() {
            // RFC 3264 §6: no acceptable codec ⇒ reject this m-line with port 0.
            answer.medias.push(rejected);
            continue;
        }

        m.formats = resolved.iter().map(|r| r.pt.to_string()).collect();
        for r in &resolved {
            if r.needs_rtpmap {
                let v = match r.cap.channels.filter(|c| *c != 1) {
                    Some(c) => format!("{} {}/{}/{}", r.pt, r.cap.name, r.cap.clock, c),
                    None => format!("{} {}/{}", r.pt, r.cap.name, r.cap.clock),
                };
                m.attributes.push(Attribute::new("rtpmap", Some(v)));
                // Typed projection must mirror the wire attribute so that
                // `stream_plans()` and callers see the negotiated codecs.
                m.rtpmaps.insert(
                    r.pt,
                    RtpMap {
                        payload: r.pt,
                        encoding: r.cap.name.clone(),
                        clock_rate: r.cap.clock,
                        channels: r.cap.channels,
                    },
                );
            }
            if let Some(f) = &r.cap.fmtp {
                m.attributes
                    .push(Attribute::new("fmtp", Some(format!("{} {}", r.pt, f))));
                m.fmtps.insert(r.pt, f.clone());
            }
        }

        // direction
        let offer_dir = offer_m.effective_direction(offer);
        let ans_dir = answer_direction(offer_dir, caps_m.direction);
        m.direction = Some(ans_dir);
        m.attributes
            .push(Attribute::new(ans_dir.as_str(), None));

        // rtcp-mux: only if offered and supported
        let offered_mux = offer_m.rtcp_mux || offer.has_attr("rtcp-mux");
        if offered_mux && caps_m.rtcp_mux {
            m.rtcp_mux = true;
            m.attributes.push(Attribute::new("rtcp-mux", None));
        }

        // mid echo (required for BUNDLE continuity)
        if let Some(mid) = &offer_m.mid {
            m.mid = Some(mid.clone());
            m.attributes.push(Attribute::new("mid", Some(mid.clone())));
        }

        // ICE echo (our credentials)
        if offer_m.ice_ufrag.is_some() || offer.ice_ufrag.is_some() {
            if let Some(ice) = &caps_m.ice {
                m.ice_ufrag = Some(ice.ufrag.clone());
                m.ice_pwd = Some(ice.pwd.clone());
                m.attributes
                    .push(Attribute::new("ice-ufrag", Some(ice.ufrag.clone())));
                m.attributes
                    .push(Attribute::new("ice-pwd", Some(ice.pwd.clone())));
            }
        }

        // DTLS fingerprint echo + setup role
        let offer_fp = offer_m.fingerprint.clone().or_else(|| offer.fingerprint.clone());
        if offer_fp.is_some() {
            if let Some(fp) = &caps_m.fingerprint {
                m.fingerprint = Some(fp.clone());
                m.attributes.push(Attribute::new(
                    "fingerprint",
                    Some(format!("{} {}", fp.hash_func, fp.value)),
                ));
            }
            let offer_setup = offer_m.setup.or(offer.setup).unwrap_or(SetupRole::Actpass);
            let role = match offer_setup {
                SetupRole::Actpass => caps_m.setup,
                SetupRole::Active => SetupRole::Passive,
                SetupRole::Passive => SetupRole::Active,
                SetupRole::Holdconn => SetupRole::Holdconn,
            };
            m.setup = Some(role);
            m.attributes
                .push(Attribute::new("setup", Some(role.as_str().to_owned())));
        }

        // ptime echo when offered
        if let Some(p) = offer_m.ptime {
            m.ptime = Some(p);
            m.attributes.push(Attribute::new("ptime", Some(p.to_string())));
        }

        m.connection = Some(Connection {
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: caps_m.host.clone(),
        });

        answer.medias.push(m);
    }

    Ok(answer)
}

/// Runtime projection of a negotiated session: one plan per m-line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamPlan {
    pub index: usize,
    pub active: bool,
    pub local_pt: u8,
    pub remote_pt: u8,
    pub codec: Option<(String, u32, Option<u16>)>,
    pub direction: Direction,
    pub rtcp_mux: bool,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: u16,
    pub telephone_event_pt: Option<u8>,
    pub mid: Option<String>,
}

/// Extract `StreamPlan`s (what the media engine should do) from a session
/// that was produced by (or validated against) `answer_session`.
pub fn stream_plans(session: &Session) -> Vec<StreamPlan> {
    let mut plans = Vec::with_capacity(session.medias.len());
    for (i, m) in session.medias.iter().enumerate() {
        let dir = m.effective_direction(session);
        let remote_addr = m
            .connection
            .as_ref()
            .or(session.connection.as_ref())
            .map(|c| c.base_address().parse::<IpAddr>().ok())
            .flatten();
        let pts = m.payload_types();
        let first_pt = pts.first().copied();
        let codec = first_pt.and_then(|pt| match m.rtpmaps.get(&pt) {
            Some(rm) => Some((rm.encoding.clone(), rm.clock_rate, rm.channels)),
            None => static_rtpmap(pt).map(|(n, c)| (n.to_owned(), c, None)),
        });
        let te_pt = m
            .rtpmaps
            .values()
            .find(|rm| rm.encoding.eq_ignore_ascii_case("telephone-event"))
            .map(|rm| rm.payload);
        plans.push(StreamPlan {
            index: i,
            active: m.port != 0 && dir != Direction::Inactive && remote_addr.is_some(),
            local_pt: first_pt.unwrap_or(0),
            remote_pt: first_pt.unwrap_or(0),
            codec,
            direction: dir,
            rtcp_mux: m.rtcp_mux || m.has_attr(session, "rtcp-mux"),
            remote_addr,
            remote_port: m.port,
            telephone_event_pt: te_pt,
            mid: m.mid.clone(),
        });
    }
    plans
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    const CHROMIUM_LIKE_OFFER: &str = "\
v=0\r\n\
o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic: WMS stream\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8 101\r\n\
c=IN IP4 0.0.0.0\r\n\
a=rtcp:9 IN IP4 0.0.0.0\r\n\
a=ice-ufrag:EsAw\r\n\
a=ice-pwd:P2uYro0UCOQ4zxjKXaWCBui1\r\n\
a=ice-options:trickle\r\n\
a=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:3D:13:B4:84:24:2C:C2:A2:C0:3E:FD:34:8E:5E:EA:6F:AF:52:CE:E6:0F\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n\
a=sendrecv\r\n\
a=rtcp-mux\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n\
a=maxptime:60\r\n\
a=ssrc:3520455752 cname:xyz\r\n";

    #[test]
    fn parse_chromium_like_offer() {
        let s = parse(CHROMIUM_LIKE_OFFER).unwrap();
        assert_eq!(s.medias.len(), 1);
        let m = &s.medias[0];
        assert_eq!(m.media, "audio");
        assert_eq!(m.proto, "UDP/TLS/RTP/SAVPF");
        assert!(m.rtcp_mux);
        assert_eq!(m.mid.as_deref(), Some("0"));
        assert_eq!(m.ice_ufrag.as_deref(), Some("EsAw"));
        assert_eq!(m.setup, Some(SetupRole::Actpass));
        assert_eq!(
            m.fingerprint.as_ref().unwrap().hash_func,
            "sha-256"
        );
        assert_eq!(m.rtpmaps[&111].encoding, "opus");
        assert_eq!(m.rtpmaps[&111].channels, Some(2));
        assert_eq!(m.ssrcs.len(), 1);
        assert_eq!(s.bundle.as_ref().unwrap().mids, vec!["0"]);
        let rt = parse(&s.serialize()).unwrap();
        assert_eq!(s, rt);
    }

    fn caps_audio() -> MediaCaps {
        let mut c = MediaCaps::audio(
            "10.0.0.5",
            20000,
            vec![
                CodecCap::new("PCMU", 8000, 0),
                CodecCap::new("PCMA", 8000, 8),
                CodecCap::new("opus", 48000, 111).with_channels(2).with_fmtp("minptime=10;useinbandfec=1"),
            ],
        );
        c.telephone_event = Some(CodecCap::new("telephone-event", 8000, 101).with_fmtp("0-16"));
        c.ice = Some(IceCreds {
            ufrag: "ourfrag".into(),
            pwd: "ourpwd".into(),
        });
        c.fingerprint = Some(Fingerprint {
            hash_func: "sha-256".into(),
            value: "AA:BB:CC:DD".into(),
        });
        c
    }

    #[test]
    fn answer_chromium_like_offer() {
        let offer = parse(CHROMIUM_LIKE_OFFER).unwrap();
        let answer = answer_session(&offer, &[caps_audio()]).unwrap();
        let m = &answer.medias[0];
        assert_eq!(m.port, 20000);
        assert!(m.rtcp_mux);
        assert_eq!(m.mid.as_deref(), Some("0"));
        assert_eq!(m.setup, Some(SetupRole::Active));
        assert_eq!(m.direction, Some(Direction::SendRecv));
        // formats: all four offered formats match our caps, in offer order
        assert_eq!(m.formats, vec!["111", "0", "8", "101"]);
        assert!(m.rtpmaps.contains_key(&111));
        assert!(m.rtpmaps.contains_key(&101));
        // static formats don't need rtpmap lines
        assert!(!m.attributes.iter().any(|a| a.name == "rtpmap"
            && a.value.as_deref().map(|v| v.starts_with("0 PCMU")).unwrap_or(false)));
        assert_eq!(m.ice_ufrag.as_deref(), Some("ourfrag"));
        assert_eq!(m.connection.as_ref().unwrap().address, "10.0.0.5");
        let rt = parse(&answer.serialize()).unwrap();
        assert_eq!(answer, rt);
        // plans
        let plans = stream_plans(&answer);
        assert_eq!(plans.len(), 1);
        assert!(plans[0].active);
        assert_eq!(plans[0].codec.as_ref().unwrap().0, "opus");
        assert_eq!(plans[0].telephone_event_pt, Some(101));
    }

    #[test]
    fn answer_rejects_unsupported_media() {
        let offer_str = CHROMIUM_LIKE_OFFER.replace("m=audio", "m=video");
        let offer = parse(&offer_str).unwrap();
        let answer = answer_session(&offer, &[caps_audio()]).unwrap();
        assert_eq!(answer.medias[0].port, 0);
    }

    #[test]
    fn answer_rejects_no_codec_intersection() {
        let offer = parse(CHROMIUM_LIKE_OFFER).unwrap();
        let mut c = caps_audio();
        c.codecs = vec![CodecCap::new("G729", 8000, 18)];
        c.telephone_event = None;
        let answer = answer_session(&offer, &[c]).unwrap();
        assert_eq!(answer.medias[0].port, 0);
    }

    #[test]
    fn direction_intersection_table() {
        use Direction::*;
        assert_eq!(answer_direction(SendRecv, SendRecv), SendRecv);
        assert_eq!(answer_direction(SendRecv, SendOnly), SendOnly);
        assert_eq!(answer_direction(SendRecv, RecvOnly), RecvOnly);
        assert_eq!(answer_direction(SendOnly, SendRecv), RecvOnly);
        assert_eq!(answer_direction(RecvOnly, SendRecv), SendOnly);
        assert_eq!(answer_direction(SendOnly, Inactive), Inactive);
        assert_eq!(answer_direction(Inactive, SendRecv), Inactive);
    }

    #[test]
    fn offer_sendonly_answer_recvonly() {
        let offer_str = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n\
            c=IN IP4 1.2.3.4\r\n\
            m=audio 5000 RTP/AVP 0\r\na=sendonly\r\na=rtpmap:0 PCMU/8000\r\n";
        let offer = parse(offer_str).unwrap();
        let mut c = caps_audio();
        c.direction = Direction::SendRecv;
        let answer = answer_session(&offer, &[c]).unwrap();
        assert_eq!(answer.medias[0].direction, Some(Direction::RecvOnly));
    }

    #[test]
    fn no_mux_when_not_supported() {
        let offer = parse(CHROMIUM_LIKE_OFFER).unwrap();
        let mut c = caps_audio();
        c.rtcp_mux = false;
        let answer = answer_session(&offer, &[c]).unwrap();
        assert!(!answer.medias[0].rtcp_mux);
    }

    #[test]
    fn setup_active_answer_passive() {
        let offer_str = CHROMIUM_LIKE_OFFER.replace("a=setup:actpass", "a=setup:active");
        let offer = parse(&offer_str).unwrap();
        let answer = answer_session(&offer, &[caps_audio()]).unwrap();
        assert_eq!(answer.medias[0].setup, Some(SetupRole::Passive));
    }

    #[test]
    fn caps_count_mismatch() {
        let offer = parse(CHROMIUM_LIKE_OFFER).unwrap();
        let r = answer_session(&offer, &[]);
        assert!(matches!(r, Err(NegotiateError::CapsCountMismatch { .. })));
    }

    #[test]
    fn offer_order_preserved_for_dynamic_pts() {
        // offer lists opus(111) before PCMU(0); answer must keep offer's pt 111
        let offer = parse(CHROMIUM_LIKE_OFFER).unwrap();
        let answer = answer_session(&offer, &[caps_audio()]).unwrap();
        assert_eq!(answer.medias[0].formats[0], "111");
        assert_eq!(answer.medias[0].rtpmaps[&111].encoding, "opus");
    }
}
