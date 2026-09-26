//! Hand-written SDP parser (RFC 4566 §5 grammar).
//!
//! Bounds-checked, allocation-light, fuzz-safe: every construct is validated
//! and errors carry the offending line number.

use crate::types::*;

/// Parse error with position info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpError {
    pub kind: SdpErrorKind,
    pub line: usize,
    pub msg: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpErrorKind {
    Syntax,
    Version,
    MissingField,
    InvalidValue,
    TooLarge,
}

impl std::fmt::Display for SdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sdp error (line {}): {:?}: {}", self.line, self.kind, self.msg)
    }
}

impl std::error::Error for SdpError {}

const MAX_LINES: usize = 512;
const MAX_LINE_LEN: usize = 8192;

/// Parse a full SDP session description.
pub fn parse(input: &str) -> Result<Session, SdpError> {
    let mut saw_version = false;
    let mut origin: Option<Origin> = None;
    let mut name: Option<String> = None;
    let mut info: Option<String> = None;
    let mut connection: Option<Connection> = None;
    let mut bandwidths: Vec<Bandwidth> = Vec::new();
    let mut timings: Vec<Timing> = Vec::new();
    let mut attributes: Vec<Attribute> = Vec::new();
    let mut extras: Vec<(char, String)> = Vec::new();
    let mut medias: Vec<MediaDescription> = Vec::new();
    // typed session mirrors
    let mut sess_dir: Option<Direction> = None;
    let mut ice_ufrag: Option<String> = None;
    let mut ice_pwd: Option<String> = None;
    let mut ice_options: Option<String> = None;
    let mut fingerprint: Option<Fingerprint> = None;
    let mut setup: Option<SetupRole> = None;
    let mut bundle: Option<BundleGroup> = None;

    // current media section
    let mut cur: Option<MediaBuilder> = None;

    let mut lines = 0usize;
    for (idx, raw_line) in input.lines().enumerate() {
        lines += 1;
        if lines > MAX_LINES {
            return Err(SdpError {
                kind: SdpErrorKind::TooLarge,
                line: idx + 1,
                msg: "too many SDP lines".into(),
            });
        }
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_LINE_LEN {
            return Err(SdpError {
                kind: SdpErrorKind::TooLarge,
                line: idx + 1,
                msg: "line too long".into(),
            });
        }
        let b = line.as_bytes();
        if b.len() < 2 || b[1] != b'=' {
            return Err(SdpError {
                kind: SdpErrorKind::Syntax,
                line: idx + 1,
                msg: format!("expected `<type>=<value>`, got {:?}", line),
            });
        }
        let typ = b[0] as char;
        let value = &line[2..];
        let lineno = idx + 1;

        if typ.is_ascii_uppercase() {
            return Err(SdpError {
                kind: SdpErrorKind::Syntax,
                line: lineno,
                msg: format!("unknown line type {:?}", typ),
            });
        }

        match typ {
            'v' => {
                let v: u32 = value.parse().map_err(|_| SdpError {
                    kind: SdpErrorKind::InvalidValue,
                    line: lineno,
                    msg: format!("bad version {:?}", value),
                })?;
                if saw_version {
                    return Err(SdpError {
                        kind: SdpErrorKind::Syntax,
                        line: lineno,
                        msg: "duplicate v=".into(),
                    });
                }
                saw_version = true;
                if v > 0 {
                    return Err(SdpError {
                        kind: SdpErrorKind::Version,
                        line: lineno,
                        msg: "only SDP version 0 is defined".into(),
                    });
                }
                // store via a placeholder replaced at the end
                // (we build the Session at the end anyway)
            }
            'o' => {
                let f: Vec<&str> = value.split(' ').collect();
                if f.len() != 6 {
                    return Err(SdpError {
                        kind: SdpErrorKind::Syntax,
                        line: lineno,
                        msg: "o= requires 6 fields".into(),
                    });
                }
                origin = Some(Origin {
                    username: f[0].to_owned(),
                    sess_id: f[1].to_owned(),
                    sess_version: f[2].to_owned(),
                    net_type: f[3].to_owned(),
                    addr_type: f[4].to_owned(),
                    address: f[5].to_owned(),
                });
            }
            's' => name = Some(value.to_owned()),
            'i' => {
                if let Some(m) = cur.as_mut() {
                    m.info = Some(value.to_owned());
                } else {
                    info = Some(value.to_owned());
                }
            }
            'u' | 'e' | 'p' | 'k' | 'z' => {
                if let Some(m) = cur.as_mut() {
                    m.extras.push((typ, value.to_owned()));
                } else {
                    extras.push((typ, value.to_owned()));
                }
            }
            'c' => {
                let c = parse_connection(value, lineno)?;
                if let Some(m) = cur.as_mut() {
                    m.connection = Some(c);
                } else {
                    connection = Some(c);
                }
            }
            'b' => {
                let (modifier, v) = value.split_once(':').ok_or(SdpError {
                    kind: SdpErrorKind::Syntax,
                    line: lineno,
                    msg: "b= requires modifier:value".into(),
                })?;
                let bw = Bandwidth {
                    modifier: modifier.to_owned(),
                    value: v.parse().map_err(|_| SdpError {
                        kind: SdpErrorKind::InvalidValue,
                        line: lineno,
                        msg: format!("bad bandwidth value {:?}", v),
                    })?,
                };
                if let Some(m) = cur.as_mut() {
                    m.bandwidths.push(bw);
                } else {
                    bandwidths.push(bw);
                }
            }
            't' => {
                let f: Vec<&str> = value.split(' ').collect();
                if f.len() != 2 {
                    return Err(SdpError {
                        kind: SdpErrorKind::Syntax,
                        line: lineno,
                        msg: "t= requires 2 fields".into(),
                    });
                }
                timings.push(Timing {
                    start: f[0].parse().map_err(|_| SdpError {
                        kind: SdpErrorKind::InvalidValue,
                        line: lineno,
                        msg: format!("bad time {:?}", f[0]),
                    })?,
                    stop: f[1].parse().map_err(|_| SdpError {
                        kind: SdpErrorKind::InvalidValue,
                        line: lineno,
                        msg: format!("bad time {:?}", f[1]),
                    })?,
                    repeats: Vec::new(),
                });
            }
            'r' => match timings.last_mut() {
                Some(t) => t.repeats.push(value.to_owned()),
                None => {
                    return Err(SdpError {
                        kind: SdpErrorKind::Syntax,
                        line: lineno,
                        msg: "r= without preceding t=".into(),
                    })
                }
            },
            'm' => {
                if let Some(b) = cur.take() {
                    medias.push(b.build()?);
                }
                cur = Some(parse_media(value, lineno)?);
            }
            'a' => {
                let (aname, aval) = match value.split_once(':') {
                    Some((n, v)) => (n, Some(v.to_owned())),
                    None => (value, None),
                };
                if aname.is_empty() {
                    return Err(SdpError {
                        kind: SdpErrorKind::Syntax,
                        line: lineno,
                        msg: "empty attribute name".into(),
                    });
                }
                let attr = Attribute::new(aname, aval);
                if let Some(m) = cur.as_mut() {
                    apply_media_attr(m, attr, lineno)?;
                } else {
                    apply_session_attr(
                        &mut attributes,
                        &mut sess_dir,
                        &mut ice_ufrag,
                        &mut ice_pwd,
                        &mut ice_options,
                        &mut fingerprint,
                        &mut setup,
                        &mut bundle,
                        attr,
                        lineno,
                    )?;
                }
            }
            _ => {
                return Err(SdpError {
                    kind: SdpErrorKind::Syntax,
                    line: lineno,
                    msg: format!("unknown line type {:?}", typ),
                })
            }
        }
    }

    // flush trailing media section
    if let Some(b) = cur.take() {
        medias.push(b.build()?);
    }

    let sess_version: u32 = 0; // v=0 is enforced above
    if !saw_version {
        return Err(SdpError {
            kind: SdpErrorKind::MissingField,
            line: lines,
            msg: "missing v=".into(),
        });
    }
    let origin = origin.ok_or(SdpError {
        kind: SdpErrorKind::MissingField,
        line: lines,
        msg: "missing o=".into(),
    })?;
    let name = name.ok_or(SdpError {
        kind: SdpErrorKind::MissingField,
        line: lines,
        msg: "missing s=".into(),
    })?;
    if timings.is_empty() {
        return Err(SdpError {
            kind: SdpErrorKind::MissingField,
            line: lines,
            msg: "missing t=".into(),
        });
    }

    Ok(Session {
        version: sess_version,
        origin,
        name,
        info,
        connection,
        bandwidths,
        timings,
        attributes,
        extras,
        direction: sess_dir,
        ice_ufrag,
        ice_pwd,
        ice_options,
        fingerprint,
        setup,
        bundle,
        medias,
    })
}

struct MediaBuilder {
    media: String,
    port: u16,
    port_count: u16,
    proto: String,
    formats: Vec<String>,
    info: Option<String>,
    connection: Option<Connection>,
    bandwidths: Vec<Bandwidth>,
    attributes: Vec<Attribute>,
    extras: Vec<(char, String)>,
    rtpmaps: std::collections::BTreeMap<u8, RtpMap>,
    fmtps: std::collections::BTreeMap<u8, String>,
    rtcp_fb: std::collections::BTreeMap<u8, Vec<String>>,
    direction: Option<Direction>,
    rtcp_mux: bool,
    mid: Option<String>,
    ptime: Option<u16>,
    maxptime: Option<u16>,
    ice_ufrag: Option<String>,
    ice_pwd: Option<String>,
    ice_options: Option<String>,
    ice_candidates: Vec<String>,
    fingerprint: Option<Fingerprint>,
    setup: Option<SetupRole>,
    rtcp_addr: Option<(u16, String)>,
    extmaps: Vec<ExtMap>,
    ssrcs: Vec<SsrcInfo>,
}

impl MediaBuilder {
    fn build(self) -> Result<MediaDescription, SdpError> {
        Ok(MediaDescription {
            media: self.media,
            port: self.port,
            port_count: self.port_count,
            proto: self.proto,
            formats: self.formats,
            info: self.info,
            connection: self.connection,
            bandwidths: self.bandwidths,
            attributes: self.attributes,
            extras: self.extras,
            rtpmaps: self.rtpmaps,
            fmtps: self.fmtps,
            rtcp_fb: self.rtcp_fb,
            direction: self.direction,
            rtcp_mux: self.rtcp_mux,
            mid: self.mid,
            ptime: self.ptime,
            maxptime: self.maxptime,
            ice_ufrag: self.ice_ufrag,
            ice_pwd: self.ice_pwd,
            ice_options: self.ice_options,
            ice_candidates: self.ice_candidates,
            fingerprint: self.fingerprint,
            setup: self.setup,
            rtcp_addr: self.rtcp_addr,
            extmaps: self.extmaps,
            ssrcs: self.ssrcs,
        })
    }
}

impl Default for MediaBuilder {
    fn default() -> Self {
        Self {
            media: String::new(),
            port: 0,
            port_count: 1,
            proto: String::new(),
            formats: Vec::new(),
            info: None,
            connection: None,
            bandwidths: Vec::new(),
            attributes: Vec::new(),
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
        }
    }
}

fn parse_media(value: &str, line: usize) -> Result<MediaBuilder, SdpError> {
    let parts: Vec<&str> = value.split(' ').filter(|s| !s.is_empty()).collect();
    if parts.len() < 4 {
        return Err(SdpError {
            kind: SdpErrorKind::Syntax,
            line,
            msg: "m= requires at least 4 fields".into(),
        });
    }
    let (port, port_count) = match parts[1].split_once('/') {
        Some((p, c)) => (
            p.parse::<u16>().map_err(|_| SdpError {
                kind: SdpErrorKind::InvalidValue,
                line,
                msg: format!("bad port {:?}", p),
            })?,
            c.parse::<u16>().map_err(|_| SdpError {
                kind: SdpErrorKind::InvalidValue,
                line,
                msg: format!("bad port count {:?}", c),
            })?,
        ),
        None => (
            parts[1].parse::<u16>().map_err(|_| SdpError {
                kind: SdpErrorKind::InvalidValue,
                line,
                msg: format!("bad port {:?}", parts[1]),
            })?,
            1,
        ),
    };
    Ok(MediaBuilder {
        media: parts[0].to_owned(),
        port,
        port_count,
        proto: parts[2].to_owned(),
        formats: parts[3..].iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    })
}

fn parse_connection(value: &str, line: usize) -> Result<Connection, SdpError> {
    let f: Vec<&str> = value.split(' ').collect();
    if f.len() != 3 || f[0] != "IN" {
        return Err(SdpError {
            kind: SdpErrorKind::Syntax,
            line,
            msg: format!("bad c= line {:?}", value),
        });
    }
    Ok(Connection {
        net_type: f[0].to_owned(),
        addr_type: f[1].to_owned(),
        address: f[2].to_owned(),
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_session_attr(
    attributes: &mut Vec<Attribute>,
    dir: &mut Option<Direction>,
    ice_ufrag: &mut Option<String>,
    ice_pwd: &mut Option<String>,
    ice_options: &mut Option<String>,
    fingerprint: &mut Option<Fingerprint>,
    setup: &mut Option<SetupRole>,
    bundle: &mut Option<BundleGroup>,
    attr: Attribute,
    line: usize,
) -> Result<(), SdpError> {
    match attr.name.as_str() {
        "sendrecv" | "sendonly" | "recvonly" | "inactive" => {
            *dir = Direction::parse(&attr.name);
        }
        "ice-ufrag" => *ice_ufrag = attr.value.clone(),
        "ice-pwd" => *ice_pwd = attr.value.clone(),
        "ice-options" => *ice_options = attr.value.clone(),
        "fingerprint" => {
            *fingerprint = Some(parse_fingerprint(attr.value.as_deref(), line)?);
        }
        "setup" => {
            let v = attr.value.as_deref().unwrap_or("");
            *setup = Some(SetupRole::parse(v).ok_or(SdpError {
                kind: SdpErrorKind::InvalidValue,
                line,
                msg: format!("bad setup role {:?}", v),
            })?);
        }
        "group" => {
            let v = attr.value.as_deref().unwrap_or("");
            if let Some(rest) = v.strip_prefix("BUNDLE") {
                let mids = rest
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_owned())
                    .collect();
                *bundle = Some(BundleGroup { mids });
            }
        }
        _ => {}
    }
    attributes.push(attr);
    Ok(())
}

fn apply_media_attr(m: &mut MediaBuilder, attr: Attribute, line: usize) -> Result<(), SdpError> {
    match attr.name.as_str() {
        "sendrecv" | "sendonly" | "recvonly" | "inactive" => {
            m.direction = Direction::parse(&attr.name);
        }
        "rtcp-mux" => m.rtcp_mux = true,
        "mid" => m.mid = attr.value.clone(),
        "ptime" => {
            m.ptime = Some(parse_u16(attr.value.as_deref(), line)?);
        }
        "maxptime" => {
            m.maxptime = Some(parse_u16(attr.value.as_deref(), line)?);
        }
        "ice-ufrag" => m.ice_ufrag = attr.value.clone(),
        "ice-pwd" => m.ice_pwd = attr.value.clone(),
        "ice-options" => m.ice_options = attr.value.clone(),
        "candidate" => {
            if let Some(v) = attr.value.as_deref() {
                m.ice_candidates.push(v.to_owned());
            }
        }
        "fingerprint" => {
            m.fingerprint = Some(parse_fingerprint(attr.value.as_deref(), line)?);
        }
        "setup" => {
            let v = attr.value.as_deref().unwrap_or("");
            m.setup = Some(SetupRole::parse(v).ok_or(SdpError {
                kind: SdpErrorKind::InvalidValue,
                line,
                msg: format!("bad setup role {:?}", v),
            })?);
        }
        "rtcp" => {
            if let Some(v) = attr.value.as_deref() {
                let mut it = v.split(' ');
                let port = it
                    .next()
                    .and_then(|p| p.parse::<u16>().ok())
                    .ok_or(SdpError {
                        kind: SdpErrorKind::InvalidValue,
                        line,
                        msg: format!("bad rtcp port {:?}", v),
                    })?;
                let rest = it.collect::<Vec<_>>().join(" ");
                m.rtcp_addr = Some((port, rest));
            }
        }
        "extmap" => {
            if let Some(v) = attr.value.as_deref() {
                m.extmaps.push(parse_extmap(v, line)?);
            }
        }
        "ssrc" => {
            if let Some(v) = attr.value.as_deref() {
                let mut it = v.splitn(2, ' ');
                let ssrc = it.next().and_then(|s| s.parse::<u32>().ok()).ok_or(SdpError {
                    kind: SdpErrorKind::InvalidValue,
                    line,
                    msg: format!("bad ssrc {:?}", v),
                })?;
                let rest = it.next().unwrap_or("");
                let (aname, aval) = match rest.split_once(':') {
                    Some((n, v)) => (n, Some(v.to_owned())),
                    None => (rest, None),
                };
                if !aname.is_empty() {
                    m.ssrcs.push(SsrcInfo {
                        ssrc,
                        attr: aname.to_owned(),
                        value: aval,
                    });
                }
            }
        }
        _ => {
            if attr.name == "rtpmap" || attr.name == "fmtp" || attr.name == "rtcp-fb" {
                let v = attr.value.as_deref().unwrap_or("");
                let mut it = v.splitn(2, ' ');
                let pt = it.next().and_then(|p| p.parse::<u8>().ok()).ok_or(SdpError {
                    kind: SdpErrorKind::InvalidValue,
                    line,
                    msg: format!("bad payload type in {:?}", v),
                })?;
                let rest = it.next().unwrap_or("");
                match attr.name.as_str() {
                    "rtpmap" => {
                        let (enc, clock, channels) = parse_rtpmap_value(rest, line)?;
                        m.rtpmaps.insert(
                            pt,
                            RtpMap {
                                payload: pt,
                                encoding: enc,
                                clock_rate: clock,
                                channels,
                            },
                        );
                    }
                    "fmtp" => {
                        m.fmtps.insert(pt, rest.to_owned());
                    }
                    "rtcp-fb" => {
                        m.rtcp_fb.entry(pt).or_default().push(rest.to_owned());
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
    m.attributes.push(attr);
    Ok(())
}

fn parse_fingerprint(value: Option<&str>, line: usize) -> Result<Fingerprint, SdpError> {
    let v = value.ok_or(SdpError {
        kind: SdpErrorKind::Syntax,
        line,
        msg: "fingerprint requires a value".into(),
    })?;
    let (hash, fp) = v.split_once(' ').ok_or(SdpError {
        kind: SdpErrorKind::Syntax,
        line,
        msg: "fingerprint requires `<hash> <value>`".into(),
    })?;
    Ok(Fingerprint {
        hash_func: hash.to_ascii_lowercase(),
        value: fp.to_owned(),
    })
}

fn parse_extmap(value: &str, line: usize) -> Result<ExtMap, SdpError> {
    let mut it = value.splitn(2, ' ');
    let head = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("");
    let (id, dir) = match head.split_once('/') {
        Some((i, d)) => (
            i.parse::<u8>().map_err(|_| SdpError {
                kind: SdpErrorKind::InvalidValue,
                line,
                msg: format!("bad extmap id {:?}", i),
            })?,
            Direction::parse(d),
        ),
        None => (
            head.parse::<u8>().map_err(|_| SdpError {
                kind: SdpErrorKind::InvalidValue,
                line,
                msg: format!("bad extmap id {:?}", head),
            })?,
            None,
        ),
    };
    let mut rest_it = rest.splitn(2, ' ');
    let uri = rest_it.next().unwrap_or("").to_owned();
    let config = rest_it.next().map(|s| s.to_owned());
    if uri.is_empty() {
        return Err(SdpError {
            kind: SdpErrorKind::Syntax,
            line,
            msg: "extmap requires a uri".into(),
        });
    }
    Ok(ExtMap {
        id,
        direction: dir,
        uri,
        config,
    })
}

fn parse_rtpmap_value(value: &str, line: usize) -> Result<(String, u32, Option<u16>), SdpError> {
    let (enc, clock, channels) = match value.split_once('/') {
        Some((e, rest)) => match rest.split_once('/') {
            Some((c, ch)) => (
                e,
                c.parse::<u32>().map_err(|_| SdpError {
                    kind: SdpErrorKind::InvalidValue,
                    line,
                    msg: format!("bad clock rate {:?}", c),
                })?,
                Some(ch.parse::<u16>().map_err(|_| SdpError {
                    kind: SdpErrorKind::InvalidValue,
                    line,
                    msg: format!("bad channel count {:?}", ch),
                })?),
            ),
            None => (e, rest.parse::<u32>().map_err(|_| SdpError {
                kind: SdpErrorKind::InvalidValue,
                line,
                msg: format!("bad clock rate {:?}", rest),
            })?, None),
        },
        None => {
            return Err(SdpError {
                kind: SdpErrorKind::Syntax,
                line,
                msg: format!("bad rtpmap value {:?}", value),
            })
        }
    };
    if enc.is_empty() || clock == 0 {
        return Err(SdpError {
            kind: SdpErrorKind::InvalidValue,
            line,
            msg: format!("bad rtpmap value {:?}", value),
        });
    }
    Ok((enc.to_owned(), clock, channels))
}

fn parse_u16(value: Option<&str>, line: usize) -> Result<u16, SdpError> {
    value
        .and_then(|v| v.trim().parse::<u16>().ok())
        .ok_or(SdpError {
            kind: SdpErrorKind::InvalidValue,
            line,
            msg: "expected u16".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    const SIMPLE: &str = "v=0\r\n\
        o=- 3881397561 3881397561 IN IP4 192.168.1.4\r\n\
        s=Talk\r\n\
        c=IN IP4 192.168.1.4\r\n\
        t=0 0\r\n\
        a=sendrecv\r\n\
        m=audio 4054 RTP/AVP 0 8 101\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        a=rtpmap:8 PCMA/8000\r\n\
        a=rtpmap:101 telephone-event/8000\r\n\
        a=fmtp:101 0-16\r\n\
        a=ptime:20\r\n";

    #[test]
    fn parse_simple() {
        let s = parse(SIMPLE).unwrap();
        assert_eq!(s.version, 0);
        assert_eq!(s.origin.username, "-");
        assert_eq!(s.name, "Talk");
        assert_eq!(s.medias.len(), 1);
        let m = &s.medias[0];
        assert_eq!(m.media, "audio");
        assert_eq!(m.port, 4054);
        assert_eq!(m.formats, vec!["0", "8", "101"]);
        assert_eq!(m.direction, None);
        assert_eq!(s.direction, Some(Direction::SendRecv));
        assert_eq!(m.ptime, Some(20));
        assert_eq!(m.rtpmaps.len(), 3);
        assert_eq!(m.rtpmaps[&101].encoding, "telephone-event");
        assert_eq!(m.fmtps[&101], "0-16");
    }

    #[test]
    fn roundtrip_simple() {
        let s1 = parse(SIMPLE).unwrap();
        let s2 = parse(&s1.serialize()).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn rejects_bad_lines() {
        assert!(parse("v=0\r\ngarbage\r\n").is_err());
        assert!(parse("o=- 1 1 IN IP4 x\r\ns=\r\nt=0 0\r\n").is_err()); // missing v
        assert!(parse("v=0\r\no=- 1 1 IN IP4 x\r\ns=\r\n").is_err()); // missing t
        assert!(parse("v=1\r\no=- 1 1 IN IP4 x\r\ns=\r\nt=0 0\r\n").is_err());
        assert!(parse("v=0\r\no=- 1 1 IN IP4 x\r\ns=\r\nt=0 0\r\nm=audio notaport RTP/AVP 0\r\n").is_err());
        assert!(parse("v=0\r\no=- 1 1 IN IP4 x\r\ns=\r\nt=0 0\r\na=\r\n").is_err());
        // r= without t=
        assert!(parse("v=0\r\no=- 1 1 IN IP4 x\r\ns=\r\nr=604800\r\n").is_err());
    }

    #[test]
    fn tolerates_lf_only() {
        let s = parse(&SIMPLE.replace("\r\n", "\n")).unwrap();
        assert_eq!(s.medias.len(), 1);
    }

    #[test]
    fn multiline_media_sections() {
        let input = "v=0\r\no=- 1 2 IN IP4 1.1.1.1\r\ns=-\r\nt=0 0\r\n\
            m=audio 5000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
            m=video 5002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
            m=audio 0 RTP/AVP 0\r\n";
        let s = parse(input).unwrap();
        assert_eq!(s.medias.len(), 3);
        assert_eq!(s.medias[2].port, 0);
        let rt = parse(&s.serialize()).unwrap();
        assert_eq!(s, rt);
    }
}
