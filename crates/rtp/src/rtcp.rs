//! RTCP packet layer (RFC 3550 §6) including compound packet handling and
//! generic transport/payload feedback headers (RFC 4585).

use crate::packet::RtpError;

/// Sender information from an SR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderInfo {
    pub ssrc: u32,
    pub ntp_sec: u32,
    pub ntp_frac: u32,
    pub rtp_timestamp: u32,
    pub packet_count: u32,
    pub octet_count: u32,
}

/// One reception report block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    pub cumulative_lost: u32,
    pub highest_sequence: u32,
    pub interarrival_jitter: u32,
    pub last_sr: u32,
    pub delay_since_last_sr: u32,
}

/// SDES item type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdesType {
    Cname,
    Name,
    Email,
    Phone,
    Loc,
    Tool,
    Note,
    Priv,
    Unknown(u8),
}

impl SdesType {
    fn from_u8(t: u8) -> SdesType {
        match t {
            1 => SdesType::Cname,
            2 => SdesType::Name,
            3 => SdesType::Email,
            4 => SdesType::Phone,
            5 => SdesType::Loc,
            6 => SdesType::Tool,
            7 => SdesType::Note,
            8 => SdesType::Priv,
            other => SdesType::Unknown(other),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            SdesType::Cname => 1,
            SdesType::Name => 2,
            SdesType::Email => 3,
            SdesType::Phone => 4,
            SdesType::Loc => 5,
            SdesType::Tool => 6,
            SdesType::Note => 7,
            SdesType::Priv => 8,
            SdesType::Unknown(t) => t,
        }
    }
}

/// SDES chunk for one SSRC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub items: Vec<(SdesType, String)>,
}

/// One parsed RTCP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    SenderReport(SenderInfo, Vec<ReportBlock>),
    ReceiverReport {
        ssrc: u32,
        blocks: Vec<ReportBlock>,
    },
    Sdes(Vec<SdesChunk>),
    Bye {
        ssrcs: Vec<u32>,
        reason: Option<String>,
    },
    App {
        subtype: u8,
        ssrc: u32,
        name: [u8; 4],
        data: Vec<u8>,
    },
    /// Generic transport feedback: NACK (fmt=1), TWCC (fmt=15), etc.
    Rtpfb {
        fmt: u8,
        sender_ssrc: u32,
        media_ssrc: u32,
        payload: Vec<u8>,
    },
    /// Payload-specific feedback: PLI (fmt=1), FIR (fmt=4), etc.
    Psfb {
        fmt: u8,
        sender_ssrc: u32,
        media_ssrc: u32,
        payload: Vec<u8>,
    },
    Unknown {
        pt: u8,
        payload: Vec<u8>,
    },
}

const RT: u8 = 0x80;

fn read_report_blocks(buf: &[u8], count: usize, off: usize) -> Result<Vec<ReportBlock>, RtpError> {
    let need = off + count * 24;
    if buf.len() < need {
        return Err(RtpError::TooShort {
            need,
            got: buf.len(),
        });
    }
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let o = off + i * 24;
        blocks.push(ReportBlock {
            ssrc: u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]),
            fraction_lost: buf[o + 4],
            cumulative_lost: u32::from_be_bytes([0, buf[o + 5], buf[o + 6], buf[o + 7]]),
            highest_sequence: u32::from_be_bytes([
                buf[o + 8],
                buf[o + 9],
                buf[o + 10],
                buf[o + 11],
            ]),
            interarrival_jitter: u32::from_be_bytes([
                buf[o + 12],
                buf[o + 13],
                buf[o + 14],
                buf[o + 15],
            ]),
            last_sr: u32::from_be_bytes([buf[o + 16], buf[o + 17], buf[o + 18], buf[o + 19]]),
            delay_since_last_sr: u32::from_be_bytes([
                buf[o + 20],
                buf[o + 21],
                buf[o + 22],
                buf[o + 23],
            ]),
        });
    }
    Ok(blocks)
}

/// Parse a compound RTCP datagram into its packets.
pub fn parse_compound(buf: &[u8]) -> Result<Vec<RtcpPacket>, RtpError> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        if buf.len() < off + 4 {
            return Err(RtpError::Truncated);
        }
        let b0 = buf[off];
        if b0 >> 6 != 2 {
            return Err(RtpError::BadVersion(b0 >> 6));
        }
        let count = (b0 & 0x1F) as usize;
        let pt = buf[off + 1];
        let len_words = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        let pkt_len = (len_words + 1) * 4;
        if buf.len() < off + pkt_len {
            return Err(RtpError::Truncated);
        }
        let body = &buf[off + 4..off + pkt_len];
        let pkt = match pt {
            200 => {
                if body.len() < 24 {
                    return Err(RtpError::Truncated);
                }
                let si = SenderInfo {
                    ssrc: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                    ntp_sec: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                    ntp_frac: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
                    rtp_timestamp: u32::from_be_bytes([body[12], body[13], body[14], body[15]]),
                    packet_count: u32::from_be_bytes([body[16], body[17], body[18], body[19]]),
                    octet_count: u32::from_be_bytes([body[20], body[21], body[22], body[23]]),
                };
                RtcpPacket::SenderReport(si, read_report_blocks(body, count.min(31), 24)?)
            }
            201 => {
                if body.len() < 4 {
                    return Err(RtpError::Truncated);
                }
                let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                RtcpPacket::ReceiverReport {
                    ssrc,
                    blocks: read_report_blocks(body, count.min(31), 4)?,
                }
            }
            202 => {
                let mut chunks = Vec::new();
                let mut co = 0usize;
                for _ in 0..count {
                    if body.len() < co + 4 {
                        return Err(RtpError::Truncated);
                    }
                    let ssrc =
                        u32::from_be_bytes([body[co], body[co + 1], body[co + 2], body[co + 3]]);
                    co += 4;
                    let mut items = Vec::new();
                    loop {
                        if body.len() <= co {
                            return Err(RtpError::Truncated);
                        }
                        let t = body[co];
                        if t == 0 {
                            co += 1;
                            // pad to 4
                            let rem = co % 4;
                            if rem != 0 {
                                co += 4 - rem;
                            }
                            break;
                        }
                        if body.len() < co + 2 {
                            return Err(RtpError::Truncated);
                        }
                        let itype = SdesType::from_u8(t);
                        let ilen = body[co + 1] as usize;
                        if body.len() < co + 2 + ilen {
                            return Err(RtpError::Truncated);
                        }
                        let val =
                            String::from_utf8_lossy(&body[co + 2..co + 2 + ilen]).into_owned();
                        items.push((itype, val));
                        co += 2 + ilen;
                    }
                    chunks.push(SdesChunk { ssrc, items });
                }
                RtcpPacket::Sdes(chunks)
            }
            203 => {
                let mut ssrcs = Vec::with_capacity(count);
                for i in 0..count {
                    let o = i * 4;
                    if body.len() < o + 4 {
                        return Err(RtpError::Truncated);
                    }
                    ssrcs.push(u32::from_be_bytes([
                        body[o],
                        body[o + 1],
                        body[o + 2],
                        body[o + 3],
                    ]));
                }
                // optional reason after SSRCs (padded)
                let mut reason = None;
                let ro = count * 4;
                if body.len() > ro {
                    let rlen = body[ro] as usize;
                    if body.len() >= ro + 1 + rlen {
                        reason = Some(
                            String::from_utf8_lossy(&body[ro + 1..ro + 1 + rlen]).into_owned(),
                        );
                    }
                }
                RtcpPacket::Bye { ssrcs, reason }
            }
            204 => {
                if body.len() < 8 {
                    return Err(RtpError::Truncated);
                }
                RtcpPacket::App {
                    subtype: count as u8,
                    ssrc: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                    name: [body[4], body[5], body[6], body[7]],
                    data: body[8..].to_vec(),
                }
            }
            205 | 206 => {
                if body.len() < 8 {
                    return Err(RtpError::Truncated);
                }
                let fmt = count as u8;
                let sender = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let media = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                let payload = body[8..].to_vec();
                if pt == 205 {
                    RtcpPacket::Rtpfb {
                        fmt,
                        sender_ssrc: sender,
                        media_ssrc: media,
                        payload,
                    }
                } else {
                    RtcpPacket::Psfb {
                        fmt,
                        sender_ssrc: sender,
                        media_ssrc: media,
                        payload,
                    }
                }
            }
            other => RtcpPacket::Unknown {
                pt: other,
                payload: body.to_vec(),
            },
        };
        out.push(pkt);
        off += pkt_len;
    }
    Ok(out)
}

fn put_header(out: &mut Vec<u8>, count: u8, pt: u8, len_words: u16) {
    out.push(RT | count);
    out.push(pt);
    out.extend_from_slice(&len_words.to_be_bytes());
}

fn encode_report_block(out: &mut Vec<u8>, b: &ReportBlock) {
    out.extend_from_slice(&b.ssrc.to_be_bytes());
    out.push(b.fraction_lost);
    out.extend_from_slice(&b.cumulative_lost.to_be_bytes()[1..4]);
    out.extend_from_slice(&b.highest_sequence.to_be_bytes());
    out.extend_from_slice(&b.interarrival_jitter.to_be_bytes());
    out.extend_from_slice(&b.last_sr.to_be_bytes());
    out.extend_from_slice(&b.delay_since_last_sr.to_be_bytes());
}

fn pad4(len: usize) -> usize {
    (4 - len % 4) % 4
}

/// Words after padding; the RTCP length field counts total/4 − 1 where total
/// includes the 4-byte header, so for a body of `len` bytes after the header:
/// length = (4 + body_padded)/4 − 1 = body_padded/4.
fn body_words(body_len: usize) -> u16 {
    ((body_len + pad4(body_len)) / 4) as u16
}

/// Encode multiple RTCP packets into one compound datagram.
pub fn encode_compound(packets: &[RtcpPacket]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for p in packets {
        match p {
            RtcpPacket::SenderReport(si, blocks) => {
                // body after the 4-byte header: ssrc(4) + sender info(20) + blocks
                let body_len = 24 + blocks.len() * 24;
                put_header(
                    &mut out,
                    blocks.len() as u8 & 0x1F,
                    200,
                    body_words(body_len),
                );
                out.extend_from_slice(&si.ssrc.to_be_bytes());
                out.extend_from_slice(&si.ntp_sec.to_be_bytes());
                out.extend_from_slice(&si.ntp_frac.to_be_bytes());
                out.extend_from_slice(&si.rtp_timestamp.to_be_bytes());
                out.extend_from_slice(&si.packet_count.to_be_bytes());
                out.extend_from_slice(&si.octet_count.to_be_bytes());
                for b in blocks {
                    encode_report_block(&mut out, b);
                }
            }
            RtcpPacket::ReceiverReport { ssrc, blocks } => {
                let body_len = 4 + blocks.len() * 24;
                put_header(
                    &mut out,
                    blocks.len() as u8 & 0x1F,
                    201,
                    body_words(body_len),
                );
                out.extend_from_slice(&ssrc.to_be_bytes());
                for b in blocks {
                    encode_report_block(&mut out, b);
                }
            }
            RtcpPacket::Sdes(chunks) => {
                let start = out.len();
                put_header(&mut out, chunks.len() as u8 & 0x1F, 202, 0);
                for c in chunks {
                    out.extend_from_slice(&c.ssrc.to_be_bytes());
                    for (t, v) in &c.items {
                        out.push(t.to_u8());
                        out.push(v.len() as u8);
                        out.extend_from_slice(v.as_bytes());
                    }
                    out.push(0);
                    let pad = pad4(out.len() - start);
                    out.extend(std::iter::repeat_n(0, pad));
                }
                // fix length
                let total = out.len() - start;
                let words = (total / 4) as u16 - 1;
                out[start + 2..start + 4].copy_from_slice(&words.to_be_bytes());
            }
            RtcpPacket::Bye { ssrcs, reason } => {
                let rbytes = reason.as_ref().map(|r| r.as_bytes()).unwrap_or(&[]);
                let mut body_len = ssrcs.len() * 4;
                if !rbytes.is_empty() {
                    body_len += 1 + rbytes.len();
                }
                put_header(
                    &mut out,
                    ssrcs.len() as u8 & 0x1F,
                    203,
                    body_words(body_len),
                );
                for s in ssrcs {
                    out.extend_from_slice(&s.to_be_bytes());
                }
                if !rbytes.is_empty() {
                    out.push(rbytes.len() as u8);
                    out.extend_from_slice(rbytes);
                    let pad = pad4(1 + rbytes.len());
                    out.extend(std::iter::repeat_n(0, pad));
                }
            }
            RtcpPacket::App {
                subtype,
                ssrc,
                name,
                data,
            } => {
                let body_len = 8 + data.len();
                put_header(&mut out, subtype & 0x1F, 204, body_words(body_len));
                out.extend_from_slice(&ssrc.to_be_bytes());
                out.extend_from_slice(name);
                out.extend_from_slice(data);
                let pad = pad4(data.len());
                out.extend(std::iter::repeat_n(0, pad));
            }
            RtcpPacket::Rtpfb {
                fmt,
                sender_ssrc,
                media_ssrc,
                payload,
            }
            | RtcpPacket::Psfb {
                fmt,
                sender_ssrc,
                media_ssrc,
                payload,
            } => {
                let pt = if matches!(p, RtcpPacket::Rtpfb { .. }) {
                    205
                } else {
                    206
                };
                let body_len = 8 + payload.len();
                put_header(&mut out, *fmt & 0x1F, pt, body_words(body_len));
                out.extend_from_slice(&sender_ssrc.to_be_bytes());
                out.extend_from_slice(&media_ssrc.to_be_bytes());
                out.extend_from_slice(payload);
                let pad = pad4(payload.len());
                out.extend(std::iter::repeat_n(0, pad));
            }
            RtcpPacket::Unknown { pt, payload } => {
                put_header(&mut out, 0, *pt, body_words(payload.len()));
                out.extend_from_slice(payload);
                let pad = pad4(payload.len());
                out.extend(std::iter::repeat_n(0, pad));
            }
        }
    }
    out
}

/// Encode one RTCP packet (wraps [`encode_compound`]).
pub fn encode_packet(p: &RtcpPacket) -> Vec<u8> {
    encode_compound(std::slice::from_ref(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sr_rr_roundtrip() {
        let sr = RtcpPacket::SenderReport(
            SenderInfo {
                ssrc: 0x1234_5678,
                ntp_sec: 4_000_000_000,
                ntp_frac: 500_000_000,
                rtp_timestamp: 12345,
                packet_count: 100,
                octet_count: 16000,
            },
            vec![ReportBlock {
                ssrc: 0xABCD,
                fraction_lost: 2,
                cumulative_lost: 7,
                highest_sequence: 0x1_000F,
                interarrival_jitter: 4,
                last_sr: 0,
                delay_since_last_sr: 0,
            }],
        );
        let rr = RtcpPacket::ReceiverReport {
            ssrc: 0x9999,
            blocks: vec![ReportBlock {
                ssrc: 0x1234_5678,
                fraction_lost: 0,
                cumulative_lost: 0,
                highest_sequence: 555,
                interarrival_jitter: 1,
                last_sr: 77,
                delay_since_last_sr: 3,
            }],
        };
        let compound = encode_compound(&[sr.clone(), rr.clone()]);
        let parsed = parse_compound(&compound).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], sr);
        assert_eq!(parsed[1], rr);
    }

    #[test]
    fn sdes_bye_roundtrip() {
        let sdes = RtcpPacket::Sdes(vec![SdesChunk {
            ssrc: 42,
            items: vec![(SdesType::Cname, "user@host".to_owned())],
        }]);
        let bye = RtcpPacket::Bye {
            ssrcs: vec![42],
            reason: Some("call ended".to_owned()),
        };
        let compound = encode_compound(&[sdes.clone(), bye.clone()]);
        let parsed = parse_compound(&compound).unwrap();
        assert_eq!(parsed[0], sdes);
        assert_eq!(parsed[1], bye);
    }

    #[test]
    fn fb_roundtrip() {
        let nack = RtcpPacket::Rtpfb {
            fmt: 1,
            sender_ssrc: 1,
            media_ssrc: 2,
            payload: vec![0x00, 0x05, 0xA0, 0x00], // NACK for seq 5, blp 0xA000
        };
        let pli = RtcpPacket::Psfb {
            fmt: 1,
            sender_ssrc: 1,
            media_ssrc: 2,
            payload: vec![],
        };
        let compound = encode_compound(&[nack.clone(), pli.clone()]);
        let parsed = parse_compound(&compound).unwrap();
        assert_eq!(parsed[0], nack);
        assert_eq!(parsed[1], pli);
    }

    #[test]
    fn app_roundtrip() {
        // APP data length is application-defined; padding to 4 bytes is part
        // of the wire format, so roundtrip is exact for aligned data.
        let app = RtcpPacket::App {
            subtype: 3,
            ssrc: 9,
            name: *b"TEST",
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let parsed = parse_compound(&encode_packet(&app)).unwrap();
        assert_eq!(parsed[0], app);
        // non-aligned data parses without panic (trailing pad bytes included)
        let app2 = RtcpPacket::App {
            subtype: 0,
            ssrc: 1,
            name: *b"XXXX",
            data: vec![9, 9, 9],
        };
        let parsed2 = parse_compound(&encode_packet(&app2)).unwrap();
        match &parsed2[0] {
            RtcpPacket::App { data, .. } => assert_eq!(data.len(), 4),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn rejects_bad_version_and_truncation() {
        assert!(parse_compound(&[0x00, 200, 0, 6]).is_err());
        assert!(parse_compound(&[0x80, 200, 0, 6, 0]).is_err()); // claims 7 words
        assert!(parse_compound(&[]).is_ok()); // empty compound is empty vec
    }

    #[test]
    fn ssrc_info_octet_count_not_confused() {
        // regression: SR packet_count and octet_count fields must not be swapped
        let si = SenderInfo {
            ssrc: 1,
            ntp_sec: 2,
            ntp_frac: 3,
            rtp_timestamp: 4,
            packet_count: 5,
            octet_count: 6,
        };
        let parsed = parse_compound(&encode_packet(&RtcpPacket::SenderReport(si, vec![]))).unwrap();
        match &parsed[0] {
            RtcpPacket::SenderReport(si2, _) => {
                assert_eq!(si2.packet_count, 5);
                assert_eq!(si2.octet_count, 6);
            }
            _ => panic!("wrong type"),
        }
    }
}
