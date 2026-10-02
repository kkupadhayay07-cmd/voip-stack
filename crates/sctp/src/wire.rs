//! SCTP wire format: common header, chunk TLV codec ([RFC 9260] §3.1/§3.3).
//!
//! All integers are big-endian. Chunk bodies are padded to 4-byte boundaries
//! with zero octets; the chunk `length` field includes the 4-byte chunk
//! header but not the padding.
//!
//! [RFC 9260]: https://datatracker.ietf.org/doc/html/rfc9260

use crate::crc32c;

/// Chunk types (RFC 9260 §3.3.1).
pub const CT_DATA: u8 = 0;
pub const CT_INIT: u8 = 1;
pub const CT_INIT_ACK: u8 = 2;
pub const CT_SACK: u8 = 3;
pub const CT_HEARTBEAT: u8 = 4;
pub const CT_HEARTBEAT_ACK: u8 = 5;
pub const CT_ABORT: u8 = 6;
pub const CT_SHUTDOWN: u8 = 7;
pub const CT_SHUTDOWN_ACK: u8 = 8;
pub const CT_ERROR: u8 = 9;
pub const CT_COOKIE_ECHO: u8 = 10;
pub const CT_COOKIE_ACK: u8 = 11;
pub const CT_SHUTDOWN_COMPLETE: u8 = 14;
/// RFC 3758 FORWARD-TSN (chunk types ≥ 0xC0 are "skip and report" class).
pub const CT_FORWARD_TSN: u8 = 0xC0;
/// RFC 6525 RE-CONFIG chunk (stream reconfiguration).
pub const CT_RE_CONFIG: u8 = 130;

/// Parameter types (RFC 9260 §3.3.2.1, RFC 5061).
pub const PT_HEARTBEAT_INFO: u16 = 1;
pub const PT_IPV4: u16 = 5;
pub const PT_IPV6: u16 = 6;
pub const PT_COOKIE_PRESERVATIVE: u16 = 7;
/// State Cookie — same numeric value as the cookie-preservative, but only
/// legal inside INIT-ACK (context disambiguates).
pub const PT_STATE_COOKIE: u16 = 7;
pub const PT_SUPPORTED_ADDR_TYPES: u16 = 9;
pub const PT_ECN: u16 = 0x8000;
/// RFC 5061 Supported Extensions — carries the FORWARD-TSN chunk type to
/// signal PR-SCTP support (RFC 3758 §3.1) and the RE-CONFIG chunk type to
/// signal stream-reset support (RFC 6525 §5 — via RFC 5061 signaling per
/// RFC 8831 §6.1).
pub const PT_SUPPORTED_EXTENSIONS: u16 = 0x8008;

/// RFC 6525 §4.1 Outgoing SSN Reset Request parameter.
pub const RC_PARAM_OUTGOING_SSN_RESET: u16 = 13;
/// RFC 6525 §4.4 Re-configuration Response parameter.
pub const RC_PARAM_RESPONSE: u16 = 16;

/// RFC 6525 §4.4 Result values.
pub const RC_RESULT_NOTHING_TO_DO: u32 = 0;
/// Success — the reset was performed.
pub const RC_RESULT_PERFORMED: u32 = 1;
/// The peer refused the reset.
pub const RC_RESULT_DENIED: u32 = 2;
/// Error — wrong SSN (stale/invalid request).
pub const RC_RESULT_WRONG_SSN: u32 = 3;
/// The peer has its own request in progress.
pub const RC_RESULT_IN_PROGRESS_PEER: u32 = 4;
/// Error — bad sequence number.
pub const RC_RESULT_BAD_SEQ: u32 = 5;
/// Deferred reset processing is underway (E2); a final response follows.
pub const RC_RESULT_IN_PROGRESS: u32 = 6;

/// Cause codes for ABORT/ERROR (RFC 9260 §3.3.10). Cause 3 doubles as a
/// recognized INIT-ACK parameter when a stale state cookie is refreshed
/// (§5.1.5): the value is the measured staleness in microseconds.
pub const CAUSE_STALE_COOKIE: u16 = 3;
pub const CAUSE_UNRECOGNIZED_CHUNK: u16 = 6;

/// DATA chunk flag bits.
pub const FLAG_DATA_E: u8 = 0x01; // end of fragmented user message
pub const FLAG_DATA_B: u8 = 0x02; // begin of fragmented user message
pub const FLAG_DATA_U: u8 = 0x04; // unordered
/// RFC 7053 SACK-IMMEDIATELY (we always SACK immediately; parsed for fidelity).
pub const FLAG_DATA_I: u8 = 0x08;

/// ABORT / SHUTDOWN-COMPLETE T-bit: the verification tag in the packet is
/// the peer's own tag (reflected), not ours.
pub const FLAG_T: u8 = 0x01;

/// One SACK gap-ack block: TSN range `cum_tsn + start ..= cum_tsn + end`
/// (offsets are ≥ 1 per RFC 9260 §3.3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlock {
    pub start: u16,
    pub end: u16,
}

/// A raw parameter TLV (context-dependent typing is done by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawParam {
    pub ptype: u16,
    pub value: Vec<u8>,
}

/// DATA chunk (§3.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChunk {
    pub tsn: u32,
    pub stream: u16,
    pub ssn: u16,
    pub ppid: u32,
    pub begin: bool,
    pub end: bool,
    pub unordered: bool,
    /// RFC 7053 SACK-IMMEDIATELY bit.
    pub immediate_sack: bool,
    pub payload: Vec<u8>,
}

/// INIT / INIT-ACK chunk (§3.3.2/§3.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitChunk {
    pub initiate_tag: u32,
    pub a_rwnd: u32,
    pub os: u16,
    pub mis: u16,
    pub initial_tsn: u32,
    pub params: Vec<RawParam>,
}

impl InitChunk {
    pub fn param(&self, ptype: u16) -> Option<&[u8]> {
        self.params
            .iter()
            .find(|p| p.ptype == ptype)
            .map(|p| p.value.as_slice())
    }
}

/// SACK chunk (§3.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SackChunk {
    pub cum_tsn: u32,
    pub a_rwnd: u32,
    pub gaps: Vec<SackBlock>,
    pub dups: Vec<u32>,
}

/// Parsed chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    Data(DataChunk),
    Init(InitChunk),
    InitAck(InitChunk),
    Sack(SackChunk),
    Heartbeat {
        info: Vec<u8>,
    },
    HeartbeatAck {
        info: Vec<u8>,
    },
    Abort {
        /// Raw cause TLVs (each already parsed out).
        causes: Vec<RawParam>,
        reflected: bool,
    },
    Error {
        causes: Vec<RawParam>,
    },
    Shutdown {
        cum_tsn: u32,
    },
    ShutdownAck,
    ShutdownComplete {
        reflected: bool,
    },
    CookieEcho {
        cookie: Vec<u8>,
    },
    CookieAck,
    ForwardTsn {
        new_cum_tsn: u32,
        /// Per-stream skips (sid, highest abandoned ssn) for ordered streams.
        streams: Vec<(u16, u16)>,
    },
    /// RFC 6525 RE-CONFIG: the only chunk that carries stream-reset
    /// parameters. Only the two parameters the data-channel close needs are
    /// decoded (Outgoing SSN Reset Request §4.1, Response §4.4); unknown
    /// parameter types are skipped (they cannot appear mid-chunk before a
    /// known one in the combinations we emit or accept).
    ReConfig(ReConfigChunk),
    /// Unrecognized chunk, preserved verbatim so the association can honor
    /// the RFC 9260 §3.3.1 report rules.
    Unknown {
        ctype: u8,
        flags: u8,
        body: Vec<u8>,
    },
}

/// RFC 6525 RE-CONFIG chunk body: one or two re-configuration parameters.
/// (The chunk has NO ARWND field — §3.1 puts the parameters directly after
/// the chunk header.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReConfigChunk {
    pub params: Vec<ReConfigParam>,
}

/// The decoded RFC 6525 parameters (the close-channel subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReConfigParam {
    /// §4.1 Outgoing SSN Reset Request: reset the SSNs of the listed
    /// OUTGOING streams of the sender. `rsn` identifies the request (init
    /// value = the sender's initial TSN); `response_seq` is the next
    /// expected peer RSN minus 1; `last_tsn` is the sender's last assigned
    /// TSN (next TSN minus 1). An empty `streams` list means ALL streams.
    OutgoingSsnReset {
        rsn: u32,
        response_seq: u32,
        last_tsn: u32,
        streams: Vec<u16>,
    },
    /// §4.4 Response: `rsn` is copied from the request; `result` is one of
    /// the `RC_RESULT_*` values.
    Response { rsn: u32, result: u32 },
}

impl Chunk {
    pub fn chunk_type(&self) -> u8 {
        match self {
            Chunk::Data(_) => CT_DATA,
            Chunk::Init(_) => CT_INIT,
            Chunk::InitAck(_) => CT_INIT_ACK,
            Chunk::Sack(_) => CT_SACK,
            Chunk::Heartbeat { .. } => CT_HEARTBEAT,
            Chunk::HeartbeatAck { .. } => CT_HEARTBEAT_ACK,
            Chunk::Abort { .. } => CT_ABORT,
            Chunk::Error { .. } => CT_ERROR,
            Chunk::Shutdown { .. } => CT_SHUTDOWN,
            Chunk::ShutdownAck => CT_SHUTDOWN_ACK,
            Chunk::ShutdownComplete { .. } => CT_SHUTDOWN_COMPLETE,
            Chunk::CookieEcho { .. } => CT_COOKIE_ECHO,
            Chunk::CookieAck => CT_COOKIE_ACK,
            Chunk::ForwardTsn { .. } => CT_FORWARD_TSN,
            Chunk::ReConfig(_) => CT_RE_CONFIG,
            Chunk::Unknown { ctype, .. } => *ctype,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SctpError {
    #[error("packet shorter than the 12-byte common header")]
    TooShort,
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("malformed chunk: {0}")]
    BadChunk(&'static str),
    #[error("message too large ({0} bytes > local max)")]
    MessageTooLarge(usize),
    #[error("send buffer exhausted")]
    SendBufferFull,
    #[error("association is not in a state that allows this operation ({0})")]
    WrongState(&'static str),
    #[error("stream {0} is not an open data channel")]
    UnknownStream(u16),
    #[error("stream {0} is closing (a stream reset is in flight)")]
    ChannelClosing(u16),
    #[error("another RFC 6525 stream-reset request is already in flight")]
    ReconfigBusy,
}

pub(crate) fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

fn be16(b: &[u8], at: usize) -> Result<u16, SctpError> {
    b.get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(SctpError::TooShort)
}

fn be32(b: &[u8], at: usize) -> Result<u32, SctpError> {
    b.get(at..at + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(SctpError::TooShort)
}

/// A parsed SCTP packet: common header fields + chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub vtag: u32,
    pub chunks: Vec<Chunk>,
}

/// Parse an SCTP packet. `verify_checksum` enforces the CRC32c (the
/// association always does; tests of malformed hand-built vectors may pass
/// `false` when the vector predates the checksum patch step).
pub fn parse_packet(buf: &[u8], verify_checksum: bool) -> Result<SctpPacket, SctpError> {
    if buf.len() < 12 {
        return Err(SctpError::TooShort);
    }
    if verify_checksum && !crc32c::validate_packet(buf, 8) {
        return Err(SctpError::BadChecksum);
    }
    let src_port = be16(buf, 0)?;
    let dst_port = be16(buf, 2)?;
    let vtag = be32(buf, 4)?;

    let mut chunks = Vec::new();
    let mut pos = 12usize;
    while pos + 4 <= buf.len() {
        let ctype = buf[pos];
        let flags = buf[pos + 1];
        let clen = be16(buf, pos + 2)? as usize;
        if clen < 4 {
            return Err(SctpError::BadChunk("chunk length < 4"));
        }
        if pos + clen > buf.len() {
            return Err(SctpError::BadChunk("chunk length exceeds packet"));
        }
        let body = &buf[pos + 4..pos + clen];
        let chunk = parse_chunk(ctype, flags, body)?;
        chunks.push(chunk);
        pos += pad4(clen);
    }
    // Trailing < 4 bytes are padding remnants — ignored per RFC 9260 §3.3.1.

    Ok(SctpPacket {
        src_port,
        dst_port,
        vtag,
        chunks,
    })
}

fn parse_chunk(ctype: u8, flags: u8, body: &[u8]) -> Result<Chunk, SctpError> {
    match ctype {
        CT_DATA => {
            if body.len() < 12 {
                return Err(SctpError::BadChunk("DATA body < 12"));
            }
            let payload = body[12..].to_vec();
            Ok(Chunk::Data(DataChunk {
                tsn: be32(body, 0)?,
                stream: be16(body, 4)?,
                ssn: be16(body, 6)?,
                ppid: be32(body, 8)?,
                begin: flags & FLAG_DATA_B != 0,
                end: flags & FLAG_DATA_E != 0,
                unordered: flags & FLAG_DATA_U != 0,
                immediate_sack: flags & FLAG_DATA_I != 0,
                payload,
            }))
        }
        CT_INIT | CT_INIT_ACK => {
            if body.len() < 16 {
                return Err(SctpError::BadChunk("INIT body < 16"));
            }
            let params = parse_params(&body[16..])?;
            let init = InitChunk {
                initiate_tag: be32(body, 0)?,
                a_rwnd: be32(body, 4)?,
                os: be16(body, 8)?,
                mis: be16(body, 10)?,
                initial_tsn: be32(body, 12)?,
                params,
            };
            Ok(if ctype == CT_INIT {
                Chunk::Init(init)
            } else {
                Chunk::InitAck(init)
            })
        }
        CT_SACK => {
            if body.len() < 12 {
                return Err(SctpError::BadChunk("SACK body < 12"));
            }
            let cum_tsn = be32(body, 0)?;
            let a_rwnd = be32(body, 4)?;
            let num_gaps = be16(body, 8)? as usize;
            let num_dups = be16(body, 10)? as usize;
            if body.len() < 12 + num_gaps * 4 + num_dups * 4 {
                return Err(SctpError::BadChunk("SACK blocks exceed body"));
            }
            let mut gaps = Vec::with_capacity(num_gaps);
            for i in 0..num_gaps {
                let at = 12 + i * 4;
                gaps.push(SackBlock {
                    start: be16(body, at)?,
                    end: be16(body, at + 2)?,
                });
            }
            let mut dups = Vec::with_capacity(num_dups);
            for i in 0..num_dups {
                dups.push(be32(body, 12 + num_gaps * 4 + i * 4)?);
            }
            Ok(Chunk::Sack(SackChunk {
                cum_tsn,
                a_rwnd,
                gaps,
                dups,
            }))
        }
        CT_HEARTBEAT | CT_HEARTBEAT_ACK => {
            let params = parse_params(body)?;
            let info = params
                .iter()
                .find(|p| p.ptype == PT_HEARTBEAT_INFO)
                .map(|p| p.value.clone())
                .ok_or(SctpError::BadChunk("HEARTBEAT without info param"))?;
            Ok(if ctype == CT_HEARTBEAT {
                Chunk::Heartbeat { info }
            } else {
                Chunk::HeartbeatAck { info }
            })
        }
        CT_ABORT => Ok(Chunk::Abort {
            causes: parse_params(body)?,
            reflected: flags & FLAG_T != 0,
        }),
        CT_ERROR => Ok(Chunk::Error {
            causes: parse_params(body)?,
        }),
        CT_SHUTDOWN => {
            if body.len() < 4 {
                return Err(SctpError::BadChunk("SHUTDOWN body < 4"));
            }
            Ok(Chunk::Shutdown {
                cum_tsn: be32(body, 0)?,
            })
        }
        CT_SHUTDOWN_ACK => Ok(Chunk::ShutdownAck),
        CT_SHUTDOWN_COMPLETE => Ok(Chunk::ShutdownComplete {
            reflected: flags & FLAG_T != 0,
        }),
        CT_COOKIE_ECHO => Ok(Chunk::CookieEcho {
            cookie: body.to_vec(),
        }),
        CT_COOKIE_ACK => Ok(Chunk::CookieAck),
        CT_FORWARD_TSN => {
            if body.len() < 4 {
                return Err(SctpError::BadChunk("FORWARD-TSN body < 4"));
            }
            let new_cum_tsn = be32(body, 0)?;
            let n = (body.len() - 4) / 4;
            let mut streams = Vec::with_capacity(n);
            for i in 0..n {
                let at = 4 + i * 4;
                streams.push((be16(body, at)?, be16(body, at + 2)?));
            }
            Ok(Chunk::ForwardTsn {
                new_cum_tsn,
                streams,
            })
        }
        CT_RE_CONFIG => {
            let params = parse_re_config_params(body)?;
            Ok(Chunk::ReConfig(ReConfigChunk { params }))
        }
        _ => Ok(Chunk::Unknown {
            ctype,
            flags,
            body: body.to_vec(),
        }),
    }
}

/// Parse RE-CONFIG chunk parameters (RFC 6525 §3.1: at least one, at most
/// two; each is a padded TLV like a chunk param).
///
/// Only the two data-channel-close parameters are decoded; unknown types are
/// skipped but still advance the cursor (the RFC 4960 §3.2.1 upper-bits
/// reporting classes are folded into that skip — the association reports
/// nothing for unknown params, matching the documented chunk-level gap).
/// Per the Task 47 lesson the ADVANCE of the last (possibly padded) param is
/// bounded: an overrun stops the walk cleanly at the chunk end.
pub fn parse_re_config_params(mut buf: &[u8]) -> Result<Vec<ReConfigParam>, SctpError> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let ptype = be16(buf, 0)?;
        let plen = be16(buf, 2)? as usize;
        if plen < 4 || plen > buf.len() {
            return Err(SctpError::BadChunk("RE-CONFIG param length invalid"));
        }
        let value = &buf[4..plen];
        match (ptype, value.len()) {
            (RC_PARAM_OUTGOING_SSN_RESET, v) if v >= 12 => {
                let rsn = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                let response_seq = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                let last_tsn = u32::from_be_bytes([value[8], value[9], value[10], value[11]]);
                // §4.1: stream numbers are 2-byte fields packed adjacently
                // (no per-stream reserved word); the parameter length is
                // 16 + 2*N with the TLV header included.
                let streams = value[12..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| u16::from_be_bytes(*p))
                    .collect();
                out.push(ReConfigParam::OutgoingSsnReset {
                    rsn,
                    response_seq,
                    last_tsn,
                    streams,
                });
            }
            (RC_PARAM_RESPONSE, v) if v >= 8 => {
                let rsn = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                let result = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                out.push(ReConfigParam::Response { rsn, result });
            }
            _ => {
                // Unknown re-configuration parameter: skip it (length was
                // already validated against the buffer).
            }
        }
        let adv = pad4(plen);
        if adv >= buf.len() {
            break;
        }
        buf = &buf[adv..];
    }
    Ok(out)
}

/// Encode one RE-CONFIG parameter TLV (header + value + zero padding).
fn encode_re_config_param(p: &ReConfigParam, out: &mut Vec<u8>) {
    match p {
        ReConfigParam::OutgoingSsnReset {
            rsn,
            response_seq,
            last_tsn,
            streams,
        } => {
            let plen = 16 + 2 * streams.len();
            out.extend_from_slice(&RC_PARAM_OUTGOING_SSN_RESET.to_be_bytes());
            out.extend_from_slice(&(plen as u16).to_be_bytes());
            out.extend_from_slice(&rsn.to_be_bytes());
            out.extend_from_slice(&response_seq.to_be_bytes());
            out.extend_from_slice(&last_tsn.to_be_bytes());
            for s in streams {
                out.extend_from_slice(&s.to_be_bytes());
            }
            out.resize(out.len() + pad4(plen) - plen, 0);
        }
        ReConfigParam::Response { rsn, result } => {
            out.extend_from_slice(&RC_PARAM_RESPONSE.to_be_bytes());
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&rsn.to_be_bytes());
            out.extend_from_slice(&result.to_be_bytes());
        }
    }
}

/// Parse a padded sequence of parameter TLVs.
///
/// The padded advance of the LAST parameter may run past the end of the
/// buffer (e.g. a trailing param with `plen = 6` in a 6-byte tail pads to
/// 8): like usrsctp/libwebrtc, stop cleanly at the chunk end instead of
/// slicing out of bounds.
pub fn parse_params(mut buf: &[u8]) -> Result<Vec<RawParam>, SctpError> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let ptype = be16(buf, 0)?;
        let plen = be16(buf, 2)? as usize;
        if plen < 4 || plen > buf.len() {
            return Err(SctpError::BadChunk("param length invalid"));
        }
        out.push(RawParam {
            ptype,
            value: buf[4..plen].to_vec(),
        });
        let adv = pad4(plen);
        if adv >= buf.len() {
            break;
        }
        buf = &buf[adv..];
    }
    Ok(out)
}

/// Encode a parameter TLV with zero padding to the 4-byte boundary.
pub fn encode_param(ptype: u16, value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&ptype.to_be_bytes());
    out.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(value);
    out.resize(out.len() + pad4(value.len() + 4) - (value.len() + 4), 0);
}

/// Encode one chunk (header + body + zero padding) into `out`.
pub fn encode_chunk(ctype: u8, flags: u8, body: &[u8], out: &mut Vec<u8>) {
    let start = out.len();
    out.extend_from_slice(&ctype.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // patched below
    out.extend_from_slice(body);
    let clen = out.len() - start;
    out.resize(out.len() + pad4(clen) - clen, 0);
    out[start + 2..start + 4].copy_from_slice(&(clen as u16).to_be_bytes());
}

/// Encode a full SCTP packet: common header, chunks, checksum patched in.
pub fn encode_packet(src_port: u16, dst_port: u16, vtag: u32, chunks: &[Chunk]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1400);
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&vtag.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // checksum placeholder

    for chunk in chunks {
        encode_chunk_into(chunk, &mut buf);
    }

    let csum = crc32c::packet_checksum(&buf);
    buf[8..12].copy_from_slice(&csum.to_be_bytes());
    buf
}

fn encode_chunk_into(chunk: &Chunk, out: &mut Vec<u8>) {
    match chunk {
        Chunk::Data(d) => {
            let mut flags = 0u8;
            if d.end {
                flags |= FLAG_DATA_E;
            }
            if d.begin {
                flags |= FLAG_DATA_B;
            }
            if d.unordered {
                flags |= FLAG_DATA_U;
            }
            if d.immediate_sack {
                flags |= FLAG_DATA_I;
            }
            let mut body = Vec::with_capacity(12 + d.payload.len());
            body.extend_from_slice(&d.tsn.to_be_bytes());
            body.extend_from_slice(&d.stream.to_be_bytes());
            body.extend_from_slice(&d.ssn.to_be_bytes());
            body.extend_from_slice(&d.ppid.to_be_bytes());
            body.extend_from_slice(&d.payload);
            encode_chunk(CT_DATA, flags, &body, out);
        }
        Chunk::Init(i) => encode_init_like(CT_INIT, i, out),
        Chunk::InitAck(i) => encode_init_like(CT_INIT_ACK, i, out),
        Chunk::Sack(s) => {
            let mut body = Vec::with_capacity(12 + s.gaps.len() * 4 + s.dups.len() * 4);
            body.extend_from_slice(&s.cum_tsn.to_be_bytes());
            body.extend_from_slice(&s.a_rwnd.to_be_bytes());
            body.extend_from_slice(&(s.gaps.len() as u16).to_be_bytes());
            body.extend_from_slice(&(s.dups.len() as u16).to_be_bytes());
            for g in &s.gaps {
                body.extend_from_slice(&g.start.to_be_bytes());
                body.extend_from_slice(&g.end.to_be_bytes());
            }
            for d in &s.dups {
                body.extend_from_slice(&d.to_be_bytes());
            }
            encode_chunk(CT_SACK, 0, &body, out);
        }
        Chunk::Heartbeat { info } => {
            let mut body = Vec::new();
            encode_param(PT_HEARTBEAT_INFO, info, &mut body);
            encode_chunk(CT_HEARTBEAT, 0, &body, out);
        }
        Chunk::HeartbeatAck { info } => {
            let mut body = Vec::new();
            encode_param(PT_HEARTBEAT_INFO, info, &mut body);
            encode_chunk(CT_HEARTBEAT_ACK, 0, &body, out);
        }
        Chunk::Abort { causes, reflected } => {
            let mut body = Vec::new();
            for c in causes {
                encode_param(c.ptype, &c.value, &mut body);
            }
            let flags = if *reflected { FLAG_T } else { 0 };
            encode_chunk(CT_ABORT, flags, &body, out);
        }
        Chunk::Error { causes } => {
            let mut body = Vec::new();
            for c in causes {
                encode_param(c.ptype, &c.value, &mut body);
            }
            encode_chunk(CT_ERROR, 0, &body, out);
        }
        Chunk::Shutdown { cum_tsn } => {
            encode_chunk(CT_SHUTDOWN, 0, &cum_tsn.to_be_bytes(), out);
        }
        Chunk::ShutdownAck => encode_chunk(CT_SHUTDOWN_ACK, 0, &[], out),
        Chunk::ShutdownComplete { reflected } => {
            let flags = if *reflected { FLAG_T } else { 0 };
            encode_chunk(CT_SHUTDOWN_COMPLETE, flags, &[], out);
        }
        Chunk::CookieEcho { cookie } => {
            encode_chunk(CT_COOKIE_ECHO, 0, cookie, out);
        }
        Chunk::CookieAck => encode_chunk(CT_COOKIE_ACK, 0, &[], out),
        Chunk::ForwardTsn {
            new_cum_tsn,
            streams,
        } => {
            let mut body = Vec::with_capacity(4 + streams.len() * 4);
            body.extend_from_slice(&new_cum_tsn.to_be_bytes());
            for (sid, ssn) in streams {
                body.extend_from_slice(&sid.to_be_bytes());
                body.extend_from_slice(&ssn.to_be_bytes());
            }
            encode_chunk(CT_FORWARD_TSN, 0, &body, out);
        }
        Chunk::ReConfig(rc) => {
            let mut body = Vec::new();
            for p in &rc.params {
                encode_re_config_param(p, &mut body);
            }
            encode_chunk(CT_RE_CONFIG, 0, &body, out);
        }
        Chunk::Unknown { ctype, flags, body } => {
            encode_chunk(*ctype, *flags, body, out);
        }
    }
}

fn encode_init_like(ctype: u8, i: &InitChunk, out: &mut Vec<u8>) {
    let mut body = Vec::with_capacity(16 + i.params.len() * 8);
    body.extend_from_slice(&i.initiate_tag.to_be_bytes());
    body.extend_from_slice(&i.a_rwnd.to_be_bytes());
    body.extend_from_slice(&i.os.to_be_bytes());
    body.extend_from_slice(&i.mis.to_be_bytes());
    body.extend_from_slice(&i.initial_tsn.to_be_bytes());
    for p in &i.params {
        encode_param(p.ptype, &p.value, &mut body);
    }
    encode_chunk(ctype, 0, &body, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built INIT packet (wire form written byte by byte, checksum is
    /// the only computed field — pinned by the CRC32c module tests).
    #[test]
    fn hand_built_init_parses_field_for_field() {
        let mut body = Vec::new();
        body.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // initiate tag
        body.extend_from_slice(&128_000u32.to_be_bytes()); // a_rwnd
        body.extend_from_slice(&1024u16.to_be_bytes()); // OS
        body.extend_from_slice(&1024u16.to_be_bytes()); // MIS
        body.extend_from_slice(&4711u32.to_be_bytes()); // initial TSN
                                                        // Supported Extensions param (0x8008) carrying FORWARD-TSN (0xC0).
        encode_param(PT_SUPPORTED_EXTENSIONS, &[CT_FORWARD_TSN], &mut body);

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&5000u16.to_be_bytes());
        pkt.extend_from_slice(&5000u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // vtag 0 for INIT
        pkt.extend_from_slice(&0u32.to_be_bytes()); // checksum placeholder
        encode_chunk(CT_INIT, 0, &body, &mut pkt);
        let csum = crc32c::packet_checksum(&pkt);
        pkt[8..12].copy_from_slice(&csum.to_be_bytes());

        let p = parse_packet(&pkt, true).expect("hand-built INIT must parse");
        assert_eq!(p.src_port, 5000);
        assert_eq!(p.dst_port, 5000);
        assert_eq!(p.vtag, 0);
        assert_eq!(p.chunks.len(), 1);
        match &p.chunks[0] {
            Chunk::Init(i) => {
                assert_eq!(i.initiate_tag, 0xDEAD_BEEF);
                assert_eq!(i.a_rwnd, 128_000);
                assert_eq!(i.os, 1024);
                assert_eq!(i.mis, 1024);
                assert_eq!(i.initial_tsn, 4711);
                assert_eq!(
                    i.param(PT_SUPPORTED_EXTENSIONS),
                    Some(&[CT_FORWARD_TSN][..])
                );
            }
            other => panic!("expected INIT, got {other:?}"),
        }
    }

    /// Hand-built SACK with gap blocks + duplicates, byte-layout pinned.
    #[test]
    fn hand_built_sack_round_layout() {
        let mut body = Vec::new();
        body.extend_from_slice(&100u32.to_be_bytes()); // cum
        body.extend_from_slice(&64_000u32.to_be_bytes()); // a_rwnd
        body.extend_from_slice(&2u16.to_be_bytes()); // 2 gap blocks
        body.extend_from_slice(&1u16.to_be_bytes()); // 1 dup
        body.extend_from_slice(&3u16.to_be_bytes()); // gap start (cum+3)
        body.extend_from_slice(&5u16.to_be_bytes()); // gap end (cum+5)
        body.extend_from_slice(&9u16.to_be_bytes());
        body.extend_from_slice(&11u16.to_be_bytes());
        body.extend_from_slice(&102u32.to_be_bytes()); // dup

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&77u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        encode_chunk(CT_SACK, 0, &body, &mut pkt);
        let csum = crc32c::packet_checksum(&pkt);
        pkt[8..12].copy_from_slice(&csum.to_be_bytes());

        let p = parse_packet(&pkt, true).unwrap();
        match &p.chunks[0] {
            Chunk::Sack(s) => {
                assert_eq!(s.cum_tsn, 100);
                assert_eq!(s.a_rwnd, 64_000);
                assert_eq!(
                    s.gaps,
                    vec![
                        SackBlock { start: 3, end: 5 },
                        SackBlock { start: 9, end: 11 }
                    ]
                );
                assert_eq!(s.dups, vec![102]);
            }
            other => panic!("expected SACK, got {other:?}"),
        }
    }

    /// Unknown chunk types follow the RFC 9260 §3.3.1 action rules via the
    /// raw pass-through variant; 4-byte alignment of trailing chunks holds.
    #[test]
    fn unknown_chunk_passthrough_and_padding() {
        // An unknown chunk of body length 3 → padded to 8 total, then a valid
        // COOKIE_ACK (empty body, length 4) must still parse.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        // unknown type 0x7F (class 01: stop+report), length 7, 3 body bytes.
        encode_chunk(0x7F, 0, &[1, 2, 3], &mut pkt);
        encode_chunk(CT_COOKIE_ACK, 0, &[], &mut pkt);
        let csum = crc32c::packet_checksum(&pkt);
        pkt[8..12].copy_from_slice(&csum.to_be_bytes());

        let p = parse_packet(&pkt, true).unwrap();
        assert_eq!(p.chunks.len(), 2);
        assert_eq!(p.chunks[0].chunk_type(), 0x7F);
        assert_eq!(p.chunks[1], Chunk::CookieAck);
    }

    #[test]
    fn checksum_corruption_is_rejected() {
        let pkt = encode_packet(1, 2, 3, &[Chunk::CookieAck]);
        let mut corrupted = pkt.clone();
        corrupted[13] ^= 0x08;
        assert!(matches!(
            parse_packet(&corrupted, true),
            Err(SctpError::BadChecksum)
        ));
        assert!(parse_packet(&pkt, true).is_ok());
    }

    #[test]
    fn truncated_packet_errors() {
        assert_eq!(parse_packet(&[0u8; 11], false), Err(SctpError::TooShort));
        // Chunk length beyond packet bounds.
        let mut pkt = vec![0u8; 16];
        pkt[12] = CT_COOKIE_ACK;
        pkt[14..16].copy_from_slice(&40u16.to_be_bytes());
        assert!(parse_packet(&pkt, false).is_err());
    }

    #[test]
    fn data_chunk_flags_survive_encode_parse() {
        let d = DataChunk {
            tsn: 9,
            stream: 3,
            ssn: 7,
            ppid: 51,
            begin: true,
            end: true,
            unordered: true,
            immediate_sack: true,
            payload: b"hi".to_vec(),
        };
        let pkt = encode_packet(5000, 5000, 42, &[Chunk::Data(d.clone())]);
        let p = parse_packet(&pkt, true).unwrap();
        assert_eq!(p.chunks[0], Chunk::Data(d));
    }

    /// AUD-3a regression: an unauthenticated INIT (or HEARTBEAT/ABORT) whose
    /// last param has `plen = 6` with only 6 bytes remaining — `pad4(6) = 8`
    /// runs past the buffer end. Must parse Ok and stop cleanly, not panic.
    #[test]
    fn trailing_short_param_stops_cleanly_without_panic() {
        let mut body = Vec::new();
        body.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // initiate tag
        body.extend_from_slice(&128_000u32.to_be_bytes()); // a_rwnd
        body.extend_from_slice(&1024u16.to_be_bytes()); // OS
        body.extend_from_slice(&1024u16.to_be_bytes()); // MIS
        body.extend_from_slice(&4711u32.to_be_bytes()); // initial TSN
                                                        // The attack param: type 1, plen 6, exactly 6 trailing bytes.
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0xAB, 0xCD]);
        assert_eq!(body.len(), 16 + 6);

        let params = parse_params(&body[16..]).expect("must parse without panicking");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].ptype, 1);
        assert_eq!(params[0].value, vec![0xAB, 0xCD]);

        // The same bytes as a full (checksummed) packet — the remote path.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&5000u16.to_be_bytes());
        pkt.extend_from_slice(&5000u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // vtag 0 for INIT
        pkt.extend_from_slice(&0u32.to_be_bytes()); // checksum placeholder
        encode_chunk(CT_INIT, 0, &body, &mut pkt);
        let csum = crc32c::packet_checksum(&pkt);
        pkt[8..12].copy_from_slice(&csum.to_be_bytes());
        let p = parse_packet(&pkt, true).expect("attack packet must parse cleanly");
        match &p.chunks[0] {
            Chunk::Init(i) => assert_eq!(i.params.len(), 1),
            other => panic!("expected INIT, got {other:?}"),
        }
    }

    /// A normal multi-param parse still yields every param (the fix above
    /// only bends the last-param padding rule).
    #[test]
    fn multi_param_parse_still_yields_all_params() {
        let mut buf = Vec::new();
        encode_param(PT_HEARTBEAT_INFO, b"info", &mut buf);
        encode_param(PT_IPV4, &[10, 0, 0, 1], &mut buf);
        encode_param(PT_SUPPORTED_EXTENSIONS, &[CT_FORWARD_TSN], &mut buf);
        let params = parse_params(&buf).expect("well-formed params must parse");
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].ptype, PT_HEARTBEAT_INFO);
        assert_eq!(params[0].value, b"info".to_vec());
        assert_eq!(params[1].ptype, PT_IPV4);
        assert_eq!(params[1].value, vec![10, 0, 0, 1]);
        assert_eq!(params[2].ptype, PT_SUPPORTED_EXTENSIONS);
        assert_eq!(params[2].value, vec![CT_FORWARD_TSN]);
    }

    #[test]
    fn forward_tsn_layout() {
        let f = Chunk::ForwardTsn {
            new_cum_tsn: 500,
            streams: vec![(2, 9), (4, 11)],
        };
        let pkt = encode_packet(1, 1, 1, std::slice::from_ref(&f));
        let p = parse_packet(&pkt, true).unwrap();
        assert_eq!(p.chunks[0], f);
    }

    /// Hand-built RE-CONFIG carrying an Outgoing SSN Reset Request, byte by
    /// byte per RFC 6525 §3.1 + §4.1: chunk type 130; parameter type 13,
    /// length 16 + 2*N (= 18 with one stream — stream numbers are packed
    /// ADJACENTLY, no reserved word per stream), RSN, response-seq, sender's
    /// last assigned TSN, then the 2-byte stream ids; the odd parameter
    /// length pads to a 4-byte chunk boundary.
    #[test]
    fn hand_built_re_config_outgoing_ssn_reset_layout() {
        let mut body = Vec::new();
        body.extend_from_slice(&13u16.to_be_bytes()); // param type 13
        body.extend_from_slice(&18u16.to_be_bytes()); // param length = 16 + 2*1
        body.extend_from_slice(&1001u32.to_be_bytes()); // request seq number
        body.extend_from_slice(&999u32.to_be_bytes()); // response seq number
        body.extend_from_slice(&1050u32.to_be_bytes()); // sender's last TSN
        body.extend_from_slice(&2u16.to_be_bytes()); // stream number 2
        assert_eq!(body.len(), 18);
        body.push(0); // padding to the 4-byte chunk boundary (chunk len 22)
        body.push(0);

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&77u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        encode_chunk(CT_RE_CONFIG, 0, &body, &mut pkt);
        let csum = crc32c::packet_checksum(&pkt);
        pkt[8..12].copy_from_slice(&csum.to_be_bytes());

        let p = parse_packet(&pkt, true).unwrap();
        match &p.chunks[0] {
            Chunk::ReConfig(rc) => {
                assert_eq!(rc.params.len(), 1);
                match &rc.params[0] {
                    ReConfigParam::OutgoingSsnReset {
                        rsn,
                        response_seq,
                        last_tsn,
                        streams,
                    } => {
                        assert_eq!(*rsn, 1001);
                        assert_eq!(*response_seq, 999);
                        assert_eq!(*last_tsn, 1050);
                        assert_eq!(streams, &[2u16]);
                    }
                    other => panic!("expected OutgoingSsnReset, got {other:?}"),
                }
            }
            other => panic!("expected RE-CONFIG, got {other:?}"),
        }
    }

    /// Hand-built Re-configuration Response (§4.4): type 16, length 12,
    /// response-seq copied from the request, result 1 = Success-Performed.
    #[test]
    fn hand_built_re_config_response_layout() {
        let mut body = Vec::new();
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&12u16.to_be_bytes());
        body.extend_from_slice(&1001u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&77u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        encode_chunk(CT_RE_CONFIG, 0, &body, &mut pkt);
        let csum = crc32c::packet_checksum(&pkt);
        pkt[8..12].copy_from_slice(&csum.to_be_bytes());

        let p = parse_packet(&pkt, true).unwrap();
        match &p.chunks[0] {
            Chunk::ReConfig(rc) => assert_eq!(
                rc.params,
                vec![ReConfigParam::Response {
                    rsn: 1001,
                    result: 1
                }]
            ),
            other => panic!("expected RE-CONFIG, got {other:?}"),
        }
    }

    /// The §3.1 allowed two-parameter combination (Response + Outgoing SSN
    /// Reset — the reciprocal-close chunk) survives encode→parse verbatim,
    /// including an odd stream count and an unknown parameter type that must
    /// be skipped without killing the rest of the chunk.
    #[test]
    fn re_config_two_params_and_unknown_skip_roundtrip() {
        let rc = Chunk::ReConfig(ReConfigChunk {
            params: vec![
                ReConfigParam::Response {
                    rsn: 7,
                    result: RC_RESULT_PERFORMED,
                },
                ReConfigParam::OutgoingSsnReset {
                    rsn: 8,
                    response_seq: 7,
                    last_tsn: 4242,
                    streams: vec![0, 1, 2],
                },
            ],
        });
        let pkt = encode_packet(1, 1, 1, std::slice::from_ref(&rc));
        let p = parse_packet(&pkt, true).unwrap();
        assert_eq!(p.chunks[0], rc);

        // An unknown parameter type (18, Add Incoming Streams) between the
        // two known ones is skipped; the known ones still decode.
        let mut body = Vec::new();
        encode_re_config_param(&ReConfigParam::Response { rsn: 7, result: 1 }, &mut body);
        // type 18, plen 8 (header + 4 bytes of payload)
        body.extend_from_slice(&18u16.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes());
        body.extend_from_slice(&[1, 2, 3, 4]);
        encode_re_config_param(
            &ReConfigParam::OutgoingSsnReset {
                rsn: 8,
                response_seq: 7,
                last_tsn: 4242,
                streams: vec![],
            },
            &mut body,
        );
        let params = parse_re_config_params(&body).unwrap();
        assert_eq!(
            params,
            vec![
                ReConfigParam::Response { rsn: 7, result: 1 },
                ReConfigParam::OutgoingSsnReset {
                    rsn: 8,
                    response_seq: 7,
                    last_tsn: 4242,
                    streams: vec![]
                },
            ]
        );
    }

    /// The Task 47 advance-validation class, one parser deeper: (a) a
    /// RE-CONFIG param whose declared length exceeds the buffer errors out
    /// (never panics); (b) a last param whose PADDED advance overruns the
    /// tail stops cleanly after decoding it — the same contract
    /// `parse_params` follows.
    #[test]
    fn re_config_trailing_param_edge_shapes() {
        // (a) truncated tail claiming plen 16 with only 6 bytes present:
        // a hard error, not a panic.
        let mut body = Vec::new();
        encode_re_config_param(&ReConfigParam::Response { rsn: 5, result: 1 }, &mut body);
        body.extend_from_slice(&13u16.to_be_bytes());
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&[0xAA, 0xBB]);
        assert!(parse_re_config_params(&body).is_err());

        // (b) Response param + a final Outgoing reset of plen 18 padded to
        // 20 with exactly 18 bytes present: the param decodes (1 stream)
        // and the walk stops at the chunk end.
        let mut body = Vec::new();
        encode_re_config_param(&ReConfigParam::Response { rsn: 5, result: 1 }, &mut body);
        body.extend_from_slice(&13u16.to_be_bytes()); // param type 13
        body.extend_from_slice(&18u16.to_be_bytes()); // 16 + 2*1
        body.extend_from_slice(&1001u32.to_be_bytes()); // rsn
        body.extend_from_slice(&999u32.to_be_bytes()); // response seq
        body.extend_from_slice(&1050u32.to_be_bytes()); // last TSN
        body.extend_from_slice(&2u16.to_be_bytes()); // stream 2 (no padding!)
        assert_eq!(body.len() % 4, 2, "the tail is deliberately unpadded");
        let params = parse_re_config_params(&body)
            .expect("legal plen with overrun padding must stop cleanly");
        assert_eq!(
            params,
            vec![
                ReConfigParam::Response { rsn: 5, result: 1 },
                ReConfigParam::OutgoingSsnReset {
                    rsn: 1001,
                    response_seq: 999,
                    last_tsn: 1050,
                    streams: vec![2],
                },
            ]
        );
    }
}
