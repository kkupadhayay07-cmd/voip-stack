//! RFC 1035 DNS wire-format codec: query encoding, response parsing, and
//! the record payloads RFC 3263 needs (A, AAAA, SRV, NAPTR).
//!
//! Scope decisions (documented, deliberate):
//! - reader-side name decompression supports RFC 1035 §4.1.4 pointers with a
//!   strict backwards-reference rule plus a jump cap, so a hostile response
//!   cannot loop the parser;
//! - EDNS0 bit-labels (0x40) and the other reserved label types are rejected;
//! - unknown record types are surfaced as [`Record::Other`] so callers can
//!   still see additional-section data they do not consume.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_SRV: u16 = 33;
pub const QTYPE_NAPTR: u16 = 35;

const CLASS_IN: u16 = 1;
const FLAG_RD: u16 = 0x0100;
const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;

/// Wire-format or protocol error surfaced by the codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Buffer ended mid-field.
    Truncated,
    /// Label > 63 bytes, empty label, or a name over the 255-byte limit.
    BadName,
    /// A compression pointer that points forwards (loops) or jumps too often.
    BadPointer,
    /// RData is shorter than the record type requires, or overruns its
    /// declared RDLENGTH.
    BadRdata,
    /// Encoded query would exceed the DNS message size.
    Overflow,
    /// Underlying socket I/O failed.
    Io(String),
    /// No matching answer arrived before the timeout budget ran out.
    Timeout,
    /// The response ID does not match the query ID.
    IdMismatch,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Truncated => write!(f, "dns message truncated"),
            DnsError::BadName => write!(f, "invalid domain name"),
            DnsError::BadPointer => write!(f, "invalid or looping compression pointer"),
            DnsError::BadRdata => write!(f, "record data invalid or exceeds RDLENGTH"),
            DnsError::Overflow => write!(f, "encoded query exceeds DNS message size"),
            DnsError::Io(e) => write!(f, "dns transport i/o: {e}"),
            DnsError::Timeout => write!(f, "dns query timed out"),
            DnsError::IdMismatch => write!(f, "dns response id mismatch"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        DnsError::Io(e.to_string())
    }
}

/// An SRV record ([RFC 2782]).
///
/// [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// Owner name the record was found under (usually the SRV query name).
    pub name: String,
    pub ttl: u32,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    /// Target host providing the service ("." is filtered out by the
    /// resolver: RFC 2782 defines it as "service decidedly not available").
    pub target: String,
}

/// A NAPTR record ([RFC 2915]).
///
/// [RFC 2915]: https://datatracker.ietf.org/doc/html/rfc2915
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaptrRecord {
    pub name: String,
    pub ttl: u32,
    /// Lower order is traversed first (RFC 2915 §2, first sort key).
    pub order: u16,
    /// Lower preference is tried first within one order (second sort key).
    pub preference: u16,
    /// Terminal flag: "S" (SRV), "A" (address), "U" (URI). Only "S" is
    /// consumed by [`crate::Resolver`].
    pub flags: String,
    /// Service string such as "SIP+D2U" (RFC 3263 §4.1).
    pub service: String,
    /// Sed-regex rewrite rule. Parsed but not applied (documented gap).
    pub regexp: String,
    /// Replacement key for S-flag records (the SRV query name).
    pub replacement: String,
}

/// One resource record from a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Srv(SrvRecord),
    Naptr(NaptrRecord),
    A {
        name: String,
        ttl: u32,
        addr: Ipv4Addr,
    },
    Aaaa {
        name: String,
        ttl: u32,
        addr: Ipv6Addr,
    },
    Other {
        name: String,
        rtype: u16,
    },
}

/// A decoded DNS response (or query — the header/question layout is shared).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    /// TC bit: the answer was cut off by UDP and must be retried over TCP.
    pub truncated: bool,
    /// 4-bit RCODE (0 = NOERROR, 3 = NXDOMAIN, ...).
    pub rcode: u8,
    /// Records from the answer, authority and additional sections.
    pub records: Vec<Record>,
}

/// Builds a standard recursive query: `id`, RD=1, one question, class IN.
pub fn encode_query(id: u16, qname: &str, qtype: u16) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(17 + qname.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    let trimmed = qname.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(DnsError::BadName);
    }
    let mut name_len = 1usize; // root byte
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(DnsError::BadName);
        }
        name_len += bytes.len() + 1;
        if name_len > 255 {
            return Err(DnsError::BadName);
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    if out.len() + 4 > u16::MAX as usize {
        return Err(DnsError::Overflow);
    }
    out.push(0); // root
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Parses a DNS message. Question sections are skipped; answer, authority
/// and additional records are all collected.
pub fn parse_response(buf: &[u8]) -> Result<Message, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = read_name(buf, pos)?;
        if next + 4 > buf.len() {
            return Err(DnsError::Truncated);
        }
        pos = next + 4; // QTYPE + QCLASS
    }

    let mut records = Vec::with_capacity(ancount + nscount + arcount);
    for _ in 0..(ancount + nscount + arcount) {
        let (name, after_name) = read_name(buf, pos)?;
        if after_name + 10 > buf.len() {
            return Err(DnsError::Truncated);
        }
        let rtype = u16::from_be_bytes([buf[after_name], buf[after_name + 1]]);
        let ttl = u32::from_be_bytes([
            buf[after_name + 4],
            buf[after_name + 5],
            buf[after_name + 6],
            buf[after_name + 7],
        ]);
        let rdlen = u16::from_be_bytes([buf[after_name + 8], buf[after_name + 9]]) as usize;
        let rdata = after_name + 10;
        let rdata_end = rdata + rdlen;
        if rdata_end > buf.len() {
            return Err(DnsError::Truncated);
        }
        let record = parse_rdata(buf, rdata, rdata_end, rtype, name, ttl)?;
        records.push(record);
        pos = rdata_end;
    }

    Ok(Message {
        id,
        is_response: flags & FLAG_QR != 0,
        truncated: flags & FLAG_TC != 0,
        rcode: (flags & 0x000F) as u8,
        records,
    })
}

fn parse_rdata(
    buf: &[u8],
    rdata: usize,
    rdata_end: usize,
    rtype: u16,
    name: String,
    ttl: u32,
) -> Result<Record, DnsError> {
    match rtype {
        QTYPE_A => {
            if rdata_end - rdata != 4 {
                return Err(DnsError::BadRdata);
            }
            Ok(Record::A {
                name,
                ttl,
                addr: Ipv4Addr::new(buf[rdata], buf[rdata + 1], buf[rdata + 2], buf[rdata + 3]),
            })
        }
        QTYPE_AAAA => {
            if rdata_end - rdata != 16 {
                return Err(DnsError::BadRdata);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[rdata..rdata_end]);
            Ok(Record::Aaaa {
                name,
                ttl,
                addr: Ipv6Addr::from(octets),
            })
        }
        QTYPE_SRV => {
            if rdata_end - rdata < 7 {
                return Err(DnsError::BadRdata);
            }
            let priority = u16::from_be_bytes([buf[rdata], buf[rdata + 1]]);
            let weight = u16::from_be_bytes([buf[rdata + 2], buf[rdata + 3]]);
            let port = u16::from_be_bytes([buf[rdata + 4], buf[rdata + 5]]);
            let (target, after) = read_name(buf, rdata + 6)?;
            if after > rdata_end {
                return Err(DnsError::BadRdata);
            }
            Ok(Record::Srv(SrvRecord {
                name,
                ttl,
                priority,
                weight,
                port,
                target,
            }))
        }
        QTYPE_NAPTR => {
            if rdata_end - rdata < 4 {
                return Err(DnsError::BadRdata);
            }
            let order = u16::from_be_bytes([buf[rdata], buf[rdata + 1]]);
            let preference = u16::from_be_bytes([buf[rdata + 2], buf[rdata + 3]]);
            let mut pos = rdata + 4;
            let flags = read_char_string(buf, &mut pos, rdata_end)?;
            let service = read_char_string(buf, &mut pos, rdata_end)?;
            let regexp = read_char_string(buf, &mut pos, rdata_end)?;
            let (replacement, after) = read_name(buf, pos)?;
            if after > rdata_end {
                return Err(DnsError::BadRdata);
            }
            Ok(Record::Naptr(NaptrRecord {
                name,
                ttl,
                order,
                preference,
                flags,
                service,
                regexp,
                replacement,
            }))
        }
        _ => Ok(Record::Other { name, rtype }),
    }
}

/// Reads a DNS character-string (single length byte + up to 255 bytes).
fn read_char_string(buf: &[u8], pos: &mut usize, end: usize) -> Result<String, DnsError> {
    if *pos >= end {
        return Err(DnsError::BadRdata);
    }
    let len = buf[*pos] as usize;
    if *pos + 1 + len > end {
        return Err(DnsError::BadRdata);
    }
    let s = String::from_utf8_lossy(&buf[*pos + 1..*pos + 1 + len]).into_owned();
    *pos += 1 + len;
    Ok(s)
}

/// Reads a possibly-compressed domain name starting at `start`.
///
/// Returns the decoded name (labels joined with ".") and the offset just
/// past the name's wire bytes — for compressed names that is the offset
/// past the pointer pair, so sequential field parsing stays correct.
///
/// Loop safety: a pointer target must be strictly backwards from the
/// pointer itself (RFC 1035 pointers only reference prior occurrences) and
/// at most 64 pointer hops are followed.
pub fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut pos = start;
    let mut jumps = 0usize;
    // Where the name ends in the original stream. For an uncompressed name
    // that is just past the root byte; once a pointer is followed it is the
    // end of the pointer pair (the referenced name's bytes do not consume
    // original-stream positions).
    let mut pointer_end: Option<usize> = None;
    let mut labels: Vec<&str> = Vec::new();
    let mut total = 0usize;

    loop {
        if pos >= buf.len() {
            return Err(DnsError::Truncated);
        }
        let len = buf[pos];
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Ok((labels.join("."), pointer_end.unwrap_or(pos + 1)));
                }
                let l = len as usize;
                if pos + 1 + l > buf.len() {
                    return Err(DnsError::Truncated);
                }
                total += l + 1;
                if total > 255 {
                    return Err(DnsError::BadName);
                }
                labels.push(
                    std::str::from_utf8(&buf[pos + 1..pos + 1 + l])
                        .map_err(|_| DnsError::BadName)?,
                );
                pos += 1 + l;
            }
            0xC0 => {
                if pos + 1 >= buf.len() {
                    return Err(DnsError::Truncated);
                }
                let ptr = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
                if ptr >= pos {
                    // Forward or self-referencing pointer: cannot happen in a
                    // well-formed message and is the only shape that loops.
                    return Err(DnsError::BadPointer);
                }
                jumps += 1;
                if jumps > 64 {
                    return Err(DnsError::BadPointer);
                }
                if pointer_end.is_none() {
                    pointer_end = Some(pos + 2);
                }
                pos = ptr;
            }
            _ => return Err(DnsError::BadName), // 0x40/0x80: reserved label types
        }
    }
}

#[cfg(test)]
pub(crate) mod canned {
    //! Hand-built DNS response packets used by the crate's tests. Writing the
    //! bytes by hand (instead of through an encoder) keeps the parser honest:
    //! the test vectors do not share a bug with the code under test.

    use super::{QTYPE_A, QTYPE_AAAA, QTYPE_NAPTR, QTYPE_SRV};

    /// Encodes an uncompressed name: "sip.example.com" -> \x03sip\x07example\x03com\x00
    pub fn name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.trim_end_matches('.').split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    pub enum Rr {
        Srv {
            priority: u16,
            weight: u16,
            port: u16,
            target: String,
            ttl: u32,
        },
        Naptr {
            order: u16,
            preference: u16,
            flags: &'static str,
            service: &'static str,
            regexp: &'static str,
            replacement: &'static str,
            ttl: u32,
        },
        A(std::net::Ipv4Addr),
        Aaaa(std::net::Ipv6Addr),
        /// Unknown/other type with empty rdata (e.g. NS surfaced under an A query).
        Raw {
            rtype: u16,
        },
    }

    /// Builds a response with one question plus the given answer records.
    pub fn response(id: u16, qname: &str, qtype: u16, answers: &[(&str, Rr)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes()); // QR+RD+RA, NOERROR
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&name_bytes(qname));
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // class IN

        for (owner, rr) in answers {
            buf.extend_from_slice(&name_bytes(owner));
            let (rtype, mut rdata) = match rr {
                Rr::Srv {
                    priority,
                    weight,
                    port,
                    target,
                    ttl: _,
                } => {
                    let mut d = Vec::new();
                    d.extend_from_slice(&priority.to_be_bytes());
                    d.extend_from_slice(&weight.to_be_bytes());
                    d.extend_from_slice(&port.to_be_bytes());
                    d.extend_from_slice(&name_bytes(target));
                    (QTYPE_SRV, d)
                }
                Rr::Naptr {
                    order,
                    preference,
                    flags,
                    service,
                    regexp,
                    replacement,
                    ttl: _,
                } => {
                    let mut d = Vec::new();
                    d.extend_from_slice(&order.to_be_bytes());
                    d.extend_from_slice(&preference.to_be_bytes());
                    for s in [*flags, *service, *regexp] {
                        d.push(s.len() as u8);
                        d.extend_from_slice(s.as_bytes());
                    }
                    d.extend_from_slice(&name_bytes(replacement));
                    (QTYPE_NAPTR, d)
                }
                Rr::A(addr) => (QTYPE_A, addr.octets().to_vec()),
                Rr::Aaaa(addr) => (QTYPE_AAAA, addr.octets().to_vec()),
                Rr::Raw { rtype } => (*rtype, Vec::new()),
            };
            buf.extend_from_slice(&rtype.to_be_bytes());
            buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
            let ttl = match rr {
                Rr::Srv { ttl, .. } | Rr::Naptr { ttl, .. } => *ttl,
                _ => 60,
            };
            buf.extend_from_slice(&ttl.to_be_bytes());
            buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            buf.append(&mut rdata);
        }
        buf
    }

    /// Response with the answer owner name compressed to a pointer at the
    /// question name (offset 12), the classic shape real resolvers emit.
    pub fn response_compressed_owner(id: u16, qname: &str, qtype: u16, rdata: Vec<u8>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&name_bytes(qname));
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(0xC0);
        buf.push(0x0C); // pointer to question name
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&60u32.to_be_bytes());
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::canned::{name_bytes, response, response_compressed_owner, Rr};
    use super::*;

    #[test]
    fn query_encodes_rd_question_and_class() {
        let q = encode_query(0xBEEF, "_sip._udp.example.com", QTYPE_SRV).unwrap();
        assert_eq!(&q[0..2], &[0xBE, 0xEF]);
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD set, opcode 0, rcode 0
        assert_eq!(&q[4..6], &[0, 1]); // QDCOUNT = 1
        assert_eq!(&q[12..17], &[4, b'_', b's', b'i', b'p']);
        let tail = &q[q.len() - 5..];
        assert_eq!(tail[0], 0); // root
        assert_eq!(&tail[1..3], &QTYPE_SRV.to_be_bytes());
        assert_eq!(&tail[3..5], &1u16.to_be_bytes()); // class IN
                                                      // QR must not be set on queries.
        assert_eq!(q[2] & 0x80, 0);
    }

    #[test]
    fn query_rejects_bad_names() {
        assert_eq!(encode_query(1, "", QTYPE_A), Err(DnsError::BadName));
        assert_eq!(encode_query(1, "a..b", QTYPE_A), Err(DnsError::BadName));
        let long = "a".repeat(64);
        assert_eq!(encode_query(1, &long, QTYPE_A), Err(DnsError::BadName));
        let total = "x".repeat(63);
        let name = format!("{total}.{total}.{total}.{total}.{total}");
        assert_eq!(encode_query(1, &name, QTYPE_A), Err(DnsError::BadName));
    }

    #[test]
    fn parses_srv_response_with_owner_compression() {
        let rdata = {
            let mut d = vec![];
            d.extend_from_slice(&10u16.to_be_bytes());
            d.extend_from_slice(&20u16.to_be_bytes());
            d.extend_from_slice(&5060u16.to_be_bytes());
            d.extend_from_slice(&name_bytes("pbx.example.net"));
            d
        };
        let msg = parse_response(&response_compressed_owner(
            0x1234,
            "_sip._udp.example.com",
            QTYPE_SRV,
            rdata,
        ))
        .unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.id, 0x1234);
        assert_eq!(msg.rcode, 0);
        assert!(!msg.truncated);
        assert_eq!(msg.records.len(), 1);
        match &msg.records[0] {
            Record::Srv(s) => {
                assert_eq!(s.name, "_sip._udp.example.com"); // decompressed via pointer
                assert_eq!(s.priority, 10);
                assert_eq!(s.weight, 20);
                assert_eq!(s.port, 5060);
                assert_eq!(s.target, "pbx.example.net");
            }
            other => panic!("expected SRV, got {other:?}"),
        }
    }

    #[test]
    fn parses_naptr_character_strings() {
        let msg = parse_response(&response(
            7,
            "example.com",
            QTYPE_NAPTR,
            &[(
                "example.com",
                Rr::Naptr {
                    order: 100,
                    preference: 10,
                    flags: "S",
                    service: "SIP+D2U",
                    regexp: "",
                    replacement: "_sip._udp.trunk.example.net",
                    ttl: 300,
                },
            )],
        ))
        .unwrap();
        match &msg.records[0] {
            Record::Naptr(n) => {
                assert_eq!(n.order, 100);
                assert_eq!(n.preference, 10);
                assert_eq!(n.flags, "S");
                assert_eq!(n.service, "SIP+D2U");
                assert_eq!(n.regexp, "");
                assert_eq!(n.replacement, "_sip._udp.trunk.example.net");
            }
            other => panic!("expected NAPTR, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_and_aaaa_and_unknown_types() {
        let msg = parse_response(&response(
            9,
            "example.com",
            QTYPE_A,
            &[
                (
                    "example.com",
                    Rr::A(std::net::Ipv4Addr::new(203, 0, 113, 7)),
                ),
                ("v6.example.com", Rr::Aaaa("2001:db8::1".parse().unwrap())),
                ("ns.example.com", Rr::Raw { rtype: 2 }), // NS
            ],
        ))
        .unwrap();
        assert!(matches!(
            &msg.records[0],
            Record::A { addr, .. } if *addr == std::net::Ipv4Addr::new(203, 0, 113, 7)
        ));
        assert!(matches!(
            &msg.records[1],
            Record::Aaaa { addr, .. } if *addr == "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        ));
        // NS record under an A query is surfaced as Other, not dropped.
        match &msg.records[2] {
            Record::Other { name, rtype } => {
                assert_eq!(name, "ns.example.com");
                assert_eq!(*rtype, 2); // NS
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn surfaces_rcode_and_truncation_bits() {
        let mut buf = response(1, "example.com", QTYPE_A, &[]);
        // NXDOMAIN
        buf[3] = (buf[3] & 0xF0) | 3;
        let msg = parse_response(&buf).unwrap();
        assert_eq!(msg.rcode, 3);
        // SERVFAIL
        buf[3] = (buf[3] & 0xF0) | 2;
        assert_eq!(parse_response(&buf).unwrap().rcode, 2);
        // TC set
        buf[3] = (buf[3] & 0xF0) | 2;
        buf[2] |= 0x02;
        let msg = parse_response(&buf).unwrap();
        assert!(msg.truncated);
        assert!(msg.is_response);
    }

    #[test]
    fn rejects_short_and_pointer_looped_buffers() {
        assert_eq!(parse_response(&[0; 8]), Err(DnsError::Truncated));
        // A pointer that points at itself: owner name = 0xC0 0x0C at offset 12.
        let mut buf = response(1, "example.com", QTYPE_A, &[]);
        buf[12] = 0xC0;
        buf[13] = 0x0C;
        assert_eq!(parse_response(&buf), Err(DnsError::BadPointer));
        // Forward pointer (never legal): 0xC0 pointing past itself.
        let mut buf2 = vec![0u8; 20];
        buf2[0..2].copy_from_slice(&1u16.to_be_bytes());
        buf2[4..6].copy_from_slice(&1u16.to_be_bytes());
        buf2[12] = 0xC0;
        buf2[13] = 0x20; // points forward (32 >= 12)
        assert_eq!(parse_response(&buf2), Err(DnsError::BadPointer));
        // RDLENGTH larger than the buffer: one A answer, then blow up its
        // RDLENGTH field (6 bytes before the rdata, i.e. 6 from the end).
        let mut buf3 = response(
            1,
            "example.com",
            QTYPE_A,
            &[("example.com", Rr::A(std::net::Ipv4Addr::new(1, 2, 3, 4)))],
        );
        let n = buf3.len();
        buf3[n - 6] = 0xFF;
        buf3[n - 5] = 0xFF;
        assert_eq!(parse_response(&buf3), Err(DnsError::Truncated));
    }

    #[test]
    fn read_name_rejects_reserved_label_types_and_overlong_names() {
        // 0x40 label type (EDNS0 bit labels) -> BadName
        let buf = [0x40u8, 0x01, 0x00];
        assert_eq!(read_name(&buf, 0), Err(DnsError::BadName));
        // A name built from 4x 63-byte labels exceeds 255 encoded bytes.
        let mut buf2 = vec![];
        for _ in 0..5 {
            buf2.push(63);
            buf2.extend_from_slice(&[b'a'; 63]);
        }
        buf2.push(0);
        assert_eq!(read_name(&buf2, 0), Err(DnsError::BadName));
    }

    #[test]
    fn read_name_follows_backward_pointer_chains() {
        // Zone-style layout: "example.com\0" at 0 (13 bytes), then the
        // "www" label at 13 with a pointer back to 0, then the root.
        let mut buf = name_bytes("example.com"); // root at offset 12
        buf.push(3);
        buf.extend_from_slice(b"www"); // label at 13
        let ptr_at = buf.len(); // 17
        buf.push(0xC0);
        buf.push(0x00); // pointer to offset 0
        buf.push(0); // root after the pointer
        let (name, end) = read_name(&buf, 13).unwrap();
        assert_eq!(name, "www.example.com");
        // End offset is past the pointer pair (before the root byte).
        assert_eq!(end, ptr_at + 2);
    }

    #[test]
    fn read_name_end_includes_root_byte_for_uncompressed_names() {
        // Regression: the end offset must count the root byte, or every
        // sequential field after an uncompressed name is misread.
        let buf = name_bytes("example.com"); // 13 bytes: 12 name + 1 root
        let (name, end) = read_name(&buf, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(end, buf.len());
    }
}
