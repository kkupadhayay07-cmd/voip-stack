//! STUN message codec ([RFC 5389]/[RFC 8489]) with the TURN extensions of
//! [RFC 5766] and ICE attributes of [RFC 8445].
//!
//! Includes MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT (CRC32) handling
//! validated against the RFC 5769 test vectors.
//!
//! [RFC 5389]: https://datatracker.ietf.org/doc/html/rfc5389
//! [RFC 8489]: https://datatracker.ietf.org/doc/html/rfc8489
//! [RFC 5766]: https://datatracker.ietf.org/doc/html/rfc5766
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445

use std::net::{IpAddr, SocketAddr};

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::crc32::crc32;

/// The STUN magic cookie (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

// -- Message classes / methods (RFC 5389 §6 + RFC 5766 §5) ------------------

pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_INDICATION: u16 = 0x0011;
pub const BINDING_RESPONSE: u16 = 0x0101;
pub const BINDING_ERROR_RESPONSE: u16 = 0x0111;

pub const ALLOCATE_REQUEST: u16 = 0x0003;
pub const ALLOCATE_RESPONSE: u16 = 0x0103;
pub const ALLOCATE_ERROR_RESPONSE: u16 = 0x0113;
pub const REFRESH_REQUEST: u16 = 0x0004;
pub const REFRESH_RESPONSE: u16 = 0x0104;
pub const SEND_INDICATION: u16 = 0x0016;
pub const DATA_INDICATION: u16 = 0x0017;
pub const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
pub const CREATE_PERMISSION_RESPONSE: u16 = 0x0108;
pub const CHANNEL_BIND_REQUEST: u16 = 0x0009;
pub const CHANNEL_BIND_RESPONSE: u16 = 0x0109;

// -- Attribute registry ------------------------------------------------------

pub const MAPPED_ADDRESS: u16 = 0x0001;
pub const USERNAME: u16 = 0x0006; // also CHANNEL-NUMBER in ChannelBind
pub const MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ERROR_CODE: u16 = 0x0009;
pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const CHANNEL_NUMBER: u16 = 0x0006;
pub const LIFETIME: u16 = 0x000D;
pub const XOR_PEER_ADDRESS: u16 = 0x0012;
pub const DATA: u16 = 0x0013;
pub const REALM: u16 = 0x0014;
pub const NONCE: u16 = 0x0015;
pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const REQUESTED_TRANSPORT: u16 = 0x0019;
pub const DONT_FRAGMENT: u16 = 0x001A;
pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const RESERVATION_TOKEN: u16 = 0x0022;
pub const PRIORITY: u16 = 0x0024;
pub const USE_CANDIDATE: u16 = 0x0025;
pub const SOFTWARE: u16 = 0x8022;
pub const ALTERNATE_SERVER: u16 = 0x8023;
pub const FINGERPRINT: u16 = 0x8028;
pub const ICE_CONTROLLED: u16 = 0x8029;
pub const ICE_CONTROLLING: u16 = 0x802A;

/// Errors from decoding / verifying STUN messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    /// Buffer too small.
    #[error("message too short ({0} bytes)")]
    TooShort(usize),
    /// Magic cookie mismatch (likely not STUN).
    #[error("bad magic cookie")]
    BadCookie,
    /// Attribute overruns the message.
    #[error("attribute overruns message")]
    BadAttribute,
    /// Message length not 4-byte aligned or inconsistent.
    #[error("bad message length")]
    BadLength,
    /// Cannot represent the address (e.g. unknown address family).
    #[error("unsupported address family {0}")]
    BadAddressFamily(u8),
    /// MESSAGE-INTEGRITY mismatch.
    #[error("integrity check failed")]
    IntegrityFailed,
    /// FINGERPRINT (CRC32) mismatch.
    #[error("fingerprint check failed")]
    FingerprintFailed,
}

/// A parsed STUN message with typed helpers.
///
/// Attributes are kept as raw TLVs; accessors interpret the well-known
/// ones.  The raw wire form is retained so integrity/fingerprint checks
/// can be run after parsing.
#[derive(Debug, Clone)]
pub struct Message {
    pub msg_type: u16,
    pub tx_id: [u8; 12],
    attrs: Vec<(u16, Vec<u8>)>,
    raw: Vec<u8>,
    /// Offset of the MESSAGE-INTEGRITY attribute (TLV header) in `raw`.
    integrity_offset: Option<usize>,
    /// Offset of the FINGERPRINT attribute (TLV header) in `raw`.
    fingerprint_offset: Option<usize>,
}

impl Message {
    /// Create a message with a fresh random transaction id.
    pub fn new(msg_type: u16) -> Self {
        let mut tx_id = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tx_id);
        Message {
            msg_type,
            tx_id,
            attrs: Vec::new(),
            raw: Vec::new(),
            integrity_offset: None,
            fingerprint_offset: None,
        }
    }

    /// Create a message reusing a transaction id (responses).
    pub fn new_with_txid(msg_type: u16, tx_id: [u8; 12]) -> Self {
        Message {
            msg_type,
            tx_id,
            attrs: Vec::new(),
            raw: Vec::new(),
            integrity_offset: None,
            fingerprint_offset: None,
        }
    }

    /// Append a raw attribute.
    pub fn add(&mut self, attr_type: u16, value: Vec<u8>) {
        self.attrs.push((attr_type, value));
    }

    /// First attribute value with the given type.
    pub fn get(&self, attr_type: u16) -> Option<&[u8]> {
        self.attrs
            .iter()
            .find(|(t, _)| *t == attr_type)
            .map(|(_, v)| v.as_slice())
    }

    /// All attribute values with the given type (XOR-PEER-ADDRESS is multi).
    pub fn get_all(&self, attr_type: u16) -> Vec<&[u8]> {
        self.attrs
            .iter()
            .filter(|(t, _)| *t == attr_type)
            .map(|(_, v)| v.as_slice())
            .collect()
    }

    pub fn has(&self, attr_type: u16) -> bool {
        self.get(attr_type).is_some()
    }

    // -- typed helpers ------------------------------------------------------

    pub fn add_xor_address(&mut self, attr_type: u16, addr: SocketAddr) {
        self.add(attr_type, encode_xor_address(addr, &self.tx_id));
    }

    pub fn xor_address(&self, attr_type: u16) -> Option<Result<SocketAddr, StunError>> {
        self.get(attr_type)
            .map(|v| decode_xor_address(v, &self.tx_id))
    }

    pub fn add_address(&mut self, attr_type: u16, addr: SocketAddr) {
        self.add(attr_type, encode_plain_address(addr));
    }

    pub fn address(&self, attr_type: u16) -> Option<Result<SocketAddr, StunError>> {
        self.get(attr_type).map(decode_plain_address)
    }

    pub fn username(&self) -> Option<String> {
        self.get(USERNAME)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    pub fn add_username(&mut self, u: &str) {
        self.add(USERNAME, u.as_bytes().to_vec());
    }

    pub fn software(&self) -> Option<String> {
        self.get(SOFTWARE)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    pub fn add_software(&mut self, s: &str) {
        self.add(SOFTWARE, s.as_bytes().to_vec());
    }

    pub fn priority(&self) -> Option<u32> {
        self.get(PRIORITY).and_then(|v| {
            if v.len() == 4 {
                Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            } else {
                None
            }
        })
    }

    pub fn add_priority(&mut self, p: u32) {
        self.add(PRIORITY, p.to_be_bytes().to_vec());
    }

    pub fn use_candidate(&self) -> bool {
        self.has(USE_CANDIDATE)
    }

    pub fn add_use_candidate(&mut self) {
        self.add(USE_CANDIDATE, Vec::new());
    }

    pub fn tie_breaker(&self, controlling: bool) -> Option<u64> {
        let t = if controlling {
            ICE_CONTROLLING
        } else {
            ICE_CONTROLLED
        };
        self.get(t).and_then(|v| {
            if v.len() == 8 {
                Some(u64::from_be_bytes([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                ]))
            } else {
                None
            }
        })
    }

    pub fn add_tie_breaker(&mut self, controlling: bool, value: u64) {
        let t = if controlling {
            ICE_CONTROLLING
        } else {
            ICE_CONTROLLED
        };
        self.add(t, value.to_be_bytes().to_vec());
    }

    pub fn error_code(&self) -> Option<(u16, String)> {
        let v = self.get(ERROR_CODE)?;
        if v.len() < 4 {
            return None;
        }
        // Error class in bits 7-4 of byte 1, number in byte 2
        // (RFC 5389 §15.6).
        let class = (v[1] & 0x07) as u16;
        let number = v[2] as u16;
        Some((
            class * 100 + number,
            String::from_utf8_lossy(&v[3..]).into_owned(),
        ))
    }

    pub fn add_error_code(&mut self, code: u16, reason: &str) {
        let mut v = vec![0u8, (code / 100) as u8, (code % 100) as u8];
        v.extend_from_slice(reason.as_bytes());
        self.add(ERROR_CODE, v);
    }

    pub fn lifetime(&self) -> Option<u32> {
        self.get(LIFETIME).and_then(|v| {
            if v.len() == 4 {
                Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            } else {
                None
            }
        })
    }

    pub fn add_lifetime(&mut self, secs: u32) {
        self.add(LIFETIME, secs.to_be_bytes().to_vec());
    }

    pub fn requested_transport(&self) -> Option<u8> {
        self.get(REQUESTED_TRANSPORT)
            .and_then(|v| v.first().copied())
    }

    pub fn add_requested_transport(&mut self, proto: u8) {
        self.add(REQUESTED_TRANSPORT, vec![proto, 0, 0, 0]);
    }

    pub fn channel_number(&self) -> Option<u16> {
        self.get(CHANNEL_NUMBER).and_then(|v| {
            if v.len() >= 2 {
                Some(u16::from_be_bytes([v[0], v[1]]))
            } else {
                None
            }
        })
    }

    pub fn add_channel_number(&mut self, n: u16) {
        self.add(CHANNEL_NUMBER, vec![(n >> 8) as u8, n as u8, 0, 0]);
    }

    // -- encoding with integrity / fingerprint ------------------------------

    /// Encode the message without integrity/fingerprint.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + 4 * self.attrs.len());
        out.extend_from_slice(&self.msg_type.to_be_bytes());
        out.extend_from_slice(&[0, 0]); // length placeholder
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.tx_id);
        let mut body = Vec::new();
        for (t, v) in &self.attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            pad4(&mut body, v.len());
        }
        let len = body.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Append MESSAGE-INTEGRITY (HMAC-SHA1) computed with `key`
    /// (RFC 5389 §15.4).  Must be called after all other attributes except
    /// FINGERPRINT.
    pub fn add_message_integrity(&mut self, key: &[u8]) {
        // Encode current attributes, patch length to end at the MI attr.
        let mut msg = self.encode();
        let mi_offset = msg.len();
        msg[2..4].copy_from_slice(&((mi_offset + 24 - 20) as u16).to_be_bytes());
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
        mac.update(&msg);
        let tag = mac.finalize().into_bytes();
        self.attrs.push((MESSAGE_INTEGRITY, tag.to_vec()));
    }

    /// Append FINGERPRINT (CRC32 XOR 0x5354554e) per RFC 5389 §15.5.
    pub fn add_fingerprint(&mut self) {
        let mut msg = self.encode();
        let fp_offset = msg.len();
        msg[2..4].copy_from_slice(&((fp_offset + 8 - 20) as u16).to_be_bytes());
        let crc = crc32(&msg) ^ 0x5354_554E;
        self.attrs.push((FINGERPRINT, crc.to_be_bytes().to_vec()));
    }

    /// Parse a message from a datagram.
    pub fn parse(buf: &[u8]) -> Result<Message, StunError> {
        if buf.len() < 20 {
            return Err(StunError::TooShort(buf.len()));
        }
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(StunError::BadCookie);
        }
        if buf.len() < 20 + len {
            return Err(StunError::BadLength);
        }
        let mut tx_id = [0u8; 12];
        tx_id.copy_from_slice(&buf[8..20]);

        let mut attrs = Vec::new();
        let mut integrity_offset = None;
        let mut fingerprint_offset = None;
        let mut pos = 20usize;
        let end = 20 + len;
        while pos < end {
            if pos + 4 > end {
                return Err(StunError::BadAttribute);
            }
            let t = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let alen = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            if pos + 4 + alen > end {
                return Err(StunError::BadAttribute);
            }
            let value = buf[pos + 4..pos + 4 + alen].to_vec();
            match t {
                MESSAGE_INTEGRITY => integrity_offset = Some(pos),
                FINGERPRINT => fingerprint_offset = Some(pos),
                _ => {}
            }
            attrs.push((t, value));
            pos += 4 + alen + pad_len(alen);
        }

        Ok(Message {
            msg_type,
            tx_id,
            attrs,
            raw: buf[..20 + len].to_vec(),
            integrity_offset,
            fingerprint_offset,
        })
    }

    /// Verify MESSAGE-INTEGRITY with `key` (RFC 5389 §15.4 receiver rules).
    pub fn verify_integrity(&self, key: &[u8]) -> Result<bool, StunError> {
        let Some(mi_tlv) = self.integrity_offset else {
            return Ok(false);
        };
        // HMAC input: the message up to (not including) the MESSAGE-INTEGRITY
        // attribute, with the header length field covering the MI attribute
        // (RFC 5389 §15.4).
        let mut input = self.raw[..mi_tlv].to_vec();
        let len = (mi_tlv + 4 + 20 - 20) as u16;
        input[2..4].copy_from_slice(&len.to_be_bytes());
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
        mac.update(&input);
        let expected = mac.finalize().into_bytes();
        let got = self
            .get(MESSAGE_INTEGRITY)
            .ok_or(StunError::IntegrityFailed)?;
        Ok(constant_eq(&expected, got))
    }

    /// Verify FINGERPRINT (RFC 5389 §15.5 receiver rules).
    pub fn verify_fingerprint(&self) -> Result<bool, StunError> {
        let Some(fp_tlv) = self.fingerprint_offset else {
            return Ok(false);
        };
        // Fingerprint input: the message up to (not including) the
        // FINGERPRINT attribute, with the length field covering it
        // (RFC 5389 §15.5).
        let mut input = self.raw[..fp_tlv].to_vec();
        let len = (fp_tlv + 4 + 4 - 20) as u16;
        input[2..4].copy_from_slice(&len.to_be_bytes());
        let expected = crc32(&input) ^ 0x5354_554E;
        let got = self.get(FINGERPRINT).ok_or(StunError::FingerprintFailed)?;
        if got.len() != 4 {
            return Err(StunError::FingerprintFailed);
        }
        Ok(expected == u32::from_be_bytes([got[0], got[1], got[2], got[3]]))
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

fn pad_len(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

fn pad4(buf: &mut Vec<u8>, n: usize) {
    for _ in 0..pad_len(n) {
        buf.push(0);
    }
}

/// XOR-MAPPED-ADDRESS / XOR-PEER-ADDRESS / XOR-RELAYED-ADDRESS encoding
/// (RFC 5389 §15.2).
pub fn encode_xor_address(addr: SocketAddr, tx_id: &[u8; 12]) -> Vec<u8> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let mut v = Vec::with_capacity(20);
    match addr {
        SocketAddr::V4(a) => {
            v.extend_from_slice(&[0x00, 0x01]);
            let port = a.port() ^ u16::from_be_bytes([cookie[0], cookie[1]]);
            v.extend_from_slice(&port.to_be_bytes());
            let octets = a.ip().octets();
            for i in 0..4 {
                v.push(octets[i] ^ cookie[i]);
            }
        }
        SocketAddr::V6(a) => {
            v.extend_from_slice(&[0x00, 0x02]);
            let port = a.port() ^ u16::from_be_bytes([cookie[0], cookie[1]]);
            v.extend_from_slice(&port.to_be_bytes());
            let mut xmask = [0u8; 16];
            xmask[..4].copy_from_slice(&cookie);
            xmask[4..].copy_from_slice(tx_id);
            let octets = a.ip().octets();
            for i in 0..16 {
                v.push(octets[i] ^ xmask[i]);
            }
        }
    }
    v
}

pub fn decode_xor_address(v: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, StunError> {
    if v.len() < 8 {
        return Err(StunError::BadAttribute);
    }
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let family = v[1];
    let port = u16::from_be_bytes([v[2], v[3]]) ^ u16::from_be_bytes([cookie[0], cookie[1]]);
    match family {
        0x01 => {
            if v.len() < 8 {
                return Err(StunError::BadAttribute);
            }
            let mut octets = [0u8; 4];
            for i in 0..4 {
                octets[i] = v[4 + i] ^ cookie[i];
            }
            Ok(SocketAddr::new(IpAddr::V4(octets.into()), port))
        }
        0x02 => {
            if v.len() < 20 {
                return Err(StunError::BadAttribute);
            }
            let mut xmask = [0u8; 16];
            xmask[..4].copy_from_slice(&cookie);
            xmask[4..].copy_from_slice(tx_id);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = v[4 + i] ^ xmask[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(octets.into()), port))
        }
        other => Err(StunError::BadAddressFamily(other)),
    }
}

/// MAPPED-ADDRESS (non-XOR, RFC 5389 §15.1).
pub fn encode_plain_address(addr: SocketAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    match addr {
        SocketAddr::V4(a) => {
            v.extend_from_slice(&[0x00, 0x01]);
            v.extend_from_slice(&a.port().to_be_bytes());
            v.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            v.extend_from_slice(&[0x00, 0x02]);
            v.extend_from_slice(&a.port().to_be_bytes());
            v.extend_from_slice(&a.ip().octets());
        }
    }
    v
}

pub fn decode_plain_address(v: &[u8]) -> Result<SocketAddr, StunError> {
    if v.len() < 8 {
        return Err(StunError::BadAttribute);
    }
    let port = u16::from_be_bytes([v[2], v[3]]);
    match v[1] {
        0x01 => {
            if v.len() < 8 {
                return Err(StunError::BadAttribute);
            }
            Ok(SocketAddr::new(
                IpAddr::V4([v[4], v[5], v[6], v[7]].into()),
                port,
            ))
        }
        0x02 => {
            if v.len() < 20 {
                return Err(StunError::BadAttribute);
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&v[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(o.into()), port))
        }
        other => Err(StunError::BadAddressFamily(other)),
    }
}

/// Derive the long-term credential HMAC key: MD5(user ":" realm ":" pass)
/// (RFC 5389 §15.4).
pub fn long_term_key(user: &str, realm: &str, pass: &str) -> Vec<u8> {
    use md5::Digest;
    let mut h = md5::Md5::new();
    h.update(user.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(pass.as_bytes());
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    const RFC5769_KEY: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";

    /// RFC 5769 §2.1 sample request: parse, verify integrity + fingerprint.
    #[test]
    fn rfc5769_sample_request() {
        let buf = hex::decode(concat!(
            "000100582112a442b7e7a701bc34d686fa87dfae",
            "802200105354554e207465737420636c69656e74",
            "002400046e0001ff",
            "80290008932ff9b151263b36",
            "000600096576746a3a68367659202020",
            "00080014",
            "9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2",
            "80280004e57a3bcf"
        ))
        .unwrap();
        let msg = Message::parse(&buf).unwrap();
        assert_eq!(msg.msg_type, BINDING_REQUEST);
        assert_eq!(msg.username().as_deref(), Some("evtj:h6vY"));
        assert_eq!(msg.priority(), Some(0x6e0001ff));
        assert_eq!(msg.tie_breaker(false), Some(0x932ff9b151263b36));
        assert_eq!(msg.software().as_deref(), Some("STUN test client"));
        assert!(msg.verify_integrity(RFC5769_KEY).unwrap());
        assert!(msg.verify_fingerprint().unwrap());
    }

    /// RFC 5769 §2.2 sample response: parse, verify, decode the XOR'd
    /// mapped address 192.0.2.1:32853.
    #[test]
    fn rfc5769_sample_response() {
        let buf = hex::decode(concat!(
            "0101003c2112a442b7e7a701bc34d686fa87dfae",
            "8022000b7465737420766563746f7220",
            "002000080001a147e112a643",
            "00080014",
            "2b91f599fd9e90c38c7489f92af9ba53f06be7d7",
            "80280004c07d4c96"
        ))
        .unwrap();
        let msg = Message::parse(&buf).unwrap();
        assert_eq!(msg.msg_type, BINDING_RESPONSE);
        let addr = msg.xor_address(XOR_MAPPED_ADDRESS).unwrap().unwrap();
        assert_eq!(addr.to_string(), "192.0.2.1:32853");
        assert!(msg.verify_integrity(RFC5769_KEY).unwrap());
        assert!(msg.verify_fingerprint().unwrap());
    }

    /// Round-trip: encode with MI+FP, parse, verify.
    #[test]
    fn encode_verify_roundtrip() {
        let mut m = Message::new(BINDING_REQUEST);
        m.add_software("voip-stack");
        m.add_username("user:pass");
        m.add_priority(12345);
        m.add_message_integrity(b"secret-password");
        m.add_fingerprint();

        let buf = m.encode();
        let parsed = Message::parse(&buf).unwrap();
        assert_eq!(parsed.username().as_deref(), Some("user:pass"));
        assert!(parsed.verify_integrity(b"secret-password").unwrap());
        assert!(parsed.verify_fingerprint().unwrap());
        assert!(!parsed.verify_integrity(b"wrong").unwrap());
    }

    /// XOR address encoding round-trips for v4 and v6.
    #[test]
    fn xor_address_roundtrip() {
        let tx = [7u8; 12];
        for addr in [
            "192.0.2.1:32853".parse::<SocketAddr>().unwrap(),
            "10.0.0.1:3478".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "[fe80::1234:5678:9abc:def0]:50000".parse().unwrap(),
        ] {
            let enc = encode_xor_address(addr, &tx);
            let dec = decode_xor_address(&enc, &tx).unwrap();
            assert_eq!(dec, addr, "{addr}");
        }
    }

    #[test]
    fn plain_address_roundtrip() {
        let tx = [0u8; 12];
        for addr in [
            "192.0.2.1:32853".parse::<SocketAddr>().unwrap(),
            "[2001:db8::99]:7000".parse().unwrap(),
        ] {
            let enc = encode_plain_address(addr);
            assert_eq!(decode_plain_address(&enc).unwrap(), addr);
            let _ = tx;
        }
    }

    #[test]
    fn error_code_helpers() {
        let mut m = Message::new(BINDING_ERROR_RESPONSE);
        m.add_error_code(401, "Unauthorized");
        assert_eq!(m.error_code().unwrap().0, 401);
        assert_eq!(m.error_code().unwrap().1, "Unauthorized");
    }

    #[test]
    fn long_term_key_matches_md5_construction() {
        let k = long_term_key("user", "realm", "pass");
        // MD5("user:realm:pass")
        use md5::Digest;
        let mut h = md5::Md5::new();
        h.update(b"user:realm:pass");
        assert_eq!(k, h.finalize().to_vec());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(Message::parse(&[]).unwrap_err(), StunError::TooShort(0));
        let m = Message::new(BINDING_REQUEST);
        let mut buf = m.encode();
        buf[4] = 0x00; // clobber cookie
        assert_eq!(Message::parse(&buf).unwrap_err(), StunError::BadCookie);
    }
}
