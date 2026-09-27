//! ICE candidates and SDP candidate-line codec (RFC 8839, formerly 5245).

use std::net::{IpAddr, SocketAddr};

/// Candidate types in priority order (RFC 8445 §5.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    Prflx,
    Srflx,
    Relay,
}

impl CandidateType {
    /// Recommended type preference (RFC 8445 §5.1.2.1 Table 1).
    pub fn type_preference(self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::Prflx => 110,
            CandidateType::Srflx => 100,
            CandidateType::Relay => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CandidateType::Host => "host",
            CandidateType::Prflx => "prflx",
            CandidateType::Srflx => "srflx",
            CandidateType::Relay => "relay",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "host" => Some(CandidateType::Host),
            "prflx" => Some(CandidateType::Prflx),
            "srflx" => Some(CandidateType::Srflx),
            "relay" => Some(CandidateType::Relay),
            _ => None,
        }
    }
}

/// Compute an ICE priority per RFC 8445 §5.1.2.1:
/// `(2^24)*type_pref + (2^8)*local_pref + (256 - component_id)`.
pub fn compute_priority(typ: CandidateType, local_pref: u32, component: u16) -> u32 {
    (typ.type_preference() << 24) + (local_pref << 8) + (256 - component as u32)
}

/// One ICE candidate.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub foundation: String,
    pub component: u16,
    pub transport: String,
    pub priority: u32,
    pub address: SocketAddr,
    pub typ: CandidateType,
    /// Related (base) address for srflx/relay candidates.
    pub related: Option<SocketAddr>,
}

impl Candidate {
    pub fn host(address: SocketAddr, component: u16, foundation: &str) -> Self {
        Candidate {
            foundation: foundation.to_string(),
            component,
            transport: "udp".into(),
            priority: compute_priority(CandidateType::Host, 65535, component),
            address,
            typ: CandidateType::Host,
            related: None,
        }
    }

    pub fn server_reflexive(
        address: SocketAddr,
        base: SocketAddr,
        component: u16,
        foundation: &str,
    ) -> Self {
        Candidate {
            foundation: foundation.to_string(),
            component,
            transport: "udp".into(),
            priority: compute_priority(CandidateType::Srflx, 65535, component),
            address,
            typ: CandidateType::Srflx,
            related: Some(base),
        }
    }

    pub fn relayed(
        address: SocketAddr,
        base: SocketAddr,
        component: u16,
        foundation: &str,
    ) -> Self {
        Candidate {
            foundation: foundation.to_string(),
            component,
            transport: "udp".into(),
            priority: compute_priority(CandidateType::Relay, 65535, component),
            address,
            typ: CandidateType::Relay,
            related: Some(base),
        }
    }

    /// Serialize to an SDP `a=candidate:` line body (RFC 8839 §5.1).
    ///
    /// Note the connection-address and port are separate fields.
    pub fn to_sdp(&self) -> String {
        let mut line = format!(
            "candidate:{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.typ.as_str()
        );
        if let Some(rel) = self.related {
            line.push_str(&format!(" raddr {} rport {}", rel.ip(), rel.port()));
        }
        line
    }

    /// Parse an SDP candidate line (with or without the `candidate:` prefix).
    pub fn from_sdp(line: &str) -> Result<Self, IceError> {
        let line = line.trim();
        let line = line.strip_prefix("a=").unwrap_or(line);
        let line = line.strip_prefix("candidate:").unwrap_or(line);
        let tok: Vec<&str> = line.split_whitespace().collect();
        if tok.len() < 8 {
            return Err(IceError::BadCandidate(line.len()));
        }
        let typ = CandidateType::from_str(tok[7]).ok_or(IceError::BadCandidate(line.len()))?;
        // connection-address and port are separate fields (RFC 8839 §5.1);
        // the address is a single token: bare IPv6, bracketed IPv6 or IPv4.
        let port: u16 = tok[5]
            .parse()
            .map_err(|_| IceError::BadCandidate(line.len()))?;
        let address =
            parse_connection_address(tok[4], port).ok_or(IceError::BadCandidate(line.len()))?;
        let mut related = None;
        if typ != CandidateType::Host {
            // scan for raddr/rport pairs after the "typ x" pair; both are
            // split into ip and port fields respectively.
            let mut i = 8;
            let mut rip: Option<String> = None;
            let mut rport: Option<u16> = None;
            while i < tok.len() {
                match tok[i] {
                    "raddr" if i + 1 < tok.len() => rip = Some(tok[i + 1].to_string()),
                    "rport" if i + 1 < tok.len() => rport = tok[i + 1].parse().ok(),
                    _ => {}
                }
                i += 2;
            }
            if let Some(rip) = rip {
                let port = rport.unwrap_or(0);
                let addr = parse_connection_address(&rip, port)
                    .ok_or(IceError::BadCandidate(line.len()))?;
                related = Some(addr);
            }
        }
        Ok(Candidate {
            foundation: tok[0].to_string(),
            component: tok[1]
                .parse()
                .map_err(|_| IceError::BadCandidate(line.len()))?,
            transport: tok[2].to_ascii_lowercase(),
            priority: tok[3]
                .parse()
                .map_err(|_| IceError::BadCandidate(line.len()))?,
            address,
            typ,
            related,
        })
    }
}

/// Parse a candidate connection-address token + port into a SocketAddr.
/// The address is one whitespace-delimited field (RFC 8839 §5.1) and may be
/// bare IPv6, a bracketed IPv6 literal or IPv4 — colons inside an IPv6
/// address must never be mistaken for an `ip:port` separator.
fn parse_connection_address(ip_txt: &str, port: u16) -> Option<SocketAddr> {
    let ip_txt = ip_txt.trim_matches(|c| c == '[' || c == ']');
    let ip: IpAddr = ip_txt.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

/// Errors from the ICE layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IceError {
    /// Unparseable candidate line.
    #[error("bad candidate line")]
    BadCandidate(usize),
    /// STUN sub-protocol failure while gathering.
    #[error("stun error: {0}")]
    Stun(#[from] crate::stun::StunError),
    /// Socket/network failure.
    #[error("io: {0}")]
    Io(String),
    /// Connectivity checks failed to produce a valid pair.
    #[error("no valid candidate pair")]
    NoValidPair,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ordering() {
        let host = compute_priority(CandidateType::Host, 65535, 1);
        let srflx = compute_priority(CandidateType::Srflx, 65535, 1);
        let relay = compute_priority(CandidateType::Relay, 65535, 1);
        assert!(host > srflx);
        assert!(srflx > relay);
        // RFC 8445 §5.1.2.1 example: component 1, host, local 65535
        assert_eq!(host, (126 << 24) + (65535 << 8) + 255);
    }

    #[test]
    fn sdp_roundtrip() {
        let c = Candidate::host("10.0.1.1:8998".parse().unwrap(), 1, "h1");
        let line = c.to_sdp();
        assert!(line.starts_with("candidate:h1 1 udp "));
        let parsed = Candidate::from_sdp(&line).unwrap();
        assert_eq!(parsed.address, c.address);
        assert_eq!(parsed.typ, CandidateType::Host);
        assert_eq!(parsed.priority, c.priority);

        // with a=candidate: prefix and raddr/rport
        let srflx = Candidate::server_reflexive(
            "203.0.113.9:50000".parse().unwrap(),
            "10.0.1.1:8998".parse().unwrap(),
            1,
            "s1",
        );
        let parsed = Candidate::from_sdp(&format!("a={}", srflx.to_sdp())).unwrap();
        assert_eq!(parsed.typ, CandidateType::Srflx);
        assert_eq!(parsed.related.unwrap().to_string(), "10.0.1.1:8998");
    }

    #[test]
    fn bad_candidates_rejected() {
        assert!(Candidate::from_sdp("candidate:1 1 udp 123").is_err());
        assert!(Candidate::from_sdp("candidate:1 1 udp 123 1.2.3.4 5 typ banana").is_err());
    }

    /// IPv6 host candidates: bare (the RFC 8839 form our to_sdp emits) and
    /// bracketed, with the address taken as a single token.
    #[test]
    fn ipv6_host_candidates_parse() {
        let c =
            Candidate::from_sdp("candidate:1 1 UDP 2130706431 2001:db8::1 8998 typ host").unwrap();
        assert_eq!(c.address.to_string(), "[2001:db8::1]:8998");
        assert_eq!(c.component, 1);
        assert_eq!(c.priority, 2130706431);
        assert_eq!(c.transport, "udp");
        assert_eq!(c.typ, CandidateType::Host);
        assert!(c.related.is_none());

        // Bracketed variant parses to the same address.
        let c2 = Candidate::from_sdp("candidate:1 1 UDP 2130706431 [2001:db8::1] 8998 typ host")
            .unwrap();
        assert_eq!(c2.address, c.address);

        // to_sdp emits the bare form and it re-parses.
        let rt = Candidate::from_sdp(&c.to_sdp()).unwrap();
        assert_eq!(rt.address, c.address);
        assert_eq!(rt.typ, CandidateType::Host);
    }

    /// IPv6 server-reflexive candidate with an IPv6 related address.
    #[test]
    fn ipv6_srflx_with_related() {
        let c = Candidate::from_sdp(
            "candidate:4 1 UDP 1694498815 2001:db8::9 61000 typ srflx raddr 2001:db8::1 rport 8998",
        )
        .unwrap();
        assert_eq!(c.typ, CandidateType::Srflx);
        assert_eq!(c.address.to_string(), "[2001:db8::9]:61000");
        assert_eq!(c.related.unwrap().to_string(), "[2001:db8::1]:8998");
    }

    /// Malformed IPv6 candidates are rejected (bad port, bad address).
    #[test]
    fn ipv6_bad_fields_rejected() {
        assert!(
            Candidate::from_sdp("candidate:1 1 UDP 2130706431 2001:db8::1 notaport typ host")
                .is_err()
        );
        assert!(
            Candidate::from_sdp("candidate:1 1 UDP 2130706431 2001:db8::zz 8998 typ host").is_err()
        );
    }
}
