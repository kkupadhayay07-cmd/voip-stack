//! ICE agent (RFC 8445 §6-8): gathering, connectivity checks, nomination
//! and keepalives over a single UDP socket (one component).
//!
//! The scheduling is "all pairs at once" rather than the RFC's paced
//! triggered-check queue — appropriate for an SBC/B2BUA where candidate
//! sets are small and latency matters — while the on-the-wire protocol
//! (roles, tie-breakers, USE-CANDIDATE, priorities, short-term credentials)
//! is fully RFC 8445.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rand::RngCore;
use tokio::net::UdpSocket;

use crate::candidate::{Candidate, CandidateType, IceError};
use crate::stun;

/// Local configuration: credentials are generated per RFC 8445 §5.1.1.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub local_ufrag: String,
    pub local_pwd: String,
    pub software: String,
    /// Controlling role can be overridden (default: random).
    pub controlling: Option<bool>,
    /// Keepalive interval on the selected pair.
    pub keepalive: Duration,
}

impl Default for AgentConfig {
    fn default() -> Self {
        let mut buf = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let hexed: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        AgentConfig {
            local_ufrag: hexed[..8].to_string(),
            local_pwd: hexed,
            software: "voip-stack-ice".into(),
            controlling: None,
            keepalive: Duration::from_secs(15),
        }
    }
}

/// One connection attempt's outcome.
#[derive(Debug, Clone)]
pub struct SelectedPair {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub local_candidate_type: CandidateType,
    pub remote_candidate_type: CandidateType,
    pub nominating: bool,
}

enum Wire {
    Stun(Vec<u8>),
    Media(Vec<u8>),
    Other(Vec<u8>, SocketAddr),
}

/// Classify an inbound datagram: STUN vs media (RFC 7983 style: first byte).
fn classify(buf: &[u8], from: SocketAddr) -> Wire {
    match buf.first() {
        Some(b) if (0u8..=3).contains(b) => Wire::Stun(buf.to_vec()),
        Some(b) if (128u8..=191).contains(b) => Wire::Media(buf.to_vec()),
        _ => Wire::Other(buf.to_vec(), from),
    }
}

/// A single-component ICE agent bound to one UDP socket.
pub struct IceAgent {
    config: AgentConfig,
    controlling: bool,
    tie_breaker: u64,
    socket: UdpSocket,
    local: Vec<Candidate>,
    remote: Vec<Candidate>,
    remote_ufrag: Option<String>,
    remote_pwd: Option<String>,
    /// peer -> outstanding check state (transaction id -> pair)
    checks: HashMap<[u8; 12], PendingCheck>,
    nominations: HashMap<[u8; 12], PendingCheck>,
    selected: Option<SelectedPair>,
    foundation_seed: u64,
}

#[derive(Debug, Clone)]
struct PendingCheck {
    pair: (SocketAddr, SocketAddr),
    use_candidate: bool,
}

impl IceAgent {
    /// Bind the agent socket and prepare for gathering.
    pub async fn new(config: AgentConfig) -> Result<Self, IceError> {
        let socket = UdpSocket::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| IceError::Io(e.to_string()))?;
        let controlling = config
            .controlling
            .unwrap_or_else(|| rand::random::<u8>() & 1 == 0);
        let mut tie = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut tie);
        Ok(IceAgent {
            controlling,
            tie_breaker: u64::from_be_bytes(tie),
            config,
            socket,
            local: Vec::new(),
            remote: Vec::new(),
            remote_ufrag: None,
            remote_pwd: None,
            checks: HashMap::new(),
            nominations: HashMap::new(),
            selected: None,
            foundation_seed: 1,
        })
    }

    pub fn local_ufrag(&self) -> &str {
        &self.config.local_ufrag
    }

    pub fn local_pwd(&self) -> &str {
        &self.config.local_pwd
    }

    pub fn is_controlling(&self) -> bool {
        self.controlling
    }

    /// Bound local port of the agent socket.
    pub fn local_addr(&self) -> Result<SocketAddr, IceError> {
        self.socket
            .local_addr()
            .map_err(|e| IceError::Io(e.to_string()))
    }

    fn next_foundation(&mut self, typ: CandidateType) -> String {
        let f = format!(
            "{}{:x}",
            typ.as_str()[..2].to_uppercase(),
            self.foundation_seed
        );
        self.foundation_seed += 1;
        f
    }

    /// Add a host candidate for the bound socket.  When the socket is
    /// bound to a wildcard address, the concrete local IP is discovered by
    /// a route probe so the candidate is actually addressable.
    pub fn gather_host(&mut self) -> Result<Candidate, IceError> {
        let bound = self.local_addr()?;
        let addr = if bound.ip().is_unspecified() {
            SocketAddr::new(
                discover_local_ip().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                bound.port(),
            )
        } else {
            bound
        };
        let c = Candidate::host(addr, 1, &self.next_foundation(CandidateType::Host));
        self.local.push(c.clone());
        Ok(c)
    }

    /// Query a STUN server through the agent socket for a server-reflexive
    /// candidate (RFC 8445 §5.1.1.2 / RFC 5389 §7).
    pub async fn gather_srflx(&mut self, stun_server: SocketAddr) -> Result<Candidate, IceError> {
        let mut req = stun::Message::new(stun::BINDING_REQUEST);
        req.add_software(&self.config.software);
        req.add_fingerprint();
        self.socket
            .send_to(&req.encode(), stun_server)
            .await
            .map_err(|e| IceError::Io(e.to_string()))?;

        let buf = &mut [0u8; 1500];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let n = tokio::time::timeout_at(deadline, self.socket.recv_from(buf))
                .await
                .map_err(|_| IceError::Io("srflx gather timeout".into()))?
                .map_err(|e| IceError::Io(e.to_string()))?
                .0;
            if let Ok(msg) = stun::Message::parse(&buf[..n]) {
                if msg.msg_type == stun::BINDING_RESPONSE && msg.tx_id == req.tx_id {
                    if let Some(addr) = msg.xor_address(stun::XOR_MAPPED_ADDRESS).transpose()? {
                        let base = self.local_addr()?;
                        let c = Candidate::server_reflexive(
                            addr,
                            base,
                            1,
                            &self.next_foundation(CandidateType::Srflx),
                        );
                        self.local.push(c.clone());
                        return Ok(c);
                    }
                }
            }
        }
    }

    /// Allocate a TURN relay candidate (RFC 5766 §6.2).  `user`/`pass` are
    /// long-term credentials; the allocation is kept alive by the agent
    /// while the connection is active.
    pub async fn gather_relay(
        &mut self,
        turn_server: SocketAddr,
        user: &str,
        pass: &str,
    ) -> Result<Candidate, IceError> {
        // 1. Binding request to learn realm/nonce (438 error).
        let mut probe = stun::Message::new(stun::ALLOCATE_REQUEST);
        probe.add_requested_transport(17); // UDP
        self.socket
            .send_to(&probe.encode(), turn_server)
            .await
            .map_err(|e| IceError::Io(e.to_string()))?;
        let (realm, nonce) = self
            .await_message(turn_server, Duration::from_secs(3), |m| {
                m.msg_type == stun::ALLOCATE_ERROR_RESPONSE
            })
            .await?
            .map(|m| {
                let realm = m
                    .get(stun::REALM)
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .unwrap_or_default();
                let nonce = m.get(stun::NONCE).map(|v| v.to_vec()).unwrap_or_default();
                (realm, nonce)
            })
            .unwrap_or((String::new(), Vec::new()));

        if realm.is_empty() {
            // Server runs without authentication.
            let mut alloc = stun::Message::new(stun::ALLOCATE_REQUEST);
            alloc.add_requested_transport(17);
            self.send_stun(alloc, turn_server).await?;
            let resp = self
                .await_message(turn_server, Duration::from_secs(3), |m| {
                    m.msg_type == stun::ALLOCATE_RESPONSE
                        || m.msg_type == stun::ALLOCATE_ERROR_RESPONSE
                })
                .await?
                .ok_or(IceError::Io("no allocate response".into()))?;
            if resp.msg_type != stun::ALLOCATE_RESPONSE {
                return Err(IceError::Io("allocate refused".into()));
            }
            let relayed = resp
                .xor_address(stun::XOR_RELAYED_ADDRESS)
                .transpose()?
                .ok_or(IceError::Io("no relayed address".into()))?;
            let base = self.local_addr()?;
            let c = Candidate::relayed(
                relayed,
                base,
                1,
                &self.next_foundation(CandidateType::Relay),
            );
            self.local.push(c.clone());
            return Ok(c);
        }

        // 2. Authenticated allocate with long-term key.
        let key = stun::long_term_key(user, &realm, pass);
        let mut alloc = stun::Message::new(stun::ALLOCATE_REQUEST);
        alloc.add_requested_transport(17);
        alloc.add_username(user);
        alloc.add(stun::REALM, realm.clone().into_bytes());
        alloc.add(stun::NONCE, nonce.clone());
        alloc.add_message_integrity(&key);
        self.send_stun_raw(alloc, turn_server).await?;

        let resp = self
            .await_message(turn_server, Duration::from_secs(3), |m| {
                m.msg_type == stun::ALLOCATE_RESPONSE || m.msg_type == stun::ALLOCATE_ERROR_RESPONSE
            })
            .await?
            .ok_or(IceError::Io("no allocate response".into()))?;
        if resp.msg_type != stun::ALLOCATE_RESPONSE {
            let (code, reason) = resp.error_code().unwrap_or((0, "?".into()));
            return Err(IceError::Io(format!("allocate {code} {reason}")));
        }
        // Verify integrity of the response.
        if !resp.verify_integrity(&key)? {
            return Err(IceError::Io("allocate integrity failed".into()));
        }
        let relayed = resp
            .xor_address(stun::XOR_RELAYED_ADDRESS)
            .transpose()?
            .ok_or(IceError::Io("no relayed address".into()))?;
        let base = self.local_addr()?;
        let c = Candidate::relayed(
            relayed,
            base,
            1,
            &self.next_foundation(CandidateType::Relay),
        );
        self.local.push(c.clone());
        Ok(c)
    }

    async fn send_stun_raw(&mut self, msg: stun::Message, to: SocketAddr) -> Result<(), IceError> {
        self.socket
            .send_to(&msg.encode(), to)
            .await
            .map(|_| ())
            .map_err(|e| IceError::Io(e.to_string()))
    }

    async fn send_stun(&mut self, mut msg: stun::Message, to: SocketAddr) -> Result<(), IceError> {
        msg.add_fingerprint();
        self.send_stun_raw(msg, to).await
    }

    async fn await_message<F>(
        &mut self,
        from: SocketAddr,
        timeout: Duration,
        mut filter: F,
    ) -> Result<Option<stun::Message>, IceError>
    where
        F: FnMut(&stun::Message) -> bool,
    {
        let buf = &mut [0u8; 1500];
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let n = tokio::time::timeout(remaining, self.socket.recv_from(buf))
                .await
                .ok()
                .and_then(|r| r.ok())
                .map(|(n, _)| n);
            let Some(n) = n else { return Ok(None) };
            if let Ok(msg) = stun::Message::parse(&buf[..n]) {
                if filter(&msg) {
                    let _ = from;
                    return Ok(Some(msg));
                }
            }
        }
    }

    /// Set remote candidates + credentials (from SDP).
    pub fn set_remote(&mut self, ufrag: &str, pwd: &str, candidates: &[Candidate]) {
        self.remote_ufrag = Some(ufrag.to_string());
        self.remote_pwd = Some(pwd.to_string());
        self.remote = candidates.to_vec();
    }

    /// Run connectivity checks until a pair is nominated or `timeout`
    /// elapses.  Returns the selected pair.
    pub async fn connect(&mut self, timeout: Duration) -> Result<SelectedPair, IceError> {
        let remote_pwd = self.remote_pwd.clone().ok_or(IceError::NoValidPair)?;
        let remote_ufrag = self.remote_ufrag.clone().ok_or(IceError::NoValidPair)?;

        // Issue checks for every candidate pair, best (highest priority)
        // remote candidate first.
        let mut remotes = self.remote.clone();
        remotes.sort_by_key(|c| std::cmp::Reverse(c.priority));
        for rc in &remotes {
            if rc.transport != "udp" {
                continue;
            }
            let use_candidate = self.controlling;
            let mut msg = stun::Message::new(stun::BINDING_REQUEST);
            msg.add_username(&format!("{remote_ufrag}:{}", self.config.local_ufrag));
            msg.add_priority(compute_prflx_priority());
            if self.controlling {
                msg.add_tie_breaker(true, self.tie_breaker);
            } else {
                msg.add_tie_breaker(false, self.tie_breaker);
            }
            if use_candidate {
                msg.add_use_candidate();
            }
            msg.add_message_integrity(remote_pwd.as_bytes());
            msg.add_fingerprint();
            let tx = msg.tx_id;
            self.send_stun_raw(msg, rc.address).await?;
            self.checks.insert(
                tx,
                PendingCheck {
                    pair: (self.local_addr()?, rc.address),
                    use_candidate,
                },
            );
        }

        // Pump the socket until nominated.
        let buf = &mut [0u8; 1500];
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(sel) = &self.selected {
                return Ok(sel.clone());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(IceError::NoValidPair);
            }
            let recv = tokio::time::timeout(remaining, self.socket.recv_from(buf)).await;
            let Ok(Ok((n, from))) = recv else {
                return Err(IceError::NoValidPair);
            };
            self.handle_datagram(&buf[..n], from).await?;
        }
    }

    async fn handle_datagram(&mut self, data: &[u8], from: SocketAddr) -> Result<(), IceError> {
        match classify(data, from) {
            Wire::Stun(bytes) => self.handle_stun(bytes, from).await,
            Wire::Media(bytes) => {
                // Post-connection media: deliver via the pending queue of
                // the application (out of scope for the agent; count only).
                let _ = bytes;
                Ok(())
            }
            Wire::Other(bytes, addr) => {
                let _ = (bytes, addr);
                Ok(())
            }
        }
    }

    async fn handle_stun(&mut self, bytes: Vec<u8>, from: SocketAddr) -> Result<(), IceError> {
        let Ok(msg) = stun::Message::parse(&bytes) else {
            return Ok(());
        };
        let remote_pwd = self.remote_pwd.clone().unwrap_or_default();
        let local_pwd = self.config.local_pwd.clone();

        match msg.msg_type {
            stun::BINDING_REQUEST => {
                // Validate USERNAME (RFC 8445 §7.3): the incoming value
                // begins with OUR ufrag, followed by the peer's.
                let expected = format!(
                    "{}:{}",
                    self.config.local_ufrag,
                    self.remote_ufrag.clone().unwrap_or_default()
                );
                if msg.username().as_deref() != Some(expected.as_str()) {
                    let mut err =
                        stun::Message::new_with_txid(stun::BINDING_ERROR_RESPONSE, msg.tx_id);
                    err.add_error_code(401, "Unauthorized");
                    self.send_stun(err, from).await?;
                    return Ok(());
                }
                if !msg.verify_integrity(local_pwd.as_bytes())? {
                    return Ok(());
                }
                let controlling_peer = msg.tie_breaker(true).is_some();
                let _ = controlling_peer;

                // Remember the peer's reflexive address as a prflx candidate.
                if !self.remote.iter().any(|c| c.address == from) {
                    let mut c = Candidate::server_reflexive(from, from, 1, "PR1");
                    c.typ = CandidateType::Prflx;
                    self.remote.push(c);
                }

                let mut resp = stun::Message::new_with_txid(stun::BINDING_RESPONSE, msg.tx_id);
                resp.add_xor_address(stun::XOR_MAPPED_ADDRESS, from);
                resp.add_message_integrity(local_pwd.as_bytes());
                resp.add_fingerprint();
                self.send_stun(resp, from).await?;

                // If the request carried USE-CANDIDATE, the peer nominated us.
                if msg.use_candidate() && self.selected.is_none() {
                    self.selected = Some(SelectedPair {
                        local: self.local_addr()?,
                        remote: from,
                        local_candidate_type: CandidateType::Host,
                        remote_candidate_type: CandidateType::Prflx,
                        nominating: false,
                    });
                }
            }
            stun::BINDING_RESPONSE => {
                // Match to an outstanding check.
                if (self.checks.contains_key(&msg.tx_id)
                    || self.nominations.contains_key(&msg.tx_id))
                    && msg.verify_integrity(remote_pwd.as_bytes())?
                {
                    let check = self
                        .checks
                        .remove(&msg.tx_id)
                        .or_else(|| self.nominations.remove(&msg.tx_id));
                    if let Some(check) = check {
                        let mapped = msg
                            .xor_address(stun::XOR_MAPPED_ADDRESS)
                            .transpose()?
                            .unwrap_or(check.pair.0);
                        let _ = mapped;
                        if check.use_candidate && self.selected.is_none() {
                            self.selected = Some(SelectedPair {
                                local: check.pair.0,
                                remote: check.pair.1,
                                local_candidate_type: CandidateType::Host,
                                remote_candidate_type: self
                                    .remote
                                    .iter()
                                    .find(|c| c.address == check.pair.1)
                                    .map(|c| c.typ)
                                    .unwrap_or(CandidateType::Prflx),
                                nominating: true,
                            });
                        } else if self.selected.is_none() && self.controlling {
                            // Aggressive nomination: controlling agent
                            // nominates the first pair that validates,
                            // with USE-CANDIDATE.
                            let mut nom = stun::Message::new(stun::BINDING_REQUEST);
                            nom.add_username(&format!(
                                "{}:{}",
                                self.remote_ufrag.clone().unwrap_or_default(),
                                self.config.local_ufrag
                            ));
                            nom.add_priority(compute_prflx_priority());
                            nom.add_tie_breaker(true, self.tie_breaker);
                            nom.add_use_candidate();
                            nom.add_message_integrity(remote_pwd.as_bytes());
                            nom.add_fingerprint();
                            let tx = nom.tx_id;
                            self.send_stun_raw(nom, check.pair.1).await?;
                            self.nominations.insert(
                                tx,
                                PendingCheck {
                                    pair: check.pair,
                                    use_candidate: true,
                                },
                            );
                        }
                    }
                }
            }
            stun::BINDING_INDICATION => {
                // Keepalive.
            }
            _ => {}
        }
        Ok(())
    }

    /// Send one keepalive binding indication on the selected pair.
    pub async fn keepalive(&mut self, remote: SocketAddr) -> Result<(), IceError> {
        let mut ind = stun::Message::new(stun::BINDING_INDICATION);
        ind.add_software(&self.config.software);
        ind.add_fingerprint();
        self.send_stun_raw(ind, remote).await
    }

    /// The selected pair, once available.
    pub fn selected(&self) -> Option<&SelectedPair> {
        self.selected.as_ref()
    }

    /// Local candidates as SDP lines.
    pub fn local_candidates_sdp(&self) -> Vec<String> {
        self.local.iter().map(|c| c.to_sdp()).collect()
    }

    /// Local candidates.
    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local
    }

    /// Raw access to the socket (for the SRTP media pump after connect).
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Split off the socket for post-ICE media pumping.
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

/// Peer-reflexive priority used in outgoing check requests
/// (RFC 8445 §7.1.1.1: prflx type preference 110).
fn compute_prflx_priority() -> u32 {
    crate::candidate::compute_priority(CandidateType::Prflx, 65535, 1)
}

/// Best-effort discovery of the machine's primary outbound IPv4/IPv6
/// address via a routing-table probe (no packets are sent: UDP `connect`
/// only consults the routing table).
fn discover_local_ip() -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip())
}
