//! Native STUN server (RFC 5389 §8) and TURN relay server (RFC 5766 §6-10)
//! sharing one UDP socket.
//!
//! - Binding requests → XOR-MAPPED-ADDRESS responses (the "server reflexive
//!   address" oracle our own agent and external clients use)
//! - TURN allocations with long-term credentials (realm/nonce, MD5 key),
//!   per-allocation UDP relay sockets, peer permissions, Send/Data
//!   indications, ChannelBind mapping

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::stun;

/// Long-term credential store: username → password.
pub type UserDb = HashMap<String, String>;

/// One TURN allocation: relay socket + permission set.
struct Allocation {
    relay: Arc<UdpSocket>,
    #[allow(dead_code)] // kept for auditing/logging future use
    username: String,
    permitted: std::collections::HashSet<std::net::IpAddr>,
    /// Channel numbers bound by this client (channel → peer addr).
    channels: HashMap<u16, SocketAddr>,
    peers: HashMap<SocketAddr, u16>,
    #[allow(dead_code)] // refreshed by Refresh requests
    expiry: Instant,
}

/// Errors from the server loop.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// STUN + TURN server configuration.
#[derive(Clone)]
pub struct StunTurnConfig {
    pub users: UserDb,
    /// When false, TURN allocations skip authentication (lab mode).
    pub require_auth: bool,
    pub software: String,
    pub default_lifetime: Duration,
}

impl Default for StunTurnConfig {
    fn default() -> Self {
        StunTurnConfig {
            users: HashMap::new(),
            require_auth: true,
            software: "voip-stack-stun-turn".into(),
            default_lifetime: Duration::from_secs(600),
        }
    }
}

/// A running STUN/TURN server.
pub struct StunTurnServer {
    socket: Arc<UdpSocket>,
    allocations: Arc<RwLock<HashMap<SocketAddr, Allocation>>>,
    nonce: String,
    realm: String,
    config: StunTurnConfig,
}

impl StunTurnServer {
    /// Bind and prepare the server.
    pub async fn bind(addr: &str, config: StunTurnConfig) -> Result<Self, ServerError> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let mut nonce_bytes = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let nonce: String = nonce_bytes.iter().map(|b| format!("{b:02x}")).collect();
        Ok(StunTurnServer {
            socket,
            allocations: Arc::new(RwLock::new(HashMap::new())),
            nonce,
            realm: "voip-stack".into(),
            config,
        })
    }

    /// The public address clients should target.
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.socket.local_addr()?)
    }

    /// Run the server loop forever.  Handles STUN binding, TURN protocol
    /// and relays media between allocations and their permitted peers.
    ///
    /// A dedicated task polls the per-allocation relay sockets so peer
    /// traffic is forwarded even while the main socket is idle.
    pub async fn run(&self) -> Result<(), ServerError> {
        // Background relay pump.
        let relay_allocs = self.allocations.clone();
        let relay_sock = self.socket.clone();
        tokio::spawn(async move {
            // Poll relay sockets every few milliseconds; forward permitted
            // peer traffic to allocation owners as Data indications.
            let mut rbuf = [0u8; 2048];
            loop {
                let mut any = false;
                {
                    let allocs = relay_allocs.read().await;
                    for (client_addr, alloc) in allocs.iter() {
                        if let Ok((n, peer)) = alloc.relay.try_recv_from(&mut rbuf) {
                            any = true;
                            let permitted = alloc.permitted.contains(&peer.ip())
                                || alloc.peers.contains_key(&peer);
                            if permitted {
                                let mut out = stun::Message::new(stun::DATA_INDICATION);
                                out.add_xor_address(stun::XOR_PEER_ADDRESS, peer);
                                out.add(stun::DATA, rbuf[..n].to_vec());
                                let _ = relay_sock.send_to(&out.encode(), *client_addr).await;
                            }
                        }
                    }
                }
                if !any {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        });

        let buf = &mut [0u8; 2048];
        loop {
            let (n, from) = self.socket.recv_from(buf).await?;
            if let Ok(msg) = stun::Message::parse(&buf[..n]) {
                self.handle(msg, from).await?;
            }
        }
    }

    async fn handle(&self, msg: stun::Message, from: SocketAddr) -> Result<(), ServerError> {
        match msg.msg_type {
            stun::BINDING_REQUEST => {
                let mut resp = stun::Message::new_with_txid(stun::BINDING_RESPONSE, msg.tx_id);
                resp.add_xor_address(stun::XOR_MAPPED_ADDRESS, from);
                resp.add_address(stun::MAPPED_ADDRESS, from);
                resp.add_software(&self.config.software);
                resp.add_fingerprint();
                let _ = self.socket.send_to(&resp.encode(), from).await;
            }
            stun::BINDING_INDICATION => {}
            stun::ALLOCATE_REQUEST => self.handle_allocate(msg, from).await,
            stun::REFRESH_REQUEST => {
                let mut resp = stun::Message::new_with_txid(stun::REFRESH_RESPONSE, msg.tx_id);
                let life = msg.lifetime().unwrap_or(600);
                resp.add_lifetime(life);
                resp.add_fingerprint();
                let _ = self.socket.send_to(&resp.encode(), from).await;
            }
            stun::CREATE_PERMISSION_REQUEST => {
                if !msg.get_all(stun::XOR_PEER_ADDRESS).is_empty() {
                    let peers = msg.get_all(stun::XOR_PEER_ADDRESS);
                    let mut allocs = self.allocations.write().await;
                    if let Some(alloc) = allocs.get_mut(&from) {
                        for p in peers {
                            if let Ok(peer) = stun::decode_xor_address(p, &msg.tx_id) {
                                alloc.permitted.insert(peer.ip());
                            }
                        }
                    }
                    drop(allocs);
                }
                let mut resp =
                    stun::Message::new_with_txid(stun::CREATE_PERMISSION_RESPONSE, msg.tx_id);
                resp.add_fingerprint();
                let _ = self.socket.send_to(&resp.encode(), from).await;
            }
            stun::CHANNEL_BIND_REQUEST => {
                let channel = msg.channel_number();
                let peer = msg
                    .xor_address(stun::XOR_PEER_ADDRESS)
                    .transpose()
                    .ok()
                    .flatten();
                if let (Some(ch), Some(peer)) = (channel, peer) {
                    let mut allocs = self.allocations.write().await;
                    if let Some(alloc) = allocs.get_mut(&from) {
                        alloc.channels.insert(ch, peer);
                        alloc.peers.insert(peer, ch);
                        alloc.permitted.insert(peer.ip());
                    }
                }
                let mut resp = stun::Message::new_with_txid(stun::CHANNEL_BIND_RESPONSE, msg.tx_id);
                resp.add_fingerprint();
                let _ = self.socket.send_to(&resp.encode(), from).await;
            }
            stun::SEND_INDICATION => {
                // Forward the DATA payload to the XOR-PEER-ADDRESS if permitted.
                let peer = msg
                    .xor_address(stun::XOR_PEER_ADDRESS)
                    .transpose()
                    .ok()
                    .flatten();
                let data = msg.get(stun::DATA).map(|d| d.to_vec());
                if let (Some(peer), Some(data)) = (peer, data) {
                    let allocs = self.allocations.read().await;
                    if let Some(alloc) = allocs.get(&from) {
                        if alloc.permitted.contains(&peer.ip()) || alloc.peers.contains_key(&peer) {
                            let _ = alloc.relay.send_to(&data, peer).await;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_allocate(&self, msg: stun::Message, from: SocketAddr) {
        // Transport must be UDP (17).
        if msg.requested_transport() != Some(17) {
            let mut err = stun::Message::new_with_txid(stun::ALLOCATE_ERROR_RESPONSE, msg.tx_id);
            err.add_error_code(442, "Unsupported Transport Protocol");
            err.add_fingerprint();
            let _ = self.socket.send_to(&err.encode(), from).await;
            return;
        }

        // Authentication (long-term credentials).
        let username = msg.username();
        let authenticated = if !self.config.require_auth {
            true
        } else if let Some(user) = username.clone() {
            let pass_ok = self
                .config
                .users
                .get(&user)
                .map(|pass| {
                    let key = stun::long_term_key(&user, &self.realm, pass);
                    msg.verify_integrity(&key).unwrap_or(false)
                })
                .unwrap_or(false);
            let nonce_ok = msg
                .get(stun::NONCE)
                .map(|n| n == self.nonce.as_bytes())
                .unwrap_or(false);
            pass_ok && nonce_ok
        } else {
            false
        };

        if !authenticated {
            let mut err = stun::Message::new_with_txid(stun::ALLOCATE_ERROR_RESPONSE, msg.tx_id);
            // 401 with fresh realm/nonce — the client retries with
            // credentials (RFC 5389 §10.2.2).
            err.add_error_code(401, "Unauthorized");
            err.add(stun::REALM, self.realm.clone().into_bytes());
            err.add(stun::NONCE, self.nonce.clone().into_bytes());
            err.add_fingerprint();
            let _ = self.socket.send_to(&err.encode(), from).await;
            return;
        }

        // Compute the long-term key for the (now authenticated) user.
        let key = username
            .as_ref()
            .map(|user| {
                stun::long_term_key(
                    user,
                    &self.realm,
                    self.config
                        .users
                        .get(user)
                        .map(|s| s.as_str())
                        .unwrap_or(""),
                )
            })
            .unwrap_or_default();

        // Already allocated?
        if self.allocations.read().await.contains_key(&from) {
            let mut resp = stun::Message::new_with_txid(stun::ALLOCATE_RESPONSE, msg.tx_id);
            resp.add_lifetime(self.config.default_lifetime.as_secs() as u32);
            if !key.is_empty() {
                resp.add_message_integrity(&key);
            }
            resp.add_fingerprint();
            let _ = self.socket.send_to(&resp.encode(), from).await;
            return;
        }

        // Bind a relay socket.
        let Ok(relay) = UdpSocket::bind(("0.0.0.0", 0)).await else {
            let mut err = stun::Message::new_with_txid(stun::ALLOCATE_ERROR_RESPONSE, msg.tx_id);
            err.add_error_code(508, "Insufficient Capacity");
            let _ = self.socket.send_to(&err.encode(), from).await;
            return;
        };
        let relayed = relay.local_addr().unwrap_or(from);

        let alloc = Allocation {
            relay: Arc::new(relay),
            username: username.unwrap_or_default(),
            permitted: std::collections::HashSet::new(),
            channels: HashMap::new(),
            peers: HashMap::new(),
            expiry: Instant::now() + self.config.default_lifetime,
        };
        self.allocations.write().await.insert(from, alloc);

        let mut resp = stun::Message::new_with_txid(stun::ALLOCATE_RESPONSE, msg.tx_id);
        resp.add_xor_address(stun::XOR_RELAYED_ADDRESS, relayed);
        resp.add_xor_address(stun::XOR_MAPPED_ADDRESS, from);
        resp.add_lifetime(self.config.default_lifetime.as_secs() as u32);
        if !key.is_empty() {
            resp.add_message_integrity(&key);
        }
        resp.add_fingerprint();
        let _ = self.socket.send_to(&resp.encode(), from).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binding_request_roundtrip() {
        let server = StunTurnServer::bind("127.0.0.1:0", StunTurnConfig::default())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move { server.run().await });

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut req = stun::Message::new(stun::BINDING_REQUEST);
        req.add_fingerprint();
        sock.send_to(&req.encode(), addr).await.unwrap();

        let buf = &mut [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(buf))
            .await
            .unwrap()
            .unwrap();
        let resp = stun::Message::parse(&buf[..n]).unwrap();
        assert_eq!(resp.msg_type, stun::BINDING_RESPONSE);
        assert_eq!(resp.tx_id, req.tx_id);
        let mapped = resp.xor_address(stun::XOR_MAPPED_ADDRESS).unwrap().unwrap();
        let local = sock.local_addr().unwrap();
        assert_eq!(mapped.ip(), local.ip());
        // Server reflexive port matches our source port.
        assert_eq!(mapped.port(), local.port());
        assert!(resp.verify_fingerprint().unwrap());
    }
}
