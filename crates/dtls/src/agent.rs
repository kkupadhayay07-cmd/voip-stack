//! DTLS-SRTP endpoint: handshake driving, SRTP profile negotiation and
//! keying-material export.
//!
//! Uses OpenSSL's DTLS 1.2 state machine (via the `openssl` crate — an
//! explicitly whitelisted, unsafe-isolated FFI binding for encryption) over
//! a datagram queue transport, adding our own flight retransmission timer
//! because the queue BIO does not carry DTLS timers.

use std::net::SocketAddr;
use std::time::Duration;

use openssl::srtp::SrtpProfileId;
use openssl::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslStream, SslVerifyMode,
};
use tokio::net::UdpSocket;

use crate::cert::Identity;
use crate::transport::QueueIo;
use crate::DtlsError;
use srtp::Profile;

/// SRTP protection profile offers, in preference order.
#[derive(Debug, Clone)]
pub struct SrtpOffers {
    profiles: Vec<Profile>,
}

impl SrtpOffers {
    /// The classic WebRTC offer.
    pub fn default_offer() -> Self {
        SrtpOffers {
            profiles: vec![
                Profile::AeadAes128Gcm,
                Profile::AeadAes256Gcm,
                Profile::AesCm128Sha1_80,
            ],
        }
    }

    pub fn from_profiles(profiles: Vec<Profile>) -> Self {
        SrtpOffers { profiles }
    }

    fn openssl_names(&self) -> String {
        self.profiles
            .iter()
            .filter_map(|p| p.dtls_name())
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Negotiated SRTP keying material (RFC 5764 §4.2).
#[derive(Debug, Clone)]
pub struct SrtpKeying {
    /// The negotiated profile.
    pub profile: Profile,
    /// `(key, salt)` the CLIENT uses to protect packets it sends.
    pub client: (Vec<u8>, Vec<u8>),
    /// `(key, salt)` the SERVER uses to protect packets it sends.
    pub server: (Vec<u8>, Vec<u8>),
}

impl SrtpKeying {
    /// Build the local outbound SRTP session and remote inbound session for
    /// the given role.
    pub fn sessions(
        &self,
        client_role: bool,
    ) -> Result<(srtp::SrtpSession, srtp::SrtpSession), DtlsError> {
        let (out_key, out_salt) = if client_role {
            &self.client
        } else {
            &self.server
        };
        let (in_key, in_salt) = if client_role {
            &self.server
        } else {
            &self.client
        };
        let out = srtp::SrtpSession::new(self.profile, out_key, out_salt)
            .map_err(|e| DtlsError::KeyExport(e.to_string()))?;
        let inp = srtp::SrtpSession::new(self.profile, in_key, in_salt)
            .map_err(|e| DtlsError::KeyExport(e.to_string()))?;
        Ok((out, inp))
    }
}

/// Which end of the DTLS association this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    /// Sends ClientHello.
    Client,
    /// Waits for ClientHello.
    Server,
}

/// Handshake outcome of a single state-machine step.
enum Progress {
    Complete,
    WantData,
}

/// One end of a DTLS-SRTP association.
pub struct DtlsEndpoint {
    identity: Identity,
    role: DtlsRole,
    stream: SslStream<QueueIo>,
    expected_peer_fingerprint: Option<String>,
    /// Last flight we sent, for timer retransmission.
    last_flight: Vec<Vec<u8>>,
}

impl DtlsEndpoint {
    /// Create an endpoint with a fresh or supplied identity.
    pub fn new(identity: Identity, role: DtlsRole, offers: SrtpOffers) -> Result<Self, DtlsError> {
        let ctx = build_context(&identity, &offers, role)?;
        let mut ssl = Ssl::new(&ctx)?;
        ssl.set_mtu(1200)?;
        match role {
            DtlsRole::Client => ssl.set_connect_state(),
            DtlsRole::Server => ssl.set_accept_state(),
        }
        let io = QueueIo::new();
        let stream = SslStream::new(ssl, io)?;
        Ok(DtlsEndpoint {
            identity,
            role,
            stream,
            expected_peer_fingerprint: None,
            last_flight: Vec::new(),
        })
    }

    /// Pin the peer certificate fingerprint (from the SDP `a=fingerprint`).
    ///
    /// The handshake fails if the peer presents a different certificate.
    pub fn pin_peer_fingerprint(&mut self, fingerprint: impl Into<String>) {
        self.expected_peer_fingerprint = Some(fingerprint.into());
    }

    /// Local identity fingerprint for the SDP answer/offer.
    pub fn fingerprint(&self) -> &str {
        self.identity.fingerprint()
    }

    /// Queue a datagram received from the network into the state machine.
    pub fn push_datagram(&mut self, datagram: Vec<u8>) {
        self.stream.get_mut().push_inbound(datagram);
    }

    /// Take the datagrams the state machine wants to send right now,
    /// remembering them as the current flight.
    pub fn take_outbound(&mut self) -> Vec<Vec<u8>> {
        let flight = self.stream.get_mut().drain_outbound();
        if !flight.is_empty() {
            self.last_flight = flight.clone();
        }
        flight
    }

    /// Retransmit state: the datagrams of the most recent flight.
    pub fn current_flight(&self) -> &[Vec<u8>] {
        &self.last_flight
    }

    /// Advance the handshake state machine once.
    fn step(&mut self) -> Result<Progress, DtlsError> {
        match self.stream.do_handshake() {
            Ok(()) => Ok(Progress::Complete),
            Err(e) => match e.code() {
                openssl::ssl::ErrorCode::WANT_READ => Ok(Progress::WantData),
                openssl::ssl::ErrorCode::WANT_WRITE => Ok(Progress::WantData),
                _ => Err(DtlsError::Handshake(format!("{e}"))),
            },
        }
    }

    /// Public single-step driver for custom event loops: returns `true`
    /// when the handshake has completed.  Call [`Self::take_outbound`]
    /// after each step and deliver incoming datagrams via
    /// [`Self::push_datagram`].
    pub fn drive_once(&mut self) -> Result<bool, DtlsError> {
        match self.step()? {
            Progress::Complete => {
                self.finish()?;
                Ok(true)
            }
            Progress::WantData => Ok(false),
        }
    }

    /// Run the whole handshake over a UDP socket, with flight
    /// retransmission on timeout.
    ///
    /// `packets_from_peer` is called for datagrams that are not DTLS
    /// records (e.g. STUN binding requests arriving concurrently).
    pub async fn handshake_udp<F>(
        &mut self,
        socket: &mut UdpSocket,
        peer: SocketAddr,
        mut packets_from_peer: F,
    ) -> Result<(), DtlsError>
    where
        F: FnMut(Vec<u8>, SocketAddr) + Send,
    {
        let mut timeout = Duration::from_millis(50);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let buf = &mut [0u8; 2048];
        loop {
            match self.step()? {
                Progress::Complete => {
                    // The state machine wrote its final flight (server
                    // CCS+Finished) — flush it before returning, otherwise
                    // the peer is left waiting and times out.
                    for datagram in self.take_outbound() {
                        let _ = socket.send_to(&datagram, peer).await;
                    }
                    return self.finish();
                }
                Progress::WantData => {}
            }
            if std::time::Instant::now() > deadline {
                return Err(DtlsError::Handshake("handshake timed out".into()));
            }

            // Send whatever the state machine produced.
            for datagram in self.take_outbound() {
                let _ = socket.send_to(&datagram, peer).await;
            }

            // Await an inbound datagram or the retransmission timer.
            let mut received = false;
            tokio::select! {
                r = socket.recv_from(buf) => {
                    match r {
                        Ok((n, from)) if from == peer => {
                            self.push_datagram(buf[..n].to_vec());
                            received = true;
                        }
                        Ok((n, from)) => packets_from_peer(buf[..n].to_vec(), from),
                        Err(e) => return Err(DtlsError::Io(e.to_string())),
                    }
                }
                _ = tokio::time::sleep(timeout) => {}
            }

            if received {
                timeout = Duration::from_millis(50);
            } else {
                // Retransmit the current flight (RFC 6347 §4.2.4) with
                // exponential backoff capped at 2 s.
                for datagram in &self.last_flight {
                    let _ = socket.send_to(datagram, peer).await;
                }
                timeout = (timeout * 2).min(Duration::from_secs(2));
            }
        }
    }

    /// Post-handshake validation and keying export.
    fn finish(&mut self) -> Result<(), DtlsError> {
        if let Some(expected) = &self.expected_peer_fingerprint {
            if let Some(cert) = self.stream.ssl().peer_certificate() {
                if !crate::cert::fingerprint_matches(&cert, expected) {
                    return Err(DtlsError::FingerprintMismatch(expected.clone()));
                }
            } else {
                return Err(DtlsError::Handshake("no peer certificate".into()));
            }
        }
        Ok(())
    }

    /// The negotiated SRTP profile.
    pub fn negotiated_profile(&self) -> Result<Profile, DtlsError> {
        let profile = self
            .stream
            .ssl()
            .selected_srtp_profile()
            .ok_or_else(|| DtlsError::KeyExport("no SRTP profile negotiated".into()))?;
        let name = profile.name();
        Profile::from_dtls_name(name)
            .ok_or_else(|| DtlsError::KeyExport(format!("unknown profile {name}")))
    }

    /// Export the RFC 5764 §4.2 SRTP keying material.
    pub fn export_srtp_keys(&self) -> Result<SrtpKeying, DtlsError> {
        let profile = self.negotiated_profile()?;
        let (key_len, salt_len) = (profile.key_len(), profile.salt_len());
        let mut material = vec![0u8; 2 * (key_len + salt_len)];
        self.stream
            .ssl()
            .export_keying_material(
                &mut material,
                "EXTRACTOR-dtls_srtp",
                // RFC 5764 §4.2: the extractor is invoked WITHOUT a context
                // (use_context = 0). Any context bytes change the PRF seed
                // and break interop with every compliant WebRTC stack.
                None,
            )
            .map_err(|e| DtlsError::KeyExport(e.to_string()))?;

        let client_key = material[..key_len].to_vec();
        let server_key = material[key_len..2 * key_len].to_vec();
        let client_salt = material[2 * key_len..2 * key_len + salt_len].to_vec();
        let server_salt = material[2 * key_len + salt_len..].to_vec();
        Ok(SrtpKeying {
            profile,
            client: (client_key, client_salt),
            server: (server_key, server_salt),
        })
    }

    /// SHA-256 fingerprint of the peer certificate (for audit logs).
    pub fn peer_fingerprint(&self) -> Option<String> {
        self.stream
            .ssl()
            .peer_certificate()
            .and_then(|c| crate::cert::fingerprint_of(&c).ok())
    }

    /// Role of this endpoint.
    pub fn role(&self) -> DtlsRole {
        self.role
    }

    /// Identity used by this endpoint.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

fn build_context(
    identity: &Identity,
    offers: &SrtpOffers,
    role: DtlsRole,
) -> Result<SslContext, DtlsError> {
    let mut builder = SslContextBuilder::new(SslMethod::dtls())?;
    builder.set_certificate(identity.certificate())?;
    builder.set_private_key(identity.key())?;
    builder.check_private_key()?;
    // WebRTC presents certificates on BOTH sides; the server must send a
    // CertificateRequest so the client's certificate arrives.  Chain
    // validation is delegated to RFC 8122 fingerprint pinning, hence the
    // always-accept callback.
    if role == DtlsRole::Server {
        builder.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            |_preverified, _ctx| true,
        );
    } else {
        builder.set_verify(SslVerifyMode::NONE);
    }
    builder.set_tlsext_use_srtp(&offers.openssl_names())?;
    builder.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")?;
    let mut options = SslOptions::empty();
    // DTLS 1.2 only (WebRTC baseline; DTLS 1.0 is deprecated).
    options.insert(SslOptions::NO_DTLSV1);
    options.insert(SslOptions::CIPHER_SERVER_PREFERENCE);
    builder.set_options(options);
    Ok(builder.build())
}

/// Map an OpenSSL `SrtpProfileId` back to our profile enum.
pub fn profile_from_openssl_id(id: SrtpProfileId) -> Option<Profile> {
    match id.as_raw() {
        x if x == SrtpProfileId::SRTP_AES128_CM_SHA1_80.as_raw() => Some(Profile::AesCm128Sha1_80),
        x if x == SrtpProfileId::SRTP_AES128_CM_SHA1_32.as_raw() => Some(Profile::AesCm128Sha1_32),
        x if x == SrtpProfileId::SRTP_AEAD_AES_128_GCM.as_raw() => Some(Profile::AeadAes128Gcm),
        x if x == SrtpProfileId::SRTP_AEAD_AES_256_GCM.as_raw() => Some(Profile::AeadAes256Gcm),
        _ => None,
    }
}
