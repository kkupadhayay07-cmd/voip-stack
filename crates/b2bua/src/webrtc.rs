//! WebRTC media transport for one B2BUA leg: ICE (RFC 8445) → DTLS-SRTP
//! (RFC 5763/5764) → SRTP (RFC 3711) over the leg's UDP socket.
//!
//! Lifecycle on an inbound offer (we are the ANSWERER):
//!
//! 1. [`WebRtcMedia::prepare`] — gather a host candidate, adopt the peer's
//!    ICE credentials/candidates and DTLS fingerprint from the offer, and
//!    build our DTLS endpoint as the CLIENT (we answer `setup:active`,
//!    RFC 5763 §5 — the answerer must be active and may not start DTLS
//!    until ICE completes).
//! 2. The answer carries [`AnswerTransport`] (credentials, candidate lines,
//!    fingerprint) back to the peer inside the 200 OK.
//! 3. [`WebRtcMedia::establish`] — run ICE connectivity checks, then the
//!    DTLS handshake over the selected pair, then export the RFC 5764 §4.2
//!    keying material into the pump's SRTP sessions.
//!
//! RFC 7983 demultiplexing on the selected socket: STUN (0–3) is consumed
//! by ICE, DTLS (20–63) by the handshake, and everything in the RTP/RTCP
//! range (128–191) is SRTP after keying.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dtls::{DtlsEndpoint, DtlsRole, SrtpOffers};
use ice::agent::{AgentConfig, IceAgent};
use ice::candidate::{Candidate, IceError};
use sdp::types::MediaDescription;
use tokio::net::UdpSocket;

use crate::media::CryptoPair;

/// Default ICE connectivity-check budget.
pub const ICE_TIMEOUT: Duration = Duration::from_secs(5);
/// Default DTLS handshake budget (flight retransmission included).
pub const DTLS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum WebRtcError {
    #[error("offer lacks ICE credentials (a=ice-ufrag/pwd)")]
    NoIceCreds,
    #[error("offer lacks a DTLS fingerprint (a=fingerprint)")]
    NoFingerprint,
    #[error("unsupported fingerprint hash {0:?} (only sha-256)")]
    UnsupportedHash(String),
    #[error("no usable ICE candidate in offer")]
    NoCandidates,
    #[error("ice: {0}")]
    Ice(String),
    #[error("dtls: {0}")]
    Dtls(#[from] dtls::DtlsError),
}

impl From<IceError> for WebRtcError {
    fn from(e: IceError) -> Self {
        WebRtcError::Ice(e.to_string())
    }
}

/// What the SDP answer must carry for this leg's WebRTC transport.
#[derive(Debug, Clone)]
pub struct AnswerTransport {
    pub ufrag: String,
    pub pwd: String,
    /// Our certificate fingerprint, `sha-256 XX:XX:…` form.
    pub fingerprint: String,
    /// Our candidate lines in RFC 8839 SDP form (without the `a=` prefix).
    pub candidates: Vec<String>,
}

/// A prepared-but-not-yet-connected WebRTC transport for one leg.
pub struct WebRtcMedia {
    agent: IceAgent,
    dtls: DtlsEndpoint,
}

/// An established transport: pump-ready socket + SRTP sessions.
pub struct EstablishedMedia {
    /// The remote address ICE nominated (the pump's send target).
    pub remote: SocketAddr,
    /// The leg socket (the ICE agent's), post-handshake.
    pub socket: Arc<UdpSocket>,
    /// SRTP sessions keyed from the DTLS handshake (we were the DTLS
    /// client, so the client key material protects our outbound stream).
    pub crypto: CryptoPair,
}

impl WebRtcMedia {
    /// Prepare the transport from an inbound offer's first media
    /// description.  Gathers one host candidate and pins the peer
    /// fingerprint from the offer (the DTLS handshake fails on mismatch).
    pub async fn prepare(offer_media: &MediaDescription) -> Result<Self, WebRtcError> {
        let ufrag = offer_media
            .ice_ufrag
            .clone()
            .ok_or(WebRtcError::NoIceCreds)?;
        let pwd = offer_media.ice_pwd.clone().ok_or(WebRtcError::NoIceCreds)?;
        let fp = offer_media
            .fingerprint
            .as_ref()
            .ok_or(WebRtcError::NoFingerprint)?;
        if fp.hash_func != "sha-256" {
            return Err(WebRtcError::UnsupportedHash(fp.hash_func.clone()));
        }
        let mut candidates = Vec::new();
        for line in &offer_media.ice_candidates {
            // Foreign candidate syntaxes (trickle placeholders, exotic
            // extensions) are skipped, not fatal — one usable address is
            // all ICE needs.
            if let Ok(c) = Candidate::from_sdp(line) {
                candidates.push(c);
            }
        }
        if candidates.is_empty() {
            return Err(WebRtcError::NoCandidates);
        }

        // The answerer runs as the controlled agent: the offerer drives
        // nomination with USE-CANDIDATE (and our checks re-issue on a timer,
        // so the reverse case would also converge).
        let mut agent = IceAgent::new(AgentConfig {
            controlling: Some(false),
            ..AgentConfig::default()
        })
        .await?;
        agent.gather_host()?;
        agent.set_remote(&ufrag, &pwd, &candidates);

        // We answer `setup:active` → DTLS client (RFC 5763 §5).
        let mut dtls = DtlsEndpoint::new(
            dtls::Identity::generate("b2bua-webrtc")?,
            DtlsRole::Client,
            SrtpOffers::default_offer(),
        )?;
        dtls.pin_peer_fingerprint(format!("{} {}", fp.hash_func, fp.value));
        Ok(WebRtcMedia { agent, dtls })
    }

    /// Credentials/candidates/fingerprint for the SDP answer.
    pub fn answer_transport(&self) -> AnswerTransport {
        AnswerTransport {
            ufrag: self.agent.local_ufrag().to_string(),
            pwd: self.agent.local_pwd().to_string(),
            fingerprint: self.dtls.fingerprint().to_string(),
            candidates: self.agent.local_candidates_sdp(),
        }
    }

    /// The port our candidate advertises (the agent socket's bound port).
    pub fn local_port(&self) -> Result<u16, WebRtcError> {
        Ok(self.agent.local_addr()?.port())
    }

    /// Run ICE checks, then the DTLS handshake over the nominated pair,
    /// then export the SRTP keying.  Must run only AFTER the answer
    /// carrying our candidates has been sent (the peer cannot validate our
    /// checks before it has the SDP).
    pub async fn establish(mut self) -> Result<EstablishedMedia, WebRtcError> {
        let pair = self.agent.connect(ICE_TIMEOUT).await?;

        // DTLS on the selected pair.  Stray datagrams (late STUN keepalives)
        // are dropped: connectivity is already established.  We own the
        // socket from here — the pump inherits it via Arc.
        let mut socket = self.agent.into_socket();
        let remote = pair.remote;
        tokio::time::timeout(DTLS_TIMEOUT, async {
            self.dtls
                .handshake_udp(&mut socket, remote, |_, _| {})
                .await
        })
        .await
        .map_err(|_| dtls::DtlsError::Handshake("dtls handshake timed out".into()))??;

        // We are the DTLS client: the client key material protects what WE
        // send, the server material protects what we receive.
        let keying = self.dtls.export_srtp_keys()?;
        let (tx, rx) = keying.sessions(true)?;
        Ok(EstablishedMedia {
            remote,
            socket: Arc::new(socket),
            crypto: CryptoPair { tx, rx },
        })
    }
}
