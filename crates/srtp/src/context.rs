//! SRTP/SRTCP session contexts: packet protection, ROC handling and
//! per-SSRC stream state.
//!
//! Implements [RFC 3711] (AES-CM + HMAC-SHA1) and [RFC 7714] (AES-GCM AEAD)
//! over raw packet buffers so it composes with any RTP/RTCP serializer.
//!
//! [RFC 3711]: https://datatracker.ietf.org/doc/html/rfc3711
//! [RFC 7714]: https://datatracker.ietf.org/doc/html/rfc7714

use std::collections::HashMap;

use crate::aes_cm::xor_keystream;
use crate::kdf::{self, Label};
use crate::replay::ReplayWindow;
use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Cryptographic profile of an SRTP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// `AES_CM_128_HMAC_SHA1_80` — RFC 3711 default, 80-bit auth tag.
    AesCm128Sha1_80,
    /// `AES_CM_128_HMAC_SHA1_32` — RFC 3711, 32-bit auth tag.
    AesCm128Sha1_32,
    /// `AEAD_AES_128_GCM` — RFC 7714, 128-bit tag.
    AeadAes128Gcm,
    /// `AEAD_AES_256_GCM` — RFC 7714, 128-bit tag.
    AeadAes256Gcm,
    /// `AEAD_AES_128_GCM` with the 96-bit tag variant.
    AeadAes128Gcm12,
    /// `AEAD_AES_256_GCM` with the 96-bit tag variant.
    AeadAes256Gcm12,
}

impl Profile {
    /// Master key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Profile::AesCm128Sha1_80
            | Profile::AesCm128Sha1_32
            | Profile::AeadAes128Gcm
            | Profile::AeadAes128Gcm12 => 16,
            Profile::AeadAes256Gcm | Profile::AeadAes256Gcm12 => 32,
        }
    }

    /// Master salt length in bytes (112 bits for AES-CM, 96 bits for GCM).
    pub fn salt_len(self) -> usize {
        match self {
            Profile::AesCm128Sha1_80 | Profile::AesCm128Sha1_32 => 14,
            _ => 12,
        }
    }

    /// Authentication tag length appended to protected packets in bytes.
    pub fn tag_len(self) -> usize {
        match self {
            Profile::AesCm128Sha1_80 => 10,
            Profile::AesCm128Sha1_32 => 4,
            Profile::AeadAes128Gcm | Profile::AeadAes256Gcm => 16,
            Profile::AeadAes128Gcm12 | Profile::AeadAes256Gcm12 => 12,
        }
    }

    /// True when the profile is an AEAD (AES-GCM) transform.
    pub fn is_aead(self) -> bool {
        !matches!(self, Profile::AesCm128Sha1_80 | Profile::AesCm128Sha1_32)
    }

    /// DTLS-SRTP `srtp_protection_profile` name ([RFC 5764 §4.1.2] and
    /// [RFC 7714 §4.1.2]) used when negotiating this profile.
    ///
    /// [RFC 5764 §4.1.2]: https://datatracker.ietf.org/doc/html/rfc5764#section-4.1.2
    /// [RFC 7714 §4.1.2]: https://datatracker.ietf.org/doc/html/rfc7714#section-4.1.2
    pub fn dtls_name(self) -> Option<&'static str> {
        match self {
            Profile::AesCm128Sha1_80 => Some("SRTP_AES128_CM_SHA1_80"),
            Profile::AesCm128Sha1_32 => Some("SRTP_AES128_CM_SHA1_32"),
            Profile::AeadAes128Gcm => Some("SRTP_AEAD_AES_128_GCM"),
            Profile::AeadAes256Gcm => Some("SRTP_AEAD_AES_256_GCM"),
            _ => None,
        }
    }

    /// Reverse lookup of [`Profile::dtls_name`].
    pub fn from_dtls_name(name: &str) -> Option<Self> {
        match name {
            "SRTP_AES128_CM_SHA1_80" => Some(Profile::AesCm128Sha1_80),
            "SRTP_AES128_CM_SHA1_32" => Some(Profile::AesCm128Sha1_32),
            "SRTP_AEAD_AES_128_GCM" => Some(Profile::AeadAes128Gcm),
            "SRTP_AEAD_AES_256_GCM" => Some(Profile::AeadAes256Gcm),
            _ => None,
        }
    }
}

/// Errors produced while protecting or unprotecting packets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SrtpError {
    /// Buffer too small to be a valid SRTP/SRTCP packet.
    #[error("packet too short ({got} bytes)")]
    TooShort { got: usize },
    /// RTP version field must be 2.
    #[error("invalid RTP version {0}")]
    BadVersion(u8),
    /// Malformed RTP header or extension.
    #[error("malformed RTP header: {0}")]
    BadRtpHeader(&'static str),
    /// RTCP packet shorter than the 8-byte fixed header.
    #[error("malformed RTCP packet")]
    BadRtcp,
    /// Authentication tag mismatch (or GCM tag failure).
    #[error("authentication failed")]
    AuthFailed,
    /// Packet index already seen inside the replay window.
    #[error("replayed packet")]
    Replayed,
    /// Master key / salt length does not match the negotiated profile.
    #[error("bad master keying material: {0}")]
    BadKeying(String),
    /// Underlying crypto failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// SRTCP index exhausted (2^31 packets per session).
    #[error("SRTCP index exhausted")]
    IndexExhausted,
}

fn bad_keying(what: &str, got: usize, want: usize) -> SrtpError {
    SrtpError::BadKeying(format!("{what}: got {got} bytes, want {want}"))
}

/// Constant-time equality for tag comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 20];
    tag.copy_from_slice(&out);
    tag
}

// ---------------------------------------------------------------------------
// Packet index / ROC handling (RFC 3711 §3.3.1 and Appendix A)
// ---------------------------------------------------------------------------

/// Estimate the 48-bit packet index for a received sequence number.
///
/// Returns `(index, v)` where `v` is the candidate rollover counter per the
/// pseudocode in RFC 3711 Appendix A (which notes "signed arithmetic is
/// assumed": a small backwards step inside the sequence space stays in the
/// current ROC, a large one belongs to ROC-1).
fn estimate_index(s_l: u16, roc: u32, seq: u16) -> (u64, u32) {
    let v = if s_l < 32768 {
        let diff = (seq as i32) - (s_l as i32);
        if diff > 32768 {
            roc.wrapping_sub(1)
        } else {
            roc
        }
    } else if (s_l as i32) - 32768 > seq as i32 {
        roc.wrapping_add(1)
    } else {
        roc
    };
    let index = ((v as u64) << 16) | seq as u64;
    (index, v)
}

/// Sender-side ROC advancement: when the sequence number moves backwards by
/// more than half the sequence space, the sender's u16 counter wrapped.
fn sender_roc(last_seq: u16, seq: u16, roc: u32) -> u32 {
    if seq < last_seq && last_seq.wrapping_sub(seq) > 0x8000 {
        roc.wrapping_add(1)
    } else {
        roc
    }
}

// ---------------------------------------------------------------------------
// IV construction
// ---------------------------------------------------------------------------

/// AES-CM packet IV (RFC 3711 §4.1.1):
/// `IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)`.
fn cm_iv(salt: &[u8], ssrc: u32, index: u64) -> [u8; 16] {
    debug_assert!(salt.len() == 14);
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(salt);
    for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
        iv[4 + i] ^= b;
    }
    let ib = (index & 0xFFFF_FFFF_FFFF).to_be_bytes();
    for (i, b) in ib[2..].iter().enumerate() {
        iv[8 + i] ^= b;
    }
    iv
}

/// AES-GCM SRTP IV (RFC 7714 §8.1):
/// `IV = salt XOR (0x0000 || SSRC || ROC || SEQ)`.
fn gcm_rtp_iv(salt: &[u8], ssrc: u32, roc: u32, seq: u16) -> [u8; 12] {
    debug_assert!(salt.len() == 12);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(salt);
    let r: [u8; 12] = [
        0,
        0,
        (ssrc >> 24) as u8,
        (ssrc >> 16) as u8,
        (ssrc >> 8) as u8,
        ssrc as u8,
        (roc >> 24) as u8,
        (roc >> 16) as u8,
        (roc >> 8) as u8,
        roc as u8,
        (seq >> 8) as u8,
        seq as u8,
    ];
    for (dst, src) in iv.iter_mut().zip(r.iter()) {
        *dst ^= src;
    }
    iv
}

/// AES-GCM SRTCP IV (RFC 7714 §9.1):
/// `IV = salt XOR (0x0000 || SSRC || 0x0000 || 0 || SRTCP-index)`.
fn gcm_rtcp_iv(salt: &[u8], ssrc: u32, index: u32) -> [u8; 12] {
    debug_assert!(salt.len() == 12);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(salt);
    let idx = index & 0x7FFF_FFFF;
    let r: [u8; 12] = [
        0,
        0,
        (ssrc >> 24) as u8,
        (ssrc >> 16) as u8,
        (ssrc >> 8) as u8,
        ssrc as u8,
        0,
        0,
        (idx >> 24) as u8,
        (idx >> 16) as u8,
        (idx >> 8) as u8,
        idx as u8,
    ];
    for (dst, src) in iv.iter_mut().zip(r.iter()) {
        *dst ^= src;
    }
    iv
}

// ---------------------------------------------------------------------------
// AES-GCM wrapper (RFC 7714)
// ---------------------------------------------------------------------------

use aes::Aes128;
use aes::Aes256;
use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::KeyInit;
use aes_gcm::AesGcm;
use aes_gcm::Nonce;

type Aes128Gcm16 = AesGcm<Aes128, U12, U16>;
type Aes256Gcm16 = AesGcm<Aes256, U12, U16>;
type Aes128Gcm12 = AesGcm<Aes128, U12, U12>;
type Aes256Gcm12 = AesGcm<Aes256, U12, U12>;

enum Gcm {
    A128(Box<Aes128Gcm16>),
    A256(Box<Aes256Gcm16>),
    A128t12(Box<Aes128Gcm12>),
    A256t12(Box<Aes256Gcm12>),
}

impl Gcm {
    fn new(key: &[u8], tag_len: usize) -> Result<Gcm, SrtpError> {
        match (key.len(), tag_len) {
            (16, 16) => Ok(Gcm::A128(Box::new(
                AesGcm::<Aes128, U12, U16>::new_from_slice(key)
                    .map_err(|e| SrtpError::Crypto(e.to_string()))?,
            ))),
            (32, 16) => Ok(Gcm::A256(Box::new(
                AesGcm::<Aes256, U12, U16>::new_from_slice(key)
                    .map_err(|e| SrtpError::Crypto(e.to_string()))?,
            ))),
            (16, 12) => Ok(Gcm::A128t12(Box::new(
                AesGcm::<Aes128, U12, U12>::new_from_slice(key)
                    .map_err(|e| SrtpError::Crypto(e.to_string()))?,
            ))),
            (32, 12) => Ok(Gcm::A256t12(Box::new(
                AesGcm::<Aes256, U12, U12>::new_from_slice(key)
                    .map_err(|e| SrtpError::Crypto(e.to_string()))?,
            ))),
            (n, t) => Err(SrtpError::BadKeying(format!(
                "GCM key {n} bytes / tag {t} bytes not supported"
            ))),
        }
    }

    /// Encrypt `pt` with `aad`; returns ciphertext || tag.
    fn seal(&self, iv: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, SrtpError> {
        let mut buf = pt.to_vec();
        let res = match self {
            Gcm::A128(c) => c.encrypt_in_place(Nonce::from_slice(iv), aad, &mut buf),
            Gcm::A256(c) => c.encrypt_in_place(Nonce::from_slice(iv), aad, &mut buf),
            Gcm::A128t12(c) => c.encrypt_in_place(Nonce::from_slice(iv), aad, &mut buf),
            Gcm::A256t12(c) => c.encrypt_in_place(Nonce::from_slice(iv), aad, &mut buf),
        };
        res.map_err(|_| SrtpError::Crypto("GCM seal failed".into()))?;
        Ok(buf)
    }

    /// Verify and decrypt `ct_and_tag` with `aad`; returns the plaintext.
    fn open(&self, iv: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> Result<Vec<u8>, SrtpError> {
        let mut buf = ct_and_tag.to_vec();
        let res = match self {
            Gcm::A128(c) => c.decrypt_in_place(Nonce::from_slice(iv), aad, &mut buf),
            Gcm::A256(c) => c.decrypt_in_place(Nonce::from_slice(iv), aad, &mut buf),
            Gcm::A128t12(c) => c.decrypt_in_place(Nonce::from_slice(iv), aad, &mut buf),
            Gcm::A256t12(c) => c.decrypt_in_place(Nonce::from_slice(iv), aad, &mut buf),
        };
        res.map_err(|_| SrtpError::AuthFailed)?;
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// RTP header scanning
// ---------------------------------------------------------------------------

/// Length of the RTP fixed header + CSRC list + extension, i.e. the offset
/// of the payload.  (RFC 3550 §5.3.1; extension per RFC 8285 general form.)
fn rtp_header_len(buf: &[u8]) -> Result<usize, SrtpError> {
    if buf.len() < 12 {
        return Err(SrtpError::TooShort { got: buf.len() });
    }
    if buf[0] >> 6 != 2 {
        return Err(SrtpError::BadVersion(buf[0] >> 6));
    }
    let cc = (buf[0] & 0x0f) as usize;
    let mut len = 12 + 4 * cc;
    if buf[0] & 0x10 != 0 {
        // X bit set: 4-byte extension header with 16-bit length in words.
        if buf.len() < len + 4 {
            return Err(SrtpError::BadRtpHeader("truncated extension header"));
        }
        let ext_words = u16::from_be_bytes([buf[len + 2], buf[len + 3]]) as usize;
        len += 4 + 4 * ext_words;
    }
    if buf.len() < len {
        return Err(SrtpError::BadRtpHeader("extension overruns packet"));
    }
    Ok(len)
}

#[inline]
fn rtp_seq(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[2], buf[3]])
}

#[inline]
fn rtp_ssrc(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]])
}

// ---------------------------------------------------------------------------
// Stream state
// ---------------------------------------------------------------------------

struct SendStream {
    roc: u32,
    last_seq: Option<u16>,
    /// SRTCP only: next index to emit.
    rtcp_index: u32,
}

impl SendStream {
    fn new(roc: u32) -> Self {
        SendStream {
            roc,
            last_seq: None,
            rtcp_index: 0,
        }
    }
}

struct RecvStream {
    roc: u32,
    s_l: Option<u16>,
    last_index: u64,
    replay: ReplayWindow,
}

impl RecvStream {
    fn new(window_size: u64) -> Self {
        RecvStream {
            roc: 0,
            s_l: None,
            last_index: 0,
            replay: ReplayWindow::new(window_size),
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

struct SessionKeys {
    enc: Vec<u8>,
    auth: Vec<u8>,
    salt: Vec<u8>,
    gcm: Option<Gcm>,
}

/// A set of derived session keys for one stream (RTP or RTCP).
#[derive(Clone, Debug)]
pub struct SessionKeySet {
    /// Session encryption key (16/24/32 bytes depending on the profile).
    pub enc: Vec<u8>,
    /// Session authentication key (20 bytes of HMAC-SHA1 keying; empty for
    /// AEAD profiles).
    pub auth: Vec<u8>,
    /// Session salt (14 bytes for AES-CM, 12 bytes for AES-GCM).
    pub salt: Vec<u8>,
}

/// A bidirectional SRTP+SRTCP session derived from one master key/salt pair.
///
/// Mirrors libsrtp's "one context per direction-pair" model: the sender and
/// receiver sides of both RTP and RTCP share the master keying material but
/// keep independent per-SSRC stream state.
pub struct SrtpSession {
    profile: Profile,
    rtp: SessionKeys,
    rtcp: SessionKeys,
    /// Sender state for SRTP (ROC tracking per SSRC).
    send: HashMap<u32, SendStream>,
    /// Receiver state for SRTP (ROC + replay per SSRC).
    recv: HashMap<u32, RecvStream>,
    /// Sender state for SRTCP (31-bit index per SSRC).  RFC 3711 keeps
    /// SRTCP contexts separate from SRTP contexts.
    send_rtcp: HashMap<u32, SendStream>,
    /// Receiver state for SRTCP (replay per SSRC).
    recv_rtcp: HashMap<u32, RecvStream>,
    window_size: u64,
}

impl SrtpSession {
    /// Build a session from master keying material (e.g. exported from a
    /// DTLS-SRTP handshake), performing the mandatory initial key derivation
    /// with `key_derivation_rate = 0` (RFC 3711 §4.3.1).
    pub fn new(profile: Profile, master_key: &[u8], master_salt: &[u8]) -> Result<Self, SrtpError> {
        if master_key.len() != profile.key_len() {
            return Err(bad_keying(
                "master key",
                master_key.len(),
                profile.key_len(),
            ));
        }
        if master_salt.len() != profile.salt_len() {
            return Err(bad_keying(
                "master salt",
                master_salt.len(),
                profile.salt_len(),
            ));
        }

        let key_len = profile.key_len();
        let salt_len = profile.salt_len();
        let auth_len = if profile.is_aead() { 0 } else { 20 };

        let derive_set = |enc_label: Label,
                          auth_label: Label,
                          salt_label: Label|
         -> Result<SessionKeySet, SrtpError> {
            let mut enc = vec![0u8; key_len];
            kdf::derive(master_key, master_salt, enc_label, 0, 0, &mut enc)
                .map_err(|e| SrtpError::Crypto(e.to_string()))?;
            let mut auth = vec![0u8; auth_len];
            if auth_len > 0 {
                kdf::derive(master_key, master_salt, auth_label, 0, 0, &mut auth)
                    .map_err(|e| SrtpError::Crypto(e.to_string()))?;
            }
            let mut salt = vec![0u8; salt_len];
            kdf::derive(master_key, master_salt, salt_label, 0, 0, &mut salt)
                .map_err(|e| SrtpError::Crypto(e.to_string()))?;
            Ok(SessionKeySet { enc, auth, salt })
        };

        let rtp = derive_set(Label::RtpEnc, Label::RtpAuth, Label::RtpSalt)?;
        let rtcp = derive_set(Label::RtcpEnc, Label::RtcpAuth, Label::RtcpSalt)?;
        Self::from_session_keys(profile, rtp, rtcp)
    }

    /// Build a session from already-derived session keys, bypassing the
    /// RFC 3711 key derivation.  Required for RFC 7714 §16-style conformance
    /// vectors and for consumers that obtain session keys directly.
    pub fn from_session_keys(
        profile: Profile,
        rtp: SessionKeySet,
        rtcp: SessionKeySet,
    ) -> Result<Self, SrtpError> {
        let gcm = if profile.is_aead() {
            Some(Gcm::new(&rtp.enc, profile.tag_len())?)
        } else {
            None
        };
        let rtcp_gcm = if profile.is_aead() {
            Some(Gcm::new(&rtcp.enc, profile.tag_len())?)
        } else {
            None
        };
        if !profile.is_aead() && (rtp.auth.len() != 20 || rtcp.auth.len() != 20) {
            return Err(bad_keying("auth key", rtp.auth.len(), 20));
        }

        Ok(SrtpSession {
            profile,
            rtp: SessionKeys {
                enc: rtp.enc,
                auth: rtp.auth,
                salt: rtp.salt,
                gcm,
            },
            rtcp: SessionKeys {
                enc: rtcp.enc,
                auth: rtcp.auth,
                salt: rtcp.salt,
                gcm: rtcp_gcm,
            },
            send: HashMap::new(),
            recv: HashMap::new(),
            send_rtcp: HashMap::new(),
            recv_rtcp: HashMap::new(),
            window_size: 64,
        })
    }

    /// Negotiated profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Set the replay window size (RFC 3711 §3.3.3 default 64; ≤ 64).
    pub fn set_window_size(&mut self, size: u64) {
        self.window_size = size.clamp(1, 64);
        for st in self.recv.values_mut() {
            st.replay = ReplayWindow::new(self.window_size);
        }
        for st in self.recv_rtcp.values_mut() {
            st.replay = ReplayWindow::new(self.window_size);
        }
    }

    /// Seed sender state for an SSRC (e.g. resuming after a restart).
    pub fn set_send_roc(&mut self, ssrc: u32, roc: u32) {
        self.send.insert(ssrc, SendStream::new(roc));
    }

    /// Seed receiver state for an SSRC.
    pub fn set_recv_roc(&mut self, ssrc: u32, roc: u32) {
        let st = self
            .recv
            .entry(ssrc)
            .or_insert_with(|| RecvStream::new(self.window_size));
        st.roc = roc;
        st.s_l = None;
    }

    // -- RTP ----------------------------------------------------------------

    /// Protect (encrypt + authenticate) an RTP packet in place.
    ///
    /// Returns the 48-bit packet index used for the IV.
    pub fn protect(&mut self, packet: &mut Vec<u8>) -> Result<u64, SrtpError> {
        let header_len = rtp_header_len(packet)?;
        let seq = rtp_seq(packet);
        let ssrc = rtp_ssrc(packet);

        let st = self.send.entry(ssrc).or_insert_with(|| SendStream::new(0));
        if let Some(last) = st.last_seq {
            st.roc = sender_roc(last, seq, st.roc);
        }
        st.last_seq = Some(seq);
        let roc = st.roc;
        let index = ((roc as u64) << 16) | seq as u64;

        match self.profile {
            Profile::AesCm128Sha1_80 | Profile::AesCm128Sha1_32 => {
                let iv = cm_iv(&self.rtp.salt, ssrc, index);
                xor_keystream(&self.rtp.enc, &iv, &mut packet[header_len..])
                    .map_err(|e| SrtpError::Crypto(e.to_string()))?;
                // RFC 3711 §3.1/§4.2: the Authenticated Portion covers the
                // whole packet (header + encrypted payload) plus the ROC.
                let tag = hmac_sha1(&self.rtp.auth, &[&packet[..], &roc.to_be_bytes()]);
                packet.extend_from_slice(&tag[..self.profile.tag_len()]);
            }
            _ => {
                let gcm = self
                    .rtp
                    .gcm
                    .as_ref()
                    .ok_or_else(|| SrtpError::Crypto("no GCM context".into()))?;
                let iv = gcm_rtp_iv(&self.rtp.salt, ssrc, roc, seq);
                let ct = gcm.seal(
                    &iv,
                    &packet[..header_len],
                    packet[header_len..].to_vec().as_slice(),
                )?;
                packet.truncate(header_len);
                packet.extend_from_slice(&ct);
            }
        }
        Ok(index)
    }

    /// Unprotect a received SRTP packet in place (verify tag, decrypt).
    ///
    /// Returns the 48-bit packet index.  Replay check happens before the
    /// costly authentication step; window state is only committed after the
    /// tag verifies, so failed forgeries never poison the stream.
    pub fn unprotect(&mut self, packet: &mut Vec<u8>) -> Result<u64, SrtpError> {
        let tag_len = self.profile.tag_len();
        if packet.len() < 12 + tag_len {
            return Err(SrtpError::TooShort { got: packet.len() });
        }
        let header_len = rtp_header_len(packet)?;
        if packet.len() < header_len + tag_len {
            return Err(SrtpError::TooShort { got: packet.len() });
        }
        let seq = rtp_seq(packet);
        let ssrc = rtp_ssrc(packet);

        // Stream lookup without allocating: per-SSRC state is committed only
        // after the tag verifies, so unauthenticated forgeries cannot grow
        // the receive map.
        let (index, v, replay_ok) = match self.recv.get_mut(&ssrc) {
            Some(st) => {
                let (index, v) = match st.s_l {
                    Some(s_l) => estimate_index(s_l, st.roc, seq),
                    None => (((st.roc as u64) << 16) | seq as u64, st.roc),
                };
                let ok = st.replay.check(index);
                (index, v, ok)
            }
            None => (seq as u64, 0u32, true),
        };

        // Replay pre-check (no state mutation yet).
        if !replay_ok {
            return Err(SrtpError::Replayed);
        }

        let tag_off = packet.len() - tag_len;
        let ok = match self.profile {
            Profile::AesCm128Sha1_80 | Profile::AesCm128Sha1_32 => {
                // RFC 3711 §4.2: the Authenticated Portion is the whole
                // packet (header + encrypted payload) followed by the ROC.
                let expected = hmac_sha1(&self.rtp.auth, &[&packet[..tag_off], &v.to_be_bytes()]);
                ct_eq(&packet[tag_off..], &expected[..tag_len])
            }
            _ => true, // GCM verifies during open()
        };
        if !ok {
            return Err(SrtpError::AuthFailed);
        }

        match self.profile {
            Profile::AesCm128Sha1_80 | Profile::AesCm128Sha1_32 => {
                let tag_off = packet.len() - tag_len;
                let iv = cm_iv(&self.rtp.salt, ssrc, index);
                xor_keystream(&self.rtp.enc, &iv, &mut packet[header_len..tag_off])
                    .map_err(|e| SrtpError::Crypto(e.to_string()))?;
                packet.truncate(tag_off);
            }
            _ => {
                let gcm = self
                    .rtp
                    .gcm
                    .as_ref()
                    .ok_or_else(|| SrtpError::Crypto("no GCM context".into()))?;
                let iv = gcm_rtp_iv(&self.rtp.salt, ssrc, v, seq);
                let aad = packet[..header_len].to_vec();
                let pt = gcm.open(&iv, &aad, &packet[header_len..])?;
                packet.truncate(header_len);
                packet.extend_from_slice(&pt);
            }
        }

        // Commit stream state only after full verification.
        let st = self
            .recv
            .entry(ssrc)
            .or_insert_with(|| RecvStream::new(self.window_size));
        st.replay.mark(index);
        if index >= st.last_index {
            st.last_index = index;
            st.roc = v;
            st.s_l = Some(seq);
        }
        Ok(index)
    }

    // -- RTCP ---------------------------------------------------------------

    /// Protect an RTCP compound packet in place (RFC 3711 §3.4 /
    /// RFC 7714 §9): everything after the first 8-byte header is encrypted,
    /// the E|index word and tag are appended.
    ///
    /// Returns the SRTCP index used.
    pub fn protect_rtcp(&mut self, packet: &mut Vec<u8>) -> Result<u32, SrtpError> {
        if packet.len() < 8 {
            return Err(SrtpError::BadRtcp);
        }
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let st = self
            .send_rtcp
            .entry(ssrc)
            .or_insert_with(|| SendStream::new(0));
        if st.rtcp_index >= 0x7FFF_FFFF {
            return Err(SrtpError::IndexExhausted);
        }
        let index = st.rtcp_index;
        st.rtcp_index = index + 1;
        let _ = &st;

        match self.profile {
            Profile::AesCm128Sha1_80 | Profile::AesCm128Sha1_32 => {
                let iv = cm_iv(&self.rtcp.salt, ssrc, index as u64);
                xor_keystream(&self.rtcp.enc, &iv, &mut packet[8..])
                    .map_err(|e| SrtpError::Crypto(e.to_string()))?;
                packet.extend_from_slice(&(0x8000_0000u32 | index).to_be_bytes());
                let tag_len = self.profile.tag_len();
                let mac_input_len = packet.len();
                let tag = hmac_sha1(&self.rtcp.auth, &[&packet[..mac_input_len]]);
                packet.extend_from_slice(&tag[..tag_len]);
            }
            _ => {
                let gcm = self
                    .rtcp
                    .gcm
                    .as_ref()
                    .ok_or_else(|| SrtpError::Crypto("no GCM context".into()))?;
                let iv = gcm_rtcp_iv(&self.rtcp.salt, ssrc, index);
                let header = packet[..8].to_vec();
                let flag = (0x8000_0000u32 | index).to_be_bytes();
                let mut aad = Vec::with_capacity(12);
                aad.extend_from_slice(&header);
                aad.extend_from_slice(&flag);
                let body = packet[8..].to_vec();
                let ct = gcm.seal(&iv, &aad, &body)?;
                packet.truncate(8);
                packet.extend_from_slice(&ct[..body.len()]);
                packet.extend_from_slice(&flag);
                packet.extend_from_slice(&ct[body.len()..]);
            }
        }
        Ok(index)
    }

    /// Unprotect a received SRTCP compound packet in place.
    ///
    /// Returns the SRTCP index.
    pub fn unprotect_rtcp(&mut self, packet: &mut Vec<u8>) -> Result<u32, SrtpError> {
        let tag_len = self.profile.tag_len();
        if packet.len() < 8 + 4 + tag_len {
            return Err(SrtpError::TooShort { got: packet.len() });
        }
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        let tag_off = packet.len() - tag_len;
        let flag_off = tag_off - 4;
        let flag = u32::from_be_bytes([
            packet[flag_off],
            packet[flag_off + 1],
            packet[flag_off + 2],
            packet[flag_off + 3],
        ]);
        let encrypted = flag >> 31 == 1;
        let index = flag & 0x7FFF_FFFF;

        // Stream lookup without allocating: state is committed only after
        // the tag verifies.
        let replay_ok = match self.recv_rtcp.get_mut(&ssrc) {
            Some(st) => st.replay.check(index as u64),
            None => true,
        };
        if !replay_ok {
            return Err(SrtpError::Replayed);
        }

        match self.profile {
            Profile::AesCm128Sha1_80 | Profile::AesCm128Sha1_32 => {
                let expected = hmac_sha1(&self.rtcp.auth, &[&packet[..tag_off]]);
                if !ct_eq(&packet[tag_off..], &expected[..tag_len]) {
                    return Err(SrtpError::AuthFailed);
                }
                if encrypted {
                    let iv = cm_iv(&self.rtcp.salt, ssrc, index as u64);
                    xor_keystream(&self.rtcp.enc, &iv, &mut packet[8..flag_off])
                        .map_err(|e| SrtpError::Crypto(e.to_string()))?;
                }
                packet.truncate(flag_off);
            }
            _ => {
                let gcm = self
                    .rtcp
                    .gcm
                    .as_ref()
                    .ok_or_else(|| SrtpError::Crypto("no GCM context".into()))?;
                let iv = gcm_rtcp_iv(&self.rtcp.salt, ssrc, index);
                let mut aad = Vec::with_capacity(12);
                aad.extend_from_slice(&packet[..8]);
                aad.extend_from_slice(&flag.to_be_bytes());
                if encrypted {
                    // ciphertext and tag are separated by the E|index word
                    let mut ct_tag = packet[8..flag_off].to_vec();
                    ct_tag.extend_from_slice(&packet[tag_off..]);
                    let pt = gcm.open(&iv, &aad, &ct_tag)?;
                    packet.truncate(8);
                    packet.extend_from_slice(&pt);
                } else {
                    // E=0: the whole packet is authenticated as AAD and the
                    // GCM tag sits alone at the end (RFC 7714 §9.3) — pass
                    // it as the tag-only "ciphertext" so open() verifies it.
                    aad.extend_from_slice(&packet[8..flag_off]);
                    gcm.open(&iv, &aad, &packet[tag_off..])?;
                }
            }
        }

        // Commit stream state only after full verification.
        let st = self
            .recv_rtcp
            .entry(ssrc)
            .or_insert_with(|| RecvStream::new(self.window_size));
        st.replay.mark(index as u64);
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtp_packet(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, 0];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0x1111_1111u32.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn estimate_index_appendix_a() {
        // s_l < 32768: seq just above → same ROC
        assert_eq!(estimate_index(1000, 5, 1001).0, (5u64 << 16) | 1001);
        // s_l < 32768: seq far above (tail of previous ROC)
        assert_eq!(estimate_index(1000, 5, 65500).0, (4u64 << 16) | 65500);
        // s_l < 32768: small backwards step stays in the same ROC (signed diff)
        assert_eq!(estimate_index(102, 0, 100).0, 100);
        // s_l >= 32768: seq far below → next ROC (wrap)
        assert_eq!(estimate_index(65000, 5, 10).0, (6u64 << 16) | 10);
        // s_l >= 32768: seq still close (same ROC)
        assert_eq!(estimate_index(65000, 5, 64000).0, (5u64 << 16) | 64000);
    }

    #[test]
    fn sender_roc_wrap() {
        assert_eq!(sender_roc(65534, 65535, 7), 7);
        assert_eq!(sender_roc(65535, 0, 7), 8);
        assert_eq!(sender_roc(65535, 3, 7), 8);
        assert_eq!(sender_roc(100, 65530, 7), 7); // forward jump, no wrap
        assert_eq!(sender_roc(100, 101, 7), 7);
        assert_eq!(sender_roc(0, 65535, 7), 7); // backwards small jump
    }

    #[test]
    fn rtp_header_len_scan() {
        let mut p = rtp_packet(1, 2, b"hello");
        assert_eq!(rtp_header_len(&p).unwrap(), 12);
        // with CSRC (inserted between the fixed header and the payload)
        p[0] = 0x81;
        p.splice(12..12, [0u8; 4]);
        assert_eq!(rtp_header_len(&p).unwrap(), 16);
        // with extension: 16 (base+CSRC) + 4 (ext header) + 8 (ext body) = 28
        p[0] = 0x91;
        p.splice(16..16, [0xBE, 0xDE, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(rtp_header_len(&p).unwrap(), 28);
    }

    #[test]
    fn bad_version_detected() {
        let mut p = rtp_packet(1, 2, b"x");
        p[0] = 0x40; // V=1
        assert_eq!(rtp_header_len(&p), Err(SrtpError::BadVersion(1)));
    }

    #[test]
    fn iv_construction_matches_rfc_7714_figure() {
        // RFC 7714 §16: SSRC 5501a0b2, ROC 0, SEQ f17b, salt "Quid pro quo"
        let salt = hex::decode("517569642070726f2071756f").unwrap();
        let iv = gcm_rtp_iv(&salt, 0x5501a0b2, 0, 0xf17b);
        assert_eq!(hex::encode(iv), "51753c6580c2726f20718414");
    }
}
