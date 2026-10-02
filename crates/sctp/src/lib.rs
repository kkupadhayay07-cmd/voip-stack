//! # sctp
//!
//! SCTP for WebRTC data channels — the protocol engine without a transport:
//!
//! - [RFC 9260]/[RFC 4960] core subset: common header with [RFC 3309] CRC32c,
//!   chunk codec (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK / DATA / SACK /
//!   HEARTBEAT / HEARTBEAT-ACK / ABORT / SHUTDOWN / SHUTDOWN-ACK /
//!   SHUTDOWN-COMPLETE / FORWARD-TSN), four-way handshake with a MAC-protected
//!   state cookie (server role), TSN window tracking, SACK generation with gap
//!   blocks and duplicate reports, T3-RTX retransmission with RFC 6298 RTO
//!   estimation (Karn's rule), congestion window slow start / congestion
//!   avoidance and peer `a_rwnd` flow control, message fragmentation and
//!   ordered/unordered reassembly
//! - [RFC 8832] Data Channel Establishment Protocol (DCEP):
//!   `DATA_CHANNEL_OPEN` / `DATA_CHANNEL_ACK` with all three reliability
//!   classes (reliable, max-retransmits, max-packet-lifetime) and the
//!   out-of-order flag; stream-id parity per §6 (association initiator odd,
//!   responder even)
//! - [RFC 3758] partial reliability: sender-side abandonment
//!   (max-retransmits *and* max-packet-lifetime) with FORWARD-TSN advance and
//!   receiver-side stream-sequence skipping
//!
//! The crate is transport-agnostic: it never touches sockets. Bytes in /
//! packets out through [`SctpEndpoint::handle_packet`] and
//! [`SctpEndpoint::drain_outbound`]; encapsulation is the caller's job —
//! over DTLS that is exactly the [RFC 8261] rule (an SCTP packet is the whole
//! DTLS application payload, no extra header).
//!
//! # Wire-form testing policy
//!
//! Every codec path is pinned by hand-built byte vectors (not self-roundtrips)
//! and the CRC32c by published check values, so the engine cannot drift into
//! being self-consistent with a wrong wire form (the Task 43 lesson).
//!
//! # Deliberate gaps (documented)
//!
//! - No multi-homing (WebRTC is single-path; one destination per association)
//! - ECNE/CWR chunks are skipped, not interpreted (ECN is not negotiated)
//! - No SCTP restart, no dynamic address reconfiguration (RFC 5061), no
//!   stream reset (RFC 6525) — a closing data channel currently leaves its
//!   stream id consumed (matches DCEP's own lifetime model)
//! - The SACK delay timer is not implemented: every DATA-bearing packet is
//!   SACKed immediately (RFC 9260 allows "MAY" delay)
//! - No RFC 8260 stream schedulers / interleaving (the I-bit is parsed and
//!   treated as unordered-classic)
//! - No fast retransmit on gap-acks (loss recovery waits for T3-RTX), and no
//!   zero-window probe (a fully exhausted peer a_rwnd needs SACK movement to
//!   resume)
//! - An inbound user message larger than `max_message_size` aborts the
//!   association (RFC 9260 allows a graceful discard instead)
//! - DCEP ACK chunks and FORWARD-TSN trailing bytes are parsed strictly
//!   (no lenience for non-minimal encodings), and [`SctpEndpoint::shutdown`]
//!   does not flush messages that were never sent (the caller drains first)
//!
//! [RFC 9260]: https://datatracker.ietf.org/doc/html/rfc9260
//! [RFC 4960]: https://datatracker.ietf.org/doc/html/rfc4960
//! [RFC 3309]: https://datatracker.ietf.org/doc/html/rfc3309
//! [RFC 8832]: https://datatracker.ietf.org/doc/html/rfc8832
//! [RFC 3758]: https://datatracker.ietf.org/doc/html/rfc3758
//! [RFC 8261]: https://datatracker.ietf.org/doc/html/rfc8261

#![forbid(unsafe_code)]

pub mod assoc;
pub mod crc32c;
pub mod dcep;
pub mod wire;

use std::time::Duration;

pub use assoc::{AssociationStats, SctpEndpoint, MAX_INIT_RETRANS};
pub use dcep::ChannelType;
pub use wire::{SackBlock, SctpError};

/// Endpoint configuration (transport-agnostic).
#[derive(Debug, Clone)]
pub struct SctpConfig {
    /// Association initiator (sent the INIT) when true. Governs stream-id
    /// parity for outbound data channels (odd) per RFC 8832 §6.
    pub is_client: bool,
    pub local_port: u16,
    pub remote_port: u16,
    /// Path MTU in bytes — DTLS-encapsulated associations must leave room for
    /// the DTLS/IP overhead (1200 is the WebRTC-blessed default).
    pub mtu: usize,
    /// Out-of-order receive buffer, in chunks (bounded memory; anything
    /// beyond is dropped and reported as a duplicate). Clamped to 65535 at
    /// endpoint creation — SACK gap-block offsets are u16.
    pub recv_window_chunks: u32,
    /// Send buffer bound, in chunks. A send that would exceed it is rejected
    /// with [`SctpError::SendBufferFull`] *before* any TSN is consumed
    /// (clamped to ≥ 1).
    pub send_buffer_chunks: u32,
    pub rto_initial: Duration,
    pub rto_min: Duration,
    pub rto_max: Duration,
    /// Outbound streams we offer (OS); inbound limit (MIS).
    pub os_streams: u16,
    pub mis_streams: u16,
    /// Largest user message we will send or deliver (mirrors SDP
    /// `a=max-message-size`).
    pub max_message_size: usize,
    /// Advertise FORWARD-TSN support and allow partial-reliability sends.
    pub forward_tsn: bool,
    /// Fixed heartbeat interval; `None` disables (the WebRTC path usually
    /// leans on the DTLS/ICE keepalives instead).
    pub heartbeat_interval: Option<Duration>,
    /// Deterministic overrides for tests: local verification tag.
    pub initial_tag: Option<u32>,
    /// Deterministic overrides for tests: first TSN we assign.
    pub initial_tsn: Option<u32>,
    /// Deterministic overrides for tests: cookie MAC key (server role).
    pub cookie_key: Option<[u8; 32]>,
    /// How long a state cookie stays valid (server role).
    pub cookie_lifetime: Duration,
}

impl Default for SctpConfig {
    fn default() -> Self {
        Self {
            is_client: true,
            local_port: 5000,
            remote_port: 5000,
            mtu: 1200,
            recv_window_chunks: 64,
            send_buffer_chunks: 256,
            rto_initial: Duration::from_millis(1000),
            rto_min: Duration::from_millis(200),
            rto_max: Duration::from_secs(60),
            os_streams: 1024,
            mis_streams: 1024,
            max_message_size: 256 * 1024,
            forward_tsn: true,
            heartbeat_interval: None,
            initial_tag: None,
            initial_tsn: None,
            cookie_key: None,
            cookie_lifetime: Duration::from_secs(60),
        }
    }
}

/// Events surfaced to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SctpEvent {
    /// Four-way handshake completed.
    Established,
    /// Peer opened a data channel (DCEP OPEN). The ack is automatic.
    DataChannelOpen {
        stream: u16,
        label: String,
        protocol: String,
        channel_type: ChannelType,
    },
    /// Our DATA_CHANNEL_OPEN was acknowledged by the peer.
    DataChannelAck { stream: u16 },
    /// Reassembled user message.
    Message {
        stream: u16,
        ppid: u32,
        data: Vec<u8>,
        unordered: bool,
    },
    /// Association terminated.
    Closed(CloseReason),
}

/// Why the association ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// Peer sent ABORT. `cause` is the raw cause-chunk bytes when present.
    Aborted(Option<Vec<u8>>),
    /// Graceful SHUTDOWN exchange finished.
    Shutdown,
    /// Local abort/shutdown requested.
    LocalClose,
    /// Handshake retransmissions exhausted.
    HandshakeTimeout,
    /// SHUTDOWN / SHUTDOWN-ACK retransmissions exhausted (T2, RFC 9260
    /// §9.1/§9.2) — the peer never completed the graceful exchange.
    ShutdownTimeout,
    /// Cookie stale / MAC mismatch / malformed handshake.
    HandshakeRejected(String),
    /// vtag/TSN/protocol rule violation.
    ProtocolViolation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_webrtc_shaped() {
        let c = SctpConfig::default();
        assert_eq!(c.local_port, 5000);
        assert_eq!(c.mtu, 1200);
        assert!(c.forward_tsn);
        assert!(c.heartbeat_interval.is_none());
    }
}
