//! # ice
//!
//! Native STUN / ICE / TURN ([RFC 5389], [RFC 8445], [RFC 5766]):
//!
//! - full STUN message codec with MESSAGE-INTEGRITY (HMAC-SHA1) and
//!   FINGERPRINT (CRC32) validated against the RFC 5769 test vectors
//! - ICE agent: host / server-reflexive / relayed candidate gathering,
//!   RFC 8445 connectivity checks with short-term credentials, role and
//!   tie-breaker handling, USE-CANDIDATE nomination, keepalives
//! - STUN binding server (the reflexive-address oracle)
//! - TURN relay server: long-term credentials, per-allocation relay
//!   sockets, permissions, Send/Data indications, ChannelBind
//! - SDP candidate-line codec (RFC 8839)
//!
//! [RFC 5389]: https://datatracker.ietf.org/doc/html/rfc5389
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
//! [RFC 5766]: https://datatracker.ietf.org/doc/html/rfc5766

#![forbid(unsafe_code)]

pub mod agent;
pub mod candidate;
pub mod crc32;
pub mod server;
pub mod stun;

pub use agent::{AgentConfig, IceAgent, SelectedPair};
pub use candidate::{compute_priority, Candidate, CandidateType, IceError};
pub use server::{ServerError, StunTurnConfig, StunTurnServer};
pub use stun::{Message, StunError};
