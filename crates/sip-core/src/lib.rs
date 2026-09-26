#![forbid(unsafe_code)]
//! # sip-core — SIP message layer (RFC 3261)
//!
//! Pure-Rust implementation of the RFC 3261 message layer: the data model,
//! a hand-written panic-free byte parser, a canonical serializer, URI and
//! header typed views, Digest authentication helpers (RFC 2617/7616) and
//! random branch/tag/Call-ID generators.
//!
//! This crate contains **no** I/O, no async runtime and no transaction or
//! transport state machines. The transport and transaction layers (other
//! work packages) build on top of the API exposed here:
//!
//! * [`parse::parse_message`] — datagram framing (UDP): Content-Length is
//!   validated, trailing octets beyond it are tolerated (RFC 3261 §18.3).
//! * [`parse::parse_stream`] — stream framing (TCP/TLS/WS): consumes exactly
//!   the header section plus `Content-Length` body bytes and returns the
//!   number of bytes consumed; returns [`ParseError::Truncated`] while the
//!   message is incomplete so callers can accumulate more bytes.
//! * [`serialize::serialize`] / [`serialize::serialize_into`] — canonical
//!   header order (`Via* From To Call-ID CSeq`, remaining headers in
//!   insertion order, recomputed `Content-Length` last), CRLF line endings.
//!
//! Parser hard limits (see [`parse`]): 64 KiB per message, 128 headers,
//! 8 KiB per header line, 64 bytes per header name, 2 KiB per URI.
//!
//! # Example
//!
//! ```
//! use sip_core::{parse_message, serialize};
//!
//! let wire = b"INVITE sip:alice@atlanta.com SIP/2.0\r\n\
//!              Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
//!              Max-Forwards: 70\r\n\
//!              To: <sip:alice@atlanta.com>\r\n\
//!              From: <sip:bob@biloxi.com>;tag=1928301774\r\n\
//!              Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
//!              CSeq: 314159 INVITE\r\n\
//!              Content-Length: 0\r\n\r\n";
//! let msg = parse_message(wire).unwrap();
//! assert_eq!(msg.call_id(), Some("a84b4c76e66710@pc33.atlanta.com"));
//! assert_eq!(msg.method(), Some(sip_core::Method::Invite));
//! let m2 = parse_message(&serialize(&msg)).unwrap();
//! assert_eq!(m2, msg);
//! ```

pub mod builder;
pub mod digest;
pub mod error;
pub mod headers;
pub mod ids;
pub mod message;
pub mod parse;
pub mod serialize;
pub mod uri;

pub use digest::{Algorithm, Qop};
pub use error::{ParseError, Result};
pub use headers::{
    Allow, AllowEvents, AuthChallenge, AuthResponse, ContactList, ContentLength, ContentType, CSeq,
    Event, Expires, FromTo, HeaderMap, MaxForwards, MinSe, ProxyRequire, RAck, Reason, ReferTo,
    Require, RetryAfter, RouteSet, SessionExpires, SubscriptionState, Supported, TokenList, Via,
};
pub use ids::{new_branch, new_call_id, new_tag};
pub use message::{Method, Request, Response, SipMessage, Version};
pub use parse::{parse_message, parse_stream};
pub use serialize::{serialize, serialize_into};
pub use uri::{Addr, Host, NameAddr, Param, Scheme, SipUri, TelUri, TransportKind};
