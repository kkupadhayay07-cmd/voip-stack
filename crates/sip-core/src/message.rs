//! SIP message data model: methods, requests, responses and the
//! [`SipMessage`] enum (RFC 3261 §7).

use crate::headers::{CSeq, HeaderMap, Via};
use crate::uri::SipUri;

/// The `SIP/2.0` protocol version marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version;

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SIP/2.0")
    }
}

/// SIP methods (RFC 3261 + common extensions).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// Establish a session (INVITE).
    Invite,
    /// Complete a transaction / acknowledge 2xx (ACK).
    Ack,
    /// Terminate a dialog (BYE).
    Bye,
    /// Cancel a pending INVITE (CANCEL).
    Cancel,
    /// Register contact bindings (REGISTER).
    Register,
    /// Query capabilities (OPTIONS).
    Options,
    /// Mid-dialog session information (INFO, RFC 6086).
    Info,
    /// Session timer refresh (UPDATE, RFC 3311).
    Update,
    /// Reliable provisional response ack (PRACK, RFC 3262).
    Prack,
    /// Event subscription (SUBSCRIBE, RFC 6665).
    Subscribe,
    /// Event notification (NOTIFY, RFC 6665).
    Notify,
    /// Refer a recipient to a resource (REFER, RFC 3515).
    Refer,
    /// Instant message (MESSAGE, RFC 3428).
    Message,
    /// Any extension method.
    Other(String),
}

impl Method {
    /// Canonical text form.
    pub fn as_str(&self) -> &str {
        match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Info => "INFO",
            Method::Update => "UPDATE",
            Method::Prack => "PRACK",
            Method::Subscribe => "SUBSCRIBE",
            Method::Notify => "NOTIFY",
            Method::Refer => "REFER",
            Method::Message => "MESSAGE",
            Method::Other(s) => s,
        }
    }

    /// Parses a method token (case-sensitive per RFC 3261 token rules,
    /// matched case-insensitively against the known set for robustness).
    pub fn parse(s: &str) -> Method {
        match s.to_ascii_uppercase().as_str() {
            "INVITE" => Method::Invite,
            "ACK" => Method::Ack,
            "BYE" => Method::Bye,
            "CANCEL" => Method::Cancel,
            "REGISTER" => Method::Register,
            "OPTIONS" => Method::Options,
            "INFO" => Method::Info,
            "UPDATE" => Method::Update,
            "PRACK" => Method::Prack,
            "SUBSCRIBE" => Method::Subscribe,
            "NOTIFY" => Method::Notify,
            "REFER" => Method::Refer,
            "MESSAGE" => Method::Message,
            _ => Method::Other(s.to_string()),
        }
    }

    /// Whether a response to this method can be ACKed as a transaction
    /// (non-2xx) — 2xx ACKs are dialog-level (RFC 3261 §13.2.2.4).
    pub fn is_invite(&self) -> bool {
        matches!(self, Method::Invite)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A SIP request: request line + headers + body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Request-URI.
    pub uri: SipUri,
    /// Header section (order preserved).
    pub headers: HeaderMap,
    /// Opaque body (payload per Content-Type).
    pub body: Vec<u8>,
}

/// A SIP response: status line + headers + body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Response code (100..=699).
    pub code: u16,
    /// Reason phrase (may be empty; transport preserves as received).
    pub reason: String,
    /// Header section (order preserved).
    pub headers: HeaderMap,
    /// Opaque body.
    pub body: Vec<u8>,
}

impl Response {
    /// Class of the response: 1 informational, 2 success, ... 6 global failure.
    pub fn class(&self) -> u8 {
        (self.code / 100) as u8
    }

    /// Provisional (1xx) response?
    pub fn is_provisional(&self) -> bool {
        self.class() == 1
    }

    /// Final (2xx-6xx) response?
    pub fn is_final(&self) -> bool {
        self.class() >= 2
    }
}

/// Either a request or a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessage {
    /// A request.
    Request(Request),
    /// A response.
    Response(Response),
}

impl SipMessage {
    /// Header section access.
    pub fn headers(&self) -> &HeaderMap {
        match self {
            SipMessage::Request(r) => &r.headers,
            SipMessage::Response(r) => &r.headers,
        }
    }

    /// Mutable header section access.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        match self {
            SipMessage::Request(r) => &mut r.headers,
            SipMessage::Response(r) => &mut r.headers,
        }
    }

    /// Body access.
    pub fn body(&self) -> &[u8] {
        match self {
            SipMessage::Request(r) => &r.body,
            SipMessage::Response(r) => &r.body,
        }
    }

    /// `Call-ID` header value.
    pub fn call_id(&self) -> Option<&str> {
        self.headers().call_id()
    }

    /// The method of a request, or of a response's CSeq.
    pub fn method(&self) -> Option<Method> {
        match self {
            SipMessage::Request(r) => Some(r.method.clone()),
            SipMessage::Response(r) => r.headers.cseq().map(|c| c.method),
        }
    }

    /// `CSeq` header.
    pub fn cseq(&self) -> Option<CSeq> {
        self.headers().cseq()
    }

    /// Top `Via` header.
    pub fn top_via(&self) -> Option<Via> {
        self.headers().first_via()
    }

    /// Transaction lookup key text: `branch` of the top Via (when the magic
    /// cookie is present) plus the method kind (RFC 3261 §17.2.3).
    pub fn branch(&self) -> Option<String> {
        self.top_via()
            .and_then(|v| v.branch)
            .filter(|b| b.starts_with("z9hG4bK"))
    }
}

/// Default reason phrase per RFC 3261 §21 and common extensions.
pub fn reason_for_code(code: u16) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        183 => "Session Progress",
        200 => "OK",
        202 => "Accepted",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Request Entity Too Large",
        415 => "Unsupported Media Type",
        416 => "Unsupported URI Scheme",
        420 => "Bad Extension",
        421 => "Extension Required",
        422 => "Session Interval Too Small",
        423 => "Interval Too Brief",
        430 => "Flow Failed",
        439 => "First Hop Lacks Outbound Support",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        482 => "Loop Detected",
        483 => "Too Many Hops",
        484 => "Address Incomplete",
        485 => "Ambiguous",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        491 => "Request Pending",
        500 => "Server Internal Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Server Time-out",
        505 => "Version Not Supported",
        513 => "Message Too Large",
        580 => "Precondition Failure",
        600 => "Busy Everywhere",
        603 => "Decline",
        604 => "Does Not Exist Anywhere",
        606 => "Not Acceptable",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_roundtrip() {
        for m in [
            "INVITE",
            "ACK",
            "BYE",
            "CANCEL",
            "REGISTER",
            "OPTIONS",
            "INFO",
            "UPDATE",
            "PRACK",
            "SUBSCRIBE",
            "NOTIFY",
            "REFER",
            "MESSAGE",
        ] {
            assert_eq!(Method::parse(m).as_str(), m);
        }
        assert_eq!(Method::parse("invite"), Method::Invite);
        assert_eq!(Method::parse("FOOBAR"), Method::Other("FOOBAR".into()));
        assert_eq!(Method::Invite.to_string(), "INVITE");
    }

    #[test]
    fn response_helpers() {
        let r = Response {
            code: 180,
            reason: "Ringing".into(),
            headers: HeaderMap::new(),
            body: Vec::new(),
        };
        assert!(r.is_provisional());
        assert!(!r.is_final());
        assert_eq!(r.class(), 1);
        assert_eq!(reason_for_code(486), "Busy Here");
        assert_eq!(reason_for_code(200), "OK");
        assert_eq!(reason_for_code(999), "");
    }

    #[test]
    fn version_display() {
        assert_eq!(Version.to_string(), "SIP/2.0");
    }
}
