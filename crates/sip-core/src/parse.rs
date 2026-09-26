//! Panic-free SIP message parser with datagram (`parse_message`) and stream
//! (`parse_stream`) framing, compact-header expansion and hard limits.

use crate::error::{ParseError, Result};
use crate::headers::{canonical_name, Header, HeaderMap};
use crate::message::{reason_for_code, Method, Request, Response, SipMessage};
use crate::uri::SipUri;

/// Parser hard limits (RFC 3261 encourages limits; these bound memory use).
pub const MAX_MESSAGE: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_HEADER_LINE: usize = 8 * 1024;
const MAX_HEADER_NAME: usize = 64;
const MAX_URI: usize = 2048;

/// Parses a UDP datagram as exactly one SIP message (RFC 3261 §18.3):
/// trailing octets beyond `Content-Length` are tolerated and ignored; a
/// body shorter than announced is a malformed message.
pub fn parse_message(buf: &[u8]) -> Result<SipMessage> {
    let (msg, consumed) = parse_stream(buf).map_err(|e| match e {
        // In datagram framing a truncated message cannot ever complete.
        ParseError::Truncated { expected, got } => ParseError::Malformed {
            line: 0,
            col: 0,
            what: format!("datagram shorter than Content-Length: expected {expected}, got {got}"),
        },
        other => other,
    })?;
    // `consumed` == min(header+body, buf.len()); trailing octets tolerated.
    let _ = consumed;
    Ok(msg)
}

/// Parses one message from a stream buffer (TCP/TLS/WS framing, RFC 3261
/// §18.3 / RFC 7118 §4.2). Returns the message and the number of bytes
/// consumed (header section + Content-Length body). Returns
/// [`ParseError::Truncated`] while the buffer ends mid-message.
pub fn parse_stream(buf: &[u8]) -> Result<(SipMessage, usize)> {
    if buf.len() > MAX_MESSAGE {
        return Err(ParseError::TooLarge { limit: MAX_MESSAGE });
    }

    // ---- locate the end of the header section (CRLFCRLF, LF-tolerant) ----
    let text = std::str::from_utf8(buf)
        .map_err(|_| ParseError::malformed("message is not valid UTF-8"))?;
    let (header_end, sep_len) = find_header_end(text).ok_or(ParseError::Truncated {
        expected: 0,
        got: buf.len(),
    })?;
    let head = &text[..header_end];
    let body_start = header_end + sep_len;

    // ---- start line ----
    let mut lines = head.split("\n");
    let start_line = lines
        .next()
        .ok_or(ParseError::Truncated {
            expected: 0,
            got: buf.len(),
        })?
        .trim_end_matches('\r');
    if start_line.is_empty() {
        return Err(ParseError::Malformed {
            line: 1,
            col: 1,
            what: "empty start line".into(),
        });
    }

    // ---- header section ----
    let mut headers = HeaderMap::new();
    let mut content_length: Option<usize> = None;
    let mut prev_continuation = false;
    let mut line_no = 2;
    let mut header_count = 0usize;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            line_no += 1;
            continue;
        }
        if line.len() > MAX_HEADER_LINE {
            return Err(ParseError::TooLarge {
                limit: MAX_HEADER_LINE,
            });
        }
        // Header folding: leading SP/HTAB continues the previous header.
        if line.starts_with(' ') || line.starts_with('\t') {
            if prev_continuation && !headers.is_empty() {
                let last = headers.headers.last_mut().expect("non-empty");
                last.value.push(' ');
                last.value.push_str(line.trim());
                continue;
            }
            return Err(ParseError::Malformed {
                line: line_no,
                col: 1,
                what: "continuation line with no preceding header".into(),
            });
        }
        let colon = line.find(':').ok_or_else(|| ParseError::Malformed {
            line: line_no,
            col: line.len(),
            what: format!("header without colon: {line:?}"),
        })?;
        let raw_name = &line[..colon];
        if raw_name.is_empty() || raw_name.len() > MAX_HEADER_NAME {
            return Err(ParseError::Malformed {
                line: line_no,
                col: 1,
                what: "bad header name length".into(),
            });
        }
        if !raw_name.bytes().all(is_token_byte) {
            return Err(ParseError::Malformed {
                line: line_no,
                col: 1,
                what: format!("invalid header name {raw_name:?}"),
            });
        }
        let name = canonical_name(raw_name.trim());
        let value = line[colon + 1..].trim().to_string();
        if name == "Content-Length" {
            let v: i64 = value
                .trim()
                .parse()
                .map_err(|_| ParseError::BadContentLength(value.parse().unwrap_or(-1)))?;
            if v < 0 {
                return Err(ParseError::BadContentLength(v));
            }
            content_length = Some(v as usize);
        }
        headers.headers.push(Header { name, value });
        prev_continuation = true;
        header_count += 1;
        if header_count > MAX_HEADERS {
            return Err(ParseError::TooLarge { limit: MAX_HEADERS });
        }
        line_no += 1;
    }

    let cl = content_length.ok_or_else(|| ParseError::malformed("missing Content-Length"))?;
    let total_needed = body_start + cl;
    if buf.len() < total_needed {
        return Err(ParseError::Truncated {
            expected: cl,
            got: buf.len().saturating_sub(body_start),
        });
    }

    // ---- build the message ----
    let body = buf[body_start..body_start + cl].to_vec();
    let msg = build_message(start_line, headers, body, line_no)?;
    Ok((msg, total_needed))
}

fn build_message(
    start_line: &str,
    headers: HeaderMap,
    body: Vec<u8>,
    line_no: usize,
) -> Result<SipMessage> {
    if let Some(rest) = start_line.strip_prefix("SIP/2.0 ") {
        // status line: code [reason]
        let mut parts = rest.splitn(2, char::is_whitespace);
        let code: u16 = parts
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|_| ParseError::Malformed {
                line: 1,
                col: 9,
                what: format!("bad status code in {start_line:?}"),
            })?;
        if !(100..1000).contains(&code) {
            return Err(ParseError::Malformed {
                line: 1,
                col: 9,
                what: format!("status code out of range: {code}"),
            });
        }
        let reason = parts.next().unwrap_or("").trim().to_string();
        let reason = if reason.is_empty() {
            reason_for_code(code).to_string()
        } else {
            reason
        };
        Ok(SipMessage::Response(Response {
            code,
            reason,
            headers,
            body,
        }))
    } else if start_line.starts_with("SIP/") {
        Err(ParseError::UnsupportedVersion(
            start_line
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string(),
        ))
    } else {
        // request line: METHOD SP request-URI SP SIP/2.0
        let parts: Vec<&str> = start_line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(ParseError::Malformed {
                line: 1,
                col: start_line.len(),
                what: "request line must be METHOD SP URI SP SIP/2.0".into(),
            });
        }
        if parts[2] != "SIP/2.0" {
            return Err(ParseError::UnsupportedVersion(parts[2].to_string()));
        }
        if parts[1].len() > MAX_URI {
            return Err(ParseError::TooLarge { limit: MAX_URI });
        }
        let uri = SipUri::parse(parts[1]).map_err(|mut e| {
            if let ParseError::Malformed { line, col, what } = &mut e {
                if *line < 1 {
                    *line = 1;
                }
                if *col < 1 {
                    *col = 1;
                }
                *what = format!("request-URI: {what} (line {line_no})");
            }
            e
        })?;
        Ok(SipMessage::Request(Request {
            method: Method::parse(parts[0]),
            uri,
            headers,
            body,
        }))
    }
}

/// Finds the header-terminating blank line. Returns (offset of the blank
/// line start, separator length). Accepts CRLFCRLF, LFLF, CRLF-LF mixes and
/// the deprecated bare-LF line endings.
fn find_header_end(text: &str) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    while i < n {
        // try to find a line that is empty (possibly after \r)
        let line_len = b[i..].iter().position(|&c| c == b'\n')? + 1;
        let line = &text[i..i + line_len];
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return Some((i, line_len));
        }
        i += line_len;
    }
    None
}

/// RFC 3261 token byte set.
pub fn is_token_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &[u8] = b"INVITE sip:alice@atlanta.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: <sip:alice@atlanta.com>\r\n\
From: <sip:bob@biloxi.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:bob@pc33.atlanta.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 4\r\n\r\nbody";

    #[test]
    fn parse_invite_request() {
        let msg = parse_message(INVITE).unwrap();
        let req = match &msg {
            SipMessage::Request(r) => r,
            _ => panic!("expected request"),
        };
        assert_eq!(req.method, Method::Invite);
        assert_eq!(req.uri.to_string(), "sip:alice@atlanta.com");
        assert_eq!(msg.call_id(), Some("a84b4c76e66710@pc33.atlanta.com"));
        assert_eq!(msg.method(), Some(Method::Invite));
        assert_eq!(msg.branch().as_deref(), Some("z9hG4bK776asdhds"));
        assert_eq!(req.body, b"body");
        assert_eq!(req.headers.content_length(), Some(4));
        assert_eq!(req.headers.content_type(), Some("application/sdp"));
    }

    #[test]
    fn parse_response() {
        let wire = b"SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
From: <sip:a@b>;tag=1\r\nTo: <sip:c@d>;tag=2\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let msg = parse_message(wire).unwrap();
        match &msg {
            SipMessage::Response(r) => {
                assert_eq!(r.code, 180);
                assert_eq!(r.reason, "Ringing");
                assert!(r.is_provisional());
            }
            _ => panic!("expected response"),
        }
        assert_eq!(msg.method(), Some(Method::Invite));
    }

    #[test]
    fn response_without_reason_gets_default() {
        let wire = b"SIP/2.0 486\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\
Call-ID: x\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
        let msg = parse_message(wire).unwrap();
        match &msg {
            SipMessage::Response(r) => assert_eq!(r.reason, "Busy Here"),
            _ => panic!(),
        }
    }

    #[test]
    fn compact_forms_and_folding() {
        let wire = b"OPTIONS sip:x@y.com SIP/2.0\r\nv: SIP/2.0/UDP h;branch=z9hG4bKc\r\n\
i: folded\n\tcontinuation\r\nt: <sip:a@b>\r\nl: 0\r\n\r\n";
        let msg = parse_message(wire).unwrap();
        assert_eq!(msg.call_id(), Some("folded continuation"));
        assert!(msg.top_via().is_some());
    }

    #[test]
    fn stream_framing_partial_input() {
        // feed the message in halves through parse_stream
        let (a, b) = INVITE.split_at(60);
        assert!(matches!(
            parse_stream(a),
            Err(ParseError::Truncated { expected: 0, .. })
        ));
        let mut both = a.to_vec();
        both.extend_from_slice(b);
        // still truncated (missing body part)
        let cut = &both[..both.len() - 2];
        assert!(matches!(
            parse_stream(cut),
            Err(ParseError::Truncated {
                expected: 4,
                got: 2
            })
        ));
        let (msg, used) = parse_stream(&both).unwrap();
        assert_eq!(used, both.len());
        assert!(matches!(msg, SipMessage::Request(_)));
    }

    #[test]
    fn datagram_tolerates_trailing_octets() {
        let mut buf = INVITE.to_vec();
        buf.extend_from_slice(b"GARBAGE");
        let msg = parse_message(&buf).unwrap();
        assert!(matches!(msg, SipMessage::Request(_)));
    }

    #[test]
    fn rejects_malformed() {
        // no Content-Length
        let bad = b"INVITE sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKx\r\n\r\n";
        assert!(parse_message(bad).is_err());
        // bad version
        let bad = b"INVITE sip:a@b SIP/3.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKx\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            parse_message(bad),
            Err(ParseError::UnsupportedVersion(_))
        ));
        // header without colon
        let bad = b"INVITE sip:a@b SIP/2.0\r\nNoColonHeader\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_message(bad).is_err());
        // empty input
        assert!(parse_message(b"").is_err());
        // bad request-URI
        let bad = b"INVITE http://x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKx\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_message(bad).is_err());
    }

    #[test]
    fn enforces_limits() {
        // too many headers
        let mut wire = String::from("OPTIONS sip:a@b SIP/2.0\r\n");
        for i in 0..200 {
            wire.push_str(&format!("X-H{i}: v{i}\r\n"));
        }
        wire.push_str("Content-Length: 0\r\n\r\n");
        assert!(matches!(
            parse_message(wire.as_bytes()),
            Err(ParseError::TooLarge { .. })
        ));
        // huge URI
        let uri = format!("sip:{}@b.com", "a".repeat(3000));
        let wire = format!("OPTIONS {uri} SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKx\r\nContent-Length: 0\r\n\r\n");
        assert!(matches!(
            parse_message(wire.as_bytes()),
            Err(ParseError::TooLarge { .. })
        ));
    }

    #[test]
    fn token_bytes() {
        assert!(is_token_byte(b'A'));
        assert!(is_token_byte(b'-'));
        assert!(!is_token_byte(b':'));
        assert!(!is_token_byte(b' '));
    }
}
