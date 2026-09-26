//! Canonical serialization (RFC 3261 §7): CRLF endings, `Via* From To
//! Call-ID CSeq` first, remaining headers in insertion order, recomputed
//! `Content-Length` last.

use crate::message::{SipMessage, Version};

/// Serializes into a fresh `Vec<u8>`.
pub fn serialize(msg: &SipMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(512 + msg.body().len());
    serialize_into(msg, &mut out);
    out
}

/// Serializes into the provided buffer.
pub fn serialize_into(msg: &SipMessage, out: &mut Vec<u8>) {
    let (start_line, headers) = match msg {
        SipMessage::Request(r) => (
            format!("{} {} {}\r\n", r.method, r.uri, Version),
            &r.headers,
        ),
        SipMessage::Response(r) => {
            let reason = if r.reason.is_empty() {
                crate::message::reason_for_code(r.code)
            } else {
                &r.reason
            };
            (format!("{} {} {}\r\n", Version, r.code, reason), &r.headers)
        }
    };
    out.extend_from_slice(start_line.as_bytes());

    let priority = |name: &str| -> u8 {
        match name {
            "Via" => 0,
            "From" => 1,
            "To" => 2,
            "Call-ID" => 3,
            "CSeq" => 4,
            "Content-Length" => u8::MAX,
            _ => 5,
        }
    };
    let mut order: Vec<usize> = (0..headers.len())
        .filter(|&i| headers.iter().nth(i).expect("idx").name != "Content-Length")
        .collect();
    order.sort_by_key(|&i| (priority(&headers.iter().nth(i).expect("idx").name), i));

    for i in order {
        let h = headers.iter().nth(i).expect("idx");
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", msg.body().len()).as_bytes());
    out.extend_from_slice(msg.body());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_message;

    fn sample_request() -> SipMessage {
        crate::parse::parse_message(
            b"INVITE sip:alice@atlanta.com SIP/2.0\r\n\
              Max-Forwards: 70\r\n\
              Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
              To: <sip:alice@atlanta.com>\r\n\
              From: <sip:bob@biloxi.com>;tag=1928301774\r\n\
              Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
              CSeq: 314159 INVITE\r\n\
              Contact: <sip:bob@pc33.atlanta.com>\r\n\
              Content-Type: text/plain\r\n\
              Content-Length: 4\r\n\r\nbody",
        )
        .unwrap()
    }

    #[test]
    fn canonical_order_and_roundtrip() {
        let msg = sample_request();
        let wire = serialize(&msg);
        let text = String::from_utf8(wire.clone()).unwrap();
        let via_pos = text.find("Via:").unwrap();
        let from_pos = text.find("From:").unwrap();
        let to_pos = text.find("To:").unwrap();
        let cid_pos = text.find("Call-ID:").unwrap();
        let cseq_pos = text.find("CSeq:").unwrap();
        let cl_pos = text.find("Content-Length:").unwrap();
        assert!(via_pos < from_pos && from_pos < to_pos && to_pos < cid_pos && cid_pos < cseq_pos);
        assert!(cl_pos > cseq_pos);
        assert!(text.ends_with("Content-Length: 4\r\n\r\nbody"));
        // Round-trip must be lossless (==).
        let reparsed = parse_message(&wire).unwrap();
        assert_eq!(reparsed, msg);
    }

    #[test]
    fn serialize_response() {
        let resp = SipMessage::Response(crate::message::Response {
            code: 486,
            reason: String::new(),
            headers: {
                let mut h = crate::headers::HeaderMap::new();
                h.add("Via", "SIP/2.0/UDP h;branch=z9hG4bKx");
                h
            },
            body: Vec::new(),
        });
        let wire = serialize(&resp);
        let text = String::from_utf8(wire).unwrap();
        assert!(text.starts_with("SIP/2.0 486 Busy Here\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn serialize_into_appends() {
        let msg = sample_request();
        let mut buf = b"PREFIX".to_vec();
        serialize_into(&msg, &mut buf);
        assert!(buf.starts_with(b"PREFIXINVITE"));
    }
}
