//! Ergonomic request/response builders with sane RFC 3261 defaults
//! (Max-Forwards 70, generated branch/tag/Call-ID, User-Agent).

use crate::headers::{HeaderMap, Via};
use crate::ids::{new_branch, new_call_id, new_tag};
use crate::message::{Method, Request, Response, SipMessage};
use crate::uri::{NameAddr, SipUri};

/// Builds a [`Request`].
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    method: Method,
    uri: SipUri,
    headers: HeaderMap,
    body: Vec<u8>,
    max_forwards_set: bool,
}

impl RequestBuilder {
    /// Starts a request to `uri` (request-URI) with default headers.
    pub fn new(method: Method, uri: SipUri) -> RequestBuilder {
        RequestBuilder {
            method,
            uri,
            headers: HeaderMap::new(),
            body: Vec::new(),
            max_forwards_set: false,
        }
    }

    /// Adds a top Via hop (`sent_by` as `host` / `host:port` / `[v6]:port`).
    pub fn via(
        mut self,
        transport: crate::uri::TransportKind,
        sent_by: &str,
        branch: Option<&str>,
    ) -> Self {
        // An "ip:port" sent-by must split into host + port; passing the whole
        // string to Host::parse used to produce Domain("ip:port"), a Via
        // header no response router could parse back.
        let (host_txt, port) = split_host_port(sent_by);
        let via = Via {
            transport,
            sent_by: crate::headers::HostPort {
                host: crate::uri::Host::parse(host_txt, host_txt.contains('['))
                    .unwrap_or(crate::uri::Host::Domain(host_txt.to_string())),
                port,
            },
            branch: Some(branch.map(str::to_string).unwrap_or_else(new_branch)),
            received: None,
            rport: Some(None),
            params: Vec::new(),
        };
        self.headers.push_via(&via);
        self
    }

    /// Sets From (name-addr text) with an auto tag unless one is present.
    pub fn from(mut self, name_addr: &str) -> Self {
        let mut n = NameAddr::parse(name_addr).unwrap_or_else(|_| NameAddr {
            display: None,
            addr: crate::uri::Addr::parse(name_addr).unwrap_or(crate::uri::Addr::Sip(
                SipUri::parse("sip:invalid@invalid").unwrap(),
            )),
            tag: None,
            params: Vec::new(),
        });
        if n.tag.is_none() {
            n.tag = Some(new_tag());
        }
        self.headers.remove_all("From");
        self.headers.add("From", n.to_string());
        self
    }

    /// Sets To (name-addr text); tag left off for initial requests.
    pub fn to(mut self, name_addr: &str) -> Self {
        self.headers.remove_all("To");
        self.headers.add("To", name_addr);
        self
    }

    /// Sets Call-ID (generated when `call_id` is `None`).
    pub fn call_id(mut self, call_id: Option<&str>) -> Self {
        let cid = call_id
            .map(str::to_string)
            .unwrap_or_else(|| new_call_id("zrtc.local"));
        self.headers.remove_all("Call-ID");
        self.headers.add("Call-ID", cid);
        self
    }

    /// Sets CSeq.
    pub fn cseq(mut self, seq: u32) -> Self {
        self.headers.remove_all("CSeq");
        self.headers.add("CSeq", format!("{} {}", seq, self.method));
        self
    }

    /// Adds a Contact header.
    pub fn contact(mut self, contact: &str) -> Self {
        self.headers.remove_all("Contact");
        self.headers.add("Contact", contact);
        self
    }

    /// Sets the body and Content-Type.
    pub fn body(mut self, content_type: &str, body: Vec<u8>) -> Self {
        self.headers.remove_all("Content-Type");
        self.headers.add("Content-Type", content_type);
        self.body = body;
        self
    }

    /// Adds/replaces an arbitrary header.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.remove_all(name);
        self.headers.add(name, value);
        self
    }

    /// Finalizes, filling in defaults: Max-Forwards 70, auto Call-ID/CSeq
    /// when not set, User-Agent.
    pub fn build(mut self) -> Request {
        if !self.max_forwards_set && self.headers.max_forwards().is_none() {
            self.headers.add("Max-Forwards", "70");
        }
        if self.headers.call_id().is_none() {
            self.headers.add("Call-ID", new_call_id("zrtc.local"));
        }
        if self.headers.cseq().is_none() {
            self.headers.add("CSeq", format!("1 {}", self.method));
        }
        if self.headers.get("User-Agent").is_none() {
            self.headers.add("User-Agent", "zrtc/0.1");
        }
        let body_len = self.body.len();
        self.headers.set_content_length(body_len);
        Request {
            method: self.method,
            uri: self.uri,
            headers: self.headers,
            body: self.body,
        }
    }

    /// Builds wrapped as a [`SipMessage`].
    pub fn build_message(self) -> SipMessage {
        SipMessage::Request(self.build())
    }
}

/// Builds a [`Response`] mirroring the request's Via/From/To/Call-ID/CSeq.
pub fn respond_to(
    req: &Request,
    code: u16,
    reason: &str,
    body: Vec<u8>,
    to_tag: Option<&str>,
) -> Response {
    let mut headers = HeaderMap::new();
    for v in req.headers.get_all("Via") {
        headers.add("Via", v);
    }
    if let Some(f) = req.headers.get("From") {
        headers.add("From", f);
    }
    let mut to = req.headers.get("To").unwrap_or("").to_string();
    if let Some(tag) = to_tag {
        if !to.contains(";tag=") {
            to = format!("{to};tag={tag}");
        }
    }
    headers.add("To", to);
    if let Some(c) = req.headers.get("Call-ID") {
        headers.add("Call-ID", c);
    }
    if let Some(c) = req.headers.get("CSeq") {
        headers.add("CSeq", c);
    }
    if let Some(c) = req.headers.get("Record-Route") {
        headers.add("Record-Route", c);
    }
    Response {
        code,
        reason: reason.to_string(),
        headers,
        body,
    }
}

/// Splits a Via sent-by into host text and optional port, respecting IPv6
/// brackets (`host`, `host:port`, `[v6]`, `[v6]:port`).
fn split_host_port(s: &str) -> (&str, Option<u16>) {
    if let Some(rb) = s.rfind(']') {
        if s[rb + 1..].starts_with(':') {
            return (&s[..=rb], s[rb + 2..].parse().ok());
        }
        return (s, None);
    }
    match s.rfind(':') {
        Some(i) if s[i + 1..].parse::<u16>().is_ok() => {
            (&s[..i], Some(s[i + 1..].parse().unwrap()))
        }
        _ => (s, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_message;
    use crate::serialize::serialize;
    use crate::uri::TransportKind;

    #[test]
    fn builder_defaults_and_parseability() {
        let req = RequestBuilder::new(
            Method::Invite,
            SipUri::parse("sip:alice@atlanta.com").unwrap(),
        )
        .via(
            TransportKind::Udp,
            "pc33.atlanta.com:5060",
            Some("z9hG4bKfixed"),
        )
        .from("<sip:bob@biloxi.com>")
        .to("<sip:alice@atlanta.com>")
        .call_id(None)
        .cseq(314159)
        .contact("<sip:bob@pc33.atlanta.com>")
        .build();
        assert_eq!(req.headers.max_forwards(), Some(70));
        assert_eq!(req.headers.cseq().unwrap().seq, 314159);
        assert!(req.headers.from().unwrap().tag.is_some());
        let wire = serialize(&SipMessage::Request(req.clone()));
        let reparsed = parse_message(&wire).unwrap();
        assert_eq!(SipMessage::Request(req.clone()), reparsed);
    }

    #[test]
    fn respond_to_mirrors_headers_and_tags_to() {
        let req = RequestBuilder::new(Method::Invite, SipUri::parse("sip:a@b.com").unwrap())
            .via(TransportKind::Udp, "h.example", Some("z9hG4bKx"))
            .from("<sip:caller@x.com>;tag=c1")
            .to("<sip:callee@b.com>")
            .build();
        let resp = respond_to(&req, 180, "Ringing", Vec::new(), Some("s1"));
        assert_eq!(resp.code, 180);
        assert_eq!(resp.headers.via_all().len(), 1);
        let to = resp.headers.to().unwrap();
        assert_eq!(to.tag.as_deref(), Some("s1"));
        assert_eq!(resp.headers.call_id(), req.headers.call_id());
        // responding twice does not double-tag
        let resp2 = respond_to(&req, 200, "OK", Vec::new(), Some("s1"));
        assert!(
            resp2
                .headers
                .to()
                .unwrap()
                .to_string()
                .matches(";tag=")
                .count()
                == 1
        );
    }

    #[test]
    fn auto_call_id_and_cseq() {
        let req = RequestBuilder::new(Method::Options, SipUri::parse("sip:a@b.com").unwrap())
            .via(TransportKind::Udp, "h", None)
            .from("<sip:x@y>")
            .to("<sip:a@b.com>")
            .build();
        assert!(req.headers.call_id().is_some());
        assert_eq!(req.headers.cseq().unwrap().seq, 1);
        assert_eq!(req.headers.cseq().unwrap().method, Method::Options);
    }

    /// Regression: an "ip:port" sent-by used to become
    /// Host::Domain("ip:port") — a Via no response router could parse.
    #[test]
    fn via_sent_by_splits_host_and_port() {
        let req = RequestBuilder::new(Method::Options, SipUri::parse("sip:a@b.com").unwrap())
            .via(TransportKind::Udp, "10.0.0.7:5070", Some("z9hG4bKv"))
            .build();
        let v = req.headers.first_via().unwrap();
        assert_eq!(v.sent_by.host.to_string(), "10.0.0.7");
        assert_eq!(v.sent_by.port, Some(5070));

        // Bare host keeps port None; IPv6 brackets are respected.
        let req2 = RequestBuilder::new(Method::Options, SipUri::parse("sip:a@b.com").unwrap())
            .via(TransportKind::Udp, "proxy.example.com", Some("z9hG4bKv2"))
            .build();
        let v2 = req2.headers.first_via().unwrap();
        assert_eq!(v2.sent_by.host.to_string(), "proxy.example.com");
        assert_eq!(v2.sent_by.port, None);

        let req3 = RequestBuilder::new(Method::Options, SipUri::parse("sip:a@b.com").unwrap())
            .via(TransportKind::Udp, "[2001:db8::1]:5060", Some("z9hG4bKv3"))
            .build();
        let v3 = req3.headers.first_via().unwrap();
        // IPv6 hosts display bracketed (wire form per RFC 3261 §19.3).
        assert_eq!(v3.sent_by.host.to_string(), "[2001:db8::1]");
        assert_eq!(v3.sent_by.port, Some(5060));
    }
}
