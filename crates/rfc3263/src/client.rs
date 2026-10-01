//! DNS query transport: UDP with one retransmission, automatic fallback to
//! TCP when a response carries the TC (truncation) bit, per RFC 1035 §4.2.
//!
//! Blocking std sockets — RFC 3263 resolution happens once per trunk setup,
//! not per packet, so a synchronous client keeps the API honest and the
//! dependencies at zero.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::wire::{encode_query, parse_response, DnsError, Message, Record};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
/// UDP is tried twice (initial + one retransmission) before giving up.
const UDP_ATTEMPTS: usize = 2;
/// RFC 1035 §2.3.4 suggests 512 B for UDP; we allow 4096. A datagram that
/// FILLS this buffer was cut off locally (the network delivered more than
/// we will read) — the response must be retried over TCP even though we
/// cannot see the server's TC flag anymore.
const UDP_BUF: usize = 4096;

/// Outcome of one UDP query exchange.
#[derive(Debug)]
enum UdpRecv {
    /// A well-formed, ID-matched response arrived.
    Answer(Message),
    /// The response was cut off locally (datagram filled the receive
    /// buffer): retry over TCP instead of parsing a partial answer.
    RetryTcp,
    /// No matching response within the deadline (retransmit or give up).
    Timeout,
}

/// Case-insensitive bailiwick test (RFC 5452): `owner` is the queried
/// name itself or a subdomain of it. Trailing dots are ignored.
fn in_bailiwick(owner: &str, qname: &str) -> bool {
    let o = owner.trim_end_matches('.').to_ascii_lowercase();
    let q = qname.trim_end_matches('.').to_ascii_lowercase();
    if q.is_empty() {
        return true;
    }
    o == q || o.ends_with(&format!(".{q}"))
}

/// Drops every record whose owner name is outside the queried name's
/// bailiwick (RFC 5452 §5.4 — records must be in-scope for the question;
/// a forged response may not inject names from other zones).
fn filter_bailiwick(msg: &mut Message, qname: &str) {
    msg.records.retain(|r| {
        let owner = match r {
            Record::Srv(s) => &s.name,
            Record::Naptr(n) => &n.name,
            Record::A { name, .. } | Record::Aaaa { name, .. } | Record::Other { name, .. } => name,
        };
        in_bailiwick(owner, qname)
    });
}

/// Monotonic query-id source: a process-wide xorshift state seeded once
/// from the clock and advanced atomically, so concurrent resolvers neither
/// collide nor repeat a small searchable ID sequence (RFC 5452 hardening).
static ID_STATE: AtomicU64 = AtomicU64::new(0);

fn next_query_id() -> u16 {
    let mut prev = ID_STATE.load(Ordering::Relaxed);
    loop {
        let mut s = prev;
        if s == 0 {
            // First caller seeds from the clock (non-zero via | 1).
            s = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs() << 20))
                .unwrap_or(0x9E37_79B9_7F4A_7C15)
                | 1;
        }
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        match ID_STATE.compare_exchange_weak(prev, s, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return ((s >> 32) as u16) ^ (s as u16),
            Err(cur) => prev = cur,
        }
    }
}

/// A blocking DNS client pointed at one recursive resolver.
#[derive(Debug, Clone)]
pub struct DnsClient {
    pub server: SocketAddr,
    pub timeout: Duration,
}

impl DnsClient {
    pub fn new(server: SocketAddr, timeout: Duration) -> Self {
        DnsClient { server, timeout }
    }

    /// Sends one query and returns the decoded response. UDP first; a
    /// truncated (TC) response is retried over TCP on the same address.
    pub fn query(&self, qname: &str, qtype: u16) -> Result<Message, DnsError> {
        let id = next_query_id();
        let packet = encode_query(id, qname, qtype)?;
        // RFC 5452: every record in the answer is constrained to the
        // bailiwick of the queried name (exact owner or a subdomain of it);
        // anything else is out-of-scope data that a spoofed/misbehaving
        // response must not inject into our resolution.
        let mut msg = match self.query_udp(id, &packet)? {
            UdpRecv::Answer(m) => m,
            UdpRecv::RetryTcp => {
                let mut m = self.query_tcp(id, &packet)?;
                filter_bailiwick(&mut m, qname);
                return Ok(m);
            }
            UdpRecv::Timeout => return Err(DnsError::Timeout),
        };
        if msg.truncated {
            let mut m = self.query_tcp(id, &packet)?;
            filter_bailiwick(&mut m, qname);
            return Ok(m);
        }
        filter_bailiwick(&mut msg, qname);
        Ok(msg)
    }

    fn query_udp(&self, id: u16, packet: &[u8]) -> Result<UdpRecv, DnsError> {
        // Bind by the server's address family: resolv.conf may hand us an
        // IPv6 nameserver, and an AF_INET socket cannot connect() to one.
        let bind = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind)?;
        sock.connect(self.server)?;
        sock.set_write_timeout(Some(self.timeout))?;
        for _ in 0..UDP_ATTEMPTS {
            sock.send(packet)?;
            match self.recv_matching_udp(&sock, id)? {
                UdpRecv::Answer(msg) => return Ok(UdpRecv::Answer(msg)),
                UdpRecv::RetryTcp => return Ok(UdpRecv::RetryTcp),
                UdpRecv::Timeout => {} // Timeout with no matching response: retransmit.
            }
        }
        Ok(UdpRecv::Timeout)
    }

    /// Waits up to `timeout`, discarding malformed, non-response (QR bit
    /// clear — a spoofed/reflected QUERY is not an answer) and
    /// mismatched-ID datagrams (late answers to a previous query are not
    /// answers). A datagram that fills the receive buffer is reported as
    /// [`UdpRecv::RetryTcp`] BEFORE parsing — a locally cut-off response
    /// may still parse cleanly, and accepting its partial record set would
    /// be silently wrong (RFC 5452 mindset: distrust the datagram).
    fn recv_matching_udp(&self, sock: &UdpSocket, id: u16) -> Result<UdpRecv, DnsError> {
        let deadline = Instant::now() + self.timeout;
        let mut buf = vec![0u8; UDP_BUF];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(UdpRecv::Timeout);
            }
            sock.set_read_timeout(Some(deadline - now))?;
            match sock.recv(&mut buf) {
                Ok(n) => {
                    if n == buf.len() {
                        // Locally truncated: the real datagram is at least
                        // this big, so we are reading a cut-off copy. TCP
                        // is the authoritative fallback (RFC 1035 §4.2.2).
                        return Ok(UdpRecv::RetryTcp);
                    }
                    if let Ok(msg) = parse_response(&buf[..n]) {
                        if msg.is_response && msg.id == id {
                            return Ok(UdpRecv::Answer(msg));
                        }
                    }
                    // Malformed, non-response or foreign datagram: keep waiting.
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(UdpRecv::Timeout);
                }
                Err(e) => return Err(DnsError::from(e)),
            }
        }
    }

    /// RFC 1035 §4.2.2: two-byte length prefix followed by the message.
    fn query_tcp(&self, id: u16, packet: &[u8]) -> Result<Message, DnsError> {
        let mut stream = TcpStream::connect_timeout(&self.server, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let mut framed = Vec::with_capacity(packet.len() + 2);
        framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        framed.extend_from_slice(packet);
        stream.write_all(&framed)?;

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Err(DnsError::Truncated);
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        let msg = parse_response(&buf)?;
        if msg.id != id || !msg.is_response {
            // Wrong id, or QR bit clear (a query, not an answer) — reject.
            return Err(DnsError::IdMismatch);
        }
        Ok(msg)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A canned-response DNS server for tests: one UDP socket and one TCP
    //! listener bound to the SAME port on 127.0.0.1 (TCP fallback must dial
    //! the server address, so both transports need to answer there).

    use super::*;
    use crate::wire::parse_response;
    use std::collections::HashMap;
    use std::sync::mpsc::{channel, Sender};
    use std::thread::JoinHandle;

    pub struct FakeDns {
        pub addr: SocketAddr,
        /// Every (qname, qtype) the server saw, in order.
        pub queries: std::sync::Arc<std::sync::Mutex<Vec<(String, u16)>>>,
        shutdown_udp: Sender<()>,
        shutdown_tcp: Sender<()>,
        handles: Vec<JoinHandle<()>>,
    }

    impl FakeDns {
        pub fn shutdown(self) {
            let _ = self.shutdown_udp.send(());
            let _ = self.shutdown_tcp.send(());
            for h in self.handles {
                let _ = h.join();
            }
        }

        /// `routes`: (qname, qtype) -> raw response bytes (the id is patched
        /// from the incoming query). A missing route answers with SERVFAIL.
        /// `tcp_response`: full response bytes served over TCP (for TC tests).
        pub fn spawn(
            routes: HashMap<(String, u16), Vec<u8>>,
            tcp_response: Option<Vec<u8>>,
        ) -> FakeDns {
            Self::spawn_on("127.0.0.1:0".parse().unwrap(), routes, tcp_response)
        }

        /// Variant bound to an explicit address (e.g. `[::1]:0` for IPv6
        /// nameserver tests). UDP and TCP share the port, as in `spawn`.
        pub fn spawn_on(
            bind_addr: SocketAddr,
            routes: HashMap<(String, u16), Vec<u8>>,
            tcp_response: Option<Vec<u8>>,
        ) -> FakeDns {
            let tcp = std::net::TcpListener::bind(bind_addr).unwrap();
            // UDP shares the TCP listener's actual (ephemeral) port so the
            // TC→TCP fallback dials a port that really serves both.
            let udp = UdpSocket::bind(tcp.local_addr().unwrap()).unwrap();
            let addr = udp.local_addr().unwrap();

            let queries: std::sync::Arc<std::sync::Mutex<Vec<(String, u16)>>> =
                std::sync::Arc::default();
            let (tx, rx) = channel::<()>();
            let q_udp = queries.clone();
            let r_udp = routes.clone();
            let h_udp = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                // Short socket timeout so the shutdown probe is noticed.
                let _ = udp.set_read_timeout(Some(Duration::from_millis(50)));
                loop {
                    if rx.try_recv().is_ok() {
                        return;
                    }
                    let (n, peer) = match udp.recv_from(&mut buf) {
                        Ok(x) => x,
                        Err(_) => continue,
                    };
                    let pkt = buf[..n].to_vec();
                    let _ = udp.send_to(&serve(&pkt, &r_udp, &q_udp), peer);
                }
            });
            let r_tcp = routes;
            let q_tcp = queries.clone();
            let (tx2, rx2) = channel::<()>();
            let _ = tcp.set_nonblocking(true);
            let h_tcp = std::thread::spawn(move || loop {
                if rx2.try_recv().is_ok() {
                    return;
                }
                match tcp.accept() {
                    Ok((stream, _)) => {
                        let mut stream = stream;
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).is_err() {
                            continue;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut pkt = vec![0u8; len];
                        if stream.read_exact(&mut pkt).is_err() {
                            continue;
                        }
                        let reply = match &tcp_response {
                            Some(bytes) => {
                                // Patch the caller's query id into the canned body.
                                let mut b = bytes.clone();
                                if pkt.len() >= 2 && b.len() >= 2 {
                                    b[0] = pkt[0];
                                    b[1] = pkt[1];
                                }
                                b
                            }
                            None => serve(&pkt, &r_tcp, &q_tcp),
                        };
                        let mut framed = Vec::with_capacity(reply.len() + 2);
                        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                        framed.extend_from_slice(&reply);
                        let _ = stream.write_all(&framed);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return,
                }
            });
            FakeDns {
                addr,
                queries,
                shutdown_udp: tx,
                shutdown_tcp: tx2,
                handles: vec![h_udp, h_tcp],
            }
        }
    }

    fn serve(
        query: &[u8],
        routes: &HashMap<(String, u16), Vec<u8>>,
        log: &std::sync::Arc<std::sync::Mutex<Vec<(String, u16)>>>,
    ) -> Vec<u8> {
        if parse_response(query).is_err() {
            return Vec::new();
        }
        // Reconstruct the question name/qtype from the query bytes.
        let mut pos = 12usize;
        let mut labels = Vec::new();
        while pos < query.len() {
            let l = query[pos] as usize;
            if l == 0 {
                pos += 1;
                break;
            }
            labels.push(String::from_utf8_lossy(&query[pos + 1..pos + 1 + l]).into_owned());
            pos += 1 + l;
        }
        if pos + 4 > query.len() {
            return Vec::new();
        }
        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
        let qname = labels.join(".");
        log.lock().unwrap().push((qname.clone(), qtype));

        let id = [query[0], query[1]];
        if let Some(resp) = routes.get(&(qname, qtype)) {
            let mut out = resp.clone();
            out[0..2].copy_from_slice(&id);
            return out;
        }
        // SERVFAIL, zero answers.
        vec![id[0], id[1], 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0]
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeDns;
    use super::*;
    use crate::wire::canned::{name_bytes, response, response_compressed_owner, Rr};
    use crate::wire::{QTYPE_A, QTYPE_SRV};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn srv_routes() -> HashMap<(String, u16), Vec<u8>> {
        let mut routes = HashMap::new();
        routes.insert(
            ("_sip._udp.example.com".to_string(), QTYPE_SRV),
            response(
                0,
                "_sip._udp.example.com",
                QTYPE_SRV,
                &[(
                    "_sip._udp.example.com",
                    Rr::Srv {
                        priority: 1,
                        weight: 5,
                        port: 5060,
                        target: "pbx.example.net".into(),
                        ttl: 60,
                    },
                )],
            ),
        );
        routes.insert(
            ("pbx.example.net".to_string(), QTYPE_A),
            response(
                0,
                "pbx.example.net",
                QTYPE_A,
                &[("pbx.example.net", Rr::A(Ipv4Addr::new(192, 0, 2, 10)))],
            ),
        );
        routes
    }

    #[test]
    fn udp_query_returns_canned_srv() {
        let dns = FakeDns::spawn(srv_routes(), None);
        let client = DnsClient::new(dns.addr, Duration::from_millis(300));
        let msg = client.query("_sip._udp.example.com", QTYPE_SRV).unwrap();
        assert_eq!(msg.rcode, 0);
        assert_eq!(msg.records.len(), 1);
        assert!(matches!(&msg.records[0], crate::wire::Record::Srv(s)
            if s.target == "pbx.example.net" && s.port == 5060));
        dns.shutdown();
    }

    #[test]
    fn udp_discards_mismatched_ids_then_accepts_the_right_one() {
        // Deterministic: hand a socket one wrong-id datagram followed by the
        // right-id answer, then drive recv_matching_udp directly.
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_sock.connect(sender.local_addr().unwrap()).unwrap();
        sender.connect(client_sock.local_addr().unwrap()).unwrap();

        let wrong = response(
            0xAAAA,
            "_sip._udp.example.com",
            QTYPE_SRV,
            &[(
                "_sip._udp.example.com",
                Rr::Srv {
                    priority: 1,
                    weight: 0,
                    port: 5060,
                    target: "late.example.net".into(),
                    ttl: 60,
                },
            )],
        );
        let right = response(
            0xBBBB,
            "_sip._udp.example.com",
            QTYPE_SRV,
            &[(
                "_sip._udp.example.com",
                Rr::Srv {
                    priority: 1,
                    weight: 0,
                    port: 5060,
                    target: "pbx.example.net".into(),
                    ttl: 60,
                },
            )],
        );
        sender.send(&wrong).unwrap();
        sender.send(&right).unwrap();

        let client = DnsClient::new("127.0.0.1:53".parse().unwrap(), Duration::from_secs(2));
        let msg = match client.recv_matching_udp(&client_sock, 0xBBBB).unwrap() {
            UdpRecv::Answer(m) => m,
            other => panic!("expected a matching answer, got {other:?}"),
        };
        assert_eq!(msg.id, 0xBBBB);
        assert!(matches!(&msg.records[0], crate::wire::Record::Srv(s)
            if s.target == "pbx.example.net"));
    }

    #[test]
    fn truncated_udp_answer_falls_back_to_tcp() {
        // UDP: TC=1 empty answer. TCP: the real SRV record.
        let mut tc = vec![0u8; 12];
        tc[2] = 0x82; // QR + TC
        tc[3] = 0x80; // RA
        tc[4..6].copy_from_slice(&1u16.to_be_bytes());
        tc.extend_from_slice(&name_bytes("_sip._udp.example.com"));
        tc.extend_from_slice(&QTYPE_SRV.to_be_bytes());
        tc.extend_from_slice(&1u16.to_be_bytes());

        let tcp_body = response_compressed_owner(0, "_sip._udp.example.com", QTYPE_SRV, {
            let mut d = vec![];
            d.extend_from_slice(&1u16.to_be_bytes());
            d.extend_from_slice(&0u16.to_be_bytes());
            d.extend_from_slice(&5060u16.to_be_bytes());
            d.extend_from_slice(&name_bytes("pbx.example.net"));
            d
        });

        let mut tc_routes = HashMap::new();
        tc_routes.insert(("_sip._udp.example.com".to_string(), QTYPE_SRV), tc);
        let dns = FakeDns::spawn(tc_routes, Some(tcp_body));

        let client = DnsClient::new(dns.addr, Duration::from_millis(500));
        let msg = client.query("_sip._udp.example.com", QTYPE_SRV).unwrap();
        assert!(!msg.truncated);
        assert_eq!(msg.records.len(), 1);
        assert!(matches!(&msg.records[0], crate::wire::Record::Srv(s)
            if s.target == "pbx.example.net"));
        dns.shutdown();
    }

    #[test]
    fn timeout_surfaces_when_server_is_silent() {
        // A UDP socket that receives but never answers.
        let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = blackhole.local_addr().unwrap();
        let client = DnsClient::new(addr, Duration::from_millis(100));
        let err = client.query("x.example.com", QTYPE_A).unwrap_err();
        assert!(matches!(err, DnsError::Timeout));
    }

    #[test]
    fn query_form_responses_are_rejected_qr_bit() {
        // RFC 5452 hardening: a datagram with the QR bit clear is a QUERY,
        // not an answer — even with a matching id it must be discarded
        // (spoofed/reflected-query rejection), surfacing as a timeout.
        let mut routes = HashMap::new();
        routes.insert(
            ("qr.test".to_string(), QTYPE_A),
            // Canned "response" that is actually a QUERY packet (QR=0):
            // encode_query emits flags 0x0100, never 0x8000.
            crate::wire::encode_query(0, "qr.test", QTYPE_A).unwrap(),
        );
        let dns = FakeDns::spawn(routes, None);
        let client = DnsClient::new(dns.addr, Duration::from_millis(100));
        let err = client.query("qr.test", QTYPE_A).unwrap_err();
        assert!(matches!(err, DnsError::Timeout), "got {err:?}");
        dns.shutdown();
    }

    #[test]
    fn udp_queries_work_over_an_ipv6_nameserver() {
        // Regression: resolv.conf may name an IPv6 resolver; the UDP socket
        // must bind that family (an AF_INET bind cannot connect() to v6 and
        // every query would hard-fail into the libc fallback).
        let mut routes = HashMap::new();
        routes.insert(
            ("v6.example.com".to_string(), QTYPE_A),
            response(
                0,
                "v6.example.com",
                QTYPE_A,
                &[("v6.example.com", Rr::A(Ipv4Addr::new(192, 0, 2, 7)))],
            ),
        );
        let dns = FakeDns::spawn_on("[::1]:0".parse().unwrap(), routes, None);
        let client = DnsClient::new(dns.addr, Duration::from_millis(500));
        let msg = client.query("v6.example.com", QTYPE_A).unwrap();
        assert_eq!(msg.records.len(), 1);
        assert!(matches!(&msg.records[0], crate::wire::Record::A { .. }));
        dns.shutdown();
    }
}

#[cfg(test)]
mod bailiwick_tests {
    use super::fake::FakeDns;
    use super::*;
    use crate::wire::canned::{response, Rr};
    use crate::wire::{QTYPE_A, QTYPE_SRV};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn routes(qname: &str, qtype: u16, answers: &[(&str, Rr)]) -> HashMap<(String, u16), Vec<u8>> {
        let mut m = HashMap::new();
        m.insert(
            (qname.to_string(), qtype),
            response(0, qname, qtype, answers),
        );
        m
    }

    // RFC 5452: a record owned by a name OUTSIDE the queried zone must not
    // leak into the resolution — a forged response cannot plant an address
    // for another zone this way. The in-bailiwick record (and case-insensitive
    // owner match) survives.
    #[test]
    fn out_of_bailiwick_records_are_dropped() {
        let dns = FakeDns::spawn(
            routes(
                "sip.example.com",
                QTYPE_A,
                &[
                    ("evil.example.net", Rr::A(Ipv4Addr::new(6, 6, 6, 6))),
                    (
                        "evil.example.com.attacker.io",
                        Rr::A(Ipv4Addr::new(7, 7, 7, 7)),
                    ),
                    ("SIP.EXAMPLE.com", Rr::A(Ipv4Addr::new(1, 2, 3, 4))),
                ],
            ),
            None,
        );
        let msg = DnsClient::new(dns.addr, Duration::from_millis(500))
            .query("sip.example.com", QTYPE_A)
            .expect("query");
        dns.shutdown();
        assert_eq!(
            msg.records.len(),
            1,
            "only the in-bailiwick record survives"
        );
        match &msg.records[0] {
            Record::A { name, addr, .. } => {
                assert_eq!(name.as_str(), "SIP.EXAMPLE.com", "owner preserved verbatim");
                assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4));
            }
            other => panic!("expected A record, got {other:?}"),
        }
    }

    // Strict query-name bailiwick: an ADDITIONAL-section A record for the
    // SRV target (`sipserver.example.com`) is NOT a subdomain of the
    // queried name (`_sip._tcp.example.com`) and is dropped. That is safe
    // BY DESIGN — the resolver never trusts additional-section addresses:
    // every SRV target is resolved through its own dedicated A/AAAA query
    // (`Resolver::lookup_ips`), whose own bailiwick check passes.
    #[test]
    fn strict_bailiwick_drops_additional_section_target_addresses() {
        let dns = FakeDns::spawn(
            routes(
                "_sip._tcp.example.com",
                QTYPE_SRV,
                &[
                    (
                        "_sip._tcp.example.com",
                        Rr::Srv {
                            priority: 1,
                            weight: 2,
                            port: 5060,
                            target: "sipserver.example.com".into(),
                            ttl: 300,
                        },
                    ),
                    ("sipserver.example.com", Rr::A(Ipv4Addr::new(10, 0, 0, 7))),
                ],
            ),
            None,
        );
        let msg = DnsClient::new(dns.addr, Duration::from_millis(500))
            .query("_sip._tcp.example.com", QTYPE_SRV)
            .expect("query");
        dns.shutdown();
        assert_eq!(
            msg.records.len(),
            1,
            "only the SRV itself survives; the target A is re-queried explicitly: {:?}",
            msg.records
        );
        assert!(matches!(&msg.records[0], Record::Srv(_)));
    }

    // A UDP datagram that fills the 4096-byte receive buffer is locally
    // truncated even if the server never set TC. The cut-off message could
    // parse cleanly and silently yield a PARTIAL record set — the client
    // must retry over TCP instead (RFC 1035 §4.2.2).
    #[test]
    fn locally_truncated_udp_falls_back_to_tcp() {
        // >4096 bytes of UDP answer with TC=0 (150 A records ≈ 4.8 KB).
        let many: Vec<(&str, Rr)> = (0..150)
            .map(|i| {
                (
                    "sip.example.com",
                    Rr::A(Ipv4Addr::new(10, (i / 256) as u8, i as u8, 1)),
                )
            })
            .collect();
        let r = routes("sip.example.com", QTYPE_A, &many);
        // The REAL answer, served over TCP only.
        let tcp = response(
            0,
            "sip.example.com",
            QTYPE_A,
            &[("sip.example.com", Rr::A(Ipv4Addr::new(1, 2, 3, 4)))],
        );
        let dns = FakeDns::spawn(r, Some(tcp));
        let msg = DnsClient::new(dns.addr, Duration::from_millis(1500))
            .query("sip.example.com", QTYPE_A)
            .expect("query");
        dns.shutdown();
        assert_eq!(
            msg.records.len(),
            1,
            "TCP fallback replaced the locally-truncated UDP answer"
        );
        match &msg.records[0] {
            Record::A { addr, .. } => assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!("expected A record, got {other:?}"),
        }
    }
}
