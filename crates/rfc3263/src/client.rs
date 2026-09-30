//! DNS query transport: UDP with one retransmission, automatic fallback to
//! TCP when a response carries the TC (truncation) bit, per RFC 1035 §4.2.
//!
//! Blocking std sockets — RFC 3263 resolution happens once per trunk setup,
//! not per packet, so a synchronous client keeps the API honest and the
//! dependencies at zero.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::wire::{encode_query, parse_response, DnsError, Message};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
/// UDP is tried twice (initial + one retransmission) before giving up.
const UDP_ATTEMPTS: usize = 2;

/// Monotonic query-id source: xorshift state seeded from the clock, mixed
/// with a process-wide counter so concurrent resolvers cannot collide.
static ID_COUNTER: AtomicU32 = AtomicU32::new(0);

fn next_query_id() -> u16 {
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs() << 20))
        .unwrap_or(0x9E3779B97F4A7C15)
        | 1;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
    (state as u16) ^ (n as u16).wrapping_mul(0x9E37)
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
        let msg = self.query_udp(id, &packet)?;
        if msg.truncated {
            self.query_tcp(id, &packet)
        } else {
            Ok(msg)
        }
    }

    fn query_udp(&self, id: u16, packet: &[u8]) -> Result<Message, DnsError> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(self.server)?;
        sock.set_write_timeout(Some(self.timeout))?;
        for _ in 0..UDP_ATTEMPTS {
            sock.send(packet)?;
            if let Some(msg) = self.recv_matching_udp(&sock, id)? {
                return Ok(msg);
            }
            // Timeout with no matching response: retransmit.
        }
        Err(DnsError::Timeout)
    }

    /// Waits up to `timeout`, discarding malformed and mismatched-ID
    /// datagrams (late answers to a previous query are not answers).
    fn recv_matching_udp(&self, sock: &UdpSocket, id: u16) -> Result<Option<Message>, DnsError> {
        let deadline = Instant::now() + self.timeout;
        let mut buf = [0u8; 4096];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            sock.set_read_timeout(Some(deadline - now))?;
            match sock.recv(&mut buf) {
                Ok(n) => {
                    if let Ok(msg) = parse_response(&buf[..n]) {
                        if msg.id == id {
                            return Ok(Some(msg));
                        }
                    }
                    // Malformed or foreign datagram: keep waiting.
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
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
        if msg.id != id {
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
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = tcp.local_addr().unwrap().port();
            let udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
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
        let msg = client
            .recv_matching_udp(&client_sock, 0xBBBB)
            .unwrap()
            .expect("matching answer within timeout");
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
}
