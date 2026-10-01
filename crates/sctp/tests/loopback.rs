//! End-to-end association tests: a deterministic client↔server loopback with
//! a virtual clock and a controllable lossy "network" (the Task 43 lesson —
//! every wire form is also pinned by hand-built bytes in the unit tests).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use sctp::{ChannelType, CloseReason, SctpConfig, SctpEndpoint, SctpError, SctpEvent};

const RTO: Duration = Duration::from_millis(100);

struct Harness {
    client: SctpEndpoint,
    server: SctpEndpoint,
    now: Instant,
    /// (dst: true = to server / false = to client, packet bytes)
    net: VecDeque<(bool, Vec<u8>)>,
    client_events: Vec<SctpEvent>,
    server_events: Vec<SctpEvent>,
}

impl Harness {
    fn new() -> Self {
        Self::new_with_heartbeat(None)
    }

    fn new_with_heartbeat(hb: Option<Duration>) -> Self {
        let base = Instant::now();
        let client = SctpEndpoint::new_client(
            SctpConfig {
                is_client: true,
                rto_initial: RTO,
                rto_min: Duration::from_millis(50),
                heartbeat_interval: hb,
                initial_tag: Some(111),
                initial_tsn: Some(1000),
                ..SctpConfig::default()
            },
            base,
        )
        .unwrap();
        let server = SctpEndpoint::new_server(SctpConfig {
            is_client: false,
            rto_initial: RTO,
            rto_min: Duration::from_millis(50),
            heartbeat_interval: hb,
            initial_tag: Some(222),
            initial_tsn: Some(2000),
            cookie_key: Some([7u8; 32]),
            ..SctpConfig::default()
        });
        let mut h = Self {
            client,
            server,
            now: base,
            net: VecDeque::new(),
            client_events: Vec::new(),
            server_events: Vec::new(),
        };
        h.drain_to_net();
        h
    }

    fn drain_to_net(&mut self) {
        for p in self.client.drain_outbound() {
            self.net.push_back((true, p));
        }
        for p in self.server.drain_outbound() {
            self.net.push_back((false, p));
        }
    }

    /// Deliver everything queued (and every response) until quiescent.
    fn deliver_all(&mut self) {
        while let Some((dst, pkt)) = self.net.pop_front() {
            if dst {
                let ev = self.server.handle_packet(&pkt, self.now);
                self.server_events.extend(ev);
            } else {
                let ev = self.client.handle_packet(&pkt, self.now);
                self.client_events.extend(ev);
            }
            self.drain_to_net();
        }
    }

    /// Run the loop until the handshake settles.
    fn handshake(&mut self) {
        self.drain_to_net();
        self.deliver_all();
    }

    /// Advance the virtual clock, fire timers, pump.
    fn advance(&mut self, d: Duration) {
        self.now += d;
        self.client.on_timeout(self.now);
        self.server.on_timeout(self.now);
        self.drain_to_net();
        self.deliver_all();
    }

    /// Remove the first packet heading to `dst` (simulated loss).
    fn drop_first(&mut self, dst: bool) -> bool {
        let pos = self.net.iter().position(|(d, _)| *d == dst);
        if let Some(pos) = pos {
            self.net.remove(pos);
        }
        pos.is_some()
    }

    /// Queue a send from the client and pump it into the network (without
    /// delivering — tests then choose what to drop).
    fn client_send(&mut self, stream: u16, data: Vec<u8>) {
        self.client
            .send_message(stream, 60, data, self.now)
            .unwrap();
        self.drain_to_net();
    }

    fn take_client_events(&mut self) -> Vec<SctpEvent> {
        std::mem::take(&mut self.client_events)
    }

    fn take_server_events(&mut self) -> Vec<SctpEvent> {
        std::mem::take(&mut self.server_events)
    }
}

fn msgs(events: &[SctpEvent]) -> Vec<(u16, Vec<u8>)> {
    events
        .iter()
        .filter_map(|e| match e {
            SctpEvent::Message { stream, data, .. } => Some((*stream, data.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn handshake_completes_both_roles() {
    let mut h = Harness::new();
    h.handshake();
    assert!(h.client.is_established(), "client must be established");
    assert!(h.server.is_established(), "server must be established");
    assert_eq!(h.take_client_events(), vec![SctpEvent::Established]);
    assert_eq!(h.take_server_events(), vec![SctpEvent::Established]);
}

#[test]
fn stream_id_parity_per_rfc8832() {
    let mut h = Harness::new();
    h.handshake();
    // Initiator (client) opens odd streams; responder (server) even.
    let c1 = h
        .client
        .open_data_channel("a", "", ChannelType::Reliable, h.now)
        .unwrap();
    let s1 = h
        .server
        .open_data_channel("srv", "", ChannelType::Reliable, h.now)
        .unwrap();
    assert_eq!(c1, 1, "client (INIT sender) must use odd ids");
    assert_eq!(s1, 0, "responder must use even ids");
    let c2 = h
        .client
        .open_data_channel("b", "", ChannelType::Reliable, h.now)
        .unwrap();
    assert_eq!(c2, 3);
    h.drain_to_net();
    h.deliver_all();
    // Peer OPENs surfaced as events with labels intact.
    let se = h.take_server_events();
    assert!(se
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelOpen { stream: 1, label, .. } if label == "a")));
    let ce = h.take_client_events();
    assert!(ce.iter().any(
        |e| matches!(e, SctpEvent::DataChannelOpen { stream: 0, label, .. } if label == "srv")
    ));
    // And the DCEP ACKs flow back (client gets the ack for its stream 1).
    assert!(ce
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelAck { stream: 1 })));
    assert!(se
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelAck { stream: 0 })));
    assert!(h.client.channels().contains(&0));
    assert!(h.server.channels().contains(&1));
}

#[test]
fn reliable_messages_both_directions() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("chat", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    h.client_send(s, b"hello".to_vec());
    h.deliver_all();
    // Server replies on the same stream id (its own channel entry exists
    // after the peer OPEN was processed).
    h.server
        .send_message(s, 60, b"bonjour".to_vec(), h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    assert_eq!(
        msgs(&h.take_client_events()),
        vec![(s, b"bonjour".to_vec())]
    );
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"hello".to_vec())]);
}

#[test]
fn large_message_fragments_and_reassembles() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("big", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    h.client_send(s, payload.clone());
    h.deliver_all();

    let got = msgs(&h.take_server_events());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, s);
    assert_eq!(got[0].1.len(), payload.len());
    assert_eq!(got[0].1, payload, "reassembled payload must be identical");
    // Sanity: the 5000-byte message rode several DATA chunks under the MTU.
    assert!(h.client.stats().data_chunks_tx >= 5);
}

#[test]
fn lost_packet_retransmitted_on_t3() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("x", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    h.client_send(s, b"survive".to_vec());
    assert!(h.drop_first(true), "must have a client packet to lose");
    h.deliver_all();
    assert!(msgs(&h.take_server_events()).is_empty());

    h.advance(RTO); // T3-RTX fires
    assert_eq!(
        msgs(&h.take_server_events()),
        vec![(s, b"survive".to_vec())]
    );
    assert!(h.client.stats().retransmits_tx >= 1);
}

#[test]
fn ordered_stream_holds_back_after_gap() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("o", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    h.client_send(s, b"one".to_vec());
    assert!(h.drop_first(true));
    h.client_send(s, b"two".to_vec());
    h.deliver_all();
    // "two" must NOT be delivered before "one" (ordered).
    assert!(
        msgs(&h.take_server_events()).is_empty(),
        "ordered delivery violated"
    );
    // The receiver still SACKs with a gap block.
    assert!(h.server.stats().sack_tx >= 1);

    h.advance(RTO); // retransmit "one"
    assert_eq!(
        msgs(&h.take_server_events()),
        vec![(s, b"one".to_vec()), (s, b"two".to_vec())]
    );
}

#[test]
fn unordered_channel_delivers_through_gaps() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("u", "", ChannelType::ReliableUnordered, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    h.client_send(s, b"first".to_vec());
    assert!(h.drop_first(true));
    h.client_send(s, b"second".to_vec());
    h.deliver_all();
    // Unordered: "second" is deliverable immediately.
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"second".to_vec())]);

    h.advance(RTO);
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"first".to_vec())]);
}

#[test]
fn max_retransmits_abandons_and_sends_forward_tsn() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("pr", "", ChannelType::MaxRetransmits(0), h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    // PR message #1 (ordered, ssn 0) is lost on the wire.
    h.client_send(s, b"dead".to_vec());
    assert!(h.drop_first(true));
    h.deliver_all();

    h.advance(RTO); // T3: retransmits becomes 1 > 0 → abandon → FORWARD-TSN
    assert!(msgs(&h.take_server_events()).is_empty());
    assert!(h.client.stats().ftsn_tx >= 1, "sender must announce FTSN");
    assert!(h.server.stats().ftsn_rx >= 1);

    // The NEXT ordered message (ssn 1) is deliverable despite the skip.
    h.client_send(s, b"alive".to_vec());
    h.deliver_all();
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"alive".to_vec())]);
}

#[test]
fn max_lifetime_abandons_expired_message() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("ttl", "", ChannelType::MaxLifetimeMs(50), h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    h.client_send(s, b"stale".to_vec());
    assert!(h.drop_first(true));
    h.deliver_all();
    h.advance(Duration::from_millis(30)); // not yet expired
    assert!(msgs(&h.take_server_events()).is_empty());
    h.advance(Duration::from_millis(30)); // lifetime passed
    h.advance(RTO); // T3 retransmit path must not resurrect it
    assert!(msgs(&h.take_server_events()).is_empty());
    assert!(h.client.stats().ftsn_tx >= 1);

    h.client_send(s, b"fresh".to_vec());
    h.deliver_all();
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"fresh".to_vec())]);
}

#[test]
fn corrupted_packet_is_silently_dropped() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("c", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.client_send(s, b"intact".to_vec());
    h.drain_to_net();

    // Corrupt one queued packet, deliver the rest.
    let pos = h.net.iter().position(|(d, _)| *d).unwrap();
    let (_, mut pkt) = h.net.remove(pos).unwrap();
    let mid = pkt.len() / 2;
    pkt[mid] ^= 0xFF;
    h.net.push_back((true, pkt));
    h.deliver_all();
    assert!(
        msgs(&h.take_server_events()).is_empty(),
        "corrupt DATA drops"
    );

    // The honest retransmission still gets through.
    h.advance(RTO);
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"intact".to_vec())]);
}

#[test]
fn duplicate_packet_reported() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("d", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.client_send(s, b"once".to_vec());
    h.drain_to_net();
    // Duplicate the DATA packet.
    let pos = h.net.iter().position(|(d, _)| *d).unwrap();
    let dup = h.net.get(pos).cloned().unwrap();
    h.net.push_back(dup);
    h.deliver_all();
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"once".to_vec())]);
    assert!(h.server.stats().duplicates_rx >= 1);
}

#[test]
fn graceful_shutdown_three_way() {
    let mut h = Harness::new();
    h.handshake();
    let _ = h.take_client_events();
    let _ = h.take_server_events();
    h.client.shutdown().unwrap();
    h.drain_to_net();
    h.deliver_all();
    assert_eq!(
        h.take_client_events(),
        vec![SctpEvent::Closed(CloseReason::Shutdown)]
    );
    assert_eq!(
        h.take_server_events(),
        vec![SctpEvent::Closed(CloseReason::Shutdown)]
    );
    assert!(h.client.is_closed() && h.server.is_closed());
}

#[test]
fn shutdown_defers_until_outstanding_acked() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("sd", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    h.client_send(s, b"payload".to_vec());
    h.client.shutdown().unwrap();
    h.drain_to_net();
    h.deliver_all();
    // Data still delivered, then the shutdown exchange runs. Snapshot both
    // sides once — taking twice would swallow the Closed event.
    let se = h.take_server_events();
    let ce = h.take_client_events();
    assert_eq!(msgs(&se), vec![(s, b"payload".to_vec())]);
    assert!(ce.contains(&SctpEvent::Closed(CloseReason::Shutdown)));
    assert!(se.contains(&SctpEvent::Closed(CloseReason::Shutdown)));
}

#[test]
fn abort_propagates_to_peer() {
    let mut h = Harness::new();
    h.handshake();
    let _ = h.take_client_events();
    let _ = h.take_server_events();
    let ev = h.client.abort();
    assert_eq!(ev, vec![SctpEvent::Closed(CloseReason::LocalClose)]);
    h.drain_to_net();
    h.deliver_all();
    let se = h.take_server_events();
    assert!(matches!(
        se.first(),
        Some(SctpEvent::Closed(CloseReason::Aborted(_)))
    ));
    assert!(h.server.is_closed());
}

#[test]
fn handshake_survives_lost_cookie_echo() {
    let mut h = Harness::new();
    // Deliver INIT → server queues INIT-ACK.
    let (_, init) = h.net.pop_front().unwrap();
    h.server_events.extend(h.server.handle_packet(&init, h.now));
    h.drain_to_net();
    // Deliver INIT-ACK → client queues COOKIE-ECHO.
    let (_, init_ack) = h.net.pop_front().unwrap();
    h.client_events
        .extend(h.client.handle_packet(&init_ack, h.now));
    h.drain_to_net();
    // Drop the COOKIE-ECHO.
    assert!(h.drop_first(true), "COOKIE-ECHO must be in flight");
    h.deliver_all();
    assert!(!h.client.is_established());

    h.advance(RTO); // T1-COOKIE retransmission
    assert!(
        h.client.is_established(),
        "T1-COOKIE retransmit must recover"
    );
    assert!(h.server.is_established());
}

#[test]
fn forged_cookie_is_rejected_by_mac() {
    let mut h = Harness::new();
    // Drive the handshake to the COOKIE-ECHO step and capture it.
    let (_, init) = h.net.pop_front().unwrap();
    h.server.handle_packet(&init, h.now);
    h.drain_to_net();
    let (_, init_ack) = h.net.pop_front().unwrap();
    h.client.handle_packet(&init_ack, h.now);
    h.drain_to_net();
    let (_, cookie_echo) = h.net.pop_front().unwrap();
    assert!(
        cookie_echo.len() > 68,
        "COOKIE-ECHO carries the 68-byte cookie"
    );

    // A server with a DIFFERENT cookie key must reject it silently.
    let mut stranger = SctpEndpoint::new_server(SctpConfig {
        is_client: false,
        cookie_key: Some([9u8; 32]),
        ..SctpConfig::default()
    });
    let events = stranger.handle_packet(&cookie_echo, h.now);
    assert!(
        events.is_empty(),
        "no Established event for a forged cookie"
    );
    assert!(!stranger.is_established());
    assert!(
        stranger.drain_outbound().is_empty(),
        "no COOKIE-ACK for a forged cookie"
    );
}

#[test]
fn heartbeat_keeps_association_alive() {
    let mut h = Harness::new_with_heartbeat(Some(Duration::from_millis(200)));
    h.handshake();
    h.advance(Duration::from_millis(200));
    h.advance(Duration::from_millis(200));
    assert!(h.client.is_established() && h.server.is_established());
    // Heartbeats flowed both ways (packets after the handshake settled).
    assert!(h.server.stats().packets_rx >= 3);
    assert!(h.client.stats().packets_rx >= 3);
}

#[test]
fn poll_timeout_exposes_timer_deadlines() {
    let h = Harness::new();
    let t = h
        .client
        .poll_timeout()
        .expect("client in InitSent must have a T1 deadline");
    assert!(t > h.now);
}

#[test]
fn message_size_cap_and_stream_checks() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("m", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();
    let too_big = vec![0u8; SctpConfig::default().max_message_size + 1];
    assert!(matches!(
        h.client.send_message(s, 60, too_big, h.now),
        Err(SctpError::MessageTooLarge(_))
    ));
    // Unknown stream rejected.
    assert!(matches!(
        h.client.send_message(999, 60, b"x".to_vec(), h.now),
        Err(SctpError::UnknownStream(999))
    ));
    // Operations before establishment rejected.
    let mut fresh = Harness::new();
    assert!(matches!(
        fresh
            .client
            .open_data_channel("nope", "", ChannelType::Reliable, fresh.now),
        Err(SctpError::WrongState(_))
    ));
}
