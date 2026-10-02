//! End-to-end association tests: a deterministic client↔server loopback with
//! a virtual clock and a controllable lossy "network" (the Task 43 lesson —
//! every wire form is also pinned by hand-built bytes in the unit tests).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use sctp::wire::{parse_packet, Chunk};
use sctp::{ChannelType, CloseReason, SctpConfig, SctpEndpoint, SctpError, SctpEvent};

const RTO: Duration = Duration::from_millis(100);

struct Harness {
    client: SctpEndpoint,
    server: SctpEndpoint,
    now: Instant,
    /// (dst: true = to server / false = to client, packet bytes)
    net: VecDeque<(bool, Vec<u8>)>,
    /// Every packet that ever crossed the "network" (assertions can inspect
    /// wire forms even after `deliver_all` drained them).
    log: Vec<(bool, Vec<u8>)>,
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
            log: Vec::new(),
            client_events: Vec::new(),
            server_events: Vec::new(),
        };
        h.drain_to_net();
        h
    }

    /// Harness with a bounded send buffer (send-buffer-full regression).
    fn new_with_send_buffer(send_buffer_chunks: u32) -> Self {
        let base = Instant::now();
        let client = SctpEndpoint::new_client(
            SctpConfig {
                is_client: true,
                rto_initial: RTO,
                rto_min: Duration::from_millis(50),
                send_buffer_chunks,
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
            log: Vec::new(),
            client_events: Vec::new(),
            server_events: Vec::new(),
        };
        h.drain_to_net();
        h
    }

    fn drain_to_net(&mut self) {
        for p in self.client.drain_outbound() {
            self.log.push((true, p.clone()));
            self.net.push_back((true, p));
        }
        for p in self.server.drain_outbound() {
            self.log.push((false, p.clone()));
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
    // Initiator (client, the DTLS client per RFC 8261 wiring) opens EVEN
    // streams; the responder (DTLS server) odd — RFC 8832 §5.1/§6.
    let c1 = h
        .client
        .open_data_channel("a", "", ChannelType::Reliable, h.now)
        .unwrap();
    let s1 = h
        .server
        .open_data_channel("srv", "", ChannelType::Reliable, h.now)
        .unwrap();
    assert_eq!(c1, 0, "client (INIT sender, DTLS client) must use even ids");
    assert_eq!(s1, 1, "responder (DTLS server) must use odd ids");
    let c2 = h
        .client
        .open_data_channel("b", "", ChannelType::Reliable, h.now)
        .unwrap();
    assert_eq!(c2, 2);
    h.drain_to_net();
    h.deliver_all();
    // Peer OPENs surfaced as events with labels intact.
    let se = h.take_server_events();
    assert!(se
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelOpen { stream: 0, label, .. } if label == "a")));
    let ce = h.take_client_events();
    assert!(ce.iter().any(
        |e| matches!(e, SctpEvent::DataChannelOpen { stream: 1, label, .. } if label == "srv")
    ));
    // And the DCEP ACKs flow back (client gets the ack for its stream 0).
    assert!(ce
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelAck { stream: 0 })));
    assert!(se
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelAck { stream: 1 })));
    assert!(h.client.channels().contains(&0));
    assert!(h.server.channels().contains(&1));
}

/// A DCEP OPEN on a stream whose parity does not match the sender's DTLS
/// role violates RFC 8832 §5.1/§6: it must be dropped WITHOUT a
/// DATA_CHANNEL_ACK (the RFC forbids acking an invalid OPEN), the channel
/// must never register, and the association must stay up.
#[test]
fn dcep_open_on_wrong_parity_is_dropped() {
    let mut h = Harness::new();
    h.handshake();
    assert!(h.client.is_established() && h.server.is_established());

    // Hand-built OPEN as if the DTLS-client peer sent it on stream 1 (odd):
    // the server expects its peer (DTLS client) to open EVEN streams, so
    // this must be ignored.
    let mut open_msg = Vec::new();
    sctp::dcep::encode_open(
        &sctp::dcep::DataChannelOpen {
            label: "wrong-parity".into(),
            protocol: "".into(),
            channel_type: ChannelType::Reliable,
            priority: 0,
        },
        &mut open_msg,
    );
    let bad = sctp::wire::encode_packet(
        5000,
        5000,
        222, // the server's own initiate tag (what it expects on inbound)
        &[Chunk::Data(sctp::wire::DataChunk {
            tsn: 1000,
            stream: 1,
            ssn: 0,
            ppid: sctp::dcep::PPID_DCEP,
            begin: true,
            end: true,
            unordered: false,
            immediate_sack: false,
            payload: open_msg.clone(),
        })],
    );
    let ev = h.server.handle_packet(&bad, h.now);
    assert!(
        !ev.iter()
            .any(|e| matches!(e, SctpEvent::DataChannelOpen { .. })),
        "wrong-parity OPEN must not surface: {ev:?}"
    );
    assert!(
        !h.server.channels().contains(&1),
        "wrong-parity OPEN must not register a channel"
    );
    assert!(h.server.is_established(), "association must survive");
    // No DCEP ACK may leave the server for the dropped OPEN. What DOES
    // leave it now (Task 53: RFC 6525 landed) is the spec close for the
    // bogus channel — an Outgoing SSN Reset Request for stream 1 (the
    // Task 51 "drop" fallback remains only when a reset of ours is already
    // in flight).
    h.drain_to_net();
    let mut saw_reset = false;
    for (_, pkt) in &h.net {
        let parsed = parse_packet(pkt, false).unwrap();
        for chunk in parsed.chunks {
            match chunk {
                Chunk::Data(d) => {
                    assert_ne!(
                        d.ppid,
                        sctp::dcep::PPID_DCEP,
                        "an invalid OPEN must never be acked"
                    );
                }
                Chunk::ReConfig(rc) => {
                    saw_reset = rc.params.iter().any(|p| {
                        matches!(
                            p,
                            sctp::wire::ReConfigParam::OutgoingSsnReset { streams, .. }
                                if streams.contains(&1)
                        )
                    });
                }
                _ => {}
            }
        }
    }
    assert!(
        saw_reset,
        "the wrong-parity OPEN must be closed with a stream reset"
    );

    // The correctly-paritied OPEN (even, from the DTLS client) is accepted.
    let good = sctp::wire::encode_packet(
        5000,
        5000,
        222,
        &[Chunk::Data(sctp::wire::DataChunk {
            tsn: 1001,
            stream: 0,
            ssn: 0,
            ppid: sctp::dcep::PPID_DCEP,
            begin: true,
            end: true,
            unordered: false,
            immediate_sack: false,
            payload: open_msg,
        })],
    );
    let ev = h.server.handle_packet(&good, h.now);
    assert!(
        ev.iter()
            .any(|e| matches!(e, SctpEvent::DataChannelOpen { stream: 0, .. })),
        "valid-parity OPEN must open the channel: {ev:?}"
    );
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
    h.client.shutdown(h.now).unwrap();
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
    h.client.shutdown(h.now).unwrap();
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

/// AUD-2: a send that would exceed `send_buffer_chunks` must be rejected
/// with `SendBufferFull` BEFORE any TSN is consumed — the pre-fix behavior
/// popped already-assigned chunks off the tail, punching a permanent TSN
/// hole that stalled ordered delivery forever.
#[test]
fn send_buffer_overflow_rejects_before_tsn_consumed() {
    let mut h = Harness::new_with_send_buffer(2);
    h.handshake();
    let s = h
        .client
        .open_data_channel("sb", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    // Two 1-chunk messages fill the buffer (nothing acked yet).
    h.client
        .send_message(s, 60, b"one".to_vec(), h.now)
        .unwrap();
    h.client
        .send_message(s, 60, b"two".to_vec(), h.now)
        .unwrap();
    h.drain_to_net();
    assert!(matches!(
        h.client.send_message(s, 60, b"three".to_vec(), h.now),
        Err(SctpError::SendBufferFull)
    ));
    // The rejected burst consumed no TSNs: the two queued messages deliver
    // gap-free.
    h.deliver_all();
    assert_eq!(
        msgs(&h.take_server_events()),
        vec![(s, b"one".to_vec()), (s, b"two".to_vec())]
    );
    // The association is alive and delivers subsequent messages.
    h.client_send(s, b"four".to_vec());
    h.deliver_all();
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"four".to_vec())]);
}

/// AUD-3 (RFC 3758 §3.5): a lost FORWARD-TSN must be regenerated (on its own
/// deadline — no T3 is running once the abandoned chunk left the queue) until
/// the peer's cumulative ack covers it, or the receiver's ordered streams
/// stall forever.
#[test]
fn lost_forward_tsn_is_retransmitted_until_acked() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("pr", "", ChannelType::MaxRetransmits(0), h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    h.client_send(s, b"dead".to_vec());
    assert!(h.drop_first(true));
    h.deliver_all();

    // T3: retransmit budget exhausted → abandon → FORWARD-TSN emitted.
    h.now += RTO;
    h.client.on_timeout(h.now);
    h.server.on_timeout(h.now);
    h.drain_to_net();
    // Lose the FORWARD-TSN (the abandoned chunk is not retransmitted, so it
    // is the only packet heading to the server).
    assert!(h.drop_first(true), "FORWARD-TSN must be in flight");
    h.deliver_all();
    assert_eq!(h.server.stats().ftsn_rx, 0, "the announcement was lost");

    // The dedicated deadline regenerates the announcement.
    let deadline = h.client.poll_timeout().expect("FTSN retransmit deadline");
    h.now = deadline;
    h.client.on_timeout(h.now);
    h.server.on_timeout(h.now);
    h.drain_to_net();
    h.deliver_all();
    assert!(
        h.server.stats().ftsn_rx >= 1,
        "lost FTSN must be regenerated"
    );

    // The receiver skipped the dead message: the next ordered one delivers.
    h.client_send(s, b"alive".to_vec());
    h.deliver_all();
    assert_eq!(msgs(&h.take_server_events()), vec![(s, b"alive".to_vec())]);
}

/// AUD-4 (RFC 9260 §9.2): a lost SHUTDOWN-ACK must not deadlock the
/// exchange — the client's T2 retransmits the SHUTDOWN and the server in
/// ShutdownAckSent re-acknowledges it.
#[test]
fn shutdown_survives_lost_shutdown_ack_via_t2() {
    let mut h = Harness::new();
    h.handshake();
    let _ = h.take_client_events();
    let _ = h.take_server_events();

    h.client.shutdown(h.now).unwrap();
    h.drain_to_net();
    // Deliver the SHUTDOWN; the server replies SHUTDOWN-ACK — lose it.
    let (_, shutdown) = h.net.pop_front().unwrap();
    h.server.handle_packet(&shutdown, h.now);
    h.drain_to_net();
    assert!(h.drop_first(false), "SHUTDOWN-ACK must be in flight");
    h.deliver_all();
    assert!(!h.client.is_closed() && !h.server.is_closed());

    // T2 fires on both sides: the client resends SHUTDOWN, the server
    // (ShutdownAckSent) re-sends SHUTDOWN-ACK → the exchange completes.
    h.advance(RTO);
    let ce = h.take_client_events();
    let se = h.take_server_events();
    assert!(ce.contains(&SctpEvent::Closed(CloseReason::Shutdown)));
    assert!(se.contains(&SctpEvent::Closed(CloseReason::Shutdown)));
    assert!(h.client.is_closed() && h.server.is_closed());
}

/// AUD-4: with the peer dead, T2 retransmission exhaustion aborts the
/// association with `ShutdownTimeout` instead of hanging forever.
#[test]
fn t2_exhaustion_aborts_with_shutdown_timeout() {
    let mut h = Harness::new();
    h.handshake();
    let _ = h.take_client_events();

    h.client.shutdown(h.now).unwrap();
    h.drain_to_net();
    // Black-hole the exchange: drop every client→server packet and never
    // let the peer answer. Pump on poll_timeout until the endpoint aborts.
    let mut events = Vec::new();
    for _ in 0..100 {
        let Some(deadline) = h.client.poll_timeout() else {
            break;
        };
        h.now = h.now.max(deadline);
        events.extend(h.client.on_timeout(h.now));
        h.drain_to_net();
        h.net.retain(|(dst, _)| !*dst);
        if h.client.is_closed() {
            break;
        }
    }
    assert!(
        events.contains(&SctpEvent::Closed(CloseReason::ShutdownTimeout)),
        "T2 exhaustion must surface ShutdownTimeout, got {events:?}"
    );
    assert!(h.client.is_closed());
}

/// AUD-5 (RFC 9260 §6.2.1): the SACK's a_rwnd must discount ALL
/// received-but-undelivered bytes (here: a chunk parked in the out-of-order
/// queue behind a gap), not just some — otherwise the advertised window
/// overstates the buffer and receive memory is unbounded.
#[test]
fn sack_a_rwnd_discounts_undelivered_bytes() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("w", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();

    h.client_send(s, b"first".to_vec());
    assert!(h.drop_first(true));
    h.client_send(s, b"second".to_vec());
    // Deliver "second" by hand and capture the server's SACK: it parks in
    // the ofo queue (6 undelivered payload bytes).
    let (_, data2) = h.net.pop_front().unwrap();
    assert!(h.server.handle_packet(&data2, h.now).is_empty());
    h.drain_to_net();
    let (_, sack_pkt) = h.net.pop_front().unwrap();
    let parsed = parse_packet(&sack_pkt, true).expect("server SACK must parse");
    let sack = match parsed.chunks.first() {
        Some(Chunk::Sack(s)) => s,
        other => panic!("expected SACK, got {other:?}"),
    };
    assert_eq!(sack.gaps.len(), 1, "gap block for the parked chunk");
    let full_window = u64::from(64u32) * 1200; // recv_window_chunks * mtu
    assert_eq!(
        u64::from(sack.a_rwnd),
        full_window - 6,
        "a_rwnd must discount the undelivered payload bytes"
    );
}

/// RFC 8832 §5.1 wire-form pin: DATA_CHANNEL_OPEN rides PPID 50
/// (WEBRTC_DCEP) — not 51. A real peer dispatches on the spec value and
/// silently ignores anything else, so a wrong PPID is invisible to a
/// self-roundtrip test (the Task 43 lesson): the emitted chunk itself is
/// inspected here.
#[test]
fn dcep_open_rides_ppid_50_per_rfc8832() {
    let mut h = Harness::new();
    h.handshake();
    assert!(h.client.is_established());

    let stream = h
        .client
        .open_data_channel("chat", "", ChannelType::Reliable, h.now)
        .unwrap();
    assert_eq!(
        stream, 0,
        "association initiator (DTLS client) uses even ids"
    );
    h.drain_to_net();

    let mut opens = 0;
    for (_, pkt) in &h.net {
        let parsed = parse_packet(pkt, false).unwrap();
        for chunk in parsed.chunks {
            if let Chunk::Data(d) = chunk {
                if d.ppid == sctp::dcep::PPID_DCEP {
                    assert_eq!(d.stream, stream);
                    assert_eq!(d.payload[0], sctp::dcep::MSG_OPEN);
                    opens += 1;
                }
            }
        }
    }
    assert_eq!(opens, 1, "exactly one DATA chunk carries the DCEP OPEN");
    // Deliver it: the server must open the channel and ack in-band.
    h.deliver_all();
    let events = h.take_server_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SctpEvent::DataChannelOpen { stream: 0, .. })),
        "server must surface the peer's DCEP OPEN: {events:?}"
    );
}

/// A user message whose PPID is NOT the DCEP value must be delivered as a
/// user message — the PPID-51 dispatch bug would have swallowed RFC 8831
/// string data (PPID 51) into the DCEP path forever.
#[test]
fn user_data_on_non_dcep_ppids_is_delivered() {
    let mut h = Harness::new();
    h.handshake();
    h.client
        .open_data_channel("chat", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all(); // ack crosses back
    assert!(h
        .take_client_events()
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelAck { stream: 0 })));

    for ppid in [51u32, 53, 60_000] {
        h.client
            .send_message(0, ppid, vec![0x55; 40], h.now)
            .unwrap();
        h.drain_to_net();
        h.deliver_all();
    }
    let got = msgs(&h.take_server_events());
    assert_eq!(got.len(), 3, "every user message must arrive");
    for (i, (_, data)) in got.iter().enumerate() {
        assert_eq!(data, &vec![0x55; 40], "message {i} payload intact");
    }
}

// ------------------------------------------------------------- RFC 6525

/// Extract the Re-configuration parameters from the outbound packets of one
/// side (drained through the harness "network").
fn re_config_params(h: &Harness, dst: bool) -> Vec<sctp::wire::ReConfigParam> {
    let mut out = Vec::new();
    for (d, pkt) in &h.log {
        if *d != dst {
            continue;
        }
        if let Ok(parsed) = parse_packet(pkt, false) {
            for chunk in parsed.chunks {
                if let Chunk::ReConfig(rc) = chunk {
                    out.extend(rc.params);
                }
            }
        }
    }
    out
}

fn closed_streams(events: &[SctpEvent]) -> Vec<u16> {
    events
        .iter()
        .filter_map(|e| match e {
            SctpEvent::DataChannelClosed { stream } => Some(*stream),
            _ => None,
        })
        .collect()
}

/// RFC 8831 §6.7 happy path: the client closes its channel, the server
/// responds and reciprocates (its own Outgoing SSN Reset for the same
/// stream), both sides see `DataChannelClosed`, and the stream id is
/// reusable — a new channel after the close gets the SAME id, and ordered
/// delivery on it works (SSN restarted at 0 on both ends).
#[test]
fn close_channel_completes_both_sides_and_reuses_the_id() {
    let mut h = Harness::new();
    h.handshake();
    let s = h
        .client
        .open_data_channel("chat", "", ChannelType::Reliable, h.now)
        .unwrap();
    assert_eq!(s, 0);
    h.drain_to_net();
    h.deliver_all(); // OPEN → server, ACK → client
    h.drain_to_net();
    h.deliver_all();
    assert!(h
        .take_client_events()
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelAck { stream: 0 })));

    // A message crosses before the close.
    h.client_send(0, b"last words".to_vec());
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    assert_eq!(
        msgs(&h.take_server_events()),
        vec![(0u16, b"last words".to_vec())]
    );

    // Close.
    h.client.close_channel(0, h.now).unwrap();
    h.drain_to_net();
    h.deliver_all(); // request → server; response + reciprocal request → client
    h.drain_to_net();
    h.deliver_all(); // reciprocal response → server
    h.drain_to_net();
    h.deliver_all();

    let client_closed = closed_streams(&h.take_client_events());
    let server_closed = closed_streams(&h.take_server_events());
    assert_eq!(client_closed, vec![0], "client: close completed");
    assert_eq!(server_closed, vec![0], "server: incoming stream was reset");

    // The reset responses from the server: Success-Performed for our RSN
    // (the client's RSN space starts at its initial TSN = 1000).
    let responses = re_config_params(&h, false);
    assert!(
        responses.iter().any(|p| matches!(
            p,
            sctp::wire::ReConfigParam::Response {
                rsn: 1000,
                result: sctp::wire::RC_RESULT_PERFORMED
            }
        )),
        "server must answer the client's reset with Success-Performed: {responses:?}"
    );
    // ... and the reciprocal request for the same stream must have crossed.
    assert!(responses.iter().any(|p| matches!(
        p,
        sctp::wire::ReConfigParam::OutgoingSsnReset { streams, .. } if streams == &vec![0u16]
    )));

    // Both sides' channels are gone: a new OPEN gets the next parity id
    // (2 — the allocator hands out ids at the high-water mark, libwebrtc
    // shape; the freed id itself is proven reusable by the exhaustion test
    // below). The reset semantics are what matter: the new channel's SSN
    // starts at 0 and ordered delivery round-trips.
    let s2 = h
        .client
        .open_data_channel("chat-2", "", ChannelType::Reliable, h.now)
        .unwrap();
    assert_eq!(s2, 2, "the next parity id after the closed one");
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    assert!(h
        .take_client_events()
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelAck { stream: 2 })));
    h.client_send(2, b"reborn".to_vec());
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    assert_eq!(
        msgs(&h.take_server_events()),
        vec![(2u16, b"reborn".to_vec())],
        "ordered delivery works on the new channel"
    );
    assert!(h.client.is_established() && h.server.is_established());
}

/// RFC 6525 guarantees all messages are delivered (or abandoned) before the
/// reset — even when the close is issued while the last message is still
/// unacknowledged on the wire.
#[test]
fn close_delivers_the_in_flight_message_before_the_reset() {
    let mut h = Harness::new();
    h.handshake();
    h.client
        .open_data_channel("chat", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();

    // Send + close in the same pass: both ride the network together.
    h.client_send(0, b"pre-close".to_vec());
    h.client.close_channel(0, h.now).unwrap();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();

    let server_events = h.take_server_events();
    let got = msgs(&server_events);
    assert_eq!(
        got,
        vec![(0u16, b"pre-close".to_vec())],
        "the message must be delivered, not silently dropped by the reset"
    );
    assert_eq!(
        closed_streams(&server_events),
        vec![0],
        "and only then does the channel close"
    );
    // The event order proves the guarantee: Message BEFORE DataChannelClosed.
    let mpos = server_events
        .iter()
        .position(|e| matches!(e, SctpEvent::Message { .. }))
        .unwrap();
    let cpos = server_events
        .iter()
        .position(|e| matches!(e, SctpEvent::DataChannelClosed { .. }))
        .unwrap();
    assert!(mpos < cpos);
}

/// §5.2.2 E2: a RE-CONFIG that overtakes its own data (reordering) enters
/// deferred reset processing — the server answers "In progress" first,
/// holds the post-reset data, and completes when its cumulative point
/// reaches the peer's last assigned TSN.
#[test]
fn deferred_reset_when_the_request_overtakes_its_data() {
    let mut h = Harness::new();
    h.handshake();
    h.client
        .open_data_channel("chat", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    h.take_client_events();
    h.take_server_events();

    // Data (TSN 1001) queued, then the close — both undelivered.
    h.client_send(0, b"post-reset data".to_vec());
    h.client.close_channel(0, h.now).unwrap();
    h.drain_to_net();
    assert!(h.net.len() >= 2, "data and request both queued");

    // Reorder: deliver the REQUEST first.
    let data_pkt = h.net.pop_front().expect("data packet first");
    h.deliver_all(); // request arrives: last_tsn (1001) > cum (1000) → E2
    let responses = re_config_params(&h, false);
    assert!(
        responses.iter().any(|p| matches!(
            p,
            sctp::wire::ReConfigParam::Response {
                rsn: 1000,
                result: sctp::wire::RC_RESULT_IN_PROGRESS
            }
        )),
        "the server must defer: {responses:?}"
    );
    h.drain_to_net();
    h.take_client_events();

    // Now the data arrives: cum reaches 1001 → the deferred reset completes
    // (E3–E5): the message is delivered, the channel closes, and the final
    // Success response follows.
    h.net.push_back(data_pkt);
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();

    let server_events = h.take_server_events();
    assert_eq!(
        msgs(&server_events),
        vec![(0u16, b"post-reset data".to_vec())],
        "the held chunk must be released and delivered"
    );
    assert_eq!(closed_streams(&server_events), vec![0]);
    let responses = re_config_params(&h, false);
    assert!(
        responses.iter().any(|p| matches!(
            p,
            sctp::wire::ReConfigParam::Response {
                rsn: 1000,
                result: sctp::wire::RC_RESULT_PERFORMED
            }
        )),
        "the final Success response must follow the In-progress one: {responses:?}"
    );
    // The client completes its close on the final response.
    assert_eq!(closed_streams(&h.take_client_events()), vec![0]);
}

/// §5.2.1: a retransmitted request gets the SAME response, and processing
/// it again must not re-fire the close event or re-reset the stream.
#[test]
fn duplicate_request_is_answered_with_the_same_response() {
    let mut h = Harness::new();
    h.handshake();
    h.client
        .open_data_channel("chat", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();

    // Client closes; the full exchange completes.
    h.client.close_channel(0, h.now).unwrap();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    h.take_client_events();
    h.take_server_events();

    // The log so far holds the original Response + the server's reciprocal
    // request; scope the replay assertion to what comes AFTER the dup.
    let params_before = re_config_params(&h, false).len();
    assert_eq!(params_before, 2);

    // Hand-built retransmission of the client's original request
    // (RSN 1000 = its initial TSN; the client's last assigned TSN is the
    // OPEN's 1000. The response_seq echo is irrelevant for the replay).
    let req = sctp::wire::encode_packet(
        5000,
        5000,
        222,
        &[Chunk::ReConfig(sctp::wire::ReConfigChunk {
            params: vec![sctp::wire::ReConfigParam::OutgoingSsnReset {
                rsn: 1000,
                response_seq: 1999, // the server's initial TSN minus 1
                last_tsn: 1000,
                streams: vec![0],
            }],
        })],
    );
    let ev = h.server.handle_packet(&req, h.now);
    assert!(
        ev.is_empty(),
        "a retransmitted request must not re-fire events: {ev:?}"
    );
    h.drain_to_net();
    let responses = &re_config_params(&h, false)[params_before..];
    assert_eq!(
        responses,
        vec![sctp::wire::ReConfigParam::Response {
            rsn: 1000,
            result: sctp::wire::RC_RESULT_PERFORMED
        }],
        "the same response must be replayed — and nothing else (no re-fire, \
         no second reciprocal reset)"
    );
    assert!(
        !h.server.channels().contains(&0),
        "and the channel must stay closed"
    );
}

/// A request for a stream the server does not know answers
/// "Success — Nothing to do" (nothing was reset), and the association
/// survives.
#[test]
fn reset_of_an_unknown_stream_answers_nothing_to_do() {
    let mut h = Harness::new();
    h.handshake();
    let req = sctp::wire::encode_packet(
        5000,
        5000,
        222,
        &[Chunk::ReConfig(sctp::wire::ReConfigChunk {
            params: vec![sctp::wire::ReConfigParam::OutgoingSsnReset {
                rsn: 1000,
                response_seq: 1999,
                last_tsn: 1005,
                streams: vec![7],
            }],
        })],
    );
    let ev = h.server.handle_packet(&req, h.now);
    assert!(ev.is_empty());
    h.drain_to_net();
    let responses = re_config_params(&h, false);
    assert_eq!(
        responses,
        vec![sctp::wire::ReConfigParam::Response {
            rsn: 1000,
            result: sctp::wire::RC_RESULT_NOTHING_TO_DO
        }]
    );
    assert!(h.server.is_established());
}

/// A close against a peer that never advertised RFC 6525 support is
/// rejected locally (WrongState), and a send on a closing channel is
/// rejected with ChannelClosing.
#[test]
fn close_channel_state_guards() {
    // Peer without stream-reset support: the server's INIT carries no
    // RE-CONFIG in Supported Extensions, so the client must refuse.
    let base = Instant::now();
    let client = SctpEndpoint::new_client(
        SctpConfig {
            is_client: true,
            rto_initial: RTO,
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
        initial_tag: Some(222),
        initial_tsn: Some(2000),
        cookie_key: Some([7u8; 32]),
        stream_reset: false,
        ..SctpConfig::default()
    });
    let mut h = Harness {
        client,
        server,
        now: base,
        net: VecDeque::new(),
        log: Vec::new(),
        client_events: Vec::new(),
        server_events: Vec::new(),
    };
    h.handshake();
    h.client
        .open_data_channel("chat", "", ChannelType::Reliable, h.now)
        .unwrap();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    assert!(matches!(
        h.client.close_channel(0, h.now),
        Err(SctpError::WrongState(_))
    ));

    // Closing channel: sends are rejected with the dedicated error.
    let mut h2 = Harness::new();
    h2.handshake();
    h2.client
        .open_data_channel("chat", "", ChannelType::Reliable, h2.now)
        .unwrap();
    h2.drain_to_net();
    h2.deliver_all();
    h2.drain_to_net();
    h2.deliver_all();
    h2.client.close_channel(0, h2.now).unwrap();
    assert!(matches!(
        h2.client.send_message(0, 51, b"no".to_vec(), h2.now),
        Err(SctpError::ChannelClosing(0))
    ));
    assert!(matches!(
        h2.client.close_channel(0, h2.now),
        Err(SctpError::ChannelClosing(0))
    ));
}

/// The freed stream id is genuinely reusable: with a tiny stream limit the
/// id space exhausts, and after a completed close the allocator's
/// wrap-around scan hands the freed id out again (RFC 8831 §6.7: streams
/// are available for reuse after a reset).
#[test]
fn freed_stream_id_is_reused_after_exhaustion() {
    let base = Instant::now();
    let client = SctpEndpoint::new_client(
        SctpConfig {
            is_client: true,
            rto_initial: RTO,
            os_streams: 6,
            mis_streams: 6,
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
        os_streams: 6,
        mis_streams: 6,
        initial_tag: Some(222),
        initial_tsn: Some(2000),
        cookie_key: Some([7u8; 32]),
        ..SctpConfig::default()
    });
    let mut h = Harness {
        client,
        server,
        now: base,
        net: VecDeque::new(),
        log: Vec::new(),
        client_events: Vec::new(),
        server_events: Vec::new(),
    };
    h.handshake();

    // Exhaust the even-id space: 0, 2, 4 (limit 6).
    let mut ids = Vec::new();
    for i in 0..3 {
        let id = h
            .client
            .open_data_channel(&format!("ch{i}"), "", ChannelType::Reliable, h.now)
            .unwrap();
        ids.push(id);
        h.drain_to_net();
        h.deliver_all();
        h.drain_to_net();
        h.deliver_all();
    }
    assert_eq!(ids, vec![0, 2, 4]);
    // A fourth open must fail: the space is truly exhausted (nothing freed).
    assert!(h
        .client
        .open_data_channel("ch3", "", ChannelType::Reliable, h.now)
        .is_err());

    // Close channel 0 (full exchange: request, response + reciprocal,
    // final response) — the id frees on both sides.
    h.client.close_channel(0, h.now).unwrap();
    for _ in 0..3 {
        h.drain_to_net();
        h.deliver_all();
    }
    assert_eq!(closed_streams(&h.take_client_events()), vec![0]);
    assert_eq!(closed_streams(&h.take_server_events()), vec![0]);

    // The allocator's wrap-around scan now hands the freed id out again.
    let id = h
        .client
        .open_data_channel("ch4", "", ChannelType::Reliable, h.now)
        .unwrap();
    assert_eq!(id, 0, "the freed id must be handed out after the wrap");
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    assert!(h
        .take_client_events()
        .iter()
        .any(|e| matches!(e, SctpEvent::DataChannelAck { stream: 0 })));
    h.client_send(0, b"reused".to_vec());
    h.deliver_all();
    h.drain_to_net();
    h.deliver_all();
    assert_eq!(
        msgs(&h.take_server_events()),
        vec![(0u16, b"reused".to_vec())],
        "ordered delivery on the reused id (SSN restart accepted)"
    );
}
