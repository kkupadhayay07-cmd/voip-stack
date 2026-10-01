//! The SCTP association state machine ([RFC 9260] §4-§8, [RFC 3758]).
//!
//! One [`SctpEndpoint`] is one association. It never touches I/O: inbound
//! bytes go through [`SctpEndpoint::handle_packet`] (an SCTP packet as a
//! whole — over DTLS that is the DTLS record payload per RFC 8261), outbound
//! packets come out of [`SctpEndpoint::drain_outbound`]. All timers are
//! driven by the caller through [`SctpEndpoint::poll_timeout`] +
//! [`SctpEndpoint::on_timeout`] with an injected `Instant`, which makes the
//! whole engine testable on a virtual clock.
//!
//! Implemented per spec: four-way handshake with MAC-protected cookie
//! (HMAC-SHA256, truncated to 16 bytes), verification-tag rules, TSN window
//! with gap-block SACKs and duplicate reporting, T3-RTX with RFC 6298 RTO
//! estimation (Karn's rule), cwnd slow start / congestion avoidance and
//! peer-a_rwnd flow control, message fragmentation, ordered/unordered
//! reassembly, RFC 3758 abandonment (max-retransmits and max-packet-lifetime)
//! with FORWARD-TSN, heartbeat exchange, graceful SHUTDOWN and ABORT.
//!
//! Simplified (each documented where it appears): no multi-homing, no SACK
//! delay (every DATA packet is SACKed immediately), DCEP establishment
//! messages are sent reliably+ordered regardless of channel policy, no
//! association-level idle timeout (reliable data retransmits forever; the
//! caller can abort).
//!
//! [RFC 9260]: https://datatracker.ietf.org/doc/html/rfc9260
//! [RFC 3758]: https://datatracker.ietf.org/doc/html/rfc3758

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::dcep::{self, ChannelType, PPID_DCEP_ACK, PPID_DCEP_OPEN};
use crate::wire::{self, Chunk, DataChunk, SackBlock, SctpError};
use crate::{CloseReason, SctpConfig, SctpEvent};

/// Handshake retransmission budget for T1-INIT / T1-COOKIE (RFC 9260 §4.1).
pub const MAX_INIT_RETRANS: u32 = 8;
/// Cookie MAC length (HMAC-SHA256 truncated).
const COOKIE_MAC_LEN: usize = 16;
/// Common header (12) + DATA fixed fields (4+12) — the fragmentation budget
/// for user payload in one MTU-sized packet.
const DATA_OVERHEAD: usize = 28;
/// DATA chunk wire size without payload: 4-byte chunk header + 12 bytes of
/// TSN/stream/ssn/ppid fields.
const DATA_CHUNK_FIXED: usize = 16;
/// Maximum duplicate TSNs reported in one SACK.
const MAX_DUPS_IN_SACK: usize = 32;
/// Inbound user messages buffered per stream while awaiting DCEP OPEN.
const PRE_DCEP_BUFFER: usize = 16;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------- PRNG

/// Process-wide xorshift64* state seeded from the clock (same pattern the
/// `rfc3263` crate uses for query IDs). Tests bypass it via config overrides.
fn next_random() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut s = STATE.load(Ordering::Relaxed);
    if s == 0 {
        s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
    }
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    STATE.store(s, Ordering::Relaxed);
    s
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ------------------------------------------------------------ seq helpers

/// `a` is before `b` in wrapping u32 order (distance < 2^31).
fn tsn_lt(a: u32, b: u32) -> bool {
    let d = b.wrapping_sub(a);
    d != 0 && d < 0x8000_0000
}

fn tsn_le(a: u32, b: u32) -> bool {
    a == b || tsn_lt(a, b)
}

fn tsn_gt(a: u32, b: u32) -> bool {
    tsn_lt(b, a)
}

fn ssn_lt(a: u16, b: u16) -> bool {
    let d = b.wrapping_sub(a);
    d != 0 && d < 0x8000
}

fn ssn_ge(a: u16, b: u16) -> bool {
    !ssn_lt(a, b)
}

fn ssn_le(a: u16, b: u16) -> bool {
    a == b || ssn_lt(a, b)
}

// ---------------------------------------------------------------- state

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Server: waiting for INIT. (A client constructor leaves InitSent.)
    Closed,
    /// Client: INIT sent.
    InitSent,
    /// Client: COOKIE-ECHO sent.
    CookieSent,
    /// Server: INIT-ACK sent, waiting for COOKIE-ECHO.
    CookieEchoed,
    Established,
    /// We initiated the graceful shutdown; SHUTDOWN sent.
    ShutdownSent,
    /// Peer initiated; we replied SHUTDOWN-ACK.
    ShutdownAckSent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Policy {
    Reliable,
    MaxRetrans(u32),
    LifetimeMs(u32),
}

#[derive(Debug, Clone)]
struct InFlight {
    tsn: u32,
    stream: u16,
    ssn: u16,
    ppid: u32,
    unordered: bool,
    begin: bool,
    end: bool,
    payload: Vec<u8>,
    policy: Policy,
    msg_id: u64,
    /// Wire size (header + body), for flow-control accounting.
    size: usize,
    sent: bool,
    first_sent: Option<Instant>,
    last_sent: Option<Instant>,
    retransmits: u32,
    abandoned: bool,
}

impl InFlight {
    fn to_chunk(&self) -> DataChunk {
        DataChunk {
            tsn: self.tsn,
            stream: self.stream,
            ssn: self.ssn,
            ppid: self.ppid,
            begin: self.begin,
            end: self.end,
            unordered: self.unordered,
            immediate_sack: false,
            payload: self.payload.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct Channel {
    channel_type: ChannelType,
    /// Next ordered stream sequence number for outbound messages.
    ssn: u16,
    /// We sent DCEP OPEN and are waiting for the peer's ACK.
    awaiting_ack: bool,
}

/// One user message being reassembled (a B..E run; classic SCTP never
/// interleaves fragments, so the run is TSN-contiguous).
#[derive(Debug, Default)]
struct FragRun {
    ssn: u16,
    first_tsn: u32,
    pieces: BTreeMap<u32, DataChunk>,
    end_seen: bool,
}

impl FragRun {
    fn complete(&self) -> bool {
        self.end_seen
            && self
                .pieces
                .last_key_value()
                .map(|(last, _)| {
                    last.wrapping_sub(self.first_tsn) as usize + 1 == self.pieces.len()
                })
                .unwrap_or(false)
    }

    fn assemble(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for c in self.pieces.values() {
            data.extend_from_slice(&c.payload);
        }
        data
    }
}

/// Ordered reassembly bookkeeping for one stream.
#[derive(Debug, Default)]
struct OrderedBuf {
    /// Next expected inbound SSN.
    expected: u16,
    current: Option<FragRun>,
    /// Completed-or-in-progress runs parked out of order (ssn > expected).
    parked: HashMap<u16, FragRun>,
}

/// Unordered reassembly: a single run at a time (classic SCTP guarantee).
#[derive(Debug, Default)]
struct UnorderedBuf {
    current: Option<FragRun>,
}

/// Timer bookkeeping for T1-INIT / T1-COOKIE.
#[derive(Debug)]
struct T1 {
    deadline: Instant,
    attempts: u32,
    /// The encoded packet to retransmit.
    payload: Vec<u8>,
}

/// Counters for observability (exposed via `SctpEndpoint::stats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AssociationStats {
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub data_chunks_rx: u64,
    pub data_chunks_tx: u64,
    pub retransmits_tx: u64,
    pub sack_rx: u64,
    pub sack_tx: u64,
    pub duplicates_rx: u64,
    pub messages_rx: u64,
    pub messages_tx: u64,
    pub ftsn_rx: u64,
    pub ftsn_tx: u64,
    pub abandoned: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
}

/// One SCTP association, transport-agnostic (see module docs).
pub struct SctpEndpoint {
    cfg: SctpConfig,
    state: State,
    cookie_key: [u8; 32],

    // ---- identity (handshake) ----
    local_tag: u32,
    local_tsn: u32, // next TSN to assign
    peer_tag: u32,
    peer_initial_tsn: u32,
    peer_a_rwnd: usize,
    peer_mis: u16,
    peer_forward_tsn: bool,
    /// Last INIT seen (server) — lets a stale cookie be refreshed with a new
    /// INIT-ACK without keeping pre-association sessions.
    last_init: Option<wire::InitChunk>,

    // ---- timers ----
    t1: Option<T1>,
    rto: Duration,
    srtt: Option<Duration>,
    rttvar: Duration,
    t3_deadline: Option<Instant>,
    heartbeat_deadline: Option<Instant>,
    heartbeat_counter: u64,

    // ---- send side ----
    inflight: VecDeque<InFlight>,
    outstanding_bytes: usize,
    cwnd: usize,
    ssthresh: usize,
    partial_bytes_acked: usize,
    msg_counter: u64,
    peer_cum: u32,
    /// Ordered streams already reported in a FORWARD-TSN (sid → ssn).
    ftsn_reported: HashMap<u16, u16>,

    // ---- receive side ----
    cum_tsn: u32,
    ofo: BTreeMap<u32, DataChunk>,
    dups: Vec<u32>,
    need_sack: bool,
    ordered: HashMap<u16, OrderedBuf>,
    unordered: UnorderedBuf,
    pre_dcep: HashMap<u16, Vec<(u32, Vec<u8>)>>,

    // ---- channels ----
    channels: HashMap<u16, Channel>,
    next_outbound_stream: u16,

    // ---- shutdown bookkeeping ----
    shutdown_pending: bool,

    // ---- output ----
    outbox: VecDeque<Vec<u8>>,

    stats: AssociationStats,
    closed: bool,
}

impl SctpEndpoint {
    // ------------------------------------------------------------ create

    fn base(cfg: SctpConfig) -> Self {
        let cookie_key = cfg.cookie_key.unwrap_or_else(|| {
            let mut k = [0u8; 32];
            for c in k.iter_mut() {
                *c = next_random() as u8;
            }
            k
        });
        let local_tag = cfg
            .initial_tag
            .unwrap_or_else(|| (next_random() | 1) as u32);
        let local_tsn = cfg.initial_tsn.unwrap_or_else(|| next_random() as u32);
        // RFC 9260 §7.2.1: cwnd = min(4*MTU, max(2*MTU, 4380)).
        let cwnd = (cfg.mtu * 4).min((cfg.mtu * 2).max(4380));
        Self {
            rto: cfg.rto_initial,
            rttvar: cfg.rto_initial / 2,
            cwnd,
            ssthresh: usize::MAX,
            next_outbound_stream: if cfg.is_client { 1 } else { 0 },
            cookie_key,
            local_tag,
            local_tsn,
            state: State::Closed,
            cfg,
            inflight: VecDeque::new(),
            ofo: BTreeMap::new(),
            dups: Vec::new(),
            channels: HashMap::new(),
            pre_dcep: HashMap::new(),
            ftsn_reported: HashMap::new(),
            ordered: HashMap::new(),
            peer_tag: 0,
            peer_initial_tsn: 0,
            peer_a_rwnd: 0,
            peer_mis: 0,
            peer_cum: 0,
            outstanding_bytes: 0,
            partial_bytes_acked: 0,
            msg_counter: 0,
            cum_tsn: 0,
            t1: None,
            srtt: None,
            t3_deadline: None,
            heartbeat_deadline: None,
            heartbeat_counter: 0,
            unordered: UnorderedBuf::default(),
            shutdown_pending: false,
            outbox: VecDeque::new(),
            stats: AssociationStats::default(),
            need_sack: false,
            closed: false,
            peer_forward_tsn: false,
            last_init: None,
        }
    }

    /// Association initiator: builds and queues the INIT immediately.
    pub fn new_client(cfg: SctpConfig, now: Instant) -> Result<Self, SctpError> {
        let mut ep = Self::base(cfg);
        ep.state = State::InitSent;
        let init = ep.build_init();
        let pkt = wire::encode_packet(ep.cfg.local_port, ep.cfg.remote_port, 0, &[init]);
        ep.t1 = Some(T1 {
            deadline: now + ep.rto,
            attempts: 0,
            payload: pkt.clone(),
        });
        ep.outbox.push_back(pkt);
        Ok(ep)
    }

    /// Responder role: waits for the peer's INIT. Nothing is sent until then.
    pub fn new_server(cfg: SctpConfig) -> Self {
        Self::base(cfg)
    }

    fn build_init(&self) -> Chunk {
        Chunk::Init(wire::InitChunk {
            initiate_tag: self.local_tag,
            a_rwnd: self.recv_window_bytes(),
            os: self.cfg.os_streams,
            mis: self.cfg.mis_streams,
            initial_tsn: self.local_tsn,
            params: if self.cfg.forward_tsn {
                vec![wire::RawParam {
                    ptype: wire::PT_SUPPORTED_EXTENSIONS,
                    value: vec![wire::CT_FORWARD_TSN],
                }]
            } else {
                Vec::new()
            },
        })
    }

    fn recv_window_bytes(&self) -> u32 {
        self.cfg.recv_window_chunks * self.cfg.mtu as u32
    }

    // -------------------------------------------------------------- io

    /// Drain fully-encoded SCTP packets for the transport (DTLS payload).
    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbox.drain(..).collect()
    }

    /// Feed one inbound SCTP packet. Malformed packets and packets failing
    /// verification-tag rules are silently dropped (RFC 9260 §8.4), so the
    /// return value is the only output.
    pub fn handle_packet(&mut self, buf: &[u8], now: Instant) -> Vec<SctpEvent> {
        let mut events = Vec::new();
        if self.closed {
            return events;
        }
        self.stats.packets_rx += 1;
        let pkt = match wire::parse_packet(buf, true) {
            Ok(p) => p,
            Err(_) => return events,
        };
        if pkt.dst_port != self.cfg.local_port || pkt.src_port != self.cfg.remote_port {
            return events;
        }

        for chunk in pkt.chunks {
            // Verification-tag rules (RFC 9260 §8.5.1): INIT carries vtag 0;
            // a T-bit ABORT/SHUTDOWN-COMPLETE may carry the peer's tag
            // (reflected); everything else must carry our tag.
            let vtag_ok = match &chunk {
                Chunk::Init(_) => pkt.vtag == 0,
                Chunk::Abort { reflected, .. } | Chunk::ShutdownComplete { reflected } => {
                    (*reflected && pkt.vtag == self.peer_tag) || pkt.vtag == self.local_tag
                }
                _ => pkt.vtag == self.local_tag,
            };
            if !vtag_ok {
                continue;
            }
            self.handle_chunk(chunk, now, &mut events);
            if self.closed {
                break;
            }
        }
        if self.need_sack && !self.closed {
            self.need_sack = false;
            self.send_sack_now();
        }
        self.flush(now);
        events
    }

    fn handle_chunk(&mut self, chunk: Chunk, now: Instant, events: &mut Vec<SctpEvent>) {
        match chunk {
            Chunk::Init(init) => self.on_init(init, now),
            Chunk::InitAck(init) => self.on_init_ack(init, now, events),
            Chunk::CookieEcho { cookie } => self.on_cookie_echo(cookie, now, events),
            Chunk::CookieAck => self.on_cookie_ack(now, events),
            Chunk::Data(d) => self.on_data(d, events),
            Chunk::Sack(s) => self.on_sack(s, now),
            Chunk::Heartbeat { info } => {
                self.queue_packet(&[Chunk::HeartbeatAck { info }]);
            }
            Chunk::HeartbeatAck { info } => self.on_heartbeat_ack(info),
            Chunk::ForwardTsn {
                new_cum_tsn,
                streams,
            } => self.on_forward_tsn(new_cum_tsn, &streams),
            Chunk::Abort { causes, .. } => {
                let raw = (!causes.is_empty()).then(|| {
                    causes
                        .iter()
                        .flat_map(|c| c.value.iter().copied())
                        .collect::<Vec<u8>>()
                });
                self.close_out();
                events.push(SctpEvent::Closed(CloseReason::Aborted(raw)));
            }
            Chunk::Error { .. } => {
                // RFC 9260 §8.5: ERROR is informational — counted, not acted on.
            }
            Chunk::Shutdown { .. } => self.on_shutdown(),
            Chunk::ShutdownAck => self.on_shutdown_ack(events),
            Chunk::ShutdownComplete { .. } => self.on_shutdown_complete(events),
            Chunk::Unknown { .. } => {
                // RFC 9260 §3.3.1 report classes — reporting is suppressed
                // (documented gap); the chunk is skipped.
            }
        }
    }

    // ------------------------------------------------------- handshake

    fn on_init(&mut self, init: wire::InitChunk, now: Instant) {
        if matches!(
            self.state,
            State::Established | State::ShutdownSent | State::ShutdownAckSent
        ) {
            return; // association restart is not supported (documented)
        }
        self.peer_tag = init.initiate_tag;
        self.peer_initial_tsn = init.initial_tsn;
        self.peer_a_rwnd = init.a_rwnd as usize;
        self.peer_mis = init.mis;
        self.peer_forward_tsn = supports_forward_tsn(&init);
        self.cum_tsn = init.initial_tsn.wrapping_sub(1);
        self.peer_cum = self.local_tsn.wrapping_sub(1);
        self.last_init = Some(init.clone());

        let cookie = self.build_cookie(&init);
        let mut params = vec![wire::RawParam {
            ptype: wire::PT_STATE_COOKIE,
            value: cookie,
        }];
        if self.cfg.forward_tsn {
            params.push(wire::RawParam {
                ptype: wire::PT_SUPPORTED_EXTENSIONS,
                value: vec![wire::CT_FORWARD_TSN],
            });
        }
        let init_ack = Chunk::InitAck(wire::InitChunk {
            initiate_tag: self.local_tag,
            a_rwnd: self.recv_window_bytes(),
            os: self.cfg.os_streams,
            mis: self.cfg.mis_streams,
            initial_tsn: self.local_tsn,
            params,
        });
        self.queue_packet(&[init_ack]);
        self.state = State::CookieEchoed;
        let _ = now;
    }

    fn on_init_ack(&mut self, init: wire::InitChunk, now: Instant, events: &mut Vec<SctpEvent>) {
        if self.state != State::InitSent {
            return;
        }
        self.peer_tag = init.initiate_tag;
        self.peer_initial_tsn = init.initial_tsn;
        self.peer_a_rwnd = init.a_rwnd as usize;
        self.peer_mis = init.mis;
        self.peer_forward_tsn = supports_forward_tsn(&init);
        self.cum_tsn = init.initial_tsn.wrapping_sub(1);
        self.peer_cum = self.local_tsn.wrapping_sub(1);
        let cookie = match init.param(wire::PT_STATE_COOKIE) {
            Some(c) if !c.is_empty() => c.to_vec(),
            _ => {
                let reason = "INIT-ACK without state cookie".to_string();
                self.close_out();
                events.push(SctpEvent::Closed(CloseReason::HandshakeRejected(reason)));
                return;
            }
        };
        let echo = Chunk::CookieEcho { cookie };
        let pkt = wire::encode_packet(
            self.cfg.local_port,
            self.cfg.remote_port,
            self.peer_tag,
            &[echo],
        );
        self.t1 = Some(T1 {
            deadline: now + self.rto,
            attempts: 0,
            payload: pkt.clone(),
        });
        self.outbox.push_back(pkt);
        self.state = State::CookieSent;
    }

    fn on_cookie_ack(&mut self, now: Instant, events: &mut Vec<SctpEvent>) {
        if self.state != State::CookieSent {
            return;
        }
        self.t1 = None;
        self.state = State::Established;
        self.heartbeat_deadline = self.cfg.heartbeat_interval.map(|i| now + i);
        events.push(SctpEvent::Established);
    }

    fn on_cookie_echo(&mut self, cookie: Vec<u8>, now: Instant, events: &mut Vec<SctpEvent>) {
        if self.state == State::Established {
            // Retransmitted COOKIE-ECHO — re-ack idempotently.
            self.queue_packet(&[Chunk::CookieAck]);
            return;
        }
        if self.state != State::CookieEchoed && self.state != State::Closed {
            return;
        }
        if !cookie_valid_mac(&self.cookie_key, &cookie) {
            return; // forged / malformed: silently discarded (RFC 9260 §5.1.4)
        }
        let parsed = match parse_cookie(&cookie) {
            Ok(c) => c,
            Err(_) => return,
        };
        let stale_ms = now_unix_ms().saturating_sub(parsed.issued_ms);
        if stale_ms > self.cfg.cookie_lifetime.as_millis() as u64 {
            // Stale cookie (RFC 9260 §5.1.5): send a fresh INIT-ACK if we
            // still have the INIT that produced it.
            if let Some(init) = self.last_init.clone() {
                self.on_init(init, now);
            }
            return;
        }
        self.local_tag = parsed.server_tag;
        self.local_tsn = parsed.server_tsn;
        self.peer_tag = parsed.client_tag;
        self.peer_initial_tsn = parsed.client_tsn;
        self.peer_a_rwnd = parsed.client_rwnd as usize;
        self.peer_mis = parsed.client_mis;
        self.peer_forward_tsn = parsed.client_forward_tsn;
        self.cum_tsn = parsed.client_tsn.wrapping_sub(1);
        self.peer_cum = parsed.server_tsn.wrapping_sub(1);
        self.state = State::Established;
        self.heartbeat_deadline = self.cfg.heartbeat_interval.map(|i| now + i);
        self.queue_packet(&[Chunk::CookieAck]);
        events.push(SctpEvent::Established);
    }

    // ------------------------------------------------------- data recv

    fn on_data(&mut self, d: DataChunk, events: &mut Vec<SctpEvent>) {
        if self.state != State::Established && self.state != State::ShutdownSent {
            return;
        }
        self.stats.data_chunks_rx += 1;
        let dist = d.tsn.wrapping_sub(self.cum_tsn);
        if dist == 0 || dist > 0x8000_0000 || dist > self.cfg.recv_window_chunks {
            // At/below the cumulative point, or beyond the advertised
            // out-of-order window → treat as duplicate (bounded memory).
            self.record_dup(d.tsn);
            return;
        }
        if self.ofo.contains_key(&d.tsn) {
            self.record_dup(d.tsn);
            return;
        }
        self.ofo.insert(d.tsn, d.clone());
        // Unordered messages are delivered on arrival — TSN contiguity gates
        // only ordered delivery (RFC 9260 §6.6).
        if d.unordered {
            self.feed_unordered(d, events);
        }
        // Advance the cumulative point through contiguous TSNs, delivering
        // the ordered messages that become available.
        while let Some(c) = self.ofo.remove(&(self.cum_tsn.wrapping_add(1))) {
            self.cum_tsn = self.cum_tsn.wrapping_add(1);
            if !c.unordered {
                self.feed_ordered(c, events);
            }
        }
        self.need_sack = true;
    }

    fn record_dup(&mut self, tsn: u32) {
        self.stats.duplicates_rx += 1;
        if self.dups.len() < MAX_DUPS_IN_SACK {
            self.dups.push(tsn);
        }
        self.need_sack = true;
    }

    fn handle_dcep(&mut self, stream: u16, payload: &[u8], events: &mut Vec<SctpEvent>) {
        match dcep::parse(payload) {
            Ok(Some(open)) => {
                if self.channels.contains_key(&stream) {
                    // RFC 8832 §5.1: OPEN on a channel that already exists is
                    // a protocol violation.
                    self.abort_protocol("duplicate DATA_CHANNEL_OPEN");
                    events.push(SctpEvent::Closed(CloseReason::ProtocolViolation(
                        "duplicate DATA_CHANNEL_OPEN".into(),
                    )));
                    return;
                }
                self.channels.insert(
                    stream,
                    Channel {
                        channel_type: open.channel_type,
                        ssn: 0,
                        awaiting_ack: false,
                    },
                );
                // The ack goes out reliably+ordered (documented choice).
                let mut ack_msg = Vec::new();
                dcep::encode_ack(&mut ack_msg);
                self.enqueue_user(stream, PPID_DCEP_ACK, ack_msg, Policy::Reliable, false);
                // Deliver user data that arrived before the OPEN (PR loss).
                if let Some(pending) = self.pre_dcep.remove(&stream) {
                    for (ppid, data) in pending {
                        events.push(SctpEvent::Message {
                            stream,
                            ppid,
                            data,
                            unordered: open.channel_type.unordered(),
                        });
                    }
                }
                events.push(SctpEvent::DataChannelOpen {
                    stream,
                    label: open.label,
                    protocol: open.protocol,
                    channel_type: open.channel_type,
                });
            }
            Ok(None) => {
                // DATA_CHANNEL_ACK for a channel we opened.
                if let Some(ch) = self.channels.get_mut(&stream) {
                    if ch.awaiting_ack {
                        ch.awaiting_ack = false;
                        events.push(SctpEvent::DataChannelAck { stream });
                    }
                }
            }
            Err(_) => {
                self.abort_protocol("malformed DCEP message");
                events.push(SctpEvent::Closed(CloseReason::ProtocolViolation(
                    "malformed DCEP message".into(),
                )));
            }
        }
    }

    fn feed_unordered(&mut self, c: DataChunk, events: &mut Vec<SctpEvent>) {
        if c.begin {
            let mut run = FragRun {
                ssn: 0,
                first_tsn: c.tsn,
                pieces: BTreeMap::new(),
                end_seen: false,
            };
            run.pieces.insert(c.tsn, c.clone());
            if c.end {
                run.end_seen = true;
                if run.complete() {
                    self.deliver_run(&run, events);
                    return;
                }
            }
            self.unordered.current = Some(run);
            return;
        }
        let Some(run) = self.unordered.current.as_mut() else {
            return; // continuation without a start — nothing to do
        };
        if tsn_lt(c.tsn, run.first_tsn) {
            return;
        }
        run.pieces.insert(c.tsn, c.clone());
        if c.end {
            run.end_seen = true;
        }
        if run.complete() {
            let run = self.unordered.current.take().unwrap();
            self.deliver_run(&run, events);
        }
    }

    fn feed_ordered(&mut self, c: DataChunk, events: &mut Vec<SctpEvent>) {
        let stream = c.stream;
        let ssn = c.ssn;
        // Phase 1 — insert the chunk into the current or a parked run.
        {
            let buf = self.ordered.entry(stream).or_default();
            if ssn == buf.expected {
                match &mut buf.current {
                    Some(run) => {
                        run.pieces.insert(c.tsn, c.clone());
                        if c.end {
                            run.end_seen = true;
                        }
                    }
                    None => {
                        let end_seen = c.end;
                        let mut run = FragRun {
                            ssn,
                            first_tsn: c.tsn,
                            pieces: BTreeMap::new(),
                            end_seen: false,
                        };
                        run.pieces.insert(c.tsn, c);
                        run.end_seen = end_seen;
                        buf.current = Some(run);
                    }
                }
            } else {
                let run = buf.parked.entry(ssn).or_insert_with(|| FragRun {
                    ssn,
                    first_tsn: c.tsn,
                    pieces: BTreeMap::new(),
                    end_seen: false,
                });
                if tsn_lt(c.tsn, run.first_tsn) {
                    run.first_tsn = c.tsn;
                }
                run.pieces.insert(c.tsn, c.clone());
                if c.end {
                    run.end_seen = true;
                }
            }
        }
        // Phase 2 — complete the current run when it is whole.
        let completed: Option<FragRun> = {
            let buf = self.ordered.get_mut(&stream).unwrap();
            if buf.current.as_ref().map(|r| r.complete()).unwrap_or(false) {
                let run = buf.current.take().unwrap();
                buf.expected = buf.expected.wrapping_add(1);
                Some(run)
            } else {
                None
            }
        };
        // Phase 3 — deliver, then drain parked runs now in order.
        if let Some(run) = completed {
            self.deliver_run(&run, events);
            loop {
                let next = self.ordered.get(&stream).map(|b| b.expected).unwrap_or(0);
                let cand = self
                    .ordered
                    .get_mut(&stream)
                    .and_then(|b| b.parked.remove(&next));
                match cand {
                    Some(p) if p.complete() => {
                        if let Some(buf) = self.ordered.get_mut(&stream) {
                            buf.expected = next.wrapping_add(1);
                        }
                        self.deliver_run(&p, events);
                    }
                    Some(p) => {
                        self.ordered
                            .get_mut(&stream)
                            .unwrap()
                            .parked
                            .insert(next, p);
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    fn deliver_run(&mut self, run: &FragRun, events: &mut Vec<SctpEvent>) {
        let Some(first) = run.pieces.values().next() else {
            return;
        };
        let stream = first.stream;
        let ppid = first.ppid;
        let unordered = first.unordered;
        let data = run.assemble();
        if data.len() > self.cfg.max_message_size {
            self.abort_protocol("inbound message exceeds max-message-size");
            events.push(SctpEvent::Closed(CloseReason::ProtocolViolation(
                "inbound message exceeds max-message-size".into(),
            )));
            return;
        }
        // DCEP rides the ordered pipeline (SSN-accounted like any user
        // message) and is dispatched here, at delivery time.
        if ppid == PPID_DCEP_OPEN || ppid == PPID_DCEP_ACK {
            self.handle_dcep(stream, &data, events);
            return;
        }
        // Hold user data until the DCEP OPEN for the stream was seen.
        if !self.channels.contains_key(&stream) {
            let slot = self.pre_dcep.entry(stream).or_default();
            if slot.len() < PRE_DCEP_BUFFER {
                slot.push((ppid, data));
            }
            return;
        }
        self.stats.messages_rx += 1;
        self.stats.bytes_rx += data.len() as u64;
        events.push(SctpEvent::Message {
            stream,
            ppid,
            data,
            unordered,
        });
    }

    // ------------------------------------------------------- data send

    /// Open a data channel (DCEP). Returns the SCTP stream id the channel
    /// uses (odd for the association initiator, even for the responder —
    /// RFC 8832 §6).
    pub fn open_data_channel(
        &mut self,
        label: &str,
        protocol: &str,
        channel_type: ChannelType,
        now: Instant,
    ) -> Result<u16, SctpError> {
        if self.state != State::Established {
            return Err(SctpError::WrongState("not established"));
        }
        let stream = self.allocate_stream()?;
        let mut msg = Vec::new();
        dcep::encode_open(
            &dcep::DataChannelOpen {
                label: label.to_string(),
                protocol: protocol.to_string(),
                channel_type,
                priority: 0,
            },
            &mut msg,
        );
        self.channels.insert(
            stream,
            Channel {
                channel_type,
                ssn: 0,
                awaiting_ack: true,
            },
        );
        // Establishment messages go reliably+ordered (documented choice).
        self.enqueue_user(stream, PPID_DCEP_OPEN, msg, Policy::Reliable, false);
        self.flush(now);
        Ok(stream)
    }

    fn allocate_stream(&mut self) -> Result<u16, SctpError> {
        let limit = if self.peer_mis == 0 {
            self.cfg.os_streams
        } else {
            self.peer_mis.min(self.cfg.os_streams)
        };
        let mut id = self.next_outbound_stream;
        while id < limit && self.channels.contains_key(&id) {
            id = id.wrapping_add(2);
        }
        if id >= limit {
            return Err(SctpError::SendBufferFull);
        }
        self.next_outbound_stream = id.wrapping_add(2);
        Ok(id)
    }

    /// Send one user message on an open channel (fragmenting as needed).
    /// Reliability/ordering come from the channel's type.
    pub fn send_message(
        &mut self,
        stream: u16,
        ppid: u32,
        data: Vec<u8>,
        now: Instant,
    ) -> Result<(), SctpError> {
        if self.state != State::Established {
            return Err(SctpError::WrongState("not established"));
        }
        let ch = self
            .channels
            .get(&stream)
            .ok_or(SctpError::UnknownStream(stream))?;
        if data.len() > self.cfg.max_message_size {
            return Err(SctpError::MessageTooLarge(data.len()));
        }
        let channel_type = ch.channel_type;
        let mut policy = match channel_type {
            ChannelType::Reliable | ChannelType::ReliableUnordered => Policy::Reliable,
            ChannelType::MaxRetransmits(n) | ChannelType::MaxRetransmitsUnordered(n) => {
                Policy::MaxRetrans(n)
            }
            ChannelType::MaxLifetimeMs(ms) | ChannelType::MaxLifetimeUnorderedMs(ms) => {
                Policy::LifetimeMs(ms)
            }
        };
        // Partial reliability requires BOTH endpoints (RFC 3758 §3.1); if the
        // peer did not advertise FORWARD-TSN, PR policies degrade to reliable.
        if !(self.peer_forward_tsn && self.cfg.forward_tsn) {
            policy = Policy::Reliable;
        }
        self.enqueue_user(stream, ppid, data, policy, channel_type.unordered());
        self.flush(now);
        Ok(())
    }

    fn enqueue_user(
        &mut self,
        stream: u16,
        ppid: u32,
        data: Vec<u8>,
        policy: Policy,
        unordered: bool,
    ) {
        let msg_id = self.msg_counter;
        self.msg_counter += 1;
        let max_payload = self.cfg.mtu.saturating_sub(DATA_OVERHEAD).max(1);
        let ssn = if unordered {
            0
        } else {
            match self.channels.get_mut(&stream) {
                Some(ch) => {
                    let ssn = ch.ssn;
                    ch.ssn = ch.ssn.wrapping_add(1);
                    ssn
                }
                None => 0,
            }
        };
        let mut offset = 0usize;
        loop {
            let end = (offset + max_payload).min(data.len());
            let payload = data[offset..end].to_vec();
            let tsn = self.local_tsn;
            self.local_tsn = self.local_tsn.wrapping_add(1);
            self.inflight.push_back(InFlight {
                tsn,
                stream,
                ssn,
                ppid,
                unordered,
                begin: offset == 0,
                end: end == data.len(),
                payload: payload.clone(),
                policy,
                msg_id,
                size: DATA_CHUNK_FIXED + payload.len(),
                sent: false,
                first_sent: None,
                last_sent: None,
                retransmits: 0,
                abandoned: false,
            });
            offset = end;
            if offset >= data.len() {
                break;
            }
        }
        // Enforce the send-buffer bound (drop from the tail on overflow —
        // halves of messages must never send).
        while self.inflight.len() > self.cfg.send_buffer_chunks as usize {
            self.inflight.pop_back();
        }
        self.stats.messages_tx += 1;
    }

    /// Build packets from the send queue within cwnd/a_rwnd/MTU bounds.
    fn flush(&mut self, now: Instant) {
        if self.closed {
            return;
        }
        self.emit_forward_tsns();

        let window = self.cwnd.min(self.peer_a_rwnd.max(1));
        let mut packet: Vec<Chunk> = Vec::new();
        let mut packet_len = 12usize;
        let mut sent_any = false;

        for i in 0..self.inflight.len() {
            if self.inflight[i].sent || self.inflight[i].abandoned {
                continue;
            }
            let size = self.inflight[i].size;
            if self.outstanding_bytes + size > window {
                break; // flow control: retry on SACK / T3-RTX
            }
            if packet_len + size > self.cfg.mtu {
                if !packet.is_empty() {
                    let chunks = std::mem::take(&mut packet);
                    packet_len = 12;
                    self.queue_packet(&chunks);
                }
                if packet_len + size > self.cfg.mtu {
                    continue; // chunk alone exceeds MTU (cannot happen with
                              // fragmentation, guarded anyway)
                }
            }
            self.inflight[i].sent = true;
            self.inflight[i].first_sent = self.inflight[i].first_sent.or(Some(now));
            self.inflight[i].last_sent = Some(now);
            self.outstanding_bytes += size;
            self.stats.data_chunks_tx += 1;
            self.stats.bytes_tx += size as u64;
            let chunk = self.inflight[i].to_chunk();
            packet.push(Chunk::Data(chunk));
            packet_len += size;
            sent_any = true;
        }
        if !packet.is_empty() {
            self.queue_packet(&packet);
        }
        if sent_any {
            // T3-RTX covers everything outstanding (RFC 9260 §7.6.2).
            self.t3_deadline = Some(now + self.rto);
        }
    }

    fn queue_packet(&mut self, chunks: &[Chunk]) {
        let pkt = wire::encode_packet(
            self.cfg.local_port,
            self.cfg.remote_port,
            self.peer_tag,
            chunks,
        );
        self.outbox.push_back(pkt);
        self.stats.packets_tx += 1;
    }

    fn send_sack_now(&mut self) {
        let mut gaps: Vec<SackBlock> = Vec::new();
        let mut iter = self.ofo.keys().copied().peekable();
        while let Some(start) = iter.next() {
            let mut end = start;
            while let Some(&nxt) = iter.peek() {
                if nxt == end.wrapping_add(1) {
                    end = nxt;
                    iter.next();
                } else {
                    break;
                }
            }
            gaps.push(SackBlock {
                start: start.wrapping_sub(self.cum_tsn) as u16,
                end: end.wrapping_sub(self.cum_tsn) as u16,
            });
        }
        let free = (self.cfg.recv_window_chunks as usize - self.ofo.len()) * self.cfg.mtu;
        let sack = Chunk::Sack(wire::SackChunk {
            cum_tsn: self.cum_tsn,
            a_rwnd: free as u32,
            gaps,
            dups: std::mem::take(&mut self.dups),
        });
        self.stats.sack_tx += 1;
        self.queue_packet(&[sack]);
    }

    // ------------------------------------------------------------ sack

    fn on_sack(&mut self, s: wire::SackChunk, now: Instant) {
        if self.state != State::Established && self.state != State::ShutdownSent {
            return;
        }
        self.stats.sack_rx += 1;
        self.peer_a_rwnd = s.a_rwnd as usize;
        if tsn_lt(self.peer_cum, s.cum_tsn) {
            self.peer_cum = s.cum_tsn;
        }

        let mut newly_acked = 0usize;
        let mut rtt_sample: Option<Duration> = None;

        // Cumulative point: everything at/below it is acked.
        while let Some(front) = self.inflight.front() {
            if tsn_le(front.tsn, s.cum_tsn) {
                let c = self.inflight.pop_front().unwrap();
                newly_acked += c.size;
                if c.retransmits == 0 && rtt_sample.is_none() {
                    rtt_sample = c
                        .last_sent
                        .map(|t| now.checked_duration_since(t).unwrap_or_default());
                }
                self.outstanding_bytes = self.outstanding_bytes.saturating_sub(c.size);
            } else {
                break;
            }
        }
        // Gap blocks (RFC 9260 §3.3.4): offsets from the cumulative point.
        for g in &s.gaps {
            let start = s.cum_tsn.wrapping_add(g.start as u32);
            let end = s.cum_tsn.wrapping_add(g.end as u32);
            let mut t = start;
            loop {
                if let Some(pos) = self.inflight.iter().position(|c| c.tsn == t) {
                    let c = self.inflight.remove(pos).unwrap();
                    newly_acked += c.size;
                    if c.retransmits == 0 && rtt_sample.is_none() {
                        rtt_sample = c
                            .last_sent
                            .map(|st| now.checked_duration_since(st).unwrap_or_default());
                    }
                    self.outstanding_bytes = self.outstanding_bytes.saturating_sub(c.size);
                }
                if t == end {
                    break;
                }
                t = t.wrapping_add(1);
            }
        }
        // Duplicate reports acknowledge the original transmission too.
        for d in &s.dups {
            if let Some(pos) = self.inflight.iter().position(|c| c.tsn == *d) {
                let c = self.inflight.remove(pos).unwrap();
                newly_acked += c.size;
                self.outstanding_bytes = self.outstanding_bytes.saturating_sub(c.size);
            }
        }

        // RFC 6298 RTO estimation (Karn's rule: never-retransmitted only).
        if let Some(rtt) = rtt_sample {
            if let Some(srtt) = self.srtt {
                self.rttvar = self.rttvar.mul_f64(0.75) + rtt.abs_diff(srtt).mul_f64(0.25);
                self.srtt = Some(srtt.mul_f64(0.875) + rtt.mul_f64(0.125));
            } else {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            let srtt = self.srtt.unwrap_or(rtt);
            self.rto = (srtt + self.rttvar * 4).clamp(self.cfg.rto_min, self.cfg.rto_max);
        }

        // Congestion window (RFC 9260 §7.2.1, simplified per-SACK steps).
        if newly_acked > 0 {
            if self.cwnd < self.ssthresh {
                self.cwnd += self.cfg.mtu;
            } else {
                self.partial_bytes_acked += newly_acked;
                if self.partial_bytes_acked >= self.cwnd {
                    self.cwnd += self.cfg.mtu;
                    self.partial_bytes_acked -= self.cwnd;
                }
            }
        }

        if self.outstanding_bytes == 0 {
            self.t3_deadline = None;
            self.partial_bytes_acked = 0;
            if self.shutdown_pending {
                self.begin_shutdown();
            }
        }
    }

    // -------------------------------------------------- forward-tsn (PR)

    /// RFC 3758: advance the peer ack point over abandoned chunks and send
    /// FORWARD-TSN. Abandoned chunk buffers are freed at send time.
    fn emit_forward_tsns(&mut self) {
        if !(self.peer_forward_tsn && self.cfg.forward_tsn) {
            // Without PR support abandoned chunks are just dropped (they can
            // only exist if the caller forced PR with both sides unaware —
            // send_message already degrades the policy, so this is defensive).
            self.inflight.retain(|c| !c.abandoned);
            return;
        }
        // Highest point where every tsn in (peer_cum, point] is abandoned.
        let mut point: Option<u32> = None;
        for c in &self.inflight {
            if tsn_le(c.tsn, self.peer_cum) {
                continue;
            }
            if c.abandoned {
                point = Some(c.tsn);
            } else {
                break;
            }
        }
        let Some(new_cum) = point else {
            return;
        };
        // Ordered stream skips for abandoned messages (RFC 3758 §3.2): one
        // entry per stream, the highest abandoned SSN, never re-reported.
        let mut streams: Vec<(u16, u16)> = Vec::new();
        for c in &self.inflight {
            if !c.abandoned || c.unordered || tsn_gt(c.tsn, new_cum) {
                continue;
            }
            match self.ftsn_reported.get(&c.stream) {
                Some(&last) if ssn_le(c.ssn, last) => {}
                _ => {
                    self.ftsn_reported.insert(c.stream, c.ssn);
                    streams.push((c.stream, c.ssn));
                }
            }
        }
        streams.sort();
        self.inflight
            .retain(|c| !(c.abandoned && tsn_le(c.tsn, new_cum)));
        self.stats.ftsn_tx += 1;
        self.stats.abandoned += 1;
        self.queue_packet(&[Chunk::ForwardTsn {
            new_cum_tsn: new_cum,
            streams,
        }]);
    }

    fn on_forward_tsn(&mut self, new_cum: u32, streams: &[(u16, u16)]) {
        if self.state != State::Established && self.state != State::ShutdownSent {
            return;
        }
        self.stats.ftsn_rx += 1;
        // Drop out-of-order chunks at or below the new point.
        let stale: Vec<u32> = self
            .ofo
            .keys()
            .copied()
            .filter(|t| tsn_le(*t, new_cum))
            .collect();
        for k in stale {
            self.ofo.remove(&k);
        }
        // An unordered partial run wholly below the point is abandoned.
        if let Some(run) = &self.unordered.current {
            let fully_stale = run
                .pieces
                .last_key_value()
                .map(|(k, _)| tsn_le(*k, new_cum))
                .unwrap_or(true);
            if fully_stale {
                self.unordered.current = None;
            }
        }
        if tsn_lt(self.cum_tsn, new_cum) {
            self.cum_tsn = new_cum;
        }
        // Ordered stream skips (RFC 3758 §4.2): for each (sid, ssn), any
        // ordered message with ssn <= the reported one is skipped.
        for (sid, ssn) in streams {
            let buf = self.ordered.entry(*sid).or_default();
            if ssn_ge(*ssn, buf.expected) {
                buf.expected = ssn.wrapping_add(1);
            }
            buf.parked
                .retain(|parked_ssn, _| !ssn_le(*parked_ssn, *ssn));
            if let Some(run) = &buf.current {
                if ssn_le(run.ssn, *ssn) {
                    buf.current = None;
                }
            }
        }
        self.need_sack = true;
    }

    // --------------------------------------------------------- timers

    /// Earliest deadline the caller should wake the endpoint at.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut min: Option<Instant> = None;
        let mut consider = |t: Option<Instant>| {
            if let Some(t) = t {
                min = Some(min.map_or(t, |m: Instant| m.min(t)));
            }
        };
        consider(self.t1.as_ref().map(|t| t.deadline));
        consider(self.t3_deadline);
        consider(self.heartbeat_deadline);
        if self.peer_forward_tsn && self.cfg.forward_tsn {
            for c in &self.inflight {
                if c.abandoned {
                    continue;
                }
                if let (Policy::LifetimeMs(ms), Some(first)) = (c.policy, c.first_sent) {
                    consider(Some(first + Duration::from_millis(ms as u64)));
                }
            }
        }
        min
    }

    /// Fire all due timers at virtual time `now`.
    pub fn on_timeout(&mut self, now: Instant) {
        if self.closed {
            return;
        }
        // T1-INIT / T1-COOKIE.
        if let Some(t1) = self.t1.as_ref() {
            if t1.deadline <= now {
                let attempts = t1.attempts + 1;
                let payload = t1.payload.clone();
                if attempts > MAX_INIT_RETRANS {
                    self.t1 = None;
                    self.close_out();
                    return;
                }
                self.t1 = Some(T1 {
                    deadline: now + self.rto,
                    attempts,
                    payload: payload.clone(),
                });
                self.outbox.push_back(payload);
                self.stats.packets_tx += 1;
            }
        }
        // Lifetime sweep (RFC 3758 max packet lifetime).
        if self.peer_forward_tsn && self.cfg.forward_tsn {
            let expired: Vec<u64> = self
                .inflight
                .iter()
                .filter(|c| match (c.policy, c.first_sent) {
                    (Policy::LifetimeMs(ms), Some(first)) => {
                        !c.abandoned
                            && now.checked_duration_since(first).unwrap_or_default()
                                >= Duration::from_millis(ms as u64)
                    }
                    _ => false,
                })
                .map(|c| c.msg_id)
                .collect();
            for msg in expired {
                self.abandon_message(msg);
            }
        }
        // T3-RTX: retransmit everything outstanding, back off RTO.
        if let Some(deadline) = self.t3_deadline {
            if deadline <= now && self.outstanding_bytes > 0 {
                self.rto = (self.rto * 2).min(self.cfg.rto_max);
                self.ssthresh = self.cwnd / 2;
                self.cwnd = self.cfg.mtu;
                self.partial_bytes_acked = 0;
                let mut exhausted: Vec<u64> = Vec::new();
                for c in self.inflight.iter_mut() {
                    if c.sent && !c.abandoned {
                        c.retransmits += 1;
                        self.stats.retransmits_tx += 1;
                        if let Policy::MaxRetrans(n) = c.policy {
                            if c.retransmits > n {
                                exhausted.push(c.msg_id);
                            }
                        }
                    }
                }
                for msg in exhausted {
                    self.abandon_message(msg);
                }
                self.emit_forward_tsns();
                let live: Vec<(usize, DataChunk)> = self
                    .inflight
                    .iter()
                    .filter(|c| c.sent && !c.abandoned)
                    .map(|c| (c.size, c.to_chunk()))
                    .collect();
                let mut packet: Vec<Chunk> = Vec::new();
                let mut packet_len = 12usize;
                for (size, chunk) in live {
                    if packet_len + size > self.cfg.mtu {
                        let chunks = std::mem::take(&mut packet);
                        packet_len = 12;
                        self.queue_packet(&chunks);
                    }
                    packet.push(Chunk::Data(chunk));
                    packet_len += size;
                }
                if !packet.is_empty() {
                    self.queue_packet(&packet);
                }
                self.t3_deadline = Some(now + self.rto);
            }
        }
        // Heartbeat.
        if let Some(deadline) = self.heartbeat_deadline {
            if deadline <= now && self.state == State::Established {
                self.heartbeat_counter += 1;
                let mut info = Vec::new();
                info.extend_from_slice(&self.heartbeat_counter.to_be_bytes());
                info.extend_from_slice(&now_unix_ms().to_be_bytes());
                self.queue_packet(&[Chunk::Heartbeat { info }]);
                self.heartbeat_deadline = Some(now + self.cfg.heartbeat_interval.unwrap());
            }
        }
        self.flush(now);
    }

    fn abandon_message(&mut self, msg_id: u64) {
        for c in self.inflight.iter_mut() {
            if c.msg_id == msg_id && !c.abandoned {
                c.abandoned = true;
                if c.sent {
                    self.outstanding_bytes = self.outstanding_bytes.saturating_sub(c.size);
                }
            }
        }
    }

    fn on_heartbeat_ack(&mut self, _info: Vec<u8>) {
        // Liveness only — RTT comes from SACK samples (clock-domain honesty).
    }

    // -------------------------------------------------------- shutdown

    /// Begin the graceful shutdown (SHUTDOWN is deferred until the peer
    /// acknowledged everything outstanding).
    pub fn shutdown(&mut self) -> Result<(), SctpError> {
        if self.state != State::Established {
            return Err(SctpError::WrongState("not established"));
        }
        self.shutdown_pending = true;
        if self.outstanding_bytes == 0 {
            self.begin_shutdown();
        }
        Ok(())
    }

    fn begin_shutdown(&mut self) {
        self.shutdown_pending = false;
        let cum = self.cum_tsn;
        self.queue_packet(&[Chunk::Shutdown { cum_tsn: cum }]);
        self.state = State::ShutdownSent;
    }

    fn on_shutdown(&mut self) {
        if self.state != State::Established && self.state != State::ShutdownSent {
            return;
        }
        self.queue_packet(&[Chunk::ShutdownAck]);
        self.state = State::ShutdownAckSent;
    }

    fn on_shutdown_ack(&mut self, events: &mut Vec<SctpEvent>) {
        if self.state != State::ShutdownSent {
            return;
        }
        self.queue_packet(&[Chunk::ShutdownComplete { reflected: false }]);
        self.close_out();
        events.push(SctpEvent::Closed(CloseReason::Shutdown));
    }

    fn on_shutdown_complete(&mut self, events: &mut Vec<SctpEvent>) {
        if self.state != State::ShutdownAckSent {
            return;
        }
        self.close_out();
        events.push(SctpEvent::Closed(CloseReason::Shutdown));
    }

    /// Send an ABORT (user-initiated) and close immediately.
    pub fn abort(&mut self) -> Vec<SctpEvent> {
        let causes = vec![wire::RawParam {
            ptype: 12, // User Initiated Abort
            value: b"local abort".to_vec(),
        }];
        self.queue_packet(&[Chunk::Abort {
            causes,
            reflected: false,
        }]);
        self.close_out();
        vec![SctpEvent::Closed(CloseReason::LocalClose)]
    }

    fn abort_protocol(&mut self, reason: &str) {
        let causes = vec![wire::RawParam {
            ptype: 13, // Protocol Violation
            value: reason.as_bytes().to_vec(),
        }];
        self.queue_packet(&[Chunk::Abort {
            causes,
            reflected: false,
        }]);
        self.close_out();
    }

    fn close_out(&mut self) {
        self.closed = true;
        self.t1 = None;
        self.t3_deadline = None;
        self.heartbeat_deadline = None;
    }

    // ------------------------------------------------------------ misc

    /// Association state check (for logs/tests).
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn stats(&self) -> AssociationStats {
        self.stats
    }

    /// Data channels currently known (opened by either side).
    pub fn channels(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self.channels.keys().copied().collect();
        v.sort();
        v
    }

    // ---------------------------------------------------------- cookie

    fn build_cookie(&self, init: &wire::InitChunk) -> Vec<u8> {
        let mut buf = Vec::with_capacity(68);
        buf.extend_from_slice(b"SCTPCK01");
        buf.extend_from_slice(&self.local_tag.to_be_bytes()); // 8
        buf.extend_from_slice(&self.local_tsn.to_be_bytes()); // 12
        buf.extend_from_slice(&self.recv_window_bytes().to_be_bytes()); // 16
        buf.extend_from_slice(&self.cfg.os_streams.to_be_bytes()); // 20
        buf.extend_from_slice(&self.cfg.mis_streams.to_be_bytes()); // 22
        buf.extend_from_slice(&init.initiate_tag.to_be_bytes()); // 24
        buf.extend_from_slice(&init.initial_tsn.to_be_bytes()); // 28
        buf.extend_from_slice(&init.a_rwnd.to_be_bytes()); // 32
        buf.extend_from_slice(&init.os.to_be_bytes()); // 36
        buf.extend_from_slice(&init.mis.to_be_bytes()); // 38
        buf.extend_from_slice(&now_unix_ms().to_be_bytes()); // 40..48
        buf.push(u8::from(supports_forward_tsn(init))); // 48
        buf.extend_from_slice(&[0u8; 3]); // 49..52 (alignment)
        let mac = cookie_mac(&self.cookie_key, &buf);
        buf.extend_from_slice(&mac); // 52..68
        buf
    }
}

struct CookieState {
    server_tag: u32,
    server_tsn: u32,
    client_tag: u32,
    client_tsn: u32,
    client_rwnd: u32,
    client_mis: u16,
    client_forward_tsn: bool,
    issued_ms: u64,
}

fn cookie_valid_mac(key: &[u8; 32], buf: &[u8]) -> bool {
    if buf.len() != 68 || &buf[..8] != b"SCTPCK01" {
        return false;
    }
    let mac: [u8; COOKIE_MAC_LEN] = match buf[52..68].try_into() {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac == cookie_mac(key, &buf[..52])
}

fn parse_cookie(buf: &[u8]) -> Result<CookieState, SctpError> {
    if buf.len() != 68 || &buf[..8] != b"SCTPCK01" {
        return Err(SctpError::BadChunk("cookie malformed"));
    }
    let rd32 = |at: usize| u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
    let rd16 = |at: usize| u16::from_be_bytes([buf[at], buf[at + 1]]);
    let issued_ms = u64::from_be_bytes([
        buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
    ]);
    Ok(CookieState {
        server_tag: rd32(8),
        server_tsn: rd32(12),
        client_tag: rd32(24),
        client_tsn: rd32(28),
        client_rwnd: rd32(32),
        client_mis: rd16(38),
        client_forward_tsn: buf[48] != 0,
        issued_ms,
    })
}

fn cookie_mac(key: &[u8; 32], data: &[u8]) -> [u8; COOKIE_MAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut short = [0u8; COOKIE_MAC_LEN];
    short.copy_from_slice(&out[..COOKIE_MAC_LEN]);
    short
}

fn supports_forward_tsn(init: &wire::InitChunk) -> bool {
    init.param(wire::PT_SUPPORTED_EXTENSIONS)
        .map(|v| v.contains(&wire::CT_FORWARD_TSN))
        .unwrap_or(false)
}

#[cfg(test)]
mod probe {
    use super::*;

    #[test]
    fn cookie_roundtrip_probe() {
        let cfg = SctpConfig {
            is_client: false,
            initial_tag: Some(222),
            initial_tsn: Some(2000),
            cookie_key: Some([7u8; 32]),
            ..Default::default()
        };
        let ep = SctpEndpoint::new_server(cfg);
        let init = wire::InitChunk {
            initiate_tag: 111,
            a_rwnd: 76800,
            os: 1024,
            mis: 1024,
            initial_tsn: 1000,
            params: vec![],
        };
        let cookie = ep.build_cookie(&init);
        println!("cookie len = {}", cookie.len());
        assert!(
            cookie_valid_mac(&ep.cookie_key, &cookie),
            "MAC must validate"
        );
        let parsed = parse_cookie(&cookie).unwrap();
        assert_eq!(parsed.client_tag, 111);
        assert_eq!(parsed.server_tag, 222);
    }
}
