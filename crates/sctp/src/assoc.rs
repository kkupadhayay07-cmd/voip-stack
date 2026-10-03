//! The SCTP association state machine ([RFC 9260] §4-§8, [RFC 3758],
//! [RFC 6525]).
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
//! with FORWARD-TSN, heartbeat exchange, graceful SHUTDOWN and ABORT, and
//! the RFC 6525 stream-reset subset RFC 8831 needs for closing a data
//! channel: Outgoing SSN Reset Request + Re-configuration Response, with
//! reciprocal reset on the answering side, the §5.2.2 E2 deferred reset
//! ("In progress" until our cumulative point reaches the peer's last
//! assigned TSN) and duplicate-request response replay.
//!
//! Simplified (each documented where it appears): no multi-homing, no SACK
//! delay (every DATA packet is SACKed immediately), DCEP establishment
//! messages are sent reliably+ordered regardless of channel policy, no
//! association-level idle timeout (reliable data retransmits forever; the
//! caller can abort), at most one stream-reset request in flight at a time
//! (a reciprocal reset demanded while another request is outstanding is
//! queued and started on completion).
//!
//! [RFC 9260]: https://datatracker.ietf.org/doc/html/rfc9260
//! [RFC 3758]: https://datatracker.ietf.org/doc/html/rfc3758
//! [RFC 6525]: https://datatracker.ietf.org/doc/html/rfc6525
//! [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::dcep::{self, ChannelType, PPID_DCEP_ACK, PPID_DCEP_OPEN};
use crate::wire::{
    self, Chunk, DataChunk, ReConfigChunk, ReConfigParam, SackBlock, SctpError, CT_FORWARD_TSN,
    CT_RE_CONFIG, RC_RESULT_IN_PROGRESS, RC_RESULT_IN_PROGRESS_PEER, RC_RESULT_NOTHING_TO_DO,
    RC_RESULT_PERFORMED,
};
use crate::{CloseReason, SctpConfig, SctpEvent};

/// Handshake retransmission budget for T1-INIT / T1-COOKIE (RFC 9260 §4.1).
pub const MAX_INIT_RETRANS: u32 = 8;
/// Cookie MAC length (HMAC-SHA256 truncated).
const COOKIE_MAC_LEN: usize = 16;
/// Offset of the MAC inside the state cookie (after the 8-byte nonce).
const COOKIE_MAC_AT: usize = 60;
/// Total state-cookie size: 60 bytes of MAC'd fields + 16-byte MAC.
const COOKIE_LEN: usize = 76;
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

/// Fill `buf` with OS entropy via the `getrandom` crate. Falls back to the
/// coarse clock only if the platform entropy source fails (never observed in
/// practice). The clock is no longer the primary seed: a wall-clock seed is
/// brute-forceable, and a shared xorshift state leaks every future output
/// (initial TSN) once one public value (the verification tag) is seen.
fn fill_random(buf: &mut [u8]) {
    if getrandom::fill(buf).is_err() {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            .to_le_bytes();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = seed[i % 8] ^ (i as u8).wrapping_mul(31);
        }
    }
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

fn tsn_ge(a: u32, b: u32) -> bool {
    !tsn_lt(a, b)
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
    /// RFC 8831 §6.7 close in progress: no more sends are accepted and the
    /// stream id is not reusable until the reset completes (the id frees
    /// when the channel is removed).
    closing: bool,
    /// The `DataChannelClosed` event was delivered (an incoming reset or
    /// our own close completion). Guards single-delivery.
    closed_notified: bool,
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

/// Timer bookkeeping for T2-SHUTDOWN / T2-SHUTDOWN-ACK (RFC 9260 §9.1/§9.2):
/// the payload is rebuilt from the state at each fire so the retransmitted
/// chunk always carries the current cumulative point.
#[derive(Debug)]
struct T2 {
    deadline: Instant,
    attempts: u32,
}

/// RFC 3758 §3.5: a FORWARD-TSN MUST be retransmitted until the peer's
/// cumulative ack point covers `new_cum`. One record is outstanding at a
/// time; a newer emission subsumes it (higher new_cum + merged skips).
#[derive(Debug, Clone)]
struct OutstandingFtsn {
    new_cum: u32,
    /// Per-stream skips (sid, highest abandoned ssn) for ordered streams.
    streams: Vec<(u16, u16)>,
}

/// RFC 6525 §5.1.1: our Outgoing SSN Reset Request is retransmitted on the
/// re-configuration timer (RTO backoff) until the peer's Response — or an
/// E1 implicit acknowledgment (the request's response_seq covering our RSN)
/// — arrives.
#[derive(Debug, Clone)]
struct OutstandingReconfig {
    rsn: u32,
    streams: Vec<u16>,
    attempts: u32,
}

/// RFC 6525 §5.2.2 E2 deferred reset: the peer's request named a
/// last-assigned TSN our cumulative point has not reached yet, so data on
/// the affected streams beyond that TSN is held until it does. One at a
/// time (a second request while one is deferred answers result 4).
#[derive(Debug)]
struct DeferredReset {
    rsn: u32,
    last_tsn: u32,
    /// Affected inbound streams (empty = ALL inbound streams, §4.1).
    streams: Vec<u16>,
    /// DATA chunks held beyond `last_tsn` (E2), keyed by TSN.
    held: BTreeMap<u32, DataChunk>,
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
    pub reconfig_rx: u64,
    pub reconfig_tx: u64,
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
    /// Peer advertised RFC 6525 stream-reset support (RE-CONFIG in the
    /// Supported Extensions parameter).
    peer_reconfig: bool,
    /// Last INIT seen (server) — lets a stale cookie be refreshed with a new
    /// INIT-ACK without keeping pre-association sessions.
    last_init: Option<wire::InitChunk>,

    // ---- timers ----
    t1: Option<T1>,
    t2: Option<T2>,
    /// Retransmission deadline for the outstanding FORWARD-TSN (RFC 3758 §3.5).
    ftsn_deadline: Option<Instant>,
    /// Retransmission deadline for the outstanding RE-CONFIG request
    /// (RFC 6525 §5.1.1 re-configuration timer).
    reconfig_deadline: Option<Instant>,
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
    /// The unacknowledged FORWARD-TSN (RFC 3758 §3.5).
    ftsn_outstanding: Option<OutstandingFtsn>,

    // ---- RFC 6525 stream reset ----
    /// Next Re-configuration Request Sequence Number (§4.1: initialized to
    /// the initial TSN, +1 per request).
    next_rsn: u32,
    /// The RSN of the last incoming request we processed (duplicate
    /// detection / response_seq bookkeeping).
    peer_rsn_seen: Option<u32>,
    /// The (rsn, result) response we sent last — a retransmitted request
    /// must be answered with the SAME response (RFC 6525 §5.2.1).
    last_response: Option<(u32, u32)>,
    /// Our request awaiting the peer's Response / E1 implicit ack.
    reconfig_outstanding: Option<OutstandingReconfig>,
    /// Reciprocal resets (RFC 8831 §6.7) queued while another request is in
    /// flight; started in order on completion.
    pending_recip: VecDeque<u16>,
    /// An E2 deferred reset in progress (peer's request, our hold).
    deferred_reset: Option<DeferredReset>,

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

    fn base(mut cfg: SctpConfig) -> Self {
        // Config sanity: SACK gap-block offsets are u16, so a receive window
        // beyond 65535 chunks can never be expressed; keep at least one slot
        // in the send buffer. All window math below stays overflow-safe for
        // the clamped ranges.
        cfg.recv_window_chunks = cfg.recv_window_chunks.min(65_535);
        cfg.send_buffer_chunks = cfg.send_buffer_chunks.max(1);
        let cookie_key = cfg.cookie_key.unwrap_or_else(|| {
            let mut k = [0u8; 32];
            fill_random(&mut k);
            k
        });
        let local_tag = cfg.initial_tag.unwrap_or_else(|| {
            let mut b = [0u8; 4];
            fill_random(&mut b);
            u32::from_be_bytes(b) | 1
        });
        let local_tsn = cfg.initial_tsn.unwrap_or_else(|| {
            let mut b = [0u8; 4];
            fill_random(&mut b);
            u32::from_be_bytes(b)
        });
        // RFC 9260 §7.2.1: cwnd = min(4*MTU, max(2*MTU, 4380)).
        let cwnd = (cfg.mtu * 4).min((cfg.mtu * 2).max(4380));
        Self {
            rto: cfg.rto_initial,
            rttvar: cfg.rto_initial / 2,
            cwnd,
            ssthresh: usize::MAX,
            // RFC 8832 §5.1/§6: the DTLS client opens EVEN streams, the DTLS
            // server ODD ones. The association initiator is expected to be
            // the DTLS client (RFC 8261 wiring), so it starts at 0.
            next_outbound_stream: if cfg.is_client { 0 } else { 1 },
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
            t2: None,
            ftsn_deadline: None,
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
            peer_reconfig: false,
            last_init: None,
            ftsn_outstanding: None,
            // §4.1: the RSN starts at the initial TSN (re-derived by the
            // server when the cookie fixes its TSN at establishment).
            next_rsn: local_tsn,
            peer_rsn_seen: None,
            last_response: None,
            reconfig_outstanding: None,
            pending_recip: VecDeque::new(),
            deferred_reset: None,
            reconfig_deadline: None,
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
            params: self.supported_extensions_params(),
        })
    }

    /// The Supported Extensions parameter (RFC 5061) advertising what this
    /// endpoint supports — FORWARD-TSN (RFC 3758 §3.1) and RE-CONFIG
    /// (RFC 6525, signaled per RFC 8831 §6.1).
    fn supported_extensions_params(&self) -> Vec<wire::RawParam> {
        if !(self.cfg.forward_tsn || self.cfg.stream_reset) {
            return Vec::new();
        }
        let mut value = Vec::with_capacity(2);
        if self.cfg.forward_tsn {
            value.push(CT_FORWARD_TSN);
        }
        if self.cfg.stream_reset {
            value.push(CT_RE_CONFIG);
        }
        vec![wire::RawParam {
            ptype: wire::PT_SUPPORTED_EXTENSIONS,
            value,
        }]
    }

    fn recv_window_bytes(&self) -> u32 {
        // Saturating: recv_window_chunks is clamped to u16 range but a large
        // MTU can still push the byte product past u32::MAX.
        (u64::from(self.cfg.recv_window_chunks) * self.cfg.mtu as u64).min(u32::MAX as u64) as u32
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
            Chunk::Init(init) => self.on_init(init, now, None),
            Chunk::InitAck(init) => self.on_init_ack(init, now, events),
            Chunk::CookieEcho { cookie } => self.on_cookie_echo(cookie, now, events),
            Chunk::CookieAck => self.on_cookie_ack(now, events),
            Chunk::Data(d) => self.on_data(d, now, events),
            Chunk::Sack(s) => self.on_sack(s, now),
            Chunk::Heartbeat { info } => {
                self.queue_packet(&[Chunk::HeartbeatAck { info }]);
            }
            Chunk::HeartbeatAck { info } => self.on_heartbeat_ack(info),
            Chunk::ForwardTsn {
                new_cum_tsn,
                streams,
            } => self.on_forward_tsn(new_cum_tsn, &streams, now, events),
            Chunk::ReConfig(rc) => self.on_re_config(rc, now, events),
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
            Chunk::Shutdown { .. } => self.on_shutdown(now),
            Chunk::ShutdownAck => self.on_shutdown_ack(events),
            Chunk::ShutdownComplete { .. } => self.on_shutdown_complete(events),
            Chunk::Unknown { .. } => {
                // RFC 9260 §3.3.1 report classes — reporting is suppressed
                // (documented gap); the chunk is skipped.
            }
        }
    }

    // ------------------------------------------------------- handshake

    fn on_init(&mut self, init: wire::InitChunk, now: Instant, stale_cookie_us: Option<u32>) {
        if matches!(
            self.state,
            State::Established
                | State::ShutdownSent
                | State::ShutdownAckSent
                | State::InitSent
                | State::CookieSent
        ) {
            // Association restart is not supported (documented). A client
            // role (InitSent/CookieSent) must not flip to CookieEchoed on an
            // uninvited INIT either — that would brick the handshake it is
            // already running (RFC 9260 §5.2.2 collision handling is out of
            // scope).
            return;
        }
        self.peer_tag = init.initiate_tag;
        self.peer_initial_tsn = init.initial_tsn;
        self.peer_a_rwnd = init.a_rwnd as usize;
        self.peer_mis = init.mis;
        self.peer_forward_tsn = supports_forward_tsn(&init);
        self.peer_reconfig = supports_re_config(&init);
        self.cum_tsn = init.initial_tsn.wrapping_sub(1);
        self.peer_cum = self.local_tsn.wrapping_sub(1);
        self.last_init = Some(init.clone());

        let cookie = self.build_cookie(&init);
        let mut params = vec![wire::RawParam {
            ptype: wire::PT_STATE_COOKIE,
            value: cookie,
        }];
        let ext = self.supported_extensions_params();
        params.extend(ext);
        if let Some(us) = stale_cookie_us {
            // RFC 9260 §5.1.5: a refreshed INIT-ACK carries the Stale Cookie
            // Error cause with the measured staleness in microseconds.
            params.push(wire::RawParam {
                ptype: wire::CAUSE_STALE_COOKIE,
                value: us.to_be_bytes().to_vec(),
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
        self.peer_reconfig = supports_re_config(&init);
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
            // Stale cookie (RFC 9260 §5.1.5): send a fresh INIT-ACK — with
            // the Stale Cookie Error cause carrying the measured staleness —
            // if we still have the INIT that produced it.
            if let Some(init) = self.last_init.clone() {
                let stale_us = stale_ms.saturating_mul(1000).min(u32::MAX as u64) as u32;
                self.on_init(init, now, Some(stale_us));
            }
            return;
        }
        self.local_tag = parsed.server_tag;
        self.local_tsn = parsed.server_tsn;
        // The RSN space follows the (possibly cookie-assigned) initial TSN
        // (RFC 6525 §4.1).
        self.next_rsn = self.local_tsn;
        self.peer_tag = parsed.client_tag;
        self.peer_initial_tsn = parsed.client_tsn;
        self.peer_a_rwnd = parsed.client_rwnd as usize;
        self.peer_mis = parsed.client_mis;
        self.peer_forward_tsn = parsed.client_forward_tsn;
        self.peer_reconfig = parsed.client_reconfig;
        self.cum_tsn = parsed.client_tsn.wrapping_sub(1);
        self.peer_cum = parsed.server_tsn.wrapping_sub(1);
        self.state = State::Established;
        self.heartbeat_deadline = self.cfg.heartbeat_interval.map(|i| now + i);
        self.queue_packet(&[Chunk::CookieAck]);
        events.push(SctpEvent::Established);
    }

    // ------------------------------------------------------- data recv

    fn on_data(&mut self, d: DataChunk, now: Instant, events: &mut Vec<SctpEvent>) {
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
        // RFC 6525 §5.2.2 E2: while a deferred reset is in progress, data on
        // the affected streams beyond the peer's last assigned TSN is held
        // until the cumulative point reaches it.
        if let Some(def) = self.deferred_reset.as_mut() {
            if tsn_gt(d.tsn, def.last_tsn)
                && (def.streams.is_empty() || def.streams.contains(&d.stream))
            {
                def.held.insert(d.tsn, d);
                self.need_sack = true;
                return;
            }
        }
        self.ofo.insert(d.tsn, d.clone());
        // Unordered messages are delivered on arrival — TSN contiguity gates
        // only ordered delivery (RFC 9260 §6.6).
        if d.unordered {
            self.feed_unordered(d, now, events);
        }
        // Advance the cumulative point through contiguous TSNs, delivering
        // the ordered messages that become available.
        while let Some(c) = self.ofo.remove(&(self.cum_tsn.wrapping_add(1))) {
            self.cum_tsn = self.cum_tsn.wrapping_add(1);
            if !c.unordered {
                self.feed_ordered(c, now, events);
            }
        }
        self.need_sack = true;
        // The advance may have reached the deferred reset's target.
        self.check_deferred_reset(now, events);
    }

    fn record_dup(&mut self, tsn: u32) {
        self.stats.duplicates_rx += 1;
        if self.dups.len() < MAX_DUPS_IN_SACK {
            self.dups.push(tsn);
        }
        self.need_sack = true;
    }

    fn handle_dcep(
        &mut self,
        stream: u16,
        payload: &[u8],
        now: Instant,
        events: &mut Vec<SctpEvent>,
    ) {
        match dcep::parse(payload) {
            Ok(Some(open)) => {
                // RFC 8832 §5.1/§6: the PEER opens EVEN streams when it is
                // the DTLS client (we are the server) and ODD ones when it
                // is the server. A parity-violating OPEN must not be acked;
                // we cannot close the single channel per RFC 8831 (no
                // stream-reset support), so it is dropped instead — the
                // association stays up and the peer's reliable OPEN
                // retransmissions keep hitting the same guard. Valid OPEN
                // parity: even iff the peer is the DTLS client (= we are
                // the association responder).
                if (stream % 2 == 1) != self.cfg.is_client {
                    // RFC 8832 §5.1: an invalid OPEN is not acked. Task 51
                    // documented "drop" because stream reset did not exist
                    // here yet; with RFC 6525 support the spec action
                    // (RFC 8831 §6.7 close) is available: reset the stream
                    // so the peer sees its incoming side reset and closes
                    // its outgoing side — which also stops the reliable
                    // OPEN retransmissions. Without free reconfig capacity
                    // (one request at a time) or peer support, fall back to
                    // the documented drop: the association survives and the
                    // retransmitted OPENs keep hitting this guard.
                    if self.peer_reconfig
                        && self.cfg.stream_reset
                        && self.reconfig_outstanding.is_none()
                    {
                        self.send_re_config_request(vec![stream], now);
                    }
                    return;
                }
                if self.channels.contains_key(&stream) {
                    // RFC 8832 §5.1: OPEN on a channel that already exists is
                    // a protocol violation.
                    self.abort_protocol("duplicate DATA_CHANNEL_OPEN");
                    events.push(SctpEvent::Closed(CloseReason::ProtocolViolation(
                        "duplicate DATA_CHANNEL_OPEN".into(),
                    )));
                    return;
                }
                // Register the channel BEFORE the ack so the ack consumes
                // SSN 0 from the stream's ordered counter — registering it
                // afterwards reset the counter to 0 and the next message on
                // this stream re-used SSN 0, which the peer's expected-SSN
                // guard then dropped forever (silent data loss).
                self.channels.insert(
                    stream,
                    Channel {
                        channel_type: open.channel_type,
                        ssn: 0,
                        awaiting_ack: false,
                        closing: false,
                        closed_notified: false,
                    },
                );
                // The ack goes out reliably+ordered (documented choice). If
                // the send buffer is exhausted, roll the registration back:
                // the peer's reliable OPEN retransmission re-triggers us once
                // space frees (T3-RTX), so nothing is lost.
                let mut ack_msg = Vec::new();
                dcep::encode_ack(&mut ack_msg);
                if self
                    .enqueue_user(stream, PPID_DCEP_ACK, ack_msg, Policy::Reliable, false)
                    .is_err()
                {
                    self.channels.remove(&stream);
                    return;
                }
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

    fn feed_unordered(&mut self, c: DataChunk, now: Instant, events: &mut Vec<SctpEvent>) {
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
                    self.deliver_run(&run, now, events);
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
            self.deliver_run(&run, now, events);
        }
    }

    fn feed_ordered(&mut self, c: DataChunk, now: Instant, events: &mut Vec<SctpEvent>) {
        let stream = c.stream;
        let ssn = c.ssn;
        // Phase 0 — chunks of a message a FORWARD-TSN already skipped must
        // be dropped at feed time, not parked forever (RFC 3758 §4.2).
        {
            let buf = self.ordered.entry(stream).or_default();
            if ssn_lt(ssn, buf.expected) {
                return;
            }
        }
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
                        if !c.begin {
                            // A fragment run can only START on a B chunk;
                            // a continuation with no open run is junk —
                            // dropping it beats fabricating a run that can
                            // never reassemble.
                            return;
                        }
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
            self.deliver_run(&run, now, events);
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
                        self.deliver_run(&p, now, events);
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

    fn deliver_run(&mut self, run: &FragRun, now: Instant, events: &mut Vec<SctpEvent>) {
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
            self.handle_dcep(stream, &data, now, events);
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
    /// uses — EVEN for the association initiator / DTLS client, ODD for the
    /// responder / DTLS server (RFC 8832 §5.1/§6).
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
                closing: false,
                closed_notified: false,
            },
        );
        // Establishment messages go reliably+ordered (documented choice).
        self.enqueue_user(stream, PPID_DCEP_OPEN, msg, Policy::Reliable, false)?;
        self.flush(now);
        Ok(stream)
    }

    fn allocate_stream(&mut self) -> Result<u16, SctpError> {
        let limit = if self.peer_mis == 0 {
            self.cfg.os_streams
        } else {
            self.peer_mis.min(self.cfg.os_streams)
        };
        // Two passes over the parity space: ids freed by a completed
        // RFC 8831 §6.7 stream reset BELOW the high-water mark are reusable
        // ("Streams are available for reuse after a reset has been
        // performed"). A closing channel's id is still occupied (its entry
        // lives until the reset completes), so it is not handed out twice.
        // The scan result is explicit: without it, the wrap-around
        // assignment of a fully exhausted second pass would present an
        // OCCUPIED id as free (the exhaustion test caught exactly that).
        let mut id = self.next_outbound_stream;
        let mut found: Option<u16> = None;
        for _ in 0..2 {
            while id < limit && self.channels.contains_key(&id) {
                id = id.wrapping_add(2);
            }
            if id < limit {
                found = Some(id);
                break;
            }
            id = if self.cfg.is_client { 0 } else { 1 };
        }
        let Some(id) = found else {
            return Err(SctpError::SendBufferFull);
        };
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
        if ch.closing {
            return Err(SctpError::ChannelClosing(stream));
        }
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
        self.enqueue_user(stream, ppid, data, policy, channel_type.unordered())?;
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
    ) -> Result<(), SctpError> {
        let max_payload = self.cfg.mtu.saturating_sub(DATA_OVERHEAD).max(1);
        // Send-buffer bound (in chunks), enforced BEFORE any TSN is consumed:
        // popping already-assigned TSNs off the tail would punch a permanent
        // hole into the TSN sequence and stall the receiver's cumulative
        // point (and with it all ordered delivery) forever.
        let needed = (data.len() as u32).div_ceil(max_payload as u32).max(1);
        let budget = self.cfg.send_buffer_chunks as usize;
        if self.inflight.len() + needed as usize > budget {
            return Err(SctpError::SendBufferFull);
        }
        let msg_id = self.msg_counter;
        self.msg_counter += 1;
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
        self.stats.messages_tx += 1;
        Ok(())
    }

    /// Build packets from the send queue within cwnd/a_rwnd/MTU bounds.
    fn flush(&mut self, now: Instant) {
        if self.closed {
            return;
        }
        self.emit_forward_tsns(now);

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

    /// Payload bytes received but not yet delivered to the application:
    /// out-of-order queue + every reassembly run + messages held pending a
    /// DCEP OPEN. This is what `a_rwnd` must discount (RFC 9260 §6.2.1 —
    /// the advertised window reflects received-but-undelivered data).
    fn undelivered_bytes(&self) -> usize {
        let mut n = 0usize;
        for c in self.ofo.values() {
            n += c.payload.len();
        }
        for buf in self.ordered.values() {
            if let Some(run) = &buf.current {
                for c in run.pieces.values() {
                    n += c.payload.len();
                }
            }
            for run in buf.parked.values() {
                for c in run.pieces.values() {
                    n += c.payload.len();
                }
            }
        }
        if let Some(run) = &self.unordered.current {
            for c in run.pieces.values() {
                n += c.payload.len();
            }
        }
        for pending in self.pre_dcep.values() {
            for (_, data) in pending {
                n += data.len();
            }
        }
        n
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
        // RFC 9260 §6.2.1: a_rwnd = advertised window − received-but-undelivered
        // bytes (floor at 0; saturating so huge configs cannot overflow).
        let undelivered = self.undelivered_bytes().min(u32::MAX as usize) as u32;
        let a_rwnd = self.recv_window_bytes().saturating_sub(undelivered);
        let sack = Chunk::Sack(wire::SackChunk {
            cum_tsn: self.cum_tsn,
            a_rwnd,
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

        // RFC 3758 §3.5: the outstanding FORWARD-TSN is acknowledged once the
        // peer's cumulative point covers its new_cum — clear the record and
        // stop retransmitting it.
        if self
            .ftsn_outstanding
            .as_ref()
            .is_some_and(|f| tsn_le(f.new_cum, s.cum_tsn))
        {
            self.ftsn_outstanding = None;
            self.ftsn_deadline = None;
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
        // `inflight` is TSN-ordered, so merge the blocks into ranges and walk
        // the queue once — O(inflight + gaps) instead of a scan per TSN.
        let mut blocks: Vec<&SackBlock> = s
            .gaps
            .iter()
            .filter(|g| g.start >= 1 && g.start <= g.end)
            .collect();
        blocks.sort_by_key(|g| (g.start, g.end));
        let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(blocks.len());
        for g in blocks {
            let (gs, ge) = (
                s.cum_tsn.wrapping_add(g.start as u32),
                s.cum_tsn.wrapping_add(g.end as u32),
            );
            match ranges.last_mut() {
                Some((_, e)) if tsn_le(gs, *e) => {
                    if tsn_lt(*e, ge) {
                        *e = ge;
                    }
                }
                _ => ranges.push((gs, ge)),
            }
        }
        let mut ri = 0usize;
        let mut idx = 0usize;
        while idx < self.inflight.len() && ri < ranges.len() {
            let t = self.inflight[idx].tsn;
            let (gs, ge) = ranges[ri];
            if tsn_lt(t, gs) {
                idx += 1;
            } else if tsn_lt(ge, t) {
                ri += 1;
            } else {
                let c = self.inflight.remove(idx).unwrap();
                newly_acked += c.size;
                if c.retransmits == 0 && rtt_sample.is_none() {
                    rtt_sample = c
                        .last_sent
                        .map(|st| now.checked_duration_since(st).unwrap_or_default());
                }
                self.outstanding_bytes = self.outstanding_bytes.saturating_sub(c.size);
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
                // Slow start: at most min(newly_acked, MTU) per SACK.
                self.cwnd += newly_acked.min(self.cfg.mtu);
            } else {
                self.partial_bytes_acked += newly_acked;
                if self.partial_bytes_acked >= self.cwnd {
                    self.cwnd += self.cfg.mtu;
                    // §7.2.2: subtract the OLD cwnd, not the incremented one.
                    self.partial_bytes_acked -= self.cwnd - self.cfg.mtu;
                }
            }
        }

        // SACK-driven FORWARD-TSN retransmission pass (RFC 3758 §3.5): keep
        // the announcement alive until a cumulative ack covers it.
        if let Some(f) = self.ftsn_outstanding.clone() {
            self.queue_packet(&[Chunk::ForwardTsn {
                new_cum_tsn: f.new_cum,
                streams: f.streams,
            }]);
            self.stats.ftsn_tx += 1;
            self.ftsn_deadline = Some(now + self.rto);
        }

        if self.outstanding_bytes == 0 {
            self.t3_deadline = None;
            self.partial_bytes_acked = 0;
            if self.shutdown_pending {
                self.begin_shutdown(now);
            }
        }
    }

    // -------------------------------------------------- forward-tsn (PR)

    /// RFC 3758: advance the peer ack point over abandoned chunks and send
    /// FORWARD-TSN. Abandoned chunk buffers are freed at send time; the
    /// announcement itself is kept in `ftsn_outstanding` and retransmitted
    /// (T3 passes, SACK-driven passes and a dedicated deadline) until a
    /// SACK's cumulative point covers it (RFC 3758 §3.5). Returns true when
    /// a fresh announcement was just emitted (so callers do not re-send it
    /// again in the same pass).
    fn emit_forward_tsns(&mut self, now: Instant) -> bool {
        if !(self.peer_forward_tsn && self.cfg.forward_tsn) {
            // Without PR support abandoned chunks are just dropped (they can
            // only exist if the caller forced PR with both sides unaware —
            // send_message already degrades the policy, so this is defensive).
            self.inflight.retain(|c| !c.abandoned);
            return false;
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
            return false;
        };
        // Ordered stream skips for abandoned messages (RFC 3758 §3.2): one
        // entry per stream carrying the HIGHEST abandoned SSN, never
        // re-reported for newer skips below the recorded point.
        let mut streams: Vec<(u16, u16)> = Vec::new();
        for c in &self.inflight {
            if !c.abandoned || c.unordered || tsn_gt(c.tsn, new_cum) {
                continue;
            }
            if let Some(&last) = self.ftsn_reported.get(&c.stream) {
                if ssn_le(c.ssn, last) {
                    continue;
                }
            }
            match streams.iter_mut().find(|(s, _)| *s == c.stream) {
                // Later chunks of the same stream carry ≥ SSN (TSN order);
                // keep the max so exactly one entry per stream is emitted.
                Some((_, ssn)) => {
                    if ssn_lt(*ssn, c.ssn) {
                        *ssn = c.ssn;
                    }
                }
                None => streams.push((c.stream, c.ssn)),
            }
            let reported = self.ftsn_reported.entry(c.stream).or_insert(c.ssn);
            if ssn_lt(*reported, c.ssn) {
                *reported = c.ssn;
            }
        }
        streams.sort();
        // An earlier FORWARD-TSN that was never cumulatively acknowledged
        // must keep riding along (RFC 3758 §3.5): merge its skips in.
        if let Some(prev) = self.ftsn_outstanding.take() {
            for (sid, ssn) in prev.streams {
                if !streams.iter().any(|(s, _)| *s == sid) {
                    streams.push((sid, ssn));
                }
            }
            streams.sort();
        }
        self.inflight
            .retain(|c| !(c.abandoned && tsn_le(c.tsn, new_cum)));
        self.stats.ftsn_tx += 1;
        self.stats.abandoned += 1;
        self.ftsn_outstanding = Some(OutstandingFtsn {
            new_cum,
            streams: streams.clone(),
        });
        self.ftsn_deadline = Some(now + self.rto);
        self.queue_packet(&[Chunk::ForwardTsn {
            new_cum_tsn: new_cum,
            streams,
        }]);
        true
    }

    fn on_forward_tsn(
        &mut self,
        new_cum: u32,
        streams: &[(u16, u16)],
        now: Instant,
        events: &mut Vec<SctpEvent>,
    ) {
        if self.state != State::Established && self.state != State::ShutdownSent {
            return;
        }
        self.stats.ftsn_rx += 1;
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
        // FORWARD-TSN also moves the cumulative point — it can complete a
        // deferred stream reset (RFC 6525 §5.2.2 E2).
        self.check_deferred_reset(now, events);
    }

    // -------------------------------------------------- re-config (6525)

    /// Close one data channel per RFC 8831 §6.7: stop sending on it (A1)
    /// and reset our outgoing stream (Outgoing SSN Reset Request). The
    /// request is retransmitted until the peer's Response arrives; the
    /// channel is removed — and its stream id freed — on completion, where
    /// [`SctpEvent::DataChannelClosed`] fires.
    pub fn close_channel(&mut self, stream: u16, now: Instant) -> Result<(), SctpError> {
        if self.state != State::Established {
            return Err(SctpError::WrongState("not established"));
        }
        if !self.cfg.stream_reset {
            return Err(SctpError::WrongState("stream reset disabled"));
        }
        if !self.peer_reconfig {
            return Err(SctpError::WrongState(
                "peer does not advertise RFC 6525 support",
            ));
        }
        let ch = self
            .channels
            .get(&stream)
            .ok_or(SctpError::UnknownStream(stream))?;
        if ch.closing {
            return Err(SctpError::ChannelClosing(stream));
        }
        if self.reconfig_outstanding.is_some() {
            return Err(SctpError::ReconfigBusy);
        }
        // A1: stop assigning new SSNs for the affected stream — sends on it
        // are rejected from here on.
        if let Some(ch) = self.channels.get_mut(&stream) {
            ch.closing = true;
        }
        self.send_re_config_request(vec![stream], now);
        self.flush(now);
        Ok(())
    }

    /// §5.1.2 A2–A6: assign the next RSN, put the request into a RE-CONFIG
    /// chunk and record it for retransmission.
    fn send_re_config_request(&mut self, streams: Vec<u16>, now: Instant) {
        let rsn = self.next_rsn;
        self.next_rsn = self.next_rsn.wrapping_add(1);
        let response_seq = self
            .peer_rsn_seen
            .unwrap_or(self.peer_initial_tsn.wrapping_sub(1));
        let last_tsn = self.local_tsn.wrapping_sub(1);
        self.queue_re_config(&[ReConfigParam::OutgoingSsnReset {
            rsn,
            response_seq,
            last_tsn,
            streams: streams.clone(),
        }]);
        self.reconfig_outstanding = Some(OutstandingReconfig {
            rsn,
            streams,
            attempts: 0,
        });
        self.reconfig_deadline = Some(now + self.rto);
        self.stats.reconfig_tx += 1;
    }

    /// Start the reciprocal reset queued earliest (RFC 8831 §6.7: the side
    /// that sees an incoming stream reset also resets its outgoing stream).
    fn start_next_reciprocal(&mut self, now: Instant) {
        if self.reconfig_outstanding.is_some() {
            return;
        }
        while let Some(stream) = self.pending_recip.pop_front() {
            if self.channels.contains_key(&stream) {
                self.send_re_config_request(vec![stream], now);
                return;
            }
        }
    }

    fn queue_re_config(&mut self, params: &[ReConfigParam]) {
        self.queue_packet(&[Chunk::ReConfig(ReConfigChunk {
            params: params.to_vec(),
        })]);
    }

    /// §5.1.7 D1–D2: respond to a request, remembering the response so a
    /// retransmitted request gets the SAME answer (§5.2.1).
    fn send_re_config_response(&mut self, rsn: u32, result: u32) {
        self.queue_re_config(&[ReConfigParam::Response { rsn, result }]);
        self.last_response = Some((rsn, result));
        self.stats.reconfig_tx += 1;
    }

    /// RE-CONFIG chunk entry: process the parameters in order. A Response
    /// (or an E1 implicit acknowledgment) completes OUR outstanding
    /// request; a request resets the listed inbound streams — immediately
    /// or deferred (E2) — and is answered.
    fn on_re_config(&mut self, rc: ReConfigChunk, now: Instant, events: &mut Vec<SctpEvent>) {
        if self.state != State::Established && self.state != State::ShutdownSent {
            return;
        }
        self.stats.reconfig_rx += 1;
        for param in rc.params {
            match param {
                ReConfigParam::Response { rsn, result } => {
                    self.on_re_config_response(rsn, result, now, events);
                }
                ReConfigParam::OutgoingSsnReset {
                    rsn,
                    response_seq,
                    last_tsn,
                    streams,
                } => {
                    self.on_re_config_request(rsn, response_seq, last_tsn, streams, now, events);
                }
            }
        }
    }

    /// §5.1.1 E1: the response (or an implicit acknowledgment carried in a
    /// peer request's response_seq field) completes our request — the close
    /// finishes, the channels are removed and their ids become reusable.
    /// Non-terminal results (4 "already in progress" / 6 "in progress")
    /// keep the request alive for retransmission.
    fn on_re_config_response(
        &mut self,
        rsn: u32,
        result: u32,
        now: Instant,
        events: &mut Vec<SctpEvent>,
    ) {
        let matches = self
            .reconfig_outstanding
            .as_ref()
            .is_some_and(|out| out.rsn == rsn);
        if !matches {
            return; // stale / unsolicited response
        }
        let out = self.reconfig_outstanding.as_ref().unwrap().clone();
        match result {
            RC_RESULT_IN_PROGRESS_PEER | RC_RESULT_IN_PROGRESS => {
                // The peer is working on it (deferred reset on its side);
                // keep retransmitting until a final answer arrives.
                return;
            }
            RC_RESULT_NOTHING_TO_DO | RC_RESULT_PERFORMED => {
                // Success: the peer performed (or had already performed)
                // the reset of our outgoing streams.
            }
            _ => {
                // Denied / errors: the reset never happened on the peer.
                // The channel is dead for the application either way — we
                // complete the close locally and free the id (documented
                // choice; a stream whose peer kept its SSN state cannot be
                // reused safely, so a DENIED close leaves the id consumed
                // unless the channel had been removed by a completed
                // incoming reset as well).
            }
        }
        self.reconfig_outstanding = None;
        self.reconfig_deadline = None;
        for s in out.streams {
            if let Some(ch) = self.channels.get_mut(&s) {
                if !ch.closed_notified {
                    ch.closed_notified = true;
                    events.push(SctpEvent::DataChannelClosed { stream: s });
                }
            }
            self.channels.remove(&s);
            // Our own SSNs for this stream restart at 0 (RFC 8831 §6.7 id
            // reuse): the old FORWARD-TSN skip point must not suppress the
            // reused stream's skips.
            self.ftsn_reported.remove(&s);
        }
        self.start_next_reciprocal(now);
    }

    /// §5.2.2: an incoming Outgoing SSN Reset Request for the streams WE
    /// RECEIVE on. Duplicate RSNs are answered with the stored response;
    /// a request whose last_tsn is ahead of our cumulative point enters
    /// deferred processing (E2, result 6) and completes later.
    fn on_re_config_request(
        &mut self,
        rsn: u32,
        response_seq: u32,
        last_tsn: u32,
        streams: Vec<u16>,
        now: Instant,
        events: &mut Vec<SctpEvent>,
    ) {
        // E1 first: does this request implicitly acknowledge OUR outstanding
        // request (response_seq names the last of our RSNs the peer saw)?
        if let Some(out) = self.reconfig_outstanding.as_ref() {
            if tsn_ge(response_seq, out.rsn) {
                let rsn_copy = out.rsn;
                // Reuse the response path for the bookkeeping (success —
                // the peer would not advertise having seen our request
                // otherwise).
                self.on_re_config_response(rsn_copy, RC_RESULT_PERFORMED, now, events);
            }
        }
        // Duplicate request (retransmission): replay the same response
        // (§5.2.1). While a deferred reset for this very request is still
        // pending, the stored response IS the "In progress" one.
        if self.peer_rsn_seen == Some(rsn) {
            if let Some((seen, result)) = self.last_response {
                if seen == rsn {
                    self.send_re_config_response(rsn, result);
                }
            }
            return;
        }
        // A second request while one is already deferred cannot be served
        // (one deferred reset at a time — documented).
        if self.deferred_reset.is_some() {
            self.send_re_config_response(rsn, RC_RESULT_IN_PROGRESS_PEER);
            return;
        }
        self.peer_rsn_seen = Some(rsn);
        // A request for streams we know nothing about needs no deferral:
        // nothing can be reset, so answer "Nothing to do" right away (E2
        // defers only when a reset will actually be performed). A stream is
        // known when a channel is registered OR receive state exists — the
        // close INITIATOR has already removed its channel when the
        // reciprocal reset arrives, but its ordered buffer (expected SSN)
        // still needs the reset for the id to be safely reusable.
        let any_known = streams.is_empty()
            || streams
                .iter()
                .any(|s| self.channels.contains_key(s) || self.ordered.contains_key(s));
        if !any_known {
            self.send_re_config_response(rsn, RC_RESULT_NOTHING_TO_DO);
            return;
        }
        // E2: deferred reset processing when our cumulative point has not
        // reached the peer's last assigned TSN yet.
        if tsn_gt(last_tsn, self.cum_tsn) {
            self.deferred_reset = Some(DeferredReset {
                rsn,
                last_tsn,
                streams: streams.clone(),
                held: BTreeMap::new(),
            });
            self.send_re_config_response(rsn, RC_RESULT_IN_PROGRESS);
            return;
        }
        // E3–E5: perform the reset now and answer success.
        let performed = self.perform_incoming_reset(&streams, events);
        let result = if performed || streams.is_empty() {
            RC_RESULT_PERFORMED
        } else {
            RC_RESULT_NOTHING_TO_DO
        };
        self.send_re_config_response(rsn, result);
        self.start_next_reciprocal(now);
    }

    /// §5.2.2 E3 (the effect, shared by the immediate and the deferred
    /// path): reset the listed INBOUND streams — expected SSN back to 0,
    /// received-but-undelivered data on them discarded — and notify the
    /// application. Returns whether at least one listed stream was reset.
    /// Reciprocal resets (RFC 8831 §6.7) are queued for streams we also
    /// send on and that are not already covered by a request of our own.
    fn perform_incoming_reset(&mut self, streams: &[u16], events: &mut Vec<SctpEvent>) -> bool {
        let mut performed = false;
        let affected: Vec<u16> = if streams.is_empty() {
            // §4.1: an empty stream list means ALL inbound streams.
            let mut all: Vec<u16> = self.channels.keys().copied().collect();
            all.extend(self.ordered.keys().copied());
            all.sort_unstable();
            all.dedup();
            all
        } else {
            streams.to_vec()
        };
        for stream in affected {
            performed = true;
            // Received-but-undelivered data on the stream is discarded.
            self.pre_dcep.remove(&stream);
            self.ordered.insert(stream, OrderedBuf::default());
            // The stream's SSNs restart at 0 after the reset (RFC 6525
            // §5.2.2 E3) — a stale FORWARD-TSN skip point recorded BEFORE
            // the reset would suppress the new stream's skips (ssn_le(0,
            // stale) is always true) and permanently stall ordered delivery
            // after an id is reused.
            self.ftsn_reported.remove(&stream);
            let stale: Vec<u32> = self
                .ofo
                .iter()
                .filter(|(_, c)| c.stream == stream)
                .map(|(t, _)| *t)
                .collect();
            for t in stale {
                self.ofo.remove(&t);
            }
            // Application notification: the peer's side of this channel is
            // gone; sends are rejected from here on.
            let channel_exists = self.channels.contains_key(&stream);
            if let Some(ch) = self.channels.get_mut(&stream) {
                if !ch.closed_notified {
                    ch.closed_notified = true;
                    ch.closing = true;
                    events.push(SctpEvent::DataChannelClosed { stream });
                }
            }
            // RFC 8831 §6.7: we also SEND on this stream, so reset it too —
            // queued while another request of ours is in flight (documented
            // simplification: one outstanding request at a time).
            let in_flight = self
                .reconfig_outstanding
                .as_ref()
                .is_some_and(|r| r.streams.contains(&stream));
            if channel_exists && !in_flight && !self.pending_recip.contains(&stream) {
                self.pending_recip.push_back(stream);
            }
        }
        performed
    }

    /// The deferred-reset completion check (RFC 6525 §5.2.2 E2→E5): once
    /// our cumulative point reaches the peer's last assigned TSN, the
    /// affected streams are reset, the held chunks are released into the
    /// normal receive path and the final success response goes out.
    fn check_deferred_reset(&mut self, now: Instant, events: &mut Vec<SctpEvent>) {
        let Some(def) = self.deferred_reset.as_ref() else {
            return;
        };
        if tsn_gt(def.last_tsn, self.cum_tsn) {
            return; // still ahead of the cumulative point
        }
        let def = self.deferred_reset.take().unwrap();
        let streams = def.streams.clone();
        self.perform_incoming_reset(&streams, events);
        // E4: release the queued chunks, in TSN order, through the normal
        // receive path (they are new-epoch data: SSNs restart at 0).
        for (_, d) in def.held {
            if tsn_le(d.tsn, self.cum_tsn) || self.ofo.contains_key(&d.tsn) {
                continue; // delivered by a retransmission in between
            }
            self.ofo.insert(d.tsn, d.clone());
            if d.unordered {
                self.feed_unordered(d, now, events);
            }
            while let Some(c) = self.ofo.remove(&(self.cum_tsn.wrapping_add(1))) {
                self.cum_tsn = self.cum_tsn.wrapping_add(1);
                if !c.unordered {
                    self.feed_ordered(c, now, events);
                }
            }
        }
        // E5: the final response for the request — and any reciprocal reset
        // the reset just queued can start now.
        self.send_re_config_response(def.rsn, RC_RESULT_PERFORMED);
        self.start_next_reciprocal(now);
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
        consider(self.t2.as_ref().map(|t| t.deadline));
        consider(self.t3_deadline);
        consider(self.heartbeat_deadline);
        consider(self.ftsn_deadline);
        consider(self.reconfig_deadline);
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

    /// Fire all due timers at virtual time `now`. Terminal timer events
    /// (handshake / shutdown retransmission exhaustion) are returned so the
    /// application learns why the association went away.
    pub fn on_timeout(&mut self, now: Instant) -> Vec<SctpEvent> {
        let mut events = Vec::new();
        if self.closed {
            return events;
        }
        // T1-INIT / T1-COOKIE: retransmit with exponential backoff (the RTO
        // doubles per attempt, clamped at rto_max — RFC 9260 §4/§5).
        let t1_due = self.t1.as_ref().is_some_and(|t| t.deadline <= now);
        if t1_due {
            let attempts = self.t1.as_ref().map(|t| t.attempts + 1).unwrap_or(1);
            let payload = self
                .t1
                .as_ref()
                .map(|t| t.payload.clone())
                .unwrap_or_default();
            if attempts > MAX_INIT_RETRANS {
                self.t1 = None;
                self.close_out();
                events.push(SctpEvent::Closed(CloseReason::HandshakeTimeout));
                return events;
            }
            self.rto = (self.rto * 2).min(self.cfg.rto_max);
            self.t1 = Some(T1 {
                deadline: now + self.rto,
                attempts,
                payload: payload.clone(),
            });
            self.outbox.push_back(payload);
            self.stats.packets_tx += 1;
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
        let t3_due = self
            .t3_deadline
            .is_some_and(|d| d <= now && self.outstanding_bytes > 0);
        if t3_due {
            self.rto = (self.rto * 2).min(self.cfg.rto_max);
            // RFC 9260 §7.2.3: ssthresh = max(cwnd/2, 4*MTU) — never below
            // the initial congestion window.
            self.ssthresh = (self.cwnd / 2).max(4 * self.cfg.mtu);
            self.cwnd = self.cfg.mtu;
            self.partial_bytes_acked = 0;
            let mut exhausted: Vec<u64> = Vec::new();
            for c in self.inflight.iter_mut() {
                if c.sent && !c.abandoned {
                    c.retransmits += 1;
                    if let Policy::MaxRetrans(n) = c.policy {
                        if c.retransmits > n {
                            // Abandoned in this same pass: the chunk is
                            // retired, NOT retransmitted — it must not
                            // inflate the retransmission counter.
                            exhausted.push(c.msg_id);
                            continue;
                        }
                    }
                    self.stats.retransmits_tx += 1;
                }
            }
            for msg in exhausted {
                self.abandon_message(msg);
            }
            // RFC 3758 §3.5: every retransmission pass re-sends an
            // unacknowledged FORWARD-TSN alongside the data chunks — unless
            // the sweep above just emitted a fresh one (it already rides
            // this pass).
            if !self.emit_forward_tsns(now) {
                if let Some(f) = self.ftsn_outstanding.clone() {
                    self.queue_packet(&[Chunk::ForwardTsn {
                        new_cum_tsn: f.new_cum,
                        streams: f.streams,
                    }]);
                    self.stats.ftsn_tx += 1;
                    self.ftsn_deadline = Some(now + self.rto);
                }
            }
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
        // T2-SHUTDOWN / T2-SHUTDOWN-ACK (RFC 9260 §9.1/§9.2): the payload is
        // rebuilt from the state at each fire. Exhaustion aborts.
        let t2_due = self.t2.as_ref().is_some_and(|t| t.deadline <= now);
        if t2_due {
            let attempts = self.t2.as_ref().map(|t| t.attempts + 1).unwrap_or(1);
            if attempts > MAX_INIT_RETRANS {
                self.t2 = None;
                self.close_out();
                events.push(SctpEvent::Closed(CloseReason::ShutdownTimeout));
                return events;
            }
            self.rto = (self.rto * 2).min(self.cfg.rto_max);
            self.t2 = Some(T2 {
                deadline: now + self.rto,
                attempts,
            });
            match self.state {
                State::ShutdownSent => {
                    self.queue_packet(&[Chunk::Shutdown {
                        cum_tsn: self.cum_tsn,
                    }]);
                }
                State::ShutdownAckSent => {
                    self.queue_packet(&[Chunk::ShutdownAck]);
                }
                _ => self.t2 = None, // stale timer (state moved on)
            }
        }
        // Outstanding FORWARD-TSN deadline (RFC 3758 §3.5): there may be no
        // T3 running once every abandoned chunk left the queue — the FTSN
        // would otherwise never be regenerated after a loss.
        let ftsn_due = self
            .ftsn_deadline
            .is_some_and(|d| d <= now && self.ftsn_outstanding.is_some());
        if ftsn_due {
            if let Some(f) = self.ftsn_outstanding.clone() {
                self.queue_packet(&[Chunk::ForwardTsn {
                    new_cum_tsn: f.new_cum,
                    streams: f.streams,
                }]);
                self.stats.ftsn_tx += 1;
            }
            self.ftsn_deadline = Some(now + self.rto);
        }
        // Re-configuration timer (RFC 6525 §5.1.1): retransmit the
        // outstanding Outgoing SSN Reset Request with RTO backoff.
        // Exhaustion completes the close locally (the channel is dead for
        // the application either way; the association survives).
        let rc_due = self
            .reconfig_deadline
            .is_some_and(|d| d <= now && self.reconfig_outstanding.is_some());
        if rc_due {
            let out = self.reconfig_outstanding.as_ref().unwrap().clone();
            if out.attempts >= MAX_INIT_RETRANS {
                self.reconfig_outstanding = None;
                self.reconfig_deadline = None;
                for s in out.streams {
                    if let Some(ch) = self.channels.get_mut(&s) {
                        if !ch.closed_notified {
                            ch.closed_notified = true;
                            events.push(SctpEvent::DataChannelClosed { stream: s });
                        }
                    }
                    self.channels.remove(&s);
                    // Same id-reuse hygiene as the success path: the reset
                    // never completed, but the channel is gone and the peer
                    // may free the id — our stale skip point must not
                    // suppress the reused stream's FORWARD-TSN skips.
                    self.ftsn_reported.remove(&s);
                }
            } else {
                let (rsn, streams) = {
                    let out = self.reconfig_outstanding.as_mut().unwrap();
                    out.attempts += 1;
                    (out.rsn, out.streams.clone())
                };
                self.rto = (self.rto * 2).min(self.cfg.rto_max);
                self.reconfig_deadline = Some(now + self.rto);
                let response_seq = self
                    .peer_rsn_seen
                    .unwrap_or(self.peer_initial_tsn.wrapping_sub(1));
                self.queue_re_config(&[ReConfigParam::OutgoingSsnReset {
                    rsn,
                    response_seq,
                    last_tsn: self.local_tsn.wrapping_sub(1),
                    streams,
                }]);
                self.stats.reconfig_tx += 1;
            }
        }
        // Heartbeat.
        if let Some(deadline) = self.heartbeat_deadline {
            if deadline <= now && self.state == State::Established {
                if let Some(interval) = self.cfg.heartbeat_interval {
                    self.heartbeat_counter += 1;
                    let mut info = Vec::new();
                    info.extend_from_slice(&self.heartbeat_counter.to_be_bytes());
                    info.extend_from_slice(&now_unix_ms().to_be_bytes());
                    self.queue_packet(&[Chunk::Heartbeat { info }]);
                    self.heartbeat_deadline = Some(now + interval);
                } else {
                    // Deadline without an interval cannot re-arm itself.
                    self.heartbeat_deadline = None;
                }
            }
        }
        self.flush(now);
        events
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
    pub fn shutdown(&mut self, now: Instant) -> Result<(), SctpError> {
        if self.state != State::Established {
            return Err(SctpError::WrongState("not established"));
        }
        self.shutdown_pending = true;
        if self.outstanding_bytes == 0 {
            self.begin_shutdown(now);
        }
        Ok(())
    }

    fn begin_shutdown(&mut self, now: Instant) {
        self.shutdown_pending = false;
        self.queue_packet(&[Chunk::Shutdown {
            cum_tsn: self.cum_tsn,
        }]);
        self.state = State::ShutdownSent;
        // T2-SHUTDOWN guards the exchange (RFC 9260 §9.1).
        self.t2 = Some(T2 {
            deadline: now + self.rto,
            attempts: 0,
        });
    }

    fn on_shutdown(&mut self, now: Instant) {
        match self.state {
            State::Established | State::ShutdownSent => {
                self.queue_packet(&[Chunk::ShutdownAck]);
                self.state = State::ShutdownAckSent;
                // T2-SHUTDOWN-ACK guards our half of the exchange
                // (RFC 9260 §9.2).
                self.t2 = Some(T2 {
                    deadline: now + self.rto,
                    attempts: 0,
                });
            }
            State::ShutdownAckSent => {
                // Retransmitted SHUTDOWN — re-ack idempotently (§9.2).
                self.queue_packet(&[Chunk::ShutdownAck]);
            }
            _ => {}
        }
    }

    fn on_shutdown_ack(&mut self, events: &mut Vec<SctpEvent>) {
        if self.state != State::ShutdownSent {
            return;
        }
        self.t2 = None;
        self.queue_packet(&[Chunk::ShutdownComplete { reflected: false }]);
        self.close_out();
        events.push(SctpEvent::Closed(CloseReason::Shutdown));
    }

    fn on_shutdown_complete(&mut self, events: &mut Vec<SctpEvent>) {
        if self.state != State::ShutdownAckSent {
            return;
        }
        self.t2 = None;
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
        self.t2 = None;
        self.t3_deadline = None;
        self.heartbeat_deadline = None;
        self.ftsn_deadline = None;
        self.ftsn_outstanding = None;
        self.reconfig_outstanding = None;
        self.reconfig_deadline = None;
        self.deferred_reset = None;
        self.pending_recip.clear();
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
        let mut buf = Vec::with_capacity(COOKIE_LEN);
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
                                                        // Byte 49 was padding; it now carries the RE-CONFIG support flag.
                                                        // Old-version cookies (padding zero) parse as "no stream reset" —
                                                        // the conservative default — and the MAC still validates, so no
                                                        // version bump of the cookie magic is needed.
        buf.push(u8::from(supports_re_config(init))); // 49
        buf.extend_from_slice(&[0u8; 2]); // 50..52 (alignment)
        let mut nonce = [0u8; 8];
        fill_random(&mut nonce);
        buf.extend_from_slice(&nonce); // 52..60
        let mac = cookie_mac(&self.cookie_key, &buf);
        buf.extend_from_slice(&mac); // 60..76
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
    client_reconfig: bool,
    issued_ms: u64,
}

fn cookie_valid_mac(key: &[u8; 32], buf: &[u8]) -> bool {
    if buf.len() != COOKIE_LEN || &buf[..8] != b"SCTPCK01" {
        return false;
    }
    let mac: [u8; COOKIE_MAC_LEN] = match buf[COOKIE_MAC_AT..COOKIE_LEN].try_into() {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac == cookie_mac(key, &buf[..COOKIE_MAC_AT])
}

fn parse_cookie(buf: &[u8]) -> Result<CookieState, SctpError> {
    if buf.len() != COOKIE_LEN || &buf[..8] != b"SCTPCK01" {
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
        client_reconfig: buf[49] != 0,
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

fn supports_re_config(init: &wire::InitChunk) -> bool {
    init.param(wire::PT_SUPPORTED_EXTENSIONS)
        .map(|v| v.contains(&CT_RE_CONFIG))
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

    /// AUD-6: the random nonce inside the MAC'd region must make every
    /// issued cookie distinct — two cookies for the SAME INIT used to be
    /// byte-identical within one clock tick, so a captured COOKIE-ECHO
    /// replayed as another exchange's cookie looked fresh.
    #[test]
    fn cookie_nonce_makes_reissued_cookies_distinct() {
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
        let a = ep.build_cookie(&init);
        let b = ep.build_cookie(&init);
        assert_ne!(a, b, "nonce must make re-issued cookies distinct");
        assert_eq!(a.len(), COOKIE_LEN);
        for c in [&a, &b] {
            assert!(cookie_valid_mac(&ep.cookie_key, c), "MAC must validate");
            assert_eq!(parse_cookie(c).unwrap().client_tag, 111);
        }
    }
}
