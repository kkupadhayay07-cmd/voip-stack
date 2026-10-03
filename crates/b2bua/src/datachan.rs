//! SCTP data channels over the leg's established WebRTC DTLS transport
//! ([RFC 8261]): an SCTP packet is the entire DTLS application payload, and
//! DCEP ([RFC 8832]) establishes channels in-band on stream 0.
//!
//! Ownership on a WebRTC leg: the media pump keeps SRTP RTP/RTCP flowing
//! and forwards post-handshake DTLS records (first byte 20–63, RFC 7983)
//! into this engine's inbound channel; this engine owns the DTLS endpoint
//! and the SCTP association. The B2BUA is the DTLS *client* (`setup:active`,
//! RFC 5763 §5), so it is the SCTP association initiator and its own
//! channels take odd stream ids (RFC 8832 §6); peer-opened channels arrive
//! on even ids.
//!
//! The engine is a single tokio task with three inputs — inbound DTLS
//! records from the pump, application commands, and the association's
//! timer wheel (`poll_timeout`/`on_timeout`) — and one output: SCTP packets
//! encrypted through DTLS and sent over the leg socket (no SRTP: DTLS
//! records are their own protection). When the pump stops (call teardown)
//! its sender drops, the inbound channel closes and the task exits.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use dtls::DtlsEndpoint;
use sctp::{SctpConfig, SctpEndpoint, SctpEvent};

/// The SCTP port the association runs on when the offer did not override it
/// (mirrors [`sctp::SctpConfig::default`] and `sdp_util::SCTP_PORT`).
pub const DEFAULT_SCTP_PORT: u16 = 5000;

/// Read buffer for DTLS application records. Must hold the largest DTLS
/// record (2^14 payload + overhead): OpenSSL does not fragment app-data
/// writes to the handshake MTU, and the queue transport truncates a datagram
/// to the caller's buffer (a truncated record is silently dropped by the
/// DTLS MAC check).
const APP_BUF_SIZE: usize = 65_535;

/// What happens to a user message received on a data channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagePolicy {
    /// Echo each message back on the same stream with the same PPID — the
    /// transparent loopback the demo and integration tests run.
    Echo,
    /// Receive and count only.
    Drop,
}

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct DataChannelConfig {
    /// The SCTP port the PEER's association listens on (from the offer's
    /// `a=sctp-port`, RFC 8841).
    pub remote_sctp_port: u16,
    /// Our DTLS role on this transport. It drives the association role (the
    /// DTLS client sends the INIT — RFC 8261 wiring) and, through it, the
    /// RFC 8832 §5.1/§6 stream parity (the DTLS client opens EVEN streams).
    pub we_are_dtls_client: bool,
    /// Largest message we accept (mirrors the SDP answer's
    /// `a=max-message-size`).
    pub max_message_size: usize,
    pub policy: MessagePolicy,
}

impl Default for DataChannelConfig {
    fn default() -> Self {
        DataChannelConfig {
            remote_sctp_port: DEFAULT_SCTP_PORT,
            // The leg-A answerer shape: we answered `setup:active`, so we
            // are the DTLS client (RFC 5763 §5).
            we_are_dtls_client: true,
            max_message_size: 256 * 1024,
            policy: MessagePolicy::Echo,
        }
    }
}

/// Application command injected into the running engine.
#[derive(Debug, Clone)]
pub enum DataCommand {
    /// Send one user message on an open channel (fragmented by the SCTP
    /// engine as needed; reliability follows the channel's DCEP type).
    Send {
        stream: u16,
        ppid: u32,
        data: Vec<u8>,
    },
    /// Close the data channel per RFC 8831 §6.7 (RFC 6525 stream reset):
    /// the engine sends the Outgoing SSN Reset Request, the peer responds
    /// and reciprocates, and the stream id becomes reusable once the
    /// exchange completes.
    CloseChannel { stream: u16 },
}

/// Shared counters for the end-of-call observability trail.
#[derive(Debug, Default)]
pub struct DataChannelStats {
    pub channels_opened: std::sync::atomic::AtomicU64,
    pub channels_closed: std::sync::atomic::AtomicU64,
    pub messages_rx: std::sync::atomic::AtomicU64,
    pub messages_tx: std::sync::atomic::AtomicU64,
    pub sctp_packets_rx: std::sync::atomic::AtomicU64,
    pub sctp_packets_tx: std::sync::atomic::AtomicU64,
}

impl DataChannelStats {
    fn add(slot: &std::sync::atomic::AtomicU64, by: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        slot.fetch_add(by, Relaxed);
    }
}

/// Handle to one running data-channel engine.
pub struct DataChannelHandle {
    /// Send commands to the engine. Dropping the handle (and the pump) ends
    /// the task: the inbound channel closes when the pump's sender drops.
    pub cmds: mpsc::UnboundedSender<DataCommand>,
    pub stats: Arc<DataChannelStats>,
}

/// Spawn the engine on an established WebRTC transport.
///
/// `inbound` receives post-handshake DTLS records forwarded by the leg's
/// media pump; `dtls` is the live endpoint from
/// [`crate::webrtc::EstablishedMedia`]. The B2BUA drives the SCTP handshake
/// as the association initiator (DTLS client).
pub fn spawn(
    cfg: DataChannelConfig,
    dtls: DtlsEndpoint,
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
) -> DataChannelHandle {
    let stats = Arc::new(DataChannelStats::default());
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let task_stats = Arc::clone(&stats);

    tokio::spawn(async move {
        run(cfg, dtls, socket, remote, inbound, cmd_rx, task_stats).await;
    });

    DataChannelHandle {
        cmds: cmd_tx,
        stats,
    }
}

/// The engine loop. Inputs race through `select!`; after EVERY input the
/// pending work is drained (decrypted SCTP packets, outbound SCTP packets,
/// timer wheel) — flush-on-input, exactly like the media pump.
async fn run(
    cfg: DataChannelConfig,
    mut dtls: DtlsEndpoint,
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    mut inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    mut cmds: mpsc::UnboundedReceiver<DataCommand>,
    stats: Arc<DataChannelStats>,
) {
    // The association role follows the DTLS role (RFC 8261): the DTLS
    // client sends the INIT — and opens EVEN streams, the DTLS server ODD
    // ones (RFC 8832 §5.1/§6, enforced by the sctp engine's allocator).
    let sctp_cfg = SctpConfig {
        is_client: cfg.we_are_dtls_client,
        local_port: DEFAULT_SCTP_PORT,
        remote_port: cfg.remote_sctp_port,
        // Room for the DTLS/IP overhead over the wire (WebRTC-blessed MTU;
        // SCTP packets stay ≤ this so every send_app_data is one record).
        mtu: 1200,
        max_message_size: cfg.max_message_size,
        ..SctpConfig::default()
    };
    let mut sctp = if cfg.we_are_dtls_client {
        match SctpEndpoint::new_client(sctp_cfg, Instant::now()) {
            Ok(ep) => ep,
            Err(e) => {
                tracing::warn!("data channels: sctp endpoint init failed: {e}");
                return;
            }
        }
    } else {
        // DTLS server: we wait for the peer's INIT (the responder role).
        SctpEndpoint::new_server(sctp_cfg)
    };
    send_sctp(&mut dtls, &mut sctp, &socket, remote, &stats).await;

    let mut app_buf = vec![0u8; APP_BUF_SIZE];

    loop {
        // Recompute the deadline EVERY iteration: inputs that create a
        // NEWER deadline than the one currently being slept on (a channel
        // close's RFC 6525 retransmission timer, an inbound-loss T3, an
        // FTSN ride-along) must wake the select immediately, not after the
        // stale earlier deadline elapses.
        let mut timer: Option<tokio::time::Instant> =
            sctp.poll_timeout().map(tokio::time::Instant::from_std);
        tokio::select! {
            rec = inbound.recv() => {
                match rec {
                    Some(datagram) => {
                        dtls.push_datagram(datagram);
                    }
                    // Pump stopped: the call is over.
                    None => break,
                }
            }
            cmd = cmds.recv() => {
                match cmd {
                    Some(DataCommand::Send { stream, ppid, data }) => {
                        match sctp.send_message(stream, ppid, data, Instant::now()) {
                            Ok(()) => DataChannelStats::add(&stats.messages_tx, 1),
                            Err(e) => tracing::debug!("data channels: send rejected: {e}"),
                        }
                    }
                    Some(DataCommand::CloseChannel { stream }) => {
                        match sctp.close_channel(stream, Instant::now()) {
                            Ok(()) => tracing::info!(stream, "data channel: closing (RFC 8831 §6.7 reset)"),
                            Err(e) => tracing::debug!("data channels: close rejected: {e}"),
                        }
                    }
                    // Application dropped the handle: keep serving the
                    // association until the pump side closes.
                    None => {}
                }
            }
            _ = async {
                match timer {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            }, if timer.is_some() => {
                timer = None;
                let now = Instant::now();
                for ev in sctp.on_timeout(now) {
                    if !handle_event(&mut sctp, ev, &cfg, &stats, &socket, &remote).await {
                        break;
                    }
                }
                if sctp.is_closed() {
                    send_sctp(&mut dtls, &mut sctp, &socket, remote, &stats).await;
                    break;
                }
            }
        }
        // Drain whatever the last input produced (decrypted SCTP packets,
        // retransmissions, handshake progress) and refresh the timer.
        if !drain_dtls_in(
            &mut dtls,
            &mut sctp,
            &mut app_buf,
            &cfg,
            &stats,
            &socket,
            &remote,
        )
        .await
        {
            break;
        }
        send_sctp(&mut dtls, &mut sctp, &socket, remote, &stats).await;
        if sctp.is_closed() {
            break;
        }
    }
    tracing::info!(
        channels = DataChannelStats::load(&stats.channels_opened),
        rx = DataChannelStats::load(&stats.messages_rx),
        tx = DataChannelStats::load(&stats.messages_tx),
        "data-channel engine stopped"
    );
}

/// Pop every pending DTLS record's decrypted payload and feed it to the SCTP
/// association. Returns `false` when the association ended.
async fn drain_dtls_in(
    dtls: &mut DtlsEndpoint,
    sctp: &mut SctpEndpoint,
    app_buf: &mut [u8],
    cfg: &DataChannelConfig,
    stats: &Arc<DataChannelStats>,
    socket: &Arc<UdpSocket>,
    remote: &SocketAddr,
) -> bool {
    loop {
        match dtls.recv_app_data(app_buf) {
            Ok(Some(n)) if n > 0 => {
                DataChannelStats::add(&stats.sctp_packets_rx, 1);
                let now = Instant::now();
                for ev in sctp.handle_packet(&app_buf[..n], now) {
                    if !handle_event(sctp, ev, cfg, stats, socket, remote).await {
                        return false;
                    }
                }
                if sctp.is_closed() {
                    return false;
                }
            }
            Ok(_) => return true, // queue drained
            Err(e) => {
                // A malformed record is dropped by OpenSSL before this; a
                // surfaced error means the DTLS association itself broke.
                tracing::info!("data channels: dtls app-data read failed: {e}");
                return false;
            }
        }
    }
}

/// Encrypt and send every SCTP packet the association queued.
async fn send_sctp(
    dtls: &mut DtlsEndpoint,
    sctp: &mut SctpEndpoint,
    socket: &Arc<UdpSocket>,
    remote: SocketAddr,
    stats: &Arc<DataChannelStats>,
) {
    let packets = sctp.drain_outbound();
    if packets.is_empty() {
        return;
    }
    DataChannelStats::add(&stats.sctp_packets_tx, packets.len() as u64);
    for pkt in packets {
        if dtls.send_app_data(&pkt).is_err() {
            return; // DTLS association broken; the loop notices on next read
        }
        for datagram in dtls.take_outbound() {
            let _ = socket.send_to(&datagram, remote).await;
        }
    }
}

/// React to one association event. Returns `false` when the loop must stop.
async fn handle_event(
    sctp: &mut SctpEndpoint,
    ev: SctpEvent,
    cfg: &DataChannelConfig,
    stats: &Arc<DataChannelStats>,
    _socket: &Arc<UdpSocket>,
    _remote: &SocketAddr,
) -> bool {
    match ev {
        SctpEvent::Established => {
            tracing::info!("data channels: SCTP association established");
            true
        }
        SctpEvent::DataChannelOpen {
            stream,
            label,
            protocol,
            ..
        } => {
            DataChannelStats::add(&stats.channels_opened, 1);
            tracing::info!(
                stream,
                label,
                protocol,
                "data channel opened by the peer (ack sent in-band)"
            );
            true
        }
        SctpEvent::DataChannelAck { stream } => {
            tracing::info!(stream, "data channel acked by the peer");
            true
        }
        SctpEvent::DataChannelClosed { stream } => {
            DataChannelStats::add(&stats.channels_closed, 1);
            tracing::info!(stream, "data channel closed (stream reset completed)");
            true
        }
        SctpEvent::Message {
            stream, ppid, data, ..
        } => {
            DataChannelStats::add(&stats.messages_rx, 1);
            match cfg.policy {
                MessagePolicy::Echo => {
                    let reply = data;
                    match sctp.send_message(stream, ppid, reply, Instant::now()) {
                        Ok(()) => DataChannelStats::add(&stats.messages_tx, 1),
                        Err(e) => tracing::debug!("data channels: echo send failed: {e}"),
                    }
                }
                MessagePolicy::Drop => {}
            }
            true
        }
        SctpEvent::Closed(reason) => {
            tracing::info!("data channels: association closed: {reason:?}");
            false
        }
    }
}

impl DataChannelStats {
    fn load(slot: &std::sync::atomic::AtomicU64) -> u64 {
        use std::sync::atomic::Ordering::Relaxed;
        slot.load(Relaxed)
    }
}
