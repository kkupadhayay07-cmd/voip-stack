//! Per-leg media pump: jitter buffering, decode → 16 kHz mono bridge →
//! encode, paced RTP transmission and RFC 4733 DTMF passthrough.
//!
//! Pumps are cross-connected by the engine: `bridge_out` carries this leg's
//! decoded 16 kHz mono PCM to the peer pump, `bridge_in` receives the peer's
//! 16 kHz mono PCM for encoding toward this leg's remote.

use bytes::Bytes;
use codecs::{CodecId, Decoder, Encoder, Registry, Resampler};
use rand::Rng;
use rtp::jitter::{JitterBuffer, JitterConfig, PushResult};
use rtp::nack::{nack_packet, nack_seqs, parse_nack_fci, NackTracker, RtxPool, RTX_POOL_DEFAULT};
use rtp::packet::{RtpExtension, RtpPacket};
use rtp::rtcp::{encode_compound, parse_compound, RtcpPacket, SdesChunk, SdesType, SenderInfo};
use rtp::twcc::{parse_twcc, twcc_packet, TwccRxMonitor, TwccSendTracker};
use srtp::SrtpSession;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex};

/// The linear bridge domain: 16 kHz mono (native for G.722; upsampled for
/// G.711/G.729; downsampled for Opus fullband — a fullband pass-through fast
/// path is a Phase 4 optimization).
pub const BRIDGE_RATE: u32 = 16_000;

/// SRTP sessions for one leg, keyed by the DTLS-SRTP handshake
/// (RFC 3711): `tx` protects what this leg sends, `rx` opens what it
/// receives.  Owned by the pump task — the sessions carry per-stream ROC
/// state that must not be shared.
pub struct CryptoPair {
    pub tx: SrtpSession,
    pub rx: SrtpSession,
}

impl std::fmt::Debug for CryptoPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoPair")
            .field("profile", &self.tx.profile())
            .finish()
    }
}

/// Protect an outbound datagram when the leg negotiated SRTP.  `rtcp`
/// selects the SRTCP transform (RFC 3711 §3.3/§3.4 — index + E-bit + auth
/// tag appended, unlike the SRTP packet-attached tag).  Returns `false`
/// when protection failed: the caller must NOT fall back to plaintext —
/// the leg negotiated SAVPF, so an unprotected packet is a wire-format
/// violation, not a fallback path.
fn seal(crypto: &mut Option<CryptoPair>, wire: &mut Vec<u8>, rtcp: bool) -> bool {
    let Some(cp) = crypto.as_mut() else {
        return true;
    };
    if rtcp {
        cp.tx.protect_rtcp(wire).is_ok()
    } else {
        cp.tx.protect(wire).is_ok()
    }
}

/// Everything the pump needs for one leg's media.
#[derive(Debug, Clone)]
pub struct PumpConfig {
    /// Codec decoded from the remote (this leg's RX codec).
    pub rx_codec: CodecId,
    /// Codec encoded toward the remote (this leg's TX codec).
    pub tx_codec: CodecId,
    /// Payload type the remote uses when sending to us.
    pub rx_pt: u8,
    /// Remote's payload type for telephone-event (relay path).
    pub te_pt_rx: Option<u8>,
    /// Payload type we transmit telephone-event with.
    pub te_pt_tx: Option<u8>,
    /// Payload type the remote expects for our TX codec.
    pub tx_pt: u8,
    /// The peer advertised `a=rtcp-fb:<pt> nack` (RFC 4585): answer NACK
    /// requests from the retransmission window and NACK the peer's gaps.
    pub nack: bool,
    /// Negotiated transport-cc header-extension id: stamp the one-byte
    /// sequence on every outbound packet (sender side), track arrival times
    /// of the peer's extension sequence numbers, emit RTCP transport-cc
    /// feedback (draft-holmerberg wire form) and correlate the peer's
    /// feedback against our send times.
    pub twcc_ext: Option<u8>,
    /// Period of the RTCP sender report (ms; floored at 50 at use site).
    pub rtcp_interval_ms: u64,
    /// Where post-handshake DTLS records (first byte 20–63, RFC 7983) go on
    /// a WebRTC leg with data channels: the `datachan` engine decrypts them
    /// into SCTP packets (RFC 8261). `None` drops the datagrams — a leg
    /// without negotiated data channels has nothing behind the DTLS seam.
    pub dtls_tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
}

/// Handle for one running pump task.
pub struct PumpHandle {
    pub stop: watch::Sender<bool>,
    pub task: tokio::task::JoinHandle<()>,
    pub remote: Arc<Mutex<Option<SocketAddr>>>,
    pub stats: Arc<MediaStats>,
}

/// Shared media counters surfaced in the end-of-call CDR.
#[derive(Debug, Default)]
pub struct MediaStats {
    pub frames_encoded: std::sync::atomic::AtomicU64,
    pub frames_concealed: std::sync::atomic::AtomicU64,
    pub packets_rx: std::sync::atomic::AtomicU64,
    pub packets_tx: std::sync::atomic::AtomicU64,
    pub packets_lost: std::sync::atomic::AtomicU64,
    /// RTCP packets parsed (counted per packet inside a compound, not per
    /// datagram).
    pub rtcp_rx: std::sync::atomic::AtomicU64,
    /// Generic NACK requests received (RFC 4585 §6.2.1).
    pub nacks_rx: std::sync::atomic::AtomicU64,
    /// Generic NACK FCI entries sent (gap sequences reported to the peer;
    /// up to 64 entries ride in one feedback packet).
    pub nacks_tx: std::sync::atomic::AtomicU64,
    /// Media packets retransmitted to answer a NACK.
    pub retransmits_tx: std::sync::atomic::AtomicU64,
    /// NACKed sequences no longer in the retransmission window.
    pub nack_misses: std::sync::atomic::AtomicU64,
    /// Transport-cc feedback reports received about our outbound stream
    /// (RTPFB fmt 15, draft-holmerberg wire form).
    pub twcc_feedbacks_rx: std::sync::atomic::AtomicU64,
    /// Packets reported lost in the latest transport-cc feedback window.
    pub twcc_window_lost: std::sync::atomic::AtomicU64,
    /// Mean excess transport-cc delay (µs) over the fastest observed packet
    /// across the latest feedback window (clock-domain free — see
    /// `TwccPacketResult::delay_us`).
    pub twcc_mean_delay_us: std::sync::atomic::AtomicI64,
    /// Datagrams dropped because SRTP protection/opening failed (never
    /// sent or parsed as plaintext).
    pub srtp_failures: std::sync::atomic::AtomicU64,
}

impl MediaStats {
    pub fn frames_encoded(&self) -> u64 {
        self.frames_encoded.load(Relaxed)
    }
    pub fn frames_concealed(&self) -> u64 {
        self.frames_concealed.load(Relaxed)
    }
    pub fn packets_rx(&self) -> u64 {
        self.packets_rx.load(Relaxed)
    }
    pub fn packets_tx(&self) -> u64 {
        self.packets_tx.load(Relaxed)
    }
    pub fn packets_lost(&self) -> u64 {
        self.packets_lost.load(Relaxed)
    }
    pub fn rtcp_rx(&self) -> u64 {
        self.rtcp_rx.load(Relaxed)
    }
    pub fn nacks_rx(&self) -> u64 {
        self.nacks_rx.load(Relaxed)
    }
    pub fn nacks_tx(&self) -> u64 {
        self.nacks_tx.load(Relaxed)
    }
    pub fn retransmits_tx(&self) -> u64 {
        self.retransmits_tx.load(Relaxed)
    }
    pub fn nack_misses(&self) -> u64 {
        self.nack_misses.load(Relaxed)
    }
    pub fn twcc_feedbacks_rx(&self) -> u64 {
        self.twcc_feedbacks_rx.load(Relaxed)
    }
    pub fn twcc_window_lost(&self) -> u64 {
        self.twcc_window_lost.load(Relaxed)
    }
    pub fn twcc_mean_delay_us(&self) -> i64 {
        self.twcc_mean_delay_us.load(Relaxed)
    }
    pub fn srtp_failures(&self) -> u64 {
        self.srtp_failures.load(Relaxed)
    }
}

fn pcm_rate(id: CodecId) -> u32 {
    match id {
        CodecId::G722 => 16_000,
        CodecId::Opus => 48_000,
        _ => 8_000,
    }
}

/// RTP clock rate for packetization of a codec.
pub fn rtp_clock(id: CodecId) -> u32 {
    match id {
        CodecId::Opus => 48_000,
        CodecId::L16 => 44_100,
        _ => 8_000,
    }
}

/// Collapse interleaved N-channel PCM to mono by averaging.
fn to_mono(pcm: &[i16], channels: u8) -> Vec<i16> {
    if channels <= 1 {
        return pcm.to_vec();
    }
    let ch = channels as usize;
    pcm.chunks(ch)
        .map(|c| {
            (c.iter().map(|&s| i32::from(s)).sum::<i32>() / ch as i32)
                .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
        })
        .collect()
}

/// One hop across the media bridge: decoded PCM toward the peer pump's
/// encoder, or an RFC 4733 DTMF event to be packetized onto the peer's
/// socket. DTMF crosses here (not out the receiving socket) so events reach
/// the OTHER leg instead of echoing back to the sender.
#[derive(Debug)]
pub enum BridgeMsg {
    Pcm(Vec<i16>),
    Dtmf {
        /// Original RTP timestamp of the event.
        timestamp: u32,
        /// Original marker bit.
        marker: bool,
        /// RFC 4733 event payload bytes.
        payload: Vec<u8>,
    },
}

/// Starts a media pump on an already-bound RTP socket (plaintext RTP/AVP
/// leg).
pub fn start_with_socket(
    cfg: PumpConfig,
    rtp: Arc<UdpSocket>,
    bridge_out: mpsc::Sender<BridgeMsg>,
    bridge_in: mpsc::Receiver<BridgeMsg>,
) -> Result<PumpHandle, codecs::CodecError> {
    start_with_socket_session_crypto(
        cfg,
        rtp,
        None,
        bridge_out,
        bridge_in,
        observ::CallSession::detached(),
    )
}

/// Same as [`start_with_socket`] but with a call context so the pump emits
/// correlated observability events (MediaStart/MediaStats/MediaEnd, RTP
/// packet taps).
pub fn start_with_socket_session(
    cfg: PumpConfig,
    rtp: Arc<UdpSocket>,
    bridge_out: mpsc::Sender<BridgeMsg>,
    bridge_in: mpsc::Receiver<BridgeMsg>,
    session: observ::CallSession,
) -> Result<PumpHandle, codecs::CodecError> {
    start_with_socket_session_crypto(cfg, rtp, None, bridge_out, bridge_in, session)
}

/// Starts a pump with optional SRTP crypto (`Some` on a leg that
/// negotiated UDP/TLS/RTP/SAVPF and completed ICE+DTLS).  The pump owns
/// the sessions: every send is protected, every receive opened, and an
/// unprotectable inbound datagram is dropped — never parsed as plaintext
/// (RFC 3711; no AVP/SAVPF fallback on a negotiated-secure leg).
pub fn start_with_socket_session_crypto(
    cfg: PumpConfig,
    rtp: Arc<UdpSocket>,
    crypto: Option<CryptoPair>,
    bridge_out: mpsc::Sender<BridgeMsg>,
    bridge_in: mpsc::Receiver<BridgeMsg>,
    session: observ::CallSession,
) -> Result<PumpHandle, codecs::CodecError> {
    let remote = Arc::new(Mutex::new(None::<SocketAddr>));
    let stats = Arc::new(MediaStats::default());
    let (stop_tx, stop) = watch::channel(false);

    let dec = Registry::decoder(cfg.rx_codec, pcm_rate(cfg.rx_codec), 1)?;
    let enc = Registry::encoder(cfg.tx_codec, pcm_rate(cfg.tx_codec), 1)?;

    let task = tokio::spawn(run_pump(
        cfg,
        rtp,
        crypto,
        remote.clone(),
        stats.clone(),
        dec,
        enc,
        stop,
        bridge_out,
        bridge_in,
        session,
    ));
    Ok(PumpHandle {
        stop: stop_tx,
        task,
        remote,
        stats,
    })
}

/// Per-leg media pump. Internal; the argument list mirrors the pump's
/// disjoint resources (socket, codecs, channels) — a config struct would
/// only obscure ownership.
#[allow(clippy::too_many_arguments)]
async fn run_pump(
    cfg: PumpConfig,
    rtp: Arc<UdpSocket>,
    mut crypto: Option<CryptoPair>,
    remote: Arc<Mutex<Option<SocketAddr>>>,
    stats: Arc<MediaStats>,
    mut dec: Box<dyn Decoder>,
    mut enc: Box<dyn Encoder>,
    mut stop: watch::Receiver<bool>,
    bridge_out: mpsc::Sender<BridgeMsg>,
    mut bridge_in: mpsc::Receiver<BridgeMsg>,
    session: observ::CallSession,
) {
    let local = rtp
        .local_addr()
        .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());
    // A wildcard bind must not leak 0.0.0.0 into capture addresses.
    let local = if local.ip().is_unspecified() {
        std::net::SocketAddr::new(std::net::IpAddr::from([127, 0, 0, 1]), local.port())
    } else {
        local
    };
    // media hook: pump start
    session.emit(observ::EventKind::MediaStart {
        pump_leg: session.leg(),
        local,
        rx_codec: format!("{:?}", cfg.rx_codec),
        tx_codec: format!("{:?}", cfg.tx_codec),
    });
    let rx_clock = rtp_clock(cfg.rx_codec);
    let tx_clock = rtp_clock(cfg.tx_codec);
    let rx_channels = dec.channels();

    let mut jb = JitterBuffer::new(JitterConfig::for_clock(rx_clock));
    let started = Instant::now();
    let mut buf = vec![0u8; 4096];

    let mut rs_rx = if dec.sample_rate() == BRIDGE_RATE {
        None
    } else {
        Resampler::new(dec.sample_rate(), BRIDGE_RATE, 1).ok()
    };
    let mut rs_tx = if enc.sample_rate() == BRIDGE_RATE {
        None
    } else {
        Resampler::new(BRIDGE_RATE, enc.sample_rate(), 1).ok()
    };

    let frame_pcm = enc.frame_samples() as u64;
    let frame_dur = Duration::from_nanos(1_000_000_000 * frame_pcm / u64::from(enc.sample_rate()));
    let mut ticker = tokio::time::interval(frame_dur.max(Duration::from_millis(5)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stats_tick = tokio::time::interval(Duration::from_secs(5));
    stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut out_seq: u16 = rand::thread_rng().gen();
    let mut out_ts: u32 = rand::thread_rng().gen();
    let ssrc: u32 = rand::thread_rng().gen();
    let ts_inc = (frame_pcm * u64::from(tx_clock) / u64::from(enc.sample_rate())).max(1) as u32;

    // RTCP channel state (RFC 3550 SR/RR + RFC 4585 NACK + transport-cc).
    let mut resend = RtxPool::new(RTX_POOL_DEFAULT);
    let mut nack_tracker = NackTracker::default();
    let mut twcc = TwccRxMonitor::new(1024);
    let mut twcc_fb_count: u8 = 0;
    // Sender side: stamp the negotiated transport-cc sequence (2-byte
    // element, draft-holmerberg §3.1) on every outbound packet and remember
    // send times so the peer's feedback correlates into per-packet delays.
    let mut twcc_tx_seq: u16 = 0;
    let mut twcc_tx = cfg.twcc_ext.map(|_| TwccSendTracker::new(1024));
    let mut remote_ssrc: Option<u32> = None;
    let mut tx_pkts: u64 = 0;
    let mut tx_octets: u64 = 0;
    let mut report_lost: u64 = 0;
    let mut report_rx: u64 = 0;
    // (NTP middle 32 bits of the peer's last SR, arrival instant)
    let mut last_sr: Option<(u32, Instant)> = None;
    let mut retransmit_guard: HashMap<u16, Instant> = HashMap::new();

    let rtcp_period = Duration::from_millis(cfg.rtcp_interval_ms.max(50));
    let mut rtcp_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + rtcp_period, rtcp_period);
    rtcp_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut twcc_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_millis(200),
        Duration::from_millis(200),
    );
    twcc_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = stats_tick.tick() => {
                // media hook: rolling counters every 5 s
                stats.packets_lost.store(jb.stats.packets_lost, Relaxed);
                session.emit(observ::EventKind::MediaStats {
                    pump_leg: session.leg(),
                    rx: stats.packets_rx(),
                    tx: stats.packets_tx(),
                    lost: stats.packets_lost(),
                    jitter_ms: jb.jitter_ms(),
                    concealed: stats.frames_concealed(),
                });
            }
            _ = rtcp_tick.tick() => {
                // RFC 3550 §6: periodic SR carrying our TX bookkeeping plus
                // a reception report about the peer's stream (the RR blocks
                // ride inside the SR). Sent only once a remote is learned.
                let dst = *remote.lock().await;
                let Some(dst) = dst else { continue };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let ntp_sec = (now.as_secs().wrapping_add(2_208_988_800)) as u32;
                let ntp_frac = ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000) as u32;
                let mut blocks = Vec::new();
                if let Some(rssrc) = remote_ssrc {
                    let lost_now = jb.stats.packets_lost;
                    let rx_now = stats.packets_rx();
                    let (d_lost, d_rx) = (lost_now.saturating_sub(report_lost), rx_now.saturating_sub(report_rx));
                    let fraction = (d_lost * 256)
                        .checked_div(d_lost + d_rx)
                        .unwrap_or(0)
                        .min(255) as u8;
                    let (last_sr_mid, dlsr) = match last_sr {
                        Some((mid, t)) => {
                            let el = t.elapsed();
                            // DLSR in 1/65536 s: micros × 65536 / 1e6,
                            // rounded (the millisecond shortcut drifted up
                            // to 7.4 ms, polluting peer RTT estimates).
                            let ticks = ((el.as_micros() * 65536 + 500_000) / 1_000_000)
                                .min(u128::from(u32::MAX)) as u32;
                            (mid, ticks)
                        }
                        None => (0, 0),
                    };
                    let highest = nack_tracker.highest_extended();
                    blocks.push(rtp::rtcp::ReportBlock {
                        ssrc: rssrc,
                        fraction_lost: fraction,
                        cumulative_lost: lost_now.min(0x007F_FFFF) as u32,
                        highest_sequence: if highest < 0 { 0 } else { (highest as u64 & 0xFFFF_FFFF) as u32 },
                        // Jitter in RTP timestamp units: keep µs precision
                        // through the conversion (an early ms truncation
                        // reported 0 for sub-millisecond jitter).
                        interarrival_jitter: (((jb.jitter_ms() * 1000.0) as u64
                            * u64::from(rx_clock))
                            / 1_000_000)
                            .min(u64::from(u32::MAX)) as u32,
                        last_sr: last_sr_mid,
                        delay_since_last_sr: dlsr,
                    });
                    report_lost = lost_now;
                    report_rx = rx_now;
                }
                let sr = RtcpPacket::SenderReport(
                    SenderInfo {
                        ssrc,
                        ntp_sec,
                        ntp_frac,
                        rtp_timestamp: out_ts,
                        packet_count: tx_pkts.min(u64::from(u32::MAX)) as u32,
                        octet_count: tx_octets.min(u64::from(u32::MAX)) as u32,
                    },
                    blocks,
                );
                // RFC 3550 §6.5.1: every compound RTCP packet carries SDES
                // with the CNAME item, identifying this RTCP member.
                let cname = RtcpPacket::Sdes(vec![SdesChunk {
                    ssrc,
                    items: vec![(SdesType::Cname, format!("zrtc-{ssrc:08x}"))],
                }]);
                let mut wire = encode_compound(&[sr, cname]);
                if seal(&mut crypto, &mut wire, true) {
                    let _ = rtp.send_to(&wire, dst).await;
                } else {
                    stats.srtp_failures.fetch_add(1, Relaxed);
                }
            }
            _ = twcc_tick.tick() => {
                // draft-holmerberg transport-cc: drain the arrival window
                // into an RTPFB fmt 15 feedback packet every 200 ms.
                if cfg.twcc_ext.is_some() {
                    let dst = *remote.lock().await;
                    if let (Some(dst), Some(rssrc)) = (dst, remote_ssrc) {
                        if let Some(fb) = twcc.build_feedback(ssrc, rssrc, twcc_fb_count) {
                            twcc_fb_count = twcc_fb_count.wrapping_add(1);
                            if let Ok(p) = twcc_packet(&fb) {
                                // RFC 3550 §6.1 / RFC 4585 §6.1: a compound
                                // starts with SR/RR — prefix an empty RR so
                                // strict receivers accept the feedback.
                                let rr = RtcpPacket::ReceiverReport {
                                    ssrc,
                                    blocks: Vec::new(),
                                };
                                let mut wire = encode_compound(&[rr, p]);
                                if seal(&mut crypto, &mut wire, true) {
                                    let _ = rtp.send_to(&wire, dst).await;
                                } else {
                                    stats.srtp_failures.fetch_add(1, Relaxed);
                                }
                            }
                        }
                    }
                }
            }
            r = rtp.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(x) => x,
                    Err(e) => { tracing::debug!("media recv err: {e}"); continue; }
                };
                // RFC 7983 demultiplexing on a secured leg: STUN (0–3)
                // never reaches the RTP/RTCP parsers; DTLS (20–63) is
                // forwarded to the data-channel engine when the leg
                // negotiated one (its records are the RFC 8261 SCTP seam)
                // and dropped otherwise.
                if crypto.is_some() {
                    match buf.first() {
                        Some(b) if *b <= 3 => continue,
                        Some(b) if (20..=63).contains(b) => {
                            if let Some(tx) = &cfg.dtls_tx {
                                let _ = tx.send(buf[..n].to_vec());
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                if rtp::looks_like_rtcp(&buf[..n]) {
                    // RFC 3550 §7.1 + RFC 4585: NACK requests pull media
                    // packets back out of the retransmission window; SRs
                    // feed our DLSR/last_sr fields.
                    let mut rtcp_wire = buf[..n].to_vec();
                    if crypto.is_some() {
                        let Some(cp) = crypto.as_mut() else { continue };
                        if cp.rx.unprotect_rtcp(&mut rtcp_wire).is_err() {
                            // Forged or corrupt SRTCP: drop, never parse.
                            stats.srtp_failures.fetch_add(1, Relaxed);
                            continue;
                        }
                    }
                    handle_rtcp(
                        &rtcp_wire,
                        src,
                        &rtp,
                        &resend,
                        &mut retransmit_guard,
                        &mut last_sr,
                        &mut twcc_tx,
                        ssrc,
                        remote_ssrc,
                        &stats,
                        &mut crypto,
                    )
                    .await;
                    continue;
                }
                if crypto.is_some() {
                    // Secured media path: open the SRTP datagram BEFORE any
                    // parsing.  An unprotectable datagram (forged, corrupt,
                    // or replayed) is dropped — never parsed as plaintext.
                    let Some(cp) = crypto.as_mut() else { continue };
                    let mut wire = buf[..n].to_vec();
                    if cp.rx.unprotect(&mut wire).is_err() {
                        stats.srtp_failures.fetch_add(1, Relaxed);
                        continue;
                    }
                    let Ok(pkt) = RtpPacket::parse(&wire) else { continue };
                    stats.packets_rx.fetch_add(1, Relaxed);
                    // media hook: RTP packet tap
                    observ::session::rtp_tap(session.call_id(), session.leg(), src, local, &wire, true);
                    {
                        let mut r = remote.lock().await;
                        if r.is_none_or(|a| a != src) {
                            *r = Some(src);
                        }
                    }
                    if remote_ssrc.is_none() {
                        remote_ssrc = Some(pkt.ssrc());
                    }
                    let now_ms = started.elapsed().as_millis() as u64;
                    nack_tracker.on_packet(pkt.ssrc(), pkt.header.sequence, now_ms);
                    if let (Some(ext_id), Some(ext)) = (cfg.twcc_ext, pkt.extension.as_ref()) {
                        if let Some(tseq) = onebyte_ext_value(ext, ext_id) {
                            twcc.on_packet(tseq, Some(started.elapsed().as_micros() as u64));
                        }
                    }
                    if Some(pkt.payload_type()) == cfg.te_pt_rx {
                        let msg = BridgeMsg::Dtmf {
                            timestamp: pkt.header.timestamp,
                            marker: pkt.header.marker,
                            payload: pkt.payload.to_vec(),
                        };
                        if bridge_out.try_send(msg).is_err() {
                            tracing::debug!("bridge backpressured; DTMF event dropped");
                        }
                        continue;
                    }
                    let _ = jb.push(
                        pkt.ssrc(),
                        pkt.header.sequence,
                        pkt.header.timestamp,
                        pkt.header.marker,
                        pkt.payload_type(),
                        pkt.payload.to_vec(),
                        now_ms,
                    );
                    continue;
                }
                let Ok(pkt) = RtpPacket::parse(&buf[..n]) else { continue };
                stats.packets_rx.fetch_add(1, Relaxed);
                // media hook: RTP packet tap
                observ::session::rtp_tap(session.call_id(), session.leg(), src, local, &buf[..n], true);
                {
                    let mut r = remote.lock().await;
                    if r.is_none_or(|a| a != src) {
                        *r = Some(src);
                    }
                }
                if remote_ssrc.is_none() {
                    remote_ssrc = Some(pkt.ssrc());
                }
                // NACK tracking runs for every accepted media packet (DTMF
                // included — same SSRC stream) so extended-sequence state and
                // wrap cycles stay correct even when sends are disabled.
                let now_ms = started.elapsed().as_millis() as u64;
                nack_tracker.on_packet(pkt.ssrc(), pkt.header.sequence, now_ms);
                if cfg.nack {
                    let ready = nack_tracker.take_ready(now_ms);
                    if !ready.is_empty() {
                        stats.nacks_tx.fetch_add(ready.len() as u64, Relaxed);
                        let p = nack_packet(ssrc, pkt.ssrc(), &ready);
                        // RFC 3550 §6.1 / RFC 4585 §6.1: a compound starts
                        // with SR/RR — prefix an empty RR.
                        let rr = RtcpPacket::ReceiverReport {
                            ssrc,
                            blocks: Vec::new(),
                        };
                        let mut wire = encode_compound(&[rr, p]);
                        if seal(&mut crypto, &mut wire, true) {
                            let _ = rtp.send_to(&wire, src).await;
                        } else {
                            stats.srtp_failures.fetch_add(1, Relaxed);
                        }
                    }
                }
                if let (Some(ext_id), Some(ext)) = (cfg.twcc_ext, pkt.extension.as_ref()) {
                    if let Some(tseq) = onebyte_ext_value(ext, ext_id) {
                        // The draft's transport-cc sequence number is a
                        // 2-byte big-endian element; the monitor unwraps the
                        // u16 space itself.
                        twcc.on_packet(tseq, Some(started.elapsed().as_micros() as u64));
                    }
                }
                // RFC 4733 DTMF passthrough: the event crosses the bridge
                // so the PEER leg packetizes and sends it — never back to
                // the sender this socket just received it from.
                if Some(pkt.payload_type()) == cfg.te_pt_rx {
                    let msg = BridgeMsg::Dtmf {
                        timestamp: pkt.header.timestamp,
                        marker: pkt.header.marker,
                        payload: pkt.payload.to_vec(),
                    };
                    if bridge_out.try_send(msg).is_err() {
                        tracing::debug!("bridge backpressured; DTMF event dropped");
                    }
                    continue;
                }
                match jb.push(
                    pkt.ssrc(),
                    pkt.header.sequence,
                    pkt.header.timestamp,
                    pkt.header.marker,
                    pkt.payload_type(),
                    pkt.payload.to_vec(),
                    started.elapsed().as_millis() as u64,
                ) {
                    PushResult::Buffered => {}
                    PushResult::Probation => {}
                    // Late arrivals already missed playout; loss is counted
                    // by the jitter buffer's sequence-gap accounting.
                    PushResult::Late => {}
                    PushResult::Duplicate => {}
                }
            }
            _ = ticker.tick() => {
                // Pop every frame whose playout deadline has arrived; a tick
                // with nothing ready produces at most one concealment frame.
                loop {
                    let now = started.elapsed().as_millis() as u64;
                    let frame = match jb.pop_ready(now) {
                        Some(f) => f,
                        None => match jb.conceal(now) {
                            Some(f) => {
                                stats.frames_concealed.fetch_add(1, Relaxed);
                                f
                            }
                            None => break,
                        },
                    };
                    // Decode to interleaved PCM, collapse to mono, resample
                    // into the 16 kHz bridge, hand over to the peer pump.
                    let mut pcm: Vec<i16> = Vec::with_capacity(2048);
                    let _ = dec.decode(&frame.payload, &mut pcm);
                    let mono = to_mono(&pcm, rx_channels);
                    let mut bridge: Vec<i16> = Vec::with_capacity(2048);
                    match &mut rs_rx {
                        Some(r) => {
                            r.process(&mono, &mut bridge);
                        }
                        None => bridge.extend_from_slice(&mono),
                    }
                    if bridge_out.try_send(BridgeMsg::Pcm(bridge)).is_err() {
                        tracing::debug!("bridge backpressured; frame dropped");
                    } else {
                        continue;
                    }
                    break;
                }
            }
            msg_in = bridge_in.recv() => {
                let Some(msg) = msg_in else { continue };
                match msg {
                    BridgeMsg::Dtmf {
                        timestamp,
                        marker,
                        payload,
                    } => {
                        // Peer-leg DTMF: packetize with OUR telephone-event
                        // PT and sequence, keep the original timestamp. If
                        // the peer leg negotiated no telephone-event codec,
                        // the event cannot be represented on this dialog —
                        // drop it rather than mislabelling an audio packet.
                        let Some(te_pt) = cfg.te_pt_tx else {
                            tracing::debug!(
                                "peer leg has no telephone-event PT; DTMF event dropped"
                            );
                            continue;
                        };
                        let mut relay = RtpPacket::new(
                            te_pt,
                            out_seq,
                            timestamp,
                            ssrc,
                            marker,
                            Bytes::from(payload),
                        );
                        out_seq = out_seq.wrapping_add(1);
                        if let (Some(ext_id), Some(tracker)) = (cfg.twcc_ext, twcc_tx.as_mut()) {
                            attach_twcc(
                                ext_id,
                                twcc_tx_seq,
                                tracker,
                                &mut relay,
                                started.elapsed().as_micros() as u64,
                            );
                            twcc_tx_seq = twcc_tx_seq.wrapping_add(1);
                        }
                        let dst = *remote.lock().await;
                        if let Some(dst) = dst {
                            // RFC 3550 §6.4.1: SR packet/octet counters track
                            // what was actually SENT.
                            tx_pkts += 1;
                            tx_octets += relay.payload.len() as u64;
                            resend.store(&relay);
                            // media hook: DTMF relay tap
                            let mut wire = relay.encode();
                            stats.packets_tx.fetch_add(1, Relaxed);
                            observ::session::rtp_tap(session.call_id(), session.leg(), local, dst, &wire, false);
                            if seal(&mut crypto, &mut wire, false) {
                                let _ = rtp.send_to(&wire, dst).await;
                            } else {
                                stats.srtp_failures.fetch_add(1, Relaxed);
                            }
                        }
                    }
                    BridgeMsg::Pcm(pcm) => {
                        // Peer audio: bridge → TX rate, encode all full frames.
                        let mut enc_in: Vec<i16> = Vec::with_capacity(pcm.len() + 64);
                        match &mut rs_tx {
                            Some(r) => {
                                r.process(&pcm, &mut enc_in);
                            }
                            None => enc_in.extend_from_slice(&pcm),
                        }
                        let frame_len = enc.frame_samples() * enc.channels() as usize;
                        while enc_in.len() >= frame_len {
                            let mut wire = Vec::with_capacity(256);
                            if enc.encode(&enc_in[..frame_len], &mut wire).is_ok() && !wire.is_empty() {
                                let mut pkt = RtpPacket::new(cfg.tx_pt, out_seq, out_ts, ssrc, false, Bytes::from(wire));
                                out_seq = out_seq.wrapping_add(1);
                                out_ts = out_ts.wrapping_add(ts_inc);
                                if let (Some(ext_id), Some(tracker)) = (cfg.twcc_ext, twcc_tx.as_mut()) {
                                    attach_twcc(
                                        ext_id,
                                        twcc_tx_seq,
                                        tracker,
                                        &mut pkt,
                                        started.elapsed().as_micros() as u64,
                                    );
                                    twcc_tx_seq = twcc_tx_seq.wrapping_add(1);
                                }
                                stats.frames_encoded.fetch_add(1, Relaxed);
                                let dst = *remote.lock().await;
                                if let Some(dst) = dst {
                                    // RFC 3550 §6.4.1: SR packet/octet counters
                                    // track what was actually SENT.
                                    tx_pkts += 1;
                                    tx_octets += pkt.payload.len() as u64;
                                    resend.store(&pkt);
                                    // media hook: encoded frame tap (pre-crypto
                                    // wire form)
                                    let mut encoded = pkt.encode();
                                    stats.packets_tx.fetch_add(1, Relaxed);
                                    if seal(&mut crypto, &mut encoded, false) {
                                        let _ = rtp.send_to(&encoded, dst).await;
                                    } else {
                                        stats.srtp_failures.fetch_add(1, Relaxed);
                                    }
                                }
                            }
                            enc_in.drain(..frame_len);
                        }
                    }
                }
            }
        }
    }
    // media hook: pump end with final counters
    let talk_ms = started.elapsed().as_millis() as u64;
    stats.packets_lost.store(jb.stats.packets_lost, Relaxed);
    session.emit(observ::EventKind::MediaEnd {
        pump_leg: session.leg(),
        rx: stats.packets_rx(),
        tx: stats.packets_tx(),
        lost: stats.packets_lost(),
        jitter_ms: jb.jitter_ms(),
        concealed: stats.frames_concealed(),
        talk_ms,
        remote: *remote.lock().await,
    });
    tracing::debug!(
        "pump stopped: encoded={} concealed={}",
        stats.frames_encoded(),
        stats.frames_concealed()
    );
}

/// Answer an incoming RTCP datagram: Generic NACK requests pull media
/// packets back out of the retransmission window (verbatim — same seq, PT
/// and SSRC as the original transmission; RFC 4585 §6.2.1 non-RTX form);
/// the peer's SR feeds our `last_sr`/DLSR bookkeeping; transport-cc
/// feedback about OUR stream correlates against recorded send times.
#[allow(clippy::too_many_arguments)]
async fn handle_rtcp(
    wire: &[u8],
    src: SocketAddr,
    rtp: &UdpSocket,
    resend: &RtxPool,
    guard: &mut HashMap<u16, Instant>,
    last_sr: &mut Option<(u32, Instant)>,
    twcc_tx: &mut Option<TwccSendTracker>,
    our_ssrc: u32,
    remote_ssrc: Option<u32>,
    stats: &MediaStats,
    crypto: &mut Option<CryptoPair>,
) {
    let Ok(packets) = parse_compound(wire) else {
        return;
    };
    for p in packets {
        stats.rtcp_rx.fetch_add(1, Relaxed);
        match p {
            RtcpPacket::SenderReport(info, _) => {
                // RFC 3550 §6.4.1: LSR/DLSR must refer to the last SR from
                // THE PEER'S media stream — an SR from any other SSRC (RTX,
                // probing) must not overwrite the bookkeeping.
                if Some(info.ssrc) == remote_ssrc {
                    let mid =
                        ((u64::from(info.ntp_sec) & 0xFFFF) << 16) | u64::from(info.ntp_frac >> 16);
                    *last_sr = Some((mid as u32, Instant::now()));
                }
            }
            RtcpPacket::Rtpfb {
                fmt: 1, payload, ..
            } => {
                stats.nacks_rx.fetch_add(1, Relaxed);
                let Ok(entries) = parse_nack_fci(&payload) else {
                    continue;
                };
                for seq in nack_seqs(&entries) {
                    // Throttle: at most one retransmission per sequence per
                    // 20 ms so repeated NACKs cannot flood the leg.
                    if guard
                        .get(&seq)
                        .is_some_and(|t| t.elapsed() < Duration::from_millis(20))
                    {
                        continue;
                    }
                    if guard.len() > 1024 {
                        guard.clear();
                    }
                    guard.insert(seq, Instant::now());
                    if let Some(orig) = resend.get(seq) {
                        // Retransmissions ride the same wire format as the
                        // original — protected on a secured leg (RFC 4585
                        // §6.2.1 non-RTX form, verbatim payload).
                        let mut wire = orig.encode();
                        stats.retransmits_tx.fetch_add(1, Relaxed);
                        if seal(crypto, &mut wire, false) {
                            let _ = rtp.send_to(&wire, src).await;
                        } else {
                            stats.srtp_failures.fetch_add(1, Relaxed);
                        }
                    } else {
                        stats.nack_misses.fetch_add(1, Relaxed);
                    }
                }
            }
            fb_pkt @ RtcpPacket::Rtpfb { fmt: 15, .. } => {
                // Transport-cc feedback about OUR outbound stream (the peer
                // echoes our SSRC as media_ssrc): correlate against send
                // times and surface the congestion window.
                let Some(tracker) = twcc_tx.as_mut() else {
                    continue;
                };
                let about_us = matches!(
                    &fb_pkt,
                    RtcpPacket::Rtpfb { media_ssrc, .. } if *media_ssrc == our_ssrc
                );
                if !about_us {
                    tracing::debug!(
                        ssrc = %our_ssrc,
                        "ignoring transport-cc feedback for another media stream"
                    );
                    continue;
                }
                if let Ok(feedback) = parse_twcc(&fb_pkt) {
                    let report = tracker.on_feedback(&feedback);
                    stats.twcc_feedbacks_rx.fetch_add(1, Relaxed);
                    stats.twcc_window_lost.store(report.lost as u64, Relaxed);
                    stats
                        .twcc_mean_delay_us
                        .store(report.mean_delay_us, Relaxed);
                }
            }
            _ => {}
        }
    }
}

/// Extract a one-byte-header extension element value (RFC 8285 §4.2) by id.
/// Transport-cc sequence numbers are 2-byte big-endian elements (draft
/// §3.1); returns their u16 value. `id == 0` starts padding, `id == 15` is
/// reserved — both end the scan.
fn onebyte_ext_value(ext: &rtp::packet::RtpExtension, want_id: u8) -> Option<u16> {
    if ext.profile != 0xBEDE {
        return None;
    }
    let d = &ext.data;
    let mut off = 0usize;
    while off < d.len() {
        let b = d[off];
        if b == 0 {
            break; // padding to the 4-byte boundary
        }
        let id = b >> 4;
        let data_len = usize::from(b & 0x0F) + 1;
        if id == 15 {
            break;
        }
        if id == want_id && data_len == 2 && off + 2 < d.len() {
            return Some(u16::from_be_bytes([d[off + 1], d[off + 2]]));
        }
        off += 1 + data_len;
    }
    None
}

/// Stamp `pkt` with the one-byte transport-cc sequence element (RFC 8285
/// §4.2, draft-holmerberg wire form) and record the send time so the peer's
/// feedback correlates into per-packet delays. Called before the packet
/// enters the retransmission window so NACKed resends carry the same
/// sequence number as the original transmission.
fn attach_twcc(
    ext_id: u8,
    seq: u16,
    tracker: &mut TwccSendTracker,
    pkt: &mut RtpPacket,
    now_us: u64,
) {
    // 2-byte big-endian element (draft-holmerberg §3.1); a negotiated id
    // outside 1..=14 skips stamping rather than emitting malformed wire.
    match RtpExtension::onebyte(ext_id, &seq.to_be_bytes()) {
        Ok(ext) => pkt.extension = Some(ext),
        Err(e) => tracing::debug!(ext_id, error = %e, "transport-cc ext not stamped"),
    }
    tracker.record_send(seq, now_us);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtp::nack::{nack_packet, GenericNack};
    use rtp::packet::RtpExtension;
    use rtp::rtcp::encode_packet;

    fn pump_cfg() -> PumpConfig {
        PumpConfig {
            rx_codec: CodecId::Pcmu,
            tx_codec: CodecId::Pcmu,
            rx_pt: 0,
            te_pt_rx: None,
            te_pt_tx: None,
            tx_pt: 0,
            nack: false,
            twcc_ext: None,
            rtcp_interval_ms: 60_000,
            dtls_tx: None,
        }
    }

    fn media_pkt(seq: u16, ssrc: u32) -> RtpPacket {
        RtpPacket::new(
            0,
            seq,
            1000 * u32::from(seq),
            ssrc,
            false,
            Bytes::from_static(b"audio-payload"),
        )
    }

    fn ext_pkt(seq: u16, ssrc: u32, twcc_seq: u16) -> Vec<u8> {
        let mut p = media_pkt(seq, ssrc);
        p.extension = Some(RtpExtension {
            profile: 0xBEDE,
            // id 1, 2-byte BE data (transport-cc seq), zero-padded to a word.
            data: Bytes::from(vec![
                0x11,
                (twcc_seq >> 8) as u8,
                (twcc_seq & 0xFF) as u8,
                0,
            ]),
        });
        p.encode()
    }

    /// Next datagram that looks like media (RTCP filtered out).
    async fn recv_media(sock: &UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
                .await
                .expect("media packet within 5 s")
                .expect("recv ok");
            if !rtp::looks_like_rtcp(&buf[..n]) {
                return buf[..n].to_vec();
            }
        }
    }

    /// Next datagram that parses as a compound RTCP packet set.
    async fn recv_rtcp(sock: &UdpSocket) -> Vec<RtcpPacket> {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
                .await
                .expect("rtcp packet within 5 s")
                .expect("recv ok");
            if rtp::looks_like_rtcp(&buf[..n]) {
                return parse_compound(&buf[..n]).unwrap();
            }
        }
    }

    struct TestPump {
        test: Arc<UdpSocket>,
        pump_addr: SocketAddr,
        in_tx: mpsc::Sender<BridgeMsg>,
        handle: PumpHandle,
    }

    async fn start(cfg: PumpConfig) -> TestPump {
        let test = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pump_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let pump_addr = pump_sock.local_addr().unwrap();
        let (out_tx, _out_rx) = mpsc::channel(64);
        let (in_tx, in_rx) = mpsc::channel(64);
        let handle = start_with_socket(cfg, pump_sock, out_tx, in_rx).unwrap();
        *handle.remote.lock().await = Some(test.local_addr().unwrap());
        TestPump {
            test,
            pump_addr,
            in_tx,
            handle,
        }
    }

    #[test]
    fn onebyte_ext_extraction_matches_id_and_profile() {
        let ext = RtpExtension {
            profile: 0xBEDE,
            data: Bytes::from(vec![0x11, 0x01, 0x02, 0]), // id 1, 2-byte data
        };
        assert_eq!(onebyte_ext_value(&ext, 1), Some(0x0102));
        assert_eq!(onebyte_ext_value(&ext, 2), None);
        // Wrong profile (two-byte space) → never matches.
        let wrong = RtpExtension {
            profile: 0x1000,
            data: ext.data.clone(),
        };
        assert_eq!(onebyte_ext_value(&wrong, 1), None);
        // Padding terminates the scan.
        let padded = RtpExtension {
            profile: 0xBEDE,
            data: Bytes::from(vec![0x00, 0x11, 0x00, 0x01]),
        };
        assert_eq!(onebyte_ext_value(&padded, 1), None);
        // A 1-byte element with the right id is NOT a transport-cc sequence
        // (the draft requires 2 bytes) — must not be misread.
        let short = RtpExtension {
            profile: 0xBEDE,
            data: Bytes::from(vec![0x10, 0x7F, 0, 0]),
        };
        assert_eq!(onebyte_ext_value(&short, 1), None);
    }

    #[tokio::test]
    async fn pump_answers_nack_from_retransmit_window() {
        let mut cfg = pump_cfg();
        cfg.nack = true;
        let tp = start(cfg).await;

        // Drive TX: the bridge domain is 16 kHz, resampled 16000→8000 for
        // PCMU. One large chunk (100 ms) survives the polyphase resampler's
        // group delay and yields several full 20 ms frames.
        tp.in_tx
            .send(BridgeMsg::Pcm(vec![0i16; 1600]))
            .await
            .unwrap();
        let w1 = recv_media(&tp.test).await;
        let w2 = recv_media(&tp.test).await;
        let q1 = RtpPacket::parse(&w1).unwrap();
        let q2 = RtpPacket::parse(&w2).unwrap();
        assert_eq!(q2.header.sequence, q1.header.sequence.wrapping_add(1));
        assert!(tp.handle.stats.frames_encoded() >= 2);

        // Drain the remainder of the initial burst so the next datagram is
        // guaranteed to be the NACK-triggered retransmission.
        let mut drain = vec![0u8; 2048];
        while tp.test.try_recv_from(&mut drain).is_ok() {}

        // NACK the first packet; the pump must re-send it verbatim.
        let nack = nack_packet(
            0x999,
            q1.ssrc(),
            &[GenericNack {
                pid: q1.header.sequence,
                blp: 0,
            }],
        );
        tp.test
            .send_to(&encode_packet(&nack), tp.pump_addr)
            .await
            .unwrap();
        let again = recv_media(&tp.test).await;
        let rq = RtpPacket::parse(&again).unwrap();
        assert_eq!(rq.header.sequence, q1.header.sequence);
        assert_eq!(rq.payload, q1.payload);
        assert_eq!(tp.handle.stats.retransmits_tx(), 1);
        assert_eq!(tp.handle.stats.nacks_rx(), 1);
        tp.handle.stop.send(true).ok();
    }

    #[tokio::test]
    async fn pump_nacks_gaps_and_reports_periodically() {
        let mut cfg = pump_cfg();
        cfg.nack = true;
        cfg.rtcp_interval_ms = 60;
        let tp = start(cfg).await;

        // A gap: 100 arrives, 101/102 are lost, 103 arrives.
        for seq in [100u16, 103] {
            let w = media_pkt(seq, 0x555).encode();
            tp.test.send_to(&w, tp.pump_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut saw_nack = false;
        let mut saw_sr = false;
        for _ in 0..12 {
            for pkt in recv_rtcp(&tp.test).await {
                match pkt {
                    RtcpPacket::Rtpfb {
                        fmt: 1,
                        media_ssrc,
                        payload,
                        ..
                    } => {
                        assert_eq!(media_ssrc, 0x555);
                        let seqs = nack_seqs(&parse_nack_fci(&payload).unwrap());
                        assert!(
                            seqs.contains(&101) && seqs.contains(&102),
                            "gap not reported: {seqs:?}"
                        );
                        saw_nack = true;
                    }
                    RtcpPacket::SenderReport(info, blocks) => {
                        assert_eq!(blocks.len(), 1, "RR block about the peer");
                        assert_eq!(blocks[0].ssrc, 0x555);
                        assert!(info.ntp_sec > 2_208_988_800, "NTP epoch 1900");
                        saw_sr = true;
                    }
                    _ => {}
                }
            }
            if saw_nack && saw_sr {
                break;
            }
        }
        assert!(saw_nack, "expected a Generic NACK for the gap");
        assert!(saw_sr, "expected a periodic SenderReport");
        assert!(tp.handle.stats.nacks_tx() >= 1);
        tp.handle.stop.send(true).ok();
    }

    #[tokio::test]
    async fn pump_sends_twcc_feedback_for_negotiated_ext() {
        let mut cfg = pump_cfg();
        cfg.twcc_ext = Some(1);
        let tp = start(cfg).await;

        for i in 0..4u16 {
            let w = ext_pkt(200 + i, 0x777, 10 + i);
            tp.test.send_to(&w, tp.pump_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut saw_twcc = false;
        for _ in 0..12 {
            for pkt in recv_rtcp(&tp.test).await {
                if let RtcpPacket::Rtpfb {
                    fmt, media_ssrc, ..
                } = pkt
                {
                    if fmt == 15 {
                        assert_eq!(media_ssrc, 0x777);
                        saw_twcc = true;
                    }
                }
            }
            if saw_twcc {
                break;
            }
        }
        assert!(saw_twcc, "expected transport-cc feedback");
        tp.handle.stop.send(true).ok();
    }

    #[tokio::test]
    async fn pump_without_negotiation_stays_rtcp_silent() {
        // No nack, no twcc, long SR period: media packets must NOT trigger
        // any feedback toward the peer (gaps are handled by PLC alone).
        let tp = start(pump_cfg()).await;
        for seq in [50u16, 55] {
            let w = media_pkt(seq, 0x333).encode();
            tp.test.send_to(&w, tp.pump_addr).await.unwrap();
        }
        // The first SR fires only after a full period (60 s): a short wait
        // confirms gap detection alone emits nothing.
        let mut buf = vec![0u8; 2048];
        let r = tokio::time::timeout(Duration::from_millis(300), tp.test.recv_from(&mut buf)).await;
        assert!(r.is_err(), "unexpected packet on an unnegotiated leg");
        tp.handle.stop.send(true).ok();
    }

    #[tokio::test]
    async fn pump_attaches_twcc_ext_on_outbound_media_and_retransmits() {
        let mut cfg = pump_cfg();
        cfg.twcc_ext = Some(1);
        let tp = start(cfg).await;

        tp.in_tx
            .send(BridgeMsg::Pcm(vec![0i16; 1600]))
            .await
            .unwrap();
        let w1 = recv_media(&tp.test).await;
        let w2 = recv_media(&tp.test).await;
        let q1 = RtpPacket::parse(&w1).unwrap();
        let q2 = RtpPacket::parse(&w2).unwrap();
        let ext1 = q1
            .extension
            .as_ref()
            .expect("tx packet carries an extension");
        let ext2 = q2
            .extension
            .as_ref()
            .expect("tx packet carries an extension");
        assert_eq!(ext1.profile, 0xBEDE);
        let s1 = onebyte_ext_value(ext1, 1).expect("transport-cc element");
        let s2 = onebyte_ext_value(ext2, 1).expect("transport-cc element");
        assert_eq!(
            s1.wrapping_add(1),
            s2,
            "transport-cc sequence increments per packet"
        );

        // Drain, then NACK packet 1: the verbatim retransmission must carry
        // the same transport-cc sequence number as the original.
        let mut drain = vec![0u8; 2048];
        while tp.test.try_recv_from(&mut drain).is_ok() {}
        let nack = nack_packet(
            0x999,
            q1.ssrc(),
            &[GenericNack {
                pid: q1.header.sequence,
                blp: 0,
            }],
        );
        tp.test
            .send_to(&encode_packet(&nack), tp.pump_addr)
            .await
            .unwrap();
        let again = recv_media(&tp.test).await;
        let rq = RtpPacket::parse(&again).unwrap();
        assert_eq!(
            rq.extension.as_ref().and_then(|e| onebyte_ext_value(e, 1)),
            Some(s1),
            "retransmission carries the original transport-cc sequence"
        );
        tp.handle.stop.send(true).ok();
    }

    #[tokio::test]
    async fn pump_without_twcc_negotiation_sends_bare_media() {
        let tp = start(pump_cfg()).await;
        tp.in_tx
            .send(BridgeMsg::Pcm(vec![0i16; 1600]))
            .await
            .unwrap();
        let w = recv_media(&tp.test).await;
        let q = RtpPacket::parse(&w).unwrap();
        assert!(
            q.extension.is_none(),
            "no header extension without negotiation"
        );
        tp.handle.stop.send(true).ok();
    }

    #[tokio::test]
    async fn pump_correlates_twcc_feedback_into_stats() {
        let mut cfg = pump_cfg();
        cfg.twcc_ext = Some(1);
        let tp = start(cfg).await;

        // Drive two outbound media packets (transport-cc seq 0 then 1).
        tp.in_tx
            .send(BridgeMsg::Pcm(vec![0i16; 1600]))
            .await
            .unwrap();
        let w1 = recv_media(&tp.test).await;
        let _w2 = recv_media(&tp.test).await;
        let q1 = RtpPacket::parse(&w1).unwrap();
        let ssrc = q1.ssrc();

        // Feedback about OUR stream: seq 0 received (+2 ms delta), seq 1
        // received with a much larger inter-arrival delta, seq 2 lost.
        // Delays are relative to the fastest observed packet: seq 0 pins
        // the clock offset, seq 1 reports ~98 ms of excess delay.
        let fb = rtp::twcc::TwccFeedback {
            sender_ssrc: 0xABC,
            media_ssrc: ssrc,
            base_seq: 0,
            ref_time_ms: 1_000,
            fb_count: 0,
            entries: vec![
                rtp::twcc::TwccEntry {
                    seq: 0,
                    received: true,
                    delta_us: Some(2_000),
                },
                rtp::twcc::TwccEntry {
                    seq: 1,
                    received: true,
                    delta_us: Some(100_000),
                },
                rtp::twcc::TwccEntry {
                    seq: 2,
                    received: false,
                    delta_us: None,
                },
            ],
        };
        let fb_pkt = rtp::twcc::twcc_packet(&fb).unwrap();
        tp.test
            .send_to(&encode_packet(&fb_pkt), tp.pump_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(tp.handle.stats.twcc_feedbacks_rx(), 1);
        assert_eq!(tp.handle.stats.twcc_window_lost(), 1);
        // seq 0 pins the clock offset; seq 1's inter-arrival delta was
        // 98 ms larger than its send spacing → clearly positive excess
        // delay even across independent clock domains.
        assert!(
            tp.handle.stats.twcc_mean_delay_us() > 10_000,
            "excess send→receive delay positive, got {}",
            tp.handle.stats.twcc_mean_delay_us()
        );
        tp.handle.stop.send(true).ok();
    }
}
