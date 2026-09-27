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
use rtp::packet::RtpPacket;
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

/// Starts a media pump on an already-bound RTP socket.
pub fn start_with_socket(
    cfg: PumpConfig,
    rtp: Arc<UdpSocket>,
    bridge_out: mpsc::Sender<Vec<i16>>,
    bridge_in: mpsc::Receiver<Vec<i16>>,
) -> Result<PumpHandle, codecs::CodecError> {
    start_with_socket_session(
        cfg,
        rtp,
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
    bridge_out: mpsc::Sender<Vec<i16>>,
    bridge_in: mpsc::Receiver<Vec<i16>>,
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
    remote: Arc<Mutex<Option<SocketAddr>>>,
    stats: Arc<MediaStats>,
    mut dec: Box<dyn Decoder>,
    mut enc: Box<dyn Encoder>,
    mut stop: watch::Receiver<bool>,
    bridge_out: mpsc::Sender<Vec<i16>>,
    mut bridge_in: mpsc::Receiver<Vec<i16>>,
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
            r = rtp.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(x) => x,
                    Err(e) => { tracing::debug!("media recv err: {e}"); continue; }
                };
                if rtp::looks_like_rtcp(&buf[..n]) { continue; }
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
                // RFC 4733 DTMF passthrough (payload relay, PT rewritten).
                if Some(pkt.payload_type()) == cfg.te_pt_rx {
                    let relay = RtpPacket::new(
                        cfg.te_pt_tx.unwrap_or(cfg.tx_pt),
                        out_seq,
                        pkt.header.timestamp,
                        ssrc,
                        pkt.header.marker,
                        Bytes::copy_from_slice(&pkt.payload),
                    );
                    out_seq = out_seq.wrapping_add(1);
                    let dst = *remote.lock().await;
                    if let Some(dst) = dst {
                        // media hook: DTMF relay tap
                        let wire = relay.encode();
                        stats.packets_tx.fetch_add(1, Relaxed);
                        observ::session::rtp_tap(session.call_id(), session.leg(), local, dst, &wire, false);
                        let _ = rtp.send_to(&wire, dst).await;
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
                    if bridge_out.try_send(bridge).is_err() {
                        tracing::debug!("bridge backpressured; frame dropped");
                    } else {
                        continue;
                    }
                    break;
                }
            }
            pcm_in = bridge_in.recv() => {
                let Some(pcm) = pcm_in else { continue };
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
                        let pkt = RtpPacket::new(cfg.tx_pt, out_seq, out_ts, ssrc, false, Bytes::from(wire));
                        out_seq = out_seq.wrapping_add(1);
                        out_ts = out_ts.wrapping_add(ts_inc);
                        stats.frames_encoded.fetch_add(1, Relaxed);
                        let dst = *remote.lock().await;
                        if let Some(dst) = dst {
                            // media hook: encoded frame tap
                            let encoded = pkt.encode();
                            stats.packets_tx.fetch_add(1, Relaxed);
                            observ::session::rtp_tap(session.call_id(), session.leg(), local, dst, &encoded, false);
                            let _ = rtp.send_to(&encoded, dst).await;
                        }
                    }
                    enc_in.drain(..frame_len);
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
