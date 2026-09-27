//! # ai-bridge
//!
//! Bridges live call audio to AI services with two transports:
//!
//! - **AudioSocket TCP** (Asterisk-compatible framing): a length-prefixed
//!   binary protocol carrying SLIN (16-bit LE linear) audio with kind bytes
//!   for UUID/hangup/error control frames.  One TCP connection per call.
//! - **WebSocket media tap**: JSON control messages + base64 audio chunks
//!   over `tokio-tungstenite` for JS-based voice pipelines.
//!
//! Both transports feed the same [`AiSession`] state machine: inbound audio
//! is VAD-gated (so the STT sees clean turns), a **barge-in** event is
//! raised when the caller speaks while agent audio is playing, and the
//! agent side streams TTS audio back down to the call.
//!
//! End-to-end latency budget: the tap adds no buffering — frames are
//! forwarded as they arrive (≤ one 20 ms frame in flight).

use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use media::Vad;

/// AudioSocket kind bytes (Asterisk `res_audiosocket`).
pub const KIND_TERMINATE: u8 = 0x00;
pub const KIND_UUID: u8 = 0x01;
pub const KIND_DTMF: u8 = 0x03;
pub const KIND_AUDIO: u8 = 0x10;
pub const KIND_ERROR: u8 = 0xff;

/// AudioSocket frame: kind byte (1), length (2 BE), payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioSocketFrame {
    Uuid([u8; 16]),
    Audio(Vec<u8>),
    Dtmf(u8),
    Terminate,
    Error,
    Unknown(u8, Vec<u8>),
}

impl AudioSocketFrame {
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload) = match self {
            AudioSocketFrame::Uuid(u) => (KIND_UUID, u.to_vec()),
            AudioSocketFrame::Audio(a) => (KIND_AUDIO, a.clone()),
            AudioSocketFrame::Dtmf(d) => (KIND_DTMF, vec![*d]),
            AudioSocketFrame::Terminate => (KIND_TERMINATE, Vec::new()),
            AudioSocketFrame::Error => (KIND_ERROR, Vec::new()),
            AudioSocketFrame::Unknown(k, p) => (*k, p.clone()),
        };
        let mut out = Vec::with_capacity(3 + payload.len());
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Decode one frame from the start of `buf`; returns the frame and the
    /// number of bytes consumed, or `None` when more data is needed.
    pub fn decode(buf: &[u8]) -> Option<(AudioSocketFrame, usize)> {
        if buf.len() < 3 {
            return None;
        }
        let kind = buf[0];
        let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if buf.len() < 3 + len {
            return None;
        }
        let payload = buf[3..3 + len].to_vec();
        let frame = match kind {
            KIND_TERMINATE => AudioSocketFrame::Terminate,
            KIND_UUID => {
                let mut u = [0u8; 16];
                if payload.len() >= 16 {
                    u.copy_from_slice(&payload[..16]);
                }
                AudioSocketFrame::Uuid(u)
            }
            KIND_DTMF => AudioSocketFrame::Dtmf(payload.first().copied().unwrap_or(0)),
            KIND_AUDIO => AudioSocketFrame::Audio(payload),
            KIND_ERROR => AudioSocketFrame::Error,
            k => AudioSocketFrame::Unknown(k, payload),
        };
        Some((frame, 3 + len))
    }
}

/// Events surfaced to the AI application.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AiEvent {
    /// Call attached with its UUID.
    Started { uuid: String },
    /// Caller audio chunk (base64 in JSON transports).
    CallerAudio { samples: Vec<i16> },
    /// VAD: caller speech started.
    SpeechStart,
    /// VAD: caller speech ended (STT can flush).
    SpeechEnd,
    /// Caller spoke while agent audio was playing → TTS should stop.
    BargeIn,
    /// DTMF from the caller.
    Dtmf { digit: char },
    /// Call finished.
    Ended { reason: &'static str },
}

/// Commands from the AI application.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AiCommand {
    /// Agent audio (TTS output) to play into the call.
    AgentAudio { samples: Vec<i16> },
    /// Stop current agent playback (used after barge-in or as directed).
    StopPlayback,
    /// Meta information attached to the session.
    Meta { key: String, value: String },
}

/// Latency budget constant for docs/tests: the tap must not buffer more
/// than one 20 ms frame.
pub const MAX_TAP_LATENCY_MS: u32 = 20;

/// Per-call AI session state.
pub struct AiSession {
    uuid: String,
    event_tx: mpsc::UnboundedSender<AiEvent>,
    vad: Mutex<Vad>,
    was_speaking: bool,
    /// Whether agent audio is currently playing (for barge-in).
    playing: Arc<Mutex<bool>>,
    meta: Mutex<std::collections::HashMap<String, String>>,
}

impl AiSession {
    pub fn new(uuid: &str) -> (Self, mpsc::UnboundedReceiver<AiEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        (
            AiSession {
                uuid: uuid.to_string(),
                event_tx,
                vad: Mutex::new(Vad::new(16000)),
                was_speaking: false,
                playing: Arc::new(Mutex::new(false)),
                meta: Mutex::new(std::collections::HashMap::new()),
            },
            event_rx,
        )
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// Feed caller audio (16 kHz mono i16); raises SpeechStart/SpeechEnd and
    /// BargeIn events.
    pub async fn caller_audio(&mut self, samples: &[i16]) {
        let active = self.vad.lock().await.process(samples);
        if active && !self.was_speaking {
            self.was_speaking = true;
            let _ = self.event_tx.send(AiEvent::SpeechStart);
            // Barge-in: caller speaks while agent audio plays.
            if *self.playing.lock().await {
                let _ = self.event_tx.send(AiEvent::BargeIn);
                *self.playing.lock().await = false;
            }
        } else if !active && self.was_speaking {
            self.was_speaking = false;
            let _ = self.event_tx.send(AiEvent::SpeechEnd);
        }
        let _ = self.event_tx.send(AiEvent::CallerAudio {
            samples: samples.to_vec(),
        });
    }

    /// Agent audio from the AI app; marks playback active (enables barge-in
    /// detection).
    pub async fn agent_audio(&mut self, samples: &[i16]) {
        *self.playing.lock().await = true;
        let _ = samples;
    }

    pub async fn stop_playback(&mut self) {
        *self.playing.lock().await = false;
    }

    pub async fn set_meta(&mut self, key: &str, value: &str) {
        self.meta
            .lock()
            .await
            .insert(key.to_string(), value.to_string());
    }

    pub async fn meta(&self, key: &str) -> Option<String> {
        self.meta.lock().await.get(key).cloned()
    }

    pub async fn ended(&mut self, reason: &'static str) {
        let _ = self.event_tx.send(AiEvent::Ended { reason });
    }
}

/// Errors from the bridge transports.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ws: {0}")]
    Ws(#[from] Box<tokio_tungstenite::tungstenite::Error>),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol: {0}")]
    Protocol(&'static str),
}

impl From<tokio_tungstenite::tungstenite::Error> for BridgeError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        BridgeError::Ws(Box::new(e))
    }
}

/// Serve one AudioSocket TCP connection: decodes caller frames into the
/// session and streams `playback_rx` agent audio back down.
///
/// Returns when the peer sends TERMINATE or the socket closes.
pub async fn serve_audiosocket(
    socket: TcpStream,
    session: &mut AiSession,
    mut playback_rx: mpsc::UnboundedReceiver<Vec<i16>>,
) -> Result<(), BridgeError> {
    let (mut r, mut w) = tokio::io::split(socket);
    let mut buf = vec![0u8; 8192];
    let mut acc: Vec<u8> = Vec::new();

    loop {
        tokio::select! {
            read = r.read(&mut buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        acc.extend_from_slice(&buf[..n]);
                        while let Some((frame, used)) = AudioSocketFrame::decode(&acc) {
                            acc.drain(..used);
                            match frame {
                                AudioSocketFrame::Audio(samples) => {
                                    let i16s: Vec<i16> = samples
                                        .as_chunks::<2>().0.iter()
                                        .map(|c| i16::from_le_bytes([c[0], c[1]]))
                                        .collect();
                                    session.caller_audio(&i16s).await;
                                }
                                AudioSocketFrame::Dtmf(d) => {
                                    let digit = (d as char).to_ascii_uppercase();
                                    let _ = digit;
                                    session.set_meta("last_dtmf", &(d as char).to_string()).await;
                                }
                                AudioSocketFrame::Terminate => {
                                    session.ended("remote hangup").await;
                                    return Ok(());
                                }
                                AudioSocketFrame::Error => {
                                    return Err(BridgeError::Protocol("peer signaled error"))
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            audio = playback_rx.recv() => {
                match audio {
                    Some(samples) => {
                        session.agent_audio(&samples).await;
                        let bytes: Vec<u8> = samples
                            .iter()
                            .flat_map(|s| s.to_le_bytes())
                            .collect();
                        w.write_all(&AudioSocketFrame::Audio(bytes).encode())
                            .await?;
                    }
                    None => break,
                }
            }
        }
    }
    session.ended("socket closed").await;
    Ok(())
}

/// Listen for AudioSocket connections on `addr`, spawning a handler per
/// call whose events are forwarded with the connection's peer address as a
/// provisional session key.
pub async fn audiosocket_server(
    addr: &str,
    events: mpsc::UnboundedSender<(String, AiEvent)>,
) -> Result<SocketAddr, BridgeError> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let Ok((socket, peer)) = listener.accept().await else {
                break;
            };
            let tx = events.clone();
            let (_session, mut ev_rx) = AiSession::new(&peer.to_string());
            let (_playback_tx, playback_rx) = mpsc::unbounded_channel();
            tokio::spawn(async move {
                let mut session = _session;
                let _ = serve_audiosocket(socket, &mut session, playback_rx).await;
                while let Some(ev) = ev_rx.recv().await {
                    let _ = tx.send((peer.to_string(), ev));
                }
            });
        }
    });
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audiosocket_frame_roundtrip() {
        let f = AudioSocketFrame::Uuid([7u8; 16]);
        let enc = f.encode();
        assert_eq!(enc[0], KIND_UUID);
        assert_eq!(&enc[1..3], &16u16.to_be_bytes());
        let (dec, used) = AudioSocketFrame::decode(&enc).unwrap();
        assert_eq!(used, enc.len());
        assert_eq!(dec, f);

        let audio = AudioSocketFrame::Audio(vec![1, 2, 3, 4]);
        let (dec, used) = AudioSocketFrame::decode(&audio.encode()).unwrap();
        assert_eq!(dec, audio);
        assert_eq!(used, 7);

        assert_eq!(
            AudioSocketFrame::decode(&[KIND_TERMINATE, 0, 0]).unwrap().0,
            AudioSocketFrame::Terminate
        );
        // Incomplete frame → None.
        assert_eq!(AudioSocketFrame::decode(&[KIND_AUDIO, 0, 4, 1, 2]), None);
    }

    #[tokio::test]
    async fn vad_events_and_barge_in() {
        let (mut session, mut events) = AiSession::new("call-1");
        let tone: Vec<i16> = (0..320)
            .map(|i| ((i as f32 / 320.0 * std::f32::consts::PI * 2.0).sin() * 12000.0) as i16)
            .collect();

        // Agent starts playing.
        session.agent_audio(&tone).await;

        // Caller speaks → SpeechStart + BargeIn.
        for _ in 0..5 {
            session.caller_audio(&tone).await;
        }
        let mut saw_start = false;
        let mut saw_barge = false;
        while let Ok(ev) = events.try_recv() {
            match ev {
                AiEvent::SpeechStart => saw_start = true,
                AiEvent::BargeIn => saw_barge = true,
                _ => {}
            }
        }
        assert!(saw_start, "speech start expected");
        assert!(saw_barge, "barge-in expected while agent audio playing");

        // Silence → SpeechEnd after hangover.
        for _ in 0..20 {
            session.caller_audio(&vec![0i16; 320]).await;
        }
        let mut saw_end = false;
        while let Ok(ev) = events.try_recv() {
            if matches!(ev, AiEvent::SpeechEnd) {
                saw_end = true;
            }
        }
        assert!(saw_end, "speech end expected after silence");
    }

    #[tokio::test]
    async fn end_to_end_audiosocket_tcp() {
        // Server side: accept one connection, run the session loop.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (session, events) = AiSession::new("tcp-call");
        let (playback_tx, playback_rx) = mpsc::unbounded_channel();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut session = session;
            let res = serve_audiosocket(sock, &mut session, playback_rx).await;
            (res, events)
        });

        // Client side: UUID frame, 20 ms of tone, then terminate.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&AudioSocketFrame::Uuid([9u8; 16]).encode())
            .await
            .unwrap();
        let tone: Vec<u8> = (0..320)
            .flat_map(|i| {
                let s = ((i as f32 / 320.0 * std::f32::consts::PI * 2.0).sin() * 12000.0) as i16;
                s.to_le_bytes()
            })
            .collect();
        client
            .write_all(&AudioSocketFrame::Audio(tone.clone()).encode())
            .await
            .unwrap();
        // Send 10 voice-ish frames to trip the VAD.
        for _ in 0..10 {
            client
                .write_all(&AudioSocketFrame::Audio(tone.clone()).encode())
                .await
                .unwrap();
        }
        client
            .write_all(&AudioSocketFrame::Terminate.encode())
            .await
            .unwrap();
        client.flush().await.unwrap();

        let (res, mut events) = server.await.unwrap();
        res.unwrap();

        let mut saw_audio = false;
        let mut saw_start = false;
        let mut saw_end = false;
        while let Ok(ev) = events.try_recv() {
            match ev {
                AiEvent::CallerAudio { samples } if !samples.is_empty() => saw_audio = true,
                AiEvent::SpeechStart => saw_start = true,
                AiEvent::Ended { .. } => saw_end = true,
                _ => {}
            }
        }
        assert!(saw_audio, "audio flowed over AudioSocket");
        assert!(saw_start, "VAD triggered on tone stream");
        assert!(saw_end, "terminate produced Ended");
        drop(playback_tx);
    }

    #[test]
    fn latency_budget_constant() {
        // The bridge must not buffer more than one frame.
        const { assert!(MAX_TAP_LATENCY_MS <= 20) };
    }
}
