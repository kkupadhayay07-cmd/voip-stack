//! Minimal in-repo SIP UAC used by the demo: places one call (INVITE →
//! 200 → ACK → paced RTP → BYE → 200) or probes a listener with OPTIONS.
//! Speaks SIP over UDP, TCP, TLS or WSS; RTP rides plain UDP (RTP/AVP).

use std::net::SocketAddr;
use std::time::Duration;

use codecs::{CodecId, Registry};
use rtp::packet::RtpPacket;
use sip_core::builder::RequestBuilder;
use sip_core::ids::{new_branch, new_call_id, new_tag};
use sip_core::message::{Method, Response, SipMessage};
use sip_core::parse::{parse_message, parse_stream};
use sip_core::uri::{SipUri, TransportKind};
use sip_core::{serialize, ParseError};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Instant};

use b2bua::sdp_util;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    Wss,
}

impl Transport {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Ok(Transport::Udp),
            "tcp" => Ok(Transport::Tcp),
            "tls" => Ok(Transport::Tls),
            "wss" => Ok(Transport::Wss),
            other => Err(format!("unknown transport '{other}' (udp|tcp|tls|wss)")),
        }
    }

    pub(crate) fn kind(self) -> TransportKind {
        match self {
            Transport::Udp => TransportKind::Udp,
            Transport::Tcp => TransportKind::Tcp,
            Transport::Tls => TransportKind::Tls,
            Transport::Wss => TransportKind::Wss,
        }
    }

    /// Lowercase name for log lines.
    pub fn name(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
            Transport::Wss => "wss",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UacOpts {
    pub target: SocketAddr,
    pub transport: Transport,
    /// Request-URI / To header.
    pub to: String,
    /// From header URI.
    pub from: String,
    pub call_id: String,
    pub rtp_ms: u64,
    pub probe: bool,
    pub timeout: Duration,
    /// Client certificate for mTLS (auth=tls_client_cert trunks).
    pub tls_identity: Option<crate::tls::TlsClientIdentity>,
}

impl Default for UacOpts {
    fn default() -> Self {
        UacOpts {
            target: "127.0.0.1:5060".parse().unwrap(),
            transport: Transport::Udp,
            to: "sip:1000@zrtc.local".into(),
            from: "sip:demo@zrtc.local".into(),
            call_id: new_call_id("zrtc-demo"),
            rtp_ms: 1000,
            probe: false,
            timeout: Duration::from_secs(15),
            tls_identity: None,
        }
    }
}

/// One transport link: datagram or stream, owned by the session.
enum Link {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(tokio_openssl::SslStream<TcpStream>),
    Ws(Box<tokio_tungstenite::WebSocketStream<tokio_openssl::SslStream<TcpStream>>>),
}

impl Link {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        use futures_util::SinkExt;
        use tokio::io::AsyncWriteExt;
        use tokio_tungstenite::tungstenite::Message;
        match self {
            Link::Udp(s) => s
                .send(bytes)
                .await
                .map(|_| ())
                .map_err(|e| format!("udp send: {e}")),
            Link::Tcp(s) => s
                .write_all(bytes)
                .await
                .map_err(|e| format!("tcp send: {e}")),
            Link::Tls(s) => s
                .write_all(bytes)
                .await
                .map_err(|e| format!("tls send: {e}")),
            Link::Ws(s) => s
                .send(Message::Binary(bytes.to_vec()))
                .await
                .map_err(|e| format!("ws send: {e}")),
        }
    }

    /// Returns one datagram (UDP) or one buffered chunk (streams) / one WS
    /// message payload.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<Option<Vec<u8>>, String> {
        use futures_util::StreamExt;
        use tokio::io::AsyncReadExt;
        use tokio_tungstenite::tungstenite::Message;
        match self {
            Link::Udp(s) => {
                let (n, _) = s
                    .recv_from(buf)
                    .await
                    .map_err(|e| format!("udp recv: {e}"))?;
                Ok(Some(buf[..n].to_vec()))
            }
            Link::Tcp(s) => match s.read(buf).await {
                Ok(0) => Ok(None),
                Ok(n) => Ok(Some(buf[..n].to_vec())),
                Err(e) => Err(format!("tcp recv: {e}")),
            },
            Link::Tls(s) => match s.read(buf).await {
                Ok(0) => Ok(None),
                Ok(n) => Ok(Some(buf[..n].to_vec())),
                Err(e) => Err(format!("tls recv: {e}")),
            },
            Link::Ws(s) => match s.next().await {
                Some(Ok(Message::Binary(b))) => Ok(Some(b)),
                Some(Ok(Message::Text(t))) => Ok(Some(t.as_bytes().to_vec())),
                Some(Ok(_)) => Ok(Some(Vec::new())),
                Some(Err(e)) => Err(format!("ws recv: {e}")),
                None => Ok(None),
            },
        }
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Link::Udp(s) => s.local_addr().ok(),
            Link::Tcp(s) => s.local_addr().ok(),
            Link::Tls(s) => s.get_ref().local_addr().ok(),
            Link::Ws(_) => None,
        }
    }
}

/// Sequential SIP session over one link. Shared by the demo UAC and the
/// vendor trunk client (REGISTER / INVITE / keepalive).
pub(crate) struct Session {
    link: Link,
    streaming: bool,
    acc: Vec<u8>,
    via_host: String,
}

impl Session {
    pub(crate) async fn connect(opts: &UacOpts) -> Result<Self, String> {
        let target = opts.target;
        let (link, streaming, local_override) = match opts.transport {
            Transport::Udp => {
                let s = UdpSocket::bind(("127.0.0.1", 0))
                    .await
                    .map_err(|e| e.to_string())?;
                s.connect(target).await.map_err(|e| e.to_string())?;
                (Link::Udp(s), false, None)
            }
            Transport::Tcp => {
                let s = TcpStream::connect(target)
                    .await
                    .map_err(|e| e.to_string())?;
                let local = s.local_addr().ok();
                (Link::Tcp(s), true, local)
            }
            Transport::Tls => {
                let s = TcpStream::connect(target)
                    .await
                    .map_err(|e| e.to_string())?;
                let local = s.local_addr().ok();
                let connector = match &opts.tls_identity {
                    Some(id) => crate::tls::client_connector_with_identity(id)?,
                    None => crate::tls::client_connector()?,
                };
                let tls = crate::tls::connect_tls(&connector, &target.ip().to_string(), s).await?;
                (Link::Tls(tls), true, local)
            }
            Transport::Wss => {
                let s = TcpStream::connect(target)
                    .await
                    .map_err(|e| e.to_string())?;
                let local = s.local_addr().ok();
                let connector = match &opts.tls_identity {
                    Some(id) => crate::tls::client_connector_with_identity(id)?,
                    None => crate::tls::client_connector()?,
                };
                let tls = crate::tls::connect_tls(&connector, &target.ip().to_string(), s).await?;
                // WebSocket client handshake over the established TLS stream.
                use tokio_tungstenite::tungstenite::client::IntoClientRequest;
                let req = format!("wss://{}/sip", target)
                    .into_client_request()
                    .map_err(|e| format!("ws request: {e}"))?;
                let (ws, _resp) = tokio_tungstenite::client_async(req, tls)
                    .await
                    .map_err(|e| format!("ws handshake: {e}"))?;
                (Link::Ws(Box::new(ws)), true, local)
            }
        };
        let local = local_override
            .or_else(|| link.local_addr())
            .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        Ok(Session {
            link,
            streaming,
            acc: Vec::with_capacity(2048),
            via_host: local.to_string(),
        })
    }

    pub(crate) async fn send_msg(&mut self, msg: &SipMessage) -> Result<(), String> {
        let bytes = serialize(msg);
        self.link.send(&bytes).await
    }

    pub(crate) async fn recv_msg(&mut self) -> Result<SipMessage, String> {
        let mut buf = vec![0u8; 16_384];
        loop {
            if self.streaming {
                match parse_stream(&self.acc) {
                    Ok((msg, used)) => {
                        self.acc.drain(..used);
                        return Ok(msg);
                    }
                    Err(ParseError::Truncated { .. }) => {}
                    Err(e) => {
                        self.acc.clear();
                        return Err(format!("stream parse: {e}"));
                    }
                }
            }
            let Some(chunk) = self.link.recv(&mut buf).await? else {
                return Err("connection closed".into());
            };
            if self.streaming {
                self.acc.extend_from_slice(&chunk);
            } else {
                return parse_message(&chunk).map_err(|e| format!("datagram parse: {e}"));
            }
        }
    }

    pub(crate) fn via(&self) -> String {
        self.via_host.clone()
    }
}

/// Entry point: probe or full call.
pub async fn run(opts: UacOpts) -> Result<(), String> {
    let tout = opts.timeout;
    timeout(tout, async move {
        let mut sess = Session::connect(&opts).await?;
        if opts.probe {
            return probe(&mut sess, &opts).await;
        }
        place_call(&mut sess, &opts).await
    })
    .await
    .map_err(|_| format!("uac timed out after {tout:?}"))?
}

async fn probe(sess: &mut Session, opts: &UacOpts) -> Result<(), String> {
    let options = RequestBuilder::new(
        Method::Options,
        SipUri::parse(&opts.to).map_err(|e| e.to_string())?,
    )
    .via(opts.transport.kind(), &sess.via(), Some(&new_branch()))
    .from(&format!("<{}>;tag={}", opts.from, new_tag()))
    .to(&format!("<{}>", opts.to))
    .call_id(Some(&new_call_id("zrtc-probe")))
    .cseq(1)
    .contact(&format!("<sip:probe@{}>", sess.via()))
    .header("Max-Forwards", "70")
    .build();
    sess.send_msg(&SipMessage::Request(options)).await?;
    loop {
        match sess.recv_msg().await? {
            SipMessage::Response(r) => {
                if r.code == 200 {
                    tracing::info!("probe ok via {:?}", opts.transport);
                    return Ok(());
                }
                return Err(format!("probe got {}", r.code));
            }
            SipMessage::Request(_) => continue,
        }
    }
}

async fn place_call(sess: &mut Session, opts: &UacOpts) -> Result<(), String> {
    // RTP socket (plain RTP/AVP over UDP regardless of SIP transport).
    let rtp = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| e.to_string())?;
    let rtp_port = rtp.local_addr().map(|a| a.port()).unwrap_or(0);

    let offer = sdp_util::build_offer("127.0.0.1", rtp_port, &[CodecId::Pcmu], rand::random());
    let invite = RequestBuilder::new(
        Method::Invite,
        SipUri::parse(&opts.to).map_err(|e| e.to_string())?,
    )
    .via(opts.transport.kind(), &sess.via(), Some(&new_branch()))
    .from(&format!("<{}>;tag={}", opts.from, new_tag()))
    .to(&format!("<{}>", opts.to))
    .call_id(Some(&opts.call_id))
    .cseq(1)
    .contact(&format!("<sip:demo@{}>", sess.via()))
    .header("Max-Forwards", "70")
    .header("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS")
    .body("application/sdp", offer.serialize().into_bytes())
    .build();
    tracing::info!(call_id = %opts.call_id, transport = ?opts.transport, "uac: INVITE -> {}", opts.target);
    sess.send_msg(&SipMessage::Request(invite)).await?;

    // 100 / 180 / 200.
    let ok: Response = loop {
        match sess.recv_msg().await? {
            SipMessage::Response(r) => match r.code {
                100 | 180 | 183 => continue,
                200 => break r,
                c => return Err(format!("INVITE rejected with {c}")),
            },
            SipMessage::Request(req) => {
                if req.method == Method::Bye {
                    let bye_ok = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                    sess.send_msg(&SipMessage::Response(bye_ok)).await?;
                    return Err("remote hung up before answer".into());
                }
            }
        }
    };
    let answer = String::from_utf8_lossy(&ok.body).to_string();
    let audio_port = extract_audio_port(&answer).ok_or("no m=audio port in answer")?;
    let remote_tag = to_tag_of(&ok);
    tracing::info!(call_id = %opts.call_id, "uac: 200 OK (answer audio port {audio_port})");

    // ACK.
    let ack = RequestBuilder::new(
        Method::Ack,
        SipUri::parse(&opts.to).map_err(|e| e.to_string())?,
    )
    .via(opts.transport.kind(), &sess.via(), Some(&new_branch()))
    .from(&format!("<{}>;tag={}", opts.from, from_tag_of(&ok)))
    .to(&format!("<{}>;tag={remote_tag}", opts.to))
    .call_id(Some(&opts.call_id))
    .cseq(1)
    .build();
    sess.send_msg(&SipMessage::Request(ack)).await?;

    // Paced RTP: 20 ms PCMU frames, 440 Hz tone.
    let mut enc = Registry::encoder(CodecId::Pcmu, 8000, 1).map_err(|e| e.to_string())?;
    let samples = (opts.rtp_ms as usize) * 8; // 8 kHz
    let pcm: Vec<i16> = (0..samples)
        .map(|i| {
            let v = (f64::from(i as u32) * 440.0 * std::f64::consts::TAU / 8000.0).sin() * 9000.0;
            v.clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
        })
        .collect();
    let dst = SocketAddr::new(opts.target.ip(), audio_port);
    let mut seq: u16 = rand::random();
    let mut ts: u32 = rand::random();
    let ssrc: u32 = rand::random();
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    for frame in pcm.chunks(160) {
        ticker.tick().await;
        let mut wire = Vec::with_capacity(200);
        enc.encode(frame, &mut wire).map_err(|e| e.to_string())?;
        let pkt = RtpPacket::new(0, seq, ts, ssrc, false, bytes::Bytes::from(wire));
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(160);
        rtp.send_to(&pkt.encode(), dst)
            .await
            .map_err(|e| e.to_string())?;
    }
    tracing::info!(call_id = %opts.call_id, "uac: sent {} frames of RTP", samples.div_ceil(160));

    // Let the jitter buffer play the tail out before tearing down.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // BYE.
    let bye = RequestBuilder::new(
        Method::Bye,
        SipUri::parse(&opts.to).map_err(|e| e.to_string())?,
    )
    .via(opts.transport.kind(), &sess.via(), Some(&new_branch()))
    .from(&format!("<{}>;tag={}", opts.from, from_tag_of(&ok)))
    .to(&format!("<{}>;tag={remote_tag}", opts.to))
    .call_id(Some(&opts.call_id))
    .cseq(2)
    .build();
    sess.send_msg(&SipMessage::Request(bye)).await?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("no 200 for BYE".into());
        }
        let msg = timeout(remaining, sess.recv_msg())
            .await
            .map_err(|_| "no 200 for BYE")??;
        match msg {
            SipMessage::Response(r) if r.code == 200 => break,
            SipMessage::Response(_) => continue,
            SipMessage::Request(req) => {
                if req.method == Method::Bye {
                    let r = sip_core::builder::respond_to(&req, 200, "OK", Vec::new(), None);
                    sess.send_msg(&SipMessage::Response(r)).await?;
                }
            }
        }
    }
    tracing::info!(call_id = %opts.call_id, "uac: call complete (BYE 200)");
    Ok(())
}

fn to_tag_of(resp: &Response) -> String {
    resp.headers
        .get("To")
        .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
        .and_then(|n| n.tag)
        .unwrap_or_default()
}

fn from_tag_of(resp: &Response) -> String {
    resp.headers
        .get("From")
        .and_then(|t| sip_core::uri::NameAddr::parse(t).ok())
        .and_then(|n| n.tag)
        .unwrap_or_default()
}

fn extract_audio_port(sdp: &str) -> Option<u16> {
    sdp.lines()
        .find(|l| l.starts_with("m=audio "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|p| p.parse().ok())
}
