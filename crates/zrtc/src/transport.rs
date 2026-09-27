//! SIP transports: UDP datagrams, TCP and TLS stream framing, and WSS
//! (SIP over secure WebSocket, RFC 7118). Every listener parses messages and
//! hands them to the core pump; responses travel back either over the shared
//! UDP socket or the exact connection the request arrived on.
//!
//! Adverse-input posture (Batch A hardening):
//!
//! * **Framing violations close the connection.** Once stream framing is
//!   violated (garbage, missing/huge `Content-Length`), the byte stream can
//!   no longer be resynchronized (RFC 3261 §18.3) — the connection is
//!   closed instead of silently re-syncing on a corrupted stream.
//! * **Idle timeout.** A connection that sends no bytes for
//!   [`STREAM_IDLE`] is closed, so a slow peer cannot park tasks and
//!   buffers forever (slowloris).
//! * **Connection cap.** Each stream listener runs at most
//!   [`MAX_STREAM_CONNS`] concurrent connections; excess connects wait in
//!   the kernel accept backlog.
//! * **Bounded queues.** The listener→core channel and each connection's
//!   writer channel are bounded; a peer that never reads cannot make the
//!   daemon buffer responses without limit.
//! * **WebSocket limits.** WSS frames larger than [`WS_MAX_MESSAGE`] /
//!   [`WS_MAX_FRAME`] are rejected at the protocol layer (library defaults
//!   allow tens of MiB); a frame may carry multiple pipelined SIP messages
//!   and CRLF keepalives (RFC 7118 §4.4 robustness).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sip_core::parse::parse_stream;
use sip_core::ParseError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;

use crate::core::{ConnRegistry, Incoming, Responder};

/// How long a stream connection (TCP/TLS/WSS) may stay silent before it is
/// closed. SIP keepalives (CRLF over stream transports, OPTIONS) refresh it.
pub const STREAM_IDLE: Duration = Duration::from_secs(180);

/// Maximum concurrent connections per stream listener. Extra connects wait
/// in the kernel accept backlog until a slot frees up.
pub const MAX_STREAM_CONNS: usize = 256;

/// Maximum WebSocket message size (one WS message = one or more SIP
/// messages + keepalive CRLFs, RFC 7118 §4.4). The SIP parser itself caps
/// messages at 64 KiB (`sip_core::parse::MAX_MESSAGE`); this bounds the
/// framing layer with headroom.
pub const WS_MAX_MESSAGE: usize = 1024 * 1024;

/// Maximum single WebSocket frame size (continuation frames aside).
pub const WS_MAX_FRAME: usize = 1024 * 1024;

/// Per-connection writer backlog: responses queued for a peer that is not
/// reading. When full, responses are dropped (and logged) instead of
/// buffering without bound.
const WRITER_BACKLOG: usize = 64;

/// Shared listener context.
#[derive(Clone)]
pub struct ListenerCtx {
    /// Core pump input (bounded: applies backpressure to listener tasks
    /// when the core pump is busy).
    pub core: Sender<Incoming>,
    /// Live connection table (TCP/TLS/WSS).
    pub registry: ConnRegistry,
    /// Read-idle window before a connection is closed.
    pub idle: Duration,
}

// ---------------------------------------------------------------- UDP ----
// The UDP listener lives in `daemon.rs` (it shares the core's outbound
// socket); this module owns the connection-oriented transports.

// ------------------------------------------------------- TCP/TLS streams --

/// Stream framing loop shared by TCP and TLS: accumulate bytes, peel whole
/// SIP messages via `parse_stream`, forward each to the core. Responses are
/// written back over this same connection through a writer task.
async fn stream_loop<S>(
    stream: S,
    peer: SocketAddr,
    ctx: ListenerCtx,
    label: &'static str,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(WRITER_BACKLOG);
    ctx.registry
        .lock()
        .expect("registry lock")
        .insert(peer, tx.clone());

    let (mut rd, mut wr) = tokio::io::split(stream);
    let transport = if label == "tls" {
        observ::event::Transport::Tls
    } else {
        observ::event::Transport::Tcp
    };
    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            // socket-boundary tap (SipTx over TCP/TLS)
            observ::session::sip_tap(&bytes, peer, transport, false);
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
            let _ = wr.flush().await;
        }
    });

    let mut acc: Vec<u8> = Vec::with_capacity(2048);
    let mut buf = vec![0u8; 8192];
    let result = 'reading: loop {
        // Idle timeout: a silent peer eventually releases its task, buffer
        // and registry slot (slowloris defense).
        match tokio::time::timeout(ctx.idle, rd.read(&mut buf)).await {
            Err(_) => break Err(format!("{label} idle timeout after {:?}", ctx.idle)),
            Ok(Err(e)) => break Err(format!("{label} read: {e}")),
            Ok(Ok(0)) => break Ok(()),
            Ok(Ok(n)) => {
                acc.extend_from_slice(&buf[..n]);
                loop {
                    match parse_stream(&acc) {
                        Ok((msg, used)) => {
                            // socket-boundary tap (SipRx over TCP/TLS)
                            observ::session::sip_tap(&acc[..used], peer, transport, true);
                            acc.drain(..used);
                            let _ = ctx
                                .core
                                .send(Incoming {
                                    msg,
                                    resp: Responder {
                                        src: peer,
                                        conn: Some(tx.clone()),
                                    },
                                })
                                .await;
                        }
                        Err(ParseError::Truncated { .. }) => break,
                        Err(e) => {
                            // Stream framing is violated: the byte stream
                            // cannot be resynchronized (RFC 3261 §18.3) and
                            // continuing would silently drop whatever
                            // follows the garbage. Close the connection.
                            break 'reading Err(format!("{label} framing error: {e}"));
                        }
                    }
                }
            }
        }
    };

    ctx.registry.lock().expect("registry lock").remove(&peer);
    writer.abort();
    result
}

pub async fn run_tcp(bind: SocketAddr, ctx: ListenerCtx) -> Result<(), String> {
    let listener = TcpListener::bind(bind).await.map_err(|e| e.to_string())?;
    run_tcp_on(listener, ctx).await
}

/// Same as [`run_tcp`] but over a pre-bound listener (test entry point).
pub async fn run_tcp_on(listener: TcpListener, ctx: ListenerCtx) -> Result<(), String> {
    let sem = Arc::new(Semaphore::new(MAX_STREAM_CONNS));
    loop {
        let (tcp, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("tcp accept: {e}"))?;
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            return Err("tcp listener closed".into());
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the connection lifetime
            if let Err(e) = stream_loop(tcp, peer, ctx, "tcp").await {
                tracing::debug!(%peer, "tcp connection ended: {e}");
            }
        });
    }
}

pub async fn run_tls(
    bind: SocketAddr,
    acceptor: openssl::ssl::SslAcceptor,
    ctx: ListenerCtx,
) -> Result<(), String> {
    let listener = TcpListener::bind(bind).await.map_err(|e| e.to_string())?;
    run_tls_on(listener, acceptor, ctx).await
}

/// Same as [`run_tls`] but over a pre-bound listener (test entry point).
pub async fn run_tls_on(
    listener: TcpListener,
    acceptor: openssl::ssl::SslAcceptor,
    ctx: ListenerCtx,
) -> Result<(), String> {
    let sem = Arc::new(Semaphore::new(MAX_STREAM_CONNS));
    loop {
        let (tcp, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("tls accept: {e}"))?;
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            return Err("tls listener closed".into());
        };
        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match crate::tls::accept_tls(&acceptor, tcp).await {
                Ok(stream) => {
                    if let Err(e) = stream_loop(stream, peer, ctx, "tls").await {
                        tracing::debug!(%peer, "tls connection ended: {e}");
                    }
                }
                Err(e) => tracing::debug!(%peer, "tls handshake failed: {e}"),
            }
        });
    }
}

// ---------------------------------------------------------------- WSS ----

pub async fn run_wss(
    bind: SocketAddr,
    acceptor: openssl::ssl::SslAcceptor,
    ctx: ListenerCtx,
) -> Result<(), String> {
    let listener = TcpListener::bind(bind).await.map_err(|e| e.to_string())?;
    run_wss_on(listener, acceptor, ctx).await
}

/// Same as [`run_wss`] but over a pre-bound listener (test entry point).
pub async fn run_wss_on(
    listener: TcpListener,
    acceptor: openssl::ssl::SslAcceptor,
    ctx: ListenerCtx,
) -> Result<(), String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
    use tokio_tungstenite::tungstenite::Message;

    let sem = Arc::new(Semaphore::new(MAX_STREAM_CONNS));
    loop {
        let (tcp, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("wss accept: {e}"))?;
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            return Err("wss listener closed".into());
        };
        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match crate::tls::accept_tls(&acceptor, tcp).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(%peer, "wss tls handshake failed: {e}");
                    return;
                }
            };
            // WebSocket upgrade on top of the established TLS stream, with
            // explicit framing limits (library defaults allow 64 MiB).
            let cfg = WebSocketConfig {
                max_message_size: Some(WS_MAX_MESSAGE),
                max_frame_size: Some(WS_MAX_FRAME),
                ..Default::default()
            };
            let ws = match tokio_tungstenite::accept_async_with_config(tls, Some(cfg)).await {
                Ok(w) => w,
                Err(e) => {
                    tracing::debug!(%peer, "wss upgrade failed: {e}");
                    return;
                }
            };
            tracing::debug!(%peer, "wss session established");

            let (mut sink, mut stream) = ws.split();
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(WRITER_BACKLOG);
            ctx.registry
                .lock()
                .expect("registry lock")
                .insert(peer, tx.clone());

            let writer = tokio::spawn(async move {
                while let Some(bytes) = rx.recv().await {
                    // socket-boundary tap (SipTx over WSS — cleartext after
                    // the TLS/WSS layers, so plaintext=true)
                    observ::session::sip_tap(&bytes, peer, observ::event::Transport::Ws, false);
                    if sink.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
            });

            // Read loop with the same idle defense as TCP/TLS. A silent WSS
            // session is closed after ctx.idle; Pong for peer pings is sent
            // by tungstenite on the next outbound write (SIP keepalives are
            // CRLF-level per RFC 7118 §4.3, not WS pings).
            while let Some(item) = tokio::time::timeout(ctx.idle, stream.next())
                .await
                .unwrap_or(None)
            {
                let payload: Vec<u8> = match item {
                    Ok(Message::Binary(bin)) => bin,
                    Ok(Message::Text(txt)) => txt.as_bytes().to_vec(),
                    Ok(Message::Close(_)) => break,
                    Ok(_) => continue,
                    Err(_) => break,
                };
                ws_payload_incoming(&payload, peer, &ctx, &tx).await;
            }

            ctx.registry.lock().expect("registry lock").remove(&peer);
            writer.abort();
        });
    }
}

/// Handles one decoded WebSocket payload: peels every SIP message it
/// contains (RFC 7118 §4.4 says senders put one message per frame, but
/// receivers must be robust) and forwards each to the core. CRLF keepalive
/// bytes and frames are silently ignored; a frame whose contents cannot be
/// parsed is logged and discarded — WS frames are self-delimiting, so the
/// connection stays usable (unlike a corrupted TCP stream).
async fn ws_payload_incoming(
    payload: &[u8],
    peer: SocketAddr,
    ctx: &ListenerCtx,
    tx: &Sender<Vec<u8>>,
) {
    let mut rest = payload;
    while !rest.is_empty() {
        match parse_stream(rest) {
            Ok((msg, used)) => {
                // socket-boundary tap (SipRx over WSS)
                observ::session::sip_tap(&rest[..used], peer, observ::event::Transport::Ws, true);
                let _ = ctx
                    .core
                    .send(Incoming {
                        msg,
                        resp: Responder {
                            src: peer,
                            conn: Some(tx.clone()),
                        },
                    })
                    .await;
                rest = &rest[used..];
            }
            // Truncated inside a frame: keepalive-only remainder, or a
            // partial message (forbidden by RFC 7118 §4.4). Either way the
            // rest of this frame is unusable — drop it and keep reading.
            Err(ParseError::Truncated { .. }) => break,
            Err(e) => {
                tracing::debug!(%peer, "wss unparseable frame: {e}");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------- tests --

#[cfg(test)]
mod framing_audit_tests {
    use super::*;
    use sip_core::message::{Method, SipMessage};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc::Receiver;
    use tokio_tungstenite::tungstenite::Message;

    const REGISTER: &[u8] = b"REGISTER sip:alice@atlanta.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
To: <sip:alice@atlanta.com>\r\n\
From: <sip:bob@biloxi.com>;tag=1\r\n\
Call-ID: reg-1@x\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:b@127.0.0.1:5060>\r\n\
Content-Length: 0\r\n\r\n";

    /// UTF-8 body "café" — the é (0xC3 0xA9) can be split by a segment.
    const UTF8_MSG: &[u8] = b"MESSAGE sip:alice@atlanta.com SIP/2.0\r\n\
Via: SIP/2.0/TCP h;branch=z9hG4bK1\r\n\
Call-ID: u8@x\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Type: text/plain\r\n\
Content-Length: 5\r\n\r\ncaf\xC3\xA9";

    /// MESSAGE announcing a body it will never send.
    const HUGE_CL: &[u8] = b"MESSAGE sip:alice@atlanta.com SIP/2.0\r\n\
Via: SIP/2.0/TCP h;branch=z9hG4bK1\r\n\
Call-ID: big@x\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 999999999\r\n\r\nshort";

    fn test_ctx(idle: Duration) -> (ListenerCtx, Receiver<Incoming>) {
        let (core_tx, core_rx) = tokio::sync::mpsc::channel(64);
        let ctx = ListenerCtx {
            core: core_tx,
            registry: Arc::new(Mutex::new(HashMap::new())),
            idle,
        };
        (ctx, core_rx)
    }

    async fn next_incoming(rx: &mut Receiver<Incoming>) -> SipMessage {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("core message within 2s")
            .expect("core channel open")
            .msg
    }

    /// Reads from the peer until EOF, asserting the server closed the
    /// connection cleanly (0-byte read) within 2 s.
    async fn expect_eof<S>(mut stream: S)
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("close within 2s")
            .expect("read ok");
        assert_eq!(n, 0, "expected clean EOF (connection closed)");
    }

    fn assert_register(msg: &SipMessage, what: &str) {
        match msg {
            SipMessage::Request(r) => {
                assert_eq!(r.method, Method::Register, "{what}");
                assert_eq!(r.headers.call_id(), Some("reg-1@x"), "{what}");
            }
            _ => panic!("{what}: expected a request"),
        }
    }

    #[tokio::test]
    async fn tcp_leading_crlf_keepalive_then_register() {
        let (ctx, mut core_rx) = test_ctx(STREAM_IDLE);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_tcp_on(listener, ctx));

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut wire = b"\r\n\r\n".to_vec();
        wire.extend_from_slice(REGISTER);
        c.write_all(&wire).await.unwrap();

        let msg = next_incoming(&mut core_rx).await;
        assert_register(&msg, "message behind the CRLF keepalive");
    }

    #[tokio::test]
    async fn tcp_pipelined_messages_all_reach_core() {
        let (ctx, mut core_rx) = test_ctx(STREAM_IDLE);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_tcp_on(listener, ctx));

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut wire = REGISTER.to_vec();
        wire.extend_from_slice(REGISTER);
        wire.extend_from_slice(b"\r\n"); // trailing keepalive
        c.write_all(&wire).await.unwrap();

        let m1 = next_incoming(&mut core_rx).await;
        let m2 = next_incoming(&mut core_rx).await;
        assert_register(&m1, "first pipelined message");
        assert_register(&m2, "second pipelined message");
    }

    #[tokio::test]
    async fn tcp_garbage_closes_connection() {
        let (ctx, mut core_rx) = test_ctx(STREAM_IDLE);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_tcp_on(listener, ctx));

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(b"NOT-SIP junk at all\r\n\r\n").await.unwrap();
        expect_eof(c).await;
        assert!(core_rx.try_recv().is_err(), "no message may reach the core");
    }

    #[tokio::test]
    async fn tcp_idle_timeout_closes_slowloris() {
        let (ctx, mut core_rx) = test_ctx(Duration::from_millis(100));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_tcp_on(listener, ctx));

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        // half a message, then silence past the idle window
        c.write_all(b"INVITE sip:a@b SIP/2.0\r\n").await.unwrap();
        expect_eof(c).await;
        assert!(core_rx.try_recv().is_err(), "no message may reach the core");
    }

    #[tokio::test]
    async fn tcp_oversized_content_length_closes() {
        let (ctx, mut core_rx) = test_ctx(STREAM_IDLE);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_tcp_on(listener, ctx));

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(HUGE_CL).await.unwrap();
        expect_eof(c).await;
        assert!(core_rx.try_recv().is_err(), "no message may reach the core");
    }

    #[tokio::test]
    async fn tcp_utf8_body_split_across_segments_survives() {
        let (ctx, mut core_rx) = test_ctx(STREAM_IDLE);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_tcp_on(listener, ctx));

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (head, tail) = UTF8_MSG.split_at(UTF8_MSG.len() - 1); // cut inside é
        c.write_all(head).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        c.write_all(tail).await.unwrap();

        let msg = next_incoming(&mut core_rx).await;
        match msg {
            SipMessage::Request(r) => assert_eq!(r.body, b"caf\xC3\xA9"),
            _ => panic!("expected a request"),
        }
    }

    #[tokio::test]
    async fn tls_leading_crlf_and_pipelined() {
        let (ctx, mut core_rx) = test_ctx(STREAM_IDLE);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let id = crate::tls::TlsIdentity::generate("127.0.0.1").unwrap();
        let acceptor = id.acceptor().unwrap();
        tokio::spawn(run_tls_on(listener, acceptor, ctx));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = crate::tls::client_connector().unwrap();
        let mut tls = crate::tls::connect_tls(&connector, "127.0.0.1", tcp)
            .await
            .unwrap();
        let mut wire = b"\r\n".to_vec();
        wire.extend_from_slice(REGISTER);
        wire.extend_from_slice(REGISTER);
        tls.write_all(&wire).await.unwrap();

        let m1 = next_incoming(&mut core_rx).await;
        let m2 = next_incoming(&mut core_rx).await;
        assert_register(&m1, "first TLS message");
        assert_register(&m2, "second TLS message");
    }

    #[tokio::test]
    async fn wss_frame_peels_pipelined_messages_and_skips_keepalives() {
        let (ctx, mut core_rx) = test_ctx(STREAM_IDLE);
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();

        // One WS frame carrying two pipelined SIP messages.
        let mut frame = REGISTER.to_vec();
        frame.extend_from_slice(REGISTER);
        ws_payload_incoming(&frame, peer, &ctx, &tx).await;
        let m1 = next_incoming(&mut core_rx).await;
        let m2 = next_incoming(&mut core_rx).await;
        assert_register(&m1, "first framed message");
        assert_register(&m2, "second framed message");

        // CRLF keepalive frame: silently ignored, nothing forwarded.
        ws_payload_incoming(b"\r\n", peer, &ctx, &tx).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), core_rx.recv())
                .await
                .is_err(),
            "keepalive frame must not produce a core message"
        );

        // Garbage frame: logged and discarded; the session stays usable.
        ws_payload_incoming(b"garbage\r\n\r\n", peer, &ctx, &tx).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), core_rx.recv())
                .await
                .is_err(),
            "garbage frame must not produce a core message"
        );
    }

    /// The WSS read loop treats `Message::Text` as SIP just like binary;
    /// make sure the payload extraction (Text → bytes) reaches the peeler.
    #[tokio::test]
    async fn wss_text_frames_are_sip_too() {
        let (ctx, mut core_rx) = test_ctx(STREAM_IDLE);
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let payload = match Message::Text(String::from_utf8(REGISTER.to_vec()).unwrap()) {
            Message::Text(t) => t.as_bytes().to_vec(),
            _ => unreachable!(),
        };
        ws_payload_incoming(&payload, peer, &ctx, &tx).await;
        let msg = next_incoming(&mut core_rx).await;
        assert_register(&msg, "text-framed message");
    }
}
