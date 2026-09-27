//! SIP transports: UDP datagrams, TCP and TLS stream framing, and WSS
//! (SIP over secure WebSocket, RFC 7118). Every listener parses messages and
//! hands them to the core pump; responses travel back either over the shared
//! UDP socket or the exact connection the request arrived on.

use std::net::SocketAddr;

use sip_core::parse::{parse_message, parse_stream};
use sip_core::ParseError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use crate::core::{ConnRegistry, Incoming, Responder};

/// Shared listener context.
#[derive(Clone)]
pub struct ListenerCtx {
    /// Core pump input.
    pub core: UnboundedSender<Incoming>,
    /// Live connection table (TCP/TLS/WSS).
    pub registry: ConnRegistry,
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
    let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
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
    let result = loop {
        match rd.read(&mut buf).await {
            Ok(0) => break Ok(()),
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                loop {
                    match parse_stream(&acc) {
                        Ok((msg, used)) => {
                            // socket-boundary tap (SipRx over TCP/TLS)
                            observ::session::sip_tap(&acc[..used], peer, transport, true);
                            acc.drain(..used);
                            let _ = ctx.core.send(Incoming {
                                msg,
                                resp: Responder {
                                    src: peer,
                                    conn: Some(tx.clone()),
                                },
                            });
                        }
                        Err(ParseError::Truncated { .. }) => break,
                        Err(e) => {
                            tracing::debug!(%peer, "{label} unparseable stream data: {e}");
                            acc.clear();
                            break;
                        }
                    }
                }
            }
            Err(e) => break Err(format!("{label} read: {e}")),
        }
    };

    ctx.registry.lock().expect("registry lock").remove(&peer);
    writer.abort();
    result
}

pub async fn run_tcp(bind: SocketAddr, ctx: ListenerCtx) -> Result<(), String> {
    let listener = TcpListener::bind(bind).await.map_err(|e| e.to_string())?;
    tracing::info!("sip/tcp listening on {bind}");
    loop {
        let (tcp, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("tcp accept: {e}"))?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
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
    tracing::info!("sip/tls listening on {bind}");
    loop {
        let (tcp, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("tls accept: {e}"))?;
        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
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
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let listener = TcpListener::bind(bind).await.map_err(|e| e.to_string())?;
    tracing::info!("sip/wss listening on {bind}");
    loop {
        let (tcp, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("wss accept: {e}"))?;
        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let tls = match crate::tls::accept_tls(&acceptor, tcp).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(%peer, "wss tls handshake failed: {e}");
                    return;
                }
            };
            // WebSocket upgrade on top of the established TLS stream.
            let ws = match tokio_tungstenite::accept_async(tls).await {
                Ok(w) => w,
                Err(e) => {
                    tracing::debug!(%peer, "wss upgrade failed: {e}");
                    return;
                }
            };
            tracing::debug!(%peer, "wss session established");

            let (mut sink, mut stream) = ws.split();
            let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
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

            while let Some(item) = stream.next().await {
                let payload: Vec<u8> = match item {
                    Ok(Message::Binary(bin)) => bin,
                    Ok(Message::Text(txt)) => txt.as_bytes().to_vec(),
                    Ok(Message::Close(_)) => break,
                    Ok(_) => continue,
                    Err(_) => break,
                };
                match parse_message(&payload) {
                    Ok(msg) => {
                        // socket-boundary tap (SipRx over WSS)
                        observ::session::sip_tap(&payload, peer, observ::event::Transport::Ws, true);
                        let _ = ctx.core.send(Incoming {
                            msg,
                            resp: Responder {
                                src: peer,
                                conn: Some(tx.clone()),
                            },
                        });
                    }
                    Err(e) => tracing::debug!(%peer, "wss unparseable: {e}"),
                }
            }

            ctx.registry.lock().expect("registry lock").remove(&peer);
            writer.abort();
        });
    }
}
