//! End-to-end DTLS-SRTP handshake tests: in-process client/server over a
//! real UDP socket pair, with SRTP session derivation from the exported
//! keying material.

use dtls::{DtlsEndpoint, DtlsRole, Identity, SrtpOffers};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

fn noop(_: Vec<u8>, _: SocketAddr) {}

async fn bind_udp() -> (UdpSocket, SocketAddr) {
    let s = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = s.local_addr().unwrap();
    (s, addr)
}

/// Client + server endpoints with cross-pinned fingerprints and two UDP
/// sockets.
struct Pair {
    client: DtlsEndpoint,
    server: DtlsEndpoint,
    csock: UdpSocket,
    ssock: UdpSocket,
    caddr: SocketAddr,
    saddr: SocketAddr,
}

async fn make_pair(offers: SrtpOffers) -> Pair {
    let client_id = Identity::generate("client").unwrap();
    let server_id = Identity::generate("server").unwrap();
    let mut client = DtlsEndpoint::new(client_id, DtlsRole::Client, offers.clone()).unwrap();
    let mut server = DtlsEndpoint::new(server_id, DtlsRole::Server, offers).unwrap();

    // Pin each other's fingerprints, as SDP offer/answer would arrange.
    let client_fp = client.fingerprint().to_string();
    let server_fp = server.fingerprint().to_string();
    server.pin_peer_fingerprint(client_fp);
    client.pin_peer_fingerprint(server_fp);

    let (csock, caddr) = bind_udp().await;
    let (ssock, saddr) = bind_udp().await;
    Pair {
        client,
        server,
        csock,
        ssock,
        caddr,
        saddr,
    }
}

async fn run_handshake(p: Pair) -> (DtlsEndpoint, DtlsEndpoint) {
    let mut client = p.client;
    let mut server = p.server;
    let mut csock = p.csock;
    let mut ssock = p.ssock;
    let (caddr, saddr) = (p.caddr, p.saddr);

    let c = tokio::spawn(async move {
        client
            .handshake_udp(&mut csock, saddr, noop)
            .await
            .expect("client handshake");
        client
    });
    let s = tokio::spawn(async move {
        server
            .handshake_udp(&mut ssock, caddr, noop)
            .await
            .expect("server handshake");
        server
    });
    let (c, s) = tokio::join!(c, s);
    (c.unwrap(), s.unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn full_dtls_srtp_handshake_and_key_export() {
    let pair = make_pair(SrtpOffers::default_offer()).await;
    let (client, server) = run_handshake(pair).await;

    // Both sides agree on the profile.
    let cp = client.negotiated_profile().unwrap();
    let sp = server.negotiated_profile().unwrap();
    assert_eq!(cp, sp);

    // Symmetric keying material.
    let ck = client.export_srtp_keys().unwrap();
    let sk = server.export_srtp_keys().unwrap();
    assert_eq!(ck.profile, sk.profile);
    assert_eq!(ck.client, sk.client);
    assert_eq!(ck.server, sk.server);

    // The key lengths match the negotiated profile.
    assert_eq!(ck.client.0.len(), cp.key_len());
    assert_eq!(ck.client.1.len(), cp.salt_len());

    // The peer certificate presented matches the pinned fingerprint.
    let sfp = server.peer_fingerprint().unwrap();
    assert_eq!(client.fingerprint(), sfp);
}

#[tokio::test(flavor = "multi_thread")]
async fn srtp_sessions_from_dtls_keys_roundtrip() {
    let pair = make_pair(SrtpOffers::default_offer()).await;
    let (client, _server) = run_handshake(pair).await;

    let ck = client.export_srtp_keys().unwrap();
    let (mut c_out, mut c_in) = ck.sessions(true).unwrap();
    let (mut s_out, mut s_in) = ck.sessions(false).unwrap();

    // Client → server media path.
    let mut pkt = {
        let mut p = vec![0x80u8, 0x60, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 9, 9, 9, 9];
        c_out.protect(&mut p).unwrap();
        p
    };
    s_in.unprotect(&mut pkt).unwrap();
    assert_eq!(&pkt[12..], &[9, 9, 9, 9]);

    // Server → client media path.
    let mut pkt = {
        let mut p = vec![0x80u8, 0x60, 0, 2, 0, 0, 0, 2, 1, 2, 3, 4, 7, 7];
        s_out.protect(&mut p).unwrap();
        p
    };
    c_in.unprotect(&mut pkt).unwrap();
    assert_eq!(&pkt[12..], &[7, 7]);
}

#[tokio::test(flavor = "multi_thread")]
async fn fingerprint_mismatch_fails_handshake() {
    let mut pair = make_pair(SrtpOffers::default_offer()).await;
    // Client pins a bogus fingerprint.
    pair.client.pin_peer_fingerprint("00:11:22:33");

    let mut client = pair.client;
    let mut server = pair.server;
    let mut csock = pair.csock;
    let mut ssock = pair.ssock;
    let (caddr, saddr) = (pair.caddr, pair.saddr);

    let c = tokio::spawn(async move { client.handshake_udp(&mut csock, saddr, noop).await });
    let s = tokio::spawn(async move { server.handshake_udp(&mut ssock, caddr, noop).await });
    let (cres, sres) = tokio::join!(c, s);
    // Server completes; client must reject the fingerprint.
    assert!(sres.unwrap().is_ok());
    assert!(cres.unwrap().is_err());
}

/// Drive a lossy handshake with our own event loop using `drive_once`,
/// dropping the first N datagrams in each direction.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_survives_packet_loss() {
    let pair = make_pair(SrtpOffers::default_offer()).await;
    let mut drops_c_to_s = 2usize;
    let mut drops_s_to_c = 1usize;

    let (caddr, saddr) = (pair.caddr, pair.saddr);
    let mut client = pair.client;
    let mut server = pair.server;
    let csock = pair.csock;
    let ssock = pair.ssock;

    let deadline = Instant::now() + Duration::from_secs(20);
    let (mut client_done, mut server_done) = (false, false);
    let buf = &mut [0u8; 2048];

    while Instant::now() < deadline && !(client_done && server_done) {
        if !client_done {
            client_done = client.drive_once().expect("client step");
        }
        if !server_done {
            server_done = server.drive_once().expect("server step");
        }
        // Transmit fresh output and retransmit current flights, both
        // through the loss filter (a dropped datagram only delays it —
        // the next timer round retransmits).  Drain even after completion:
        // the final flight (server CCS+Finished) is written by the state
        // machine on the very step that returns complete.
        for d in client.take_outbound() {
            send_lossy(&csock, &d, saddr, &mut drops_c_to_s).await;
        }
        for d in server.take_outbound() {
            send_lossy(&ssock, &d, caddr, &mut drops_s_to_c).await;
        }
        // Pump network both ways.
        if let Ok((n, _)) = csock.try_recv_from(buf) {
            client.push_datagram(buf[..n].to_vec());
        }
        if let Ok((n, _)) = ssock.try_recv_from(buf) {
            server.push_datagram(buf[..n].to_vec());
        }
        if !client_done {
            for d in client.current_flight() {
                send_lossy(&csock, d, saddr, &mut drops_c_to_s).await;
            }
        }
        if !server_done {
            for d in server.current_flight() {
                send_lossy(&ssock, d, caddr, &mut drops_s_to_c).await;
            }
        }
        let _ = (&mut client, &mut server);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(client_done && server_done, "handshake must survive loss");

    // Keys still agree.
    let ck = client.export_srtp_keys().unwrap();
    let sk = server.export_srtp_keys().unwrap();
    assert_eq!(ck.client, sk.client);
    assert_eq!(ck.server, sk.server);
}

/// Send one datagram, dropping it while drop budget remains.
async fn send_lossy(sock: &UdpSocket, d: &[u8], to: SocketAddr, drops: &mut usize) {
    if *drops > 0 {
        *drops -= 1;
        return;
    }
    let _ = sock.send_to(d, to).await;
}
