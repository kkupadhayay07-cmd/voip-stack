//! ICE integration tests: agent-to-agent connectivity checks over a real
//! loopback socket, STUN gathering, and TURN relaying through our server.

use std::time::Duration;

use ice::candidate::Candidate;
use ice::stun;
use ice::{AgentConfig, IceAgent, StunTurnConfig, StunTurnServer};
use tokio::net::UdpSocket;

fn shuffle_credentials(tag: u8) -> AgentConfig {
    let mut c = AgentConfig::default();
    c.local_ufrag = format!("{tag}{}", c.local_ufrag);
    c.local_pwd = format!("{tag}{}", c.local_pwd);
    c
}

/// Two agents on loopback: exchange host candidates, run checks, nominate.
#[tokio::test(flavor = "multi_thread")]
async fn agent_pair_ice_handshake() {
    let mut a = IceAgent::new(shuffle_credentials(0xa)).await.unwrap();
    let mut b = IceAgent::new(shuffle_credentials(0xb)).await.unwrap();
    let a_host = a.gather_host().unwrap();
    let b_host = b.gather_host().unwrap();

    // Signaling exchange (out of band).
    a.set_remote(b.local_ufrag(), b.local_pwd(), b.local_candidates());
    b.set_remote(a.local_ufrag(), a.local_pwd(), a.local_candidates());

    let a_addr = a_host.address;
    let b_addr = b_host.address;
    let (ta, tb) = (
        tokio::spawn(async move { a.connect(Duration::from_secs(8)).await }),
        tokio::spawn(async move { b.connect(Duration::from_secs(8)).await }),
    );
    let (ra, rb) = tokio::join!(ta, tb);
    let pa = ra.unwrap().expect("agent A pair");
    let pb = rb.unwrap().expect("agent B pair");

    // Each side selected the other's host candidate address.
    assert_eq!(pa.remote, b_addr, "A selected B's candidate");
    assert_eq!(pb.remote, a_addr, "B selected A's candidate");
}

/// srflx gathering through our own STUN server.
#[tokio::test(flavor = "multi_thread")]
async fn srflx_gathering_via_stun_server() {
    let server = StunTurnServer::bind("127.0.0.1:0", StunTurnConfig::default())
        .await
        .unwrap();
    let stun_addr = server.local_addr().unwrap();
    tokio::spawn(async move { server.run().await });

    let mut agent = IceAgent::new(shuffle_credentials(0xc)).await.unwrap();
    let host = agent.gather_host().unwrap();
    let srflx = agent.gather_srflx(stun_addr).await.unwrap();

    assert_eq!(srflx.typ, ice::CandidateType::Srflx);
    // The reflexive address preserves the source port and resolves the
    // wildcard bind address to a concrete one.
    assert_eq!(srflx.address.port(), host.address.port());
    assert_ne!(srflx.address.ip().to_string(), "0.0.0.0");
    assert_ne!(host.address.ip().to_string(), "0.0.0.0");
}

/// TURN: allocate with long-term credentials, CreatePermission, Send
/// indication out, Data indication back.
#[tokio::test(flavor = "multi_thread")]
async fn turn_allocate_and_relay() {
    let mut users = std::collections::HashMap::new();
    users.insert("alice".to_string(), "secret123".to_string());
    let config = StunTurnConfig {
        users,
        require_auth: true,
        ..Default::default()
    };
    let server = StunTurnServer::bind("127.0.0.1:0", config).await.unwrap();
    let turn_addr = server.local_addr().unwrap();
    tokio::spawn(async move { server.run().await });

    let mut agent = IceAgent::new(shuffle_credentials(0xd)).await.unwrap();
    let relay = agent
        .gather_relay(turn_addr, "alice", "secret123")
        .await
        .unwrap();
    assert_eq!(relay.typ, ice::CandidateType::Relay);
    assert_ne!(relay.address, agent.local_addr().unwrap());

    // A peer socket that the agent will talk to through the relay.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    // CreatePermission for the peer.
    let mut perm = stun::Message::new(stun::CREATE_PERMISSION_REQUEST);
    perm.add_xor_address(stun::XOR_PEER_ADDRESS, peer_addr);
    perm.add_fingerprint();
    agent
        .socket()
        .send_to(&perm.encode(), turn_addr)
        .await
        .unwrap();

    // Wait briefly for the response, then Send indication → peer.
    let buf = &mut [0u8; 1500];
    let _ = tokio::time::timeout(Duration::from_millis(300), agent.socket().recv_from(buf)).await;

    let mut send = stun::Message::new(stun::SEND_INDICATION);
    send.add_xor_address(stun::XOR_PEER_ADDRESS, peer_addr);
    send.add(stun::DATA, b"hello-turn".to_vec());
    send.add_fingerprint();
    agent
        .socket()
        .send_to(&send.encode(), turn_addr)
        .await
        .unwrap();

    // The peer receives the relayed payload.
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(buf))
        .await
        .expect("peer receives relayed data")
        .unwrap();
    assert_eq!(&buf[..n], b"hello-turn");

    // And data sent from the peer to the relayed address arrives as a
    // Data indication.
    peer.send_to(b"pong", relay.address).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), agent.socket().recv_from(buf))
        .await
        .expect("agent receives data indication")
        .unwrap();
    let ind = stun::Message::parse(&buf[..n]).unwrap();
    assert_eq!(ind.msg_type, stun::DATA_INDICATION);
    assert_eq!(ind.get(stun::DATA).unwrap(), b"pong");
}

/// Candidate line exchange sanity across the agent boundary.
#[tokio::test]
async fn candidate_lines_roundtrip() {
    let mut agent = IceAgent::new(AgentConfig::default()).await.unwrap();
    let c = agent.gather_host().unwrap();
    let line = c.to_sdp();
    let parsed = Candidate::from_sdp(&line).unwrap();
    assert_eq!(parsed.address, c.address);
    assert_eq!(parsed.priority, c.priority);
}
