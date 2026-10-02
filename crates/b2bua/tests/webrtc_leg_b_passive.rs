//! WebRTC leg B (offerer side, RFC 5763) — PASSIVE answer:
//! the callee answers `setup:passive`, so the B2BUA drives DTLS as the CLIENT
//! (the role flip RFC 5763 §5 allows). Plain PCMU caller → B2BUA → callee.

#[path = "webrtc_leg_b/common.rs"]
mod common;

use common::*;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leg_b_webrtc_passive_answer_loopback() {
    init_log().await;
    let (tx, mut cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let callee_sip = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let callee_addr = callee_sip.local_addr().unwrap();
    let engine_addr = spawn_engine(callee_addr, tx).await;

    // setup:passive — the B2BUA becomes the DTLS CLIENT on leg B.
    let callee_task = tokio::spawn(run_webrtc_callee(callee_sip, "passive"));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (decoded_a, bye200) = run_plain_caller(engine_addr, "webrtc-leg-b-passive").await;
    assert!(bye200, "no 200 for BYE");
    assert!(
        decoded_a.len() > 3200,
        "no decrypted audio returned to the plain caller (decoded={})",
        decoded_a.len()
    );

    let (acks, decoded_b) = timeout(Duration::from_secs(20), callee_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(acks, 1, "callee must receive ACK");
    assert!(
        decoded_b.len() > 1200,
        "callee decoded too little audio: {}",
        decoded_b.len()
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = drain_cdr_until_call_ended(&mut cdr_rx).await;
    assert_cdr_trail(&events);
}
