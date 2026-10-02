//! WebRTC leg B (offerer side, RFC 5763) — ACTIVE answer:
//! the callee answers `setup:active` (DTLS client), so the B2BUA is the DTLS
//! SERVER. Plain PCMU caller → B2BUA (`webrtc` route) → mini WebRTC callee;
//! audio crosses the SRTP leg both ways and the CDR trail completes.

#[path = "webrtc_leg_b/common.rs"]
mod common;

use b2bua::CdrEvent;
use common::*;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leg_b_webrtc_active_answer_loopback() {
    init_log().await;
    let (tx, mut cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let callee_sip = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let callee_addr = callee_sip.local_addr().unwrap();
    let engine_addr = spawn_engine(callee_addr, tx).await;

    let callee_task = tokio::spawn(run_webrtc_callee(callee_sip, "active"));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (decoded_a, bye200) = run_plain_caller(engine_addr, "webrtc-leg-b-active").await;
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
    if let Some(CdrEvent::CallEnded {
        frames_a_to_b,
        duration_ms,
        ..
    }) = events
        .iter()
        .find(|e| matches!(e, CdrEvent::CallEnded { .. }))
    {
        assert!(
            *frames_a_to_b >= 30,
            "expected ≥ 30 bridged frames, got {frames_a_to_b}"
        );
        assert!(*duration_ms > 0);
    } else {
        panic!("no CALL_ENDED CDR");
    }
}
