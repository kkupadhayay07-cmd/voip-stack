//! Leg-B data channels (RFC 8841 offerer side) — the mirror policy end to
//! end: a WebRTC caller offers audio + m=application; the B2BUA answers
//! both on leg A AND mirrors the application m-line into its leg-B offer; a
//! WebRTC callee accepts it. Both data channels come up over their own
//! DTLS associations — leg A: B2BUA engine = DTLS client (even streams);
//! leg B: B2BUA engine = DTLS server (the callee is active → client →
//! initiator, even streams) — while SRTP audio bridges caller↔callee, and
//! the CDR trail completes.

#[path = "webrtc_leg_b_datachan/common.rs"]
mod common;

use b2bua::CdrEvent;
use common::*;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leg_b_datachannel_mirror_loopback() {
    init_log().await;
    let (tx, mut cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let callee_sip = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let callee_addr = callee_sip.local_addr().unwrap();
    let engine_addr = spawn_engine(callee_addr, tx).await;

    let callee_task = tokio::spawn(run_webrtc_callee_dc(callee_sip, "active", DcMode::Accept));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let caller = run_webrtc_caller_dc(engine_addr, "webrtc-leg-b-datachan").await;

    // Leg A answer: audio + application both accepted, sctp-port echoed.
    let answer = &caller.answer_sdp;
    let app_line = answer
        .lines()
        .find(|l| l.starts_with("m=application "))
        .expect("leg A answer must carry the application m-line");
    let parts: Vec<&str> = app_line.split_whitespace().collect();
    assert_eq!(parts[2], "UDP/DTLS/SCTP", "proto mirrored: {app_line}");
    let app_port: u16 = parts[1].parse().unwrap();
    assert!(app_port > 0, "data channel must be accepted on leg A");
    assert!(answer.contains("a=sctp-port:5000\r\n"), "{answer}");
    assert!(answer.contains("a=max-message-size:262144\r\n"), "{answer}");
    // parse → serialize → parse stays a fixed point.
    let rt = sdp::parse::parse(answer).unwrap();
    assert_eq!(rt.serialize(), *answer, "answer roundtrip not stable");

    // Leg A channel: the probe message echoed by the leg-A engine.
    assert!(caller.dc_up, "leg A SCTP association never established");
    assert_eq!(
        caller.echoes,
        vec![(51u32, b"leg-a-dc".to_vec())],
        "leg A echo must preserve PPID and payload"
    );
    assert!(
        caller.decoded_len > 400,
        "SRTP audio must still flow on leg A: {}",
        caller.decoded_len
    );
    assert!(caller.bye200, "no 200 for BYE");

    // Leg B: the callee saw the mirrored offer (asserted in the harness),
    // accepted it, and both messages echo byte-for-byte with PPIDs.
    let callee = timeout(Duration::from_secs(25), callee_task)
        .await
        .unwrap()
        .unwrap();
    assert!(callee.dc_up, "leg B SCTP association never established");
    let tests = [
        (51u32, b"leg-b-dc-hello".to_vec()),
        (53, (0..2000).map(|i| (i % 251) as u8).collect::<Vec<u8>>()),
    ];
    assert_eq!(
        callee.echoes.len(),
        tests.len(),
        "all leg B messages must echo back: {:?}",
        callee.echoes
    );
    for ((ppid, data), (epid, edata)) in callee.echoes.iter().zip(tests.iter()) {
        assert_eq!(ppid, epid, "leg B echo preserves the PPID");
        assert_eq!(
            data, edata,
            "leg B echo preserves the payload byte-for-byte"
        );
    }
    assert!(
        callee.decoded_len > 1200,
        "callee decoded too little audio: {}",
        callee.decoded_len
    );
    assert!(callee.got_bye, "callee never received the BYE");

    // CDR trail completes.
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
            *frames_a_to_b >= 15,
            "expected ≥ 15 bridged frames, got {frames_a_to_b}"
        );
        assert!(*duration_ms > 0);
    } else {
        panic!("no CALL_ENDED CDR");
    }
}
