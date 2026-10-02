//! Leg-B data channels — the graceful-decline path: the WebRTC callee
//! rejects the offered `m=application` m-line the RFC 3264 §6 way (port 0)
//! while accepting the audio. The B2BUA must bridge the call audio-only:
//! no data-channel engine on leg B, no teardown, normal CDR trail.

#[path = "webrtc_leg_b_datachan/common.rs"]
mod common;

use b2bua::CdrEvent;
use common::*;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leg_b_datachannel_decline_keeps_audio_alive() {
    init_log().await;
    let (tx, mut cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let callee_sip = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let callee_addr = callee_sip.local_addr().unwrap();
    let engine_addr = spawn_engine(callee_addr, tx).await;

    let callee_task = tokio::spawn(run_webrtc_callee_dc(callee_sip, "active", DcMode::Reject));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The caller still offers audio + application (so the mirror policy
    // offers the m-line downstream), and exercises the leg-A channel —
    // that one is unaffected by the callee's decline.
    let caller = run_webrtc_caller_dc(engine_addr, "webrtc-leg-b-dc-reject").await;
    assert!(
        caller.answer_sdp.contains("m=application"),
        "{}",
        caller.answer_sdp
    );
    assert!(caller.dc_up, "leg A SCTP association never established");
    assert_eq!(
        caller.echoes,
        vec![(51u32, b"leg-a-dc".to_vec())],
        "leg A echo must still work"
    );
    assert!(caller.decoded_len > 400);
    assert!(caller.bye200, "no 200 for BYE");

    // The callee rejected the m-line (port 0): it never sees an SCTP INIT
    // (its dc_up stays false — no association was attempted on leg B), but
    // audio bridges normally and the call ends cleanly.
    let callee = timeout(Duration::from_secs(25), callee_task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !callee.dc_up,
        "no data-channel association may come up on a declined m-line"
    );
    assert!(
        callee.echoes.is_empty(),
        "no data may arrive on a declined m-line: {:?}",
        callee.echoes
    );
    assert!(
        callee.decoded_len > 1200,
        "callee decoded too little audio: {}",
        callee.decoded_len
    );
    assert!(callee.got_bye, "callee never received the BYE");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = drain_cdr_until_call_ended(&mut cdr_rx).await;
    assert_cdr_trail(&events);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, CdrEvent::CallEnded { .. })),
        "the call must end cleanly (audio-only leg B)"
    );
}
