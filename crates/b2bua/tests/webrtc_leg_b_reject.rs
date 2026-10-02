//! WebRTC leg B (offerer side, RFC 5763) — downgrade rejection:
//! a `webrtc` route whose downstream answers PLAIN RTP/AVP releases the call
//! with 503 instead of degrading to plaintext (no AVP/SAVPF fallback).

#[path = "webrtc_leg_b/common.rs"]
mod common;

use common::*;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leg_b_webrtc_rejects_plain_answer() {
    init_log().await;
    let (tx, _cdr_rx) = tokio::sync::mpsc::unbounded_channel();
    let callee_sip = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let callee_addr = callee_sip.local_addr().unwrap();
    let engine_addr = spawn_engine(callee_addr, tx).await;

    let callee_task = tokio::spawn(run_plain_downgrade_callee(callee_sip));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let code = run_plain_caller_expect_503(engine_addr, "webrtc-leg-b-reject").await;
    assert_eq!(
        code, 503,
        "a plain answer on a webrtc route must release the call with 503"
    );
    // The downstream saw the ACK; the call is torn down (no BYE is required
    // after a 503 to leg A — the callee's socket just goes quiet).
    let _ = timeout(Duration::from_secs(10), callee_task).await;
}
