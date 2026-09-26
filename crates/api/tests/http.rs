//! HTTP integration tests via axum's oneshot test utilities.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use cdr::{CallRecordBuilder, CdrStore, Direction};
use dialer::{Campaign, Dialer, PacingMode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use api::build_router;

async fn test_app() -> Router {
    let cdrs = CdrStore::new(100);
    // Seed two records.
    cdrs.insert(
        CallRecordBuilder::new(Direction::Outbound, "sip:a@x", "sip:b@y")
            .a_call_id("ac-1")
            .campaign("camp-1")
            .finish(200, false, 42),
    )
    .await;
    cdrs.insert(
        CallRecordBuilder::new(Direction::Outbound, "sip:a@x", "sip:c@y")
            .a_call_id("ac-2")
            .campaign("camp-1")
            .finish(486, false, 0),
    )
    .await;

    let mut dialer = Dialer::new(cdrs.clone());
    dialer.add_campaign(Campaign::new(
        "camp-1",
        PacingMode::Progressive,
        vec!["5550001".into()],
    ));
    let state = api::new_state(cdrs, dialer);
    build_router(state)
}

#[tokio::test]
async fn health_and_ready() {
    let app = test_app().await;
    let resp = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn metrics_endpoint_prometheus_format() {
    let app = test_app().await;
    let resp = app
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("# TYPE voip_calls_answered_total counter"));
}

#[tokio::test]
async fn cdr_listing_and_single_fetch() {
    let app = test_app().await;
    // List all.
    let resp = app
        .clone()
        .oneshot(Request::get("/cdrs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let arr: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(arr.as_array().unwrap().len(), 2);

    // Filter by disposition.
    let resp = app
        .clone()
        .oneshot(
            Request::get("/cdrs?disposition=busy&campaign=camp-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let arr: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(arr.as_array().unwrap().len(), 1);
    assert_eq!(arr[0]["a_call_id"], "ac-2");

    // Single record by id.
    let id = arr[0]["id"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/cdrs/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Unknown id → 404.
    let resp = app
        .oneshot(
            Request::get("/cdrs/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn campaign_stats_endpoint() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::get("/campaigns/camp-1/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["total"], 2);
    assert_eq!(v["answered"], 1);
    assert!((v["answer_rate"].as_f64().unwrap() - 0.5).abs() < 1e-9);
}

#[tokio::test]
async fn campaign_creation_and_pacing() {
    let app = test_app().await;
    let resp = app
        .clone()
        .oneshot(
            Request::post("/campaigns")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "id": "camp-2",
                        "mode": "predictive",
                        "caller_ids": ["5551000", "5551001"],
                        "max_attempts": 4
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Pacing: predictive with agents but at abandon limit → blocked reason.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/campaigns/camp-2/dialer/pace")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "agents_ready": 5,
                        "agents_busy": 0,
                        "avg_talk_secs": 60.0,
                        "avg_ring_secs": 10.0,
                        "utc_hour": 12
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Predictive with 5 idle agents, no abandonment history: overdial is
    // computed then capped at 3x idle agents = 15.
    assert_eq!(v["lines_to_dial"], 15);
    assert_eq!(v["reason"], "predictive");
}

#[tokio::test]
async fn bad_mode_rejected() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::post("/campaigns")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"id": "x", "mode": "banana", "caller_ids": []}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
