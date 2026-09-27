//! # api
//!
//! Control plane for the VoIP stack: REST + WebSocket + Prometheus metrics.
//!
//! - `GET  /healthz` — liveness
//! - `GET  /readyz`  — readiness (store reachable)
//! - `GET  /metrics` — Prometheus exposition format
//! - `GET  /cdrs`    — query CDRs (`?campaign=&disposition=&limit=`)
//! - `GET  /cdrs/{id}` — single CDR
//! - `GET  /campaigns/{id}/stats` — dialer aggregates
//! - `POST /campaigns/{id}/dialer/pace` — recompute pacing decision
//! - `WS   /ws` — event stream (call states) + JSON commands (ping)
//!
//! The state is shared via `Arc<AppState>` so the service binary can wire
//! the same stores the engines use.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cdr::{CdrQuery, CdrStore, Direction, Disposition};
use dialer::{Campaign, Dialer, LiveStats};
use serde::Deserialize;
use tokio::sync::RwLock;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub cdrs: CdrStore,
    pub dialer: Arc<RwLock<Dialer>>,
    pub metrics: Arc<Metrics>,
    pub started: std::time::Instant,
}

/// Prometheus counters/gauges (hand-rolled exposition).
#[derive(Debug, Default)]
pub struct Metrics {
    pub calls_inbound_total: AtomicU64,
    pub calls_outbound_total: AtomicU64,
    pub calls_answered_total: AtomicU64,
    pub calls_failed_total: AtomicU64,
    pub ws_clients_connected: AtomicU64,
    pub http_requests_total: AtomicU64,
}

impl Metrics {
    fn render(&self) -> String {
        let mut s = String::with_capacity(1024);
        let counters: [(&str, &str, &AtomicU64); 6] = [
            (
                "voip_calls_inbound_total",
                "Inbound calls received",
                &self.calls_inbound_total,
            ),
            (
                "voip_calls_outbound_total",
                "Outbound calls originated",
                &self.calls_outbound_total,
            ),
            (
                "voip_calls_answered_total",
                "Calls answered",
                &self.calls_answered_total,
            ),
            (
                "voip_calls_failed_total",
                "Calls failed or abandoned",
                &self.calls_failed_total,
            ),
            (
                "voip_ws_clients_connected",
                "WebSocket control clients",
                &self.ws_clients_connected,
            ),
            (
                "voip_http_requests_total",
                "HTTP requests served",
                &self.http_requests_total,
            ),
        ];
        for (name, help, counter) in counters {
            s.push_str(&format!("# HELP {name} {help}\n"));
            s.push_str(&format!("# TYPE {name} counter\n"));
            s.push_str(&format!("{name} {}\n", counter.load(Ordering::Relaxed)));
        }
        s
    }
}

/// Query params for GET /cdrs.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CdrQueryParams {
    pub campaign: Option<String>,
    pub disposition: Option<String>,
    pub direction: Option<String>,
    pub min_talk_secs: Option<u64>,
    pub limit: Option<usize>,
}

impl CdrQueryParams {
    fn into_query(self) -> Result<CdrQuery, String> {
        let disposition = match self.disposition.as_deref() {
            None => None,
            Some("answered") => Some(Disposition::Answered),
            Some("busy") => Some(Disposition::Busy),
            Some("no_answer") => Some(Disposition::NoAnswer),
            Some("rejected") => Some(Disposition::Rejected),
            Some("failed") => Some(Disposition::Failed),
            Some("canceled") => Some(Disposition::Canceled),
            Some("blocked") => Some(Disposition::Blocked),
            Some(other) => return Err(format!("unknown disposition '{other}'")),
        };
        let direction = match self.direction.as_deref() {
            None => None,
            Some("inbound") => Some(Direction::Inbound),
            Some("outbound") => Some(Direction::Outbound),
            Some(other) => return Err(format!("unknown direction '{other}'")),
        };
        Ok(CdrQuery {
            campaign_id: self.campaign,
            disposition,
            direction,
            min_talk_secs: self.min_talk_secs,
            limit: self.limit,
        })
    }
}

/// Error → HTTP response mapping.
pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = Json(serde_json::json!({ "error": self.1 })).into_response();
        *resp.status_mut() = self.0;
        resp
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<AppState>) -> ApiResult<&'static str> {
    // A cheap round-trip through the store proves the runtime is sound.
    let _ = state.cdrs.query(&CdrQuery::default()).await;
    Ok("ready")
}

async fn metrics(State(state): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
        .into_response()
}

async fn list_cdrs(
    State(state): State<AppState>,
    Query(params): Query<CdrQueryParams>,
) -> ApiResult<Json<serde_json::Value>> {
    state
        .metrics
        .http_requests_total
        .fetch_add(1, Ordering::Relaxed);
    let query = params
        .into_query()
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    let records = state.cdrs.query(&query).await;
    Ok(Json(serde_json::to_value(&records).unwrap_or_default()))
}

async fn get_cdr(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    match state.cdrs.get(&id).await {
        Some(rec) => Ok(Json(serde_json::to_value(&rec).unwrap_or_default())),
        None => Err(ApiError(StatusCode::NOT_FOUND, "cdr not found".into())),
    }
}

async fn campaign_stats(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let stats = state.cdrs.stats(Some(&id)).await;
    Ok(Json(serde_json::to_value(stats).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
pub struct PaceRequest {
    pub agents_ready: Option<usize>,
    pub agents_busy: Option<usize>,
    pub lines_ringing: Option<usize>,
    pub avg_talk_secs: Option<f64>,
    pub avg_ring_secs: Option<f64>,
    pub utc_hour: Option<u8>,
}

async fn pace_campaign(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PaceRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let stats = LiveStats {
        agents_ready: req.agents_ready.unwrap_or(0),
        agents_busy: req.agents_busy.unwrap_or(0),
        lines_ringing: req.lines_ringing.unwrap_or(0),
        dialed_recent: 0,
        answered_recent: 0,
        avg_talk_secs: req.avg_talk_secs.unwrap_or(0.0),
        avg_ring_secs: req.avg_ring_secs.unwrap_or(0.0),
    };
    let dialer = state.dialer.read().await;
    let decision = dialer.pace(&id, &stats, req.utc_hour.unwrap_or(12));
    Ok(Json(serde_json::json!({
        "campaign": id,
        "lines_to_dial": decision.lines_to_dial,
        "reason": decision.reason,
    })))
}

/// Add a campaign (JSON body mirrors dialer::Campaign essentials).
#[derive(Debug, Deserialize)]
pub struct CreateCampaign {
    pub id: String,
    pub mode: String,
    pub caller_ids: Vec<String>,
    pub max_attempts: Option<u32>,
}

async fn create_campaign(
    State(state): State<AppState>,
    Json(body): Json<CreateCampaign>,
) -> ApiResult<Json<serde_json::Value>> {
    let mode = match body.mode.as_str() {
        "preview" => dialer::PacingMode::Preview,
        "progressive" => dialer::PacingMode::Progressive,
        "predictive" => dialer::PacingMode::Predictive,
        other => {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!("unknown mode '{other}'"),
            ))
        }
    };
    let mut campaign = Campaign::new(&body.id, mode, body.caller_ids);
    if let Some(ma) = body.max_attempts {
        campaign.max_attempts = ma;
    }
    let mut dialer = state.dialer.write().await;
    dialer.add_campaign(campaign);
    Ok(Json(serde_json::json!({ "created": body.id })))
}

/// WebSocket control channel: pushes JSON events, accepts "ping".
async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    state
        .metrics
        .ws_clients_connected
        .fetch_add(1, Ordering::Relaxed);
    ws.on_upgrade(|socket| ws_loop(socket, state))
}

async fn ws_loop(mut socket: WebSocket, state: AppState) {
    let _ = socket
        .send(Message::Text(
            serde_json::json!({
                "type": "hello",
                "uptime_secs": state.started.elapsed().as_secs()
            })
            .to_string()
            .into(),
        ))
        .await;
    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(t) => {
                let text = t.as_str();
                let reply = if text.contains("ping") {
                    serde_json::json!({ "type": "pong" }).to_string()
                } else {
                    serde_json::json!({ "type": "echo", "received": text }).to_string()
                };
                if socket.send(Message::Text(reply.into())).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    state
        .metrics
        .ws_clients_connected
        .fetch_sub(1, Ordering::Relaxed);
}

/// Build the router with shared state.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/cdrs", get(list_cdrs))
        .route("/cdrs/{id}", get(get_cdr))
        .route("/campaigns/{id}/stats", get(campaign_stats))
        .route("/campaigns/{id}/dialer/pace", post(pace_campaign))
        .route("/campaigns", post(create_campaign))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

/// Convenience: assemble the full application state from stores.
pub fn new_state(cdrs: CdrStore, dialer: Dialer) -> AppState {
    AppState {
        cdrs,
        dialer: Arc::new(RwLock::new(dialer)),
        metrics: Arc::new(Metrics::default()),
        started: std::time::Instant::now(),
    }
}

/// Correlation helper for callers assembling meta maps.
pub type MetaMap = HashMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_exposition_format() {
        let m = Metrics::default();
        m.calls_answered_total.fetch_add(3, Ordering::Relaxed);
        let text = m.render();
        assert!(text.contains("# HELP voip_calls_answered_total"));
        assert!(text.contains("voip_calls_answered_total 3"));
    }

    #[test]
    fn query_params_map_to_cdr_query() {
        let params = CdrQueryParams {
            campaign: Some("c1".into()),
            disposition: Some("answered".into()),
            direction: Some("outbound".into()),
            min_talk_secs: Some(5),
            limit: Some(10),
        };
        let q = params.into_query().unwrap();
        assert_eq!(q.campaign_id.as_deref(), Some("c1"));
        assert_eq!(q.disposition, Some(Disposition::Answered));
        assert_eq!(q.direction, Some(Direction::Outbound));
        assert_eq!(q.limit, Some(10));
        assert!(CdrQueryParams {
            disposition: Some("banana".into()),
            ..Default::default()
        }
        .into_query()
        .is_err());
    }
}
