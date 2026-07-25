//! Liveness and readiness.
//!
//! Health output is deliberately minimal: version and status only. Dependency
//! detail, build paths, and error strings belong in logs, not in an endpoint
//! that is usually left unauthenticated.

use axum::{Json, extract::State, http::StatusCode};

use crate::{api::dto::HealthResponse, state::AppState};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Liveness: the process is up and the runtime is responsive.
pub async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: VERSION,
    })
}

/// Readiness: dependencies are reachable, so it is safe to route traffic here.
pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    match state.health().ping().await {
        Ok(_) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ready",
                version: VERSION,
            }),
        ),
        Err(err) => {
            tracing::error!(error = %err, "readiness probe failed: database unreachable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "unavailable",
                    version: VERSION,
                }),
            )
        }
    }
}
