// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP routes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use tavern_protocol::rest::{ComponentStatus, GatewayVersions, HealthResponse, VersionResponse};
use tavern_protocol::{GATEWAY_MAJOR_VERSION, GATEWAY_MINOR_VERSION};

use crate::{AppState, db};

/// Routes of the server, without middleware.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
}

/// `GET /health`: 200 when the server and its database work, 503 otherwise.
async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    if db::is_healthy(&state.db).await {
        let body = HealthResponse {
            status: ComponentStatus::Ok,
            database: ComponentStatus::Ok,
        };
        (StatusCode::OK, Json(body))
    } else {
        let body = HealthResponse {
            status: ComponentStatus::Unavailable,
            database: ComponentStatus::Unavailable,
        };
        (StatusCode::SERVICE_UNAVAILABLE, Json(body))
    }
}

/// `GET /version`: software and protocol versions of this instance.
async fn version(State(state): State<AppState>) -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "tavern".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        gateway: GatewayVersions {
            min_major: GATEWAY_MAJOR_VERSION,
            max_major: GATEWAY_MAJOR_VERSION,
            minor: GATEWAY_MINOR_VERSION,
        },
        source_url: state.source_url,
    })
}
