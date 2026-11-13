// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health and version endpoints.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use tavern_protocol::rest::{
    B64, ComponentStatus, GatewayVersions, HealthResponse, VersionResponse,
};
use tavern_protocol::{GATEWAY_MAJOR_VERSION, GATEWAY_MINOR_VERSION};

use crate::{AppState, db};

/// `GET /health`: 200 when the server and its database work, 503 otherwise.
#[utoipa::path(
    get,
    path = "/health",
    tag = "system",
    responses(
        (status = 200, body = HealthResponse),
        (status = 503, body = HealthResponse)
    )
)]
pub(crate) async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
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
#[utoipa::path(get, path = "/version", tag = "system", responses((status = 200, body = VersionResponse)))]
pub(crate) async fn version(State(state): State<AppState>) -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "tavern".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        gateway: GatewayVersions {
            min_major: GATEWAY_MAJOR_VERSION,
            max_major: GATEWAY_MAJOR_VERSION,
            minor: GATEWAY_MINOR_VERSION,
        },
        mls_external_sender_key: B64::from(state.secrets.external_sender.public_bytes()),
        source_url: state.settings.source_url.clone(),
    })
}
