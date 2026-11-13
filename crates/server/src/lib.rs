// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tavern instance server.
//!
//! At this stage (milestone M0) the server exposes `GET /health` and
//! `GET /version`, connects to PostgreSQL and applies migrations. It never
//! handles plaintext user content; see `docs/threat-model.md`.

#![forbid(unsafe_code)]

pub mod config;
pub mod db;
pub mod routes;
pub mod telemetry;

use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use sqlx::PgPool;
use tavern_protocol::DEFAULT_MAX_REST_BODY_BYTES;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Upper bound for handling one REST request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// State shared by all request handlers.
#[derive(Debug, Clone)]
pub struct AppState {
    /// PostgreSQL connection pool.
    pub db: PgPool,
    /// Public URL of this instance's source code.
    pub source_url: Option<String>,
}

/// Builds the HTTP application.
pub fn app(state: AppState) -> Router {
    routes::router()
        .layer(DefaultBodyLimit::max(DEFAULT_MAX_REST_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        // The default span records method, path and status only: no headers,
        // no bodies, no client address.
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
