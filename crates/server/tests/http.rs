// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests against a real PostgreSQL database.
//!
//! They are ignored by default because they need a database. Run them with:
//!
//! ```sh
//! TAVERN_TEST_DATABASE_URL=postgres://tavern:tavern@localhost:5432/tavern \
//!     cargo test -p tavern-server -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers panic on set-up failure"
)]

use std::net::SocketAddr;

use tavern_protocol::rest::{ComponentStatus, HealthResponse, VersionResponse};
use tavern_server::{AppState, app, db};
use tokio::net::TcpListener;

const DATABASE_URL_VAR: &str = "TAVERN_TEST_DATABASE_URL";

/// Starts the application on an ephemeral port and returns its address.
async fn spawn_app() -> SocketAddr {
    let database_url = std::env::var(DATABASE_URL_VAR)
        .unwrap_or_else(|_| panic!("{DATABASE_URL_VAR} must be set to run this test"));

    let pool = db::connect(&database_url, 2)
        .await
        .expect("database must be reachable");
    db::migrate(&pool).await.expect("migrations must apply");

    let state = AppState {
        db: pool,
        source_url: Some("https://example.org/source".to_owned()),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    addr
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn health_reports_ok_with_a_working_database() {
    let addr = spawn_app().await;

    let response = reqwest::get(format!("http://{addr}/health")).await.unwrap();

    assert_eq!(response.status(), 200);
    let body: HealthResponse = response.json().await.unwrap();
    assert_eq!(body.status, ComponentStatus::Ok);
    assert_eq!(body.database, ComponentStatus::Ok);
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn version_reports_software_and_protocol_versions() {
    let addr = spawn_app().await;

    let response = reqwest::get(format!("http://{addr}/version"))
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let body: VersionResponse = response.json().await.unwrap();
    assert_eq!(body.name, "tavern");
    assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        body.gateway.max_major,
        tavern_protocol::GATEWAY_MAJOR_VERSION
    );
    assert_eq!(
        body.source_url.as_deref(),
        Some("https://example.org/source")
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn migrations_can_run_twice() {
    let database_url = std::env::var(DATABASE_URL_VAR).unwrap();
    let pool = db::connect(&database_url, 1).await.unwrap();

    db::migrate(&pool).await.unwrap();
    db::migrate(&pool).await.unwrap();
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn unknown_routes_return_404() {
    let addr = spawn_app().await;

    let response = reqwest::get(format!("http://{addr}/nope")).await.unwrap();

    assert_eq!(response.status(), 404);
}
