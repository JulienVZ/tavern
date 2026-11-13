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

mod common;

use common::{DATABASE_URL_VAR, TestApp};
use tavern_protocol::rest::{ComponentStatus, HealthResponse, VersionResponse};
use tavern_server::db;

/// Starts the application on an ephemeral port and returns its address.
async fn spawn_app() -> std::net::SocketAddr {
    TestApp::spawn().await.addr
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

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn wrong_database_password_is_explained() {
    let mut url = reqwest::Url::parse(&std::env::var(DATABASE_URL_VAR).unwrap()).unwrap();
    url.set_password(Some("not-the-password")).unwrap();

    let error = db::connect(url.as_str(), 1).await.unwrap_err();

    assert!(
        matches!(error, db::ConnectError::AuthenticationFailed),
        "{error:?}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn openapi_document_lists_the_routes() {
    let addr = spawn_app().await;

    let document: serde_json::Value = reqwest::get(format!("http://{addr}/v1/openapi.json"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let paths = document["paths"].as_object().unwrap();
    for path in [
        "/health",
        "/v1/auth/login/start",
        "/v1/devices",
        "/v1/admin/invites",
    ] {
        assert!(
            paths.contains_key(path),
            "{path} is missing from the OpenAPI document"
        );
    }
    assert!(document["components"]["schemas"]["LoginGrant"].is_object());
}
