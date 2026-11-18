// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests against a real PostgreSQL database.
//!
//! They are ignored by default because they need a database. Run them with:
//!
//! ```sh
//! TAVERN_TEST_DATABASE_URL=postgres://tavern:tavern@localhost:5432/tavern_test \
//!     cargo test -p tavern-server -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers panic on set-up failure"
)]

mod common;

use common::{TestApp, database_url};
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
    let database_url = database_url();
    let pool = db::connect(&database_url, 1).await.unwrap();

    db::migrate(&pool).await.unwrap();
    db::migrate(&pool).await.unwrap();
}

/// Every error is in the API's own format, so that a client never has to
/// guess. In particular an unknown route says so with a dedicated code: a
/// client built for a newer server then tells its user that the instance is
/// too old, instead of "this is not a Tavern instance".
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn unknown_routes_and_methods_answer_with_a_coded_error() {
    use tavern_protocol::rest::{ErrorBody, ErrorCode};

    let addr = spawn_app().await;
    let client = reqwest::Client::new();

    for request in [
        client.get(format!("http://{addr}/nope")),
        client
            .post(format!("http://{addr}/v1/auth/some/future/route"))
            .json(&()),
        // A known path with a method it does not have.
        client.delete(format!("http://{addr}/health")),
        client.get(format!("http://{addr}/v1/auth/login/start")),
    ] {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 404);
        let body: ErrorBody = response.json().await.unwrap();
        assert_eq!(body.code, ErrorCode::UnknownEndpoint);
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn malformed_bodies_answer_with_a_coded_error() {
    use tavern_protocol::rest::{ErrorBody, ErrorCode};

    let addr = spawn_app().await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/v1/auth/login/start");

    for request in [
        client.post(&url).json(&serde_json::json!({})),
        client
            .post(&url)
            .json(&serde_json::json!({ "handle": 4, "credential_request": "AA" })),
        client
            .post(&url)
            .header("content-type", "application/json")
            .body("{not json"),
        client.post(&url).body("handle=alice"),
    ] {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 400);
        let body: ErrorBody = response.json().await.unwrap();
        assert_eq!(body.code, ErrorCode::InvalidArgument);
    }

    // Too large for the REST body limit.
    let huge = serde_json::json!({ "handle": "a".repeat(200_000), "credential_request": "AA" });
    let response = client.post(&url).json(&huge).send().await.unwrap();
    assert_eq!(response.status(), 413);
    let body: ErrorBody = response.json().await.unwrap();
    assert_eq!(body.code, ErrorCode::PayloadTooLarge);
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn wrong_database_password_is_explained() {
    let mut url = reqwest::Url::parse(&database_url()).unwrap();
    url.set_password(Some("not-the-password")).unwrap();

    let error = db::connect(url.as_str(), 1).await.unwrap_err();

    assert!(
        matches!(error, db::ConnectError::AuthenticationFailed),
        "{error:?}"
    );
}

/// The routes of REST 1.4, frozen (1.4 added friends and blocks). If this
/// test fails because a route was added or removed, update the list **and
/// increment `tavern_protocol::REST_MINOR_VERSION`**: that number is how a
/// client tells its user that an instance is older than the client.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_route_list_matches_the_announced_rest_version() {
    const REST_MINOR_OF_THIS_LIST: u32 = 4;
    const ROUTES: &[&str] = &[
        "/health",
        "/v1/account/password/finish",
        "/v1/account/password/start",
        "/v1/account/recovery-key",
        "/v1/account/totp/confirm",
        "/v1/account/totp/disable",
        "/v1/account/totp/enable",
        "/v1/admin/invites",
        "/v1/admin/invites/{invite_id}",
        "/v1/admin/users",
        "/v1/admin/users/{user_id}/disable",
        "/v1/admin/users/{user_id}/enable",
        "/v1/admin/users/{user_id}/totp/disable",
        "/v1/auth/login/finish",
        "/v1/auth/login/start",
        "/v1/auth/login/totp",
        "/v1/auth/logout",
        "/v1/auth/reauth/finish",
        "/v1/auth/reauth/start",
        "/v1/auth/recover/finish",
        "/v1/auth/recover/start",
        "/v1/auth/register/finish",
        "/v1/auth/register/start",
        "/v1/blocks/{user_id}",
        "/v1/devices",
        "/v1/devices/me/key-packages",
        "/v1/devices/me/key-packages/count",
        "/v1/devices/{device_id}",
        "/v1/devices/{device_id}/session",
        "/v1/friends",
        "/v1/friends/requests",
        "/v1/friends/requests/{user_id}",
        "/v1/friends/requests/{user_id}/accept",
        "/v1/friends/{user_id}",
        "/v1/users/me",
        "/v1/users/{user_id}/key-packages/claim",
        "/version",
    ];
    let addr = spawn_app().await;

    let document: serde_json::Value = reqwest::get(format!("http://{addr}/v1/openapi.json"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut paths: Vec<&str> = document["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    paths.sort_unstable();

    assert_eq!(
        paths, ROUTES,
        "the route list changed: see the comment on this test"
    );
    assert_eq!(
        tavern_protocol::REST_MINOR_VERSION,
        REST_MINOR_OF_THIS_LIST,
        "REST_MINOR_VERSION changed: update the frozen route list with it"
    );
    assert!(document["components"]["schemas"]["LoginGrant"].is_object());
    assert!(
        document["components"]["schemas"]["SessionResponse"]["properties"]["local_store_share"]
            .is_object()
    );

    let version: VersionResponse = reqwest::get(format!("http://{addr}/version"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(version.rest.major, tavern_protocol::REST_MAJOR_VERSION);
    assert_eq!(version.rest.minor, tavern_protocol::REST_MINOR_VERSION);
}
