// SPDX-License-Identifier: AGPL-3.0-or-later

//! A panic caused by a request fails that request, never the server (ADR
//! 0019, section 18): a route that panics, under the layers every route of
//! the server runs under, answers 500 INTERNAL, and the server answers the
//! next requests. The log says where the panic happened, not its message.
//!
//! Needs no database: the pool is never used.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use sqlx::postgres::PgPoolOptions;
use tavern_protocol::rest::{ErrorBody, ErrorCode};
use tavern_server::{AppState, Settings, panics, with_layers};
use tracing_subscriber::fmt::MakeWriter;

/// Collects what the subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

// Single-threaded runtime: the server's tasks run on the test's thread,
// where the capturing subscriber is installed.
#[tokio::test]
async fn a_handler_that_panics_answers_500_and_the_server_goes_on() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    panics::install_hook();

    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://tavern@127.0.0.1:9/never_used_test")
        .unwrap();
    let state = AppState::new(
        pool,
        common::test_secrets(),
        Settings::new(None, false, Duration::from_secs(60)),
    );
    let routes = Router::new()
        .route(
            "/panics",
            get(|| async { panic!("a message quoting the request: PANIC-MARKER") }),
        )
        .route("/answers", get(|| async { StatusCode::NO_CONTENT }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = with_layers(routes, state);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::new();

    for _ in 0..3 {
        let response = client
            .get(format!("http://{addr}/panics"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: ErrorBody = response.json().await.unwrap();
        assert_eq!(body.code, ErrorCode::Internal);
        assert!(!body.message.contains("PANIC-MARKER"));
    }
    let response = client
        .get(format!("http://{addr}/answers"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        log.matches("panic; its message is not logged").count(),
        3,
        "{log}"
    );
    assert!(
        log.contains("location=crates/server/tests/panics.rs:"),
        "{log}"
    );
    assert!(log.contains("status=500"), "{log}");
    assert!(log.contains("status=204"), "{log}");
    assert!(!log.contains("PANIC-MARKER"), "{log}");
}
