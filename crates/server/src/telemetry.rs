// SPDX-License-Identifier: AGPL-3.0-or-later

//! Logging set-up.
//!
//! Logs stay on the host: nothing is sent to a third party. Secrets, tokens,
//! keys, ciphertext and plaintext must never be logged.

use std::io::IsTerminal;
use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::ParseError;

use crate::config::LogFormat;

/// Installs the global `tracing` subscriber.
///
/// `level` is a filter directive such as `info` or `tavern_server=debug,info`.
pub fn init(level: &str, format: LogFormat) -> Result<(), ParseError> {
    let filter = EnvFilter::builder().parse(level)?;
    // Colours only when a person is watching: container logs stay plain text.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal());

    match format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
    Ok(())
}

/// Route name logged for a request that matched no route.
const UNMATCHED: &str = "unmatched";

/// Route of the liveness check. The container health check calls it every
/// ten seconds: logged at `debug`, so that it does not drown the rest.
const HEALTH_ROUTE: &str = "/health";

/// Middleware: one `info` line per request, with the method, the route
/// template, the status and the duration. Calls to `/health` are logged at
/// `debug` instead.
///
/// The template (`/v1/devices/{device_id}`) is logged, never the URL: paths
/// carry identifiers and query strings can carry anything. A request that
/// matches no route is logged as `unmatched`, so that whatever a scanner
/// sends does not reach the logs. Headers, bodies, client addresses, handles
/// and tokens are not read here at all.
pub async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| UNMATCHED.to_owned(), |path| path.as_str().to_owned());
    let started = Instant::now();

    let response = next.run(request).await;

    let status = response.status().as_u16();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if route == HEALTH_ROUTE {
        tracing::debug!(%method, %route, status, duration_ms, "request");
    } else {
        tracing::info!(%method, %route, status, duration_ms, "request");
    }
    response
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex, PoisonError};

    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::post;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    /// Collects what the subscriber writes.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

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

    /// Runs `requests` against the router while capturing what is logged at
    /// `level` and above.
    fn capture(level: tracing::Level) -> (Captured, tracing::subscriber::DefaultGuard) {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .with_max_level(level)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (captured, guard)
    }

    /// Serves a router with the logging middleware and returns its address.
    async fn serve() -> std::net::SocketAddr {
        let app = Router::new()
            .route(
                "/v1/admin/users/{user_id}/totp/disable",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                HEALTH_ROUTE,
                axum::routing::get(|| async { StatusCode::OK }),
            )
            .layer(axum::middleware::from_fn(log_request));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    // Single-threaded runtime: the server task runs on the test's thread,
    // where the capturing subscriber is installed.
    #[tokio::test]
    async fn a_request_is_logged_by_its_route_template_and_nothing_personal() {
        let (captured, _guard) = capture(tracing::Level::INFO);
        let addr = serve().await;
        let client = reqwest::Client::new();

        let user = "0193a1c2-7b1e-7c3d-9f00-5a6b7c8d9e0f";
        let response = client
            .post(format!(
                "http://{addr}/v1/admin/users/{user}/totp/disable?handle=uma.secret"
            ))
            .bearer_auth("c2Vzc2lvbi10b2tlbg")
            .body("body-marker")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
        // No route: logged without the path that was asked for.
        let response = client
            .get(format!("http://{addr}/wp-admin/probe-marker"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);

        let log = captured.text();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "{log}");
        for expected in [
            "INFO",
            "method=POST",
            "route=/v1/admin/users/{user_id}/totp/disable",
            "status=204",
            "duration_ms=",
        ] {
            assert!(lines[0].contains(expected), "{expected} in {log}");
        }
        for expected in ["method=GET", "route=unmatched", "status=404"] {
            assert!(lines[1].contains(expected), "{expected} in {log}");
        }
        for forbidden in [
            user,
            "handle",
            "uma.secret",
            "c2Vzc2lvbi10b2tlbg",
            "body-marker",
            "probe-marker",
            "127.0.0.1",
            "authorization",
        ] {
            assert!(!log.contains(forbidden), "{forbidden} in {log}");
        }
    }

    #[tokio::test]
    async fn health_checks_are_logged_at_debug_only() {
        for (level, expected) in [(tracing::Level::INFO, 0), (tracing::Level::DEBUG, 1)] {
            let (captured, _guard) = capture(level);
            let addr = serve().await;
            let response = reqwest::get(format!("http://{addr}/health")).await.unwrap();
            assert_eq!(response.status(), 200);

            let log = captured.text();
            let lines = log.lines().filter(|line| line.contains("route=/health"));
            assert_eq!(lines.count(), expected, "{level}: {log}");
        }
    }
}
