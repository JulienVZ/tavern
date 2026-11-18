// SPDX-License-Identifier: AGPL-3.0-or-later

//! A panic caused by a request fails that request, never the server (ADR
//! 0019, section 18).
//!
//! The server is built with `panic = "unwind"` (the `server` profile of the
//! workspace; `main.rs` refuses to compile otherwise): a panic unwinds the
//! task it happened in, never the process. On top of that, each REST request
//! runs under [`layer`], and gets `500 INTERNAL`; each gateway frame is
//! handled under [`guard`], and its connection closes with 1011. Blocking
//! work runs under [`blocking`], the only way the server runs it
//! (`crates/server/clippy.toml`). The panic hook ([`install_hook`]) logs
//! where a panic happened, never its message: a message can quote what the
//! request carried. Nothing else logs it either: a `JoinError`'s `Display`
//! quotes it, so none is ever logged that way.

use std::any::Any;
use std::panic::AssertUnwindSafe;

use axum::response::{IntoResponse, Response};
use futures_util::FutureExt as _;
use tavern_protocol::rest::ErrorCode;
use tower_http::catch_panic::CatchPanicLayer;

use crate::error::{ApiError, ApiResult};

/// Replaces the default panic hook, which prints the panic's message: this
/// one logs its location (file and line) only.
pub fn install_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |at| format!("{}:{}", at.file(), at.line()),
        );
        tracing::error!(%location, "panic; its message is not logged");
    }));
}

type PanicResponse = fn(Box<dyn Any + Send + 'static>) -> Response;

fn internal_error(_panic: Box<dyn Any + Send + 'static>) -> Response {
    // Logged by the hook and by the request log (status 500); the client
    // learns nothing more.
    ApiError::new(ErrorCode::Internal, "internal error").into_response()
}

/// The layer that answers `500 INTERNAL`, in the API's error format, to a
/// request whose handler panicked.
pub fn layer() -> CatchPanicLayer<PanicResponse> {
    CatchPanicLayer::custom(internal_error as PanicResponse)
}

/// Runs blocking work (decoding, checking signatures) off the async threads,
/// like `tokio::task::spawn_blocking`, and turns a panic in it into an
/// internal error. What is logged is that the task panicked, or was
/// cancelled, and its id: never the panic's message.
#[allow(
    clippy::disallowed_methods,
    reason = "the one place the server calls spawn_blocking"
)]
pub async fn blocking<T, F>(work: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|error| {
        let task = error.id();
        if error.is_panic() {
            tracing::error!(%task, "a blocking task panicked; its message is not logged");
        } else {
            tracing::error!(%task, "a blocking task was cancelled");
        }
        ApiError::new(ErrorCode::Internal, "internal error")
    })
}

/// A future panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Panicked;

/// Runs `future`, and returns [`Panicked`] instead of unwinding further if
/// it panics. What the future held is dropped: the caller must not reuse
/// state it may have left half changed. The gateway ends the connection.
pub async fn guard<F: Future>(future: F) -> Result<F::Output, Panicked> {
    AssertUnwindSafe(future)
        .catch_unwind()
        .await
        .map_err(|_| Panicked)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Single-threaded runtime: the awaiting task runs on the test's thread,
    // where the capturing subscriber is installed.
    #[tokio::test]
    async fn a_panic_in_blocking_work_is_an_internal_error_logged_without_its_message() {
        let (captured, _guard) = crate::test_log::capture(tracing::Level::INFO);

        assert_eq!(blocking(|| 7).await, Ok(7));
        let failed = blocking(|| {
            if blocking_input() {
                panic!("a message quoting the input: PANIC-MARKER");
            }
        })
        .await
        .unwrap_err();

        assert_eq!(failed.code, ErrorCode::Internal);
        assert!(!failed.message.contains("PANIC-MARKER"));
        let log = captured.text();
        assert!(
            log.contains("a blocking task panicked; its message is not logged"),
            "{log}"
        );
        assert!(log.contains("task="), "{log}");
        assert!(!log.contains("PANIC-MARKER"), "{log}");
    }

    fn blocking_input() -> bool {
        std::hint::black_box(true)
    }

    #[tokio::test]
    async fn a_guarded_panic_is_returned_not_unwound() {
        assert_eq!(guard(async { 7 }).await, Ok(7));
        let panicked = guard(async {
            if guard(async { 1 }).await == Ok(1) {
                panic!("from a request");
            }
        })
        .await;
        assert_eq!(panicked, Err(Panicked));
    }
}
