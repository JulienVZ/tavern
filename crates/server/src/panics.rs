// SPDX-License-Identifier: AGPL-3.0-or-later

//! A panic caused by a request fails that request, never the server (ADR
//! 0019, section 18).
//!
//! The server is built with `panic = "unwind"` (the `server` profile of the
//! workspace; `main.rs` refuses to compile otherwise): a panic unwinds the
//! task it happened in, never the process. On top of that, each REST request
//! runs under [`layer`], and gets `500 INTERNAL`; each gateway frame is
//! handled under [`guard`], and its connection closes with 1011. The panic
//! hook ([`install_hook`]) logs where a panic happened, never its message:
//! a message can quote what the request carried.

use std::any::Any;
use std::panic::AssertUnwindSafe;

use axum::response::{IntoResponse, Response};
use futures_util::FutureExt as _;
use tavern_protocol::rest::ErrorCode;
use tower_http::catch_panic::CatchPanicLayer;

use crate::error::ApiError;

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
