// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed access to the instance's REST API.

use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tavern_protocol::rest::{B64, ErrorBody, ErrorCode};

use crate::error::ClientError;
use crate::instance::{InstanceUrl, http_client};

/// How a request is authorised.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Auth<'a> {
    /// No credentials.
    None,
    /// A session token. A refusal means the session ended.
    Session(&'a B64),
    /// A single-use enrolment or re-authentication token.
    Grant(&'a B64),
}

/// Classifies an error response that carries no API error body.
///
/// Servers older than REST 1.1 answer unknown routes with a bare 404 or 405.
/// A reverse proxy in front of a stopped server answers 502, 503 or 504.
fn classify_bare_status(status: StatusCode) -> ClientError {
    match status {
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::NOT_IMPLEMENTED => {
            ClientError::IncompatibleServer
        }
        _ => ClientError::ServerError,
    }
}

/// The REST API of one instance.
#[derive(Debug, Clone)]
pub(crate) struct Api {
    http: reqwest::Client,
    instance: InstanceUrl,
}

impl Api {
    pub(crate) fn new(instance: InstanceUrl) -> Result<Self, ClientError> {
        Ok(Self {
            http: http_client()?,
            instance,
        })
    }

    pub(crate) fn instance(&self) -> &InstanceUrl {
        &self.instance
    }

    async fn send<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        auth: Auth<'_>,
        body: Option<&B>,
    ) -> Result<reqwest::Response, ClientError> {
        let mut request = self.http.request(method, self.instance.endpoint(path)?);
        if let Auth::Session(token) | Auth::Grant(token) = auth {
            request = request.bearer_auth(data_encoding::BASE64URL_NOPAD.encode(token.as_slice()));
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(ClientError::Unreachable)?;
        if response.status().is_success() {
            return Ok(response);
        }

        let status = response.status();
        // The instance was validated when it was chosen, so an answer that is
        // not one of its JSON errors is never "this is not Tavern": it is a
        // server that does not know this route, or one that failed.
        let Ok(error) = response.json::<ErrorBody>().await else {
            return Err(classify_bare_status(status));
        };
        Err(match (error.code, auth) {
            (ErrorCode::Unauthenticated, Auth::Session(_))
                if status == StatusCode::UNAUTHORIZED =>
            {
                ClientError::SessionEnded
            }
            (ErrorCode::InvalidCredentials, _) => ClientError::InvalidCredentials,
            (ErrorCode::UnknownEndpoint, _) => ClientError::IncompatibleServer,
            (ErrorCode::Internal, _) => ClientError::ServerError,
            (code, _) => ClientError::Api {
                code,
                retry_after_ms: error.retry_after_ms,
            },
        })
    }

    /// Sends a request with a JSON body and decodes the JSON answer.
    pub(crate) async fn call<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        auth: Auth<'_>,
        body: &B,
    ) -> Result<R, ClientError> {
        self.send(method, path, auth, Some(body))
            .await?
            .json()
            .await
            // A success whose body this client cannot read: the two sides
            // disagree about the format.
            .map_err(|_| ClientError::IncompatibleServer)
    }

    /// Sends a request with a JSON body and expects no content back.
    pub(crate) async fn call_empty<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        auth: Auth<'_>,
        body: &B,
    ) -> Result<(), ClientError> {
        self.send(method, path, auth, Some(body)).await.map(|_| ())
    }

    /// Sends a request without a body and decodes the JSON answer.
    pub(crate) async fn fetch<R: DeserializeOwned>(
        &self,
        path: &str,
        auth: Auth<'_>,
    ) -> Result<R, ClientError> {
        self.send::<()>(Method::GET, path, auth, None)
            .await?
            .json()
            .await
            // A success whose body this client cannot read: the two sides
            // disagree about the format.
            .map_err(|_| ClientError::IncompatibleServer)
    }

    /// Sends a request without a body and expects no content back.
    pub(crate) async fn act(
        &self,
        method: Method,
        path: &str,
        auth: Auth<'_>,
    ) -> Result<(), ClientError> {
        self.send::<()>(method, path, auth, None).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct Anything {
        #[expect(dead_code, reason = "only decoded, never read")]
        value: u32,
    }

    /// An API pointed at a server that answers every request with `status`
    /// and `body`.
    async fn api_answering(status: &'static str, body: &'static str) -> Api {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Api::new(InstanceUrl::parse(&format!("http://{addr}")).unwrap()).unwrap()
    }

    async fn call(api: &Api, auth: Auth<'_>) -> ClientError {
        api.call::<_, Anything>(Method::POST, "v1/anything", auth, &())
            .await
            .unwrap_err()
    }

    /// The bug found by hand at the end of M1: an older server without the
    /// credential routes answered 404 with no body, and the client said
    /// "this is not a Tavern instance".
    #[tokio::test]
    async fn a_missing_route_on_an_older_server_is_an_incompatibility() {
        for (status, body) in [
            ("404 Not Found", ""),
            ("405 Method Not Allowed", ""),
            ("404 Not Found", "<html>not found</html>"),
            (
                "404 Not Found",
                r#"{"code":"UNKNOWN_ENDPOINT","message":"no such endpoint"}"#,
            ),
        ] {
            let error = call(&api_answering(status, body).await, Auth::None).await;
            assert!(
                matches!(error, ClientError::IncompatibleServer),
                "{status} {body}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_resource_is_not_an_incompatibility() {
        let api = api_answering(
            "404 Not Found",
            r#"{"code":"NOT_FOUND","message":"not found"}"#,
        )
        .await;

        let error = call(&api, Auth::None).await;

        assert_eq!(error.api_code(), Some(ErrorCode::NotFound));
    }

    #[tokio::test]
    async fn server_failures_are_reported_as_such() {
        for (status, body) in [
            ("500 Internal Server Error", ""),
            (
                "500 Internal Server Error",
                r#"{"code":"INTERNAL","message":"internal error"}"#,
            ),
            ("502 Bad Gateway", "<html>bad gateway</html>"),
            ("503 Service Unavailable", ""),
            ("400 Bad Request", "not json"),
        ] {
            let error = call(&api_answering(status, body).await, Auth::None).await;
            assert!(
                matches!(error, ClientError::ServerError),
                "{status} {body}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_success_this_client_cannot_read_is_an_incompatibility() {
        let error = call(
            &api_answering("200 OK", r#"{"other":"shape"}"#).await,
            Auth::None,
        )
        .await;

        assert!(
            matches!(error, ClientError::IncompatibleServer),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn only_a_session_refusal_ends_the_session() {
        let body = r#"{"code":"UNAUTHENTICATED","message":"authentication is required"}"#;
        let api = api_answering("401 Unauthorized", body).await;
        let token = B64(vec![1; 32]);

        assert!(matches!(
            call(&api, Auth::Session(&token)).await,
            ClientError::SessionEnded
        ));
        assert_eq!(
            call(&api, Auth::Grant(&token)).await.api_code(),
            Some(ErrorCode::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn nothing_listening_is_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let api = Api::new(InstanceUrl::parse(&format!("http://{addr}")).unwrap()).unwrap();

        assert!(matches!(
            call(&api, Auth::None).await,
            ClientError::Unreachable(_)
        ));
    }
}
