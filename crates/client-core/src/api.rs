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
        let error: ErrorBody = response
            .json()
            .await
            .map_err(|_| ClientError::UnexpectedResponse)?;
        Err(match (error.code, auth) {
            (ErrorCode::Unauthenticated, Auth::Session(_))
                if status == StatusCode::UNAUTHORIZED =>
            {
                ClientError::SessionEnded
            }
            (ErrorCode::InvalidCredentials, _) => ClientError::InvalidCredentials,
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
            .map_err(|_| ClientError::UnexpectedResponse)
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
            .map_err(|_| ClientError::UnexpectedResponse)
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
