// SPDX-License-Identifier: AGPL-3.0-or-later

//! Connection to a Tavern instance.

use std::net::IpAddr;
use std::time::Duration;

use tavern_protocol::rest::HealthResponse;
use url::{Host, Url};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = concat!("tavern-client/", env!("CARGO_PKG_VERSION"));

/// Base URL of an instance, as typed by the user and validated.
///
/// Only `https` is accepted, except for loopback hosts where `http` is allowed
/// so that a developer can run a server locally without TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceUrl(Url);

/// Why a string is not an acceptable instance URL.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InstanceUrlError {
    /// The string is not a URL.
    #[error("not a valid URL")]
    Malformed,
    /// The scheme is neither `https` nor `http` on a loopback host.
    #[error("the instance must be reached over https")]
    InsecureScheme,
    /// The URL carries a user name or password.
    #[error("the URL must not contain credentials")]
    HasCredentials,
    /// The URL carries a query string or a fragment.
    #[error("the URL must not contain a query or a fragment")]
    HasQueryOrFragment,
}

impl InstanceUrl {
    /// Parses and validates what the user typed.
    ///
    /// A missing scheme defaults to `https`. Any path is kept as a prefix, so
    /// an instance can be served under a sub-path.
    pub fn parse(input: &str) -> Result<Self, InstanceUrlError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(InstanceUrlError::Malformed);
        }
        let with_scheme = if trimmed.contains("://") {
            trimmed.to_owned()
        } else {
            format!("https://{trimmed}")
        };

        let mut url = Url::parse(&with_scheme).map_err(|_| InstanceUrlError::Malformed)?;
        let host = url.host().ok_or(InstanceUrlError::Malformed)?;

        match url.scheme() {
            "https" => {}
            "http" if is_loopback(&host) => {}
            _ => return Err(InstanceUrlError::InsecureScheme),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(InstanceUrlError::HasCredentials);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(InstanceUrlError::HasQueryOrFragment);
        }

        // Normalise to a trailing slash so that `join` appends to the path.
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self(url))
    }

    /// The normalised URL, with a trailing slash.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn endpoint(&self, path: &str) -> Result<Url, ClientError> {
        self.0
            .join(path)
            .map_err(|_| ClientError::UnexpectedResponse)
    }
}

fn is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => *name == "localhost",
        Host::Ipv4(ip) => IpAddr::V4(*ip).is_loopback(),
        Host::Ipv6(ip) => IpAddr::V6(*ip).is_loopback(),
    }
}

/// A request to an instance failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The instance could not be reached (DNS, TCP, TLS or timeout).
    #[error("the instance cannot be reached")]
    Unreachable(#[source] reqwest::Error),
    /// Something answered, but not like a Tavern instance.
    #[error("the server did not answer like a Tavern instance")]
    UnexpectedResponse,
}

/// Queries `GET /health` on the instance.
///
/// A 503 answer with a well-formed body is returned as `Ok`: the instance
/// exists and reports that it is unhealthy.
pub async fn fetch_health(instance: &InstanceUrl) -> Result<HealthResponse, ClientError> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(ClientError::Unreachable)?;

    let response = client
        .get(instance.endpoint("health")?)
        .send()
        .await
        .map_err(ClientError::Unreachable)?;

    let status = response.status().as_u16();
    if status != 200 && status != 503 {
        return Err(ClientError::UnexpectedResponse);
    }
    response
        .json::<HealthResponse>()
        .await
        .map_err(|_| ClientError::UnexpectedResponse)
}

#[cfg(test)]
mod tests {
    use tavern_protocol::rest::ComponentStatus;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn scheme_defaults_to_https() {
        let url = InstanceUrl::parse("  chat.example.org ").unwrap();
        assert_eq!(url.as_str(), "https://chat.example.org/");
    }

    #[test]
    fn sub_paths_are_kept_as_prefix() {
        let url = InstanceUrl::parse("https://example.org/tavern").unwrap();
        assert_eq!(
            url.endpoint("health").unwrap().as_str(),
            "https://example.org/tavern/health"
        );
    }

    #[test]
    fn http_is_allowed_on_loopback_only() {
        assert!(InstanceUrl::parse("http://localhost:8080").is_ok());
        assert!(InstanceUrl::parse("http://127.0.0.1:8080").is_ok());
        assert!(InstanceUrl::parse("http://[::1]:8080").is_ok());
        assert_eq!(
            InstanceUrl::parse("http://chat.example.org"),
            Err(InstanceUrlError::InsecureScheme)
        );
        assert_eq!(
            InstanceUrl::parse("http://192.168.1.10:8080"),
            Err(InstanceUrlError::InsecureScheme)
        );
        assert_eq!(
            InstanceUrl::parse("ftp://example.org"),
            Err(InstanceUrlError::InsecureScheme)
        );
    }

    #[test]
    fn credentials_query_and_fragment_are_rejected() {
        assert_eq!(
            InstanceUrl::parse("https://user:pw@example.org"),
            Err(InstanceUrlError::HasCredentials)
        );
        assert_eq!(
            InstanceUrl::parse("https://example.org/?a=b"),
            Err(InstanceUrlError::HasQueryOrFragment)
        );
        assert_eq!(
            InstanceUrl::parse("https://example.org/#x"),
            Err(InstanceUrlError::HasQueryOrFragment)
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(InstanceUrl::parse(""), Err(InstanceUrlError::Malformed));
        assert_eq!(
            InstanceUrl::parse("https://"),
            Err(InstanceUrlError::Malformed)
        );
        assert_eq!(
            InstanceUrl::parse("not a url"),
            Err(InstanceUrlError::Malformed)
        );
    }

    /// Serves one canned HTTP response on a loopback port.
    async fn serve_once(status_line: &'static str, body: &'static str) -> InstanceUrl {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        InstanceUrl::parse(&format!("http://{addr}")).unwrap()
    }

    #[tokio::test]
    async fn healthy_instance_is_reported() {
        let instance = serve_once("HTTP/1.1 200 OK", r#"{"status":"ok","database":"ok"}"#).await;

        let health = fetch_health(&instance).await.unwrap();

        assert_eq!(health.status, ComponentStatus::Ok);
        assert_eq!(health.database, ComponentStatus::Ok);
    }

    #[tokio::test]
    async fn unhealthy_instance_is_reported_not_an_error() {
        let instance = serve_once(
            "HTTP/1.1 503 Service Unavailable",
            r#"{"status":"unavailable","database":"unavailable"}"#,
        )
        .await;

        let health = fetch_health(&instance).await.unwrap();

        assert_eq!(health.status, ComponentStatus::Unavailable);
    }

    #[tokio::test]
    async fn foreign_server_is_rejected() {
        let instance = serve_once("HTTP/1.1 200 OK", r#"{"hello":"world"}"#).await;

        let error = fetch_health(&instance).await.unwrap_err();

        assert!(matches!(error, ClientError::UnexpectedResponse));
    }

    #[tokio::test]
    async fn closed_port_is_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let instance = InstanceUrl::parse(&format!("http://{addr}")).unwrap();

        let error = fetch_health(&instance).await.unwrap_err();

        assert!(matches!(error, ClientError::Unreachable(_)));
    }
}
