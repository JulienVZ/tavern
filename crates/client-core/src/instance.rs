// SPDX-License-Identifier: AGPL-3.0-or-later

//! Connection to a Tavern instance.

use std::net::IpAddr;
use std::time::Duration;

use tavern_protocol::rest::{HealthResponse, VersionResponse};
use url::{Host, Url};

use crate::error::ClientError;

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

    pub(crate) fn endpoint(&self, path: &str) -> Result<Url, ClientError> {
        self.0.join(path).map_err(|_| ClientError::ServerError)
    }

    /// The gateway WebSocket URL of this instance: `wss` for `https`, and
    /// `ws` only for the loopback hosts for which `http` is accepted.
    pub(crate) fn gateway_url(&self) -> Result<Url, ClientError> {
        let mut url = self.endpoint(tavern_protocol::GATEWAY_PATH.trim_start_matches('/'))?;
        let scheme = if url.scheme() == "http" { "ws" } else { "wss" };
        url.set_scheme(scheme)
            .map_err(|()| ClientError::ServerError)?;
        Ok(url)
    }
}

fn is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => *name == "localhost",
        Host::Ipv4(ip) => IpAddr::V4(*ip).is_loopback(),
        Host::Ipv6(ip) => IpAddr::V6(*ip).is_loopback(),
    }
}

/// Queries `GET /health` on the instance.
///
/// A 503 answer with a well-formed body is returned as `Ok`: the instance
/// exists and reports that it is unhealthy. Anything that does not look like
/// Tavern's health answer is [`ClientError::NotTavern`].
pub async fn fetch_health(instance: &InstanceUrl) -> Result<HealthResponse, ClientError> {
    let response = http_client()?
        .get(instance.endpoint("health")?)
        .send()
        .await
        .map_err(ClientError::Unreachable)?;

    let status = response.status().as_u16();
    if status != 200 && status != 503 {
        return Err(ClientError::NotTavern);
    }
    response
        .json::<HealthResponse>()
        .await
        .map_err(|_| ClientError::NotTavern)
}

/// Queries `GET /version` on the instance.
pub async fn fetch_version(instance: &InstanceUrl) -> Result<VersionResponse, ClientError> {
    let response = http_client()?
        .get(instance.endpoint("version")?)
        .send()
        .await
        .map_err(ClientError::Unreachable)?;
    if !response.status().is_success() {
        return Err(ClientError::NotTavern);
    }
    response
        .json::<VersionResponse>()
        .await
        .map_err(|_| ClientError::NotTavern)
}

/// How the instance's protocol versions compare with this client's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compatibility {
    /// The instance serves everything this client uses.
    Compatible,
    /// The instance is older than this client: some features will fail
    /// until its administrator updates it.
    ServerOlder,
    /// The instance speaks a newer major version: this client must be updated.
    ServerNewer,
}

/// Compares the versions announced by `GET /version` with the ones this
/// client was built for.
///
/// Within a major version additions are compatible, so a server with a higher
/// minor version is fine; a lower one lacks routes this client calls.
pub fn compatibility(version: &VersionResponse) -> Compatibility {
    use tavern_protocol::{GATEWAY_MAJOR_VERSION, REST_MAJOR_VERSION, REST_MINOR_VERSION};

    if version.rest.major > REST_MAJOR_VERSION || version.gateway.min_major > GATEWAY_MAJOR_VERSION
    {
        Compatibility::ServerNewer
    } else if version.rest.major < REST_MAJOR_VERSION
        || version.rest.minor < REST_MINOR_VERSION
        || version.gateway.max_major < GATEWAY_MAJOR_VERSION
    {
        Compatibility::ServerOlder
    } else {
        Compatibility::Compatible
    }
}

/// Builds the HTTP client used for every request to an instance: rustls,
/// timeouts on connection and on the whole request, and no redirects, so an
/// instance cannot silently send the client elsewhere.
pub(crate) fn http_client() -> Result<reqwest::Client, ClientError> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(ClientError::Unreachable)
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
    fn the_gateway_url_follows_the_scheme_and_prefix() {
        let secure = InstanceUrl::parse("https://example.org/tavern").unwrap();
        assert_eq!(
            secure.gateway_url().unwrap().as_str(),
            "wss://example.org/tavern/gateway/v1"
        );
        let local = InstanceUrl::parse("http://localhost:8080").unwrap();
        assert_eq!(
            local.gateway_url().unwrap().as_str(),
            "ws://localhost:8080/gateway/v1"
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
    fn loopback_lookalikes_do_not_get_plain_http() {
        for input in [
            "http://localhost.evil.example",
            "http://evil.example/localhost",
            "http://127.0.0.1.nip.io",
            "http://0.0.0.0:8080",
            "http://10.0.0.1",
            "http://[::ffff:127.0.0.1]:8080",
            "http://[fe80::1]:8080",
            "http://localhost.",
        ] {
            assert_eq!(
                InstanceUrl::parse(input),
                Err(InstanceUrlError::InsecureScheme),
                "{input}"
            );
        }
    }

    #[test]
    fn loopback_host_matching_ignores_case() {
        let url = InstanceUrl::parse("HTTP://LOCALHOST:8080").unwrap();
        assert_eq!(url.as_str(), "http://localhost:8080/");
        assert!(InstanceUrl::parse("http://127.8.9.10:1").is_ok());
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

        assert!(matches!(error, ClientError::NotTavern));
    }

    fn version(rest: (u32, u32), gateway: (u32, u32)) -> VersionResponse {
        use tavern_protocol::rest::{B64, GatewayVersions, RestVersion};
        VersionResponse {
            name: "tavern".to_owned(),
            version: "0.0.1".to_owned(),
            rest: RestVersion {
                major: rest.0,
                minor: rest.1,
            },
            gateway: GatewayVersions {
                min_major: gateway.0,
                max_major: gateway.1,
                minor: 0,
            },
            mls_external_sender_key: B64(vec![0; 32]),
            source_url: None,
            commit: None,
        }
    }

    #[test]
    fn versions_are_compared_with_what_this_client_needs() {
        use tavern_protocol::{REST_MAJOR_VERSION as MAJOR, REST_MINOR_VERSION as MINOR};

        assert_eq!(
            compatibility(&version((MAJOR, MINOR), (1, 1))),
            Compatibility::Compatible
        );
        // Additions within a major version do not break this client.
        assert_eq!(
            compatibility(&version((MAJOR, MINOR + 5), (1, 2))),
            Compatibility::Compatible
        );
        // A server before REST 1.1 does not announce a REST version at all.
        assert_eq!(
            compatibility(&version((0, 0), (1, 1))),
            Compatibility::ServerOlder
        );
        assert_eq!(
            compatibility(&version((MAJOR, MINOR - 1), (1, 1))),
            Compatibility::ServerOlder
        );
        assert_eq!(
            compatibility(&version((MAJOR, MINOR), (0, 0))),
            Compatibility::ServerOlder
        );
        assert_eq!(
            compatibility(&version((MAJOR + 1, 0), (1, 1))),
            Compatibility::ServerNewer
        );
        assert_eq!(
            compatibility(&version((MAJOR, MINOR), (2, 3))),
            Compatibility::ServerNewer
        );
    }

    #[tokio::test]
    async fn an_older_server_is_recognised_from_its_version_answer() {
        // The exact answer of the stale server that caused the M1 confusion.
        let instance = serve_once(
            "HTTP/1.1 200 OK",
            r#"{"name":"tavern","version":"0.0.1","gateway":{"min_major":1,"max_major":1,"minor":0},"mls_external_sender_key":"1k65qNtRtDfVes98E4fa8SL7iixlNwmTYLH7HCzMEgY"}"#,
        )
        .await;

        let version = fetch_version(&instance).await.unwrap();

        assert_eq!(compatibility(&version), Compatibility::ServerOlder);
    }

    #[tokio::test]
    async fn a_foreign_version_answer_is_not_tavern() {
        let instance = serve_once("HTTP/1.1 200 OK", r#"{"version":"nginx"}"#).await;

        assert!(matches!(
            fetch_version(&instance).await.unwrap_err(),
            ClientError::NotTavern
        ));
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
