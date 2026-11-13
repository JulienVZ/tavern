// SPDX-License-Identifier: AGPL-3.0-or-later

//! JSON bodies of the REST API.

use serde::{Deserialize, Serialize};

/// State of one component checked by `GET /health`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    /// The component answered in time.
    Ok,
    /// The component did not answer or returned an error.
    Unavailable,
}

/// Body of `GET /health`.
///
/// The endpoint answers 200 when every component is [`ComponentStatus::Ok`]
/// and 503 otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall status.
    pub status: ComponentStatus,
    /// PostgreSQL connectivity.
    pub database: ComponentStatus,
}

/// Body of `GET /version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionResponse {
    /// Software name.
    pub name: String,
    /// Server version (semver).
    pub version: String,
    /// Gateway protocol versions served by this instance.
    pub gateway: GatewayVersions,
    /// Where the source code of this instance can be obtained (AGPL network clause).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
}

/// Gateway protocol versions served by an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayVersions {
    /// Oldest major version still served.
    pub min_major: u32,
    /// Newest major version served.
    pub max_major: u32,
    /// Minor version of the newest major version.
    pub minor: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_uses_snake_case_statuses() {
        let body = HealthResponse {
            status: ComponentStatus::Unavailable,
            database: ComponentStatus::Unavailable,
        };

        let json = serde_json::to_string(&body).unwrap();

        assert_eq!(json, r#"{"status":"unavailable","database":"unavailable"}"#);
    }

    #[test]
    fn version_response_omits_missing_source_url() {
        let body = VersionResponse {
            name: "tavern".to_owned(),
            version: "0.0.1".to_owned(),
            gateway: GatewayVersions {
                min_major: 1,
                max_major: 1,
                minor: 0,
            },
            source_url: None,
        };

        let json = serde_json::to_string(&body).unwrap();

        assert!(!json.contains("source_url"));
        assert_eq!(
            serde_json::from_str::<VersionResponse>(&json).unwrap(),
            body
        );
    }
}
