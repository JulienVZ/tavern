// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tauri shell of the Tavern desktop client.
//!
//! This crate only maps commands and events onto `tavern-client-core`. It
//! contains no business logic, and the webview never receives keys or
//! ciphertext.

use serde::Serialize;
use tavern_client_core::{ClientError, InstanceUrl, InstanceUrlError, fetch_health};
use tavern_protocol::rest::HealthResponse;

/// Result of probing an instance, as shown by the "instance URL" screen.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstanceProbe {
    /// The URL after validation and normalisation.
    url: String,
    /// What `GET /health` answered.
    health: HealthResponse,
}

/// Machine-readable failure of a command. The UI maps each code to a
/// localised message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CommandError {
    InvalidUrl,
    InsecureUrl,
    Unreachable,
    NotAnInstance,
}

impl From<InstanceUrlError> for CommandError {
    fn from(error: InstanceUrlError) -> Self {
        match error {
            InstanceUrlError::InsecureScheme => Self::InsecureUrl,
            InstanceUrlError::Malformed
            | InstanceUrlError::HasCredentials
            | InstanceUrlError::HasQueryOrFragment => Self::InvalidUrl,
        }
    }
}

impl From<ClientError> for CommandError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Unreachable(_) => Self::Unreachable,
            ClientError::UnexpectedResponse => Self::NotAnInstance,
        }
    }
}

/// Validates the URL typed by the user and queries the instance's health.
#[tauri::command]
async fn probe_instance(url: String) -> Result<InstanceProbe, CommandError> {
    let instance = InstanceUrl::parse(&url)?;
    let health = fetch_health(&instance).await?;
    Ok(InstanceProbe {
        url: instance.as_str().to_owned(),
        health,
    })
}

/// Starts the desktop application and blocks until it exits.
pub fn run() -> Result<(), tauri::Error> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![probe_instance])
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_urls_are_reported_with_a_code() {
        assert_eq!(
            probe_instance(String::new()).await.unwrap_err(),
            CommandError::InvalidUrl
        );
        assert_eq!(
            probe_instance("http://chat.example.org".to_owned())
                .await
                .unwrap_err(),
            CommandError::InsecureUrl
        );
    }

    #[test]
    fn error_codes_serialise_as_snake_case() {
        let json = serde_json::to_string(&CommandError::NotAnInstance).unwrap();
        assert_eq!(json, r#""not_an_instance""#);
    }
}
