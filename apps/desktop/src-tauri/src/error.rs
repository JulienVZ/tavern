// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors returned to the webview: a machine-readable code that the interface
//! maps to a localised message. No detail that could contain a secret.

use serde::Serialize;
use tavern_client_core::local::LocalStoreError;
use tavern_client_core::password::PasswordIssue;
use tavern_client_core::{ClientError, InstanceUrlError};
use tavern_protocol::handle::HandleError;

/// Failure of a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommandError {
    /// Snake-case code, e.g. `invalid_credentials`.
    code: String,
    /// A finer reason for `weak_password` and `invalid_handle`.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'static str>,
    /// For `rate_limited`: how long to wait.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
}

impl CommandError {
    pub(crate) fn code(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            detail: None,
            retry_after_ms: None,
        }
    }

    fn detailed(code: &str, detail: &'static str) -> Self {
        Self {
            code: code.to_owned(),
            detail: Some(detail),
            retry_after_ms: None,
        }
    }

    pub(crate) fn is(&self, code: &str) -> bool {
        self.code == code
    }
}

impl From<InstanceUrlError> for CommandError {
    fn from(error: InstanceUrlError) -> Self {
        match error {
            InstanceUrlError::InsecureScheme => Self::code("insecure_url"),
            InstanceUrlError::Malformed
            | InstanceUrlError::HasCredentials
            | InstanceUrlError::HasQueryOrFragment => Self::code("invalid_url"),
        }
    }
}

impl From<ClientError> for CommandError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Unreachable(_) => Self::code("unreachable"),
            ClientError::NotTavern => Self::code("not_an_instance"),
            ClientError::IncompatibleServer => Self::code("incompatible_server"),
            ClientError::ClientTooOld => Self::code("client_too_old"),
            ClientError::ServerError => Self::code("server_error"),
            ClientError::Api {
                code,
                retry_after_ms,
            } => {
                // `ErrorCode` serialises in SCREAMING_SNAKE_CASE.
                let name = serde_json::to_value(code)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_ascii_lowercase))
                    .unwrap_or_else(|| "internal".to_owned());
                Self {
                    code: name,
                    detail: None,
                    retry_after_ms,
                }
            }
            ClientError::InvalidHandle(reason) => Self::detailed(
                "invalid_handle",
                match reason {
                    HandleError::TooShort => "too_short",
                    HandleError::TooLong => "too_long",
                    HandleError::InvalidCharacter | HandleError::NotCanonical => {
                        "invalid_character"
                    }
                    HandleError::MisplacedDot => "misplaced_dot",
                },
            ),
            ClientError::WeakPassword(issue) => Self::detailed(
                "weak_password",
                match issue {
                    PasswordIssue::TooShort => "too_short",
                    PasswordIssue::TooLong => "too_long",
                    PasswordIssue::TooGuessable => "too_guessable",
                },
            ),
            ClientError::InvalidCredentials => Self::code("invalid_credentials"),
            ClientError::InvalidRecoveryKey => Self::code("invalid_recovery_key"),
            ClientError::SessionEnded => Self::code("session_ended"),
            ClientError::DeviceRevoked => Self::code("device_revoked"),
            ClientError::UntrustedKeyMaterial => Self::code("untrusted_key_material"),
            ClientError::AccountTooOld => Self::code("account_too_old"),
            ClientError::Store(_) => Self::code("keychain_unavailable"),
            ClientError::LocalStore(LocalStoreError::TooNew { .. }) => {
                Self::code("local_store_too_new")
            }
            ClientError::LocalStore(_) => Self::code("local_store_unavailable"),
            ClientError::ClockSkew { .. } => Self::code("clock_skew"),
            ClientError::Crypto(_) | ClientError::Mls(_) | ClientError::Interrupted => {
                Self::code("internal")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tavern_protocol::rest::ErrorCode;

    use super::*;

    #[test]
    fn api_codes_become_snake_case() {
        let error = CommandError::from(ClientError::Api {
            code: ErrorCode::InvalidInvite,
            retry_after_ms: None,
        });
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            r#"{"code":"invalid_invite"}"#
        );

        let limited = CommandError::from(ClientError::Api {
            code: ErrorCode::RateLimited,
            retry_after_ms: Some(1200),
        });
        assert_eq!(
            serde_json::to_string(&limited).unwrap(),
            r#"{"code":"rate_limited","retryAfterMs":1200}"#
        );
    }

    #[test]
    fn local_refusals_carry_their_reason() {
        let weak = CommandError::from(ClientError::WeakPassword(PasswordIssue::TooGuessable));
        assert_eq!(
            serde_json::to_string(&weak).unwrap(),
            r#"{"code":"weak_password","detail":"too_guessable"}"#
        );
        let handle = CommandError::from(ClientError::InvalidHandle(HandleError::TooShort));
        assert!(handle.is("invalid_handle"));
    }

    #[test]
    fn urls_are_classified() {
        assert!(CommandError::from(InstanceUrlError::InsecureScheme).is("insecure_url"));
        assert!(CommandError::from(InstanceUrlError::Malformed).is("invalid_url"));
        assert!(CommandError::from(InstanceUrlError::HasCredentials).is("invalid_url"));
    }

    #[test]
    fn the_four_kinds_of_instance_failure_have_distinct_codes() {
        let codes = [
            CommandError::from(ClientError::NotTavern),
            CommandError::from(ClientError::IncompatibleServer),
            CommandError::from(ClientError::ServerError),
            CommandError::from(ClientError::ClientTooOld),
        ];
        let names: Vec<&str> = codes.iter().map(|error| error.code.as_str()).collect();

        assert_eq!(
            names,
            [
                "not_an_instance",
                "incompatible_server",
                "server_error",
                "client_too_old"
            ]
        );
    }

    #[test]
    fn store_and_crypto_details_are_not_exposed() {
        let error = CommandError::from(ClientError::Store("secret detail".to_owned()));
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("secret detail")
        );
    }
}
