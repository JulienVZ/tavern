// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors of the client core.

use tavern_crypto::CryptoError;
use tavern_protocol::handle::HandleError;
use tavern_protocol::rest::ErrorCode;

use crate::password::PasswordIssue;

/// Something the client tried failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The instance could not be reached (DNS, TCP, TLS or timeout).
    #[error("the instance cannot be reached")]
    Unreachable(#[source] reqwest::Error),
    /// Something answered, but not like a Tavern instance.
    #[error("the server did not answer like a Tavern instance")]
    UnexpectedResponse,
    /// The instance refused the request.
    #[error("the instance refused the request ({code:?})")]
    Api {
        /// Why.
        code: ErrorCode,
        /// When to retry, for rate limits.
        retry_after_ms: Option<u64>,
    },
    /// The handle typed by the user is not acceptable.
    #[error("invalid handle: {0}")]
    InvalidHandle(#[from] HandleError),
    /// The password does not meet the strength requirement.
    #[error("the password is too weak")]
    WeakPassword(PasswordIssue),
    /// The handle or password is wrong. Deliberately not more precise.
    #[error("wrong handle or password")]
    InvalidCredentials,
    /// The recovery key typed by the user is malformed or does not belong to
    /// this account.
    #[error("the recovery key is not valid for this account")]
    InvalidRecoveryKey,
    /// The session ended: the user must log in again.
    #[error("the session ended")]
    SessionEnded,
    /// This device was revoked from another device. Its local record was
    /// removed; logging in again enrols this computer as a new device.
    #[error("this device was revoked")]
    DeviceRevoked,
    /// The instance returned key material that does not verify. Either the
    /// data is corrupted or the instance is misbehaving.
    #[error("the instance returned invalid key material")]
    UntrustedKeyMaterial,
    /// A cryptographic operation failed.
    #[error("cryptographic failure: {0}")]
    Crypto(CryptoError),
    /// The operating system's credential store failed.
    #[error("the system keychain is unavailable: {0}")]
    Store(String),
    /// A background task was cancelled.
    #[error("the operation was interrupted")]
    Interrupted,
}

impl ClientError {
    /// The API error code, when the instance refused the request.
    pub fn api_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Api { code, .. } => Some(*code),
            _ => None,
        }
    }
}

impl From<CryptoError> for ClientError {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::AuthenticationFailed => Self::InvalidCredentials,
            other => Self::Crypto(other),
        }
    }
}
