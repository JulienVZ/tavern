// SPDX-License-Identifier: AGPL-3.0-or-later

//! JSON bodies of the REST API.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use self::bytes::B64;

/// State of one component checked by `GET /health`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall status.
    pub status: ComponentStatus,
    /// PostgreSQL connectivity.
    pub database: ComponentStatus,
}

/// Body of `GET /version`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionResponse {
    /// Software name.
    pub name: String,
    /// Server version (semver).
    pub version: String,
    /// REST API version served by this instance. Absent on servers older
    /// than REST 1.1, which reads as 0.0.
    #[serde(default)]
    pub rest: RestVersion,
    /// Gateway protocol versions served by this instance.
    pub gateway: GatewayVersions,
    /// Ed25519 public key of the instance's MLS external sender.
    pub mls_external_sender_key: B64,
    /// Where the source code of this instance can be obtained (AGPL network clause).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// Git commit this server was built from, when the build recorded it
    /// (`TAVERN_BUILD_COMMIT`). A `-dirty` suffix means uncommitted changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// REST API version served by an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RestVersion {
    /// Major version: the number in the `/v1` path prefix.
    pub major: u32,
    /// Minor version, incremented with every addition.
    pub minor: u32,
}

/// Gateway protocol versions served by an instance.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayVersions {
    /// Oldest major version still served.
    pub min_major: u32,
    /// Newest major version served.
    pub max_major: u32,
    /// Minor version of the newest major version.
    pub minor: u32,
}

/// Binary values in JSON: unpadded base64url strings.
mod bytes {
    use std::fmt;

    use data_encoding::BASE64URL_NOPAD;
    use serde::de::{self, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Bytes carried in JSON as an unpadded base64url string.
    ///
    /// `Debug` prints the length only: these fields carry keys, tokens and
    /// protocol messages that must not end up in logs.
    #[derive(Clone, PartialEq, Eq, Default)]
    #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = Byte))]
    pub struct B64(pub Vec<u8>);

    impl B64 {
        /// The bytes.
        pub fn as_slice(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<Vec<u8>> for B64 {
        fn from(bytes: Vec<u8>) -> Self {
            Self(bytes)
        }
    }

    impl From<&[u8]> for B64 {
        fn from(bytes: &[u8]) -> Self {
            Self(bytes.to_vec())
        }
    }

    impl<const N: usize> From<[u8; N]> for B64 {
        fn from(bytes: [u8; N]) -> Self {
            Self(bytes.to_vec())
        }
    }

    impl fmt::Debug for B64 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "B64(<{} bytes>)", self.0.len())
        }
    }

    impl Serialize for B64 {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&BASE64URL_NOPAD.encode(&self.0))
        }
    }

    impl<'de> Deserialize<'de> for B64 {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct B64Visitor;

            impl Visitor<'_> for B64Visitor {
                type Value = B64;

                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an unpadded base64url string")
                }

                fn visit_str<E: de::Error>(self, value: &str) -> Result<B64, E> {
                    BASE64URL_NOPAD
                        .decode(value.as_bytes())
                        .map(B64)
                        .map_err(|_| E::custom("invalid base64url"))
                }
            }

            deserializer.deserialize_str(B64Visitor)
        }
    }
}

/// Machine-readable error codes of the REST API. See `docs/protocol.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Malformed or out-of-range field.
    InvalidArgument,
    /// Missing, unknown or expired session or token.
    Unauthenticated,
    /// Authenticated but not allowed.
    Forbidden,
    /// The resource does not exist.
    NotFound,
    /// This server has no such route or method: it is older than the client,
    /// or otherwise incompatible with it.
    UnknownEndpoint,
    /// The resource already exists.
    AlreadyExists,
    /// The request body is too large.
    PayloadTooLarge,
    /// Too many requests; see `retry_after_ms`.
    RateLimited,
    /// The server failed.
    Internal,
    /// The server cannot answer now.
    Unavailable,
    /// Wrong handle or password, or a failed login exchange.
    InvalidCredentials,
    /// The invitation code is unknown, expired, revoked or used up.
    InvalidInvite,
    /// The handle is already used by another account.
    HandleTaken,
    /// The handle is not in canonical form.
    InvalidHandle,
    /// A TOTP code is required to continue.
    TotpRequired,
    /// The TOTP code is wrong or was already used.
    TotpInvalid,
    /// The account is disabled.
    AccountDisabled,
    /// The device certificate is invalid for this account.
    InvalidDeviceCertificate,
    /// A two-step exchange timed out or its identifier is unknown.
    ExchangeExpired,
    /// The account already has the maximum number of devices.
    TooManyDevices,
    /// A signature or proof did not verify.
    InvalidProof,
    /// A KeyPackage was refused: malformed, expired, valid for too long,
    /// another device's, or not the key and certificate the device enrolled
    /// with.
    InvalidKeyPackage,
    /// This user blocks the other one: unblock them first.
    Blocked,
    /// The two users are not friends: unknown, not friends any more, or
    /// either one blocks the other, which this code does not tell apart.
    NotFriends,
}

/// Body of every REST error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorBody {
    /// What went wrong, for programs.
    pub code: ErrorCode,
    /// What went wrong, in English, for logs. User interfaces localise from `code`.
    pub message: String,
    /// How long to wait before retrying, for `RATE_LIMITED` and `UNAVAILABLE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Operating system family of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
    /// Linux.
    Linux,
}

impl Platform {
    /// The value stored in `devices.platform`.
    pub fn to_db(self) -> i16 {
        match self {
            Self::Windows => 1,
            Self::Macos => 2,
            Self::Linux => 3,
        }
    }

    /// Reads a value stored in `devices.platform`.
    pub fn from_db(value: i16) -> Option<Self> {
        match value {
            1 => Some(Self::Windows),
            2 => Some(Self::Macos),
            3 => Some(Self::Linux),
            _ => None,
        }
    }
}

macro_rules! dto {
    ($(#[$meta:meta])* pub struct $name:ident { $($(#[$fmeta:meta])* pub $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        pub struct $name { $($(#[$fmeta])* pub $field: $ty),* }
    };
}

// --- Registration -----------------------------------------------------------

dto! {
    /// `POST /v1/auth/register/start`
    pub struct RegisterStartRequest {
        /// Invitation code as typed by the user.
        pub invite_code: String,
        /// Canonical handle.
        pub handle: String,
        /// OPAQUE `RegistrationRequest`.
        pub registration_request: B64,
    }
}

dto! {
    /// Answer to `register/start`, `account/password/start`.
    pub struct RegistrationResponse {
        /// OPAQUE `RegistrationResponse`.
        pub registration_response: B64,
        /// OPAQUE suite to use.
        pub opaque_suite: u16,
    }
}

dto! {
    /// `POST /v1/auth/register/finish`
    pub struct RegisterFinishRequest {
        /// Invitation code as typed by the user.
        pub invite_code: String,
        /// Canonical handle.
        pub handle: String,
        /// Display name, 1 to 64 characters.
        pub display_name: String,
        /// OPAQUE `RegistrationUpload`.
        pub registration_upload: B64,
        /// Account identity public key (Ed25519).
        pub identity_key: B64,
        /// Identity private key wrapped under the OPAQUE export key.
        pub wrapped_password_copy: B64,
        /// Identity private key wrapped under the recovery key.
        pub wrapped_recovery_copy: B64,
    }
}

dto! {
    /// Answer to `register/finish`.
    pub struct RegisterFinishResponse {
        /// The new account.
        pub user_id: Uuid,
        /// Whether the invitation made this account an administrator.
        pub is_admin: bool,
    }
}

// --- Login ------------------------------------------------------------------

dto! {
    /// `POST /v1/auth/login/start`
    pub struct LoginStartRequest {
        /// Canonical handle.
        pub handle: String,
        /// OPAQUE `CredentialRequest`.
        pub credential_request: B64,
    }
}

dto! {
    /// Answer to `login/start` and `reauth/start`.
    pub struct LoginStartResponse {
        /// Identifies this exchange in the next request. Valid for 60 seconds.
        pub login_id: B64,
        /// OPAQUE `CredentialResponse`.
        pub credential_response: B64,
        /// OPAQUE suite of the account.
        pub opaque_suite: u16,
    }
}

dto! {
    /// `POST /v1/auth/login/finish`
    pub struct LoginFinishRequest {
        /// From `login/start`.
        pub login_id: B64,
        /// OPAQUE `CredentialFinalization`.
        pub credential_finalization: B64,
    }
}

dto! {
    /// `POST /v1/auth/login/totp`
    pub struct LoginTotpRequest {
        /// From `login/start`.
        pub login_id: B64,
        /// Six-digit TOTP code, or a TOTP recovery code.
        pub code: String,
    }
}

/// Answer to `login/finish` and `login/totp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginOutcome {
    /// The password was right; a TOTP code is now required (`login/totp`).
    TotpRequired,
    /// Login complete.
    Ok(LoginGrant),
}

dto! {
    /// What a completed login gives the client.
    pub struct LoginGrant {
        /// The account.
        pub user_id: Uuid,
        /// Canonical handle.
        pub handle: String,
        /// Display name.
        pub display_name: String,
        /// Whether the account administers the instance.
        pub is_admin: bool,
        /// Authorises enrolling a device or reopening a session. Single use, 5 minutes.
        pub enrolment_token: B64,
        /// Nonce an existing device signs to reopen its session. Single use.
        pub session_nonce: B64,
        /// Account identity public key.
        pub identity_key: B64,
        /// Identity private key wrapped under the OPAQUE export key.
        pub wrapped_password_copy: B64,
    }
}

// --- Devices and sessions -----------------------------------------------------

dto! {
    /// `POST /v1/devices`, authorised by an enrolment token.
    pub struct EnrolDeviceRequest {
        /// Device certificate signed by the account identity key.
        pub certificate: B64,
        /// Device name, encrypted for the user's own devices.
        pub name_encrypted: Option<B64>,
        /// Operating system family.
        pub platform: Platform,
    }
}

dto! {
    /// `POST /v1/devices/{id}/session`, authorised by an enrolment token.
    pub struct ReopenSessionRequest {
        /// Signature by the device key over the session nonce, the account and the device.
        pub proof: B64,
    }
}

dto! {
    /// A new session.
    pub struct SessionResponse {
        /// The device the session belongs to.
        pub device_id: Uuid,
        /// Bearer token for the REST API and the gateway.
        pub session_token: B64,
        /// When the session expires if unused, in milliseconds since the Unix epoch.
        pub expires_at_ms: u64,
        /// The server's part of the key that wraps this device's local store
        /// (32 bytes). It is useless without the part derived from the
        /// account root secret. Since REST 1.2.
        pub local_store_share: B64,
    }
}

dto! {
    /// One device of the account.
    pub struct DeviceInfo {
        /// Device identifier.
        pub device_id: Uuid,
        /// Operating system family.
        pub platform: Platform,
        /// Device certificate.
        pub certificate: B64,
        /// Device name, encrypted for the user's own devices.
        pub name_encrypted: Option<B64>,
        /// Enrolment time, in milliseconds since the Unix epoch.
        pub created_at_ms: u64,
        /// Last activity (day precision), in milliseconds since the Unix epoch.
        pub last_seen_at_ms: Option<u64>,
        /// Whether this is the device making the request.
        pub current: bool,
    }
}

dto! {
    /// `GET /v1/devices`
    pub struct DeviceList {
        /// Active devices of the account.
        pub devices: Vec<DeviceInfo>,
    }
}

dto! {
    /// `GET /v1/users/me`
    pub struct Me {
        /// The account.
        pub user_id: Uuid,
        /// Canonical handle.
        pub handle: String,
        /// Display name.
        pub display_name: String,
        /// Whether the account administers the instance.
        pub is_admin: bool,
        /// Whether TOTP is enabled.
        pub totp_enabled: bool,
        /// Account identity public key.
        pub identity_key: B64,
        /// The device making the request.
        pub device_id: Uuid,
    }
}

// --- Administration -----------------------------------------------------------

dto! {
    /// `POST /v1/admin/invites`
    pub struct CreateInviteRequest {
        /// How many accounts may register with the code (default 1).
        pub max_uses: Option<u32>,
        /// Validity in hours (default 168, one week).
        pub expires_in_hours: Option<u32>,
    }
}

dto! {
    /// An invitation, without its code.
    pub struct InviteInfo {
        /// Invitation identifier.
        pub invite_id: Uuid,
        /// How many accounts may register with the code.
        pub max_uses: u32,
        /// How many already did.
        pub uses: u32,
        /// Whether the code makes its user an administrator.
        pub grants_admin: bool,
        /// Whether the invitation was revoked.
        pub revoked: bool,
        /// Creation time, in milliseconds since the Unix epoch.
        pub created_at_ms: u64,
        /// Expiry, in milliseconds since the Unix epoch.
        pub expires_at_ms: Option<u64>,
    }
}

dto! {
    /// Answer to `POST /v1/admin/invites`. The code is shown only here.
    pub struct CreatedInvite {
        /// The code to give to the invited person.
        pub code: String,
        /// The invitation.
        pub invite: InviteInfo,
    }
}

dto! {
    /// `GET /v1/admin/invites`
    pub struct InviteList {
        /// Invitations, newest first.
        pub invites: Vec<InviteInfo>,
    }
}

dto! {
    /// An account as seen by an administrator.
    pub struct AdminUser {
        /// The account.
        pub user_id: Uuid,
        /// Canonical handle.
        pub handle: String,
        /// Display name.
        pub display_name: String,
        /// Whether the account administers the instance.
        pub is_admin: bool,
        /// Whether the account is disabled.
        pub disabled: bool,
        /// Whether TOTP is enabled.
        pub totp_enabled: bool,
        /// Number of active devices.
        pub device_count: u32,
        /// Registration time, in milliseconds since the Unix epoch.
        pub created_at_ms: u64,
    }
}

dto! {
    /// `GET /v1/admin/users`
    pub struct AdminUserList {
        /// Accounts, oldest first.
        pub users: Vec<AdminUser>,
    }
}

// --- TOTP -----------------------------------------------------------------------

dto! {
    /// Answer to `POST /v1/account/totp/enable`.
    pub struct TotpEnrolment {
        /// Shared secret in base32, for manual entry.
        pub secret: String,
        /// `otpauth://` URL, for a QR code rendered by the client.
        pub otpauth_url: String,
    }
}

dto! {
    /// A TOTP code, for `totp/confirm` and `totp/disable`.
    pub struct TotpCodeRequest {
        /// Six-digit code.
        pub code: String,
    }
}

dto! {
    /// Answer to `POST /v1/account/totp/confirm`.
    pub struct TotpRecoveryCodes {
        /// Single-use codes that replace a TOTP code. Shown once.
        pub recovery_codes: Vec<String>,
    }
}

// --- Re-authentication and credential changes -----------------------------------

dto! {
    /// `POST /v1/auth/reauth/start`, from an existing session.
    pub struct ReauthStartRequest {
        /// OPAQUE `CredentialRequest`.
        pub credential_request: B64,
    }
}

dto! {
    /// `POST /v1/auth/reauth/finish`
    pub struct ReauthFinishRequest {
        /// From `reauth/start`.
        pub login_id: B64,
        /// OPAQUE `CredentialFinalization`.
        pub credential_finalization: B64,
        /// Required when TOTP is enabled.
        pub totp_code: Option<String>,
    }
}

dto! {
    /// Proof of a fresh password check, needed to change credentials.
    pub struct ReauthGrant {
        /// Authorises one credential change. Valid for 5 minutes.
        pub reauth_token: B64,
        /// Challenge the account identity key signs with the change.
        pub challenge: B64,
        /// Identity private key wrapped under the current OPAQUE export key.
        pub wrapped_password_copy: B64,
    }
}

dto! {
    /// `POST /v1/account/password/start`
    pub struct PasswordStartRequest {
        /// From `reauth/finish`.
        pub reauth_token: B64,
        /// OPAQUE `RegistrationRequest` for the new password.
        pub registration_request: B64,
    }
}

dto! {
    /// `POST /v1/account/password/finish`
    pub struct PasswordFinishRequest {
        /// From `reauth/finish`.
        pub reauth_token: B64,
        /// OPAQUE `RegistrationUpload` for the new password.
        pub registration_upload: B64,
        /// Identity private key wrapped under the new export key.
        pub wrapped_password_copy: B64,
        /// Account identity key signature authorising the change.
        pub signature: B64,
    }
}

dto! {
    /// `POST /v1/account/recovery-key`
    pub struct RotateRecoveryKeyRequest {
        /// From `reauth/finish`.
        pub reauth_token: B64,
        /// Identity private key wrapped under the new recovery key.
        pub wrapped_recovery_copy: B64,
        /// Account identity key signature authorising the change.
        pub signature: B64,
    }
}

dto! {
    /// `POST /v1/auth/recover/start`
    pub struct RecoverStartRequest {
        /// Canonical handle.
        pub handle: String,
        /// OPAQUE `RegistrationRequest` for the new password.
        pub registration_request: B64,
    }
}

dto! {
    /// Answer to `recover/start`. Identical in shape for unknown handles.
    pub struct RecoverStartResponse {
        /// Identifies this exchange in `recover/finish`. Valid for 5 minutes.
        pub recovery_id: B64,
        /// Challenge the account identity key signs with the change.
        pub challenge: B64,
        /// Account identity public key.
        pub identity_key: B64,
        /// Identity private key wrapped under the recovery key.
        pub wrapped_recovery_copy: B64,
        /// OPAQUE `RegistrationResponse` for the new password.
        pub registration_response: B64,
        /// OPAQUE suite to use.
        pub opaque_suite: u16,
    }
}

dto! {
    /// `POST /v1/auth/recover/finish`
    pub struct RecoverFinishRequest {
        /// From `recover/start`.
        pub recovery_id: B64,
        /// OPAQUE `RegistrationUpload` for the new password.
        pub registration_upload: B64,
        /// Identity private key wrapped under the new export key.
        pub wrapped_password_copy: B64,
        /// Account identity key signature authorising the change.
        pub signature: B64,
    }
}

// --- KeyPackages (ADR 0019, section 3) --------------------------------------------

dto! {
    /// `POST /v1/devices/me/key-packages`
    pub struct UploadKeyPackagesRequest {
        /// One-time KeyPackages of this device, at most 100.
        pub key_packages: Vec<B64>,
        /// A new last-resort KeyPackage, which replaces the current one.
        pub last_resort: Option<B64>,
    }
}

dto! {
    /// Answer to the upload and to `GET /v1/devices/me/key-packages/count`.
    pub struct KeyPackageCount {
        /// One-time KeyPackages of this device that the server can still serve.
        pub one_time: u32,
    }
}

dto! {
    /// A KeyPackage served by a claim.
    pub struct DeviceKeyPackage {
        /// The device the server says it is for. The claimer checks it
        /// against the device certificate, which is in the package's
        /// credential.
        pub device_id: Uuid,
        /// The KeyPackage.
        pub key_package: B64,
    }
}

dto! {
    /// Answer to `POST /v1/users/{user_id}/key-packages/claim`.
    pub struct KeyPackageClaim {
        /// One KeyPackage for each active device of the user that has one,
        /// the requesting device excepted. A device with none is absent: it
        /// joins later by external commit.
        pub key_packages: Vec<DeviceKeyPackage>,
    }
}

// --- Friends and blocks (ADR 0020) ---------------------------------------------

dto! {
    /// Another user, as the friend list shows them.
    pub struct UserSummary {
        /// The user.
        pub user_id: Uuid,
        /// Canonical handle.
        pub handle: String,
        /// Display name.
        pub display_name: String,
        /// Account identity public key, which the client pins when the
        /// friendship is accepted (ADR 0019, section 10).
        pub identity_key: B64,
        /// When the friendship was accepted, the request sent, or the block
        /// made.
        pub since_ms: u64,
    }
}

dto! {
    /// Answer to `GET /v1/friends`.
    pub struct FriendList {
        /// Friends.
        pub friends: Vec<UserSummary>,
        /// Requests other users sent this user, waiting for an answer.
        pub received: Vec<UserSummary>,
        /// Requests this user sent, waiting for an answer.
        pub sent: Vec<UserSummary>,
        /// Users this user blocks.
        pub blocked: Vec<UserSummary>,
    }
}

dto! {
    /// `POST /v1/friends/requests`
    pub struct FriendRequest {
        /// Canonical handle of the user to befriend.
        pub handle: String,
    }
}

/// Where a relation stands after a friend request.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOutcome {
    /// The request waits for the other user's answer.
    RequestSent,
    /// The other user had sent a request already: both are now friends.
    Friends,
}

dto! {
    /// Answer to `POST /v1/friends/requests`.
    pub struct FriendRequestAnswer {
        /// The user the request is for.
        pub user_id: Uuid,
        /// What the request led to.
        pub outcome: RequestOutcome,
    }
}

// --- Conversations (ADR 0019, section 4) ------------------------------------------

/// What a conversation is.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationKind {
    /// A direct conversation between two users.
    Dm,
}

dto! {
    /// `POST /v1/conversations`: the DM with a friend.
    pub struct CreateDmRequest {
        /// The friend.
        pub user_id: Uuid,
    }
}

dto! {
    /// A conversation of the user.
    pub struct Conversation {
        /// The conversation.
        pub conversation_id: Uuid,
        /// What it is.
        pub kind: ConversationKind,
        /// Its members, smaller id first.
        pub members: Vec<Uuid>,
        /// The generation of its MLS group, `null` while it has none.
        pub generation: Option<u32>,
        /// The current epoch of its MLS group, `null` while it has none:
        /// any active device of a member may then create the group.
        pub epoch: Option<u64>,
        /// The last sequence number assigned in it.
        pub last_seq: u64,
        /// A DM whose users are not friends any more: kept, with its
        /// history, but nothing new can be sent in it.
        pub read_only: bool,
        /// Whether the requesting device is in its MLS group, and not being
        /// removed from it. `false` for a device left out of the group (one
        /// enrolled after it was created, one back after an inactivity): it
        /// joins by external commit, in a DM that is not read-only.
        pub joined: bool,
    }
}

dto! {
    /// Answer to `GET /v1/conversations`.
    pub struct ConversationList {
        /// Oldest first.
        pub conversations: Vec<Conversation>,
    }
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
    fn version_response_omits_what_the_instance_does_not_report() {
        let body = VersionResponse {
            name: "tavern".to_owned(),
            version: "0.0.1".to_owned(),
            rest: RestVersion { major: 1, minor: 1 },
            gateway: GatewayVersions {
                min_major: 1,
                max_major: 1,
                minor: 0,
            },
            mls_external_sender_key: B64(vec![1, 2, 3]),
            source_url: None,
            commit: None,
        };

        let json = serde_json::to_string(&body).unwrap();

        assert!(!json.contains("source_url"));
        assert!(!json.contains("commit"));
        assert_eq!(
            serde_json::from_str::<VersionResponse>(&json).unwrap(),
            body
        );
    }

    #[test]
    fn a_version_answer_without_rest_version_reads_as_zero() {
        // What a server older than REST 1.1 sends.
        let json = r#"{"name":"tavern","version":"0.0.1",
            "gateway":{"min_major":1,"max_major":1,"minor":0},
            "mls_external_sender_key":"AQID"}"#;

        let body: VersionResponse = serde_json::from_str(json).unwrap();

        assert_eq!(body.rest, RestVersion { major: 0, minor: 0 });
    }

    #[test]
    fn bytes_travel_as_unpadded_base64url() {
        let json = serde_json::to_string(&B64(vec![0xfb, 0xff, 0xfe])).unwrap();

        assert_eq!(json, r#""-__-""#);
        assert_eq!(
            serde_json::from_str::<B64>(&json).unwrap(),
            B64(vec![0xfb, 0xff, 0xfe])
        );
        assert!(serde_json::from_str::<B64>(r#""-__-==""#).is_err());
        assert!(serde_json::from_str::<B64>(r#""+//+""#).is_err());
        assert!(serde_json::from_str::<B64>("12").is_err());
    }

    #[test]
    fn bytes_do_not_appear_in_debug_output() {
        assert_eq!(format!("{:?}", B64(vec![0xAA; 32])), "B64(<32 bytes>)");
    }

    #[test]
    fn login_outcome_is_tagged_by_status() {
        let json = serde_json::to_string(&LoginOutcome::TotpRequired).unwrap();
        assert_eq!(json, r#"{"status":"totp_required"}"#);

        let grant = LoginGrant {
            user_id: Uuid::nil(),
            handle: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            is_admin: false,
            enrolment_token: B64(vec![1]),
            session_nonce: B64(vec![2]),
            identity_key: B64(vec![3]),
            wrapped_password_copy: B64(vec![4]),
        };
        let json = serde_json::to_string(&LoginOutcome::Ok(grant.clone())).unwrap();
        assert!(json.starts_with(r#"{"status":"ok","user_id":"#));
        assert_eq!(
            serde_json::from_str::<LoginOutcome>(&json).unwrap(),
            LoginOutcome::Ok(grant)
        );
    }

    #[test]
    fn error_codes_use_screaming_snake_case() {
        let body = ErrorBody {
            code: ErrorCode::InvalidCredentials,
            message: "nope".to_owned(),
            retry_after_ms: None,
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"code":"INVALID_CREDENTIALS","message":"nope"}"#
        );
    }

    #[test]
    fn platform_database_values_round_trip() {
        for platform in [Platform::Windows, Platform::Macos, Platform::Linux] {
            assert_eq!(Platform::from_db(platform.to_db()), Some(platform));
        }
        assert_eq!(Platform::from_db(0), None);
    }
}
