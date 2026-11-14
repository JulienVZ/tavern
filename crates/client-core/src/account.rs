// SPDX-License-Identifier: AGPL-3.0-or-later

//! Accounts: registration, login, device enrolment and the signed-in client.
//!
//! All key handling happens here, never in the user interface. The password
//! is consumed by OPAQUE and never sent. The account identity key exists in
//! memory only while a device is being certified.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::Method;
use tavern_crypto::identity::{
    AccountIdentityKey, DeviceKey, IdentityPublicKey, SessionChallenge, WrappingKey,
};
use tavern_crypto::opaque::client::{Login, Registration};
use tavern_crypto::opaque::{ExportKey, Password};
use tavern_crypto::recovery::RecoveryKey;
use tavern_crypto::secret::Secret;
use tavern_protocol::handle::Handle;
use tavern_protocol::rest::{
    AdminUserList, B64, CreateInviteRequest, CreatedInvite, DeviceList, EnrolDeviceRequest,
    ErrorCode, InviteList, LoginFinishRequest, LoginGrant, LoginOutcome, LoginStartRequest,
    LoginStartResponse, LoginTotpRequest, Me, Platform, RegisterFinishRequest,
    RegisterFinishResponse, RegisterStartRequest, RegistrationResponse, ReopenSessionRequest,
    SessionResponse, TotpCodeRequest, TotpEnrolment, TotpRecoveryCodes,
};
use uuid::Uuid;

use crate::api::{Api, Auth};
use crate::error::ClientError;
use crate::gateway::Gateway;
use crate::instance::InstanceUrl;
use crate::password;
use crate::store::{SecretStore, StoredDevice, store_key};

/// Runs CPU-heavy work (Argon2id) off the async executor.
async fn blocking<T, F>(work: F) -> Result<T, ClientError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ClientError::Interrupted)
}

fn current_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// One instance, as seen by a device that may or may not be signed in.
#[derive(Clone)]
pub struct InstanceClient {
    api: Api,
    store: Arc<dyn SecretStore>,
    store_key: String,
}

impl std::fmt::Debug for InstanceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceClient")
            .field("instance", self.api.instance())
            .finish()
    }
}

/// What the user typed to register.
#[derive(Debug)]
pub struct NewAccount<'a> {
    /// Invitation code.
    pub invite_code: &'a str,
    /// Handle as typed; it is canonicalised (lower-cased) and validated.
    pub handle: &'a str,
    /// Display name.
    pub display_name: &'a str,
    /// Password.
    pub password: &'a str,
}

/// A new account. The recovery key must be shown to the user now: it is not
/// stored anywhere and cannot be shown again.
#[derive(Debug)]
pub struct Registered {
    /// The account.
    pub user_id: Uuid,
    /// The canonical handle. It cannot be changed later.
    pub handle: Handle,
    /// Whether the invitation made this account an administrator.
    pub is_admin: bool,
    /// The recovery key.
    pub recovery_key: RecoveryKey,
}

/// Where a login stands.
#[derive(Debug)]
pub enum LoginStep {
    /// The password was right; a TOTP code is needed.
    TotpRequired(Box<PendingTotp>),
    /// Signed in.
    Done(Box<SignedIn>),
}

/// A completed login.
#[derive(Debug)]
pub struct SignedIn {
    /// The signed-in client.
    pub client: Client,
    /// `true` when this login enrolled the device. The interface must then
    /// explain that a new device starts without message history.
    pub new_device: bool,
}

/// A login waiting for its TOTP code.
pub struct PendingTotp {
    instance: InstanceClient,
    login_id: B64,
    export_key: ExportKey,
}

impl std::fmt::Debug for PendingTotp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingTotp")
    }
}

impl PendingTotp {
    /// Submits a TOTP code or a TOTP recovery code.
    ///
    /// On a wrong code (`TOTP_INVALID`) the same `PendingTotp` can be used
    /// again. After too many attempts the instance closes the login and
    /// answers `EXCHANGE_EXPIRED`: the user starts over from the password.
    pub async fn submit(&self, code: &str) -> Result<SignedIn, ClientError> {
        let request = LoginTotpRequest {
            login_id: self.login_id.clone(),
            code: code.to_owned(),
        };
        let outcome: LoginOutcome = self
            .instance
            .api
            .call(Method::POST, "v1/auth/login/totp", Auth::None, &request)
            .await?;
        match outcome {
            LoginOutcome::Ok(grant) => self.instance.complete_login(grant, &self.export_key).await,
            LoginOutcome::TotpRequired => Err(ClientError::UnexpectedResponse),
        }
    }
}

impl InstanceClient {
    /// Prepares to talk to an instance. `profile` separates several accounts
    /// on one computer; pass `None` normally.
    pub fn new(
        instance: InstanceUrl,
        store: Arc<dyn SecretStore>,
        profile: Option<&str>,
    ) -> Result<Self, ClientError> {
        let store_key = store_key(instance.as_str(), profile);
        Ok(Self {
            api: Api::new(instance)?,
            store,
            store_key,
        })
    }

    /// The instance this client talks to.
    pub fn instance(&self) -> &InstanceUrl {
        self.api.instance()
    }

    /// The handle last used on this device for this instance, if any.
    pub fn remembered_handle(&self) -> Result<Option<String>, ClientError> {
        Ok(self
            .store
            .load(&self.store_key)?
            .map(|device| device.handle))
    }

    /// Creates an account. Does not sign in: call [`InstanceClient::login`] next.
    ///
    /// Fails with [`ClientError::WeakPassword`] before contacting the
    /// instance when the password does not meet the strength requirement.
    pub async fn register(&self, input: NewAccount<'_>) -> Result<Registered, ClientError> {
        let handle = Handle::canonicalize(input.handle)?;
        password::check(input.password, &[handle.as_str(), input.display_name])
            .map_err(ClientError::WeakPassword)?;
        let password = Password::new(input.password);

        let (state, request) = Registration::start(&password)?;
        let response: RegistrationResponse = self
            .api
            .call(
                Method::POST,
                "v1/auth/register/start",
                Auth::None,
                &RegisterStartRequest {
                    invite_code: input.invite_code.to_owned(),
                    handle: handle.as_str().to_owned(),
                    registration_request: B64(request),
                },
            )
            .await?;

        let finish_handle = handle.clone();
        let output = blocking(move || {
            state.finish(
                &password,
                response.registration_response.as_slice(),
                &finish_handle,
            )
        })
        .await??;

        // The identity is created here and leaves this function only wrapped.
        let identity = AccountIdentityKey::generate();
        let recovery_key = RecoveryKey::generate();
        let request = RegisterFinishRequest {
            invite_code: input.invite_code.to_owned(),
            handle: handle.as_str().to_owned(),
            display_name: input.display_name.to_owned(),
            registration_upload: B64(output.upload),
            identity_key: B64::from(identity.public().to_bytes()),
            wrapped_password_copy: B64(
                identity.wrap(&WrappingKey::from_export_key(&output.export_key)?)?
            ),
            wrapped_recovery_copy: B64(
                identity.wrap(&WrappingKey::from_recovery_key(&recovery_key)?)?
            ),
        };
        let created: RegisterFinishResponse = self
            .api
            .call(
                Method::POST,
                "v1/auth/register/finish",
                Auth::None,
                &request,
            )
            .await?;

        Ok(Registered {
            user_id: created.user_id,
            handle,
            is_admin: created.is_admin,
            recovery_key,
        })
    }

    /// Runs the OPAQUE exchange and returns the instance's answer with the
    /// export key derived from the password.
    async fn opaque_login(
        &self,
        handle: &Handle,
        password: Password,
    ) -> Result<(LoginOutcome, B64, ExportKey), ClientError> {
        let (state, request) = Login::start(&password)?;
        let response: LoginStartResponse = self
            .api
            .call(
                Method::POST,
                "v1/auth/login/start",
                Auth::None,
                &LoginStartRequest {
                    handle: handle.as_str().to_owned(),
                    credential_request: B64(request),
                },
            )
            .await?;

        let finish_handle = handle.clone();
        let credential_response = response.credential_response;
        let output = blocking(move || {
            state.finish(&password, credential_response.as_slice(), &finish_handle)
        })
        .await??;

        let outcome: LoginOutcome = self
            .api
            .call(
                Method::POST,
                "v1/auth/login/finish",
                Auth::None,
                &LoginFinishRequest {
                    login_id: response.login_id.clone(),
                    credential_finalization: B64(output.finalization),
                },
            )
            .await?;
        Ok((outcome, response.login_id, output.export_key))
    }

    /// Signs in. A wrong handle and a wrong password give the same
    /// [`ClientError::InvalidCredentials`].
    pub async fn login(&self, handle: &str, password: &str) -> Result<LoginStep, ClientError> {
        // A handle that cannot exist is reported like a wrong password.
        let handle = Handle::canonicalize(handle).map_err(|_| ClientError::InvalidCredentials)?;
        let (outcome, login_id, export_key) =
            self.opaque_login(&handle, Password::new(password)).await?;
        match outcome {
            LoginOutcome::TotpRequired => Ok(LoginStep::TotpRequired(Box::new(PendingTotp {
                instance: self.clone(),
                login_id,
                export_key,
            }))),
            LoginOutcome::Ok(grant) => self
                .complete_login(grant, &export_key)
                .await
                .map(Box::new)
                .map(LoginStep::Done),
        }
    }

    /// Turns a grant into a session: reopens this device's session when the
    /// device is already enrolled for the account, enrols it otherwise.
    async fn complete_login(
        &self,
        grant: LoginGrant,
        export_key: &ExportKey,
    ) -> Result<SignedIn, ClientError> {
        let known = self
            .store
            .load(&self.store_key)?
            .filter(|device| device.user_id == grant.user_id);

        let (session, device_seed, new_device) = match known {
            Some(device) => {
                let seed =
                    Secret::<32>::from_slice(device.device_seed.as_slice()).ok_or_else(|| {
                        ClientError::Store("stored device key is malformed".to_owned())
                    })?;
                let session = self.reopen(&grant, device.device_id, &seed).await;
                match session {
                    Ok(session) => (session, device.device_seed, false),
                    Err(error) => {
                        if error.api_code() == Some(ErrorCode::InvalidProof) {
                            // The device was revoked. Forget it: the next
                            // login enrols this computer as a new device.
                            self.store.delete(&self.store_key)?;
                            return Err(ClientError::DeviceRevoked);
                        }
                        return Err(error);
                    }
                }
            }
            None => {
                let (session, seed) = self.enrol(&grant, export_key).await?;
                (session, B64::from(*seed.expose()), true)
            }
        };

        self.store.save(
            &self.store_key,
            &StoredDevice {
                user_id: grant.user_id,
                handle: grant.handle.clone(),
                device_id: session.device_id,
                device_seed,
                session_token: Some(session.session_token.clone()),
            },
        )?;
        Ok(SignedIn {
            client: Client {
                instance: self.clone(),
                user_id: grant.user_id,
                device_id: session.device_id,
                session_token: session.session_token,
            },
            new_device,
        })
    }

    async fn reopen(
        &self,
        grant: &LoginGrant,
        device_id: Uuid,
        seed: &Secret<32>,
    ) -> Result<SessionResponse, ClientError> {
        let nonce: [u8; 32] = grant
            .session_nonce
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::UnexpectedResponse)?;
        let proof = DeviceKey::from_seed(seed).sign_session_proof(&SessionChallenge {
            nonce: &nonce,
            user_id: grant.user_id.as_bytes(),
            device_id: device_id.as_bytes(),
        });
        self.api
            .call(
                Method::POST,
                &format!("v1/devices/{device_id}/session"),
                Auth::Grant(&grant.enrolment_token),
                &ReopenSessionRequest {
                    proof: B64::from(proof),
                },
            )
            .await
    }

    /// Enrols this computer as a new device: opens the wrapped account key
    /// with the export key, certifies a fresh device key, and lets the
    /// account key go out of scope, which erases it.
    async fn enrol(
        &self,
        grant: &LoginGrant,
        export_key: &ExportKey,
    ) -> Result<(SessionResponse, Secret<32>), ClientError> {
        let expected = IdentityPublicKey::from_bytes(grant.identity_key.as_slice())
            .map_err(|_| ClientError::UntrustedKeyMaterial)?;
        let identity = AccountIdentityKey::unwrap(
            grant.wrapped_password_copy.as_slice(),
            &WrappingKey::from_export_key(export_key)?,
            &expected,
        )
        .map_err(|_| ClientError::UntrustedKeyMaterial)?;

        let device_key = DeviceKey::generate();
        let device_id = Uuid::new_v4();
        let certificate = identity.certify_device(
            grant.user_id.as_bytes(),
            device_id.as_bytes(),
            &device_key.public(),
            now_ms(),
        );
        drop(identity);

        let session: SessionResponse = self
            .api
            .call(
                Method::POST,
                "v1/devices",
                Auth::Grant(&grant.enrolment_token),
                &EnrolDeviceRequest {
                    certificate: B64(certificate),
                    // Device names are encrypted for the user's own devices,
                    // which needs the MLS self-group of milestone M2.
                    name_encrypted: None,
                    platform: current_platform(),
                },
            )
            .await?;
        if session.device_id != device_id {
            return Err(ClientError::UnexpectedResponse);
        }
        Ok((session, device_key.seed()))
    }

    /// Resumes the session saved on this device, if it is still valid.
    pub async fn resume(&self) -> Result<Option<Client>, ClientError> {
        let Some(mut device) = self.store.load(&self.store_key)? else {
            return Ok(None);
        };
        let Some(session_token) = device.session_token.clone() else {
            return Ok(None);
        };
        let client = Client {
            instance: self.clone(),
            user_id: device.user_id,
            device_id: device.device_id,
            session_token,
        };
        match client.me().await {
            Ok(_) => Ok(Some(client)),
            Err(ClientError::SessionEnded) => {
                // Keep the device key: the next login reopens the session
                // instead of enrolling this computer again.
                device.session_token = None;
                self.store.save(&self.store_key, &device)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

/// A signed-in device.
#[derive(Clone)]
pub struct Client {
    instance: InstanceClient,
    user_id: Uuid,
    device_id: Uuid,
    session_token: B64,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl Client {
    fn auth(&self) -> Auth<'_> {
        Auth::Session(&self.session_token)
    }

    fn api(&self) -> &Api {
        &self.instance.api
    }

    /// The account.
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// This device.
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// The signed-in account, as the instance sees it.
    pub async fn me(&self) -> Result<Me, ClientError> {
        self.api().fetch("v1/users/me", self.auth()).await
    }

    /// The active devices of the account.
    pub async fn devices(&self) -> Result<DeviceList, ClientError> {
        self.api().fetch("v1/devices", self.auth()).await
    }

    /// Revokes a device of the account. Revoking this device signs it out.
    pub async fn revoke_device(&self, device_id: Uuid) -> Result<(), ClientError> {
        self.api()
            .act(
                Method::DELETE,
                &format!("v1/devices/{device_id}"),
                self.auth(),
            )
            .await?;
        if device_id == self.device_id {
            self.instance.store.delete(&self.instance.store_key)?;
        }
        Ok(())
    }

    /// Signs out. The device stays enrolled: the next login reopens its session.
    pub async fn logout(self) -> Result<(), ClientError> {
        let result = self
            .api()
            .act(Method::POST, "v1/auth/logout", self.auth())
            .await;
        self.forget_session()?;
        match result {
            Ok(()) | Err(ClientError::SessionEnded) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Removes the session token from the store, keeping the device key.
    pub fn forget_session(&self) -> Result<(), ClientError> {
        let store = &self.instance.store;
        if let Some(mut device) = store.load(&self.instance.store_key)? {
            device.session_token = None;
            store.save(&self.instance.store_key, &device)?;
        }
        Ok(())
    }

    /// Opens the real-time connection of this device.
    pub fn connect_gateway(
        &self,
    ) -> Result<
        (
            Gateway,
            tokio::sync::mpsc::Receiver<crate::gateway::GatewayEvent>,
        ),
        ClientError,
    > {
        Gateway::start(
            self.api().instance().gateway_url()?,
            self.session_token.clone(),
        )
    }

    // --- TOTP ---

    /// Starts enabling TOTP. Returns the secret to show as text and QR code.
    pub async fn totp_enable(&self) -> Result<TotpEnrolment, ClientError> {
        self.api()
            .call(Method::POST, "v1/account/totp/enable", self.auth(), &())
            .await
    }

    /// Confirms TOTP with a first code. Returns the recovery codes, to be
    /// shown once.
    pub async fn totp_confirm(&self, code: &str) -> Result<TotpRecoveryCodes, ClientError> {
        let request = TotpCodeRequest {
            code: code.to_owned(),
        };
        self.api()
            .call(
                Method::POST,
                "v1/account/totp/confirm",
                self.auth(),
                &request,
            )
            .await
    }

    /// Disables TOTP with a current code or a recovery code.
    pub async fn totp_disable(&self, code: &str) -> Result<(), ClientError> {
        let request = TotpCodeRequest {
            code: code.to_owned(),
        };
        self.api()
            .call_empty(
                Method::POST,
                "v1/account/totp/disable",
                self.auth(),
                &request,
            )
            .await
    }

    // --- Administration ---

    /// Creates an invitation code (administrators only).
    pub async fn create_invite(
        &self,
        max_uses: Option<u32>,
        expires_in_hours: Option<u32>,
    ) -> Result<CreatedInvite, ClientError> {
        let request = CreateInviteRequest {
            max_uses,
            expires_in_hours,
        };
        self.api()
            .call(Method::POST, "v1/admin/invites", self.auth(), &request)
            .await
    }

    /// Lists invitations (administrators only).
    pub async fn invites(&self) -> Result<InviteList, ClientError> {
        self.api().fetch("v1/admin/invites", self.auth()).await
    }

    /// Revokes an invitation (administrators only).
    pub async fn revoke_invite(&self, invite_id: Uuid) -> Result<(), ClientError> {
        self.api()
            .act(
                Method::DELETE,
                &format!("v1/admin/invites/{invite_id}"),
                self.auth(),
            )
            .await
    }

    /// Lists the accounts of the instance (administrators only).
    pub async fn users(&self) -> Result<AdminUserList, ClientError> {
        self.api().fetch("v1/admin/users", self.auth()).await
    }

    /// Disables or re-enables an account (administrators only).
    pub async fn set_user_disabled(
        &self,
        user_id: Uuid,
        disabled: bool,
    ) -> Result<(), ClientError> {
        let action = if disabled { "disable" } else { "enable" };
        self.api()
            .act(
                Method::POST,
                &format!("v1/admin/users/{user_id}/{action}"),
                self.auth(),
            )
            .await
    }

    /// Disables the TOTP of a user who lost their authenticator and recovery
    /// codes (administrators only). The user's devices are notified.
    pub async fn disable_user_totp(&self, user_id: Uuid) -> Result<(), ClientError> {
        self.api()
            .act(
                Method::POST,
                &format!("v1/admin/users/{user_id}/totp/disable"),
                self.auth(),
            )
            .await
    }
}
