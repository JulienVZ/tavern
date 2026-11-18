// SPDX-License-Identifier: AGPL-3.0-or-later

//! Accounts: registration, login, device enrolment and the signed-in client.
//!
//! All key handling happens here, never in the user interface. The password
//! is consumed by OPAQUE and never sent. The account root secret, and the
//! identity key derived from it, exist in memory only for the time of a
//! sign-in or a credential change.
//!
//! One computer keeps one device per account (ADR 0017): signing out keeps
//! the device, so signing in again finds it and its local store.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::Method;
use tavern_crypto::identity::{
    AccountRootSecret, CredentialUpdate, CredentialUpdatePurpose, DeviceKey, IdentityPublicKey,
    SessionChallenge, WrappingKey,
};
use tavern_crypto::local_store::{self, StoreKeyParts};
use tavern_crypto::mls::key_package;
use tavern_crypto::mls::{ClaimedKeyPackage, Roster, VerifiedLeaf};
use tavern_crypto::opaque::client::{Login, Registration};
use tavern_crypto::opaque::{ExportKey, Password};
use tavern_crypto::recovery::RecoveryKey;
use tavern_crypto::secret::Secret;
use tavern_protocol::handle::Handle;
use tavern_protocol::rest::{
    AdminUserList, B64, CreateInviteRequest, CreatedInvite, DeviceList, EnrolDeviceRequest,
    ErrorCode, FriendList, FriendRequest, FriendRequestAnswer, InviteList, KeyPackageClaim,
    KeyPackageCount, LoginFinishRequest, LoginGrant, LoginOutcome, LoginStartRequest,
    LoginStartResponse, LoginTotpRequest, Me, PasswordFinishRequest, PasswordStartRequest,
    Platform, ReauthFinishRequest, ReauthGrant, ReauthStartRequest, RecoverFinishRequest,
    RecoverStartRequest, RecoverStartResponse, RegisterFinishRequest, RegisterFinishResponse,
    RegisterStartRequest, RegistrationResponse, ReopenSessionRequest, RotateRecoveryKeyRequest,
    SessionResponse, TotpCodeRequest, TotpEnrolment, TotpRecoveryCodes, UploadKeyPackagesRequest,
};
use uuid::Uuid;

use crate::api::{Api, Auth};
use crate::error::ClientError;
use crate::gateway::Gateway;
use crate::instance::InstanceUrl;
use crate::local::{AccountDirectory, Binding, LocalStore};
use crate::password;
use crate::store::{KnownAccounts, Records, SecretStore, StoredDevice};

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
    records: Records,
    /// Where the local stores of this computer live.
    local_root: Arc<PathBuf>,
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
    /// `true` when the device was known but its local store could no longer
    /// be opened: the instance lost its part of the key (for instance after
    /// an old backup was restored), or the file was damaged or deleted. The
    /// store starts empty again, and the interface must say that the local
    /// history is gone.
    pub store_reset: bool,
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
            LoginOutcome::TotpRequired => Err(ClientError::ServerError),
        }
    }
}

impl InstanceClient {
    /// Prepares to talk to an instance. `local_root` is the directory of this
    /// computer's local stores (the application's local data directory).
    /// `profile` separates several accounts on one computer; pass `None`
    /// normally.
    pub fn new(
        instance: InstanceUrl,
        store: Arc<dyn SecretStore>,
        local_root: &Path,
        profile: Option<&str>,
    ) -> Result<Self, ClientError> {
        let records = Records::new(store, instance.as_str(), profile);
        Ok(Self {
            api: Api::new(instance)?,
            records,
            local_root: Arc::new(local_root.to_owned()),
        })
    }

    /// The directory of an account's local store on this computer.
    fn account_directory(&self, user_id: Uuid) -> AccountDirectory {
        AccountDirectory(
            self.local_root
                .join("accounts")
                .join(local_store::directory_name(
                    self.records.scope(),
                    user_id.as_bytes(),
                )),
        )
    }

    /// Opens the local store of a signed-in account (see
    /// [`AccountDirectory::open`]) and records that this device has one.
    /// Returns the store and whether it had to start empty.
    async fn open_local_store(
        &self,
        device: &StoredDevice,
        store_key: &Arc<Secret<32>>,
        fresh: bool,
    ) -> Result<(LocalStore, bool), ClientError> {
        let directory = self.account_directory(device.user_id);
        let key = Arc::clone(store_key);
        let binding = Binding {
            user_id: device.user_id,
            device_id: device.device_id,
        };
        let existed = device.local_store_created;
        let opened =
            blocking(move || directory.open(&key, binding, fresh, existed, now_ms())).await??;
        if !existed {
            let mut device = device.clone();
            device.local_store_created = true;
            self.records.update_device(&device)?;
        }
        Ok((opened.store, opened.reset))
    }

    /// Deletes an account's local store from this computer, after its device
    /// was revoked: nothing can open it any more. A failure is only logged:
    /// the files are unreadable, and the next new store replaces them.
    async fn remove_local_store(&self, user_id: Uuid) {
        let directory = self.account_directory(user_id);
        match blocking(move || directory.remove()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "could not delete a revoked local store"),
            Err(error) => tracing::warn!(%error, "could not delete a revoked local store"),
        }
    }

    /// The instance this client talks to.
    pub fn instance(&self) -> &InstanceUrl {
        self.api.instance()
    }

    /// The accounts that have a device on this computer for this instance,
    /// to offer them at sign-in.
    pub fn known_accounts(&self) -> Result<KnownAccounts, ClientError> {
        self.records.known()
    }

    /// The handle last used on this computer for this instance, if any.
    pub fn remembered_handle(&self) -> Result<Option<String>, ClientError> {
        Ok(self.records.last_device()?.map(|device| device.handle))
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

        // The root secret is created here and leaves this function only
        // wrapped; the identity key is derived from it.
        let root = AccountRootSecret::generate();
        let identity = root.identity_key()?;
        let recovery_key = RecoveryKey::generate();
        let request = RegisterFinishRequest {
            invite_code: input.invite_code.to_owned(),
            handle: handle.as_str().to_owned(),
            display_name: input.display_name.to_owned(),
            registration_upload: B64(output.upload),
            identity_key: B64::from(identity.public().to_bytes()),
            wrapped_password_copy: B64(
                root.wrap(&WrappingKey::from_export_key(&output.export_key)?)?
            ),
            wrapped_recovery_copy: B64(root.wrap(&WrappingKey::from_recovery_key(&recovery_key)?)?),
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
    /// device is already enrolled for the account, enrols it otherwise. Either
    /// way the key of the local store ends up in memory and in the record.
    async fn complete_login(
        &self,
        grant: LoginGrant,
        export_key: &ExportKey,
    ) -> Result<SignedIn, ClientError> {
        let expected = IdentityPublicKey::from_bytes(grant.identity_key.as_slice())
            .map_err(|_| ClientError::UntrustedKeyMaterial)?;
        // Erased when this function returns.
        let root = AccountRootSecret::unwrap(
            grant.wrapped_password_copy.as_slice(),
            &WrappingKey::from_export_key(export_key)?,
            &expected,
        )
        .map_err(|error| {
            ClientError::from_wrapped_root(error, ClientError::UntrustedKeyMaterial)
        })?;

        let known = self.records.device(grant.user_id)?;
        let (session, device_seed, wrapped, new_device, store_created) = match known {
            Some(device) => {
                let seed =
                    Secret::<32>::from_slice(device.device_seed.as_slice()).ok_or_else(|| {
                        ClientError::Store("stored device key is malformed".to_owned())
                    })?;
                match self.reopen(&grant, device.device_id, &seed).await {
                    Ok(session) => (
                        session,
                        device.device_seed,
                        Some(device.wrapped_store_key),
                        false,
                        device.local_store_created,
                    ),
                    Err(error) => {
                        if error.api_code() == Some(ErrorCode::InvalidProof) {
                            // The device was revoked. Forget it: the next
                            // login enrols this computer as a new device.
                            self.records.forget_device(grant.user_id)?;
                            self.remove_local_store(grant.user_id).await;
                            return Err(ClientError::DeviceRevoked);
                        }
                        return Err(error);
                    }
                }
            }
            None => {
                let (session, seed) = self.enrol(&grant, &root).await?;
                (session, B64::from(*seed.expose()), None, true, false)
            }
        };

        // The key of the local store: opened with the account's part and the
        // server's, or created with the device.
        let server_part = Secret::<32>::from_slice(session.local_store_share.as_slice())
            .ok_or(ClientError::ServerError)?;
        let account_part =
            root.local_store_part(grant.user_id.as_bytes(), session.device_id.as_bytes())?;
        let parts = StoreKeyParts {
            account_part: &account_part,
            server_part: &server_part,
            user_id: grant.user_id.as_bytes(),
            device_id: session.device_id.as_bytes(),
        };
        let opened = wrapped
            .as_ref()
            .and_then(|wrapped| parts.unwrap(wrapped.as_slice()).ok());
        let key_reset = wrapped.is_some() && opened.is_none();
        let (store_key, wrapped_store_key) = match (opened, wrapped) {
            (Some(store_key), Some(wrapped)) => (store_key, wrapped),
            _ => {
                let store_key = Secret::<32>::random();
                let wrapped = B64(parts.wrap(&store_key)?);
                (store_key, wrapped)
            }
        };

        let device = StoredDevice {
            user_id: grant.user_id,
            handle: grant.handle.clone(),
            device_id: session.device_id,
            device_seed,
            wrapped_store_key,
            session_token: Some(session.session_token.clone()),
            store_key: Some(B64::from(*store_key.expose())),
            // A new key cannot open what a store had before.
            local_store_created: store_created && !key_reset,
        };
        // Saved before the store is opened: if that fails, the next start
        // resumes this session and tries again, instead of enrolling anew.
        self.records.save_device(&device)?;
        let store_key = Arc::new(store_key);
        let (local, store_reset) = self
            .open_local_store(&device, &store_key, new_device || key_reset)
            .await?;
        Ok(SignedIn {
            client: Client {
                instance: self.clone(),
                user_id: grant.user_id,
                device_id: session.device_id,
                session_token: session.session_token,
                store_key,
                local,
            },
            new_device,
            store_reset: key_reset || store_reset,
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
            .map_err(|_| ClientError::ServerError)?;
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

    /// Enrols this computer as a new device: derives the account identity
    /// key, certifies a fresh device key with it, and lets the identity key
    /// go out of scope, which erases it.
    async fn enrol(
        &self,
        grant: &LoginGrant,
        root: &AccountRootSecret,
    ) -> Result<(SessionResponse, Secret<32>), ClientError> {
        let identity = root.identity_key()?;

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
            return Err(ClientError::ServerError);
        }
        Ok((session, device_key.seed()))
    }

    /// Sets a new password with the recovery key, for a user who forgot
    /// theirs. Every session of the account ends; TOTP stays as it was.
    ///
    /// A malformed key, a key that does not belong to the account and an
    /// unknown handle all give [`ClientError::InvalidRecoveryKey`]. An
    /// account whose keys are in a retired format gives
    /// [`ClientError::AccountTooOld`].
    pub async fn recover(
        &self,
        handle: &str,
        recovery_key: &str,
        new_password: &str,
    ) -> Result<(), ClientError> {
        let handle = Handle::canonicalize(handle).map_err(|_| ClientError::InvalidRecoveryKey)?;
        let recovery_key =
            RecoveryKey::parse(recovery_key).map_err(|_| ClientError::InvalidRecoveryKey)?;
        password::check(new_password, &[handle.as_str()]).map_err(ClientError::WeakPassword)?;
        let password = Password::new(new_password);

        let (state, request) = Registration::start(&password)?;
        let start: RecoverStartResponse = self
            .api
            .call(
                Method::POST,
                "v1/auth/recover/start",
                Auth::None,
                &RecoverStartRequest {
                    handle: handle.as_str().to_owned(),
                    registration_request: B64(request),
                },
            )
            .await?;

        // For an unknown handle the instance returns decoys, which no key opens.
        let expected = IdentityPublicKey::from_bytes(start.identity_key.as_slice())
            .map_err(|_| ClientError::InvalidRecoveryKey)?;
        let root = AccountRootSecret::unwrap(
            start.wrapped_recovery_copy.as_slice(),
            &WrappingKey::from_recovery_key(&recovery_key)?,
            &expected,
        )
        .map_err(|error| ClientError::from_wrapped_root(error, ClientError::InvalidRecoveryKey))?;
        let challenge: [u8; 32] = start
            .challenge
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::ServerError)?;

        let finish_handle = handle.clone();
        let registration_response = start.registration_response;
        let output = blocking(move || {
            state.finish(&password, registration_response.as_slice(), &finish_handle)
        })
        .await??;
        // The same root secret, wrapped under the new password: the identity
        // and the local stores of the account's devices are unchanged.
        let wrapped = root.wrap(&WrappingKey::from_export_key(&output.export_key)?)?;
        let signature = root
            .identity_key()?
            .sign_credential_update(&CredentialUpdate {
                purpose: CredentialUpdatePurpose::Recovery,
                challenge: &challenge,
                handle: &handle,
                opaque_upload: &output.upload,
                wrapped_password_copy: &wrapped,
                wrapped_recovery_copy: &[],
            });
        drop(root);

        self.api
            .call_empty(
                Method::POST,
                "v1/auth/recover/finish",
                Auth::None,
                &RecoverFinishRequest {
                    recovery_id: start.recovery_id,
                    registration_upload: B64(output.upload),
                    wrapped_password_copy: B64(wrapped),
                    signature: B64::from(signature),
                },
            )
            .await
            .map_err(|error| match error.api_code() {
                Some(ErrorCode::InvalidProof) => ClientError::InvalidRecoveryKey,
                _ => error,
            })
    }

    /// Resumes the session of the account used last on this computer, if it
    /// is still valid, and opens its local store. Needs neither the password
    /// nor, for the store, the instance's part of the key: a signed-in
    /// account keeps its store key in the record. Never a new device.
    pub async fn resume(&self) -> Result<Option<SignedIn>, ClientError> {
        let Some(mut device) = self.records.last_device()? else {
            return Ok(None);
        };
        let (Some(session_token), Some(store_key)) = (
            device.session_token.clone(),
            device
                .store_key
                .as_ref()
                .and_then(|key| Secret::<32>::from_slice(key.as_slice())),
        ) else {
            return Ok(None);
        };
        let me: Result<Me, ClientError> = self
            .api
            .fetch("v1/users/me", Auth::Session(&session_token))
            .await;
        match me {
            Ok(_) => {}
            Err(ClientError::SessionEnded) => {
                // Same as signing out: the device key stays, so the next
                // login reopens this device; the store key goes.
                device.sign_out();
                self.records.update_device(&device)?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        let store_key = Arc::new(store_key);
        let (local, store_reset) = self.open_local_store(&device, &store_key, false).await?;
        Ok(Some(SignedIn {
            client: Client {
                instance: self.clone(),
                user_id: device.user_id,
                device_id: device.device_id,
                session_token,
                store_key,
                local,
            },
            new_device: false,
            store_reset,
        }))
    }
}

/// Proof of a fresh password check, holding the account root secret in
/// memory for the one credential change it authorises. Erased when dropped.
pub struct Reauthenticated {
    handle: Handle,
    display_name: String,
    root: AccountRootSecret,
    challenge: [u8; 32],
    token: B64,
}

impl std::fmt::Debug for Reauthenticated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reauthenticated(<redacted>)")
    }
}

/// A signed-in device.
#[derive(Clone)]
pub struct Client {
    instance: InstanceClient,
    user_id: Uuid,
    device_id: Uuid,
    session_token: B64,
    /// Key of this device's local store.
    store_key: Arc<Secret<32>>,
    /// The local store, open while signed in.
    local: LocalStore,
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

    /// The key of this device's local store. It is the same after signing
    /// out and back in, and unknown to the instance.
    pub fn local_store_key(&self) -> &Secret<32> {
        &self.store_key
    }

    /// This device's local store for the account. Closed by signing out.
    pub fn local_store(&self) -> &LocalStore {
        &self.local
    }

    /// The signed-in account, as the instance sees it.
    pub async fn me(&self) -> Result<Me, ClientError> {
        self.api().fetch("v1/users/me", self.auth()).await
    }

    /// The active devices of the account.
    pub async fn devices(&self) -> Result<DeviceList, ClientError> {
        self.api().fetch("v1/devices", self.auth()).await
    }

    /// Uploads one-time KeyPackages of this device and, optionally, a new
    /// last-resort one, which replaces the current one (ADR 0019, section
    /// 3). Returns how many one-time packages the instance can still serve.
    pub async fn upload_key_packages(
        &self,
        one_time: Vec<Vec<u8>>,
        last_resort: Option<Vec<u8>>,
    ) -> Result<u32, ClientError> {
        let request = UploadKeyPackagesRequest {
            key_packages: one_time.into_iter().map(B64).collect(),
            last_resort: last_resort.map(B64),
        };
        let count: KeyPackageCount = self
            .api()
            .call(
                Method::POST,
                "v1/devices/me/key-packages",
                self.auth(),
                &request,
            )
            .await?;
        Ok(count.one_time)
    }

    /// How many one-time KeyPackages of this device the instance can still
    /// serve.
    pub async fn key_package_count(&self) -> Result<u32, ClientError> {
        let count: KeyPackageCount = self
            .api()
            .fetch("v1/devices/me/key-packages/count", self.auth())
            .await?;
        Ok(count.one_time)
    }

    /// Claims a KeyPackage for each active device of `user_id` (this device
    /// excepted), and checks each one against the identity key this device
    /// trusts for that user (`roster`) and the device the instance named for
    /// it. Only a [`ClaimedKeyPackage`] can be added to a group. A package
    /// that fails the checks fails the claim: the instance returned key
    /// material that does not verify.
    pub async fn claim_key_packages(
        &self,
        user_id: Uuid,
        roster: &impl Roster,
    ) -> Result<Vec<ClaimedKeyPackage>, ClientError> {
        let claim: KeyPackageClaim = self
            .api()
            .call_without_body(
                Method::POST,
                &format!("v1/users/{user_id}/key-packages/claim"),
                self.auth(),
            )
            .await?;
        claim
            .key_packages
            .into_iter()
            .map(|served| {
                let device = VerifiedLeaf {
                    user_id: *user_id.as_bytes(),
                    device_id: *served.device_id.as_bytes(),
                };
                key_package::validate_claimed(served.key_package.as_slice(), device, roster)
                    .map_err(|_| ClientError::UntrustedKeyMaterial)
            })
            .collect()
    }

    /// The user's friends, the requests they received and sent, and the
    /// users they block (ADR 0020).
    pub async fn friends(&self) -> Result<FriendList, ClientError> {
        self.api().fetch("v1/friends", self.auth()).await
    }

    /// Sends a friend request to the user with this handle, as typed. The
    /// instance answers `NOT_FOUND` for a handle no account has, and
    /// `BLOCKED` when this user blocks that one. A request crossing one from
    /// that user makes both friends at once.
    pub async fn send_friend_request(
        &self,
        handle: &str,
    ) -> Result<FriendRequestAnswer, ClientError> {
        let handle = Handle::canonicalize(handle)?;
        let request = FriendRequest {
            handle: handle.as_str().to_owned(),
        };
        self.api()
            .call(Method::POST, "v1/friends/requests", self.auth(), &request)
            .await
    }

    /// Accepts the friend request `user_id` sent.
    pub async fn accept_friend_request(&self, user_id: Uuid) -> Result<(), ClientError> {
        self.api()
            .act(
                Method::POST,
                &format!("v1/friends/requests/{user_id}/accept"),
                self.auth(),
            )
            .await
    }

    /// Declines the request `user_id` sent, or cancels the one sent to them.
    pub async fn remove_friend_request(&self, user_id: Uuid) -> Result<(), ClientError> {
        self.api()
            .act(
                Method::DELETE,
                &format!("v1/friends/requests/{user_id}"),
                self.auth(),
            )
            .await
    }

    /// Ends the friendship with `user_id`.
    pub async fn remove_friend(&self, user_id: Uuid) -> Result<(), ClientError> {
        self.api()
            .act(
                Method::DELETE,
                &format!("v1/friends/{user_id}"),
                self.auth(),
            )
            .await
    }

    /// Blocks `user_id`: a friendship or a request between the two ends, and
    /// they cannot reach this user any more. They are not told.
    pub async fn block(&self, user_id: Uuid) -> Result<(), ClientError> {
        self.api()
            .act(Method::PUT, &format!("v1/blocks/{user_id}"), self.auth())
            .await
    }

    /// Lifts the block on `user_id`. What they sent meanwhile is dropped.
    pub async fn unblock(&self, user_id: Uuid) -> Result<(), ClientError> {
        self.api()
            .act(Method::DELETE, &format!("v1/blocks/{user_id}"), self.auth())
            .await
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
            // Its store can never be opened again (the instance erased its
            // part of the key): close it and delete it.
            self.instance.records.forget_device(self.user_id)?;
            self.local.close();
            self.instance.remove_local_store(self.user_id).await;
        }
        Ok(())
    }

    /// Signs out and erases this device: it is revoked on the instance, which
    /// destroys its part of the local store key, and its record and its
    /// local store are deleted from this computer. The next sign-in enrols a
    /// new device, without history. This cannot be undone.
    pub async fn erase_device(self) -> Result<(), ClientError> {
        self.revoke_device(self.device_id).await
    }

    /// Signs out. The device stays enrolled and keeps its key and its wrapped
    /// store key: the next login to this account reopens the same device and
    /// its local store. Until then the store cannot be read.
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

    /// Closes the local store, and removes the session token and the store
    /// key from the record, keeping the device key. Also used when the
    /// instance ended the session.
    pub fn forget_session(&self) -> Result<(), ClientError> {
        self.local.close();
        let records = &self.instance.records;
        if let Some(mut device) = records.device(self.user_id)? {
            device.sign_out();
            records.update_device(&device)?;
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

    // --- Credential changes ---

    /// Proves knowledge of the current password again (and of the second
    /// factor when TOTP is enabled). The result authorises exactly one
    /// credential change and expires after five minutes.
    pub async fn reauthenticate(
        &self,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<Reauthenticated, ClientError> {
        let me = self.me().await?;
        let handle = Handle::canonicalize(&me.handle).map_err(|_| ClientError::ServerError)?;
        let password = Password::new(password);

        let (state, request) = Login::start(&password)?;
        let start: LoginStartResponse = self
            .api()
            .call(
                Method::POST,
                "v1/auth/reauth/start",
                self.auth(),
                &ReauthStartRequest {
                    credential_request: B64(request),
                },
            )
            .await?;
        let finish_handle = handle.clone();
        let credential_response = start.credential_response;
        let output = blocking(move || {
            state.finish(&password, credential_response.as_slice(), &finish_handle)
        })
        .await??;

        let grant: ReauthGrant = self
            .api()
            .call(
                Method::POST,
                "v1/auth/reauth/finish",
                self.auth(),
                &ReauthFinishRequest {
                    login_id: start.login_id,
                    credential_finalization: B64(output.finalization),
                    totp_code: totp_code.map(str::to_owned),
                },
            )
            .await?;

        let expected = IdentityPublicKey::from_bytes(me.identity_key.as_slice())
            .map_err(|_| ClientError::UntrustedKeyMaterial)?;
        let root = AccountRootSecret::unwrap(
            grant.wrapped_password_copy.as_slice(),
            &WrappingKey::from_export_key(&output.export_key)?,
            &expected,
        )
        .map_err(|error| {
            ClientError::from_wrapped_root(error, ClientError::UntrustedKeyMaterial)
        })?;
        let challenge = grant
            .challenge
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::ServerError)?;
        Ok(Reauthenticated {
            handle,
            display_name: me.display_name,
            root,
            challenge,
            token: grant.reauth_token,
        })
    }

    /// Changes the password. Every other device of the account is signed out
    /// and must sign in again with the new password; this device stays in.
    pub async fn change_password(
        &self,
        reauth: Reauthenticated,
        new_password: &str,
    ) -> Result<(), ClientError> {
        password::check(
            new_password,
            &[reauth.handle.as_str(), &reauth.display_name],
        )
        .map_err(ClientError::WeakPassword)?;
        let password = Password::new(new_password);

        let (state, request) = Registration::start(&password)?;
        let response: RegistrationResponse = self
            .api()
            .call(
                Method::POST,
                "v1/account/password/start",
                self.auth(),
                &PasswordStartRequest {
                    reauth_token: reauth.token.clone(),
                    registration_request: B64(request),
                },
            )
            .await?;
        let finish_handle = reauth.handle.clone();
        let output = blocking(move || {
            state.finish(
                &password,
                response.registration_response.as_slice(),
                &finish_handle,
            )
        })
        .await??;

        // The root secret is wrapped again under the new export key.
        let wrapped = reauth
            .root
            .wrap(&WrappingKey::from_export_key(&output.export_key)?)?;
        let identity = reauth.root.identity_key()?;
        let signature = identity.sign_credential_update(&CredentialUpdate {
            purpose: CredentialUpdatePurpose::PasswordChange,
            challenge: &reauth.challenge,
            handle: &reauth.handle,
            opaque_upload: &output.upload,
            wrapped_password_copy: &wrapped,
            wrapped_recovery_copy: &[],
        });
        self.api()
            .call_empty(
                Method::POST,
                "v1/account/password/finish",
                self.auth(),
                &PasswordFinishRequest {
                    reauth_token: reauth.token,
                    registration_upload: B64(output.upload),
                    wrapped_password_copy: B64(wrapped),
                    signature: B64::from(signature),
                },
            )
            .await
    }

    /// Replaces the recovery key. The previous one stops working at once.
    /// The new key must be shown to the user now: it is stored nowhere.
    pub async fn rotate_recovery_key(
        &self,
        reauth: Reauthenticated,
    ) -> Result<RecoveryKey, ClientError> {
        let recovery_key = RecoveryKey::generate();
        let wrapped = reauth
            .root
            .wrap(&WrappingKey::from_recovery_key(&recovery_key)?)?;
        let identity = reauth.root.identity_key()?;
        let signature = identity.sign_credential_update(&CredentialUpdate {
            purpose: CredentialUpdatePurpose::RecoveryKeyRotation,
            challenge: &reauth.challenge,
            handle: &reauth.handle,
            opaque_upload: &[],
            wrapped_password_copy: &[],
            wrapped_recovery_copy: &wrapped,
        });
        self.api()
            .call_empty(
                Method::POST,
                "v1/account/recovery-key",
                self.auth(),
                &RotateRecoveryKeyRequest {
                    reauth_token: reauth.token,
                    wrapped_recovery_copy: B64(wrapped),
                    signature: B64::from(signature),
                },
            )
            .await?;
        Ok(recovery_key)
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
