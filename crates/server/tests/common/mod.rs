// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared harness for the integration tests: starts the server on an
//! ephemeral port against a real PostgreSQL database and plays the client
//! side of the protocol with `tavern-crypto`.
//!
//! The tests share one database. Each uses its own random handles, so they
//! can run in parallel and be re-run without cleaning up.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    dead_code,
    reason = "test helpers panic on failure, and not every test file uses every helper"
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use openmls_memory_storage::MemoryStorage;
use reqwest::StatusCode;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tavern_crypto::identity::{
    AccountIdentityKey, AccountRootSecret, DeviceKey, SessionChallenge, WrappingKey,
};
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::{DeviceSigner, Provider, key_package};
use tavern_crypto::opaque::Password;
use tavern_crypto::opaque::client::{Login, Registration};
use tavern_crypto::recovery::RecoveryKey;
use tavern_crypto::token;
use tavern_protocol::handle::Handle;
use tavern_protocol::rest::*;
use tavern_server::secrets::InstanceSecrets;
use tavern_server::{AppState, Settings, app, db, routes};
use tokio::net::TcpListener;
use uuid::Uuid;

pub const DATABASE_URL_VAR: &str = "TAVERN_TEST_DATABASE_URL";

/// The URL of the test database, from `TAVERN_TEST_DATABASE_URL`.
///
/// Tests create accounts by the hundred and rewrite rows at will, so they
/// refuse any database whose name does not end in `_test`: the database of a
/// development stack, with the accounts used for manual testing, is never
/// touched. `deploy/scripts/test-db.sh` creates one and prints its URL.
pub fn database_url() -> String {
    let url = std::env::var(DATABASE_URL_VAR)
        .unwrap_or_else(|_| panic!("{DATABASE_URL_VAR} must be set to run this test"));
    let name = url
        .rsplit('/')
        .next()
        .and_then(|rest| rest.split('?').next())
        .unwrap_or_default();
    assert!(
        name.ends_with("_test"),
        "{DATABASE_URL_VAR} names the database \"{name}\": tests only run on a database \
         whose name ends in _test (see deploy/scripts/test-db.sh)"
    );
    url
}
pub const PASSWORD: &str = "correct horse battery staple";

/// A running server and an HTTP client pointed at it.
pub struct TestApp {
    pub addr: SocketAddr,
    pub state: AppState,
    http: reqwest::Client,
}

/// A registered account, with what its owner knows.
pub struct Account {
    pub user_id: Uuid,
    pub handle: Handle,
    pub identity: AccountIdentityKey,
    pub recovery_key: RecoveryKey,
}

/// An enrolled device and its session.
pub struct Device {
    pub device_id: Uuid,
    pub key: DeviceKey,
    /// The certificate it enrolled with.
    pub certificate: Vec<u8>,
    pub session_token: B64,
}

impl Device {
    /// A KeyPackage of this device, built as its client would. The private
    /// parts are dropped: these tests never join a group with it.
    pub fn key_package(&self, last_resort: bool) -> B64 {
        let provider = Provider::new(MemoryStorage::default());
        let package = key_package::build(
            &provider,
            &DeviceSigner::new(&self.key),
            for_device(&self.certificate, &self.key.public()),
            last_resort,
        )
        .unwrap();
        B64(key_package::to_bytes(&package).unwrap())
    }

    /// `count` one-time KeyPackages of this device.
    pub fn key_packages(&self, count: usize) -> Vec<B64> {
        (0..count).map(|_| self.key_package(false)).collect()
    }
}

pub fn random_handle(prefix: &str) -> String {
    let suffix: [u8; 6] = token::random_bytes();
    let hex: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{prefix}_{hex}")
}

pub fn test_secrets() -> InstanceSecrets {
    let generated: HashMap<String, String> = InstanceSecrets::generate()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    InstanceSecrets::from_lookup(|name| generated.get(name).cloned()).unwrap()
}

impl TestApp {
    pub async fn spawn() -> Self {
        Self::spawn_with(false).await
    }

    /// Like [`TestApp::spawn`], without the authentication rate limits, for
    /// tests that make many attempts on one handle. The limits themselves are
    /// tested with the default configuration.
    pub async fn spawn_unlimited() -> Self {
        Self::spawn_with(true).await
    }

    async fn spawn_with(unlimited: bool) -> Self {
        Self::spawn_configured(|settings| {
            if unlimited {
                settings.auth_per_ip_per_minute = 10_000;
                settings.auth_per_handle_per_minute = 10_000;
            }
        })
        .await
    }

    /// Like [`TestApp::spawn`], with settings changed by `configure`.
    pub async fn spawn_configured(configure: impl FnOnce(&mut Settings)) -> Self {
        let database_url = database_url();
        let pool = db::connect(&database_url, 5)
            .await
            .expect("database must be reachable");
        db::migrate(&pool).await.expect("migrations must apply");

        let state = AppState::new(pool, test_secrets(), {
            let mut settings = Settings::new(
                Some("https://example.org/source".to_owned()),
                false,
                Duration::from_secs(3600),
            );
            configure(&mut settings);
            settings
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = app(state.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            addr,
            state,
            http: reqwest::Client::new(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Sends a request and returns the status and raw body.
    pub async fn send<B: Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        bearer: Option<&B64>,
        body: Option<&B>,
    ) -> (StatusCode, Vec<u8>) {
        let mut request = self.http.request(method, self.url(path));
        if let Some(token) = bearer {
            let encoded = serde_json::to_value(token).unwrap();
            request = request.bearer_auth(encoded.as_str().unwrap());
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        (status, response.bytes().await.unwrap().to_vec())
    }

    /// POST that must succeed; returns the decoded body.
    pub async fn post<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        bearer: Option<&B64>,
        body: &B,
    ) -> R {
        let (status, bytes) = self
            .send(reqwest::Method::POST, path, bearer, Some(body))
            .await;
        assert!(
            status.is_success(),
            "{path}: {status} {}",
            String::from_utf8_lossy(&bytes)
        );
        serde_json::from_slice(&bytes).unwrap()
    }

    /// POST that must fail; returns the status and error code.
    pub async fn post_err<B: Serialize>(
        &self,
        path: &str,
        bearer: Option<&B64>,
        body: &B,
    ) -> (StatusCode, ErrorCode) {
        let (status, bytes) = self
            .send(reqwest::Method::POST, path, bearer, Some(body))
            .await;
        assert!(!status.is_success(), "{path} unexpectedly succeeded");
        let error: ErrorBody = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("{path}: {status} {}", String::from_utf8_lossy(&bytes)));
        (status, error.code)
    }

    pub async fn get<R: DeserializeOwned>(&self, path: &str, bearer: &B64) -> R {
        let (status, bytes) = self
            .send::<()>(reqwest::Method::GET, path, Some(bearer), None)
            .await;
        assert!(
            status.is_success(),
            "{path}: {status} {}",
            String::from_utf8_lossy(&bytes)
        );
        serde_json::from_slice(&bytes).unwrap()
    }

    pub async fn status<B: Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        bearer: Option<&B64>,
        body: Option<&B>,
    ) -> StatusCode {
        self.send(method, path, bearer, body).await.0
    }

    /// Creates an invitation directly, as `create-admin-invite` does on the host.
    pub async fn invite(&self, grants_admin: bool) -> String {
        routes::admin::insert_invite(&self.state.db, None, 1, 24, grants_admin)
            .await
            .unwrap()
            .code
    }

    /// Registers a new account with a fresh invitation.
    pub async fn register(&self, prefix: &str, admin: bool) -> Account {
        let invite = self.invite(admin).await;
        self.register_with(&random_handle(prefix), PASSWORD, &invite)
            .await
            .unwrap()
    }

    pub async fn register_with(
        &self,
        handle: &str,
        password: &str,
        invite_code: &str,
    ) -> Result<Account, (StatusCode, ErrorCode)> {
        let canonical = Handle::canonicalize(handle).unwrap();
        let password = Password::new(password);
        let (state, request) = Registration::start(&password).unwrap();

        let start = RegisterStartRequest {
            invite_code: invite_code.to_owned(),
            handle: handle.to_owned(),
            registration_request: B64(request),
        };
        let (status, bytes) = self
            .send(
                reqwest::Method::POST,
                "/v1/auth/register/start",
                None,
                Some(&start),
            )
            .await;
        if !status.is_success() {
            return Err((
                status,
                serde_json::from_slice::<ErrorBody>(&bytes).unwrap().code,
            ));
        }
        let response: RegistrationResponse = serde_json::from_slice(&bytes).unwrap();

        let output = state
            .finish(
                &password,
                response.registration_response.as_slice(),
                &canonical,
            )
            .unwrap();
        let root = AccountRootSecret::generate();
        let identity = root.identity_key().unwrap();
        let recovery_key = RecoveryKey::generate();
        let finish = RegisterFinishRequest {
            invite_code: invite_code.to_owned(),
            handle: handle.to_owned(),
            display_name: "Test User".to_owned(),
            registration_upload: B64(output.upload),
            identity_key: B64::from(identity.public().to_bytes()),
            wrapped_password_copy: B64(root
                .wrap(&WrappingKey::from_export_key(&output.export_key).unwrap())
                .unwrap()),
            wrapped_recovery_copy: B64(root
                .wrap(&WrappingKey::from_recovery_key(&recovery_key).unwrap())
                .unwrap()),
        };
        let (status, bytes) = self
            .send(
                reqwest::Method::POST,
                "/v1/auth/register/finish",
                None,
                Some(&finish),
            )
            .await;
        if !status.is_success() {
            return Err((
                status,
                serde_json::from_slice::<ErrorBody>(&bytes).unwrap().code,
            ));
        }
        let created: RegisterFinishResponse = serde_json::from_slice(&bytes).unwrap();
        Ok(Account {
            user_id: created.user_id,
            handle: canonical,
            identity,
            recovery_key,
        })
    }

    /// Runs the OPAQUE login. `Err` carries the server's answer to a failed
    /// `login/finish`; a wrong password fails on the client, in which case a
    /// deliberately invalid finalization is sent to observe the server.
    pub async fn login(
        &self,
        handle: &str,
        password: &str,
    ) -> Result<(LoginOutcome, B64), (StatusCode, ErrorCode)> {
        let canonical = Handle::canonicalize(handle).unwrap();
        let password = Password::new(password);
        let (state, request) = Login::start(&password).unwrap();
        let start = LoginStartRequest {
            handle: handle.to_owned(),
            credential_request: B64(request),
        };
        let (status, bytes) = self
            .send(
                reqwest::Method::POST,
                "/v1/auth/login/start",
                None,
                Some(&start),
            )
            .await;
        if !status.is_success() {
            return Err((
                status,
                serde_json::from_slice::<ErrorBody>(&bytes).unwrap().code,
            ));
        }
        let response: LoginStartResponse = serde_json::from_slice(&bytes).unwrap();

        let finalization = match state.finish(
            &password,
            response.credential_response.as_slice(),
            &canonical,
        ) {
            Ok(output) => output.finalization,
            Err(_) => vec![0u8; 64],
        };
        let finish = LoginFinishRequest {
            login_id: response.login_id.clone(),
            credential_finalization: B64(finalization),
        };
        let (status, bytes) = self
            .send(
                reqwest::Method::POST,
                "/v1/auth/login/finish",
                None,
                Some(&finish),
            )
            .await;
        if !status.is_success() {
            return Err((
                status,
                serde_json::from_slice::<ErrorBody>(&bytes).unwrap().code,
            ));
        }
        Ok((serde_json::from_slice(&bytes).unwrap(), response.login_id))
    }

    /// Logs in an account without TOTP and returns the grant.
    pub async fn grant(&self, account: &Account) -> LoginGrant {
        match self
            .login(account.handle.as_str(), PASSWORD)
            .await
            .unwrap()
            .0
        {
            LoginOutcome::Ok(grant) => grant,
            LoginOutcome::TotpRequired => panic!("unexpected TOTP step"),
        }
    }

    /// Builds a grant without going through a login, as `login/finish` does
    /// after a successful one. Logins are limited per handle, so tests that
    /// need many grants for one account use this.
    pub fn direct_grant(&self, account: &Account) -> LoginGrant {
        let enrolment_token: [u8; 32] = token::random_bytes();
        let session_nonce: [u8; 32] = token::random_bytes();
        assert!(self.state.pending.enrolments.insert(
            token::hash(&enrolment_token),
            tavern_server::Enrolment {
                user_id: account.user_id,
                session_nonce
            },
        ));
        LoginGrant {
            user_id: account.user_id,
            handle: account.handle.as_str().to_owned(),
            display_name: "Test User".to_owned(),
            is_admin: false,
            enrolment_token: B64::from(enrolment_token),
            session_nonce: B64::from(session_nonce),
            identity_key: B64::from(account.identity.public().to_bytes()),
            wrapped_password_copy: B64(Vec::new()),
        }
    }

    /// Enrols a new device with a grant.
    pub async fn enrol_with(&self, account: &Account, grant: &LoginGrant) -> Device {
        let key = DeviceKey::generate();
        let device_id = Uuid::new_v4();
        let certificate = account.identity.certify_device(
            account.user_id.as_bytes(),
            device_id.as_bytes(),
            &key.public(),
            1_700_000_000_000,
        );
        let session: SessionResponse = self
            .post(
                "/v1/devices",
                Some(&grant.enrolment_token),
                &EnrolDeviceRequest {
                    certificate: B64(certificate.clone()),
                    name_encrypted: None,
                    platform: Platform::Linux,
                },
            )
            .await;
        assert_eq!(session.device_id, device_id);
        Device {
            device_id,
            key,
            certificate,
            session_token: session.session_token,
        }
    }

    /// Logs in and enrols a new device.
    pub async fn enrol(&self, account: &Account) -> Device {
        let grant = self.grant(account).await;
        self.enrol_with(account, &grant).await
    }

    /// Registers an account and enrols its first device.
    pub async fn account_with_device(&self, prefix: &str, admin: bool) -> (Account, Device) {
        let account = self.register(prefix, admin).await;
        let device = self.enrol(&account).await;
        (account, device)
    }
}

pub fn session_proof(grant: &LoginGrant, account: &Account, device: &Device) -> B64 {
    let nonce: [u8; 32] = grant.session_nonce.as_slice().try_into().unwrap();
    B64::from(device.key.sign_session_proof(&SessionChallenge {
        nonce: &nonce,
        user_id: account.user_id.as_bytes(),
        device_id: device.device_id.as_bytes(),
    }))
}
