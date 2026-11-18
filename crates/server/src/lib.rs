// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tavern instance server.
//!
//! At milestone M1 the server handles accounts: registration by invitation,
//! OPAQUE login, devices, sessions, TOTP and credential recovery. M2 adds the
//! public state of MLS groups and the devices' KeyPackages. It never sees a
//! password, a private key or plaintext user content; see
//! `docs/threat-model.md`.

#![forbid(unsafe_code)]

pub mod activity;
pub mod config;
pub mod db;
pub mod error;
pub mod gateway;
pub mod mls;
pub mod notices;
pub mod panics;
pub mod pending;
pub mod rate_limit;
pub mod routes;
pub mod secrets;
pub mod session;
pub mod telemetry;
pub mod totp;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use sqlx::PgPool;
use tavern_crypto::identity::CHALLENGE_LEN;
use tavern_crypto::opaque::server::LoginState;
use tavern_crypto::token::{HASH_LEN, TOKEN_LEN};
use tavern_protocol::DEFAULT_MAX_REST_BODY_BYTES;
use tavern_protocol::handle::Handle;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::config::ClaimLimits;
use crate::gateway::Registry;
use crate::pending::ExpiringMap;
use crate::rate_limit::RateLimits;
use crate::secrets::InstanceSecrets;

/// Upper bound for handling one REST request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the two halves of an OPAQUE exchange may be apart.
const EXCHANGE_TTL: Duration = Duration::from_secs(60);
/// How long an enrolment token, a TOTP step or a credential change stays open.
const GRANT_TTL: Duration = Duration::from_secs(5 * 60);
/// How many exchanges of each kind may be in flight at once.
const PENDING_CAPACITY: usize = 10_000;

/// Identifier of an exchange in progress.
pub type ExchangeId = [u8; 16];

/// An OPAQUE login between `start` and `finish`.
pub struct PendingLogin {
    /// OPAQUE server state.
    pub state: LoginState,
    /// The account, when the handle exists and the account can log in.
    pub user_id: Option<Uuid>,
    /// Set for a re-authentication: the session that asked for it.
    pub reauth_for: Option<Uuid>,
}

/// What an enrolment token authorises.
#[derive(Debug, Clone, Copy)]
pub struct Enrolment {
    /// The account that logged in.
    pub user_id: Uuid,
    /// Nonce an existing device signs to reopen its session.
    pub session_nonce: [u8; CHALLENGE_LEN],
}

/// A credential change in progress.
#[derive(Debug, Clone)]
pub struct CredentialChange {
    /// The account, or `None` when a recovery was started for an unknown handle.
    pub user_id: Option<Uuid>,
    /// The handle the change is for.
    pub handle: Handle,
    /// Challenge the account identity key must sign.
    pub challenge: [u8; CHALLENGE_LEN],
    /// The device that asked, kept logged in after a password change.
    pub device_id: Option<Uuid>,
}

/// State kept in memory between the steps of an exchange.
pub struct Pending {
    /// Logins between `start` and `finish`.
    pub logins: ExpiringMap<ExchangeId, PendingLogin>,
    /// Logins that passed the password check and wait for a TOTP code:
    /// the account and the number of failed attempts.
    pub totp: ExpiringMap<ExchangeId, (Uuid, u8)>,
    /// Enrolment tokens, by token hash.
    pub enrolments: ExpiringMap<[u8; HASH_LEN], Enrolment>,
    /// Re-authentication tokens, by token hash.
    pub reauths: ExpiringMap<[u8; HASH_LEN], CredentialChange>,
    /// Recoveries between `start` and `finish`.
    pub recoveries: ExpiringMap<ExchangeId, CredentialChange>,
}

impl Default for Pending {
    fn default() -> Self {
        Self {
            logins: ExpiringMap::new(EXCHANGE_TTL, PENDING_CAPACITY),
            totp: ExpiringMap::new(GRANT_TTL, PENDING_CAPACITY),
            enrolments: ExpiringMap::new(GRANT_TTL, PENDING_CAPACITY),
            reauths: ExpiringMap::new(GRANT_TTL, PENDING_CAPACITY),
            recoveries: ExpiringMap::new(GRANT_TTL, PENDING_CAPACITY),
        }
    }
}

/// Settings that request handlers need.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Public URL of this instance's source code.
    pub source_url: Option<String>,
    /// Whether the last `X-Forwarded-For` entry is the client address.
    pub trust_forwarded_for: bool,
    /// How long an unused session stays valid.
    pub session_ttl: Duration,
    /// Authentication requests allowed per minute and per client address.
    pub auth_per_ip_per_minute: u32,
    /// Authentication attempts allowed per minute and per handle.
    pub auth_per_handle_per_minute: u32,
    /// Days a device may stay away and still count as active.
    pub device_inactive_days: u32,
    /// How often KeyPackages may be claimed.
    pub claim_limits: ClaimLimits,
    /// Friend requests a user may send per hour.
    pub friend_requests_per_hour: u32,
}

impl Settings {
    /// Settings with the production rate limits and the default device
    /// inactivity window.
    pub fn new(
        source_url: Option<String>,
        trust_forwarded_for: bool,
        session_ttl: Duration,
    ) -> Self {
        Self {
            source_url,
            trust_forwarded_for,
            session_ttl,
            auth_per_ip_per_minute: rate_limit::AUTH_PER_IP_PER_MINUTE,
            auth_per_handle_per_minute: rate_limit::AUTH_PER_HANDLE_PER_MINUTE,
            device_inactive_days: activity::DEFAULT_INACTIVE_DAYS,
            claim_limits: ClaimLimits::default(),
            friend_requests_per_hour: config::DEFAULT_FRIEND_REQUESTS_PER_HOUR,
        }
    }
}

/// State shared by all request handlers.
#[derive(Clone)]
pub struct AppState {
    /// PostgreSQL connection pool.
    pub db: PgPool,
    /// Instance secrets.
    pub secrets: Arc<InstanceSecrets>,
    /// Settings.
    pub settings: Arc<Settings>,
    /// Exchanges in progress.
    pub pending: Arc<Pending>,
    /// Rate limiters.
    pub rate_limits: Arc<RateLimits>,
    /// Connected devices.
    pub gateway: Arc<Registry>,
}

impl AppState {
    /// Assembles the state of a server.
    pub fn new(db: PgPool, secrets: InstanceSecrets, settings: Settings) -> Self {
        let rate_limits = RateLimits::new(
            settings.auth_per_ip_per_minute,
            settings.auth_per_handle_per_minute,
            settings.claim_limits,
            settings.friend_requests_per_hour,
        );
        Self {
            db,
            secrets: Arc::new(secrets),
            settings: Arc::new(settings),
            pending: Arc::new(Pending::default()),
            rate_limits: Arc::new(rate_limits),
            gateway: Arc::new(Registry::default()),
        }
    }
}

/// Length of tokens handed to clients, re-exported for the route modules.
pub(crate) const CLIENT_TOKEN_LEN: usize = TOKEN_LEN;

/// Builds the HTTP application.
///
/// Serve it with `into_make_service_with_connect_info::<SocketAddr>()`: rate
/// limiting needs the peer address.
pub fn app(state: AppState) -> Router {
    with_layers(routes::router(state.clone()), state)
}

/// Puts `router` under the layers every route of the server runs under: the
/// default body limit, the panic catcher, the timeout, and the request log.
/// [`app`] uses it; tests use it on routes of their own.
pub fn with_layers(router: Router<AppState>, state: AppState) -> Router {
    router
        .layer(DefaultBodyLimit::max(DEFAULT_MAX_REST_BODY_BYTES))
        // A handler that panics answers 500 INTERNAL; the server goes on.
        .layer(panics::layer())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        // Outermost, so that timeouts, refused bodies and panics are logged
        // too.
        .layer(axum::middleware::from_fn(telemetry::log_request))
        .with_state(state)
}
