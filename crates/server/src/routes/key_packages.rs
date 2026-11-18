// SPDX-License-Identifier: AGPL-3.0-or-later

//! KeyPackages (ADR 0019, section 3): each device uploads its own, and a user
//! claims one for each active device of a user they may start a conversation
//! with, to add those devices to it.
//!
//! A one-time package is served once: the claiming transaction keeps its
//! row, without its bytes, until it expires, so that the same package sent
//! again (a retried upload) is never stored nor served a second time; and
//! two claims at once never get the same one. The last-resort package is
//! served when no one-time package is left, and kept.

use axum::Json;
use axum::extract::{Path, State};
use sqlx::PgExecutor;
use tavern_crypto::identity::IdentityPublicKey;
use tavern_crypto::mls::key_package::{
    self, KeyPackageError, LOW_WATERMARK, UploadedKeyPackage, Uploader,
};
use tavern_protocol::rest::{
    B64, DeviceKeyPackage, ErrorBody, ErrorCode, KeyPackageClaim, KeyPackageCount,
    UploadKeyPackagesRequest,
};
use tavern_protocol::{MAX_KEY_PACKAGES_PER_UPLOAD, MAX_STORED_KEY_PACKAGES};
use uuid::Uuid;

use crate::AppState;
use crate::activity;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::gateway::Event;
use crate::panics;
use crate::routes::friends;
use crate::session::Session;

/// The packages a claim may serve: not served already, not expired, nor
/// about to be (the device that claims one must still be able to add it to
/// a group). A string literal, for `concat!`: queries stay static.
macro_rules! servable {
    () => {
        "served_at IS NULL AND expires_at > now() + interval '1 hour'"
    };
}

fn refused(error: &KeyPackageError) -> ApiError {
    let message = match error {
        KeyPackageError::Malformed => "a KeyPackage is malformed or too large",
        KeyPackageError::WrongCiphersuite => "a KeyPackage uses another ciphersuite",
        KeyPackageError::Invalid(_) => "a KeyPackage is not valid: signature, keys or lifetime",
        KeyPackageError::LifetimeTooLong => "a KeyPackage is valid for too long",
        KeyPackageError::Leaf(_) => {
            "a KeyPackage does not carry the key and certificate this device enrolled with"
        }
        KeyPackageError::WrongDevice => "a KeyPackage belongs to another device",
        KeyPackageError::LastResortMismatch => {
            "a KeyPackage's last-resort flag does not match where it was sent"
        }
    };
    ApiError::new(ErrorCode::InvalidKeyPackage, message)
}

/// One-time packages of `device` that a claim can still serve.
pub(crate) async fn remaining<'c>(db: impl PgExecutor<'c>, device: Uuid) -> ApiResult<u32> {
    let count: i64 = sqlx::query_scalar(concat!(
        "SELECT count(*) FROM key_packages WHERE device_id = $1 AND NOT last_resort AND ",
        servable!()
    ))
    .bind(device)
    .fetch_one(db)
    .await?;
    Ok(u32::try_from(count).unwrap_or(u32::MAX))
}

/// The uploading device as the database knows it: its account's identity
/// key, and the key and certificate it enrolled with.
async fn uploader(state: &AppState, session: &Session) -> ApiResult<Uploader> {
    let (identity_key, signature_key, certificate): (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT u.identity_key, d.signature_key, d.certificate \
             FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = $1",
    )
    .bind(session.device_id)
    .fetch_one(&state.db)
    .await?;
    Ok(Uploader {
        user_id: *session.user_id.as_bytes(),
        device_id: *session.device_id.as_bytes(),
        identity_key: IdentityPublicKey::from_bytes(&identity_key)
            .map_err(|error| ApiError::internal("stored identity key", &error))?,
        signature_key,
        certificate,
    })
}

type Checked = (
    Vec<(Vec<u8>, UploadedKeyPackage)>,
    Option<(Vec<u8>, UploadedKeyPackage)>,
);

/// Checks every package of an upload, off the async threads: up to a
/// hundred signatures and certificates. One refused package refuses the
/// upload.
async fn check(uploader: Uploader, request: UploadKeyPackagesRequest) -> ApiResult<Checked> {
    panics::blocking(move || {
        let check_one = |bytes: B64, last_resort: bool| {
            key_package::validate_upload(bytes.as_slice(), &uploader, last_resort)
                .map(|uploaded| (bytes.0, uploaded))
                .map_err(|error| refused(&error))
        };
        let one_time = request
            .key_packages
            .into_iter()
            .map(|bytes| check_one(bytes, false))
            .collect::<ApiResult<Vec<_>>>()?;
        let last_resort = request
            .last_resort
            .map(|bytes| check_one(bytes, true))
            .transpose()?;
        Ok((one_time, last_resort))
    })
    .await?
}

async fn insert<'c>(
    db: impl PgExecutor<'c>,
    device: Uuid,
    (bytes, uploaded): &(Vec<u8>, UploadedKeyPackage),
    last_resort: bool,
) -> ApiResult<()> {
    let not_after = i64::try_from(uploaded.not_after)
        .map_err(|_| ApiError::new(ErrorCode::InvalidKeyPackage, "a KeyPackage is not valid"))?;
    // The same package sent again (a retried upload) is already there, or
    // was served and keeps its reference until it expires: not stored again.
    sqlx::query(
        "INSERT INTO key_packages (device_id, key_package, reference, last_resort, expires_at) \
         VALUES ($1, $2, $3, $4, to_timestamp($5)) ON CONFLICT (reference) DO NOTHING",
    )
    .bind(device)
    .bind(bytes)
    .bind(&uploaded.reference)
    .bind(last_resort)
    .bind(not_after)
    .execute(db)
    .await?;
    Ok(())
}

/// Uploads one-time KeyPackages of this device and, optionally, a new
/// last-resort KeyPackage, which replaces the current one. Each must be this
/// device's, with the key and certificate it enrolled with, valid now and
/// for at most 90 days. Returns the one-time packages left to serve.
#[utoipa::path(
    post,
    path = "/v1/devices/me/key-packages",
    tag = "key-packages",
    request_body = UploadKeyPackagesRequest,
    security(("session" = [])),
    responses((status = 200, body = KeyPackageCount), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn upload(
    State(state): State<AppState>,
    session: Session,
    ApiJson(request): ApiJson<UploadKeyPackagesRequest>,
) -> ApiResult<Json<KeyPackageCount>> {
    if request.key_packages.len() > MAX_KEY_PACKAGES_PER_UPLOAD {
        return Err(ApiError::new(
            ErrorCode::PayloadTooLarge,
            "at most 100 KeyPackages per upload",
        ));
    }
    let uploader = uploader(&state, &session).await?;
    let (one_time, last_resort) = check(uploader, request).await?;
    let device = session.device_id;

    let mut tx = state.db.begin().await?;
    // Uploads of one device take turns, so that the limit holds.
    sqlx::query("SELECT 1 FROM devices WHERE id = $1 FOR UPDATE")
        .bind(device)
        .execute(&mut *tx)
        .await?;
    // The device's expired packages go now; those of devices that upload
    // nothing go with the hourly purge (M2, tasks 8 and 9).
    sqlx::query("DELETE FROM key_packages WHERE device_id = $1 AND expires_at <= now()")
        .bind(device)
        .execute(&mut *tx)
        .await?;
    for package in &one_time {
        insert(&mut *tx, device, package, false).await?;
    }
    if let Some(package) = &last_resort {
        sqlx::query("DELETE FROM key_packages WHERE device_id = $1 AND last_resort")
            .bind(device)
            .execute(&mut *tx)
            .await?;
        insert(&mut *tx, device, package, true).await?;
    }
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM key_packages \
         WHERE device_id = $1 AND NOT last_resort AND served_at IS NULL",
    )
    .bind(device)
    .fetch_one(&mut *tx)
    .await?;
    if usize::try_from(stored).unwrap_or(usize::MAX) > MAX_STORED_KEY_PACKAGES {
        // Dropping the transaction keeps nothing of this upload.
        return Err(ApiError::new(
            ErrorCode::PayloadTooLarge,
            "a device keeps at most 200 KeyPackages on the server",
        ));
    }
    let one_time = remaining(&mut *tx, device).await?;
    tx.commit().await?;
    Ok(Json(KeyPackageCount { one_time }))
}

/// The one-time KeyPackages of this device that the server can still serve.
#[utoipa::path(
    get,
    path = "/v1/devices/me/key-packages/count",
    tag = "key-packages",
    security(("session" = [])),
    responses((status = 200, body = KeyPackageCount), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn count(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<KeyPackageCount>> {
    let one_time = remaining(&state.db, session.device_id).await?;
    Ok(Json(KeyPackageCount { one_time }))
}

/// Claims one KeyPackage for each active device of a user, the requesting
/// device excepted: a one-time package, or the last-resort one when none is
/// left. A device with neither is absent from the answer.
///
/// Allowed for one's own account and for a friend's. Anyone else, an
/// unknown user included, is refused with `FORBIDDEN`, and nothing is
/// consumed. At most 60 claims an hour per requesting user, and for a
/// friend's packages 3 an hour and 10 a day per pair (configurable).
#[utoipa::path(
    post,
    path = "/v1/users/{user_id}/key-packages/claim",
    tag = "key-packages",
    params(("user_id" = Uuid, Path, description = "The user whose devices to add")),
    security(("session" = [])),
    responses((status = 200, body = KeyPackageClaim), (status = "4XX", body = ErrorBody))
)]
pub(crate) async fn claim(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<KeyPackageClaim>> {
    state.rate_limits.claims.check_requester(session.user_id)?;
    let mut tx = state.db.begin().await?;
    if user_id != session.user_id {
        // Under the pair's turn (ADR 0020): a block or an unfriending either
        // ends before the friendship is read, and the claim is refused, or
        // waits for the claim to end.
        let friendship = friends::lock_pair(&mut tx, session.user_id, user_id).await?;
        if !friendship.is_some_and(|row| row.accepted) {
            return Err(ApiError::forbidden());
        }
        state
            .rate_limits
            .claims
            .check_pair(session.user_id, user_id)?;
    }

    let devices: Vec<Uuid> = sqlx::query_scalar(concat!(
        "SELECT d.id FROM devices d JOIN users u ON u.id = d.user_id \
         WHERE d.user_id = $1 AND d.id <> $2 AND ",
        activity::active_device!("$3"),
        " ORDER BY d.created_at"
    ))
    .bind(user_id)
    .bind(session.device_id)
    .bind(activity::window(state.settings.device_inactive_days))
    .fetch_all(&mut *tx)
    .await?;

    let mut served = Vec::with_capacity(devices.len());
    let mut low = Vec::new();
    for device in devices {
        // Oldest first; a package another claim is taking right now is
        // skipped, never served twice. Its row stays, without its bytes,
        // until it expires.
        let one_time: Option<Vec<u8>> = sqlx::query_scalar(concat!(
            "WITH taken AS ( \
                 SELECT id, key_package FROM key_packages \
                 WHERE device_id = $1 AND NOT last_resort AND ",
            servable!(),
            " ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED) \
             UPDATE key_packages k SET served_at = now(), key_package = '\\x' \
             FROM taken WHERE k.id = taken.id \
             RETURNING taken.key_package"
        ))
        .bind(device)
        .fetch_optional(&mut *tx)
        .await?;
        let package = match one_time {
            Some(package) => Some(package),
            None => {
                sqlx::query_scalar(concat!(
                    "SELECT key_package FROM key_packages \
                     WHERE device_id = $1 AND last_resort AND ",
                    servable!()
                ))
                .bind(device)
                .fetch_optional(&mut *tx)
                .await?
            }
        };
        let Some(package) = package else {
            continue;
        };
        let left = remaining(&mut *tx, device).await?;
        if usize::try_from(left).unwrap_or(usize::MAX) < LOW_WATERMARK {
            low.push((device, left));
        }
        served.push(DeviceKeyPackage {
            device_id: device,
            key_package: B64(package),
        });
    }
    tx.commit().await?;

    for (device, remaining) in low {
        state
            .gateway
            .notify_device(device, Event::KeyPackagesLow { remaining });
    }
    Ok(Json(KeyPackageClaim {
        key_packages: served,
    }))
}
