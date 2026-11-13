// SPDX-License-Identifier: AGPL-3.0-or-later

//! TOTP (RFC 6238) as an optional second step of login.
//!
//! TOTP is checked by the server. It protects against a stolen password being
//! used from the network; it does not protect the wrapped account key against
//! someone who controls the server (see `docs/threat-model.md`). The shared
//! secret is therefore a server-side secret: it is stored encrypted under the
//! instance's TOTP key so that a database dump alone does not reveal it.

use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sqlx::PgPool;
use tavern_crypto::secret::Secret;
use tavern_crypto::token::{self, HumanCode};
use totp_rs::{Algorithm, Builder, Totp};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

use tavern_protocol::rest::ErrorCode;

/// Length of the shared secret, in bytes (160 bits, as recommended by RFC 4226).
pub const SECRET_LEN: usize = 20;
/// Number of recovery codes issued when TOTP is enabled.
pub const RECOVERY_CODES: usize = 10;

const DIGITS: u8 = 6;
const STEP_SECONDS: u64 = 30;
const NONCE_LEN: usize = 24;
const ISSUER: &str = "Tavern";

fn invalid_code() -> ApiError {
    ApiError::new(ErrorCode::TotpInvalid, "invalid code")
}

fn build(secret: &[u8], account: &str) -> ApiResult<Totp> {
    // Skew is handled by `matching_step`, hence 0 here.
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(DIGITS)
        .with_skew(0)
        .with_step_duration(STEP_SECONDS)
        .with_secret(secret.to_vec())
        .with_issuer(Some(ISSUER))
        .with_account_name(account)
        .build()
        .map_err(|error| ApiError::internal("totp", &error))
}

/// The base32 secret and `otpauth://` URL shown to the user at enrolment.
pub fn enrolment(secret: &[u8], handle: &str) -> ApiResult<(String, String)> {
    let totp = build(secret, handle)?;
    let url = totp
        .to_url()
        .map_err(|error| ApiError::internal("totp", &error))?;
    Ok((totp.secret().to_base32(), url))
}

/// Returns the time step for which `code` is valid, accepting the previous,
/// current and next step to tolerate clock drift.
fn matching_step(secret: &[u8], code: &str, now_seconds: u64) -> ApiResult<Option<i64>> {
    let code = code.trim();
    if code.len() != usize::from(DIGITS) || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let totp = build(secret, "")?;
    let current = now_seconds / STEP_SECONDS;
    for step in [current.saturating_sub(1), current, current + 1] {
        let expected = totp.generate(step * STEP_SECONDS).to_string();
        if token::constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return Ok(i64::try_from(step).ok());
        }
    }
    Ok(None)
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Encrypts a TOTP secret for storage. The account id is bound as associated
/// data, so a stored secret cannot be moved to another account.
pub fn seal(key: &Secret<32>, user_id: Uuid, secret: &[u8]) -> ApiResult<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = token::random_bytes();
    let ciphertext = XChaCha20Poly1305::new(key.expose().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| ApiError::internal("totp", &"encryption failed"))?;
    Ok([nonce.as_slice(), &ciphertext].concat())
}

/// Decrypts a stored TOTP secret.
pub fn open(key: &Secret<32>, user_id: Uuid, sealed: &[u8]) -> ApiResult<Vec<u8>> {
    if sealed.len() <= NONCE_LEN {
        return Err(ApiError::internal("totp", &"stored secret is truncated"));
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.expose().into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| ApiError::internal("totp", &"stored secret cannot be decrypted"))
}

/// Checks a six-digit code for an account and records the step it used, so
/// that the same code cannot be accepted twice.
///
/// `require_enabled` is `false` only while the user confirms the enrolment.
pub async fn verify_code(
    db: &PgPool,
    key: &Secret<32>,
    user_id: Uuid,
    code: &str,
    require_enabled: bool,
) -> ApiResult<()> {
    let row: Option<(Option<Vec<u8>>, bool)> =
        sqlx::query_as("SELECT totp_secret, totp_enabled_at IS NOT NULL FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    let Some((Some(sealed), enabled)) = row else {
        return Err(invalid_code());
    };
    if require_enabled && !enabled {
        return Err(invalid_code());
    }

    let secret = open(key, user_id, &sealed)?;
    let Some(step) = matching_step(&secret, code, now_seconds())? else {
        return Err(invalid_code());
    };

    // Accept the step only if it is newer than the last one used.
    let updated = sqlx::query(
        "UPDATE users SET totp_last_step = $2 \
         WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(user_id)
    .bind(step)
    .execute(db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(invalid_code());
    }
    Ok(())
}

/// Checks a TOTP code or, failing that, a single-use recovery code.
pub async fn verify_code_or_recovery(
    db: &PgPool,
    key: &Secret<32>,
    user_id: Uuid,
    code: &str,
) -> ApiResult<()> {
    match verify_code(db, key, user_id, code, true).await {
        Ok(()) => return Ok(()),
        Err(error) if error.code != ErrorCode::TotpInvalid => return Err(error),
        Err(_) => {}
    }
    let Ok(recovery) = HumanCode::parse(code) else {
        return Err(invalid_code());
    };
    let used = sqlx::query(
        "UPDATE totp_recovery_codes SET used_at = now() \
         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(recovery.hash().as_slice())
    .execute(db)
    .await?;
    if used.rows_affected() == 1 {
        Ok(())
    } else {
        Err(invalid_code())
    }
}

/// Removes TOTP from an account: secret, state and recovery codes.
pub async fn clear(db: &PgPool, user_id: Uuid) -> ApiResult<()> {
    let mut tx = db.begin().await?;
    sqlx::query(
        "UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL \
         WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238, appendix B, SHA-1 test secret.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn codes_match_the_rfc_6238_vectors() {
        // The RFC lists 8-digit codes; ours are their last 6 digits.
        for (time, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_234_567_890, "005924"),
        ] {
            assert_eq!(
                build(RFC_SECRET, "x").unwrap().generate(time).to_string(),
                code
            );
            assert_eq!(
                matching_step(RFC_SECRET, code, time).unwrap(),
                Some((time / 30) as i64)
            );
        }
    }

    #[test]
    fn one_step_of_drift_is_tolerated_in_each_direction() {
        let code = build(RFC_SECRET, "x")
            .unwrap()
            .generate(1_111_111_109)
            .to_string();
        let step = 1_111_111_109 / 30;

        assert_eq!(
            matching_step(RFC_SECRET, &code, (step + 1) * 30).unwrap(),
            Some(step as i64)
        );
        assert_eq!(
            matching_step(RFC_SECRET, &code, (step - 1) * 30).unwrap(),
            Some(step as i64)
        );
        assert_eq!(
            matching_step(RFC_SECRET, &code, (step + 2) * 30).unwrap(),
            None
        );
        assert_eq!(
            matching_step(RFC_SECRET, &code, (step - 2) * 30).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_codes_never_match() {
        for code in ["", "12345", "1234567", "abcdef", "12 456", "１２３４５６"] {
            assert_eq!(
                matching_step(RFC_SECRET, code, 59).unwrap(),
                None,
                "{code:?}"
            );
        }
        assert_eq!(matching_step(RFC_SECRET, " 287082 ", 59).unwrap(), Some(1));
    }

    #[test]
    fn sealed_secrets_open_only_for_the_same_account_and_key() {
        let key = Secret::<32>::random();
        let user = Uuid::from_u128(1);
        let sealed = seal(&key, user, RFC_SECRET).unwrap();

        assert_eq!(open(&key, user, &sealed).unwrap(), RFC_SECRET);
        assert_ne!(seal(&key, user, RFC_SECRET).unwrap(), sealed);
        assert!(
            !sealed
                .windows(RFC_SECRET.len())
                .any(|window| window == RFC_SECRET)
        );
        assert!(open(&key, Uuid::from_u128(2), &sealed).is_err());
        assert!(open(&Secret::random(), user, &sealed).is_err());
        assert!(open(&key, user, &sealed[..NONCE_LEN]).is_err());
    }

    #[test]
    fn enrolment_url_names_the_issuer_and_account() {
        let (secret, url) = enrolment(RFC_SECRET, "alice").unwrap();

        assert_eq!(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert!(url.starts_with("otpauth://totp/Tavern:alice?"));
        assert!(url.contains("issuer=Tavern"));
    }
}
