// SPDX-License-Identifier: AGPL-3.0-or-later

//! This device's KeyPackages (ADR 0019, section 3): 20 one-time packages
//! and one last-resort package on the instance, their private parts in the
//! local store.
//!
//! At each connection, and when the instance says fewer than 10 one-time
//! packages are left (`KeyPackagesLow`), the device tops them up
//! ([`crate::account::Client::maintain_key_packages`]). The last-resort
//! package is replaced every 30 days, and after a Welcome used it.
//!
//! A package is recorded with its public bytes until the instance confirms
//! the upload: an upload whose answer was lost sends the same packages
//! again, never new ones in their place, since the instance may serve them.
//! What the device no longer needs is forgotten, its private parts deleted
//! from the store:
//!
//! - a replaced last-resort package, 30 days after its replacement (a grace
//!   period, decided 2026-11-25: a claim may have served it just before,
//!   and its Welcome may wait for the device up to the retention, 30 days
//!   at most);
//! - a one-time package, once its lifetime is over (90 days): the instance
//!   no longer serves it;
//! - a package the instance refused.

use rusqlite::OptionalExtension as _;
use tavern_crypto::identity::DeviceKey;
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::key_package::{
    self, LAST_RESORT_ROTATION_DAYS, LIFETIME_SECONDS, ONE_TIME_COUNT,
};
use tavern_crypto::mls::{DeviceSigner, MlsError, Provider};

use crate::error::ClientError;
use crate::local::mls::SqlStorage;
use crate::local::{LocalStore, LocalStoreError};

const DAY_MS: u64 = 24 * 3600 * 1000;
/// How long the private parts of a replaced last-resort package are kept.
pub const LAST_RESORT_GRACE_MS: u64 = 30 * DAY_MS;
/// How long a one-time package is kept: its lifetime.
const ONE_TIME_KEPT_MS: u64 = LIFETIME_SECONDS * 1000;
/// Age at which the last-resort package is replaced.
const LAST_RESORT_ROTATION_MS: u64 = LAST_RESORT_ROTATION_DAYS * DAY_MS;

/// Why the KeyPackages could not be kept up.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Failure {
    #[error(transparent)]
    Store(#[from] LocalStoreError),
    #[error("cannot build a KeyPackage: {0}")]
    Mls(#[from] MlsError),
}

impl From<rusqlite::Error> for Failure {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(LocalStoreError::Database(
            error
                .sqlite_error_code()
                .map_or_else(|| "rusqlite".to_owned(), |code| format!("{code:?}")),
        ))
    }
}

impl From<Failure> for ClientError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Store(error) => Self::LocalStore(error),
            Failure::Mls(error) => Self::Mls(error),
        }
    }
}

/// What to upload: packages built (now or before, the instance not having
/// confirmed them yet), their private parts in the store. Each is its
/// reference and its bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ToUpload {
    pub(crate) one_time: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) last_resort: Option<(Vec<u8>, Vec<u8>)>,
}

impl ToUpload {
    pub(crate) fn is_empty(&self) -> bool {
        self.one_time.is_empty() && self.last_resort.is_none()
    }

    fn references(&self) -> Vec<Vec<u8>> {
        self.one_time
            .iter()
            .chain(self.last_resort.iter())
            .map(|(reference, _)| reference.clone())
            .collect()
    }
}

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Forgets what is no longer needed, then gathers what to upload, in one
/// transaction: the packages the instance has not confirmed, then new
/// one-time packages up to 20 (`remaining` are still on the instance), and
/// a new last-resort package if there is none, if it is 30 days old, or if
/// a Welcome used it (`replace_last_resort`, or its private parts gone).
pub(crate) async fn prepare(
    store: &LocalStore,
    device_key: DeviceKey,
    certificate: Vec<u8>,
    remaining: u32,
    replace_last_resort: bool,
    now_ms: u64,
) -> Result<ToUpload, Failure> {
    store
        .transaction(move |transaction| {
            let provider = Provider::new(SqlStorage::new(transaction));
            forget_unneeded(transaction, &provider, now_ms)?;

            let mut upload = ToUpload::default();
            let pending: Vec<(Vec<u8>, bool, Vec<u8>)> = transaction
                .prepare(
                    "SELECT reference, last_resort, package FROM key_packages \
                     WHERE package IS NOT NULL ORDER BY created_at_ms",
                )?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<Result<_, _>>()?;
            for (reference, last_resort, package) in pending {
                if last_resort {
                    upload.last_resort = Some((reference, package));
                } else {
                    upload.one_time.push((reference, package));
                }
            }

            let current: Option<(Vec<u8>, i64)> = transaction
                .query_row(
                    "SELECT reference, created_at_ms FROM key_packages \
                     WHERE last_resort = 1 AND replaced_at_ms IS NULL \
                     ORDER BY created_at_ms DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let needs_last_resort = upload.last_resort.is_none()
                && (replace_last_resort
                    || match &current {
                        None => true,
                        Some((reference, created)) => {
                            now_ms.saturating_sub(u64::try_from(*created).unwrap_or(0))
                                >= LAST_RESORT_ROTATION_MS
                                // Used by a Welcome: its private parts are gone.
                                || !key_package::is_held(&provider, reference)?
                        }
                    });

            let missing = ONE_TIME_COUNT
                .saturating_sub(usize::try_from(remaining).unwrap_or(usize::MAX))
                .saturating_sub(upload.one_time.len());
            for _ in 0..missing {
                let built = build_one(
                    transaction,
                    &provider,
                    &device_key,
                    &certificate,
                    false,
                    now_ms,
                )?;
                upload.one_time.push(built);
            }
            if needs_last_resort {
                upload.last_resort = Some(build_one(
                    transaction,
                    &provider,
                    &device_key,
                    &certificate,
                    true,
                    now_ms,
                )?);
            }
            Ok(upload)
        })
        .await
}

fn build_one(
    transaction: &rusqlite::Transaction<'_>,
    provider: &Provider<SqlStorage<'_>>,
    device_key: &DeviceKey,
    certificate: &[u8],
    last_resort: bool,
    now_ms: u64,
) -> Result<(Vec<u8>, Vec<u8>), Failure> {
    let signer = DeviceSigner::new(device_key);
    let credential = for_device(certificate, &device_key.public());
    let package = key_package::build(provider, &signer, credential, last_resort)?;
    let reference = key_package::reference(provider, &package)?;
    let bytes = key_package::to_bytes(&package)?;
    transaction.execute(
        "INSERT INTO key_packages (reference, last_resort, package, created_at_ms) \
         VALUES (?1, ?2, ?3, ?4)",
        (
            reference.as_slice(),
            last_resort,
            bytes.as_slice(),
            ms(now_ms),
        ),
    )?;
    Ok((reference, bytes))
}

/// Deletes the private parts, and the rows, of the packages this device no
/// longer needs (module documentation); and the rows of packages a Welcome
/// used, whose private parts OpenMLS deleted.
fn forget_unneeded(
    transaction: &rusqlite::Transaction<'_>,
    provider: &Provider<SqlStorage<'_>>,
    now_ms: u64,
) -> Result<(), Failure> {
    let expired: Vec<Vec<u8>> = transaction
        .prepare(
            "SELECT reference FROM key_packages \
             WHERE (last_resort = 0 AND created_at_ms <= ?1 - ?2) \
                OR (replaced_at_ms IS NOT NULL AND replaced_at_ms <= ?1 - ?3)",
        )?
        .query_map(
            (ms(now_ms), ms(ONE_TIME_KEPT_MS), ms(LAST_RESORT_GRACE_MS)),
            |row| row.get(0),
        )?
        .collect::<Result<_, _>>()?;
    for reference in &expired {
        key_package::forget(provider, reference)?;
    }
    let all: Vec<Vec<u8>> = transaction
        .prepare("SELECT reference FROM key_packages")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    for reference in all {
        if !key_package::is_held(provider, &reference)? {
            transaction.execute("DELETE FROM key_packages WHERE reference = ?1", [reference])?;
        }
    }
    Ok(())
}

/// The instance took `upload`: its packages are confirmed (their public
/// bytes dropped), and the earlier last-resort package, if a new one went
/// up, starts its grace period.
pub(crate) async fn uploaded(
    store: &LocalStore,
    upload: &ToUpload,
    now_ms: u64,
) -> Result<(), Failure> {
    let references = upload.references();
    let last_resort = upload
        .last_resort
        .as_ref()
        .map(|(reference, _)| reference.clone());
    store
        .transaction(move |transaction| {
            for reference in &references {
                transaction.execute(
                    "UPDATE key_packages SET package = NULL WHERE reference = ?1",
                    [reference],
                )?;
            }
            if let Some(reference) = last_resort {
                transaction.execute(
                    "UPDATE key_packages SET replaced_at_ms = ?1 \
                     WHERE last_resort = 1 AND replaced_at_ms IS NULL AND reference <> ?2",
                    (ms(now_ms), reference),
                )?;
            }
            Ok(())
        })
        .await
}

/// The instance refused `upload`: what was built for it is forgotten.
pub(crate) async fn refused(store: &LocalStore, upload: &ToUpload) -> Result<(), Failure> {
    let references = upload.references();
    store
        .transaction(move |transaction| {
            let provider = Provider::new(SqlStorage::new(transaction));
            for reference in references {
                key_package::forget(&provider, &reference)?;
                transaction
                    .execute("DELETE FROM key_packages WHERE reference = ?1", [reference])?;
            }
            Ok(())
        })
        .await
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests panic on failure"
    )]

    use tavern_crypto::identity::AccountRootSecret;
    use tavern_crypto::secret::Secret;
    use uuid::Uuid;

    use super::*;
    use crate::local::{Binding, DATABASE_FILE};

    const NOW_MS: u64 = 1_794_000_000_000;

    struct Setup {
        store: LocalStore,
        seed: [u8; 32],
        certificate: Vec<u8>,
        _dir: tempfile::TempDir,
    }

    impl Setup {
        fn new() -> Self {
            let (user, device) = (Uuid::from_u128(1), Uuid::from_u128(2));
            let key = DeviceKey::generate();
            let certificate = AccountRootSecret::generate()
                .identity_key()
                .unwrap()
                .certify_device(user.as_bytes(), device.as_bytes(), &key.public(), NOW_MS);
            let dir = tempfile::tempdir().unwrap();
            let store = LocalStore::open(
                &dir.path().join(DATABASE_FILE),
                &Secret::from_slice(&[3; 32]).unwrap(),
                Binding {
                    user_id: user,
                    device_id: device,
                },
                NOW_MS,
            )
            .unwrap();
            Self {
                store,
                seed: *key.seed().expose(),
                certificate,
                _dir: dir,
            }
        }

        async fn prepare(&self, remaining: u32, replace: bool, now_ms: u64) -> ToUpload {
            prepare(
                &self.store,
                DeviceKey::from_seed(&Secret::from_slice(&self.seed).unwrap()),
                self.certificate.clone(),
                remaining,
                replace,
                now_ms,
            )
            .await
            .unwrap()
        }

        async fn held(&self, reference: &[u8]) -> bool {
            let reference = reference.to_vec();
            self.store
                .transaction(move |transaction| {
                    let provider = Provider::new(SqlStorage::new(transaction));
                    Ok::<_, Failure>(key_package::is_held(&provider, &reference)?)
                })
                .await
                .unwrap()
        }
    }

    fn reference(entry: &(Vec<u8>, Vec<u8>)) -> Vec<u8> {
        entry.0.clone()
    }

    /// Section 3: the device tops its one-time packages up to 20, with one
    /// last-resort package; an upload not confirmed is sent again as it
    /// is, with nothing new in its place.
    #[tokio::test]
    async fn what_is_missing_is_built_once_and_sent_until_confirmed() {
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        assert_eq!(first.one_time.len(), ONE_TIME_COUNT);
        assert!(first.last_resort.is_some());
        // The answer was lost: the same packages, nothing more.
        let again = setup.prepare(0, false, NOW_MS).await;
        assert_eq!(again, first);
        uploaded(&setup.store, &first, NOW_MS).await.unwrap();
        assert!(
            setup
                .prepare(ONE_TIME_COUNT as u32, false, NOW_MS)
                .await
                .is_empty()
        );
        // Nine left on the instance: eleven more, the last resort kept.
        let more = setup.prepare(9, false, NOW_MS).await;
        assert_eq!(more.one_time.len(), 11);
        assert!(more.last_resort.is_none());
    }

    /// Section 3: the last-resort package is replaced after 30 days, or when
    /// a Welcome used it; the one it replaces keeps its private parts for
    /// the grace period (30 days), then they are deleted.
    #[tokio::test]
    async fn a_replaced_last_resort_package_is_kept_for_its_grace_period() {
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        uploaded(&setup.store, &first, NOW_MS).await.unwrap();
        let old = reference(first.last_resort.as_ref().unwrap());

        let day = DAY_MS;
        assert!(setup.prepare(20, false, NOW_MS + 29 * day).await.is_empty());
        let rotated = setup.prepare(20, false, NOW_MS + 30 * day).await;
        let new = reference(rotated.last_resort.as_ref().unwrap());
        assert_ne!(new, old);
        uploaded(&setup.store, &rotated, NOW_MS + 30 * day)
            .await
            .unwrap();
        assert!(setup.held(&old).await);

        setup.prepare(20, false, NOW_MS + 59 * day).await;
        assert!(setup.held(&old).await, "within the grace period");
        setup.prepare(20, false, NOW_MS + 60 * day).await;
        assert!(!setup.held(&old).await, "after the grace period");
        assert!(setup.held(&new).await);

        // A Welcome used the last resort: replaced at once.
        let replaced = setup.prepare(20, true, NOW_MS + 61 * day).await;
        assert!(replaced.last_resort.is_some());
    }

    /// Section 3: what the instance refuses is forgotten; a one-time package
    /// is forgotten once its lifetime is over.
    #[tokio::test]
    async fn refused_and_expired_packages_are_forgotten() {
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        refused(&setup.store, &first).await.unwrap();
        for entry in first.one_time.iter().chain(first.last_resort.iter()) {
            assert!(!setup.held(&reference(entry)).await);
        }
        let second = setup.prepare(0, false, NOW_MS).await;
        assert_ne!(second.one_time, first.one_time);
        uploaded(&setup.store, &second, NOW_MS).await.unwrap();
        let one = reference(&second.one_time[0]);
        setup
            .prepare(20, false, NOW_MS + ONE_TIME_KEPT_MS - 1)
            .await;
        assert!(setup.held(&one).await);
        setup.prepare(20, false, NOW_MS + ONE_TIME_KEPT_MS).await;
        assert!(!setup.held(&one).await);
    }
}
