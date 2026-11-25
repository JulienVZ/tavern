// SPDX-License-Identifier: AGPL-3.0-or-later

//! This device's KeyPackages (ADR 0019, section 3): 20 one-time packages
//! and one last-resort package on the instance, their private parts in the
//! local store.
//!
//! The device keeps them up ([`crate::account::Client::maintain_key_packages`])
//! at each connection of the gateway, when the instance says fewer than 10
//! one-time packages are left (`KeyPackagesLow`), and every hour whatever
//! the connection: what is due locally (forgetting) never waits for the
//! instance. The last-resort package is replaced every 30 days, and after
//! a Welcome used it: OpenMLS keeps its bundle at a join, but
//! [`tavern_crypto::mls::Group::join`] deletes it, so a used last resort
//! is a last resort no longer held.
//!
//! A package is recorded with its public bytes until the instance confirms
//! the upload: an upload whose answer was lost sends the same packages
//! again, never new ones in their place, since the instance may serve them.
//! What the device no longer needs is forgotten, its private parts deleted
//! from the store ([`forget_due`]):
//!
//! - a one-time package, once its lifetime (90 days) and the longest
//!   retention (30 days) are over: a claim made just before its end of
//!   life may bring a Welcome that waits on the instance up to the
//!   retention (decided 2026-11-25, after the review of task 10a);
//! - a replaced last-resort package, 30 days after its replacement, for the
//!   same reason (decided 2026-11-25);
//! - a package the instance refused the first time it was sent. A package
//!   sent before and refused when sent again (its first answer lost) may be
//!   on the instance: it is not sent again, and kept as long as it may be
//!   used.

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
/// The longest retention of an instance (`TAVERN_MESSAGE_RETENTION_DAYS`):
/// how long a Welcome may wait for this device.
pub const MAX_RETENTION_MS: u64 = 30 * DAY_MS;
/// How long the private parts of a replaced last-resort package are kept.
pub const LAST_RESORT_GRACE_MS: u64 = MAX_RETENTION_MS;
/// How long the private parts of a one-time package are kept: its lifetime,
/// then the longest wait of a Welcome made just before its end.
pub const ONE_TIME_KEPT_MS: u64 = LIFETIME_SECONDS * 1000 + MAX_RETENTION_MS;
/// Age at which the last-resort package is replaced.
const LAST_RESORT_ROTATION_MS: u64 = LAST_RESORT_ROTATION_DAYS * DAY_MS;
/// After a refusal caused by this device's clock, how long before building
/// packages again.
pub const REFUSAL_BACKOFF_MS: u64 = DAY_MS;
/// How often the KeyPackages are kept up, whatever the connection.
pub const UPKEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Runs `run` now, then every `every`, until aborted: the upkeep's clock,
/// independent of the connection.
pub(crate) fn spawn_every<F, Fut>(every: std::time::Duration, run: F) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(every);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            run().await;
        }
    })
}

/// The name, in `client_state`, of the time of the last refusal caused by
/// this device's clock.
const REFUSED_AT: &str = "key_packages_refused_at_ms";

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

/// How an upload went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The instance took it.
    Taken,
    /// The instance refused it.
    Refused,
    /// No answer: the instance may hold it or not.
    Unknown,
}

impl Outcome {
    /// How an upload went, from its answer: a refusal of the instance (an
    /// error status) is `Refused`; anything else that failed (the network,
    /// a timeout, an answer that cannot be read) leaves the result unknown.
    pub(crate) fn of<T>(answer: &Result<T, ClientError>) -> Self {
        match answer {
            Ok(_) => Self::Taken,
            Err(ClientError::Api { .. }) => Self::Refused,
            Err(_) => Self::Unknown,
        }
    }
}

/// Checks this device's certificate before it is kept and sent with every
/// KeyPackage (review of task 10a, point 15): it must be signed by the
/// account's identity key, as the instance gives it, and certify this
/// device's key for this account and this device.
pub(crate) fn check_certificate(
    identity_key: &[u8],
    certificate: &[u8],
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    device_key: &DeviceKey,
) -> Result<(), ClientError> {
    let identity = tavern_crypto::identity::IdentityPublicKey::from_bytes(identity_key)
        .map_err(|_| ClientError::UntrustedKeyMaterial)?;
    let certified = identity
        .verify_device_certificate(certificate)
        .map_err(|_| ClientError::UntrustedKeyMaterial)?;
    if certified.user_id != *user_id.as_bytes()
        || certified.device_id != *device_id.as_bytes()
        || certified.device_key.to_bytes() != device_key.public().to_bytes()
    {
        return Err(ClientError::UntrustedKeyMaterial);
    }
    Ok(())
}

fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Forgets, in one transaction, what this device no longer needs (module
/// documentation). Purely local: it never waits for the instance. Returns
/// whether anything was forgotten, to erase the journal then.
pub(crate) async fn forget_due(store: &LocalStore, now_ms: u64) -> Result<bool, Failure> {
    store
        .transaction(move |transaction| {
            let provider = Provider::new(SqlStorage::new(transaction));
            forget_unneeded(transaction, &provider, now_ms)
        })
        .await
}

/// Gathers what to upload, in one transaction: the packages the instance
/// has not confirmed, then new one-time packages up to 20 (`remaining` are
/// on the instance; the packages not confirmed are sent with them, and
/// change nothing if the instance already holds them), and a new
/// last-resort package if there is none, if it is 30 days old, or if a
/// Welcome used it (`replace_last_resort`, or its private parts gone).
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
            // A last resort a Welcome used has no row left: its private
            // parts were deleted at the join, and `forget_unneeded` dropped
            // its row above. Then none is current.
            let needs_last_resort = upload.last_resort.is_none()
                && (replace_last_resort
                    || current.is_none_or(|(_, created)| {
                        now_ms.saturating_sub(u64::try_from(created).unwrap_or(0))
                            >= LAST_RESORT_ROTATION_MS
                    }));

            // What the instance holds is `remaining`, whether or not it took
            // the packages not confirmed: never fewer than 20 after this
            // upload, at worst as many more as were not confirmed (the
            // instance keeps up to 200).
            let missing =
                ONE_TIME_COUNT.saturating_sub(usize::try_from(remaining).unwrap_or(usize::MAX));
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
/// used, whose private parts are gone. Returns whether it forgot any.
fn forget_unneeded(
    transaction: &rusqlite::Transaction<'_>,
    provider: &Provider<SqlStorage<'_>>,
    now_ms: u64,
) -> Result<bool, Failure> {
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
    let mut forgot = !expired.is_empty();
    for reference in all {
        if !key_package::is_held(provider, &reference)? {
            transaction.execute("DELETE FROM key_packages WHERE reference = ?1", [reference])?;
            forgot = true;
        }
    }
    Ok(forgot)
}

/// Records how the upload of `upload` went, in one transaction.
///
/// - Taken: its packages are confirmed (their public bytes dropped), and
///   the earlier last-resort package, if a new one went up, starts its
///   grace period.
/// - Refused: a package never sent before is forgotten; one sent before may
///   be on the instance, and is kept as long as it may be used, but never
///   sent again (a replaced last resort, from now).
/// - Unknown: they are marked sent, to send again next time.
pub(crate) async fn settle(
    store: &LocalStore,
    upload: &ToUpload,
    outcome: Outcome,
    now_ms: u64,
) -> Result<(), Failure> {
    let references = upload.references();
    let last_resort = upload
        .last_resort
        .as_ref()
        .map(|(reference, _)| reference.clone());
    store
        .transaction(move |transaction| {
            let provider = Provider::new(SqlStorage::new(transaction));
            match outcome {
                Outcome::Taken => {
                    for reference in &references {
                        transaction.execute(
                            "UPDATE key_packages SET package = NULL, sent = 1 WHERE reference = ?1",
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
                }
                Outcome::Refused => {
                    for reference in references {
                        let sent: bool = transaction.query_row(
                            "SELECT sent FROM key_packages WHERE reference = ?1",
                            [&reference],
                            |row| row.get(0),
                        )?;
                        if sent {
                            transaction.execute(
                                "UPDATE key_packages SET package = NULL, \
                                     replaced_at_ms = CASE WHEN last_resort = 1 \
                                         THEN coalesce(replaced_at_ms, ?2) END \
                                 WHERE reference = ?1",
                                (&reference, ms(now_ms)),
                            )?;
                        } else {
                            key_package::forget(&provider, &reference)?;
                            transaction.execute(
                                "DELETE FROM key_packages WHERE reference = ?1",
                                [reference],
                            )?;
                        }
                    }
                }
                Outcome::Unknown => {
                    for reference in &references {
                        transaction.execute(
                            "UPDATE key_packages SET sent = 1 WHERE reference = ?1",
                            [reference],
                        )?;
                    }
                }
            }
            Ok(())
        })
        .await
}

/// When the instance last refused packages because of this device's
/// clock, if it did.
pub(crate) async fn refused_at(store: &LocalStore) -> Result<Option<u64>, Failure> {
    store
        .transaction(|transaction| {
            let at: Option<i64> = transaction
                .query_row(
                    "SELECT value FROM client_state WHERE name = ?1",
                    [REFUSED_AT],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(at.map(|at| u64::try_from(at).unwrap_or(0)))
        })
        .await
}

/// Records a refusal caused by this device's clock (`Some`), or that the
/// clock is right again (`None`).
pub(crate) async fn set_refused_at(store: &LocalStore, at: Option<u64>) -> Result<(), Failure> {
    store
        .transaction(move |transaction| {
            match at {
                Some(at) => transaction.execute(
                    "INSERT INTO client_state (name, value) VALUES (?1, ?2) \
                     ON CONFLICT (name) DO UPDATE SET value = excluded.value",
                    (REFUSED_AT, ms(at)),
                )?,
                None => {
                    transaction.execute("DELETE FROM client_state WHERE name = ?1", [REFUSED_AT])?
                }
            };
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

    pub(crate) struct Setup {
        pub(crate) store: LocalStore,
        seed: [u8; 32],
        certificate: Vec<u8>,
        _dir: tempfile::TempDir,
    }

    impl Setup {
        pub(crate) fn new() -> Self {
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

        async fn settle(&self, upload: &ToUpload, outcome: Outcome, now_ms: u64) {
            settle(&self.store, upload, outcome, now_ms).await.unwrap();
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
        // The answer was lost: the same packages are sent again, the same
        // last resort among them.
        setup.settle(&first, Outcome::Unknown, NOW_MS).await;
        let again = setup.prepare(20, false, NOW_MS).await;
        assert_eq!(again, first);
        setup.settle(&again, Outcome::Taken, NOW_MS).await;
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

    /// Review of task 10a, point 9: packages whose upload was not confirmed
    /// are not counted twice. If the instance in fact stored them, its count
    /// has them: the device builds what is missing from that count, and the
    /// packages sent again change nothing. If it did not, the instance gets
    /// them and 20 more. Never below 20.
    #[tokio::test]
    async fn packages_not_confirmed_are_not_counted_twice() {
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        setup.settle(&first, Outcome::Unknown, NOW_MS).await;
        // The instance did store them, and served five since.
        let next = setup.prepare(15, false, NOW_MS).await;
        assert_eq!(next.one_time.len(), ONE_TIME_COUNT + 5);
        // It did not: they are sent again with 20 new ones.
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        setup.settle(&first, Outcome::Unknown, NOW_MS).await;
        let next = setup.prepare(0, false, NOW_MS).await;
        assert_eq!(next.one_time.len(), 2 * ONE_TIME_COUNT);
    }

    /// Section 3: the last-resort package is replaced after 30 days, or when
    /// a Welcome used it; the one it replaces keeps its private parts for
    /// the grace period (30 days), then they are deleted, without the
    /// instance (`forget_due`).
    #[tokio::test]
    async fn a_replaced_last_resort_package_is_kept_for_its_grace_period() {
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        setup.settle(&first, Outcome::Taken, NOW_MS).await;
        let old = reference(first.last_resort.as_ref().unwrap());

        let day = DAY_MS;
        assert!(setup.prepare(20, false, NOW_MS + 29 * day).await.is_empty());
        let rotated = setup.prepare(20, false, NOW_MS + 30 * day).await;
        let new = reference(rotated.last_resort.as_ref().unwrap());
        assert_ne!(new, old);
        setup
            .settle(&rotated, Outcome::Taken, NOW_MS + 30 * day)
            .await;
        assert!(setup.held(&old).await);

        assert!(!forget_due(&setup.store, NOW_MS + 59 * day).await.unwrap());
        assert!(setup.held(&old).await, "within the grace period");
        assert!(forget_due(&setup.store, NOW_MS + 60 * day).await.unwrap());
        assert!(!setup.held(&old).await, "after the grace period");
        assert!(setup.held(&new).await);

        // A Welcome used the last resort: replaced at once.
        let replaced = setup.prepare(20, true, NOW_MS + 61 * day).await;
        assert!(replaced.last_resort.is_some());
    }

    /// Review of task 10a, point 10: a Welcome made with the last-resort
    /// package deletes its private parts at the join (OpenMLS keeps them;
    /// `tavern_crypto::mls::Group::join` deletes them, tested there): the
    /// next upkeep sees it gone, and builds a new one at once, whatever its
    /// age, even without `replace_last_resort`.
    #[tokio::test]
    async fn a_last_resort_used_by_a_welcome_is_replaced() {
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        setup.settle(&first, Outcome::Taken, NOW_MS).await;
        let used = reference(first.last_resort.as_ref().unwrap());
        let deleted = used.clone();
        setup
            .store
            .transaction(move |transaction| {
                let provider = Provider::new(SqlStorage::new(transaction));
                // What the join does with a used last resort.
                Ok::<_, Failure>(key_package::forget(&provider, &deleted)?)
            })
            .await
            .unwrap();
        let next = setup.prepare(20, false, NOW_MS + DAY_MS).await;
        assert!(next.one_time.is_empty());
        let new = reference(next.last_resort.as_ref().expect("a new last resort"));
        assert_ne!(new, used);
    }

    /// Review of task 10a, point 1: a one-time package keeps its private
    /// parts through its lifetime and the longest retention (90 + 30 days),
    /// then they are deleted without the instance.
    #[tokio::test]
    async fn a_one_time_package_is_kept_through_its_lifetime_and_the_retention() {
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        setup.settle(&first, Outcome::Taken, NOW_MS).await;
        let one = reference(&first.one_time[0]);
        assert!(
            !forget_due(&setup.store, NOW_MS + 119 * DAY_MS)
                .await
                .unwrap()
        );
        assert!(setup.held(&one).await, "day 119");
        assert!(
            forget_due(&setup.store, NOW_MS + 120 * DAY_MS)
                .await
                .unwrap()
        );
        assert!(!setup.held(&one).await, "day 120");
    }

    /// Review of task 10a, point 8: a package refused the first time it is
    /// sent is forgotten; one sent before, whose answer was lost, and refused
    /// when sent again, may be on the instance: kept, never sent again.
    #[tokio::test]
    async fn a_refused_package_is_forgotten_only_if_never_sent_before() {
        let setup = Setup::new();
        let first = setup.prepare(0, false, NOW_MS).await;
        setup.settle(&first, Outcome::Refused, NOW_MS).await;
        for entry in first.one_time.iter().chain(first.last_resort.iter()) {
            assert!(!setup.held(&reference(entry)).await);
        }

        let second = setup.prepare(0, false, NOW_MS).await;
        assert_ne!(second.one_time, first.one_time);
        setup.settle(&second, Outcome::Unknown, NOW_MS).await;
        setup.settle(&second, Outcome::Refused, NOW_MS).await;
        for entry in second.one_time.iter().chain(second.last_resort.iter()) {
            assert!(setup.held(&reference(entry)).await);
        }
        // Not sent again: new packages in their place, and a new last resort.
        let third = setup.prepare(0, false, NOW_MS).await;
        assert!(
            third
                .one_time
                .iter()
                .all(|entry| !second.one_time.contains(entry))
        );
        assert_ne!(third.last_resort, second.last_resort);
        // The old last resort, as replaced, goes after its grace period.
        let old = reference(second.last_resort.as_ref().unwrap());
        forget_due(&setup.store, NOW_MS + LAST_RESORT_GRACE_MS)
            .await
            .unwrap();
        assert!(!setup.held(&old).await);
    }

    /// Review of task 10a, point 2: the upkeep runs every hour on its own
    /// clock, connected or not (here a simulated one).
    #[tokio::test(start_paused = true)]
    async fn the_upkeep_runs_every_hour_on_its_own() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let runs = Arc::new(AtomicU32::new(0));
        let handle = spawn_every(UPKEEP_INTERVAL, {
            let runs = Arc::clone(&runs);
            move || {
                let runs = Arc::clone(&runs);
                async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        tokio::task::yield_now().await;
        assert_eq!(runs.load(Ordering::SeqCst), 1, "at once");
        for _ in 0..24 {
            tokio::time::advance(UPKEEP_INTERVAL).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            25,
            "then every hour, for a day"
        );
        handle.abort();
    }

    /// Review of task 10a, point 15: only a certificate of this device's key,
    /// for this account and this device, under the account's identity key.
    #[test]
    fn only_this_devices_certificate_is_kept() {
        let (user, device) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let root = AccountRootSecret::generate();
        let identity = root.identity_key().unwrap();
        let key = DeviceKey::generate();
        let public = identity.public().to_bytes();
        let good =
            identity.certify_device(user.as_bytes(), device.as_bytes(), &key.public(), NOW_MS);
        assert!(check_certificate(&public, &good, user, device, &key).is_ok());

        let untrusted = |result: Result<(), ClientError>| {
            assert!(
                matches!(result, Err(ClientError::UntrustedKeyMaterial)),
                "{result:?}"
            );
        };
        // Another account's identity key.
        let other = AccountRootSecret::generate().identity_key().unwrap();
        untrusted(check_certificate(
            &other.public().to_bytes(),
            &good,
            user,
            device,
            &key,
        ));
        // Another device, another account, another key.
        untrusted(check_certificate(
            &public,
            &good,
            user,
            Uuid::from_u128(3),
            &key,
        ));
        untrusted(check_certificate(
            &public,
            &good,
            Uuid::from_u128(3),
            device,
            &key,
        ));
        untrusted(check_certificate(
            &public,
            &good,
            user,
            device,
            &DeviceKey::generate(),
        ));
        // Not a certificate.
        untrusted(check_certificate(&public, b"garbage", user, device, &key));
        let mut tampered = good.clone();
        if let Some(byte) = tampered.last_mut() {
            *byte ^= 1;
        }
        untrusted(check_certificate(&public, &tampered, user, device, &key));
    }

    /// Review of task 10a, point 16, the branches of the upkeep: the
    /// instance's refusal, and a failure of the network (or no answer),
    /// which leaves the result unknown.
    #[test]
    fn an_upload_is_taken_refused_or_unknown() {
        assert_eq!(Outcome::of(&Ok::<(), ClientError>(())), Outcome::Taken);
        let refused: Result<(), ClientError> = Err(ClientError::Api {
            code: tavern_protocol::rest::ErrorCode::InvalidKeyPackage,
            retry_after_ms: None,
        });
        assert_eq!(Outcome::of(&refused), Outcome::Refused);
        for failure in [ClientError::ServerError, ClientError::Interrupted] {
            assert_eq!(Outcome::of(&Err::<(), _>(failure)), Outcome::Unknown);
        }
    }

    /// The time of a refusal caused by the clock is kept, and cleared.
    #[tokio::test]
    async fn a_refusal_caused_by_the_clock_is_remembered() {
        let setup = Setup::new();
        assert_eq!(refused_at(&setup.store).await.unwrap(), None);
        set_refused_at(&setup.store, Some(NOW_MS)).await.unwrap();
        assert_eq!(refused_at(&setup.store).await.unwrap(), Some(NOW_MS));
        set_refused_at(&setup.store, None).await.unwrap();
        assert_eq!(refused_at(&setup.store).await.unwrap(), None);
    }
}
