// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where a device keeps its secrets between launches (ADR 0017).
//!
//! Everything here lives in the operating system's credential store
//! (Keychain, Credential Manager, Secret Service), never in a file:
//!
//! - **one record per instance, profile and account** ([`StoredDevice`]): the
//!   identity of this device for that account. Signing in to another account
//!   uses another record, so each account keeps its device;
//! - **one index per instance and profile** ([`KnownAccounts`]): which
//!   accounts have a record, and which was used last.
//!
//! What a record holds depends on whether the account is signed in:
//!
//! | | signed in | signed out |
//! |---|---|---|
//! | device key seed | yes | yes |
//! | wrapped store key | yes | yes |
//! | session token | yes | no |
//! | store key | yes | no |
//!
//! The wrapped store key opens only with a part derived from the account
//! root secret and a part held by the server: the local store of a
//! signed-out account cannot be read without authenticating again.
//!
//! The account root secret and the account identity key are never stored:
//! they are in memory for the time of a sign-in and erased right after.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tavern_protocol::rest::B64;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// What a device remembers about one account on one instance.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDevice {
    /// The account.
    pub user_id: Uuid,
    /// Canonical handle, to prefill the login screen.
    pub handle: String,
    /// This device.
    pub device_id: Uuid,
    /// Seed of the device key.
    pub device_seed: B64,
    /// The key of the local store, wrapped (`tavern_crypto::local_store`).
    pub wrapped_store_key: B64,
    /// Current session token. Absent while signed out.
    pub session_token: Option<B64>,
    /// The key of the local store. Absent while signed out.
    pub store_key: Option<B64>,
}

impl StoredDevice {
    /// Removes what only a signed-in account may keep.
    pub fn sign_out(&mut self) {
        self.session_token = None;
        self.store_key = None;
    }
}

impl std::fmt::Debug for StoredDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |present: bool| present.then_some("<redacted>");
        f.debug_struct("StoredDevice")
            .field("user_id", &self.user_id)
            .field("handle", &self.handle)
            .field("device_id", &self.device_id)
            .field("device_seed", &"<redacted>")
            .field("wrapped_store_key", &"<redacted>")
            .field("session_token", &redacted(self.session_token.is_some()))
            .field("store_key", &redacted(self.store_key.is_some()))
            .finish()
    }
}

/// An account that has a device record on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownAccount {
    /// The account.
    pub user_id: Uuid,
    /// Canonical handle.
    pub handle: String,
}

/// The accounts known for one instance and profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownAccounts {
    /// Accounts with a device record, in the order they were first used.
    pub accounts: Vec<KnownAccount>,
    /// The account used last: resumed at start-up, prefilled at sign-in.
    pub last: Option<Uuid>,
}

/// A place to keep small secrets under string keys.
pub trait SecretStore: Send + Sync {
    /// Reads the secret stored under `key`.
    fn read(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ClientError>;
    /// Writes the secret stored under `key`.
    fn write(&self, key: &str, secret: &[u8]) -> Result<(), ClientError>;
    /// Removes the secret stored under `key`. Not an error if there is none.
    fn delete(&self, key: &str) -> Result<(), ClientError>;
}

/// The device records and the index of one instance and profile.
#[derive(Clone)]
pub(crate) struct Records {
    store: Arc<dyn SecretStore>,
    /// Key of the index; device records append `@<user id>`.
    base: String,
}

impl Records {
    /// `profile` separates several sets of accounts on one computer (used
    /// for development and tests).
    pub(crate) fn new(
        store: Arc<dyn SecretStore>,
        instance_url: &str,
        profile: Option<&str>,
    ) -> Self {
        let base = match profile {
            Some(profile) if !profile.is_empty() => format!("{instance_url}#{profile}"),
            _ => instance_url.to_owned(),
        };
        Self { store, base }
    }

    fn device_key(&self, user_id: Uuid) -> String {
        format!("{}@{user_id}", self.base)
    }

    /// A record this version cannot read (an older format, corruption) is
    /// treated as absent: the user signs in and the device is enrolled anew.
    fn load<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, ClientError> {
        Ok(self
            .store
            .read(key)?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok()))
    }

    fn save<T: Serialize>(&self, key: &str, value: &T) -> Result<(), ClientError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(value).map_err(|error| ClientError::Store(error.to_string()))?,
        );
        self.store.write(key, &bytes)
    }

    /// The accounts known here.
    pub(crate) fn known(&self) -> Result<KnownAccounts, ClientError> {
        Ok(self.load(&self.base)?.unwrap_or_default())
    }

    /// The device record of an account, if this computer has one.
    pub(crate) fn device(&self, user_id: Uuid) -> Result<Option<StoredDevice>, ClientError> {
        Ok(self
            .load::<StoredDevice>(&self.device_key(user_id))?
            .filter(|device| device.user_id == user_id))
    }

    /// The record of the account used last.
    pub(crate) fn last_device(&self) -> Result<Option<StoredDevice>, ClientError> {
        match self.known()?.last {
            Some(user_id) => self.device(user_id),
            None => Ok(None),
        }
    }

    /// Writes a device record and makes its account the last one used.
    pub(crate) fn save_device(&self, device: &StoredDevice) -> Result<(), ClientError> {
        self.save(&self.device_key(device.user_id), device)?;
        let mut known = self.known()?;
        known
            .accounts
            .retain(|account| account.user_id != device.user_id);
        known.accounts.push(KnownAccount {
            user_id: device.user_id,
            handle: device.handle.clone(),
        });
        known.last = Some(device.user_id);
        self.save(&self.base, &known)
    }

    /// Updates a device record without changing which account was used last.
    pub(crate) fn update_device(&self, device: &StoredDevice) -> Result<(), ClientError> {
        self.save(&self.device_key(device.user_id), device)
    }

    /// Deletes the device record of an account: this computer is no longer a
    /// device of it.
    pub(crate) fn forget_device(&self, user_id: Uuid) -> Result<(), ClientError> {
        self.store.delete(&self.device_key(user_id))?;
        let mut known = self.known()?;
        known.accounts.retain(|account| account.user_id != user_id);
        if known.last == Some(user_id) {
            known.last = None;
        }
        self.save(&self.base, &known)
    }
}

/// A store that forgets everything when dropped. For tests.
#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<HashMap<String, Vec<u8>>>);

impl MemoryStore {
    /// Every secret stored, concatenated: lets a test check that some bytes
    /// are not kept anywhere.
    pub fn all_bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .flatten()
            .copied()
            .collect()
    }
}

impl SecretStore for MemoryStore {
    fn read(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ClientError> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned()
            .map(Zeroizing::new))
    }

    fn write(&self, key: &str, secret: &[u8]) -> Result<(), ClientError> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.to_owned(), secret.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), ClientError> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
        Ok(())
    }
}

/// The operating system's credential store.
#[derive(Debug, Clone)]
pub struct KeychainStore {
    service: String,
}

impl KeychainStore {
    /// Creates a store whose entries are filed under `service`, the
    /// application identifier.
    pub fn new(service: &str) -> Self {
        Self {
            service: service.to_owned(),
        }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, ClientError> {
        keyring::Entry::new(&self.service, key)
            .map_err(|error| ClientError::Store(error.to_string()))
    }
}

impl SecretStore for KeychainStore {
    fn read(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, ClientError> {
        match self.entry(key)?.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(ClientError::Store(error.to_string())),
        }
    }

    fn write(&self, key: &str, secret: &[u8]) -> Result<(), ClientError> {
        self.entry(key)?
            .set_secret(secret)
            .map_err(|error| ClientError::Store(error.to_string()))
    }

    fn delete(&self, key: &str) -> Result<(), ClientError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(ClientError::Store(error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(user: u128, handle: &str) -> StoredDevice {
        StoredDevice {
            user_id: Uuid::from_u128(user),
            handle: handle.to_owned(),
            device_id: Uuid::from_u128(user + 100),
            device_seed: B64(vec![0xAB; 32]),
            wrapped_store_key: B64(vec![0xEF; 73]),
            session_token: Some(B64(vec![0xCD; 32])),
            store_key: Some(B64(vec![0x12; 32])),
        }
    }

    fn records(store: &Arc<MemoryStore>, profile: Option<&str>) -> Records {
        Records::new(store.clone(), "https://x/", profile)
    }

    #[test]
    fn each_account_keeps_its_own_device_record() {
        let store = Arc::new(MemoryStore::default());
        let records = records(&store, None);
        let (alice, bob) = (sample(1, "alice"), sample(2, "bob"));

        assert_eq!(records.known().unwrap(), KnownAccounts::default());
        records.save_device(&alice).unwrap();
        records.save_device(&bob).unwrap();

        // Signing in to bob did not touch alice's device.
        assert_eq!(records.device(alice.user_id).unwrap(), Some(alice.clone()));
        assert_eq!(records.device(bob.user_id).unwrap(), Some(bob.clone()));
        assert_eq!(records.last_device().unwrap(), Some(bob.clone()));
        let handles: Vec<String> = records
            .known()
            .unwrap()
            .accounts
            .into_iter()
            .map(|account| account.handle)
            .collect();
        assert_eq!(handles, ["alice", "bob"]);

        // Coming back to alice makes her the last one used, without a duplicate.
        records.save_device(&alice).unwrap();
        assert_eq!(records.last_device().unwrap(), Some(alice.clone()));
        assert_eq!(records.known().unwrap().accounts.len(), 2);

        // Forgetting one account leaves the other.
        records.forget_device(alice.user_id).unwrap();
        records.forget_device(alice.user_id).unwrap();
        assert_eq!(records.device(alice.user_id).unwrap(), None);
        assert_eq!(records.last_device().unwrap(), None);
        assert_eq!(records.device(bob.user_id).unwrap(), Some(bob));
    }

    #[test]
    fn profiles_and_instances_are_separate() {
        let store = Arc::new(MemoryStore::default());
        let alice = sample(1, "alice");
        records(&store, None).save_device(&alice).unwrap();

        assert_eq!(
            records(&store, Some("")).device(alice.user_id).unwrap(),
            Some(alice.clone())
        );
        assert_eq!(
            records(&store, Some("second"))
                .device(alice.user_id)
                .unwrap(),
            None
        );
        let elsewhere = Records::new(store.clone(), "https://y/", None);
        assert_eq!(elsewhere.device(alice.user_id).unwrap(), None);
        assert_eq!(elsewhere.known().unwrap(), KnownAccounts::default());
    }

    #[test]
    fn signing_out_keeps_the_device_and_drops_what_opens_the_store() {
        let mut device = sample(1, "alice");
        device.sign_out();

        assert_eq!(device.session_token, None);
        assert_eq!(device.store_key, None);
        assert_eq!(device.device_seed, sample(1, "alice").device_seed);
        assert_eq!(
            device.wrapped_store_key,
            sample(1, "alice").wrapped_store_key
        );
    }

    #[test]
    fn an_unreadable_record_is_treated_as_absent() {
        let store = Arc::new(MemoryStore::default());
        let records = records(&store, None);
        let alice = sample(1, "alice");
        // What milestone M1 stored under the key that now holds the index.
        store
            .write("https://x/", br#"{"user_id":"x","handle":"old"}"#)
            .unwrap();
        store
            .write(&records.device_key(alice.user_id), b"not json")
            .unwrap();

        assert_eq!(records.known().unwrap(), KnownAccounts::default());
        assert_eq!(records.device(alice.user_id).unwrap(), None);
        // And is simply replaced by the next sign-in.
        records.save_device(&alice).unwrap();
        assert_eq!(records.last_device().unwrap(), Some(alice));
    }

    #[test]
    fn debug_output_hides_keys_and_token() {
        let debug = format!("{:?}", sample(1, "alice"));

        assert!(debug.contains("alice"));
        assert!(!debug.contains("171") && !debug.to_lowercase().contains("ab, ab"));
        assert_eq!(debug.matches("<redacted>").count(), 4);
    }
}
