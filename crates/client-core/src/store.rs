// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where a device keeps its secrets between launches.
//!
//! At milestone M1 a device stores one small record per instance: its
//! identifiers, its device key and its session token. It lives in the
//! operating system's credential store (Keychain, Credential Manager, Secret
//! Service), never in a file. The encrypted local database arrives with M2.
//!
//! The account identity key is never stored: it is unwrapped in memory when a
//! device is enrolled and erased right after.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use tavern_protocol::rest::B64;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// What a device remembers about its account on one instance.
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
    /// Current session token, absent after a logout or an ended session.
    pub session_token: Option<B64>,
}

impl std::fmt::Debug for StoredDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredDevice")
            .field("user_id", &self.user_id)
            .field("handle", &self.handle)
            .field("device_id", &self.device_id)
            .field("device_seed", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A place to keep one [`StoredDevice`] per key.
pub trait SecretStore: Send + Sync {
    /// Reads the record stored under `key`.
    fn load(&self, key: &str) -> Result<Option<StoredDevice>, ClientError>;
    /// Writes the record stored under `key`.
    fn save(&self, key: &str, device: &StoredDevice) -> Result<(), ClientError>;
    /// Removes the record stored under `key`. Not an error if there is none.
    fn delete(&self, key: &str) -> Result<(), ClientError>;
}

/// The key under which the record for an instance is stored. `profile`
/// separates several accounts on one computer (used for development and
/// tests; a profile switcher may come later).
pub fn store_key(instance_url: &str, profile: Option<&str>) -> String {
    match profile {
        Some(profile) if !profile.is_empty() => format!("{instance_url}#{profile}"),
        _ => instance_url.to_owned(),
    }
}

/// A store that forgets everything when dropped. For tests.
#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<HashMap<String, StoredDevice>>);

impl SecretStore for MemoryStore {
    fn load(&self, key: &str) -> Result<Option<StoredDevice>, ClientError> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned())
    }

    fn save(&self, key: &str, device: &StoredDevice) -> Result<(), ClientError> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.to_owned(), device.clone());
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
    fn load(&self, key: &str) -> Result<Option<StoredDevice>, ClientError> {
        match self.entry(key)?.get_secret() {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                // A record this version cannot read is treated as absent: the
                // user logs in again and the device is enrolled anew.
                Ok(serde_json::from_slice(&bytes).ok())
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(ClientError::Store(error.to_string())),
        }
    }

    fn save(&self, key: &str, device: &StoredDevice) -> Result<(), ClientError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(device).map_err(|error| ClientError::Store(error.to_string()))?,
        );
        self.entry(key)?
            .set_secret(&bytes)
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

    fn sample() -> StoredDevice {
        StoredDevice {
            user_id: Uuid::from_u128(1),
            handle: "alice".to_owned(),
            device_id: Uuid::from_u128(2),
            device_seed: B64(vec![0xAB; 32]),
            session_token: Some(B64(vec![0xCD; 32])),
        }
    }

    #[test]
    fn the_memory_store_round_trips_and_deletes() {
        let store = MemoryStore::default();

        assert_eq!(store.load("k").unwrap(), None);
        store.save("k", &sample()).unwrap();
        assert_eq!(store.load("k").unwrap(), Some(sample()));
        assert_eq!(store.load("other").unwrap(), None);
        store.delete("k").unwrap();
        store.delete("k").unwrap();
        assert_eq!(store.load("k").unwrap(), None);
    }

    #[test]
    fn profiles_get_separate_keys() {
        assert_eq!(store_key("https://x/", None), "https://x/");
        assert_eq!(store_key("https://x/", Some("")), "https://x/");
        assert_eq!(store_key("https://x/", Some("second")), "https://x/#second");
    }

    #[test]
    fn debug_output_hides_the_key_and_token() {
        let debug = format!("{:?}", sample());

        assert!(debug.contains("alice"));
        assert!(!debug.contains("171") && !debug.to_lowercase().contains("ab, ab"));
        assert!(debug.matches("<redacted>").count() == 2);
    }

    #[test]
    fn the_stored_form_round_trips_through_json() {
        let json = serde_json::to_vec(&sample()).unwrap();
        assert_eq!(
            serde_json::from_slice::<StoredDevice>(&json).unwrap(),
            sample()
        );
    }
}
