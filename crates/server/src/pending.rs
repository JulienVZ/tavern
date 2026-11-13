// SPDX-License-Identifier: AGPL-3.0-or-later

//! Short-lived state kept in memory between the steps of an exchange: OPAQUE
//! logins in progress, enrolment tokens, challenges.
//!
//! Entries expire after a fixed time and each map has a hard capacity, so an
//! attacker who starts many exchanges cannot grow the server's memory without
//! bound. Entries are single use: reading one removes it.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// A map whose entries expire and can be taken once.
#[derive(Debug)]
pub struct ExpiringMap<K, V> {
    entries: Mutex<HashMap<K, (Instant, V)>>,
    ttl: Duration,
    capacity: usize,
}

impl<K: Eq + Hash, V> ExpiringMap<K, V> {
    /// Creates a map whose entries live for `ttl`, holding at most `capacity` of them.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            capacity,
        }
    }

    /// Stores `value` under `key`. Returns `false`, storing nothing, when the
    /// map is full even after dropping expired entries.
    pub fn insert(&self, key: K, value: V) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.capacity {
            entries.retain(|_, (expires, _)| *expires > now);
            if entries.len() >= self.capacity {
                return false;
            }
        }
        entries.insert(key, (now + self.ttl, value));
        true
    }

    /// Removes and returns the value under `key`, unless it is absent or expired.
    pub fn take(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let (expires, value) = entries.remove(key)?;
        (expires > Instant::now()).then_some(value)
    }

    /// How long entries live.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_single_use() {
        let map = ExpiringMap::new(Duration::from_secs(60), 10);

        assert!(map.insert("a", 1));
        assert_eq!(map.take(&"a"), Some(1));
        assert_eq!(map.take(&"a"), None);
        assert_eq!(map.take(&"never"), None);
    }

    #[test]
    fn expired_entries_cannot_be_taken() {
        let map = ExpiringMap::new(Duration::ZERO, 10);

        assert!(map.insert("a", 1));
        assert_eq!(map.take(&"a"), None);
    }

    #[test]
    fn capacity_is_enforced() {
        let map = ExpiringMap::new(Duration::from_secs(60), 2);

        assert!(map.insert("a", 1));
        assert!(map.insert("b", 2));
        assert!(!map.insert("c", 3));
        assert_eq!(map.take(&"c"), None);
        assert_eq!(map.take(&"a"), Some(1));
        assert!(map.insert("c", 3));
    }

    #[test]
    fn expired_entries_make_room() {
        let map = ExpiringMap::new(Duration::ZERO, 1);

        assert!(map.insert("a", 1));
        assert!(map.insert("b", 2));
    }
}
