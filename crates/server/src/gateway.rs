// SPDX-License-Identifier: AGPL-3.0-or-later

//! Registry of connected devices, used to push events to them.
//!
//! The WebSocket endpoint that feeds this registry is in `routes/gateway.rs`.
//! Events are best effort: a device that is offline learns about missed
//! enrolments and security notices from the `Ready` message at its next
//! connection.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use tokio::sync::mpsc;
use uuid::Uuid;

use crate::notices::Notice;

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    /// The user logged out or revoked the device.
    Revoked,
    /// The password was changed or recovered.
    CredentialsChanged,
    /// The account was disabled by an administrator.
    AccountDisabled,
    /// A newer connection of the same device replaced this one.
    Replaced,
}

/// Something a connected device is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A device of the account was enrolled (`added`) or revoked.
    DeviceListChanged {
        /// The device concerned.
        device_id: Uuid,
        /// `true` for an enrolment, `false` for a revocation.
        added: bool,
    },
    /// The session of the receiving device ended. The connection closes next.
    SessionRevoked(RevocationReason),
    /// Something security-relevant happened to the account. The notice is
    /// stored: devices that miss this event get it at their next connection.
    SecurityNotice(Notice),
}

/// Events queued per connection before the device is considered too slow.
const QUEUE_LEN: usize = 32;

#[derive(Debug)]
struct Connection {
    user_id: Uuid,
    /// Distinguishes two successive connections of the same device.
    generation: u64,
    sender: mpsc::Sender<Event>,
}

/// Connected devices, by device id.
#[derive(Debug, Default)]
pub struct Registry {
    connections: Mutex<HashMap<Uuid, Connection>>,
    next_generation: Mutex<u64>,
}

/// Handle returned by [`Registry::connect`].
#[derive(Debug)]
pub struct Subscription {
    /// Events for this connection.
    pub events: mpsc::Receiver<Event>,
    /// Identifies this connection in [`Registry::disconnect`].
    pub generation: u64,
}

impl Registry {
    /// Registers a connection for `device_id`. A previous connection of the
    /// same device is told it was replaced.
    pub fn connect(&self, user_id: Uuid, device_id: Uuid) -> Subscription {
        let generation = {
            let mut next = self
                .next_generation
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *next += 1;
            *next
        };
        let (sender, events) = mpsc::channel(QUEUE_LEN);
        let previous = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                device_id,
                Connection {
                    user_id,
                    generation,
                    sender,
                },
            );
        if let Some(previous) = previous {
            // Best effort: if its queue is full the old connection times out anyway.
            let _ = previous
                .sender
                .try_send(Event::SessionRevoked(RevocationReason::Replaced));
        }
        Subscription { events, generation }
    }

    /// Removes a connection, unless a newer one of the same device replaced it.
    pub fn disconnect(&self, device_id: Uuid, generation: u64) {
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if connections
            .get(&device_id)
            .is_some_and(|c| c.generation == generation)
        {
            connections.remove(&device_id);
        }
    }

    /// Sends an event to one device, if connected.
    pub fn notify_device(&self, device_id: Uuid, event: Event) {
        let connections = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(connection) = connections.get(&device_id) {
            let _ = connection.sender.try_send(event);
        }
    }

    /// Sends an event to every connected device of an account, except `except`.
    pub fn notify_user(&self, user_id: Uuid, except: Option<Uuid>, event: Event) {
        let connections = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (device_id, connection) in connections.iter() {
            if connection.user_id == user_id && Some(*device_id) != except {
                let _ = connection.sender.try_send(event);
            }
        }
    }

    /// Number of connected devices.
    pub fn connected(&self) -> usize {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDED: Event = Event::DeviceListChanged {
        device_id: Uuid::nil(),
        added: true,
    };

    #[test]
    fn events_reach_the_other_devices_of_the_account_only() {
        let registry = Registry::default();
        let (alice, bob) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let (a1, a2, b1) = (
            Uuid::from_u128(11),
            Uuid::from_u128(12),
            Uuid::from_u128(21),
        );
        let mut sub_a1 = registry.connect(alice, a1);
        let mut sub_a2 = registry.connect(alice, a2);
        let mut sub_b1 = registry.connect(bob, b1);

        registry.notify_user(alice, Some(a2), ADDED);

        assert_eq!(sub_a1.events.try_recv().unwrap(), ADDED);
        assert!(sub_a2.events.try_recv().is_err());
        assert!(sub_b1.events.try_recv().is_err());
    }

    #[test]
    fn a_second_connection_replaces_the_first() {
        let registry = Registry::default();
        let (user, device) = (Uuid::from_u128(1), Uuid::from_u128(11));
        let mut first = registry.connect(user, device);
        let mut second = registry.connect(user, device);

        assert_eq!(
            first.events.try_recv().unwrap(),
            Event::SessionRevoked(RevocationReason::Replaced)
        );
        // The old connection's clean-up must not remove the new one.
        registry.disconnect(device, first.generation);
        assert_eq!(registry.connected(), 1);
        registry.notify_device(device, ADDED);
        assert_eq!(second.events.try_recv().unwrap(), ADDED);

        registry.disconnect(device, second.generation);
        assert_eq!(registry.connected(), 0);
    }

    #[test]
    fn a_full_queue_drops_events_instead_of_blocking() {
        let registry = Registry::default();
        let (user, device) = (Uuid::from_u128(1), Uuid::from_u128(11));
        let _subscription = registry.connect(user, device);

        for _ in 0..(QUEUE_LEN * 2) {
            registry.notify_device(device, ADDED);
        }
    }
}
