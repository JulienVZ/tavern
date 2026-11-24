// SPDX-License-Identifier: AGPL-3.0-or-later

//! Registry of connected devices, used to push events to them.
//!
//! The WebSocket endpoint that feeds this registry is in `routes/gateway.rs`.
//! Events are notifications, never the only copy of anything: a device that
//! is offline learns about missed enrolments and security notices from the
//! `Ready` message at its next connection, gets its Welcomes again, and
//! fetches the sequences it has not read. An event is never dropped in
//! silence either: a connection whose queue is full is taken out of the
//! registry, and closed with 4009 once it has sent what its queue holds.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tavern_protocol::gateway::v1 as proto;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::notices::Notice;

/// Where the receiving user stands with another one (ADR 0020).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// Nothing: no request, no friendship, or a block by the other user.
    None,
    /// This user sent a request.
    RequestSent,
    /// The other user sent a request.
    RequestReceived,
    /// Friends.
    Friends,
    /// This user blocks the other one.
    Blocked,
}

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

/// Something a connected device is told. Messages are shared, not copied,
/// between the devices they go to.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A claim left the receiving device fewer than 10 one-time KeyPackages.
    KeyPackagesLow {
        /// The one-time KeyPackages left.
        remaining: u32,
    },
    /// The receiving user's relation with `user_id` changed.
    FriendshipChanged {
        /// The other user.
        user_id: Uuid,
        /// The relation now, as the receiving user sees it.
        relation: Relation,
    },
    /// A DM of the receiving user was created.
    ConversationCreated {
        /// The conversation.
        conversation_id: Uuid,
        /// Its two users, smaller id first.
        members: [Uuid; 2],
    },
    /// A message of a conversation's sequence: application, commit or
    /// proposal.
    Sequenced(Arc<proto::StoredMessage>),
    /// A Welcome for the receiving device.
    Welcome(Arc<proto::WelcomeEvent>),
    /// The receiving device is not in the group of a conversation of its
    /// user, or is being removed from it: it joins by external commit.
    JoinConversation {
        /// The conversation.
        conversation_id: Uuid,
    },
    /// A friend of the receiving user enrolled (`added`) or revoked a device.
    UserDevicesChanged {
        /// The friend.
        user_id: Uuid,
        /// The device.
        device_id: Uuid,
        /// `true` for an enrolment, `false` for a revocation.
        added: bool,
    },
}

/// Events queued per connection. A device that lets more wait is
/// disconnected (4009): it reconnects, and fetches what it missed.
pub const EVENT_QUEUE_LEN: usize = 32;

#[derive(Debug)]
struct Connection {
    user_id: Uuid,
    /// Distinguishes two successive connections of the same device.
    generation: u64,
    sender: mpsc::Sender<Event>,
    /// Set when an event found the queue full.
    overflowed: Arc<AtomicBool>,
    /// Set when the device's session ended: the connection closes at once.
    ended: watch::Sender<Option<RevocationReason>>,
}

impl Connection {
    /// Queues `event`. `false` when the queue is full: the event is not
    /// delivered, and the connection must leave the registry.
    fn deliver(&self, event: Event) -> bool {
        match self.sender.try_send(event) {
            Err(TrySendError::Full(_)) => {
                self.overflowed.store(true, Ordering::Release);
                false
            }
            // Closed: the connection is ending, and leaves by itself.
            Ok(()) | Err(TrySendError::Closed(_)) => true,
        }
    }
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
    /// Events for this connection. They end when the registry lets the
    /// connection go: replaced, or its queue full ([`Self::overflowed`]).
    pub events: mpsc::Receiver<Event>,
    /// Identifies this connection in [`Registry::disconnect`].
    pub generation: u64,
    overflowed: Arc<AtomicBool>,
    /// Resolves once the device's session ended.
    pub ended: SessionEnd,
}

/// The end of a connection's session, set by [`Registry::end_session`].
#[derive(Debug)]
pub struct SessionEnd(watch::Receiver<Option<RevocationReason>>);

impl SessionEnd {
    /// Resolves once the device's session ended ([`Registry::end_session`]),
    /// with the reason; never otherwise. The connection then closes at once,
    /// whatever its queue still holds and whatever the client sends.
    pub async fn wait(&mut self) -> RevocationReason {
        loop {
            if let Some(reason) = *self.0.borrow_and_update() {
                return reason;
            }
            if self.0.changed().await.is_err() {
                // The registry let the connection go otherwise: its events
                // say how.
                std::future::pending::<()>().await;
            }
        }
    }
}

impl Subscription {
    /// Whether the registry let this connection go because an event found
    /// its queue full.
    pub fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }
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
        let (sender, events) = mpsc::channel(EVENT_QUEUE_LEN);
        let overflowed = Arc::new(AtomicBool::new(false));
        let (ended_sender, ended) = watch::channel(None);
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
                    overflowed: Arc::clone(&overflowed),
                    ended: ended_sender,
                },
            );
        if let Some(previous) = previous {
            // Dropped next, which ends its events: if its queue is full, it
            // closes as replaced all the same.
            let _ = previous
                .sender
                .try_send(Event::SessionRevoked(RevocationReason::Replaced));
        }
        Subscription {
            events,
            generation,
            overflowed,
            ended: SessionEnd(ended),
        }
    }

    /// The session of `device_id` ended (revoked, the account disabled, its
    /// credentials changed): its connection, if any, leaves the registry and
    /// closes at once with `reason`, without handling another request or
    /// waiting for its queue to drain.
    pub fn end_session(&self, device_id: Uuid, reason: RevocationReason) {
        let connection = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&device_id);
        if let Some(connection) = connection {
            // Set before the connection's queue closes with it.
            connection.ended.send_replace(Some(reason));
        }
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

    /// Sends an event to one device, if connected. A device whose queue is
    /// full is let go instead (4009).
    pub fn notify_device(&self, device_id: Uuid, event: Event) {
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if connections
            .get(&device_id)
            .is_some_and(|connection| !connection.deliver(event))
        {
            connections.remove(&device_id);
        }
    }

    /// Sends an event to every connected device of an account, except
    /// `except`. A device whose queue is full is let go instead (4009).
    pub fn notify_user(&self, user_id: Uuid, except: Option<Uuid>, event: Event) {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|device_id, connection| {
                connection.user_id != user_id
                    || Some(*device_id) == except
                    || connection.deliver(event.clone())
            });
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

    #[tokio::test]
    async fn an_ended_session_closes_its_connection_at_once() {
        let registry = Registry::default();
        let (user, device) = (Uuid::from_u128(1), Uuid::from_u128(11));
        let mut subscription = registry.connect(user, device);
        registry.notify_device(device, ADDED);
        registry.end_session(device, RevocationReason::Revoked);
        assert_eq!(subscription.ended.wait().await, RevocationReason::Revoked);
        assert_eq!(registry.connected(), 0);
        // Nothing reaches it any more; its other devices are not concerned.
        registry.end_session(Uuid::from_u128(12), RevocationReason::Revoked);
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

    /// An event that finds the queue full is not dropped in silence: the
    /// connection is let go, after the events it holds, and knows why.
    #[test]
    fn a_full_queue_lets_the_connection_go_instead_of_dropping_events() {
        let registry = Registry::default();
        let (user, device) = (Uuid::from_u128(1), Uuid::from_u128(11));
        let other = Uuid::from_u128(12);
        let mut subscription = registry.connect(user, device);
        let mut other_subscription = registry.connect(user, other);

        for _ in 0..EVENT_QUEUE_LEN {
            registry.notify_device(device, ADDED);
        }
        assert_eq!(registry.connected(), 2);
        assert!(!subscription.overflowed());
        registry.notify_user(user, None, ADDED);
        assert_eq!(registry.connected(), 1, "the full one is let go");
        assert!(subscription.overflowed());
        for _ in 0..EVENT_QUEUE_LEN {
            assert_eq!(subscription.events.try_recv().unwrap(), ADDED);
        }
        assert_eq!(
            subscription.events.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
        assert_eq!(other_subscription.events.try_recv().unwrap(), ADDED);
        assert!(!other_subscription.overflowed());

        // Through notify_device as well.
        for _ in 0..=EVENT_QUEUE_LEN {
            registry.notify_device(other, ADDED);
        }
        assert_eq!(registry.connected(), 0);
        assert!(other_subscription.overflowed());
    }

    /// A replaced connection is not one that overflowed.
    #[test]
    fn a_replaced_connection_did_not_overflow() {
        let registry = Registry::default();
        let (user, device) = (Uuid::from_u128(1), Uuid::from_u128(11));
        let first = registry.connect(user, device);
        let _second = registry.connect(user, device);
        assert!(!first.overflowed());
    }
}
