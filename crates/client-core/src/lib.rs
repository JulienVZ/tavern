// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tavern client logic, independent of any user interface.
//!
//! The desktop shell (`apps/desktop/src-tauri`) is a thin layer over this
//! crate. At milestone M1 it covers accounts: registration, login, device
//! enrolment, sessions, TOTP, administration of invitations, and the
//! real-time connection that announces new devices.
//!
//! Keys and passwords never leave this crate towards the interface: the
//! interface passes what the user typed and receives results to display.

pub mod account;
mod api;
pub mod error;
pub mod gateway;
pub mod instance;
pub mod password;
pub mod qr;
pub mod store;

pub use account::{
    Client, InstanceClient, LoginStep, NewAccount, PendingTotp, Registered, SignedIn,
};
pub use error::ClientError;
pub use gateway::{
    Gateway, GatewayEvent, NewDevice, SecurityNotice, SecurityNoticeKind, SessionEnd,
};
pub use instance::{
    Compatibility, InstanceUrl, InstanceUrlError, compatibility, fetch_health, fetch_version,
};
pub use store::{KeychainStore, MemoryStore, SecretStore, StoredDevice};
