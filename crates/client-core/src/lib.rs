// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tavern client logic, independent of any user interface.
//!
//! The desktop shell (`apps/desktop/src-tauri`) is a thin layer over this
//! crate. At milestone M0 it can validate an instance URL and query the
//! instance's health endpoint.

pub mod instance;

pub use instance::{ClientError, InstanceUrl, InstanceUrlError, fetch_health};
