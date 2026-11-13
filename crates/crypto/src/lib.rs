// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cryptographic building blocks of Tavern.
//!
//! This crate assembles audited primitives (`opaque-ke`, `ed25519-dalek`,
//! RustCrypto) and implements none itself. At milestone M1 it covers account
//! authentication and identity:
//!
//! - [`opaque`]: OPAQUE registration and login, client and server sides;
//! - [`identity`]: account identity key, its wrapped copies, device keys,
//!   device certificates and the signatures that authorise credential changes;
//! - [`recovery`]: the recovery key shown once to the user;
//! - [`token`]: random tokens and their hashes;
//! - [`secret`]: containers that erase secrets from memory.
//!
//! MLS arrives with milestone M2. Design: `docs/adr/0003-opaque-authentication.md`
//! and `docs/adr/0011-account-identity-and-primitives.md`.
//!
//! The server uses this crate to verify and to run the server half of OPAQUE.
//! It never holds a key that decrypts user content.

#![forbid(unsafe_code)]

mod encoding;
mod error;

pub mod identity;
pub mod opaque;
pub mod recovery;
pub mod secret;
pub mod token;

pub use error::CryptoError;
