// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cryptographic building blocks of Tavern.
//!
//! This crate will wrap OpenMLS (groups, credentials, KeyPackages, exporter),
//! `opaque-ke` (registration and login), account identity keys, media key
//! derivation and attachment encryption. It never implements a primitive
//! itself. See `docs/adr/0002-mls-via-openmls.md` and
//! `docs/adr/0003-opaque-authentication.md`.
//!
//! The crate is intentionally empty until milestone M1.

#![forbid(unsafe_code)]
