// SPDX-License-Identifier: AGPL-3.0-or-later

//! Schema of the local store, versioned with `PRAGMA user_version`.
//!
//! `MIGRATIONS[n]` takes a store from version `n` to version `n + 1`. A
//! migration is never edited once released: a change is a new migration.
//! Each one runs in its own transaction, so a store is always at a version
//! that exists. A store newer than this client is refused, never opened: an
//! older client could misread what it does not know.
//!
//! The tables of each feature arrive with that feature (MLS state, contacts,
//! messages, the search index of M5).

use rusqlite::{Connection, TransactionBehavior};

use super::{Binding, LocalStoreError, database};

/// Version 1: what the store is.
const V1_STORE_INFO: &str = "
    -- The account and device this store belongs to, checked at every
    -- opening, and when it was created.
    CREATE TABLE store_info (
        id            INTEGER PRIMARY KEY CHECK (id = 1),
        user_id       BLOB    NOT NULL CHECK (length(user_id) = 16),
        device_id     BLOB    NOT NULL CHECK (length(device_id) = 16),
        created_at_ms INTEGER NOT NULL
    ) STRICT;
";

const V2_MLS: &str = "
    -- The MLS state of this device, as OpenMLS stores it (ADR 0019,
    -- section 13; local::mls). What OpenMLS deletes is deleted.
    CREATE TABLE mls_state (
        label TEXT NOT NULL,
        key   BLOB NOT NULL,
        value BLOB NOT NULL,
        PRIMARY KEY (label, key)
    ) STRICT, WITHOUT ROWID;

    -- The KeyPackages this device built (ADR 0019, section 3): their
    -- private parts are in mls_state until used or forgotten, the public
    -- package here until the instance confirmed the upload (sent again
    -- otherwise). A replaced last-resort package is kept for a grace period;
    -- a one-time package, until its lifetime ends.
    CREATE TABLE key_packages (
        reference      BLOB    PRIMARY KEY,
        last_resort    INTEGER NOT NULL CHECK (last_resort IN (0, 1)),
        package        BLOB,
        created_at_ms  INTEGER NOT NULL,
        replaced_at_ms INTEGER
    ) STRICT;

    -- This device's certificate, as it enrolled: its KeyPackages carry it.
    CREATE TABLE device_certificate (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        certificate BLOB    NOT NULL
    ) STRICT;

    -- The plaintext of conversations, by the number of their sequence.
    CREATE TABLE messages (
        conversation_id  BLOB    NOT NULL CHECK (length(conversation_id) = 16),
        seq              INTEGER NOT NULL CHECK (seq > 0),
        sender_device_id BLOB    CHECK (length(sender_device_id) = 16),
        sent_at_ms       INTEGER NOT NULL,
        body             BLOB    NOT NULL,
        PRIMARY KEY (conversation_id, seq)
    ) STRICT;
";

pub(super) const MIGRATIONS: &[&str] = &[V1_STORE_INFO, V2_MLS];

/// The schema version this client writes.
pub const LATEST_VERSION: u32 = MIGRATIONS.len() as u32;

pub(super) fn version(connection: &Connection) -> Result<u32, LocalStoreError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
        .map_err(|error| database(&error))
}

/// Creates the schema of a new store, or upgrades an existing one.
pub(super) fn bring_up_to_date(
    connection: &mut Connection,
    binding: Binding,
    now_ms: u64,
) -> Result<(), LocalStoreError> {
    let found = version(connection)?;
    if found > LATEST_VERSION {
        return Err(LocalStoreError::TooNew {
            found,
            known: LATEST_VERSION,
        });
    }
    if found == 0 {
        return create(connection, binding, now_ms);
    }
    upgrade(connection, found, LATEST_VERSION)
}

/// A new store: every migration and its identity, in one transaction.
fn create(
    connection: &mut Connection,
    binding: Binding,
    now_ms: u64,
) -> Result<(), LocalStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| database(&error))?;
    let tables: i64 = transaction
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .map_err(|error| database(&error))?;
    if tables != 0 {
        // Version 0 with tables: not a store this client created.
        return Err(LocalStoreError::OtherDevice);
    }
    for migration in MIGRATIONS {
        transaction
            .execute_batch(migration)
            .map_err(|error| database(&error))?;
    }
    transaction
        .execute(
            "INSERT INTO store_info (id, user_id, device_id, created_at_ms) VALUES (1, ?1, ?2, ?3)",
            (
                binding.user_id.as_bytes().as_slice(),
                binding.device_id.as_bytes().as_slice(),
                i64::try_from(now_ms).unwrap_or(i64::MAX),
            ),
        )
        .map_err(|error| database(&error))?;
    transaction
        .pragma_update(None, "user_version", LATEST_VERSION)
        .map_err(|error| database(&error))?;
    transaction.commit().map_err(|error| database(&error))
}

/// Applies the migrations from `from` to `to`, one transaction each.
pub(super) fn upgrade(
    connection: &mut Connection,
    from: u32,
    to: u32,
) -> Result<(), LocalStoreError> {
    for target in from + 1..=to {
        let Some(migration) = usize::try_from(target - 1)
            .ok()
            .and_then(|index| MIGRATIONS.get(index))
        else {
            return Err(LocalStoreError::TooNew {
                found: target,
                known: LATEST_VERSION,
            });
        };
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| database(&error))?;
        transaction
            .execute_batch(migration)
            .map_err(|error| database(&error))?;
        transaction
            .pragma_update(None, "user_version", target)
            .map_err(|error| database(&error))?;
        transaction.commit().map_err(|error| database(&error))?;
    }
    Ok(())
}
