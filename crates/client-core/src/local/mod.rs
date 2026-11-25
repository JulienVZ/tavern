// SPDX-License-Identifier: AGPL-3.0-or-later

//! The local store: one encrypted SQLite database per account on this
//! computer ([ADR 0018](../../../../docs/adr/0018-local-store-encryption.md)).
//!
//! It is encrypted by SQLCipher with the store key of
//! [ADR 0017](../../../../docs/adr/0017-device-identity-and-sign-out.md),
//! given as a raw 256-bit key, and opened only while the account is signed
//! in. Nothing in it is ever written in clear: pages, journal and indexes all
//! go through SQLCipher, and temporary data stays in memory.
//!
//! # Frozen SQLCipher parameters
//!
//! The file format is SQLCipher 4 and must stay readable by every later
//! version of the client, on every system and whichever crypto library
//! SQLCipher uses there. It is fixed by [`connect`] and checked by tests,
//! including against a file committed in the repository:
//!
//! - `PRAGMA key = "x'…'"`: the 32-byte store key used as the encryption key
//!   itself. No PBKDF2 stretching of the key: it is already random. (SQLCipher
//!   derives the per-database HMAC key from it with two PBKDF2 iterations;
//!   that is part of the format.)
//! - `PRAGMA cipher_compatibility = 4`: AES-256-CBC, HMAC-SHA512 on every
//!   page, 4096-byte pages, no plaintext header.
//!
//! # Where it lives
//!
//! `<local data directory>/accounts/<name>/store.db`, where `<name>` is a
//! hash of the instance, profile and account
//! ([`tavern_crypto::local_store::directory_name`]): the directory listing
//! reveals neither the instance nor the account.

mod migrations;
pub mod mls;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension};
use tavern_crypto::secret::Secret;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use migrations::LATEST_VERSION;

/// File name of the database in an account's directory.
pub const DATABASE_FILE: &str = "store.db";
/// File name a database that could not be opened is moved to, so that a
/// fresh one can be created. Replaced the next time it happens.
pub const UNREADABLE_FILE: &str = "unreadable.db";
/// SQLite's page cache per connection, in KiB: the client's memory budget
/// (CLAUDE.md §6) leaves no room for the default.
const PAGE_CACHE_KIB: i64 = 2048;
/// How long a write waits for another connection (another window of the
/// same profile) to finish.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// The files SQLite may create next to a database.
const COMPANION_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Why the local store could not be used.
#[derive(Debug, thiserror::Error)]
pub enum LocalStoreError {
    /// The file does not open with this key: wrong key, damaged file, or not
    /// a database encrypted by this client (a plain SQLite file included).
    #[error("the local store cannot be read with this key")]
    Unreadable,
    /// The file opens, but belongs to another account or device.
    #[error("the local store belongs to another account or device")]
    OtherDevice,
    /// A newer version of the client upgraded the file.
    #[error(
        "the local store was written by a newer version of Tavern (schema {found}, known {known})"
    )]
    TooNew {
        /// Schema version of the file.
        found: u32,
        /// Latest version this client knows.
        known: u32,
    },
    /// The account signed out: the store is closed and its key forgotten.
    #[error("the local store is closed")]
    Closed,
    /// SQLite failed. Holds the error code only, never any SQL.
    #[error("the local store failed ({0})")]
    Database(String),
    /// The files of the store could not be created, moved or removed.
    #[error("the files of the local store cannot be accessed: {0}")]
    Io(#[from] std::io::Error),
}

/// Keeps the SQLite error code and drops the rest: some rusqlite errors carry
/// the SQL text, and the statement that sets the key contains the key.
fn database(error: &rusqlite::Error) -> LocalStoreError {
    match error.sqlite_error_code() {
        Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt) => LocalStoreError::Unreadable,
        Some(code) => LocalStoreError::Database(format!("{code:?}")),
        None => LocalStoreError::Database("rusqlite".to_owned()),
    }
}

/// Which account and device a store belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// The account.
    pub user_id: Uuid,
    /// This device.
    pub device_id: Uuid,
}

/// What a store says about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreInfo {
    /// The account and device it belongs to.
    pub binding: Binding,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// Its schema version.
    pub schema_version: u32,
}

/// An open local store. Cheap to clone; every clone is closed by
/// [`LocalStore::close`].
#[derive(Clone)]
pub struct LocalStore {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    connection: Mutex<Option<Connection>>,
}

impl std::fmt::Debug for LocalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStore")
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}

impl LocalStore {
    /// Opens the database at `path` with `key`, creating it if the file does
    /// not exist, and brings its schema up to date. A new store is bound to
    /// `binding`; an existing one must already be.
    ///
    /// Never opens anything in clear: a plain SQLite file, a file encrypted
    /// with another key and a damaged file all give
    /// [`LocalStoreError::Unreadable`]. Blocking; see [`open_in`].
    pub fn open(
        path: &Path,
        key: &Secret<32>,
        binding: Binding,
        now_ms: u64,
    ) -> Result<Self, LocalStoreError> {
        let mut connection = connect(path, key)?;
        migrations::bring_up_to_date(&mut connection, binding, now_ms)?;
        let info = read_info(&connection)?;
        if info.binding != binding {
            return Err(LocalStoreError::OtherDevice);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                path: path.to_owned(),
                connection: Mutex::new(Some(connection)),
            }),
        })
    }

    /// A store without encryption, for the tests that read what the file
    /// holds: SQLCipher without a key is plain SQLite, configured as the
    /// encrypted store is (`secure_delete`, write-ahead log), so what they
    /// find in the file is what the encrypted pages hold.
    #[cfg(test)]
    pub(crate) fn open_unencrypted(
        path: &Path,
        binding: Binding,
        now_ms: u64,
    ) -> Result<Self, LocalStoreError> {
        let mut connection = Connection::open(path).map_err(|error| database(&error))?;
        configure(&connection).map_err(|error| database(&error))?;
        migrations::bring_up_to_date(&mut connection, binding, now_ms)?;
        Ok(Self {
            inner: Arc::new(Inner {
                path: path.to_owned(),
                connection: Mutex::new(Some(connection)),
            }),
        })
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Whether the store is still open.
    pub fn is_open(&self) -> bool {
        self.lock().is_some()
    }

    /// What the store says about itself.
    pub async fn info(&self) -> Result<StoreInfo, LocalStoreError> {
        self.run(|connection| read_info(connection)).await
    }

    /// Closes the store: SQLite checkpoints the journal into the file and
    /// SQLCipher erases the key from memory. Every later use fails with
    /// [`LocalStoreError::Closed`]. Closing twice does nothing.
    pub fn close(&self) {
        let connection = self.lock().take();
        if let Some(Err((connection, error))) = connection.map(Connection::close) {
            tracing::warn!(error = %database(&error), "local store did not close cleanly");
            // Dropping it closes it anyway, without reporting.
            drop(connection);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Connection>> {
        // A panic while holding the lock leaves the connection usable.
        self.inner
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `work` in one transaction, on a thread where blocking is
    /// allowed: committed if it returns `Ok`, rolled back otherwise. What
    /// OpenMLS writes through [`mls::SqlStorage`] over the transaction, and
    /// what the caller writes next to it, commit or fail together.
    pub(crate) async fn transaction<T, E, F>(&self, work: F) -> Result<T, E>
    where
        T: Send + 'static,
        E: From<LocalStoreError> + Send + 'static,
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<T, E> + Send + 'static,
    {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = store.lock();
            let connection = guard.as_mut().ok_or(LocalStoreError::Closed)?;
            let transaction = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| database(&error))?;
            let done = work(&transaction)?;
            transaction.commit().map_err(|error| database(&error))?;
            Ok(done)
        })
        .await
        .map_err(|_| E::from(LocalStoreError::Closed))?
    }

    /// Empties the write-ahead log into the database file and truncates it.
    /// With `secure_delete`, what was deleted is then overwritten in the
    /// file, and no longer held by earlier frames of the log: the secrets
    /// OpenMLS deleted, the text of deleted messages. Called after each
    /// batch that deletes them. A reader of another window may keep the log
    /// from being truncated; the next call does it.
    pub async fn erase_journal(&self) -> Result<(), LocalStoreError> {
        self.run(|connection| {
            connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
                .map_err(|error| database(&error))
        })
        .await
    }

    /// Deletes the text of a message, which `secure_delete` overwrites in
    /// the file (gone from the log at the next [`LocalStore::erase_journal`]).
    /// Returns whether there was one.
    pub async fn delete_message(
        &self,
        conversation: Uuid,
        seq: u64,
    ) -> Result<bool, LocalStoreError> {
        self.run(move |connection| {
            let deleted = connection
                .execute(
                    "DELETE FROM messages WHERE conversation_id = ?1 AND seq = ?2",
                    (
                        conversation.as_bytes().as_slice(),
                        i64::try_from(seq).unwrap_or(i64::MAX),
                    ),
                )
                .map_err(|error| database(&error))?;
            Ok(deleted > 0)
        })
        .await
    }

    /// This device's certificate, if the store has it yet.
    pub(crate) async fn certificate(&self) -> Result<Option<Vec<u8>>, LocalStoreError> {
        self.run(|connection| {
            connection
                .query_row(
                    "SELECT certificate FROM device_certificate WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| database(&error))
        })
        .await
    }

    /// Records this device's certificate.
    pub(crate) async fn set_certificate(
        &self,
        certificate: Vec<u8>,
    ) -> Result<(), LocalStoreError> {
        self.run(move |connection| {
            connection
                .execute(
                    "INSERT INTO device_certificate (id, certificate) VALUES (1, ?1) \
                     ON CONFLICT (id) DO UPDATE SET certificate = excluded.certificate",
                    [certificate],
                )
                .map(|_| ())
                .map_err(|error| database(&error))
        })
        .await
    }

    /// Runs `work` on the connection, on a thread where blocking is allowed.
    pub(crate) async fn run<T, F>(&self, work: F) -> Result<T, LocalStoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, LocalStoreError> + Send + 'static,
    {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = store.lock();
            let connection = guard.as_mut().ok_or(LocalStoreError::Closed)?;
            work(connection)
        })
        .await
        .map_err(|_| LocalStoreError::Closed)?
    }
}

/// A message's text, written in the transaction that processed it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "written by the sync engine of task 10b of M2")
)]
pub(crate) struct StoredText<'a> {
    pub(crate) conversation: Uuid,
    pub(crate) seq: u64,
    pub(crate) sender_device: Option<Uuid>,
    pub(crate) sent_at_ms: u64,
    pub(crate) body: &'a [u8],
}

/// Writes a message's text, in the caller's transaction.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the sync engine of task 10b of M2")
)]
pub(crate) fn store_text(
    transaction: &rusqlite::Transaction<'_>,
    text: &StoredText<'_>,
) -> Result<(), LocalStoreError> {
    transaction
        .execute(
            "INSERT INTO messages (conversation_id, seq, sender_device_id, sent_at_ms, body) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                text.conversation.as_bytes().as_slice(),
                i64::try_from(text.seq).unwrap_or(i64::MAX),
                text.sender_device.map(|device| device.as_bytes().to_vec()),
                i64::try_from(text.sent_at_ms).unwrap_or(i64::MAX),
                text.body,
            ),
        )
        .map(|_| ())
        .map_err(|error| database(&error))
}

/// Opens a connection to an encrypted database with the frozen parameters
/// (module documentation), and checks that the key opens it.
fn connect(path: &Path, key: &Secret<32>) -> Result<Connection, LocalStoreError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| database(&error))?;

    // Process-wide, and can only be turned on: SQLCipher wipes every block
    // SQLite frees, including the text of the statement below.
    connection
        .execute_batch("PRAGMA cipher_memory_security = ON;")
        .map_err(|error| database(&error))?;
    set_key(&connection, key)?;
    connection
        .execute_batch("PRAGMA cipher_compatibility = 4;")
        .map_err(|error| database(&error))?;
    // The first read decrypts page 1: a wrong key, a plain file or a damaged
    // file fail here.
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| database(&error))?;

    configure(&connection).map_err(|error| database(&error))?;
    Ok(connection)
}

/// `PRAGMA key = "x'<64 hex digits>'"`: a raw key, used as is.
///
/// rusqlite has no safe binding for `sqlite3_key`, and `unsafe` is avoided.
/// The statement is built in a buffer that never reallocates and is erased
/// when dropped; SQLite's own copy is erased by memory security.
fn set_key(connection: &Connection, key: &Secret<32>) -> Result<(), LocalStoreError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut statement = Zeroizing::new(String::with_capacity(96));
    statement.push_str("PRAGMA key = \"x'");
    for byte in key.expose() {
        statement.push(char::from(HEX[usize::from(byte >> 4)]));
        statement.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    statement.push_str("'\";");
    // Not `database()`: whatever happens, say nothing about this statement.
    connection
        .execute_batch(&statement)
        .map_err(|_| LocalStoreError::Database("key".to_owned()))
}

fn configure(connection: &Connection) -> rusqlite::Result<()> {
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    // WAL: encrypted by SQLCipher like the pages; lets two windows of one
    // profile read while the other writes.
    let mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(rusqlite::Error::InvalidQuery);
    }
    connection.execute_batch(&format!(
        "PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -{PAGE_CACHE_KIB};"
    ))
}

fn read_info(connection: &Connection) -> Result<StoreInfo, LocalStoreError> {
    let row = connection
        .query_row(
            "SELECT user_id, device_id, created_at_ms FROM store_info WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| database(&error))?;
    let Some((user_id, device_id, created_at_ms)) = row else {
        return Err(LocalStoreError::OtherDevice);
    };
    let id = |bytes: Vec<u8>| Uuid::from_slice(&bytes).map_err(|_| LocalStoreError::OtherDevice);
    Ok(StoreInfo {
        binding: Binding {
            user_id: id(user_id)?,
            device_id: id(device_id)?,
        },
        created_at_ms: u64::try_from(created_at_ms).unwrap_or(0),
        schema_version: migrations::version(connection)?,
    })
}

/// How an account's store was opened at sign-in.
#[derive(Debug)]
pub(crate) struct Opened {
    pub(crate) store: LocalStore,
    /// The store this device had could not be opened or was gone: it starts
    /// empty, and the user must be told.
    pub(crate) reset: bool,
}

/// Where the store of an account lives, and what to do with what is there.
#[derive(Debug, Clone)]
pub(crate) struct AccountDirectory(pub(crate) PathBuf);

impl AccountDirectory {
    fn database(&self) -> PathBuf {
        self.0.join(DATABASE_FILE)
    }

    /// Opens the store of a signed-in account. Blocking.
    ///
    /// - `fresh`: the store key was just created (new device, or the old key
    ///   could not be opened). Whatever is in the directory is unreadable by
    ///   construction and is deleted first.
    /// - `existed`: this device had created a store before. If it is gone,
    ///   or no longer opens, the new empty store is reported as a reset.
    ///
    /// A file that does not open is moved aside (`unreadable.db`), never
    /// deleted: it may be the victim of a bug that a later version fixes.
    /// Other failures (disk, permissions, a newer schema) are errors, and
    /// nothing is touched.
    pub(crate) fn open(
        &self,
        key: &Secret<32>,
        binding: Binding,
        fresh: bool,
        existed: bool,
        now_ms: u64,
    ) -> Result<Opened, LocalStoreError> {
        if fresh {
            self.remove()?;
        }
        create_private_dir(&self.0)?;
        let database = self.database();
        if !database.exists() {
            let store = LocalStore::open(&database, key, binding, now_ms)?;
            return Ok(Opened {
                store,
                reset: existed && !fresh,
            });
        }
        match LocalStore::open(&database, key, binding, now_ms) {
            Ok(store) => Ok(Opened {
                store,
                reset: false,
            }),
            Err(LocalStoreError::Unreadable | LocalStoreError::OtherDevice) => {
                tracing::warn!("the local store could not be opened; starting an empty one");
                self.set_aside()?;
                let store = LocalStore::open(&database, key, binding, now_ms)?;
                Ok(Opened { store, reset: true })
            }
            Err(error) => Err(error),
        }
    }

    fn set_aside(&self) -> Result<(), LocalStoreError> {
        let database = self.database();
        let unreadable = self.0.join(UNREADABLE_FILE);
        std::fs::rename(&database, &unreadable)?;
        for suffix in COMPANION_SUFFIXES {
            let companion = with_suffix(&database, suffix);
            if !companion.exists() {
                continue;
            }
            if suffix == "-wal" {
                // Pages not yet checkpointed belong with their database.
                std::fs::rename(&companion, with_suffix(&unreadable, suffix))?;
            } else {
                std::fs::remove_file(&companion)?;
            }
        }
        Ok(())
    }

    /// Deletes the directory and everything in it. Not an error if it does
    /// not exist. The store must be closed first.
    pub(crate) fn remove(&self) -> Result<(), LocalStoreError> {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Creates a directory that only the current user can enter (Unix; on
/// Windows the local application data directory is already private).
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

#[cfg(test)]
mod mls_tests;
#[cfg(test)]
mod tests;
