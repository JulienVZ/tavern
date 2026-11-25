// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests of the local store. They run on the three systems in CI: SQLCipher
//! uses CommonCrypto on macOS and OpenSSL elsewhere, and the file format must
//! be the same everywhere.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tavern_crypto::secret::Secret;
use uuid::Uuid;

use super::migrations::{LATEST_VERSION, MIGRATIONS, upgrade};
use super::{
    AccountDirectory, Binding, DATABASE_FILE, LocalStore, LocalStoreError, UNREADABLE_FILE,
};

const NOW_MS: u64 = 1_794_000_000_000;

fn binding() -> Binding {
    Binding {
        user_id: Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0001),
        device_id: Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_00d1),
    }
}

fn key(seed: u8) -> Secret<32> {
    Secret::from_slice(&[seed; 32]).unwrap()
}

fn store_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join(DATABASE_FILE)
}

/// Runs a statement on an open store.
async fn exec(store: &LocalStore, sql: &'static str) {
    store
        .run(move |connection| {
            connection
                .execute_batch(sql)
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
}

/// The rows a pragma returns, one per line.
async fn pragma(store: &LocalStore, name: &'static str) -> String {
    use rusqlite::types::Value;
    store
        .run(move |connection| {
            let mut statement = connection
                .prepare(&format!("PRAGMA {name}"))
                .map_err(|error| super::database(&error))?;
            let rows = statement
                .query_map([], |row| row.get::<_, Value>(0))
                .map_err(|error| super::database(&error))?;
            let mut lines = Vec::new();
            for value in rows {
                lines.push(match value.map_err(|error| super::database(&error))? {
                    Value::Integer(number) => number.to_string(),
                    Value::Text(text) => text,
                    other => format!("{other:?}"),
                });
            }
            Ok(lines.join("\n"))
        })
        .await
        .unwrap()
}

/// Every byte of every file in `dir`.
fn all_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn the_cipher_parameters_are_frozen() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(&store_path(&dir), &key(1), binding(), NOW_MS).unwrap();

    assert!(pragma(&store, "cipher_version").await.starts_with("4."));
    assert_eq!(pragma(&store, "cipher_page_size").await, "4096");
    assert_eq!(pragma(&store, "cipher_use_hmac").await, "1");
    assert_eq!(pragma(&store, "cipher_hmac_algorithm").await, "HMAC_SHA512");
    assert_eq!(
        pragma(&store, "cipher_kdf_algorithm").await,
        "PBKDF2_HMAC_SHA512"
    );
    assert_eq!(pragma(&store, "cipher_plaintext_header_size").await, "0");
    // Memory security wipes what SQLite frees, the key statement included.
    assert_eq!(pragma(&store, "cipher_memory_security").await, "1");
    assert_eq!(pragma(&store, "journal_mode").await, "wal");
    assert_eq!(pragma(&store, "temp_store").await, "2");
    assert_eq!(pragma(&store, "secure_delete").await, "1");
    assert_eq!(pragma(&store, "foreign_keys").await, "1");
}

#[tokio::test]
async fn the_crypto_comes_from_the_expected_library() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(&store_path(&dir), &key(1), binding(), NOW_MS).unwrap();
    let provider = pragma(&store, "cipher_provider").await;
    let version = pragma(&store, "cipher_provider_version").await;

    if cfg!(target_os = "macos") {
        assert_eq!(provider, "commoncrypto", "{version}");
    } else {
        // The OpenSSL compiled into the client (openssl-src), not the
        // system's: CI also checks that the binary does not link libcrypto.
        assert_eq!(provider, "openssl", "{version}");
        assert!(version.starts_with("OpenSSL 3."), "{version}");
    }
}

#[tokio::test]
async fn a_store_reopens_with_its_key_and_refuses_any_other() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_path(&dir);
    let store = LocalStore::open(&path, &key(1), binding(), NOW_MS).unwrap();
    exec(
        &store,
        "CREATE TABLE probe (body TEXT); INSERT INTO probe VALUES ('kept');",
    )
    .await;
    let created = store.info().await.unwrap();
    store.close();
    assert!(!store.is_open());
    assert!(matches!(store.info().await, Err(LocalStoreError::Closed)));

    let again = LocalStore::open(&path, &key(1), binding(), NOW_MS + 1).unwrap();
    assert_eq!(again.info().await.unwrap(), created);
    let body = again
        .run(|connection| {
            connection
                .query_row("SELECT body FROM probe", [], |row| row.get::<_, String>(0))
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
    assert_eq!(body, "kept");
    again.close();

    for wrong in [key(2), key(0)] {
        assert!(matches!(
            LocalStore::open(&path, &wrong, binding(), NOW_MS),
            Err(LocalStoreError::Unreadable)
        ));
    }
    // The refusals changed nothing: the right key still opens it.
    LocalStore::open(&path, &key(1), binding(), NOW_MS)
        .unwrap()
        .close();
}

#[test]
fn a_plain_or_foreign_file_is_never_opened() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_path(&dir);
    // Without a key, SQLCipher writes an ordinary SQLite file.
    let plain = Connection::open(&path).unwrap();
    plain
        .execute_batch("CREATE TABLE probe (body TEXT); INSERT INTO probe VALUES ('in clear');")
        .unwrap();
    drop(plain);
    let before = std::fs::read(&path).unwrap();
    assert!(before.starts_with(b"SQLite format 3\0"));

    assert!(matches!(
        LocalStore::open(&path, &key(1), binding(), NOW_MS),
        Err(LocalStoreError::Unreadable)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let garbage = dir.path().join("garbage.db");
    std::fs::write(&garbage, [0x5a_u8; 8192]).unwrap();
    assert!(matches!(
        LocalStore::open(&garbage, &key(1), binding(), NOW_MS),
        Err(LocalStoreError::Unreadable)
    ));
}

#[tokio::test]
async fn nothing_is_written_in_clear() {
    const MARKERS: [&[u8]; 4] = [
        b"MARKER-message-body-5d1e",
        b"MARKER-searchable-word",
        b"MARKER-blob-c0ffee",
        b"MARKER-table-name",
    ];
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(&store_path(&dir), &key(1), binding(), NOW_MS).unwrap();
    exec(
        &store,
        "CREATE TABLE MARKER_table_name (body TEXT, data BLOB);
         CREATE VIRTUAL TABLE search USING fts5(body, tokenize = 'unicode61 remove_diacritics 2');
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 300)
         INSERT INTO MARKER_table_name
             SELECT 'MARKER-message-body-5d1e ' || i, CAST('MARKER-blob-c0ffee' AS BLOB) FROM n;
         INSERT INTO search SELECT 'MARKER-searchable-word ' || body FROM MARKER_table_name;",
    )
    .await;
    // Make the markers reach the disk without a checkpoint: everything is in
    // the write-ahead log at this point.
    let check = |stage: &str| {
        let files = all_bytes(dir.path());
        assert!(files.iter().any(|(name, _)| name == DATABASE_FILE));
        for (name, bytes) in &files {
            for marker in MARKERS {
                let marker = String::from_utf8_lossy(marker).replace('-', "_");
                assert!(
                    !contains(bytes, marker.as_bytes()),
                    "{stage}: {marker} found in {name}"
                );
            }
            for marker in MARKERS {
                assert!(
                    !contains(bytes, marker),
                    "{stage}: {} found in {name}",
                    String::from_utf8_lossy(marker)
                );
            }
            assert!(!contains(bytes, b"SQLite format 3"), "{stage}: {name}");
        }
        files
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>()
    };
    let while_open = check("open");
    assert!(
        while_open.iter().any(|name| name.ends_with("-wal")),
        "{while_open:?}"
    );
    // No temporary file next to the store.
    assert!(
        while_open
            .iter()
            .all(|name| name.starts_with(DATABASE_FILE)),
        "{while_open:?}"
    );

    store.close();
    check("closed");
}

#[tokio::test]
async fn full_text_search_ignores_accents_and_case() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(&store_path(&dir), &key(1), binding(), NOW_MS).unwrap();
    exec(
        &store,
        "CREATE VIRTUAL TABLE search USING fts5(body, tokenize = 'unicode61 remove_diacritics 2');
         INSERT INTO search VALUES ('Rendez-vous à l''École à midi'), ('rien à voir');",
    )
    .await;
    let found = store
        .run(|connection| {
            connection
                .query_row(
                    "SELECT body FROM search WHERE search MATCH 'ecole AND a'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
    assert_eq!(found, "Rendez-vous à l'École à midi");
}

#[tokio::test]
async fn every_earlier_schema_version_is_brought_up_to_date() {
    for from in 0..=LATEST_VERSION {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(&dir);
        // A store as an older client left it: migrations up to `from`.
        let store = LocalStore::open(&path, &key(1), binding(), NOW_MS).unwrap();
        if from < LATEST_VERSION {
            store
                .run(move |connection| {
                    rebuild_at(connection, from);
                    Ok(())
                })
                .await
                .unwrap();
        }
        store.close();

        let store = LocalStore::open(&path, &key(1), binding(), NOW_MS).unwrap();
        let info = store.info().await.unwrap();
        assert_eq!(info.schema_version, LATEST_VERSION, "from version {from}");
        assert_eq!(info.binding, binding());
    }
}

/// Replaces the content of `connection` by the schema of version `version`.
fn rebuild_at(connection: &mut Connection, version: u32) {
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for table in tables {
        connection
            .execute_batch(&format!("DROP TABLE \"{table}\""))
            .unwrap();
    }
    connection.pragma_update(None, "user_version", 0).unwrap();
    if version == 0 {
        return;
    }
    connection.execute_batch(MIGRATIONS[0]).unwrap();
    connection
        .execute(
            "INSERT INTO store_info VALUES (1, ?1, ?2, ?3)",
            (
                binding().user_id.as_bytes().as_slice(),
                binding().device_id.as_bytes().as_slice(),
                1_i64,
            ),
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    upgrade(connection, 1, version).unwrap();
}

#[tokio::test]
async fn a_store_from_a_newer_client_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_path(&dir);
    let store = LocalStore::open(&path, &key(1), binding(), NOW_MS).unwrap();
    store
        .run(|connection| {
            connection
                .pragma_update(None, "user_version", LATEST_VERSION + 1)
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
    store.close();

    assert!(matches!(
        LocalStore::open(&path, &key(1), binding(), NOW_MS),
        Err(LocalStoreError::TooNew { found, known }) if found == LATEST_VERSION + 1 && known == LATEST_VERSION
    ));
}

#[test]
fn a_store_of_another_device_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_path(&dir);
    LocalStore::open(&path, &key(1), binding(), NOW_MS)
        .unwrap()
        .close();
    let other = Binding {
        device_id: Uuid::from_u128(0xd2),
        ..binding()
    };
    assert!(matches!(
        LocalStore::open(&path, &key(1), other, NOW_MS),
        Err(LocalStoreError::OtherDevice)
    ));
}

// --- The format of the first release, frozen ------------------------------------

const FIXTURE: &str = "fixtures/local-store-v1.db";
const FIXTURE_CREATED_AT_MS: u64 = 1_794_000_000_000;

fn fixture_key() -> Secret<32> {
    let bytes: Vec<u8> = (0u8..32).collect();
    Secret::from_slice(&bytes).unwrap()
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE)
}

/// Opens the store committed in the repository, written by the first version
/// of the store: every later client, on every system, must open it with its
/// raw key, migrate it, and refuse any other key.
#[tokio::test]
async fn the_format_of_the_first_release_still_opens() {
    let dir = tempfile::tempdir().unwrap();
    let copy = store_path(&dir);
    std::fs::copy(fixture_path(), &copy).unwrap();

    assert!(matches!(
        LocalStore::open(&copy, &key(1), binding(), NOW_MS),
        Err(LocalStoreError::Unreadable)
    ));
    let store = LocalStore::open(&copy, &fixture_key(), binding(), NOW_MS).unwrap();
    let info = store.info().await.unwrap();
    assert_eq!(info.binding, binding());
    assert_eq!(info.created_at_ms, FIXTURE_CREATED_AT_MS);
    assert_eq!(info.schema_version, LATEST_VERSION);
    let marker = store
        .run(|connection| {
            connection
                .query_row("SELECT body FROM fixture_probe", [], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
    assert_eq!(marker, "written by the first version of the store");
    let check = pragma(&store, "cipher_integrity_check").await;
    assert!(check.is_empty(), "{check}");
}

/// Writes the fixture above. Run once, when a store format is created; never
/// to make the test above pass.
#[tokio::test]
#[ignore = "writes fixtures/local-store-v1.db"]
async fn write_the_fixture_of_the_first_release() {
    let path = fixture_path();
    assert!(!path.exists(), "the fixture exists and is frozen");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let store = LocalStore::open(&path, &fixture_key(), binding(), FIXTURE_CREATED_AT_MS).unwrap();
    exec(
        &store,
        "CREATE TABLE fixture_probe (body TEXT);
         INSERT INTO fixture_probe VALUES ('written by the first version of the store');",
    )
    .await;
    store.close();
}

// --- What sign-in does with an account's directory ---------------------------------

#[test]
fn a_fresh_key_replaces_whatever_was_there() {
    let root = tempfile::tempdir().unwrap();
    let directory = AccountDirectory(root.path().join("account"));
    let first = directory
        .open(&key(1), binding(), true, false, NOW_MS)
        .unwrap();
    assert!(!first.reset);
    first.store.close();

    // New device or lost key: the old file can never be read again.
    let fresh = directory
        .open(&key(2), binding(), true, true, NOW_MS)
        .unwrap();
    assert!(
        !fresh.reset,
        "a new device is announced as such, not as a reset"
    );
    fresh.store.close();
    assert!(!directory.0.join(UNREADABLE_FILE).exists());
}

#[test]
fn a_store_that_vanished_is_reported() {
    let root = tempfile::tempdir().unwrap();
    let directory = AccountDirectory(root.path().join("account"));
    // Before this version of the client, signed-in accounts had no store.
    let first = directory
        .open(&key(1), binding(), false, false, NOW_MS)
        .unwrap();
    assert!(!first.reset);
    first.store.close();

    std::fs::remove_dir_all(&directory.0).unwrap();
    let again = directory
        .open(&key(1), binding(), false, true, NOW_MS)
        .unwrap();
    assert!(again.reset);
    again.store.close();
}

#[test]
fn a_store_that_does_not_open_is_set_aside_and_reported() {
    let root = tempfile::tempdir().unwrap();
    let directory = AccountDirectory(root.path().join("account"));
    directory
        .open(&key(1), binding(), false, false, NOW_MS)
        .unwrap()
        .store
        .close();
    let database = directory.0.join(DATABASE_FILE);
    let mut damaged = std::fs::read(&database).unwrap();
    damaged[100] ^= 0xff;
    std::fs::write(&database, &damaged).unwrap();

    let opened = directory
        .open(&key(1), binding(), false, true, NOW_MS)
        .unwrap();
    assert!(opened.reset);
    opened.store.close();
    assert_eq!(
        std::fs::read(directory.0.join(UNREADABLE_FILE)).unwrap(),
        damaged
    );
}

#[test]
fn other_failures_touch_nothing() {
    let root = tempfile::tempdir().unwrap();
    let directory = AccountDirectory(root.path().join("account"));
    let opened = directory
        .open(&key(1), binding(), false, false, NOW_MS)
        .unwrap();
    let path = opened.store.path().to_owned();
    opened.store.close();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(&format!(
            "PRAGMA key = \"x'{}'\"; PRAGMA cipher_compatibility = 4; PRAGMA user_version = {};",
            "01".repeat(32),
            LATEST_VERSION + 1
        ))
        .unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();

    assert!(matches!(
        directory.open(&key(1), binding(), false, true, NOW_MS),
        Err(LocalStoreError::TooNew { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!directory.0.join(UNREADABLE_FILE).exists());
}

#[test]
fn removing_a_directory_that_does_not_exist_is_fine() {
    let root = tempfile::tempdir().unwrap();
    AccountDirectory(root.path().join("never"))
        .remove()
        .unwrap();
}

/// Every commit is durable before it returns (review of task 10a, point 5):
/// `synchronous = FULL`, with the write-ahead log.
#[tokio::test]
async fn commits_are_durable() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalStore::open(&store_path(&dir), &key(1), binding(), NOW_MS).unwrap();
    // 2 is FULL.
    assert_eq!(pragma(&store, "synchronous").await, "2");
    assert_eq!(pragma(&store, "journal_mode").await, "wal");
    // On macOS, fsync alone does not reach the disk.
    if cfg!(target_os = "macos") {
        assert_eq!(pragma(&store, "fullfsync").await, "1");
        assert_eq!(pragma(&store, "checkpoint_fullfsync").await, "1");
    }
}

/// How long a small commit takes, by durability setting: the measure asked
/// with point 5 of the review of task 10a. Bounded (300 commits of a row).
#[tokio::test]
#[ignore = "a measurement, run on demand"]
#[expect(clippy::print_stdout, reason = "the measurement is printed")]
async fn measure_durable_commits() {
    for setting in ["NORMAL", "FULL", "FULL_FULLFSYNC"] {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::open(&store_path(&dir), &key(1), binding(), NOW_MS).unwrap();
        let elapsed = store
            .run(move |connection| {
                let (synchronous, fullfsync) = match setting {
                    "FULL_FULLFSYNC" => ("FULL", "ON"),
                    other => (other, "OFF"),
                };
                connection
                    .execute_batch(&format!(
                        "PRAGMA synchronous = {synchronous}; PRAGMA fullfsync = {fullfsync};
                         CREATE TABLE probe (n INTEGER);"
                    ))
                    .map_err(|error| super::database(&error))?;
                let start = std::time::Instant::now();
                for n in 0..300 {
                    let transaction = connection
                        .transaction()
                        .map_err(|error| super::database(&error))?;
                    transaction
                        .execute("INSERT INTO probe VALUES (?1)", [n])
                        .map_err(|error| super::database(&error))?;
                    transaction
                        .commit()
                        .map_err(|error| super::database(&error))?;
                }
                Ok(start.elapsed())
            })
            .await
            .unwrap();
        println!(
            "{setting}: {:.3} ms per commit",
            elapsed.as_secs_f64() * 1000.0 / 300.0
        );
    }
}

/// Review of task 10a, point 16: a store of each earlier version, brought up
/// to date, then used by MLS: KeyPackages built in it, their upload settled,
/// and their private parts forgotten, through the tables of every version.
#[tokio::test]
async fn an_upgraded_store_runs_mls_operations() {
    use tavern_crypto::identity::{AccountRootSecret, DeviceKey};

    use crate::key_packages::{self, Outcome};
    for from in 1..LATEST_VERSION {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(&dir);
        let store = LocalStore::open(&path, &key(1), binding(), NOW_MS).unwrap();
        store
            .run(move |connection| {
                rebuild_at(connection, from);
                Ok(())
            })
            .await
            .unwrap();
        store.close();
        let store = LocalStore::open(&path, &key(1), binding(), NOW_MS).unwrap();

        let device_key = DeviceKey::generate();
        let certificate = AccountRootSecret::generate()
            .identity_key()
            .unwrap()
            .certify_device(
                binding().user_id.as_bytes(),
                binding().device_id.as_bytes(),
                &device_key.public(),
                NOW_MS,
            );
        let upload = key_packages::prepare(&store, device_key, certificate, 0, false, NOW_MS)
            .await
            .unwrap();
        assert_eq!(upload.one_time.len(), 20, "from version {from}");
        key_packages::settle(&store, &upload, Outcome::Unknown, NOW_MS)
            .await
            .unwrap();
        key_packages::settle(&store, &upload, Outcome::Taken, NOW_MS)
            .await
            .unwrap();
        let later = NOW_MS + key_packages::ONE_TIME_KEPT_MS + key_packages::LAST_RESORT_GRACE_MS;
        assert!(key_packages::forget_due(&store, later).await.unwrap());
        store.close();
    }
}

/// Review of task 10a, point 11: a reader in another connection keeps the
/// journal from being emptied: `erase_journal` tries again, then says so
/// (`Busy`) rather than reporting it emptied; once the reader is gone, the
/// next call empties it.
#[tokio::test]
async fn an_incomplete_checkpoint_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = store_path(&dir);
    let store = LocalStore::open_unencrypted(&path, binding(), NOW_MS).unwrap();
    store
        .run(|connection| {
            connection
                .execute_batch("CREATE TABLE probe (n INTEGER); INSERT INTO probe VALUES (1);")
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
    // Another window reads, from the journal's current state.
    let reader = Connection::open(&path).unwrap();
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM probe;")
        .unwrap();
    store
        .run(|connection| {
            connection
                .execute_batch("INSERT INTO probe VALUES (2);")
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
    assert!(matches!(
        store.erase_journal().await,
        Err(LocalStoreError::Busy)
    ));
    reader.execute_batch("COMMIT;").unwrap();
    drop(reader);
    store.erase_journal().await.unwrap();
    let wal = path.with_file_name(format!("{DATABASE_FILE}-wal"));
    let wal_len = std::fs::metadata(&wal).map_or(0, |metadata| metadata.len());
    assert_eq!(wal_len, 0, "the journal is emptied");
}
