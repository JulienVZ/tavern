// SPDX-License-Identifier: AGPL-3.0-or-later

//! A restored backup (ADR 0019, section 15): what the server does at
//! start-up, told by `restore.sh` or by its marker. Each test has a database
//! of its own ([`common::fresh_database`]): a restore revokes every session
//! of the instance and deletes every one-time KeyPackage, which the other
//! tests, sharing the test database, would see.
//!
//! ```sh
//! TAVERN_TEST_DATABASE_URL=postgres://... cargo test -p tavern-server -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

mod common;

use std::path::Path;

use common::dm::*;
use common::{Account, Device, TestApp, drop_database, fresh_database};
use reqwest::{Method, StatusCode};
use tavern_protocol::gateway::v1 as proto;
use tavern_server::restore::{self, Handled, Marker, Start};

/// What `restore.sh` does after `pg_restore`: the next generation, with the
/// date of the backup.
async fn restore_sh(app: &TestApp, backup_taken_at: &str) {
    sqlx::query(
        "UPDATE instance_state SET generation = generation + 1, \
             backup_taken_at = $1::timestamptz",
    )
    .bind(backup_taken_at)
    .execute(&app.state.db)
    .await
    .unwrap();
}

fn restored(start: Start) -> Handled {
    match start {
        Start::Restored(handled) => handled,
        Start::Unchanged => panic!("the restore was not seen"),
    }
}

/// Whether `token` still opens a session.
async fn signed_in(app: &TestApp, device: &Device) -> bool {
    let status = app
        .status::<()>(
            Method::GET,
            "/v1/devices",
            Some(&device.session_token),
            None,
        )
        .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::UNAUTHORIZED,
        "{status}"
    );
    status == StatusCode::OK
}

/// The restore notices of `account`: their dates of backup.
async fn restore_notices(app: &TestApp, account: &Account) -> Vec<Option<i64>> {
    sqlx::query_scalar(
        "SELECT (extract(epoch FROM backup_taken_at) * 1000)::bigint FROM security_notices \
         WHERE user_id = $1 AND kind = 6",
    )
    .bind(account.user_id)
    .fetch_all(&app.state.db)
    .await
    .unwrap()
}

async fn one_time_packages(app: &TestApp, device: &Device) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE NOT last_resort), count(*) FILTER (WHERE last_resort) \
         FROM key_packages WHERE device_id = $1",
    )
    .bind(device.device_id)
    .fetch_one(&app.state.db)
    .await
    .unwrap()
}

async fn generations(app: &TestApp) -> (i64, i64) {
    sqlx::query_as("SELECT generation, handled_generation FROM instance_state")
        .fetch_one(&app.state.db)
        .await
        .unwrap()
}

/// A copy of the database at `url` as it is now: what a backup holds. No
/// one may use it meanwhile, so the caller closed its pool.
async fn copy_of(url: &str) -> String {
    let copy = fresh_database().await;
    drop_database(&copy).await;
    let (source, target) = (
        url.rsplit('/').next().unwrap(),
        copy.rsplit('/').next().unwrap(),
    );
    let admin = sqlx::PgPool::connect(&common::database_url())
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE {target} TEMPLATE {source}"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
    copy
}

/// Section 15, told by `restore.sh`: at start-up, before serving anything,
/// in one transaction, every session revoked, the notice with the date of
/// the backup for every account, every one-time KeyPackage deleted (the
/// last resort kept), every conversation to recreate. Once only. Devices
/// sign in again with the password; `Ready` announces the generation and
/// lists the notice, to a device enrolled after the restore too.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_restore_is_handled_once_at_start_up() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, |_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let (start, _) = restore::at_start(&app.state.db, dir.path()).await.unwrap();
    assert_eq!(start, Start::Unchanged);

    let (alice, mut alice1, bob, bob1, dm) = group_of_two(&app).await;
    let last_resort = bob1.device.key_package(true);
    upload_last_resort(&app, &bob1.device, last_resort.clone()).await;
    let carol = app.register("rs", false).await;
    // An administrator, and an invitation nobody used yet.
    let admin = app.register("rs", true).await;
    let invite = app.invite(false).await;
    let seq_before = last_seq(&app, dm.conversation).await;
    assert_eq!(one_time_packages(&app, &bob1.device).await, (3, 1));
    let sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE revoked_at IS NULL")
            .fetch_one(&app.state.db)
            .await
            .unwrap();

    restore_sh(&app, "2026-11-01T10:00:00Z").await;
    let handled = restored(
        restore::at_start(&app.state.db, dir.path())
            .await
            .unwrap()
            .0,
    );
    let backup_ms = 1_793_527_200_000;
    assert_eq!(
        handled,
        Handled {
            generation: 1,
            by_marker: false,
            backup_taken_at_ms: Some(backup_ms),
            sessions: u64::try_from(sessions).unwrap(),
            notices: 4,
            admin_notices: 1,
            invitations: 1,
            key_packages: 3,
            conversations: 1,
        }
    );
    assert_eq!(generations(&app).await, (1, 1));
    assert!(!signed_in(&app, &alice1.device).await);
    assert!(!signed_in(&app, &bob1.device).await);
    for account in [&alice, &bob, &carol, &admin] {
        assert_eq!(restore_notices(&app, account).await, [Some(backup_ms)]);
    }
    // The administrator is told what the restore undid of their actions,
    // and no invitation works any more.
    let admin_notices: Vec<Option<i64>> = sqlx::query_scalar(
        "SELECT (extract(epoch FROM backup_taken_at) * 1000)::bigint FROM security_notices \
         WHERE kind = 7 ORDER BY user_id",
    )
    .fetch_all(&app.state.db)
    .await
    .unwrap();
    assert_eq!(admin_notices, [Some(backup_ms)]);
    assert!(
        app.register_with(&common::random_handle("rs"), common::PASSWORD, &invite)
            .await
            .is_err()
    );
    // The numbering goes on above any number given after the backup.
    assert_eq!(
        last_seq(&app, dm.conversation).await,
        seq_before + restore::SEQUENCE_JUMP
    );
    assert_eq!(one_time_packages(&app, &bob1.device).await, (0, 1));
    let to_recreate: bool =
        sqlx::query_scalar("SELECT needs_recreation FROM conversations WHERE id = $1")
            .bind(dm.conversation)
            .fetch_one(&app.state.db)
            .await
            .unwrap();
    assert!(to_recreate);

    // Once: the next start finds nothing to do.
    let (start, marker) = restore::at_start(&app.state.db, dir.path()).await.unwrap();
    assert_eq!(start, Start::Unchanged);
    assert_eq!(marker.generation, 1);
    assert_eq!(restore_notices(&app, &alice).await.len(), 1);

    // Alice signs in again on her device, which the database knows: the
    // generation and the notice, with the date of the backup.
    app.reopen(&alice, &mut alice1.device).await;
    let (_, ready) = common::ws::connect(&app, &alice1.device).await;
    assert_eq!(ready.instance_generation, 1);
    let [notice] = ready.security_notices.as_slice() else {
        panic!("expected the restore notice: {:?}", ready.security_notices);
    };
    assert_eq!(
        notice.kind,
        i32::from(proto::SecurityNoticeKind::InstanceRestored)
    );
    assert_eq!(notice.backup_taken_at_ms, 1_793_527_200_000);
    // Carol comes back on a new computer: told as well.
    let carol1 = app.enrol(&carol).await;
    let (_, ready) = common::ws::connect(&app, &carol1).await;
    assert_eq!(ready.security_notices.len(), 1);
    // What Alice may claim of Bob's: his last resort only, until his
    // devices upload new packages.
    let (status, bytes) = app
        .send::<()>(
            Method::POST,
            &format!("/v1/users/{}/key-packages/claim", bob.user_id),
            Some(&alice1.device.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let served: tavern_protocol::rest::KeyPackageClaim = serde_json::from_slice(&bytes).unwrap();
    let [package] = served.key_packages.as_slice() else {
        panic!("expected Bob's one device with packages: {served:?}");
    };
    assert_eq!(package.key_package, last_resort);

    drop_database(&url).await;
}

/// Section 15, told by the marker alone: the database was put back to a
/// copy taken earlier, without `restore.sh`. A revocation made since is
/// undone in the copy: the server revokes every session all the same, and
/// raises the generation itself, the date of its last record before the
/// copy standing for the backup's.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_marker_tells_a_restore_nobody_recorded() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, |_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice1) = app.account_with_device("rs", false).await;
    let started = restore::at_start(&app.state.db, dir.path()).await.unwrap();
    assert_eq!(started.0, Start::Unchanged);
    let alive_at: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM alive_at) * 1000)::bigint FROM instance_state",
    )
    .fetch_one(&app.state.db)
    .await
    .unwrap();

    // The backup, then a revocation after it.
    app.state.db.close().await;
    let backup = copy_of(&url).await;
    let app = app.restarted_on(&url).await;
    let alice2 = app.enrol(&alice).await;
    let status = app
        .status::<()>(
            Method::DELETE,
            &format!("/v1/devices/{}", alice1.device_id),
            Some(&alice2.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let last = restore::record(&app.state.db, dir.path()).await.unwrap();
    assert!(last.changes > started.1.changes);

    // The server starts on the backup: the revoked device is active there.
    let restored_app = app.restarted_on(&backup).await;
    assert!(signed_in(&restored_app, &alice1).await);
    let handled = restored(
        restore::at_start(&restored_app.state.db, dir.path())
            .await
            .unwrap()
            .0,
    );
    assert!(handled.by_marker);
    assert_eq!(handled.generation, 1);
    assert_eq!(handled.backup_taken_at_ms, Some(alive_at));
    assert!(!signed_in(&restored_app, &alice1).await);
    assert_eq!(
        restore_notices(&restored_app, &alice).await,
        [Some(alive_at)]
    );
    assert_eq!(generations(&restored_app).await, (1, 1));
    let (start, marker) = restore::at_start(&restored_app.state.db, dir.path())
        .await
        .unwrap();
    assert_eq!(start, Start::Unchanged);
    assert_eq!(marker.generation, 1);

    drop_database(&backup).await;
    drop_database(&url).await;
}

/// Section 15: restoring with `restore.sh` a backup older than the last
/// restore gives a generation the devices have never seen, above the
/// marker's, and not the one `restore.sh` computed from the backup.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn an_older_backup_gets_a_generation_never_seen() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, |_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    app.account_with_device("rs", false).await;
    restore::at_start(&app.state.db, dir.path()).await.unwrap();
    app.state.db.close().await;
    let old_backup = copy_of(&url).await;

    // A first restore, of a newer backup: generation 1.
    let app = app.restarted_on(&url).await;
    restore_sh(&app, "2026-11-10T08:00:00Z").await;
    let first = restored(
        restore::at_start(&app.state.db, dir.path())
            .await
            .unwrap()
            .0,
    );
    assert_eq!(first.generation, 1);

    // Then the older one, which holds generation 0: restore.sh makes it 1,
    // a generation the devices have seen already.
    let old = app.restarted_on(&old_backup).await;
    restore_sh(&old, "2026-11-01T08:00:00Z").await;
    let second = restored(
        restore::at_start(&old.state.db, dir.path())
            .await
            .unwrap()
            .0,
    );
    assert_eq!(second.generation, 2);
    assert_eq!(second.backup_taken_at_ms, Some(1_793_520_000_000));
    assert_eq!(generations(&old).await, (2, 2));

    drop_database(&old_backup).await;
    drop_database(&url).await;
}

/// The marker of another database tells nothing about this one: it is
/// replaced, and nothing is handled. A data directory the server cannot
/// write to stops the start-up.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_marker_of_another_database_tells_nothing() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, |_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let current = restore::current(&app.state.db).await.unwrap();
    let elsewhere = Marker {
        instance_id: uuid::Uuid::new_v4(),
        generation: 5,
        changes: current.changes + 1_000,
    };
    restore::write_marker(dir.path(), elsewhere).unwrap();
    let (start, marker) = restore::at_start(&app.state.db, dir.path()).await.unwrap();
    assert_eq!(start, Start::Unchanged);
    assert_eq!(marker.instance_id, current.instance_id);
    assert_eq!(restore::read_marker(dir.path()).unwrap(), Some(marker));

    let file = dir.path().join("not-a-directory");
    std::fs::write(&file, "").unwrap();
    assert!(
        restore::at_start(&app.state.db, Path::new(&file))
            .await
            .is_err()
    );

    drop_database(&url).await;
}

/// Section 15: the handling is one transaction, the generation marked
/// handled at its end. One that fails halfway (here, at the deletion of
/// the KeyPackages) changes nothing, and the next start does all of it.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_handling_that_fails_halfway_is_done_again_from_the_start() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, |_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice1) = app.account_with_device("rs", false).await;
    upload(&app, &alice1, 2).await;
    restore_sh(&app, "2026-11-01T10:00:00Z").await;
    sqlx::query(
        "CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'stopped halfway'; END $$",
    )
    .execute(&app.state.db)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER halfway BEFORE DELETE ON key_packages \
         FOR EACH STATEMENT EXECUTE FUNCTION refuse()",
    )
    .execute(&app.state.db)
    .await
    .unwrap();

    assert!(restore::at_start(&app.state.db, dir.path()).await.is_err());
    assert_eq!(generations(&app).await, (1, 0));
    assert!(signed_in(&app, &alice1).await);
    assert!(restore_notices(&app, &alice).await.is_empty());
    assert_eq!(one_time_packages(&app, &alice1).await, (2, 0));

    sqlx::query("DROP TRIGGER halfway ON key_packages")
        .execute(&app.state.db)
        .await
        .unwrap();
    let handled = restored(
        restore::at_start(&app.state.db, dir.path())
            .await
            .unwrap()
            .0,
    );
    assert_eq!((handled.generation, handled.notices), (1, 1));
    assert!(!signed_in(&app, &alice1).await);
    assert_eq!(restore_notices(&app, &alice).await.len(), 1);
    assert_eq!(one_time_packages(&app, &alice1).await, (0, 0));

    drop_database(&url).await;
}

/// The marker on disk, once it says at least `changes`.
async fn marker_reaches(dir: &Path, changes: i64) -> Marker {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let Some(marker) = restore::read_marker(dir).unwrap()
                && marker.changes >= changes
            {
                return marker;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the marker was never brought up to date")
}

/// Section 15, the review's scenario: the database restored while the
/// server runs. The marker loop follows the database as it changes, never
/// writes a marker backwards, and stops the server instead; the next start
/// then handles the restore, a revocation the restore undid included.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_restore_while_the_server_runs_stops_it_and_is_handled_at_the_next_start() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, |_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let (_alice, alice1) = app.account_with_device("rs", false).await;
    let every = std::time::Duration::from_millis(20);

    let (app, dir, alice1) = (&app, &dir, &alice1);
    // Bounded: if the loop never noticed, `serve` would wait for ever.
    let ran = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        restore::run(&app.state.db, dir.path(), every, |start| async move {
            assert_eq!(start, Start::Unchanged);
            // What the backup holds: the counter, and alice1's session live.
            let backup = restore::current(&app.state.db).await.unwrap();
            // After it: alice1 revoked, which the marker follows.
            sqlx::query("UPDATE sessions SET revoked_at = now() WHERE device_id = $1")
                .bind(alice1.device_id)
                .execute(&app.state.db)
                .await
                .unwrap();
            let followed = marker_reaches(dir.path(), backup.changes + 1).await;
            // The restore, made with the server running: the counter goes back
            // with the data.
            sqlx::query("UPDATE sessions SET revoked_at = NULL WHERE device_id = $1")
                .bind(alice1.device_id)
                .execute(&app.state.db)
                .await
                .unwrap();
            sqlx::query("SELECT setval('instance_changes', $1)")
                .bind(backup.changes)
                .execute(&app.state.db)
                .await
                .unwrap();
            // The server goes on serving until the loop sees it.
            std::future::pending::<()>().await;
            followed
        }),
    )
    .await
    .expect("the server went on serving a database that went back");
    assert!(
        matches!(ran, Err(restore::RestoreError::WentBack)),
        "{ran:?}"
    );
    // The marker was not written backwards.
    let on_disk = restore::read_marker(dir.path()).unwrap().unwrap();
    assert!(on_disk.changes > restore::current(&app.state.db).await.unwrap().changes);
    assert!(signed_in(app, alice1).await);

    // The next start handles it.
    let handled = restored(
        restore::at_start(&app.state.db, dir.path())
            .await
            .unwrap()
            .0,
    );
    assert!(handled.by_marker);
    assert!(!signed_in(app, alice1).await);

    drop_database(&url).await;
}

/// Section 15: the start-up comes first (a restore recorded by
/// `restore.sh` is handled before anything is served), and a clean stop
/// leaves the marker as the database is then, however recent the change.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_start_up_comes_first_and_a_clean_stop_records_the_marker() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, |_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    restore_sh(&app, "2026-11-01T10:00:00Z").await;
    // A loop slower than the test: only the stop can write the change.
    let every = std::time::Duration::from_secs(3600);

    let (app, dir) = (&app, &dir);
    let changed = restore::run(&app.state.db, dir.path(), every, |start| async move {
        assert!(matches!(start, Start::Restored(_)));
        assert_eq!(generations(app).await, (1, 1));
        app.register("rs", false).await;
        restore::current(&app.state.db).await.unwrap()
    })
    .await
    .unwrap();
    let on_disk = restore::read_marker(dir.path()).unwrap().unwrap();
    assert_eq!(on_disk, changed);
    assert_eq!(on_disk.generation, 1);

    drop_database(&url).await;
}
