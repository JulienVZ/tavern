// SPDX-License-Identifier: AGPL-3.0-or-later

//! The hourly purge (ADR 0019, sections 3, 12 and 15): what goes and what
//! stays, table by table. A test binary of its own, with a single test: the
//! purge works on the whole database, which tests share, and would delete
//! rows that other tests of a binary read. Assertions look at this test's
//! rows only.
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

use common::TestApp;
use common::dm::*;
use tavern_crypto::mls::Incoming;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_server::{purge, removals};
use uuid::Uuid;

async fn expire(app: &TestApp, table: &str, condition: &str, id: Uuid) {
    // Built from this file's table names and conditions, and a UUID.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "UPDATE {table} SET expires_at = now() - interval '1 second' WHERE {condition} = '{id}'"
    )))
    .execute(&app.state.db)
    .await
    .unwrap();
}

async fn count(app: &TestApp, query: &'static str, id: Uuid) -> i64 {
    sqlx::query_scalar(query)
        .bind(id)
        .fetch_one(&app.state.db)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_purge_deletes_what_is_no_longer_needed_and_keeps_the_rest() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, bob, mut bob1, dm) = group_of_two(&app).await;

    // Messages: kept until every device they were for acknowledged them.
    // The first commit was for no device (both joined by it); the sender
    // does not count.
    for text in [b"one".as_slice(), b"two"] {
        let message = alice1.encrypt(text);
        let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
        message_ack(&alice1.answer(id).await);
        bob1.receive_text(&dm).await;
    }
    bob1.ack(&dm, 2).await;
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(sequence(&app, dm.conversation).await, [(3, 1)]);
    bob1.ack(&dm, 3).await;
    purge::purge(&app.state.db).await.unwrap();
    assert!(sequence(&app, dm.conversation).await.is_empty());

    // Or once expired, acknowledged or not.
    let message = alice1.encrypt(b"three");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    let message = alice1.encrypt(b"four");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    sqlx::query(
        "UPDATE messages SET expires_at = now() - interval '1 second' \
         WHERE conversation_id = $1 AND seq = 4",
    )
    .bind(dm.conversation)
    .execute(&app.state.db)
    .await
    .unwrap();
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(sequence(&app, dm.conversation).await, [(5, 1)]);

    // Idempotency records: kept until they expire.
    let records = "SELECT count(*) FROM sent_messages WHERE conversation_id = $1";
    assert_eq!(count(&app, records, dm.conversation).await, 4);
    sqlx::query(
        "UPDATE sent_messages SET expires_at = now() - interval '1 second' \
         WHERE conversation_id = $1 AND seq <= 3",
    )
    .bind(dm.conversation)
    .execute(&app.state.db)
    .await
    .unwrap();
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, records, dm.conversation).await, 2);

    // Welcomes: Bob's was acknowledged at his join. One not acknowledged is
    // kept, until it expires.
    let welcomes = "SELECT count(*) FROM welcomes WHERE conversation_id = $1";
    assert_eq!(count(&app, welcomes, dm.conversation).await, 0);
    let pending: Uuid = sqlx::query_scalar(
        "INSERT INTO welcomes (conversation_id, recipient_device_id, payload, expires_at) \
         VALUES ($1, $2, '\\x00', now() + interval '1 day') RETURNING id",
    )
    .bind(dm.conversation)
    .bind(bob1.device.device_id)
    .fetch_one(&app.state.db)
    .await
    .unwrap();
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, welcomes, dm.conversation).await, 1);
    expire(&app, "welcomes", "id", pending).await;
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, welcomes, dm.conversation).await, 0);

    // KeyPackages: kept until they expire, served or not.
    let bob2 = app.enrol(&bob).await;
    upload(&app, &bob2, 2).await;
    let packages = "SELECT count(*) FROM key_packages WHERE device_id = $1";
    assert_eq!(count(&app, packages, bob2.device_id).await, 2);
    let first: Uuid =
        sqlx::query_scalar("SELECT id FROM key_packages WHERE device_id = $1 ORDER BY id LIMIT 1")
            .bind(bob2.device_id)
            .fetch_one(&app.state.db)
            .await
            .unwrap();
    expire(&app, "key_packages", "id", first).await;
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, packages, bob2.device_id).await, 1);

    // A device that left: its row stays until it acknowledged the sequence
    // up to its departure.
    assert!(
        removals::remove_from(&app.state, dm.conversation, bob1.device.device_id)
            .await
            .unwrap()
    );
    let ServerPayload::ProposalEvent(event) = alice1.event().await else {
        panic!("expected the server's removal");
    };
    assert!(matches!(
        alice1.process(&dm, &event.message.unwrap().mls_message),
        Incoming::Proposal
    ));
    let commit = alice1.commit_pending(&dm);
    let id = alice1.submit(&dm, 1, commit, false).await;
    let left = commit_ack(&alice1.answer(id).await).seq;
    alice1.merge();
    let rows = "SELECT count(*) FROM conversation_devices WHERE conversation_id = $1";
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, rows, dm.conversation).await, 2);
    // Its proposal and its departure were for it: kept for it.
    assert_eq!(
        sequence(&app, dm.conversation).await,
        [(5, 1), (6, 3), (7, 2)]
    );
    bob1.ack(&dm, left).await;
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, rows, dm.conversation).await, 1);
    assert_eq!(
        routed(&app, dm.conversation).await,
        [alice1.device.device_id]
    );
}
