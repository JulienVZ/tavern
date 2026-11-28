// SPDX-License-Identifier: AGPL-3.0-or-later

//! The hourly purge (ADR 0019, sections 3, 12 and 15): what goes and what
//! stays, table by table. A test binary of its own, whose tests take turns
//! ([`PURGE`]): the purge works on the whole database, which tests share,
//! and would delete rows that other tests read. Assertions look at each
//! test's rows only.
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

use common::dm::*;
use common::{Device, TestApp};
use tavern_crypto::mls::Incoming;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_server::{purge, removals};
use uuid::Uuid;

/// The tests of this binary take turns: one purge at a time.
static PURGE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    let _turn = PURGE.lock().await;
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
    upload(&app, &bob2, 3).await;
    claim(&app, &alice1.device, &bob, &dm.keys).await;
    let packages = "SELECT count(*) FROM key_packages WHERE device_id = $1";
    assert_eq!(count(&app, packages, bob2.device_id).await, 3);
    let served: Uuid = sqlx::query_scalar(
        "SELECT id FROM key_packages WHERE device_id = $1 AND served_at IS NOT NULL",
    )
    .bind(bob2.device_id)
    .fetch_one(&app.state.db)
    .await
    .unwrap();
    let unserved: Uuid = sqlx::query_scalar(
        "SELECT id FROM key_packages WHERE device_id = $1 AND served_at IS NULL \
         ORDER BY id LIMIT 1",
    )
    .bind(bob2.device_id)
    .fetch_one(&app.state.db)
    .await
    .unwrap();
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, packages, bob2.device_id).await, 3);
    expire(&app, "key_packages", "id", served).await;
    expire(&app, "key_packages", "id", unserved).await;
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, packages, bob2.device_id).await, 1);

    // A device that left: its row stays until it acknowledged the sequence
    // up to its departure.
    make_due(&app, dm.conversation, bob1.device.device_id).await;
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

async fn revoked(app: &TestApp, device: &Device) {
    sqlx::query("UPDATE devices SET revoked_at = now() WHERE id = $1")
        .bind(device.device_id)
        .execute(&app.state.db)
        .await
        .unwrap();
}

/// The server's removal of `member`'s device from `dm`, committed by
/// `committer`: the number of the commit, the device's departure.
async fn removed(app: &TestApp, dm: &Dm, committer: &mut Member, member: &Member) -> u64 {
    make_due(app, dm.conversation, member.device.device_id).await;
    assert!(
        removals::remove_from(&app.state, dm.conversation, member.device.device_id)
            .await
            .unwrap()
    );
    let ServerPayload::ProposalEvent(event) = committer.event().await else {
        panic!("expected the server's removal");
    };
    assert!(matches!(
        committer.process(dm, &event.message.unwrap().mls_message),
        Incoming::Proposal
    ));
    let commit = committer.commit_pending(dm);
    let epoch = committer.group.as_ref().unwrap().epoch();
    let id = committer.submit(dm, epoch, commit, false).await;
    let seq = commit_ack(&committer.answer(id).await).seq;
    committer.merge();
    seq
}

/// A revoked device will never read: the purge waits for it no more, for
/// the messages it was for and for its row once it left.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_revoked_device_is_waited_for_no_more() {
    let _turn = PURGE.lock().await;
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let message = alice1.encrypt(b"for Bob only");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    bob1.receive_text(&dm).await;

    revoked(&app, &bob1.device).await;
    purge::purge(&app.state.db).await.unwrap();
    assert!(sequence(&app, dm.conversation).await.is_empty());

    removed(&app, &dm, &mut alice1, &bob1).await;
    let rows = "SELECT count(*) FROM conversation_devices WHERE conversation_id = $1";
    assert_eq!(count(&app, rows, dm.conversation).await, 2);
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(count(&app, rows, dm.conversation).await, 1);
}

/// A device that left keeps its row while a message it was for, and has
/// not acknowledged, remains: whatever expires first, whatever the
/// retention. Here the retention was lowered, and the commit of its
/// departure expired before an older message.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_departed_device_keeps_its_row_while_a_message_for_it_remains() {
    let _turn = PURGE.lock().await;
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let message = alice1.encrypt(b"not read yet");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    let left = removed(&app, &dm, &mut alice1, &bob1).await;
    assert_eq!(left, 4);
    sqlx::query(
        "UPDATE messages SET expires_at = now() - interval '1 second' \
         WHERE conversation_id = $1 AND seq >= 3",
    )
    .bind(dm.conversation)
    .execute(&app.state.db)
    .await
    .unwrap();

    let rows = "SELECT count(*) FROM conversation_devices WHERE conversation_id = $1";
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(sequence(&app, dm.conversation).await, [(2, 1)]);
    assert_eq!(count(&app, rows, dm.conversation).await, 2);
    let seqs: Vec<u64> = bob1
        .fetch(&dm, 0, 0)
        .await
        .messages
        .iter()
        .map(|message| message.seq)
        .collect();
    assert_eq!(seqs, [2], "still readable by the device that left");

    expire(&app, "messages", "conversation_id", dm.conversation).await;
    purge::purge(&app.state.db).await.unwrap();
    assert!(sequence(&app, dm.conversation).await.is_empty());
    assert_eq!(count(&app, rows, dm.conversation).await, 1);
}

/// A device the server is removing reads up to its proposal: what follows
/// was not for it, and goes once the others acknowledged it, while what it
/// was for waits for it.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn what_follows_a_device_s_proposal_does_not_wait_for_it() {
    let _turn = PURGE.lock().await;
    let app = TestApp::spawn_unlimited().await;
    let (alice, mut alice1, _, bob1, dm) = group_of_two(&app).await;
    let mut alice2 = Member::connect(&app, app.enrol(&alice).await).await;
    commit_ack(&alice2.join_externally(&dm).await);
    alice2.merge();
    for device in [&bob1.device, &alice2.device] {
        make_due(&app, dm.conversation, device.device_id).await;
        assert!(
            removals::remove_from(&app.state, dm.conversation, device.device_id)
                .await
                .unwrap()
        );
    }
    assert_eq!(
        pending_removals(&app, dm.conversation).await,
        [(bob1.device.device_id, 3), (alice2.device.device_id, 4)]
    );
    alice1.ack(&dm, 4).await;
    alice2.ack(&dm, 4).await;
    purge::purge(&app.state.db).await.unwrap();
    assert_eq!(sequence(&app, dm.conversation).await, [(2, 2), (3, 3)]);
}
