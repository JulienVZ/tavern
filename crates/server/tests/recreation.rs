// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recreating a conversation's group (ADR 0019, sections 15 and 17): after
//! a restore, the only commit a conversation takes; at a user's request, at
//! most once an hour. A restore marks every conversation of the instance;
//! these tests mark their own conversations only, as it does.
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
use reqwest::{Method, StatusCode};
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_server::config::ClaimLimits;
use tavern_server::removals;
use uuid::Uuid;

/// Recreations claim KeyPackages again and again.
async fn spawn() -> TestApp {
    TestApp::spawn_configured(|settings| {
        settings.claim_limits = ClaimLimits {
            per_requester_per_hour: 1_000,
            per_pair_per_hour: 1_000,
            per_pair_per_day: 1_000,
        };
    })
    .await
}

/// What a restore does to the conversation.
async fn to_recreate(app: &TestApp, dm: &Dm) {
    sqlx::query("UPDATE conversations SET needs_recreation = true WHERE id = $1")
        .bind(dm.conversation)
        .execute(&app.state.db)
        .await
        .unwrap();
}

async fn recreation_of(app: &TestApp, dm: &Dm) -> (bool, bool) {
    sqlx::query_as(
        "SELECT needs_recreation, recreated_at IS NOT NULL FROM conversations WHERE id = $1",
    )
    .bind(dm.conversation)
    .fetch_one(&app.state.db)
    .await
    .unwrap()
}

async fn generations_stored(app: &TestApp, dm: &Dm) -> Vec<i64> {
    sqlx::query_scalar(
        "SELECT generation FROM mls_groups WHERE conversation_id = $1 ORDER BY generation",
    )
    .bind(dm.conversation)
    .fetch_all(&app.state.db)
    .await
    .unwrap()
}

/// `member` builds the first commit of the group's `generation`, with the
/// packages of `peer`'s devices; its earlier group is dropped.
async fn recreate(
    app: &TestApp,
    member: &mut Member,
    peer: &common::Account,
    dm: &mut Dm,
    generation: u32,
) -> tavern_crypto::mls::Commit {
    let claimed = claim(app, &member.device, peer, &dm.keys).await;
    if member.group.is_some() {
        member.drop_group();
    }
    dm.generation = generation;
    member.create(dm, &claimed)
}

fn refused(payload: &ServerPayload) -> proto::ErrorCode {
    code(payload)
}

/// Sections 15 and 17: once restored, a conversation takes nothing but
/// the recreation of its group, at any generation above its own (the
/// devices may know generations the server lost). The recreation deletes
/// what the old group left, the sequence goes on, and a message for the
/// old group is refused, while the new group works.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn after_a_restore_a_conversation_takes_its_recreation_only() {
    let app = spawn().await;
    let (_alice, mut alice1, bob, mut bob1, mut dm) = group_of_two(&app).await;
    let message = alice1.encrypt(b"before");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    assert_eq!(bob1.receive_text(&dm).await.1, b"before");
    let old_message = alice1.encrypt(b"for the old group");
    let update = bob1.self_update(&dm);
    to_recreate(&app, &dm).await;

    let id = alice1
        .send_message(&dm, Uuid::new_v4(), old_message.clone())
        .await;
    assert_eq!(
        refused(&alice1.answer(id).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    let id = bob1.submit(&dm, 1, update, false).await;
    assert_eq!(
        refused(&bob1.answer(id).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    assert_eq!(
        refused(&bob1.request(group_info_request(&dm)).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    // The server asks for no removal in a group that is to be recreated.
    assert_eq!(
        removals::remove_device(&app.state, bob1.device.device_id)
            .await
            .unwrap(),
        0
    );

    upload(&app, &bob1.device, 2).await;
    let before = last_seq(&app, dm.conversation).await;
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 3).await;
    let id = alice1.submit(&dm, 0, commit, false).await;
    let ack = *commit_ack(&alice1.answer(id).await);
    assert_eq!(
        (ack.seq, ack.new_epoch),
        (u64::try_from(before).unwrap() + 1, 1)
    );
    alice1.merge();
    bob1.drop_group();
    bob1.join(&dm).await;

    // Only the new group is left, and the sequence went on.
    assert_eq!(sequence(&app, dm.conversation).await, [(before + 1, 2)]);
    assert_eq!(generations_stored(&app, &dm).await, [3]);
    assert_eq!(recreation_of(&app, &dm).await, (false, true));
    assert_eq!(welcomes_of(&app, dm.conversation).await.len(), 1);
    let mut devices = vec![alice1.device.device_id, bob1.device.device_id];
    devices.sort();
    assert_eq!(routed(&app, dm.conversation).await, devices);

    let id = alice1.send_message(&dm, Uuid::new_v4(), old_message).await;
    assert_eq!(
        refused(&alice1.answer(id).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    let message = alice1.encrypt(b"after");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    assert_eq!(bob1.receive_text(&dm).await.1, b"after");
}

/// Section 17: two devices recreating at once give one group: the first
/// commit wins, the other is told it is stale.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn two_recreations_at_once_give_one_group() {
    let app = spawn().await;
    let (alice, mut alice1, bob, mut bob1, mut dm) = group_of_two(&app).await;
    upload(&app, &alice1.device, 2).await;
    upload(&app, &bob1.device, 2).await;
    to_recreate(&app, &dm).await;
    let mut theirs = dm_copy(&dm);
    let from_alice = recreate(&app, &mut alice1, &bob, &mut dm, 1).await;
    let from_bob = recreate(&app, &mut bob1, &alice, &mut theirs, 1).await;

    let (held, holder) = hold(&app, dm.conversation).await;
    let first = alice1.submit(&dm, 0, from_alice, false).await;
    waiting_for(&app, holder, 1).await;
    let second = bob1.submit(&theirs, 0, from_bob, false).await;
    waiting_for(&app, holder, 2).await;
    held.rollback().await.unwrap();

    assert_eq!(commit_ack(&alice1.answer(first).await).new_epoch, 1);
    assert_eq!(
        refused(&bob1.answer(second).await),
        proto::ErrorCode::StaleEpoch
    );
    assert_eq!(generations_stored(&app, &dm).await, [1]);
    assert_eq!(recreation_of(&app, &dm).await, (false, true));
}

/// Section 17, at a user's request (section 11): the next generation
/// only, at most once an hour (`RATE_LIMITED` for a device of the group,
/// with the wait), and between friends only.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_user_recreates_a_group_at_most_once_an_hour() {
    let app = spawn().await;
    let (alice, mut alice1, bob, mut bob1, mut dm) = group_of_two(&app).await;
    upload(&app, &bob1.device, 6).await;

    // Not marked by a restore: no generation skipped.
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 2).await;
    let id = alice1.submit(&dm, 0, commit, false).await;
    assert_eq!(
        refused(&alice1.answer(id).await),
        proto::ErrorCode::InvalidCommit
    );
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 1).await;
    let id = alice1.submit(&dm, 0, commit, false).await;
    commit_ack(&alice1.answer(id).await);
    alice1.merge();
    bob1.drop_group();
    bob1.join(&dm).await;

    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 2).await;
    let id = alice1.submit(&dm, 0, commit, false).await;
    let ServerPayload::Error(error) = alice1.answer(id).await else {
        panic!("expected a refusal");
    };
    assert_eq!(error.code, i32::from(proto::ErrorCode::RateLimited));
    assert!((1..=3_600_000).contains(&error.retry_after_ms));

    // An hour later.
    sqlx::query(
        "UPDATE conversations SET recreated_at = now() - interval '61 minutes' WHERE id = $1",
    )
    .bind(dm.conversation)
    .execute(&app.state.db)
    .await
    .unwrap();
    // A read-only DM is not recreated: its new group would add leaves.
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 2).await;
    let status = app
        .status::<()>(
            Method::DELETE,
            &format!("/v1/friends/{}", alice.user_id),
            Some(&bob1.device.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let id = alice1.submit(&dm, 0, commit, false).await;
    assert_eq!(
        refused(&alice1.answer(id).await),
        proto::ErrorCode::NotFriends
    );
    assert_eq!(generations_stored(&app, &dm).await, [1]);
}

/// Section 15: a conversation that had no group at the time of the backup
/// may have had one after it, at generation 0: once restored, it is
/// created at a later generation.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_restored_conversation_without_a_group_skips_generation_0() {
    let app = spawn().await;
    let (alice, alice1) = app.account_with_device("rc", false).await;
    let bob = app.register("rc", false).await;
    let mut dm = dm_between(&app, (&alice, &alice1), &bob).await;
    let bob1 = app.enrol(&bob).await;
    upload(&app, &bob1, 2).await;
    let mut alice1 = Member::connect(&app, alice1).await;
    to_recreate(&app, &dm).await;

    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 0).await;
    let id = alice1.submit(&dm, 0, commit, false).await;
    assert_eq!(
        refused(&alice1.answer(id).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 1).await;
    let id = alice1.submit(&dm, 0, commit, false).await;
    assert_eq!(commit_ack(&alice1.answer(id).await).new_epoch, 1);
    assert_eq!(generations_stored(&app, &dm).await, [1]);
    assert_eq!(recreation_of(&app, &dm).await, (false, true));
}

/// A second view of the same DM, for another device's group.
fn dm_copy(dm: &Dm) -> Dm {
    Dm {
        conversation: dm.conversation,
        generation: dm.generation,
        participants: dm.participants,
        keys: Keys(dm.keys.0.clone()),
        external_sender: dm.external_sender,
    }
}
