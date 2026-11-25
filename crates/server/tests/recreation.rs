// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recreating a conversation's group (ADR 0019, sections 15 and 17): after
//! a restore, the only commit a conversation takes, at the first group
//! generation of the new instance generation; at a user's request, the next
//! generation, at most once an hour. The tests after a restore have a
//! database of their own ([`common::fresh_database`]): the restore changes
//! the whole instance.
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
use common::{Account, TestApp, drop_database, fresh_database};
use reqwest::{Method, StatusCode};
use tavern_crypto::mls::Commit;
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_protocol::group_generation;
use tavern_server::config::ClaimLimits;
use tavern_server::{removals, restore};
use uuid::Uuid;

/// Recreations claim KeyPackages again and again.
fn many_claims(settings: &mut tavern_server::Settings) {
    settings.claim_limits = ClaimLimits {
        per_requester_per_hour: 1_000,
        per_pair_per_hour: 1_000,
        per_pair_per_day: 1_000,
    };
}

/// The group generation the first restore requires.
fn after_first_restore() -> u32 {
    group_generation::after_restore(1).unwrap()
}

/// A restore as the server handles it at start-up, `restore.sh` having
/// raised the generation; then the devices sign in again, and upload new
/// KeyPackages (the one-time ones were deleted).
async fn restore_and_sign_in(app: &TestApp, members: &mut [(&Account, &mut Member)]) {
    sqlx::query("UPDATE instance_state SET generation = generation + 1")
        .execute(&app.state.db)
        .await
        .unwrap();
    assert!(matches!(
        restore::handle(&app.state.db, None).await.unwrap(),
        restore::Start::Restored(_)
    ));
    for (account, member) in members {
        app.reopen(account, &mut member.device).await;
        member.socket = common::ws::connect(app, &member.device).await.0;
        member.events.clear();
        upload(app, &member.device, 3).await;
    }
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

/// An hour later, for the limit on recreations.
async fn an_hour_later(app: &TestApp, dm: &Dm) {
    sqlx::query(
        "UPDATE conversations SET recreated_at = now() - interval '61 minutes' WHERE id = $1",
    )
    .bind(dm.conversation)
    .execute(&app.state.db)
    .await
    .unwrap();
}

/// `member` builds the first commit of the group's `generation`, with the
/// packages of `peer`'s devices; its earlier group is dropped.
async fn recreate(
    app: &TestApp,
    member: &mut Member,
    peer: &Account,
    dm: &mut Dm,
    generation: u32,
) -> Commit {
    let claimed = claim(app, &member.device, peer, &dm.keys).await;
    if member.group.is_some() {
        member.drop_group();
    }
    dm.generation = generation;
    member.create(dm, &claimed)
}

async fn submitted(member: &mut Member, dm: &Dm, commit: Commit) -> ServerPayload {
    let id = member.submit(dm, 0, commit, false).await;
    member.answer(id).await
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

/// Sections 15 and 17: once restored, a conversation takes nothing but
/// the recreation of its group, at the first generation of the new
/// instance generation only. The recreation deletes what the old group
/// left; its number comes after the jump of the restore, above any number
/// given after the backup; a message or a commit for the old group is
/// refused, while the new group works.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn after_a_restore_a_conversation_takes_its_recreation_only() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, many_claims).await;
    let (alice, mut alice1, bob, mut bob1, mut dm) = group_of_two(&app).await;
    let message = alice1.encrypt(b"before");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    assert_eq!(bob1.receive_text(&dm).await.1, b"before");
    let old_message = alice1.encrypt(b"for the old group");
    let update = bob1.self_update(&dm);
    let before = last_seq(&app, dm.conversation).await;
    restore_and_sign_in(&app, &mut [(&alice, &mut alice1), (&bob, &mut bob1)]).await;

    let id = alice1
        .send_message(&dm, Uuid::new_v4(), old_message.clone())
        .await;
    assert_eq!(
        code(&alice1.answer(id).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    let id = bob1.submit(&dm, 1, update.clone(), false).await;
    assert_eq!(
        code(&bob1.answer(id).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    assert_eq!(
        code(&bob1.request(group_info_request(&dm)).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    // The server asks for no removal in a group to recreate.
    assert_eq!(
        removals::remove_device(&app.state, bob1.device.device_id)
            .await
            .unwrap(),
        0
    );

    // The next generation, as a device that does not know of the restore
    // would pick it: refused.
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 1).await;
    assert_eq!(
        code(&submitted(&mut alice1, &dm, commit).await),
        proto::ErrorCode::InvalidCommit
    );
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, after_first_restore()).await;
    let ack = *commit_ack(&submitted(&mut alice1, &dm, commit).await);
    let jumped = before + restore::SEQUENCE_JUMP;
    assert_eq!(
        (ack.seq, ack.new_epoch),
        (u64::try_from(jumped).unwrap() + 1, 1)
    );
    alice1.merge();
    bob1.drop_group();
    bob1.join(&dm).await;

    // Only the new group is left.
    assert_eq!(sequence(&app, dm.conversation).await, [(jumped + 1, 2)]);
    assert_eq!(
        generations_stored(&app, &dm).await,
        [i64::from(after_first_restore())]
    );
    assert_eq!(recreation_of(&app, &dm).await, (false, true));
    assert_eq!(welcomes_of(&app, dm.conversation).await.len(), 1);
    let mut devices = vec![alice1.device.device_id, bob1.device.device_id];
    devices.sort();
    assert_eq!(routed(&app, dm.conversation).await, devices);

    // The old group's message and commit, now that it was recreated.
    let id = alice1.send_message(&dm, Uuid::new_v4(), old_message).await;
    assert_eq!(
        code(&alice1.answer(id).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    let mut old = dm_copy(&dm);
    old.generation = 0;
    let id = bob1.submit(&old, 1, update, false).await;
    assert_eq!(
        code(&bob1.answer(id).await),
        proto::ErrorCode::GroupRecreationRequired
    );
    let message = alice1.encrypt(b"after");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    assert_eq!(bob1.receive_text(&dm).await.1, b"after");

    drop_database(&url).await;
}

/// Section 17: two devices recreating at once at the same generation give
/// one group: the first commit wins, the other is told it is stale.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn two_recreations_at_once_give_one_group() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, many_claims).await;
    let (alice, mut alice1, bob, mut bob1, mut dm) = group_of_two(&app).await;
    restore_and_sign_in(&app, &mut [(&alice, &mut alice1), (&bob, &mut bob1)]).await;
    let mut theirs = dm_copy(&dm);
    let from_alice = recreate(&app, &mut alice1, &bob, &mut dm, after_first_restore()).await;
    let from_bob = recreate(&app, &mut bob1, &alice, &mut theirs, after_first_restore()).await;

    let (held, holder) = hold(&app, dm.conversation).await;
    let first = alice1.submit(&dm, 0, from_alice, false).await;
    waiting_for(&app, holder, 1).await;
    let second = bob1.submit(&theirs, 0, from_bob, false).await;
    waiting_for(&app, holder, 2).await;
    held.rollback().await.unwrap();

    assert_eq!(commit_ack(&alice1.answer(first).await).new_epoch, 1);
    assert_eq!(
        code(&bob1.answer(second).await),
        proto::ErrorCode::StaleEpoch
    );
    assert_eq!(
        generations_stored(&app, &dm).await,
        [i64::from(after_first_restore())]
    );

    drop_database(&url).await;
}

/// Sections 15 and 17, the review's case: two devices recreating at once at
/// different generations, one of them unaware of the restore. Only the
/// generation the restore requires is taken, and generations never cross:
/// the other device joins the one group by its Welcome.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn two_recreations_at_different_generations_give_the_required_one() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, many_claims).await;
    let (alice, mut alice1, bob, mut bob1, mut dm) = group_of_two(&app).await;
    restore_and_sign_in(&app, &mut [(&alice, &mut alice1), (&bob, &mut bob1)]).await;
    let mut theirs = dm_copy(&dm);
    let from_alice = recreate(&app, &mut alice1, &bob, &mut dm, after_first_restore()).await;
    let from_bob = recreate(&app, &mut bob1, &alice, &mut theirs, 1).await;

    // Bob's first, then Alice's.
    let (held, holder) = hold(&app, dm.conversation).await;
    let first = bob1.submit(&theirs, 0, from_bob, false).await;
    waiting_for(&app, holder, 1).await;
    let second = alice1.submit(&dm, 0, from_alice, false).await;
    waiting_for(&app, holder, 2).await;
    held.rollback().await.unwrap();

    assert_eq!(
        code(&bob1.answer(first).await),
        proto::ErrorCode::InvalidCommit
    );
    assert_eq!(commit_ack(&alice1.answer(second).await).new_epoch, 1);
    alice1.merge();
    bob1.drop_group();
    bob1.join(&dm).await;
    assert_eq!(
        generations_stored(&app, &dm).await,
        [i64::from(after_first_restore())]
    );

    drop_database(&url).await;
}

/// Section 17, at a user's request (section 11): the next generation only,
/// at most once an hour (`RATE_LIMITED` to a device of the group, with the
/// wait; `STALE_EPOCH` to a device outside it, which has a Welcome to
/// process or the group to join), accepted again an hour later, and
/// between friends only.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_user_recreates_a_group_at_most_once_an_hour() {
    let app = TestApp::spawn_configured(many_claims).await;
    let (alice, mut alice1, bob, mut bob1, mut dm) = group_of_two(&app).await;
    upload(&app, &alice1.device, 4).await;
    upload(&app, &bob1.device, 8).await;

    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 2).await;
    assert_eq!(
        code(&submitted(&mut alice1, &dm, commit).await),
        proto::ErrorCode::InvalidCommit
    );
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 1).await;
    commit_ack(&submitted(&mut alice1, &dm, commit).await);
    alice1.merge();
    bob1.drop_group();
    bob1.join(&dm).await;

    // Within the hour: a device of the group is told to wait.
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 2).await;
    let ServerPayload::Error(error) = submitted(&mut alice1, &dm, commit).await else {
        panic!("expected a refusal");
    };
    assert_eq!(error.code, i32::from(proto::ErrorCode::RateLimited));
    assert!((1..=3_600_000).contains(&error.retry_after_ms));
    // A device outside the group (Bob's newest) is told the group changed.
    let bob2 = app.enrol(&bob).await;
    let mut bob2 = Member::connect(&app, bob2).await;
    let mut theirs = dm_copy(&dm);
    let commit = recreate(&app, &mut bob2, &alice, &mut theirs, 2).await;
    assert_eq!(
        code(&submitted(&mut bob2, &theirs, commit).await),
        proto::ErrorCode::StaleEpoch
    );

    // An hour later, accepted.
    an_hour_later(&app, &dm).await;
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 2).await;
    assert_eq!(
        commit_ack(&submitted(&mut alice1, &dm, commit).await).new_epoch,
        1
    );
    alice1.merge();
    assert_eq!(generations_stored(&app, &dm).await, [2]);

    // A read-only DM is not recreated: its new group would add leaves.
    an_hour_later(&app, &dm).await;
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 3).await;
    let status = app
        .status::<()>(
            Method::DELETE,
            &format!("/v1/friends/{}", alice.user_id),
            Some(&bob1.device.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        code(&submitted(&mut alice1, &dm, commit).await),
        proto::ErrorCode::NotFriends
    );
    assert_eq!(generations_stored(&app, &dm).await, [2]);
}

/// Section 17: who may not recreate. A revoked device is told so before
/// anything else (`UNAUTHENTICATED`); a device the server is removing for
/// its inactivity, and that is active again, may, which settles its
/// removal.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_revoked_device_never_recreates_a_device_back_may() {
    let app = TestApp::spawn_configured(many_claims).await;
    let (alice, mut alice1, bob, mut bob1, mut dm) = group_of_two(&app).await;
    upload(&app, &alice1.device, 4).await;
    upload(&app, &bob1.device, 4).await;

    // Alice's device, away for 40 days: the server asks for its removal.
    sqlx::query(
        "UPDATE devices SET last_seen_at = date_trunc('day', now()) - interval '40 days' \
         WHERE id = $1",
    )
    .bind(alice1.device.device_id)
    .execute(&app.state.db)
    .await
    .unwrap();
    removals::remove_from(&app.state, dm.conversation, alice1.device.device_id)
        .await
        .unwrap();
    assert_eq!(pending_removals(&app, dm.conversation).await.len(), 1);
    // Back: seen today again.
    sqlx::query("UPDATE devices SET last_seen_at = date_trunc('day', now()) WHERE id = $1")
        .bind(alice1.device.device_id)
        .execute(&app.state.db)
        .await
        .unwrap();
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 1).await;
    commit_ack(&submitted(&mut alice1, &dm, commit).await);
    assert!(pending_removals(&app, dm.conversation).await.is_empty());

    // Bob's device, revoked in the database (its connection not told).
    an_hour_later(&app, &dm).await;
    let mut theirs = dm_copy(&dm);
    let commit = recreate(&app, &mut bob1, &alice, &mut theirs, 2).await;
    for statement in [
        "UPDATE devices SET revoked_at = now() WHERE id = $1",
        "UPDATE sessions SET revoked_at = now() WHERE device_id = $1",
    ] {
        sqlx::query(statement)
            .bind(bob1.device.device_id)
            .execute(&app.state.db)
            .await
            .unwrap();
    }
    let refused = tavern_server::delivery::submit_commit(
        &app.state,
        &session(&bob, &bob1.device),
        proto::SubmitCommit {
            conversation_id: dm.conversation.as_bytes().to_vec(),
            epoch: 0,
            mls_commit: commit.commit,
            mls_welcome: commit.welcome.unwrap_or_default(),
            mls_group_info: commit.group_info,
            external: false,
        },
    )
    .await
    .expect_err("refused");
    assert_eq!(refused.code, proto::ErrorCode::Unauthenticated);
}

/// Sections 4 and 17: what no first commit may be. Without a group and
/// without a restore, generation 0 only; a commit whose header names
/// another conversation is refused; after a restore, a conversation that
/// had no group takes the restore's generation, not 0, which a group
/// created after the backup may have had.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn first_commits_take_the_one_generation_allowed() {
    let url = fresh_database().await;
    let app = TestApp::spawn_on(&url, many_claims).await;
    let (alice, alice1) = app.account_with_device("rc", false).await;
    let bob = app.register("rc", false).await;
    let mut dm = dm_between(&app, (&alice, &alice1), &bob).await;
    let carol = app.register("rc", false).await;
    let mut elsewhere = dm_between(&app, (&alice, &alice1), &carol).await;
    let bob1 = app.enrol(&bob).await;
    upload(&app, &bob1, 6).await;
    let carol1 = app.enrol(&carol).await;
    upload(&app, &carol1, 2).await;
    let mut alice1 = Member::connect(&app, alice1).await;

    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 1).await;
    assert_eq!(
        code(&submitted(&mut alice1, &dm, commit).await),
        proto::ErrorCode::InvalidCommit
    );
    // The first commit of the DM with Carol, submitted for the DM with Bob.
    let commit = recreate(&app, &mut alice1, &carol, &mut elsewhere, 0).await;
    assert_eq!(
        code(&submitted(&mut alice1, &dm, commit).await),
        proto::ErrorCode::InvalidCommit
    );

    restore_and_sign_in(&app, &mut [(&alice, &mut alice1)]).await;
    let mut bob1 = bob1;
    app.reopen(&bob, &mut bob1).await;
    upload(&app, &bob1, 3).await;
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, 0).await;
    assert_eq!(
        code(&submitted(&mut alice1, &dm, commit).await),
        proto::ErrorCode::InvalidCommit
    );
    let commit = recreate(&app, &mut alice1, &bob, &mut dm, after_first_restore()).await;
    assert_eq!(
        commit_ack(&submitted(&mut alice1, &dm, commit).await).new_epoch,
        1
    );
    assert_eq!(
        generations_stored(&app, &dm).await,
        [i64::from(after_first_restore())]
    );
    assert_eq!(recreation_of(&app, &dm).await, (false, true));

    drop_database(&url).await;
}
