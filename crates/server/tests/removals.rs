// SPDX-License-Identifier: AGPL-3.0-or-later

//! The server's removals (ADR 0019, sections 4, 6 and 15): a revoked
//! device, the devices of a disabled account and a device away for longer
//! than `TAVERN_DEVICE_INACTIVE_DAYS` leave their groups by the server's
//! `Remove`, once per group; the device is cut off from its proposal on;
//! a device back from an inactivity rejoins by external commit, which
//! settles its removal; devices left out of a group are told to join.
//! Groups built by `tavern-crypto` on the clients' side, against a real
//! server and database.
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
use common::{Account, Device, TestApp};
use reqwest::{Method, StatusCode};
use tavern_crypto::mls::Incoming;
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_server::removals;
use uuid::Uuid;

/// The next event of `member`, which must be the server's removal: its
/// stored message.
async fn removal_event(member: &mut Member) -> proto::StoredMessage {
    let ServerPayload::ProposalEvent(event) = member.event().await else {
        panic!("expected the server's removal");
    };
    let proposal = event.message.unwrap();
    assert!(proposal.sender_device_id.is_empty(), "the server's");
    proposal
}

/// Makes `device` look away since 40 days, longer than the default window.
async fn away(app: &TestApp, device: &Device) {
    sqlx::query(
        "UPDATE devices SET last_seen_at = date_trunc('day', now()) - interval '40 days', \
                            created_at = now() - interval '40 days' \
         WHERE id = $1",
    )
    .bind(device.device_id)
    .execute(&app.state.db)
    .await
    .unwrap();
}

/// Makes `device` seen today again, as its next connection does.
async fn back(app: &TestApp, device: &Device) {
    sqlx::query("UPDATE devices SET last_seen_at = date_trunc('day', now()) WHERE id = $1")
        .bind(device.device_id)
        .execute(&app.state.db)
        .await
        .unwrap();
}

async fn acked_seq(app: &TestApp, dm: &Dm, device: &Device) -> i64 {
    sqlx::query_scalar(
        "SELECT acked_seq FROM conversation_devices WHERE conversation_id = $1 AND device_id = $2",
    )
    .bind(dm.conversation)
    .bind(device.device_id)
    .fetch_one(&app.state.db)
    .await
    .unwrap()
}

/// Bob's device, already in a group with Alice, joins a DM with Carol: the
/// group as Carol's device keeps it.
async fn carol_s_group_with(app: &TestApp, bob: &Account, bob1: &mut Member) -> (Member, Dm) {
    let (carol, carol1) = app.account_with_device("rm", false).await;
    let dm = dm_between(app, (&carol, &carol1), bob).await;
    let claimed = claim(app, &carol1, bob, &dm.keys).await;
    assert_eq!(claimed.len(), 1, "only Bob's first device has packages");
    let mut carol1 = Member::connect(app, carol1).await;
    let commit = carol1.create(&dm, &claimed);
    let id = carol1.submit(&dm, 0, commit, false).await;
    commit_ack(&carol1.answer(id).await);
    carol1.merge();
    bob1.join(&dm).await;
    (carol1, dm)
}

/// Sections 6 and 18: a device revoked through the REST route leaves each
/// of its groups by one proposal of the server, whatever asks again; the
/// first member online commits it, and the group takes messages again.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_revoked_device_leaves_each_of_its_groups_once() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, bob, mut bob1, dm) = group_of_two(&app).await;
    let (mut carol1, dm2) = carol_s_group_with(&app, &bob, &mut bob1).await;

    let bob2 = app.enrol(&bob).await;
    let status = app
        .status::<()>(
            Method::DELETE,
            &format!("/v1/devices/{}", bob1.device.device_id),
            Some(&bob2.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    for (member, dm) in [(&mut alice1, &dm), (&mut carol1, &dm2)] {
        let proposal = removal_event(member).await;
        assert_eq!((proposal.seq, proposal.epoch), (2, 1));
        assert!(matches!(
            member.process(dm, &proposal.mls_message),
            Incoming::Proposal
        ));
        assert_eq!(
            pending_removals(&app, dm.conversation).await,
            [(bob1.device.device_id, 2)]
        );
    }
    // Asked again, by the request's path, one group at a time, or the
    // sweep: nothing more.
    assert_eq!(
        removals::remove_device(&app.state, bob1.device.device_id)
            .await
            .unwrap(),
        0
    );
    assert!(
        !removals::remove_from(&app.state, dm.conversation, bob1.device.device_id)
            .await
            .unwrap()
    );
    removals::sweep(&app.state).await.unwrap();
    for dm in [&dm, &dm2] {
        assert_eq!(sequence(&app, dm.conversation).await, [(1, 2), (2, 3)]);
    }

    let commit = alice1.commit_pending(&dm);
    let id = alice1.submit(&dm, 1, commit, false).await;
    commit_ack(&alice1.answer(id).await);
    alice1.merge();
    assert!(pending_removals(&app, dm.conversation).await.is_empty());
    assert_eq!(
        pending_removals(&app, dm2.conversation).await,
        [(bob1.device.device_id, 2)],
        "the other group still waits for its member"
    );
    assert_eq!(
        routed(&app, dm.conversation).await,
        [alice1.device.device_id]
    );
    let message = alice1.encrypt(b"after the removal");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    carol1.nothing_waiting().await;
}

/// Section 6 and the maintainer's preference: a disabled account's devices
/// leave their groups as at a revocation; enabling it again asks nothing
/// more (its devices come back by external commit, tasks 10 and 11).
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_disabled_account_s_devices_leave_their_groups() {
    let app = TestApp::spawn_unlimited().await;
    let (_, admin1) = app.account_with_device("rm", true).await;
    let (_, mut alice1, bob, bob1, dm) = group_of_two(&app).await;

    let status = app
        .status::<()>(
            Method::POST,
            &format!("/v1/admin/users/{}/disable", bob.user_id),
            Some(&admin1.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let proposal = removal_event(&mut alice1).await;
    assert_eq!(proposal.seq, 2);
    assert_eq!(
        pending_removals(&app, dm.conversation).await,
        [(bob1.device.device_id, 2)]
    );

    let status = app
        .status::<()>(
            Method::POST,
            &format!("/v1/admin/users/{}/enable", bob.user_id),
            Some(&admin1.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    removals::sweep(&app.state).await.unwrap();
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2), (2, 3)]);
    alice1.nothing_waiting().await;
}

/// Section 15: a device away for longer than the window is removed by the
/// sweep, without being revoked. From its proposal on it is cut off: no
/// event, the sequence up to its proposal and no further, its cursor
/// capped there, nothing sent. Back, it rejoins by external commit, which
/// removes its earlier leaf and so settles its removal; the server asks
/// again only for the removals still applicable.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn an_inactive_device_is_removed_cut_off_and_comes_back_by_external_commit() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, _alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let mut alice2 = Member::connect(&app, app.enrol(&alice).await).await;
    commit_ack(&alice2.join_externally(&dm).await);
    alice2.merge();
    let ServerPayload::CommitEvent(event) = bob1.event().await else {
        panic!("expected the external commit");
    };
    assert!(matches!(
        bob1.process(&dm, &event.message.unwrap().mls_message),
        Incoming::Commit { .. }
    ));
    // Built while Bob's device is still a member.
    let held = bob1.encrypt(b"held");

    away(&app, &bob1.device).await;
    removals::sweep(&app.state).await.unwrap();
    assert_eq!(
        pending_removals(&app, dm.conversation).await,
        [(bob1.device.device_id, 3)]
    );
    assert_eq!(removal_event(&mut bob1).await.seq, 3);
    assert!(!listed(&app, &bob1.device, &dm).await.joined);

    // Another removal after Bob's: not for Bob's device.
    away(&app, &alice2.device).await;
    removals::sweep(&app.state).await.unwrap();
    assert_eq!(
        pending_removals(&app, dm.conversation).await,
        [(bob1.device.device_id, 3), (alice2.device.device_id, 4)]
    );
    bob1.nothing_waiting().await;
    let batch = bob1.fetch(&dm, 0, 0).await;
    let seqs: Vec<u64> = batch.messages.iter().map(|message| message.seq).collect();
    assert_eq!(seqs, [2, 3], "from its join to its proposal");
    bob1.ack(&dm, 100).await;
    assert_eq!(acked_seq(&app, &dm, &bob1.device).await, 3);
    let id = bob1.send_message(&dm, Uuid::new_v4(), held).await;
    assert_eq!(code(&bob1.answer(id).await), proto::ErrorCode::NotAMember);

    // Back: the external commit removes its earlier leaf, which settles its
    // removal; Alice's second device's is asked again, after it.
    back(&app, &bob1.device).await;
    let ack = bob1.join_externally(&dm).await;
    assert_eq!((commit_ack(&ack).seq, commit_ack(&ack).new_epoch), (5, 3));
    bob1.merge();
    assert_eq!(
        pending_removals(&app, dm.conversation).await,
        [(alice2.device.device_id, 6)]
    );
    assert_eq!(
        sequence(&app, dm.conversation).await,
        [(1, 2), (2, 2), (3, 3), (4, 3), (5, 2), (6, 3)]
    );
    assert!(listed(&app, &bob1.device, &dm).await.joined);
    let ServerPayload::ProposalEvent(event) = bob1.event().await else {
        panic!("expected the removal asked again");
    };
    assert_eq!(event.message.unwrap().seq, 6);
    assert_eq!(
        routed(&app, dm.conversation).await,
        in_tree(&app, &dm).await
    );
}

/// Section 6: two removals of the same leaf at once, the request's and the
/// sweep's, give one proposal; the second waits for the first and finds
/// nothing to do.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn two_removals_of_one_leaf_at_once_give_one_proposal() {
    let app = TestApp::spawn_unlimited().await;
    let (_, _alice1, _, bob1, dm) = group_of_two(&app).await;
    away(&app, &bob1.device).await;

    let (tx, holder) = hold(&app, dm.conversation).await;
    let request = tokio::spawn({
        let state = app.state.clone();
        let device = bob1.device.device_id;
        async move { removals::remove_device(&state, device).await.unwrap() }
    });
    let sweep = tokio::spawn({
        let state = app.state.clone();
        async move { removals::sweep(&state).await.unwrap() }
    });
    waiting_for(&app, holder, 2).await;
    tx.commit().await.unwrap();
    let by_request = request.await.unwrap();
    sweep.await.unwrap();

    assert!(by_request <= 1);
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2), (2, 3)]);
    assert_eq!(
        pending_removals(&app, dm.conversation).await,
        [(bob1.device.device_id, 2)]
    );
}

/// Section 4: an active device of a participant that is not in the group
/// (enrolled after it was created) is told, after each commit, to join by
/// external commit, and lists the conversation as not joined; once it
/// joined, it lists it as joined. In a read-only DM, nobody is told.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn devices_left_out_are_told_to_join_in_a_dm_open_to_writing_only() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, mut alice1, bob, _, dm) = group_of_two(&app).await;
    let mut alice2 = Member::connect(&app, app.enrol(&alice).await).await;
    assert!(!listed(&app, &alice2.device, &dm).await.joined);
    assert!(listed(&app, &alice1.device, &dm).await.joined);

    let commit = alice1.self_update(&dm);
    let id = alice1.submit(&dm, 1, commit, false).await;
    commit_ack(&alice1.answer(id).await);
    alice1.merge();
    alice2.nothing_waiting().await;
    assert_eq!(alice2.told_to_join, [dm.conversation]);

    commit_ack(&alice2.join_externally(&dm).await);
    alice2.merge();
    assert!(listed(&app, &alice2.device, &dm).await.joined);
    let ServerPayload::CommitEvent(event) = alice1.event().await else {
        panic!("expected the external commit");
    };
    assert!(matches!(
        alice1.process(&dm, &event.message.unwrap().mls_message),
        Incoming::Commit { .. }
    ));

    // Read-only: an update goes through, and nobody is told to join.
    let status = app
        .status::<()>(
            Method::DELETE,
            &format!("/v1/friends/{}", bob.user_id),
            Some(&alice1.device.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let mut alice3 = Member::connect(&app, app.enrol(&alice).await).await;
    let commit = alice1.self_update(&dm);
    let id = alice1.submit(&dm, 3, commit, false).await;
    commit_ack(&alice1.answer(id).await);
    alice1.merge();
    alice3.nothing_waiting().await;
    assert!(alice3.told_to_join.is_empty());
    let listed = listed(&app, &alice3.device, &dm).await;
    assert!(listed.read_only && !listed.joined);
}
