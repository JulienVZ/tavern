// SPDX-License-Identifier: AGPL-3.0-or-later

//! A conversation's sequence through the gateway (ADR 0019, sections 4 to 7,
//! 16 and 18): groups built by `tavern-crypto` on the clients' side, as a
//! client builds them, against a real server and database.
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

use common::ws::{Received, connect, expect_close, expect_frame, hello, open, receive, send};
use common::{Account, Device, TestApp};
use openmls_memory_storage::MemoryStorage;
use reqwest::Method;
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::{
    ClaimedKeyPackage, Commit, DeviceSigner, Group, Incoming, Provider, VerifiedLeaf, padding,
};
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::client_frame::Payload as ClientPayload;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_protocol::{
    GATEWAY_HELLOS_PER_MINUTE, GATEWAY_REQUEST_BURST, GATEWAY_SUBPROTOCOL,
    MAX_APPLICATION_MESSAGE_BYTES, close_code,
};
use tavern_server::delivery::{self, Kind};
use tavern_server::gateway::EVENT_QUEUE_LEN;
use tavern_server::removals;
use uuid::Uuid;

/// Sections 4 and 18: the first device creates the group with its own
/// other device and the peer's devices; those join by Welcome, a device
/// that was offline gets its Welcome at its next connection, and every
/// device of the group but the sender reads the message, in order.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_group_is_created_joined_and_written_to() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, alice1) = app.account_with_device("sq", false).await;
    let bob = app.register("sq", false).await;
    let dm = dm_between(&app, (&alice, &alice1), &bob).await;
    let alice2 = app.enrol(&alice).await;
    let bob1 = app.enrol(&bob).await;
    let bob2 = app.enrol(&bob).await;
    // The device `dm_between` enrolled for Bob uploads nothing: absent.
    for device in [&alice2, &bob1, &bob2] {
        upload(&app, device, 3).await;
    }
    let mut claimed = claim(&app, &alice1, &alice, &dm.keys).await;
    claimed.extend(claim(&app, &alice1, &bob, &dm.keys).await);
    assert_eq!(claimed.len(), 3);
    let mut alice1 = Member::connect(&app, alice1).await;
    let mut alice2 = Member::connect(&app, alice2).await;
    let mut bob1 = Member::connect(&app, bob1).await;

    let commit = alice1.create(&dm, &claimed);
    let id = alice1.submit(&dm, 0, commit, false).await;
    let ack = alice1.answer(id).await;
    assert_eq!((commit_ack(&ack).seq, commit_ack(&ack).new_epoch), (1, 1));
    alice1.merge();
    alice2.join(&dm).await;
    bob1.join(&dm).await;
    assert_eq!(
        routed(&app, dm.conversation).await,
        in_tree(&app, &dm).await
    );
    assert_eq!(routed(&app, dm.conversation).await.len(), 4);

    let message = alice1.encrypt(b"hello");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    assert_eq!(message_ack(&alice1.answer(id).await).seq, 2);
    assert_eq!(bob1.receive_text(&dm).await, (2, b"hello".to_vec()));
    assert_eq!(
        alice2.receive_text(&dm).await,
        (2, b"hello".to_vec()),
        "the sender's own other devices too"
    );
    alice1.nothing_waiting().await;

    // Offline until now: its Welcome waits for it, then it reads from there.
    let mut bob2 = Member::connect(&app, bob2).await;
    bob2.join(&dm).await;
    let batch = bob2.fetch(&dm, 0, 0).await;
    assert!(!batch.more);
    assert_eq!(batch.messages.len(), 1, "from its join on: not the commit");
    let message = batch.messages[0].clone();
    assert_eq!(
        (message.seq, message.kind()),
        (2, proto::MessageKind::Application)
    );
    match bob2.process(&dm, &message.mls_message) {
        Incoming::Application { content, .. } => assert_eq!(content.expose(), b"hello"),
        other => panic!("{other:?}"),
    }
    // Acknowledged: not sent again.
    let Member { device, socket, .. } = bob2;
    drop(socket);
    let mut bob2 = Member::connect(&app, device).await;
    bob2.nothing_waiting().await;
}

/// Section 4: a conversation whose creating device stopped before its first
/// commit gets its group from a device of the other user.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_conversation_without_a_group_gets_it_from_either_user() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, alice1) = app.account_with_device("sq", false).await;
    let bob = app.register("sq", false).await;
    let dm = dm_between(&app, (&alice, &alice1), &bob).await;
    let bob1 = app.enrol(&bob).await;
    upload(&app, &alice1, 3).await;
    let claimed = claim(&app, &bob1, &alice, &dm.keys).await;
    let mut alice1 = Member::connect(&app, alice1).await;
    let mut bob1 = Member::connect(&app, bob1).await;

    let commit = bob1.create(&dm, &claimed);
    let id = bob1.submit(&dm, 0, commit, false).await;
    assert_eq!(commit_ack(&bob1.answer(id).await).new_epoch, 1);
    bob1.merge();
    alice1.join(&dm).await;
    assert_eq!(
        routed(&app, dm.conversation).await,
        in_tree(&app, &dm).await
    );
}

/// Sections 4 and 18: two first commits at once. Both wait for the
/// conversation, held here until PostgreSQL shows them waiting; one wins,
/// the other gets STALE_EPOCH and joins the winner's group by its Welcome.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn of_two_first_commits_at_once_one_wins_and_the_other_joins() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, alice1) = app.account_with_device("sq", false).await;
    let bob = app.register("sq", false).await;
    let dm = dm_between(&app, (&alice, &alice1), &bob).await;
    let bob1 = app.enrol(&bob).await;
    upload(&app, &alice1, 3).await;
    upload(&app, &bob1, 3).await;
    let for_alice = claim(&app, &alice1, &bob, &dm.keys).await;
    let for_bob = claim(&app, &bob1, &alice, &dm.keys).await;
    let mut alice1 = Member::connect(&app, alice1).await;
    let mut bob1 = Member::connect(&app, bob1).await;
    let alice_commit = alice1.create(&dm, &for_alice);
    let bob_commit = bob1.create(&dm, &for_bob);

    let (held, holder) = hold(&app, dm.conversation).await;
    let alice_id = alice1.submit(&dm, 0, alice_commit, false).await;
    let bob_id = bob1.submit(&dm, 0, bob_commit, false).await;
    waiting_for(&app, holder, 2).await;
    held.commit().await.unwrap();
    let (alice_answer, bob_answer) = (alice1.answer(alice_id).await, bob1.answer(bob_id).await);

    let (winner, loser, answer, refused) = match (&alice_answer, &bob_answer) {
        (ServerPayload::CommitAck(_), _) => (&mut alice1, &mut bob1, &alice_answer, &bob_answer),
        _ => (&mut bob1, &mut alice1, &bob_answer, &alice_answer),
    };
    assert_eq!(commit_ack(answer).seq, 1);
    assert_eq!(code(refused), proto::ErrorCode::StaleEpoch);
    winner.merge();
    loser.drop_group();
    loser.join(&dm).await;
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2)]);
    assert_eq!(
        routed(&app, dm.conversation).await,
        in_tree(&app, &dm).await
    );
}

/// Sections 7 and 18: one commit per epoch under concurrent submissions;
/// the second gets STALE_EPOCH, discards its commit and processes the
/// first.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn of_two_commits_for_one_epoch_the_second_is_stale() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let alice_commit = alice1.self_update(&dm);
    let bob_commit = bob1.self_update(&dm);

    let (held, holder) = hold(&app, dm.conversation).await;
    let alice_id = alice1.submit(&dm, 1, alice_commit, false).await;
    let bob_id = bob1.submit(&dm, 1, bob_commit, false).await;
    waiting_for(&app, holder, 2).await;
    held.commit().await.unwrap();
    let (alice_answer, bob_answer) = (alice1.answer(alice_id).await, bob1.answer(bob_id).await);

    let (winner, loser, answer, refused) = match (&alice_answer, &bob_answer) {
        (ServerPayload::CommitAck(_), _) => (&mut alice1, &mut bob1, &alice_answer, &bob_answer),
        _ => (&mut bob1, &mut alice1, &bob_answer, &alice_answer),
    };
    assert_eq!(
        (commit_ack(answer).seq, commit_ack(answer).new_epoch),
        (2, 2)
    );
    assert_eq!(code(refused), proto::ErrorCode::StaleEpoch);
    assert_eq!(current_epoch(refused), 2, "the epoch to catch up with");
    winner.merge();
    loser.discard();
    let ServerPayload::CommitEvent(event) = loser.event().await else {
        panic!("expected the winning commit");
    };
    let commit = event.message.unwrap();
    assert!(matches!(
        loser.process(&dm, &commit.mls_message),
        Incoming::Commit { .. }
    ));
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2), (2, 2)]);
}

/// Section 7: a message is stored and delivered once, whatever the resends,
/// even re-encrypted for a later epoch; a message for a past epoch is
/// STALE_EPOCH.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_message_is_stored_and_delivered_once_whatever_the_resends() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let first = Uuid::new_v4();
    let message = alice1.encrypt(b"once");
    let id = alice1.send_message(&dm, first, message.clone()).await;
    let ack = message_ack(&alice1.answer(id).await);
    let id = alice1.send_message(&dm, first, message.clone()).await;
    assert_eq!(
        message_ack(&alice1.answer(id).await),
        ack,
        "the original acknowledgement"
    );
    assert_eq!(bob1.receive_text(&dm).await, (ack.seq, b"once".to_vec()));

    // A commit moves the epoch: the old ciphertext is stale, and the same
    // message re-encrypted still gets its original acknowledgement.
    let commit = alice1.self_update(&dm);
    let id = alice1.submit(&dm, 1, commit, false).await;
    assert_eq!(commit_ack(&alice1.answer(id).await).new_epoch, 2);
    alice1.merge();
    let ServerPayload::CommitEvent(event) = bob1.event().await else {
        panic!("expected the commit");
    };
    bob1.process(&dm, &event.message.unwrap().mls_message);
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    let stale = alice1.answer(id).await;
    assert_eq!(
        (code(&stale), current_epoch(&stale)),
        (proto::ErrorCode::StaleEpoch, 2)
    );
    let again = alice1.encrypt(b"once");
    let id = alice1.send_message(&dm, first, again).await;
    assert_eq!(message_ack(&alice1.answer(id).await), ack);

    let next = alice1.encrypt(b"next");
    let id = alice1.send_message(&dm, Uuid::new_v4(), next).await;
    let next_ack = message_ack(&alice1.answer(id).await);
    assert_eq!(
        bob1.receive_text(&dm).await,
        (next_ack.seq, b"next".to_vec()),
        "nothing delivered twice in between"
    );
    assert_eq!(
        sequence(&app, dm.conversation).await,
        [(1, 2), (2, 1), (3, 2), (4, 1)]
    );
}

/// The maintainer's requirement for task 8: numbers are taken under the
/// conversation's lock, strictly increasing and without gaps, a failed
/// transaction taking its number back; under concurrent submissions too.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_sequence_has_no_gap_even_when_a_transaction_fails() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, alice1) = app.account_with_device("sq", false).await;
    let bob = app.register("sq", false).await;
    let dm = dm_between(&app, (&alice, &alice1), &bob).await;
    let append = |sender: Uuid| {
        let db = app.state.db.clone();
        let (conversation, me) = (dm.conversation, alice.user_id);
        async move {
            let mut tx = db.begin().await.unwrap();
            delivery::lock(&mut tx, conversation, me).await.unwrap();
            let entry = delivery::append(
                &mut tx,
                conversation,
                Kind::Application,
                1,
                Some(sender),
                b"ciphertext",
                30,
            )
            .await
            .unwrap();
            (tx, entry.seq)
        }
    };

    let (failed, seq) = append(alice1.device_id).await;
    assert_eq!(seq, 1);
    failed.rollback().await.unwrap();
    let (kept, seq) = append(alice1.device_id).await;
    assert_eq!(seq, 1, "the failed transaction took its number back");
    kept.commit().await.unwrap();

    let appended = futures_util::future::join_all((0..20).map(|_| async {
        let (tx, seq) = append(alice1.device_id).await;
        tx.commit().await.unwrap();
        seq
    }))
    .await;
    let mut seqs = appended;
    seqs.sort_unstable();
    assert_eq!(seqs, (2..=21).collect::<Vec<i64>>());
    let stored: Vec<i64> = sequence(&app, dm.conversation)
        .await
        .into_iter()
        .map(|(seq, _)| seq)
        .collect();
    assert_eq!(stored, (1..=21).collect::<Vec<i64>>());
}

/// Messages sent at once from both sides take consecutive numbers.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn messages_sent_at_once_take_consecutive_numbers() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let mut alice_ids = Vec::new();
    let mut bob_ids = Vec::new();
    for _ in 0..5 {
        let message = alice1.encrypt(b"from alice");
        alice_ids.push(alice1.send_message(&dm, Uuid::new_v4(), message).await);
        let message = bob1.encrypt(b"from bob");
        bob_ids.push(bob1.send_message(&dm, Uuid::new_v4(), message).await);
    }
    let mut seqs = Vec::new();
    for id in alice_ids {
        seqs.push(message_ack(&alice1.answer(id).await).seq);
    }
    for id in bob_ids {
        seqs.push(message_ack(&bob1.answer(id).await).seq);
    }
    seqs.sort_unstable();
    assert_eq!(seqs, (2..=11).collect::<Vec<u64>>());
}

/// The server asks to remove `device` from the group, as at a revocation
/// (`removals`): its proposal is stored with the group's state, and
/// appended to the sequence.
async fn server_removes(app: &TestApp, dm: &Dm, device: VerifiedLeaf) {
    make_due(app, dm.conversation, Uuid::from_bytes(device.device_id)).await;
    let issued = removals::remove_from(
        &app.state,
        dm.conversation,
        Uuid::from_bytes(device.device_id),
    )
    .await
    .unwrap();
    assert!(issued);
}

/// Section 6: while the server's removals are pending, no application
/// message is accepted, and a member's commit must carry them.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn pending_removals_hold_messages_and_commits_that_leave_them_out() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, bob, mut bob1, dm) = group_of_two(&app).await;
    // Built before Alice's device knows of the removal: an older or faulty
    // client's.
    let message = alice1.encrypt(b"held");
    let commit = alice1.self_update(&dm);
    server_removes(&app, &dm, leaf(&bob, &bob1.device)).await;

    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    assert_eq!(
        code(&alice1.answer(id).await),
        proto::ErrorCode::RemovalPending
    );
    let id = alice1.submit(&dm, 1, commit, false).await;
    assert_eq!(
        code(&alice1.answer(id).await),
        proto::ErrorCode::RemovalPending
    );
    // Both devices are told, the one to remove included, which then hears
    // nothing more.
    for member in [&mut alice1, &mut bob1] {
        let ServerPayload::ProposalEvent(event) = member.event().await else {
            panic!("expected the server's removal");
        };
        let proposal = event.message.unwrap();
        assert_eq!((proposal.seq, proposal.epoch), (2, 1));
    }
    bob1.nothing_waiting().await;
}

/// Section 5: an external commit cannot carry the server's pending
/// removals; the server asks for them again, right after it in the
/// sequence, and the joining device gets them too.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn an_external_commit_brings_the_pending_removals_again() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, mut alice1, bob, bob1, dm) = group_of_two(&app).await;
    server_removes(&app, &dm, leaf(&bob, &bob1.device)).await;
    let ServerPayload::ProposalEvent(event) = alice1.event().await else {
        panic!("expected the server's removal");
    };
    assert!(matches!(
        alice1.process(&dm, &event.message.unwrap().mls_message),
        Incoming::Proposal
    ));
    let alice2 = app.enrol(&alice).await;
    let mut alice2 = Member::connect(&app, alice2).await;

    let answer = alice2
        .request(ClientPayload::FetchGroupInfo(proto::FetchGroupInfo {
            conversation_id: dm.conversation.as_bytes().to_vec(),
        }))
        .await;
    let ServerPayload::GroupInfo(info) = answer else {
        panic!("{answer:?}");
    };
    assert_eq!(info.epoch, 1);
    let (group, commit, _) = Group::join_by_external_commit(
        &alice2.device.provider,
        &DeviceSigner::new(&alice2.device.key),
        for_device(&alice2.device.certificate, &alice2.device.key.public()),
        &info.mls_group_info,
        &dm.expected(),
        &dm.keys,
        &dm.external_sender,
    )
    .unwrap();
    alice2.group = Some(group);
    let id = alice2.submit(&dm, 1, commit, true).await;
    let ack = alice2.answer(id).await;
    assert_eq!((commit_ack(&ack).seq, commit_ack(&ack).new_epoch), (3, 2));
    alice2.merge();

    let ServerPayload::ProposalEvent(event) = alice2.event().await else {
        panic!("expected the removal asked again");
    };
    let proposal = event.message.unwrap();
    assert_eq!((proposal.seq, proposal.epoch), (4, 2));
    assert!(proposal.sender_device_id.is_empty(), "the server's");
    assert!(matches!(
        alice2.process(&dm, &proposal.mls_message),
        Incoming::Proposal
    ));
    let ServerPayload::CommitEvent(event) = alice1.event().await else {
        panic!("expected the external commit");
    };
    assert!(matches!(
        alice1.process(&dm, &event.message.unwrap().mls_message),
        Incoming::Commit { .. }
    ));
    let ServerPayload::ProposalEvent(event) = alice1.event().await else {
        panic!("expected the removal asked again");
    };
    assert!(matches!(
        alice1.process(&dm, &event.message.unwrap().mls_message),
        Incoming::Proposal
    ));
    assert_eq!(
        sequence(&app, dm.conversation).await,
        [(1, 2), (2, 3), (3, 2), (4, 3)]
    );
    assert_eq!(
        routed(&app, dm.conversation).await,
        in_tree(&app, &dm).await
    );
    assert_eq!(routed(&app, dm.conversation).await.len(), 3);
    // The removal moved to its proposal of the new epoch.
    assert_eq!(
        pending_removals(&app, dm.conversation).await,
        [(bob1.device.device_id, 4)]
    );
}

/// Section 16 and ADR 0020: a read-only DM takes no message and no new
/// leaf, while removals and updates go through. The blocked user is
/// answered exactly what an unfriended one is; only the blocker learns
/// BLOCKED; and no event tells the blocker anything of what was refused.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_read_only_dm_takes_nothing_new_and_never_discloses_a_block() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let alice2 = app.enrol(&alice).await;
    let mut alice2 = Member::connect(&app, alice2).await;
    // Read while they were friends: an external commit is tried below.
    let answer = alice2.request(group_info_request(&dm)).await;
    let ServerPayload::GroupInfo(info) = answer else {
        panic!("{answer:?}");
    };
    let status = app
        .status::<()>(
            Method::PUT,
            &format!("/v1/blocks/{}", alice.user_id),
            Some(&bob1.device.session_token),
            None,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::NO_CONTENT);

    let message = alice1.encrypt(b"refused");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    let while_blocked = error_text(&alice1.answer(id).await);
    assert_eq!(while_blocked.0, proto::ErrorCode::NotFriends);
    let message = bob1.encrypt(b"refused too");
    let id = bob1.send_message(&dm, Uuid::new_v4(), message).await;
    assert_eq!(code(&bob1.answer(id).await), proto::ErrorCode::Blocked);

    // The GroupInfo: refused, the same way; its tree would tell Alice of
    // every change of Bob's devices.
    assert_eq!(
        error_text(&alice2.request(group_info_request(&dm)).await),
        while_blocked,
        "the same answer"
    );
    assert_eq!(
        code(&bob1.request(group_info_request(&dm)).await),
        proto::ErrorCode::Blocked
    );

    // A new leaf: refused, the same way.
    let (_, commit, _) = Group::join_by_external_commit(
        &alice2.device.provider,
        &DeviceSigner::new(&alice2.device.key),
        for_device(&alice2.device.certificate, &alice2.device.key.public()),
        &info.mls_group_info,
        &dm.expected(),
        &dm.keys,
        &dm.external_sender,
    )
    .unwrap();
    let id = alice2.submit(&dm, 1, commit, true).await;
    assert_eq!(
        error_text(&alice2.answer(id).await),
        while_blocked,
        "the same answer"
    );

    // An update of one's own leaf goes through.
    let commit = alice1.self_update(&dm);
    let id = alice1.submit(&dm, 1, commit, false).await;
    assert_eq!(commit_ack(&alice1.answer(id).await).new_epoch, 2);
    alice1.merge();

    // Unblocked, still not friends: what Alice is told has not changed.
    let status = app
        .status::<()>(
            Method::DELETE,
            &format!("/v1/blocks/{}", alice.user_id),
            Some(&bob1.device.session_token),
            None,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::NO_CONTENT);
    let message = alice1.encrypt(b"still refused");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    assert_eq!(error_text(&alice1.answer(id).await), while_blocked);
    // Ex-friends, neither blocking: NOT_FRIENDS for both.
    assert_eq!(
        error_text(&alice2.request(group_info_request(&dm)).await),
        while_blocked
    );
    assert_eq!(
        error_text(&bob1.request(group_info_request(&dm)).await),
        while_blocked
    );

    // Bob's device saw the update, and nothing of what was refused.
    let ServerPayload::CommitEvent(event) = bob1.event().await else {
        panic!("expected Alice's update");
    };
    assert!(matches!(
        bob1.process(&dm, &event.message.unwrap().mls_message),
        Incoming::Commit { .. }
    ));
    bob1.nothing_waiting().await;
    assert_eq!(
        sequence(&app, dm.conversation).await,
        [(1, 2), (2, 2)],
        "nothing refused was stored"
    );
}

/// The maintainer's requirement for task 8: the server alone decides who
/// receives what, from the tree it merged. A commit that adds one of Bob's
/// devices sends the Welcome to that device only: not to another of Bob's
/// devices whose package Alice also claimed.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_server_alone_decides_who_receives_a_welcome() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, bob, _bob1, dm) = group_of_two(&app).await;
    let bob2 = app.enrol(&bob).await;
    let bob3 = app.enrol(&bob).await;
    upload(&app, &bob2, 3).await;
    upload(&app, &bob3, 3).await;
    let claimed = claim(&app, &alice1.device, &bob, &dm.keys).await;
    let for_bob2: Vec<ClaimedKeyPackage> = claimed
        .into_iter()
        .filter(|package| {
            package.device().map(|device| device.device_id) == Some(*bob2.device_id.as_bytes())
        })
        .collect();
    assert_eq!(for_bob2.len(), 1);
    let mut bob2 = Member::connect(&app, bob2).await;
    let mut bob3 = Member::connect(&app, bob3).await;

    let commit = {
        let Member { group, device, .. } = &mut alice1;
        group
            .as_mut()
            .unwrap()
            .add(
                &device.provider,
                &DeviceSigner::new(&device.key),
                &for_bob2,
                &dm.keys,
            )
            .unwrap()
    };
    let id = alice1.submit(&dm, 1, commit, false).await;
    assert_eq!(commit_ack(&alice1.answer(id).await).new_epoch, 2);
    alice1.merge();
    bob2.join(&dm).await;
    bob3.nothing_waiting().await;
    let routed_now = routed(&app, dm.conversation).await;
    assert_eq!(routed_now, in_tree(&app, &dm).await);
    assert!(!routed_now.contains(&bob3.device.device_id));
}

/// A device reads the sequence from its join to the commit that removed
/// it, in pages; a device still in the group reads on.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_device_reads_from_its_join_to_its_removal_in_pages() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, alice1) = app.account_with_device("sq", false).await;
    let bob = app.register("sq", false).await;
    let dm = dm_between(&app, (&alice, &alice1), &bob).await;
    let alice2 = app.enrol(&alice).await;
    let bob1 = app.enrol(&bob).await;
    upload(&app, &alice2, 3).await;
    upload(&app, &bob1, 3).await;
    let mut claimed = claim(&app, &alice1, &alice, &dm.keys).await;
    claimed.extend(claim(&app, &alice1, &bob, &dm.keys).await);
    let alice2_leaf = leaf(&alice, &alice2);
    let mut alice1 = Member::connect(&app, alice1).await;
    let mut alice2 = Member::connect(&app, alice2).await;
    let mut bob1 = Member::connect(&app, bob1).await;
    let commit = alice1.create(&dm, &claimed);
    let id = alice1.submit(&dm, 0, commit, false).await;
    commit_ack(&alice1.answer(id).await);
    alice1.merge();
    alice2.join(&dm).await;
    bob1.join(&dm).await;

    for text in [b"two".as_slice(), b"three", b"four"] {
        let message = alice1.encrypt(text);
        let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
        message_ack(&alice1.answer(id).await);
    }
    let commit = {
        let Member { group, device, .. } = &mut alice1;
        let group = group.as_mut().unwrap();
        let removed = group
            .leaf_of(&alice2_leaf.user_id, &alice2_leaf.device_id)
            .unwrap();
        group
            .remove(
                &device.provider,
                &DeviceSigner::new(&device.key),
                &[removed],
                &dm.keys,
            )
            .unwrap()
    };
    let id = alice1.submit(&dm, 1, commit, false).await;
    assert_eq!(commit_ack(&alice1.answer(id).await).seq, 5);
    alice1.merge();
    let message = alice1.encrypt(b"six");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    assert_eq!(message_ack(&alice1.answer(id).await).seq, 6);

    let seqs = |batch: &proto::MessageBatch| -> Vec<u64> {
        batch.messages.iter().map(|message| message.seq).collect()
    };
    let page = alice2.fetch(&dm, 0, 2).await;
    assert_eq!((seqs(&page), page.more), (vec![2, 3], true));
    let page = alice2.fetch(&dm, 3, 0).await;
    assert_eq!(
        (seqs(&page), page.more),
        (vec![4, 5], false),
        "up to the commit that removed it"
    );
    let page = bob1.fetch(&dm, 0, 0).await;
    assert_eq!(seqs(&page), [2, 3, 4, 5, 6]);
    assert_eq!(
        routed(&app, dm.conversation).await,
        in_tree(&app, &dm).await
    );
}

/// `protocol.md`, section 7: 30 requests per 10 seconds, bursts of 60;
/// beyond, RATE_LIMITED, and a connection that keeps exceeding is closed
/// (4007).
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn requests_beyond_the_limit_are_refused_then_the_connection_closed() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("sq", false).await;
    let (mut socket, _) = connect(&app, &device).await;
    for id in 2..=100 {
        send(
            &mut socket,
            id,
            ClientPayload::Heartbeat(proto::Heartbeat {}),
        )
        .await;
    }
    let (mut answered, mut limited) = (0, 0);
    let closed = loop {
        match receive(&mut socket).await {
            Received::Frame(frame) => match frame.payload {
                Some(ServerPayload::HeartbeatAck(_)) => answered += 1,
                Some(ServerPayload::Error(error)) => {
                    assert_eq!(error.code(), proto::ErrorCode::RateLimited);
                    assert!(error.retry_after_ms > 0);
                    limited += 1;
                }
                other => panic!("{other:?}"),
            },
            Received::Closed(code) => break code,
        }
    };
    assert!(answered >= GATEWAY_REQUEST_BURST, "{answered}");
    assert!(limited >= 1);
    assert_eq!(closed, Some(close_code::RATE_LIMITED));
}

/// Requests from outside the conversation, and malformed ones.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn requests_from_outside_or_malformed_are_refused() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, _bob1, dm) = group_of_two(&app).await;
    let (_, carol1) = app.account_with_device("sq", false).await;
    let mut carol1 = Member::connect(&app, carol1).await;
    let conversation = dm.conversation.as_bytes().to_vec();

    for conversation in [conversation.clone(), Uuid::new_v4().as_bytes().to_vec()] {
        let requests = [
            ClientPayload::SendMessage(proto::SendMessage {
                conversation_id: conversation.clone(),
                client_message_id: Uuid::new_v4().as_bytes().to_vec(),
                mls_message: alice1.encrypt(b"not hers"),
            }),
            ClientPayload::FetchMessages(proto::FetchMessages {
                conversation_id: conversation.clone(),
                after_seq: 0,
                limit: 0,
            }),
            ClientPayload::FetchGroupInfo(proto::FetchGroupInfo {
                conversation_id: conversation.clone(),
            }),
            ClientPayload::SubmitCommit(proto::SubmitCommit {
                conversation_id: conversation.clone(),
                epoch: 1,
                mls_commit: vec![1],
                mls_welcome: vec![],
                mls_group_info: vec![1],
                external: true,
            }),
        ];
        for request in requests {
            let answer = carol1.request(request).await;
            assert_eq!(code(&answer), proto::ErrorCode::NotAMember);
        }
    }

    let commit = alice1.self_update(&dm);
    let without_info = proto::SubmitCommit {
        conversation_id: conversation.clone(),
        epoch: 1,
        mls_commit: commit.commit.clone(),
        mls_welcome: vec![],
        mls_group_info: vec![],
        external: false,
    };
    let answer = alice1
        .request(ClientPayload::SubmitCommit(without_info))
        .await;
    assert_eq!(code(&answer), proto::ErrorCode::GroupInfoRequired);
    let too_large = proto::SubmitCommit {
        conversation_id: conversation.clone(),
        epoch: 1,
        mls_commit: vec![0; tavern_protocol::MAX_COMMIT_BYTES + 1],
        mls_welcome: vec![],
        mls_group_info: commit.group_info,
        external: false,
    };
    let answer = alice1.request(ClientPayload::SubmitCommit(too_large)).await;
    assert_eq!(code(&answer), proto::ErrorCode::PayloadTooLarge);
    // Not an application message: garbage, or a commit.
    for not_application in [b"garbage".to_vec(), commit.commit] {
        let id = alice1
            .send_message(&dm, Uuid::new_v4(), not_application)
            .await;
        assert_eq!(
            code(&alice1.answer(id).await),
            proto::ErrorCode::InvalidArgument
        );
    }
}

/// Section 8: the largest content, 64 KiB padded, goes through and is read;
/// the client refuses a larger one, and the server any application message
/// beyond its limit, before reading it.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_largest_message_goes_through_and_one_byte_more_does_not() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let largest = vec![0x61; padding::MAX_CONTENT];
    let message = alice1.encrypt(&largest);
    assert!(message.len() > padding::BUCKETS[padding::BUCKETS.len() - 1]);
    assert!(message.len() <= MAX_APPLICATION_MESSAGE_BYTES);
    let id = alice1
        .send_message(&dm, Uuid::new_v4(), message.clone())
        .await;
    let ack = message_ack(&alice1.answer(id).await);
    assert_eq!(bob1.receive_text(&dm).await, (ack.seq, largest));

    let too_long = {
        let Member { group, device, .. } = &mut alice1;
        group.as_mut().unwrap().encrypt(
            &device.provider,
            &DeviceSigner::new(&device.key),
            &vec![0x61; padding::MAX_CONTENT + 1],
        )
    };
    assert!(too_long.is_err(), "beyond the largest bucket");

    let mut over = message;
    over.resize(MAX_APPLICATION_MESSAGE_BYTES + 1, 0);
    let id = alice1.send_message(&dm, Uuid::new_v4(), over.clone()).await;
    assert_eq!(
        code(&alice1.answer(id).await),
        proto::ErrorCode::PayloadTooLarge
    );
    // At the limit, the size passes; what follows the message does not.
    over.truncate(MAX_APPLICATION_MESSAGE_BYTES);
    let id = alice1.send_message(&dm, Uuid::new_v4(), over).await;
    assert_eq!(
        code(&alice1.answer(id).await),
        proto::ErrorCode::InvalidArgument
    );
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2), (2, 1)]);
}

/// `protocol.md`, section 3: events are notifications. A device that does
/// not keep up (its connection busy here, while more events than its queue
/// holds arrive) is closed with 4009 once its queue is sent, instead of
/// losing an event in silence; reconnected, it fetches what it missed.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_device_that_falls_behind_is_closed_and_misses_nothing() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let (held, holder) = hold_cursor(&app, dm.conversation, bob1.device.device_id).await;
    let ack_id = bob1
        .send_request(ClientPayload::AckMessages(proto::AckMessages {
            conversation_id: dm.conversation.as_bytes().to_vec(),
            up_to_seq: 1,
        }))
        .await;
    waiting_for(&app, holder, 1).await;

    let texts: Vec<Vec<u8>> = (0..=EVENT_QUEUE_LEN)
        .map(|i| format!("message {i}").into_bytes())
        .collect();
    for text in &texts {
        let message = alice1.encrypt(text);
        let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
        message_ack(&alice1.answer(id).await);
    }
    held.commit().await.unwrap();

    let mut pushed = Vec::new();
    let closed = loop {
        match receive(&mut bob1.socket).await {
            Received::Frame(frame) => match frame.payload.unwrap() {
                ServerPayload::Ack(_) => assert_eq!(frame.request_id, ack_id),
                ServerPayload::MessageEvent(event) => pushed.push(event.message.unwrap()),
                other if bob1.seen(&other) => {}
                other => panic!("{other:?}"),
            },
            Received::Closed(code) => break code,
        }
    };
    assert_eq!(closed, Some(close_code::EVENT_QUEUE_FULL));
    let seqs: Vec<u64> = pushed.iter().map(|message| message.seq).collect();
    let pushed_count = u64::try_from(EVENT_QUEUE_LEN).unwrap();
    assert_eq!(seqs, (2..2 + pushed_count).collect::<Vec<u64>>());

    let Member { device, group, .. } = bob1;
    let mut bob1 = Member::connect(&app, device).await;
    bob1.group = group;
    let mut read = Vec::new();
    for message in &pushed {
        match bob1.process(&dm, &message.mls_message) {
            Incoming::Application { content, .. } => read.push(content.expose().to_vec()),
            other => panic!("{other:?}"),
        }
    }
    let missed = bob1.fetch(&dm, *seqs.last().unwrap(), 0).await;
    assert_eq!(missed.messages.len(), 1);
    match bob1.process(&dm, &missed.messages[0].mls_message) {
        Incoming::Application { content, .. } => read.push(content.expose().to_vec()),
        other => panic!("{other:?}"),
    }
    assert_eq!(read, texts, "nothing lost");
}

/// `protocol.md`, section 3: events may arrive out of order (each request
/// notifies after its own transaction). A device processes the sequence in
/// the order of its numbers: given N+2 without N+1, it puts N+2 aside and
/// fetches the gap. Here a commit and a message of its new epoch arrive the
/// other way round.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn events_out_of_order_are_read_in_the_order_of_the_sequence() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let commit = alice1.self_update(&dm);
    let id = alice1.submit(&dm, 1, commit, false).await;
    assert_eq!(commit_ack(&alice1.answer(id).await).seq, 2);
    alice1.merge();
    let message = alice1.encrypt(b"after the commit");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    assert_eq!(message_ack(&alice1.answer(id).await).seq, 3);
    let ServerPayload::CommitEvent(commit_event) = bob1.event().await else {
        panic!("expected the commit");
    };
    let ServerPayload::MessageEvent(message_event) = bob1.event().await else {
        panic!("expected the message");
    };
    let (first_seen, second_seen) = (
        message_event.message.unwrap(),
        commit_event.message.unwrap(),
    );

    // Processed as it comes, the message cannot be read: it is of an epoch
    // the device has not reached.
    {
        let Member { group, device, .. } = &mut bob1;
        let early =
            group
                .as_mut()
                .unwrap()
                .process(&device.provider, &first_seen.mls_message, &dm.keys);
        assert!(early.is_err());
    }
    // The contract: the device has read up to 1, so 3 waits, and the gap is
    // fetched; the sequence comes back in order.
    let read = 1;
    assert!(first_seen.seq > read + 1);
    let gap = bob1.fetch(&dm, read, 0).await;
    let seqs: Vec<u64> = gap.messages.iter().map(|message| message.seq).collect();
    assert_eq!(seqs, [2, 3]);
    assert_eq!(gap.messages[0], second_seen);
    assert!(matches!(
        bob1.process(&dm, &gap.messages[0].mls_message),
        Incoming::Commit { .. }
    ));
    match bob1.process(&dm, &first_seen.mls_message) {
        Incoming::Application { content, .. } => assert_eq!(content.expose(), b"after the commit"),
        other => panic!("{other:?}"),
    }
}

/// `protocol.md`, section 7: the limit on requests is the device's, across
/// its connections, so that reconnecting gives no new budget; and a device
/// may say `Hello` 10 times a minute.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn reconnecting_gives_no_new_budget_and_hellos_are_limited() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("sq", false).await;
    let (mut socket, _) = connect(&app, &device).await;
    let burst = u64::from(GATEWAY_REQUEST_BURST);
    for id in 2..2 + burst {
        send(
            &mut socket,
            id,
            ClientPayload::Heartbeat(proto::Heartbeat {}),
        )
        .await;
    }
    let mut answered = 0;
    while answered < burst {
        let frame = expect_frame(&mut socket).await;
        assert!(
            matches!(frame.payload, Some(ServerPayload::HeartbeatAck(_))),
            "{frame:?}"
        );
        answered += 1;
    }
    drop(socket);

    let (mut socket, _) = connect(&app, &device).await;
    for id in 2..5 {
        send(
            &mut socket,
            id,
            ClientPayload::Heartbeat(proto::Heartbeat {}),
        )
        .await;
    }
    let mut limited = 0;
    for _ in 2..5 {
        if let Some(ServerPayload::Error(error)) = expect_frame(&mut socket).await.payload {
            assert_eq!(error.code(), proto::ErrorCode::RateLimited);
            limited += 1;
        }
    }
    assert!(limited >= 1, "the new connection has no new budget");
    drop(socket);

    // Two Hellos so far: the next ones are answered up to the limit (one
    // more, if the minute's budget grew meanwhile), then refused.
    let mut hellos = 2;
    let refused = loop {
        let mut socket = open(&app, Some(GATEWAY_SUBPROTOCOL)).await.unwrap();
        send(&mut socket, 1, hello(&device.session_token)).await;
        let frame = expect_frame(&mut socket).await;
        match frame.payload {
            Some(ServerPayload::Ready(_)) => hellos += 1,
            Some(ServerPayload::Error(error)) => {
                assert_eq!(frame.request_id, 1);
                break (error, expect_close(&mut socket).await);
            }
            other => panic!("{other:?}"),
        }
        assert!(hellos <= GATEWAY_HELLOS_PER_MINUTE + 1, "never refused");
    };
    assert!(hellos >= GATEWAY_HELLOS_PER_MINUTE, "{hellos}");
    assert_eq!(refused.0.code(), proto::ErrorCode::RateLimited);
    assert!(refused.0.retry_after_ms > 0);
    assert_eq!(refused.1, Some(close_code::RATE_LIMITED));
}

/// A second DM of Alice's first device, with Carol, and its group (Carol's
/// device joins later, if ever): the group as Alice's device keeps it.
async fn second_dm(app: &TestApp, alice: &Account, alice1: &Member) -> (Dm, Group) {
    let carol = app.register("sq", false).await;
    let dm = dm_between(app, (alice, &alice1.device), &carol).await;
    let carol1 = app.enrol(&carol).await;
    upload(app, &carol1, 3).await;
    let claimed = claim(app, &alice1.device, &carol, &dm.keys).await;
    let device = &alice1.device;
    let (mut group, commit) = Group::create(
        &device.provider,
        &DeviceSigner::new(&device.key),
        for_device(&device.certificate, &device.key.public()),
        &dm.expected(),
        &dm.external_sender,
        &claimed,
        &dm.keys,
    )
    .unwrap();
    let acked = delivery::submit_commit(
        &app.state,
        &session(alice, device),
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
    .unwrap();
    assert_eq!(acked.seq, 1);
    group.merge_pending_commit(&device.provider).unwrap();
    (dm, group)
}

/// Section 7: one `client_message_id` sent at once in two conversations,
/// under two locks. The second request waits for the first's record, then
/// gets INVALID_ARGUMENT, as when they come one after the other: never
/// INTERNAL. It took a number, and gives it back.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn one_client_message_id_at_once_in_two_conversations() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let (other_dm, mut other_group) = second_dm(&app, &alice, &alice1).await;
    let in_first = alice1.encrypt(b"first");
    let in_other = other_group
        .encrypt(
            &alice1.device.provider,
            &DeviceSigner::new(&alice1.device.key),
            b"other",
        )
        .unwrap();
    let id = Uuid::new_v4();

    // The first request records the id, then waits for this gate before it
    // commits.
    let mut gate = app.state.db.begin().await.unwrap();
    let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let key: i64 = rand_key();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *gate)
        .await
        .unwrap();
    let trigger = Trigger::install(
        &app,
        "sent_messages",
        dm.conversation,
        &format!("PERFORM pg_advisory_xact_lock({key});"),
    )
    .await;
    let send = |conversation: Uuid, message: Vec<u8>| {
        let (state, session) = (app.state.clone(), session(&alice, &alice1.device));
        tokio::spawn(async move {
            delivery::send_message(
                &state,
                &session,
                proto::SendMessage {
                    conversation_id: conversation.as_bytes().to_vec(),
                    client_message_id: id.as_bytes().to_vec(),
                    mls_message: message,
                },
            )
            .await
        })
    };
    let first = send(dm.conversation, in_first);
    waiting_for(&app, gate_pid, 1).await;
    let second = send(other_dm.conversation, in_other);
    waiting_for(&app, gate_pid, 2).await;
    gate.commit().await.unwrap();

    let first = first.await.unwrap().unwrap();
    assert_eq!(first.seq, 2);
    let refused = second.await.unwrap().unwrap_err();
    assert_eq!(
        (refused.code, refused.message),
        (
            proto::ErrorCode::InvalidArgument,
            "this client message id was used elsewhere"
        )
    );
    assert_eq!(sequence(&app, other_dm.conversation).await, [(1, 2)]);
    assert_eq!(last_seq(&app, other_dm.conversation).await, 1, "given back");
    assert_eq!(bob1.receive_text(&dm).await, (2, b"first".to_vec()));
    trigger.remove(&app).await;
}

fn rand_key() -> i64 {
    i64::from_be_bytes(Uuid::new_v4().as_bytes()[..8].try_into().unwrap())
}

/// Section 7: the same message sent twice at once (a device that resends
/// while its first try is still in flight): both wait for the conversation;
/// one stores it, the other gets its acknowledgement; delivered once.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_message_sent_twice_at_once_is_stored_once() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, mut alice1, _, mut bob1, dm) = group_of_two(&app).await;
    let request = proto::SendMessage {
        conversation_id: dm.conversation.as_bytes().to_vec(),
        client_message_id: Uuid::new_v4().as_bytes().to_vec(),
        mls_message: alice1.encrypt(b"twice"),
    };
    let (held, holder) = hold(&app, dm.conversation).await;
    let tries: Vec<_> = (0..2)
        .map(|_| {
            let (state, session) = (app.state.clone(), session(&alice, &alice1.device));
            let request = request.clone();
            tokio::spawn(async move { delivery::send_message(&state, &session, request).await })
        })
        .collect();
    waiting_for(&app, holder, 2).await;
    held.commit().await.unwrap();
    let mut acks = Vec::new();
    for task in tries {
        acks.push(task.await.unwrap().unwrap());
    }
    assert_eq!(acks[0], acks[1], "one acknowledgement");
    assert_eq!(acks[0].seq, 2);
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2), (2, 1)]);
    assert_eq!(bob1.receive_text(&dm).await, (2, b"twice".to_vec()));
    bob1.nothing_waiting().await;
}

/// The maintainer's requirement for task 8, on real requests: one that
/// fails after it took its number (here a write that follows it fails)
/// takes it back with everything else, and the next one gets it.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_request_that_fails_after_taking_a_number_gives_it_back() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, bob, mut bob1, dm) = group_of_two(&app).await;

    // A message: its idempotency record cannot be written.
    let trigger = Trigger::install(
        &app,
        "sent_messages",
        dm.conversation,
        "RAISE EXCEPTION 'injected failure';",
    )
    .await;
    let id = Uuid::new_v4();
    let message = alice1.encrypt(b"after a failure");
    let request = alice1.send_message(&dm, id, message.clone()).await;
    assert_eq!(
        code(&alice1.answer(request).await),
        proto::ErrorCode::Internal
    );
    assert_eq!(last_seq(&app, dm.conversation).await, 1);
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2)]);
    trigger.remove(&app).await;
    let request = alice1.send_message(&dm, id, message).await;
    assert_eq!(message_ack(&alice1.answer(request).await).seq, 2);
    assert_eq!(
        bob1.receive_text(&dm).await,
        (2, b"after a failure".to_vec())
    );
    bob1.nothing_waiting().await;

    // A commit adding a device: its Welcome cannot be written.
    let bob2 = app.enrol(&bob).await;
    upload(&app, &bob2, 3).await;
    let for_bob2: Vec<ClaimedKeyPackage> = claim(&app, &alice1.device, &bob, &dm.keys)
        .await
        .into_iter()
        .filter(|package| {
            package.device().map(|device| device.device_id) == Some(*bob2.device_id.as_bytes())
        })
        .collect();
    let mut bob2 = Member::connect(&app, bob2).await;
    let commit = add(&mut alice1, &dm, &for_bob2);
    let routed_before = routed(&app, dm.conversation).await;
    let trigger = Trigger::install(
        &app,
        "welcomes",
        dm.conversation,
        "RAISE EXCEPTION 'injected failure';",
    )
    .await;
    let request = alice1.submit(&dm, 1, commit.clone(), false).await;
    assert_eq!(
        code(&alice1.answer(request).await),
        proto::ErrorCode::Internal
    );
    assert_eq!(last_seq(&app, dm.conversation).await, 2);
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2), (2, 1)]);
    assert_eq!(group_epoch(&app, dm.conversation).await, Some(1));
    assert_eq!(routed(&app, dm.conversation).await, routed_before);
    assert_eq!(
        welcomes_of(&app, dm.conversation).await.len(),
        1,
        "Bob's first"
    );
    bob1.nothing_waiting().await;
    bob2.nothing_waiting().await;
    trigger.remove(&app).await;
    let request = alice1.submit(&dm, 1, commit, false).await;
    let ack = alice1.answer(request).await;
    assert_eq!((commit_ack(&ack).seq, commit_ack(&ack).new_epoch), (3, 2));
    alice1.merge();
    bob2.join(&dm).await;
    let ServerPayload::CommitEvent(event) = bob1.event().await else {
        panic!("expected the commit");
    };
    assert_eq!(event.message.unwrap().seq, 3);
}

/// Alice's device adds `packages` to its group: the commit, not merged.
fn add(alice1: &mut Member, dm: &Dm, packages: &[ClaimedKeyPackage]) -> Commit {
    let Member { group, device, .. } = alice1;
    group
        .as_mut()
        .unwrap()
        .add(
            &device.provider,
            &DeviceSigner::new(&device.key),
            packages,
            &dm.keys,
        )
        .unwrap()
}

/// Section 4: what the server checks of a group's first commit, which it
/// cannot process: a commit of this group at epoch 0, by the submitter,
/// whose Welcome is for exactly the KeyPackages its tree shows added.
/// Nothing refused is stored.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_first_commit_is_checked_for_what_can_be_checked() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, mut alice1, _, _bob1, first_dm) = group_of_two(&app).await;
    let carol = app.register("sq", false).await;
    let dm = dm_between(&app, (&alice, &alice1.device), &carol).await;
    let carol1 = app.enrol(&carol).await;
    upload(&app, &carol1, 3).await;
    let claimed = claim(&app, &alice1.device, &carol, &dm.keys).await;
    let other_package = claim(&app, &alice1.device, &carol, &dm.keys).await;
    let create = |packages: &[ClaimedKeyPackage], provider: &Provider<MemoryStorage>| {
        let device = &alice1.device;
        Group::create(
            provider,
            &DeviceSigner::new(&device.key),
            for_device(&device.certificate, &device.key.public()),
            &dm.expected(),
            &dm.external_sender,
            packages,
            &dm.keys,
        )
        .unwrap()
        .1
    };
    let commit = create(&claimed, &alice1.device.provider);
    // The same group created with Carol's other package, elsewhere.
    let other = create(&other_package, &Provider::new(MemoryStorage::default()));
    let welcome = commit.welcome.clone().unwrap();
    let of_the_first_dm = alice1.self_update(&first_dm).commit;
    alice1.discard();

    let alice_session = session(&alice, &alice1.device);
    let submit = |mls_commit: Vec<u8>, mls_welcome: Vec<u8>| {
        delivery::submit_commit(
            &app.state,
            &alice_session,
            proto::SubmitCommit {
                conversation_id: dm.conversation.as_bytes().to_vec(),
                epoch: 0,
                mls_commit,
                mls_welcome,
                mls_group_info: commit.group_info.clone(),
                external: false,
            },
        )
    };
    let refused = [
        (b"garbage".to_vec(), welcome.clone()),
        (welcome.clone(), welcome.clone()),
        (of_the_first_dm, welcome.clone()),
        (forge_sender(&commit.commit, 1), welcome.clone()),
        (commit.commit.clone(), Vec::new()),
        (commit.commit.clone(), other.welcome.clone().unwrap()),
        (commit.commit.clone(), commit.group_info.clone()),
    ];
    for (case, (mls_commit, mls_welcome)) in refused.into_iter().enumerate() {
        let answer = submit(mls_commit, mls_welcome).await;
        assert_eq!(
            answer.map_err(|refused| refused.code),
            Err(proto::ErrorCode::InvalidCommit),
            "case {case}"
        );
    }
    assert_eq!(group_epoch(&app, dm.conversation).await, None);
    assert!(sequence(&app, dm.conversation).await.is_empty());
    assert!(welcomes_of(&app, dm.conversation).await.is_empty());
    assert!(routed(&app, dm.conversation).await.is_empty());

    let acked = submit(commit.commit.clone(), welcome).await.unwrap();
    assert_eq!((acked.seq, acked.new_epoch), (1, 1));
    let welcomed: Vec<Uuid> = welcomes_of(&app, dm.conversation)
        .await
        .into_iter()
        .map(|(_, device)| device)
        .collect();
    assert_eq!(welcomed, [carol1.device_id]);
}

/// `commit` (an MLS `PublicMessage`) claiming to be from leaf `index`: its
/// signature no longer matches, which the server cannot check for a first
/// commit, but its framing still does. RFC 9420: version and wire format
/// (2 bytes each), the group id (a one-byte length here, then its bytes),
/// the epoch (8 bytes), the sender's type (1 byte) and leaf index (4 bytes).
fn forge_sender(commit: &[u8], index: u32) -> Vec<u8> {
    let length = usize::from(commit[4]);
    assert!(length < 0x40, "a one-byte length");
    let at = 4 + 1 + length + 8;
    assert_eq!(commit[at], 1, "a member sender");
    let mut forged = commit.to_vec();
    forged[at + 1..at + 5].copy_from_slice(&index.to_be_bytes());
    forged
}

/// Sections 4 and 7: a member's commit is refused when its Welcome is not
/// for exactly the KeyPackages it adds (none, or another's), when it comes
/// with a Welcome and adds no one, and when it is for an epoch the group
/// has not reached. Nothing refused is stored.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_member_commit_whose_welcome_or_epoch_does_not_fit_is_refused() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, bob, mut bob1, dm) = group_of_two(&app).await;
    let bob2 = app.enrol(&bob).await;
    let bob3 = app.enrol(&bob).await;
    upload(&app, &bob2, 3).await;
    upload(&app, &bob3, 3).await;
    let claimed = claim(&app, &alice1.device, &bob, &dm.keys).await;
    let of = |device: &Device| -> Vec<ClaimedKeyPackage> {
        claimed
            .iter()
            .filter(|package| {
                package.device().map(|leaf| leaf.device_id) == Some(*device.device_id.as_bytes())
            })
            .cloned()
            .collect()
    };
    let (for_bob2, for_bob3) = (of(&bob2), of(&bob3));
    let welcome_for_bob3 = add(&mut alice1, &dm, &for_bob3).welcome.unwrap();
    alice1.discard();
    let adding_bob2 = add(&mut alice1, &dm, &for_bob2);

    let mut refused = Vec::new();
    for welcome in [Vec::new(), welcome_for_bob3] {
        let id = alice1
            .submit(
                &dm,
                1,
                Commit {
                    welcome: Some(welcome),
                    ..adding_bob2.clone()
                },
                false,
            )
            .await;
        refused.push(alice1.answer(id).await);
    }
    alice1.discard();
    let update = alice1.self_update(&dm);
    let id = alice1
        .submit(
            &dm,
            1,
            Commit {
                welcome: Some(adding_bob2.welcome.clone().unwrap()),
                ..update.clone()
            },
            false,
        )
        .await;
    refused.push(alice1.answer(id).await);
    // Announced for the next epoch, then built for it.
    let id = alice1.submit(&dm, 2, update, false).await;
    refused.push(alice1.answer(id).await);
    alice1.merge();
    let ahead = alice1.self_update(&dm);
    let id = alice1.submit(&dm, 2, ahead.clone(), false).await;
    refused.push(alice1.answer(id).await);
    let id = alice1.submit(&dm, 1, ahead, false).await;
    refused.push(alice1.answer(id).await);

    for answer in &refused {
        assert_eq!(code(answer), proto::ErrorCode::InvalidCommit, "{answer:?}");
    }
    assert_eq!(group_epoch(&app, dm.conversation).await, Some(1));
    assert_eq!(sequence(&app, dm.conversation).await, [(1, 2)]);
    assert_eq!(welcomes_of(&app, dm.conversation).await.len(), 1);
    bob1.nothing_waiting().await;
}

/// A device's read position never moves past what it may read, nor back;
/// a device acknowledges its own Welcomes only.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn acknowledgements_stay_within_what_the_device_may_read() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, bob, mut bob1, dm) = group_of_two(&app).await;
    let message = alice1.encrypt(b"two");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    bob1.receive_text(&dm).await;
    let acked = |device: Uuid| {
        let db = app.state.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT acked_seq FROM conversation_devices \
                 WHERE conversation_id = $1 AND device_id = $2",
            )
            .bind(dm.conversation)
            .bind(device)
            .fetch_one(&db)
            .await
            .unwrap()
        }
    };
    for up_to_seq in [1_000, 1] {
        let answer = bob1
            .request(ClientPayload::AckMessages(proto::AckMessages {
                conversation_id: dm.conversation.as_bytes().to_vec(),
                up_to_seq,
            }))
            .await;
        assert!(matches!(answer, ServerPayload::Ack(_)), "{answer:?}");
        assert_eq!(acked(bob1.device.device_id).await, 2, "after {up_to_seq}");
    }
    let message = alice1.encrypt(b"three");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    message_ack(&alice1.answer(id).await);
    assert_eq!(bob1.receive_text(&dm).await, (3, b"three".to_vec()));
    let unread = bob1.fetch(&dm, 2, 0).await;
    assert_eq!(unread.messages.len(), 1, "still to acknowledge");

    // Another device's Welcome: not found, and left as it is.
    let bob2 = app.enrol(&bob).await;
    upload(&app, &bob2, 3).await;
    let for_bob2: Vec<ClaimedKeyPackage> = claim(&app, &alice1.device, &bob, &dm.keys)
        .await
        .into_iter()
        .filter(|package| {
            package.device().map(|device| device.device_id) == Some(*bob2.device_id.as_bytes())
        })
        .collect();
    let commit = add(&mut alice1, &dm, &for_bob2);
    let id = alice1.submit(&dm, 1, commit, false).await;
    commit_ack(&alice1.answer(id).await);
    alice1.merge();
    let (welcome_id, _) = welcomes_of(&app, dm.conversation)
        .await
        .into_iter()
        .find(|(_, device)| *device == bob2.device_id)
        .unwrap();
    let answer = bob1
        .request(ClientPayload::AckWelcome(proto::AckWelcome {
            welcome_id: welcome_id.as_bytes().to_vec(),
        }))
        .await;
    assert_eq!(code(&answer), proto::ErrorCode::NotFound);
    let still: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT (extract(epoch FROM acked_at))::bigint FROM welcomes WHERE id = $1",
    )
    .bind(welcome_id)
    .fetch_optional(&app.state.db)
    .await
    .unwrap();
    assert_eq!(still, Some(None));
    let mut bob2 = Member::connect(&app, bob2).await;
    bob2.join(&dm).await;
}

/// Section 4: a first commit may add a last-resort KeyPackage the server
/// served, even once its device replaced it: the server keeps its row, as
/// served and without its bytes, until it expires, and matches the Welcome
/// to it. A last resort never served is deleted when replaced.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_first_commit_may_add_a_last_resort_replaced_since() {
    let app = TestApp::spawn_unlimited().await;
    let (alice, alice1) = app.account_with_device("sq", false).await;
    let bob = app.register("sq", false).await;
    let dm = dm_between(&app, (&alice, &alice1), &bob).await;
    let bob1 = app.enrol(&bob).await;
    let first = bob1.key_package(true);
    upload_last_resort(&app, &bob1, first).await;
    let claimed = claim(&app, &alice1, &bob, &dm.keys).await;
    assert_eq!(claimed.len(), 1, "Bob's last resort, the only package");

    // Bob's device replaces it, then a never served one.
    upload_last_resort(&app, &bob1, bob1.key_package(true)).await;
    let rows = || async {
        let rows: Vec<(bool, bool, i32)> = sqlx::query_as(
            "SELECT last_resort, served_at IS NOT NULL, octet_length(key_package) \
             FROM key_packages WHERE device_id = $1 ORDER BY created_at, id",
        )
        .bind(bob1.device_id)
        .fetch_all(&app.state.db)
        .await
        .unwrap();
        rows
    };
    let kept = rows().await;
    assert_eq!(kept.len(), 2);
    assert_eq!((kept[0].0, kept[0].1, kept[0].2), (false, true, 0));
    assert!(kept[1].0 && !kept[1].1);
    upload_last_resort(&app, &bob1, bob1.key_package(true)).await;
    let kept = rows().await;
    assert_eq!(kept.len(), 2, "the replaced one never served is gone");
    assert_eq!((kept[0].0, kept[0].1), (false, true));

    let mut alice1 = Member::connect(&app, alice1).await;
    let mut bob1 = Member::connect(&app, bob1).await;
    let commit = alice1.create(&dm, &claimed);
    let id = alice1.submit(&dm, 0, commit, false).await;
    commit_ack(&alice1.answer(id).await);
    alice1.merge();
    bob1.join(&dm).await;
}
