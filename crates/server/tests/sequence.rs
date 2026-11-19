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

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use common::ws::{Received, Socket, connect, expect_frame, receive, send};
use common::{Account, Device, TestApp};
use reqwest::Method;
use tavern_crypto::identity::{ID_LEN, IdentityPublicKey};
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::{
    ClaimedKeyPackage, Commit, DeviceSigner, ExpectedGroup, Group, Incoming, Roster, ServerSigner,
    VerifiedLeaf, key_package,
};
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::client_frame::Payload as ClientPayload;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_protocol::rest::{
    Conversation, CreateDmRequest, KeyPackageClaim, KeyPackageCount, UploadKeyPackagesRequest,
};
use tavern_protocol::{GATEWAY_REQUEST_BURST, close_code};
use tavern_server::delivery::{self, Kind};
use tavern_server::mls;
use uuid::Uuid;

/// The identity keys the clients of these tests trust.
#[derive(Clone)]
struct Keys(HashMap<[u8; ID_LEN], IdentityPublicKey>);

impl Roster for Keys {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.0.get(user_id).copied()
    }
}

fn leaf(account: &Account, device: &Device) -> VerifiedLeaf {
    VerifiedLeaf {
        user_id: *account.user_id.as_bytes(),
        device_id: *device.device_id.as_bytes(),
    }
}

/// A DM between two friends, as its clients know it.
struct Dm {
    conversation: Uuid,
    participants: [[u8; ID_LEN]; 2],
    keys: Keys,
    external_sender: [u8; 32],
}

impl Dm {
    fn expected(&self) -> ExpectedGroup<'_> {
        ExpectedGroup {
            identity: self.identity(),
            participants: &self.participants,
        }
    }

    fn identity(&self) -> GroupIdentity {
        GroupIdentity {
            conversation_id: *self.conversation.as_bytes(),
            generation: 0,
        }
    }
}

/// Makes `a` and `b` friends, and `a`'s device creates their DM (no group).
async fn dm_between(app: &TestApp, (a, a1): (&Account, &Device), b: &Account) -> Dm {
    let b_device = app.enrol(b).await;
    app.befriend((a, a1), (b, &b_device)).await;
    let conversation: Conversation = app
        .post(
            "/v1/conversations",
            Some(&a1.session_token),
            &CreateDmRequest { user_id: b.user_id },
        )
        .await;
    let mut participants = [*a.user_id.as_bytes(), *b.user_id.as_bytes()];
    participants.sort();
    Dm {
        conversation: conversation.conversation_id,
        participants,
        keys: Keys(
            [
                (*a.user_id.as_bytes(), a.identity.public()),
                (*b.user_id.as_bytes(), b.identity.public()),
            ]
            .into_iter()
            .collect(),
        ),
        external_sender: app.state.secrets.external_sender.public_bytes(),
    }
}

async fn upload(app: &TestApp, device: &Device, count: usize) {
    let _: KeyPackageCount = app
        .post(
            "/v1/devices/me/key-packages",
            Some(&device.session_token),
            &UploadKeyPackagesRequest {
                key_packages: device.key_packages(count),
                last_resort: None,
            },
        )
        .await;
}

/// The packages `by` claims for `user`'s devices, checked as a client does.
async fn claim(app: &TestApp, by: &Device, user: &Account, keys: &Keys) -> Vec<ClaimedKeyPackage> {
    let (status, bytes) = app
        .send::<()>(
            Method::POST,
            &format!("/v1/users/{}/key-packages/claim", user.user_id),
            Some(&by.session_token),
            None,
        )
        .await;
    assert!(status.is_success(), "{status}");
    let claim: KeyPackageClaim = serde_json::from_slice(&bytes).unwrap();
    claim
        .key_packages
        .iter()
        .map(|served| {
            let device = VerifiedLeaf {
                user_id: *user.user_id.as_bytes(),
                device_id: *served.device_id.as_bytes(),
            };
            key_package::validate_claimed(served.key_package.as_slice(), device, keys).unwrap()
        })
        .collect()
}

fn code(payload: &ServerPayload) -> proto::ErrorCode {
    match payload {
        ServerPayload::Error(error) => error.code(),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn current_epoch(payload: &ServerPayload) -> u64 {
    match payload {
        ServerPayload::Error(error) => error.current_epoch,
        other => panic!("expected an error, got {other:?}"),
    }
}

fn error_text(payload: &ServerPayload) -> (proto::ErrorCode, String) {
    match payload {
        ServerPayload::Error(error) => (error.code(), error.message.clone()),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// A device connected to the gateway, with its group.
struct Member {
    device: Device,
    socket: Socket,
    next_request: u64,
    events: VecDeque<ServerPayload>,
    group: Option<Group>,
}

impl Member {
    async fn connect(app: &TestApp, device: Device) -> Self {
        let (socket, _) = connect(app, &device).await;
        Self {
            device,
            socket,
            next_request: 1,
            events: VecDeque::new(),
            group: None,
        }
    }

    async fn send_request(&mut self, payload: ClientPayload) -> u64 {
        self.next_request += 1;
        send(&mut self.socket, self.next_request, payload).await;
        self.next_request
    }

    /// The answer to request `id`; events that arrive meanwhile are kept.
    async fn answer(&mut self, id: u64) -> ServerPayload {
        loop {
            let frame = expect_frame(&mut self.socket).await;
            if frame.request_id == id {
                return frame.payload.unwrap();
            }
            assert_eq!(frame.request_id, 0, "the answer to another request");
            self.events.push_back(frame.payload.unwrap());
        }
    }

    async fn request(&mut self, payload: ClientPayload) -> ServerPayload {
        let id = self.send_request(payload).await;
        self.answer(id).await
    }

    /// The next event of a sequence or a Welcome; events about friends,
    /// devices and KeyPackages are skipped.
    async fn event(&mut self) -> ServerPayload {
        loop {
            let event = match self.events.pop_front() {
                Some(event) => event,
                None => {
                    let frame = expect_frame(&mut self.socket).await;
                    assert_eq!(frame.request_id, 0);
                    frame.payload.unwrap()
                }
            };
            match event {
                ServerPayload::FriendshipChanged(_)
                | ServerPayload::ConversationCreated(_)
                | ServerPayload::UserDevicesChanged(_)
                | ServerPayload::DeviceListChanged(_)
                | ServerPayload::KeyPackagesLow(_) => {}
                event => return event,
            }
        }
    }

    /// Asserts that no event of a sequence or Welcome is waiting: a
    /// heartbeat's answer comes first.
    async fn nothing_waiting(&mut self) {
        let answer = self
            .request(ClientPayload::Heartbeat(proto::Heartbeat {}))
            .await;
        assert!(matches!(answer, ServerPayload::HeartbeatAck(_)));
        while let Some(event) = self.events.pop_front() {
            assert!(
                matches!(
                    event,
                    ServerPayload::FriendshipChanged(_)
                        | ServerPayload::UserDevicesChanged(_)
                        | ServerPayload::DeviceListChanged(_)
                        | ServerPayload::KeyPackagesLow(_)
                ),
                "unexpected {event:?}"
            );
        }
    }

    fn create(&mut self, dm: &Dm, claimed: &[ClaimedKeyPackage]) -> Commit {
        let (group, commit) = Group::create(
            &self.device.provider,
            &DeviceSigner::new(&self.device.key),
            for_device(&self.device.certificate, &self.device.key.public()),
            &dm.expected(),
            &dm.external_sender,
            claimed,
            &dm.keys,
        )
        .unwrap();
        self.group = Some(group);
        commit
    }

    fn self_update(&mut self, dm: &Dm) -> Commit {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .self_update(&device.provider, &DeviceSigner::new(&device.key), &dm.keys)
            .unwrap()
    }

    fn encrypt(&mut self, content: &[u8]) -> Vec<u8> {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .encrypt(&device.provider, &DeviceSigner::new(&device.key), content)
            .unwrap()
    }

    fn process(&mut self, dm: &Dm, message: &[u8]) -> Incoming {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .process(&device.provider, message, &dm.keys)
            .unwrap()
    }

    fn merge(&mut self) {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .merge_pending_commit(&device.provider)
            .unwrap();
    }

    /// Drops this device's own group, the one it created and lost the race
    /// with (ADR 0019, section 4), before it joins the winner's.
    fn drop_group(&mut self) {
        let group = self.group.take().unwrap();
        group.delete(&self.device.provider).unwrap();
    }

    fn discard(&mut self) {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .discard_pending_commit(&device.provider)
            .unwrap();
    }

    async fn submit(&mut self, dm: &Dm, epoch: u64, commit: Commit, external: bool) -> u64 {
        self.send_request(ClientPayload::SubmitCommit(proto::SubmitCommit {
            conversation_id: dm.conversation.as_bytes().to_vec(),
            epoch,
            mls_commit: commit.commit,
            mls_welcome: commit.welcome.unwrap_or_default(),
            mls_group_info: commit.group_info,
            external,
        }))
        .await
    }

    async fn send_message(&mut self, dm: &Dm, client_message_id: Uuid, message: Vec<u8>) -> u64 {
        self.send_request(ClientPayload::SendMessage(proto::SendMessage {
            conversation_id: dm.conversation.as_bytes().to_vec(),
            client_message_id: client_message_id.as_bytes().to_vec(),
            mls_message: message,
        }))
        .await
    }

    /// Joins by the next Welcome, and acknowledges it.
    async fn join(&mut self, dm: &Dm) {
        let ServerPayload::WelcomeEvent(welcome) = self.event().await else {
            panic!("expected a Welcome");
        };
        assert_eq!(welcome.conversation_id, dm.conversation.as_bytes());
        let joined = Group::join(
            &self.device.provider,
            &welcome.mls_welcome,
            &dm.expected(),
            &dm.keys,
            &dm.external_sender,
        )
        .unwrap();
        self.group = Some(joined.group);
        let ack = self
            .request(ClientPayload::AckWelcome(proto::AckWelcome {
                welcome_id: welcome.welcome_id,
            }))
            .await;
        assert!(matches!(ack, ServerPayload::Ack(_)), "{ack:?}");
    }

    /// The next application message, decrypted: its sequence number and
    /// content.
    async fn receive_text(&mut self, dm: &Dm) -> (u64, Vec<u8>) {
        let ServerPayload::MessageEvent(event) = self.event().await else {
            panic!("expected a message");
        };
        let message = event.message.unwrap();
        match self.process(dm, &message.mls_message) {
            Incoming::Application { content, .. } => (message.seq, content.expose().to_vec()),
            other => panic!("{other:?}"),
        }
    }

    async fn fetch(&mut self, dm: &Dm, after_seq: u64, limit: u32) -> proto::MessageBatch {
        let answer = self
            .request(ClientPayload::FetchMessages(proto::FetchMessages {
                conversation_id: dm.conversation.as_bytes().to_vec(),
                after_seq,
                limit,
            }))
            .await;
        let ServerPayload::MessageBatch(batch) = answer else {
            panic!("{answer:?}");
        };
        batch
    }
}

fn commit_ack(payload: &ServerPayload) -> &proto::CommitAck {
    match payload {
        ServerPayload::CommitAck(ack) => ack,
        other => panic!("expected a commit acknowledgement, got {other:?}"),
    }
}

fn message_ack(payload: &ServerPayload) -> proto::SendMessageAck {
    match payload {
        ServerPayload::SendMessageAck(ack) => *ack,
        other => panic!("expected a message acknowledgement, got {other:?}"),
    }
}

/// The devices of the conversation's group, as the server routes to them.
async fn routed(app: &TestApp, conversation: Uuid) -> Vec<Uuid> {
    let mut devices: Vec<Uuid> = sqlx::query_scalar(
        "SELECT device_id FROM conversation_devices \
         WHERE conversation_id = $1 AND left_seq IS NULL",
    )
    .bind(conversation)
    .fetch_all(&app.state.db)
    .await
    .unwrap();
    devices.sort();
    devices
}

/// The devices the server's public state of the group holds.
async fn in_tree(app: &TestApp, dm: &Dm) -> Vec<Uuid> {
    let mut conn = app.state.db.acquire().await.unwrap();
    let loaded = mls::load(&mut conn, dm.identity()).await.unwrap().unwrap();
    let mut devices: Vec<Uuid> = loaded
        .state
        .leaves()
        .into_iter()
        .map(|(_, leaf)| Uuid::from_bytes(leaf.device_id))
        .collect();
    devices.sort();
    devices
}

async fn sequence(app: &TestApp, conversation: Uuid) -> Vec<(i64, i16)> {
    sqlx::query_as("SELECT seq, kind FROM messages WHERE conversation_id = $1 ORDER BY seq")
        .bind(conversation)
        .fetch_all(&app.state.db)
        .await
        .unwrap()
}

/// Holds `conversation`'s row, as a request adding to its sequence does,
/// until the returned transaction ends; with its backend.
async fn hold(
    app: &TestApp,
    conversation: Uuid,
) -> (sqlx::Transaction<'static, sqlx::Postgres>, i32) {
    let mut tx = app.state.db.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SELECT 1 FROM conversations WHERE id = $1 FOR UPDATE")
        .bind(conversation)
        .execute(&mut *tx)
        .await
        .unwrap();
    (tx, pid)
}

/// Returns once `count` backends wait behind `holder`: for a row lock, the
/// first waiter waits for the holder and the next ones for the waiter ahead
/// of them, hence the chain. PostgreSQL announces no such event, so it is
/// polled; the timeout only keeps a broken test from hanging.
async fn waiting_for(app: &TestApp, holder: i32, count: i64) {
    let wait = async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "WITH RECURSIVE chain(pid) AS ( \
                     SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) \
                     UNION \
                     SELECT a.pid FROM pg_stat_activity a \
                     JOIN chain c ON c.pid = ANY(pg_blocking_pids(a.pid))) \
                 SELECT count(*) FROM chain",
            )
            .bind(holder)
            .fetch_one(&app.state.db)
            .await
            .unwrap();
            if waiting == count {
                break;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::time::timeout(Duration::from_secs(60), wait)
        .await
        .expect("the requests never waited for the conversation");
}

/// Alice and Bob's DM, its group created by Alice's first device with Bob's
/// first device: both connected, in the group.
async fn group_of_two(app: &TestApp) -> (Account, Member, Account, Member, Dm) {
    let (alice, alice1) = app.account_with_device("sq", false).await;
    let bob = app.register("sq", false).await;
    let dm = dm_between(app, (&alice, &alice1), &bob).await;
    let bob1 = app.enrol(&bob).await;
    // Only Bob's newest device has packages, and is active in the group.
    upload(app, &bob1, 3).await;
    let claimed = claim(app, &alice1, &bob, &dm.keys).await;
    let mut alice1 = Member::connect(app, alice1).await;
    let mut bob1 = Member::connect(app, bob1).await;
    let commit = alice1.create(&dm, &claimed);
    let id = alice1.submit(&dm, 0, commit, false).await;
    commit_ack(&alice1.answer(id).await);
    alice1.merge();
    bob1.join(&dm).await;
    (alice, alice1, bob, bob1, dm)
}

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
/// (task 9): its proposal is stored with the group's state.
async fn server_removes(app: &TestApp, dm: &Dm, device: VerifiedLeaf) {
    let mut tx = app.state.db.begin().await.unwrap();
    let mut loaded = mls::load(&mut tx, dm.identity()).await.unwrap().unwrap();
    let leaf = loaded.state.leaf_of(device).unwrap();
    loaded
        .state
        .remove(leaf, &ServerSigner::new(&app.state.secrets.external_sender))
        .unwrap()
        .unwrap();
    mls::save(&mut tx, loaded).await.unwrap();
    tx.commit().await.unwrap();
}

/// Section 6: while the server's removals are pending, no application
/// message is accepted, and a member's commit must carry them.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn pending_removals_hold_messages_and_commits_that_leave_them_out() {
    let app = TestApp::spawn_unlimited().await;
    let (_, mut alice1, bob, mut bob1, dm) = group_of_two(&app).await;
    server_removes(&app, &dm, leaf(&bob, &bob1.device)).await;

    let message = alice1.encrypt(b"held");
    let id = alice1.send_message(&dm, Uuid::new_v4(), message).await;
    assert_eq!(
        code(&alice1.answer(id).await),
        proto::ErrorCode::RemovalPending
    );
    let commit = alice1.self_update(&dm);
    let id = alice1.submit(&dm, 1, commit, false).await;
    assert_eq!(
        code(&alice1.answer(id).await),
        proto::ErrorCode::RemovalPending
    );
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
    assert_eq!((commit_ack(&ack).seq, commit_ack(&ack).new_epoch), (2, 2));
    alice2.merge();

    let ServerPayload::ProposalEvent(event) = alice2.event().await else {
        panic!("expected the removal asked again");
    };
    let proposal = event.message.unwrap();
    assert_eq!((proposal.seq, proposal.epoch), (3, 2));
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
        [(1, 2), (2, 2), (3, 3)]
    );
    assert_eq!(
        routed(&app, dm.conversation).await,
        in_tree(&app, &dm).await
    );
    assert_eq!(routed(&app, dm.conversation).await.len(), 3);
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

    // A new leaf: refused, though the GroupInfo may be read.
    let answer = alice2
        .request(ClientPayload::FetchGroupInfo(proto::FetchGroupInfo {
            conversation_id: dm.conversation.as_bytes().to_vec(),
        }))
        .await;
    let ServerPayload::GroupInfo(info) = answer else {
        panic!("{answer:?}");
    };
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
