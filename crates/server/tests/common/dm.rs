// SPDX-License-Identifier: AGPL-3.0-or-later

//! DMs with their MLS groups, built by `tavern-crypto` on the clients' side,
//! as a client builds them: devices connected to the gateway, and what the
//! server stores of their conversations (ADR 0019).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use reqwest::Method;
use tavern_crypto::identity::{ID_LEN, IdentityPublicKey};
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::{
    ClaimedKeyPackage, Commit, DeviceSigner, ExpectedGroup, Group, Incoming, Roster, VerifiedLeaf,
    key_package,
};
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::client_frame::Payload as ClientPayload;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_protocol::rest::{
    Conversation, ConversationList, CreateDmRequest, KeyPackageClaim, KeyPackageCount,
    UploadKeyPackagesRequest,
};
use tavern_server::mls;
use tavern_server::session::Session;
use uuid::Uuid;

use super::ws::{Socket, connect, expect_frame, send};
use super::{Account, Device, TestApp};

/// The identity keys the clients of these tests trust.
#[derive(Clone)]
pub struct Keys(pub HashMap<[u8; ID_LEN], IdentityPublicKey>);

impl Roster for Keys {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.0.get(user_id).copied()
    }
}

pub fn leaf(account: &Account, device: &Device) -> VerifiedLeaf {
    VerifiedLeaf {
        user_id: *account.user_id.as_bytes(),
        device_id: *device.device_id.as_bytes(),
    }
}

/// A DM between two friends, as its clients know it.
pub struct Dm {
    pub conversation: Uuid,
    pub participants: [[u8; ID_LEN]; 2],
    pub keys: Keys,
    pub external_sender: [u8; 32],
}

impl Dm {
    pub fn expected(&self) -> ExpectedGroup<'_> {
        ExpectedGroup {
            identity: self.identity(),
            participants: &self.participants,
        }
    }

    pub fn identity(&self) -> GroupIdentity {
        GroupIdentity {
            conversation_id: *self.conversation.as_bytes(),
            generation: 0,
        }
    }
}

/// Makes `a` and `b` friends, and `a`'s device creates their DM (no group).
pub async fn dm_between(app: &TestApp, (a, a1): (&Account, &Device), b: &Account) -> Dm {
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

pub async fn upload(app: &TestApp, device: &Device, count: usize) {
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
pub async fn claim(
    app: &TestApp,
    by: &Device,
    user: &Account,
    keys: &Keys,
) -> Vec<ClaimedKeyPackage> {
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

pub fn code(payload: &ServerPayload) -> proto::ErrorCode {
    match payload {
        ServerPayload::Error(error) => error.code(),
        other => panic!("expected an error, got {other:?}"),
    }
}

pub fn current_epoch(payload: &ServerPayload) -> u64 {
    match payload {
        ServerPayload::Error(error) => error.current_epoch,
        other => panic!("expected an error, got {other:?}"),
    }
}

pub fn error_text(payload: &ServerPayload) -> (proto::ErrorCode, String) {
    match payload {
        ServerPayload::Error(error) => (error.code(), error.message.clone()),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// A device connected to the gateway, with its group.
pub struct Member {
    pub device: Device,
    pub socket: Socket,
    pub next_request: u64,
    pub events: VecDeque<ServerPayload>,
    pub group: Option<Group>,
    /// The Welcomes it acknowledged. A Welcome may arrive twice, pushed
    /// and sent again at connection (`protocol.md`, section 3): like a
    /// client, the device goes by its id.
    pub acked_welcomes: HashSet<Vec<u8>>,
    /// The conversations the server told this device to join by external
    /// commit (`JoinConversation`), in the order it did; kept aside by
    /// [`Member::event`].
    pub told_to_join: Vec<Uuid>,
}

impl Member {
    /// Whether `event` is a Welcome this device already acknowledged.
    pub fn seen(&self, event: &ServerPayload) -> bool {
        matches!(event, ServerPayload::WelcomeEvent(welcome)
            if self.acked_welcomes.contains(&welcome.welcome_id))
    }
}

impl Member {
    pub async fn connect(app: &TestApp, device: Device) -> Self {
        let (socket, _) = connect(app, &device).await;
        Self {
            device,
            socket,
            next_request: 1,
            events: VecDeque::new(),
            group: None,
            acked_welcomes: HashSet::new(),
            told_to_join: Vec::new(),
        }
    }

    pub async fn send_request(&mut self, payload: ClientPayload) -> u64 {
        self.next_request += 1;
        send(&mut self.socket, self.next_request, payload).await;
        self.next_request
    }

    /// The answer to request `id`; events that arrive meanwhile are kept.
    pub async fn answer(&mut self, id: u64) -> ServerPayload {
        loop {
            let frame = expect_frame(&mut self.socket).await;
            if frame.request_id == id {
                return frame.payload.unwrap();
            }
            assert_eq!(frame.request_id, 0, "the answer to another request");
            self.events.push_back(frame.payload.unwrap());
        }
    }

    pub async fn request(&mut self, payload: ClientPayload) -> ServerPayload {
        let id = self.send_request(payload).await;
        self.answer(id).await
    }

    /// The next event of a sequence or a Welcome; events about friends,
    /// devices and KeyPackages are skipped.
    pub async fn event(&mut self) -> ServerPayload {
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
                ServerPayload::JoinConversation(join) => self
                    .told_to_join
                    .push(Uuid::from_slice(&join.conversation_id).unwrap()),
                event if self.seen(&event) => {}
                event => return event,
            }
        }
    }

    /// Asserts that no event of a sequence or Welcome is waiting: a
    /// heartbeat's answer comes first.
    pub async fn nothing_waiting(&mut self) {
        let answer = self
            .request(ClientPayload::Heartbeat(proto::Heartbeat {}))
            .await;
        assert!(matches!(answer, ServerPayload::HeartbeatAck(_)));
        while let Some(event) = self.events.pop_front() {
            if let ServerPayload::JoinConversation(join) = &event {
                self.told_to_join
                    .push(Uuid::from_slice(&join.conversation_id).unwrap());
                continue;
            }
            assert!(
                self.seen(&event)
                    || matches!(
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

    pub fn create(&mut self, dm: &Dm, claimed: &[ClaimedKeyPackage]) -> Commit {
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

    pub fn self_update(&mut self, dm: &Dm) -> Commit {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .self_update(&device.provider, &DeviceSigner::new(&device.key), &dm.keys)
            .unwrap()
    }

    pub fn encrypt(&mut self, content: &[u8]) -> Vec<u8> {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .encrypt(&device.provider, &DeviceSigner::new(&device.key), content)
            .unwrap()
    }

    pub fn process(&mut self, dm: &Dm, message: &[u8]) -> Incoming {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .process(&device.provider, message, &dm.keys)
            .unwrap()
    }

    pub fn merge(&mut self) {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .merge_pending_commit(&device.provider)
            .unwrap();
    }

    /// Drops this device's own group, the one it created and lost the race
    /// with (ADR 0019, section 4), before it joins the winner's.
    pub fn drop_group(&mut self) {
        let group = self.group.take().unwrap();
        group.delete(&self.device.provider).unwrap();
    }

    pub fn discard(&mut self) {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .discard_pending_commit(&device.provider)
            .unwrap();
    }

    pub async fn submit(&mut self, dm: &Dm, epoch: u64, commit: Commit, external: bool) -> u64 {
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

    pub async fn send_message(
        &mut self,
        dm: &Dm,
        client_message_id: Uuid,
        message: Vec<u8>,
    ) -> u64 {
        self.send_request(ClientPayload::SendMessage(proto::SendMessage {
            conversation_id: dm.conversation.as_bytes().to_vec(),
            client_message_id: client_message_id.as_bytes().to_vec(),
            mls_message: message,
        }))
        .await
    }

    /// Joins by the next Welcome, and acknowledges it.
    pub async fn join(&mut self, dm: &Dm) {
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
                welcome_id: welcome.welcome_id.clone(),
            }))
            .await;
        assert!(matches!(ack, ServerPayload::Ack(_)), "{ack:?}");
        self.acked_welcomes.insert(welcome.welcome_id);
    }

    /// The next application message, decrypted: its sequence number and
    /// content.
    pub async fn receive_text(&mut self, dm: &Dm) -> (u64, Vec<u8>) {
        let ServerPayload::MessageEvent(event) = self.event().await else {
            panic!("expected a message");
        };
        let message = event.message.unwrap();
        match self.process(dm, &message.mls_message) {
            Incoming::Application { content, .. } => (message.seq, content.expose().to_vec()),
            other => panic!("{other:?}"),
        }
    }

    /// Commits the server's pending removals, as the first member online
    /// does (ADR 0019, section 6).
    pub fn commit_pending(&mut self, dm: &Dm) -> Commit {
        let Self { group, device, .. } = self;
        group
            .as_mut()
            .unwrap()
            .commit_pending_proposals(&device.provider, &DeviceSigner::new(&device.key), &dm.keys)
            .unwrap()
            .expect("removals are pending")
    }

    /// The group's latest GroupInfo, or the refusal.
    pub async fn group_info(&mut self, dm: &Dm) -> ServerPayload {
        self.request(ClientPayload::FetchGroupInfo(proto::FetchGroupInfo {
            conversation_id: dm.conversation.as_bytes().to_vec(),
        }))
        .await
    }

    /// Joins the group by external commit, dropping the group it held if
    /// any (a resync, or a return), and submits the commit: its answer.
    pub async fn join_externally(&mut self, dm: &Dm) -> ServerPayload {
        if let Some(group) = self.group.take() {
            group.delete(&self.device.provider).unwrap();
        }
        let ServerPayload::GroupInfo(info) = self.group_info(dm).await else {
            panic!("expected the GroupInfo");
        };
        let (group, commit, _) = Group::join_by_external_commit(
            &self.device.provider,
            &DeviceSigner::new(&self.device.key),
            for_device(&self.device.certificate, &self.device.key.public()),
            &info.mls_group_info,
            &dm.expected(),
            &dm.keys,
            &dm.external_sender,
        )
        .unwrap();
        self.group = Some(group);
        let id = self.submit(dm, info.epoch, commit, true).await;
        self.answer(id).await
    }

    pub async fn ack(&mut self, dm: &Dm, up_to_seq: u64) {
        let answer = self
            .request(ClientPayload::AckMessages(proto::AckMessages {
                conversation_id: dm.conversation.as_bytes().to_vec(),
                up_to_seq,
            }))
            .await;
        assert!(matches!(answer, ServerPayload::Ack(_)), "{answer:?}");
    }

    pub async fn fetch(&mut self, dm: &Dm, after_seq: u64, limit: u32) -> proto::MessageBatch {
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

pub fn commit_ack(payload: &ServerPayload) -> &proto::CommitAck {
    match payload {
        ServerPayload::CommitAck(ack) => ack,
        other => panic!("expected a commit acknowledgement, got {other:?}"),
    }
}

pub fn message_ack(payload: &ServerPayload) -> proto::SendMessageAck {
    match payload {
        ServerPayload::SendMessageAck(ack) => *ack,
        other => panic!("expected a message acknowledgement, got {other:?}"),
    }
}

/// The devices of the conversation's group, as the server routes to them.
pub async fn routed(app: &TestApp, conversation: Uuid) -> Vec<Uuid> {
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
pub async fn in_tree(app: &TestApp, dm: &Dm) -> Vec<Uuid> {
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

pub async fn sequence(app: &TestApp, conversation: Uuid) -> Vec<(i64, i16)> {
    sqlx::query_as("SELECT seq, kind FROM messages WHERE conversation_id = $1 ORDER BY seq")
        .bind(conversation)
        .fetch_all(&app.state.db)
        .await
        .unwrap()
}

/// The DM as the device `device` lists it (`GET /v1/conversations`).
pub async fn listed(app: &TestApp, device: &Device, dm: &Dm) -> Conversation {
    let list: ConversationList = app.get("/v1/conversations", &device.session_token).await;
    list.conversations
        .into_iter()
        .find(|conversation| conversation.conversation_id == dm.conversation)
        .unwrap()
}

/// The server's removals pending in `conversation`: device and proposal.
pub async fn pending_removals(app: &TestApp, conversation: Uuid) -> Vec<(Uuid, i64)> {
    sqlx::query_as(
        "SELECT device_id, proposal_seq FROM pending_removals \
         WHERE conversation_id = $1 ORDER BY proposal_seq",
    )
    .bind(conversation)
    .fetch_all(&app.state.db)
    .await
    .unwrap()
}

/// Holds `conversation`'s row, as a request adding to its sequence does,
/// until the returned transaction ends; with its backend.
pub async fn hold(
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
pub async fn waiting_for(app: &TestApp, holder: i32, count: i64) {
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

/// Holds `device`'s read position in `conversation` (its row of
/// `conversation_devices`) until the returned transaction ends, with its
/// backend: the device's `AckMessages` waits meanwhile, and its connection
/// with it.
pub async fn hold_cursor(
    app: &TestApp,
    conversation: Uuid,
    device: Uuid,
) -> (sqlx::Transaction<'static, sqlx::Postgres>, i32) {
    let mut tx = app.state.db.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "SELECT 1 FROM conversation_devices \
         WHERE conversation_id = $1 AND device_id = $2 FOR UPDATE",
    )
    .bind(conversation)
    .bind(device)
    .execute(&mut *tx)
    .await
    .unwrap();
    (tx, pid)
}

/// A trigger that runs `body` (PL/pgSQL) after each row inserted into
/// `table` for `conversation`, and for no other: the tests share one
/// database. It makes a request fail, or wait, at a precise point.
pub struct Trigger {
    pub name: String,
    pub table: &'static str,
}

impl Trigger {
    pub async fn install(
        app: &TestApp,
        table: &'static str,
        conversation: Uuid,
        body: &str,
    ) -> Self {
        let name = format!("test_{}", Uuid::new_v4().simple());
        // Built from a random name, a table and a body of this file, and a
        // UUID: nothing from outside.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN {body} RETURN NULL; END $$; \
             CREATE TRIGGER {name} AFTER INSERT ON {table} FOR EACH ROW \
             WHEN (NEW.conversation_id = '{conversation}') EXECUTE FUNCTION {name}();"
        )))
        .execute(&app.state.db)
        .await
        .unwrap();
        Self { name, table }
    }

    pub async fn remove(self, app: &TestApp) {
        let Self { name, table } = self;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP TRIGGER {name} ON {table}; DROP FUNCTION {name}();"
        )))
        .execute(&app.state.db)
        .await
        .unwrap();
    }
}

/// The session of `device`, to call the server's handlers directly: two
/// requests of one device at once, which one connection never sends.
pub fn session(account: &Account, device: &Device) -> Session {
    Session {
        user_id: account.user_id,
        device_id: device.device_id,
        is_admin: false,
    }
}

pub async fn last_seq(app: &TestApp, conversation: Uuid) -> i64 {
    sqlx::query_scalar("SELECT last_seq FROM conversations WHERE id = $1")
        .bind(conversation)
        .fetch_one(&app.state.db)
        .await
        .unwrap()
}

pub async fn group_epoch(app: &TestApp, conversation: Uuid) -> Option<i64> {
    sqlx::query_scalar("SELECT epoch FROM mls_groups WHERE conversation_id = $1")
        .bind(conversation)
        .fetch_optional(&app.state.db)
        .await
        .unwrap()
}

pub async fn welcomes_of(app: &TestApp, conversation: Uuid) -> Vec<(Uuid, Uuid)> {
    sqlx::query_as(
        "SELECT id, recipient_device_id FROM welcomes WHERE conversation_id = $1 ORDER BY id",
    )
    .bind(conversation)
    .fetch_all(&app.state.db)
    .await
    .unwrap()
}

pub fn group_info_request(dm: &Dm) -> ClientPayload {
    ClientPayload::FetchGroupInfo(proto::FetchGroupInfo {
        conversation_id: dm.conversation.as_bytes().to_vec(),
    })
}

/// Alice and Bob's DM, its group created by Alice's first device with Bob's
/// first device: both connected, in the group.
pub async fn group_of_two(app: &TestApp) -> (Account, Member, Account, Member, Dm) {
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
