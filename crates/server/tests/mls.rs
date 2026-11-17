// SPDX-License-Identifier: AGPL-3.0-or-later

//! The public state of MLS groups in PostgreSQL (ADR 0019, section 14): real
//! accounts and devices in the database, a DM made by `tavern-crypto` on the
//! client side, and the server storing, checking and merging its state in
//! transactions.
//!
//! Needs PostgreSQL, like `tests/http.rs`:
//!
//! ```sh
//! TAVERN_TEST_DATABASE_URL=postgres://... cargo test -p tavern-server -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers panic on failure"
)]

mod common;

use std::collections::HashMap;

use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider as _;
use sqlx::PgPool;
use tavern_crypto::identity::{
    AccountIdentityKey, AccountRootSecret, DeviceKey, ExternalSenderKey, ID_LEN, IdentityPublicKey,
};
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::key_package;
use tavern_crypto::mls::{
    ClaimedKeyPackage, Commit, DeviceSigner, ExpectedGroup, Group, LeafError, MlsError, Provider,
    PublicState, Roster, ServerSigner, VerifiedLeaf,
};
use tavern_server::db;
use tavern_server::mls::{self, ServerRoster, StateError};
use uuid::Uuid;

async fn pool() -> PgPool {
    let pool = db::connect(&common::database_url(), 4).await.unwrap();
    db::migrate(&pool).await.unwrap();
    pool
}

/// A user with one device, in the database and on the client side.
struct Person {
    user: Uuid,
    identity: AccountIdentityKey,
    device: Uuid,
    key: DeviceKey,
    certificate: Vec<u8>,
    provider: Provider<MemoryStorage>,
}

impl Person {
    async fn new(pool: &PgPool) -> Self {
        let identity = AccountRootSecret::generate().identity_key().unwrap();
        let handle = format!("mls_{}", &Uuid::new_v4().simple().to_string()[..16]);
        let user: Uuid = sqlx::query_scalar(
            "INSERT INTO users (handle, display_name, opaque_suite, opaque_record, identity_key, \
             identity_key_wrapped_pw, identity_key_wrapped_rk) \
             VALUES ($1, 'MLS test', 1, '\\x00', $2, '\\x00', '\\x00') RETURNING id",
        )
        .bind(&handle)
        .bind(identity.public().to_bytes().to_vec())
        .fetch_one(pool)
        .await
        .unwrap();
        let mut person = Self {
            user,
            identity,
            device: Uuid::nil(),
            key: DeviceKey::generate(),
            certificate: Vec::new(),
            provider: Provider::new(MemoryStorage::default()),
        };
        person.enrol(pool).await;
        person
    }

    /// Enrols a new device of the same user.
    async fn enrol(&mut self, pool: &PgPool) {
        self.key = DeviceKey::generate();
        self.provider = Provider::new(MemoryStorage::default());
        self.device = Uuid::new_v4();
        self.certificate = self.identity.certify_device(
            self.user.as_bytes(),
            self.device.as_bytes(),
            &self.key.public(),
            0,
        );
        sqlx::query(
            "INSERT INTO devices (id, user_id, signature_key, certificate, platform) \
             VALUES ($1, $2, $3, $4, 1)",
        )
        .bind(self.device)
        .bind(self.user)
        .bind(self.key.public().to_bytes().to_vec())
        .bind(&self.certificate)
        .execute(pool)
        .await
        .unwrap();
    }

    fn leaf(&self) -> VerifiedLeaf {
        VerifiedLeaf {
            user_id: *self.user.as_bytes(),
            device_id: *self.device.as_bytes(),
        }
    }

    fn signer(&self) -> DeviceSigner<'_> {
        DeviceSigner::new(&self.key)
    }

    fn claimed(&self, roster: &Keys) -> ClaimedKeyPackage {
        let package = key_package::build(
            &self.provider,
            &self.signer(),
            for_device(&self.certificate, &self.key.public()),
            false,
        )
        .unwrap();
        key_package::validate_claimed(
            self.provider.crypto(),
            &key_package::to_bytes(&package).unwrap(),
            self.leaf(),
            roster,
        )
        .unwrap()
    }
}

/// The identity keys a client pinned.
struct Keys(HashMap<[u8; ID_LEN], IdentityPublicKey>);

impl Keys {
    fn of(people: &[&Person]) -> Self {
        Self(
            people
                .iter()
                .map(|person| (*person.user.as_bytes(), person.identity.public()))
                .collect(),
        )
    }
}

impl Roster for Keys {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.0.get(user_id).copied()
    }
}

/// Alice and Bob's DM, created by Alice, joined by Bob, and stored by the
/// server.
struct Dm {
    alice: Person,
    bob: Person,
    server: ExternalSenderKey,
    identity: GroupIdentity,
    participants: [[u8; ID_LEN]; 2],
    alice_group: Group,
    bob_group: Group,
}

impl Dm {
    async fn new(pool: &PgPool) -> Self {
        let alice = Person::new(pool).await;
        let bob = Person::new(pool).await;
        let server = ExternalSenderKey::generate();
        let identity = GroupIdentity {
            conversation_id: *Uuid::new_v4().as_bytes(),
            generation: 0,
        };
        let participants = [*alice.user.as_bytes(), *bob.user.as_bytes()];
        let keys = Keys::of(&[&alice, &bob]);
        let expected = ExpectedGroup {
            identity,
            participants: &participants,
        };
        let (mut alice_group, created) = Group::create(
            &alice.provider,
            &alice.signer(),
            for_device(&alice.certificate, &alice.key.public()),
            &expected,
            &server.public_bytes(),
            &[bob.claimed(&keys)],
            &keys,
        )
        .unwrap();
        alice_group.merge_pending_commit(&alice.provider).unwrap();
        let bob_group = Group::join(
            &bob.provider,
            created.welcome.as_ref().unwrap(),
            &expected,
            &keys,
            &server.public_bytes(),
        )
        .unwrap()
        .group;

        let dm = Self {
            alice,
            bob,
            server,
            identity,
            participants,
            alice_group,
            bob_group,
        };
        let mut tx = pool.begin().await.unwrap();
        let roster = dm.roster(&mut tx).await;
        let (state, devices) = PublicState::create(
            &created.group_info,
            &dm.expected(),
            dm.alice.leaf(),
            &roster,
            &dm.server.public_bytes(),
        )
        .unwrap();
        assert_eq!(devices.len(), 2);
        mls::insert(&mut tx, &state, &created.group_info)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        dm
    }

    fn expected(&self) -> ExpectedGroup<'_> {
        ExpectedGroup {
            identity: self.identity,
            participants: &self.participants,
        }
    }

    fn keys(&self) -> Keys {
        Keys::of(&[&self.alice, &self.bob])
    }

    async fn roster(&self, conn: &mut sqlx::PgConnection) -> ServerRoster {
        ServerRoster::load(conn, &[self.alice.user, self.bob.user])
            .await
            .unwrap()
    }

    fn bob_update(&mut self) -> Commit {
        let keys = self.keys();
        self.bob_group
            .self_update(&self.bob.provider, &self.bob.signer(), &keys)
            .unwrap()
    }

    /// Submits Bob's `commit` to the server in a transaction, and commits
    /// the transaction or rolls it back.
    async fn submit_bob(&self, pool: &PgPool, commit: &Commit, keep: bool) -> u64 {
        let mut tx = pool.begin().await.unwrap();
        let mut stored = mls::load(&mut tx, self.identity).await.unwrap().unwrap();
        let roster = self.roster(&mut tx).await;
        let validated = stored
            .state
            .validate_commit(
                &commit.commit,
                &commit.group_info,
                self.bob.leaf(),
                &self.expected(),
                &roster,
            )
            .unwrap();
        let merged = stored
            .state
            .merge(validated, &ServerSigner::new(&self.server))
            .unwrap();
        mls::save(&mut tx, &stored.state, Some(&merged.group_info))
            .await
            .unwrap();
        if keep {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        merged.epoch
    }

    async fn stored_epoch(&self, pool: &PgPool) -> (u64, Vec<u8>) {
        let mut conn = pool.acquire().await.unwrap();
        let stored = mls::load(&mut conn, self.identity).await.unwrap().unwrap();
        (stored.state.epoch(), stored.group_info)
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_public_state_moves_with_the_transaction_of_each_commit() {
    let pool = pool().await;
    let mut dm = Dm::new(&pool).await;
    assert_eq!(dm.stored_epoch(&pool).await.0, 1);

    // Accepted and committed: the next request sees epoch 2 and its
    // GroupInfo.
    let commit = dm.bob_update();
    assert_eq!(dm.submit_bob(&pool, &commit, true).await, 2);
    assert_eq!(dm.stored_epoch(&pool).await, (2, commit.group_info.clone()));
    dm.bob_group.merge_pending_commit(&dm.bob.provider).unwrap();
    let keys = dm.keys();
    dm.alice_group
        .process(&dm.alice.provider, &commit.commit, &keys)
        .unwrap();

    // Accepted, then the transaction fails: nothing moved.
    let commit = dm.bob_update();
    dm.submit_bob(&pool, &commit, false).await;
    assert_eq!(dm.stored_epoch(&pool).await.0, 2);

    // Checked again on the reloaded state, it goes through.
    assert_eq!(dm.submit_bob(&pool, &commit, true).await, 3);
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_server_s_removal_is_stored_with_the_state() {
    let pool = pool().await;
    let dm = Dm::new(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let mut stored = mls::load(&mut tx, dm.identity).await.unwrap().unwrap();
    let bob = stored.state.leaf_of(dm.bob.leaf()).unwrap();
    stored
        .state
        .remove(bob, &ServerSigner::new(&dm.server))
        .unwrap()
        .unwrap();
    mls::save(&mut tx, &stored.state, None).await.unwrap();
    tx.commit().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let stored = mls::load(&mut conn, dm.identity).await.unwrap().unwrap();
    assert_eq!(stored.state.pending_removals().unwrap(), [bob]);
    assert_eq!(
        stored.state.epoch(),
        1,
        "a proposal does not move the epoch"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_revoked_device_is_not_accepted_any_more() {
    let pool = pool().await;
    let mut dm = Dm::new(&pool).await;
    let commit = dm.bob_update();
    sqlx::query("UPDATE devices SET revoked_at = now() WHERE id = $1")
        .bind(dm.bob.device)
        .execute(&pool)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let stored = mls::load(&mut conn, dm.identity).await.unwrap().unwrap();
    let roster = dm.roster(&mut conn).await;
    let result = stored.state.validate_commit(
        &commit.commit,
        &commit.group_info,
        dm.bob.leaf(),
        &dm.expected(),
        &roster,
    );
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::InactiveDevice))),
        "{result:?}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_new_generation_replaces_the_conversation_s_earlier_ones() {
    let pool = pool().await;
    let mut dm = Dm::new(&pool).await;
    let old_group = dm.identity.to_group_id().as_slice().to_vec();
    let conversation = Uuid::from_bytes(dm.identity.conversation_id);

    // Recreated (section 17): generation 1, with a new device of Bob's.
    dm.bob.enrol(&pool).await;
    let next = dm.identity.next().unwrap();
    let expected = ExpectedGroup {
        identity: next,
        participants: &dm.participants,
    };
    let keys = dm.keys();
    let (_, created) = Group::create(
        &dm.alice.provider,
        &dm.alice.signer(),
        for_device(&dm.alice.certificate, &dm.alice.key.public()),
        &expected,
        &dm.server.public_bytes(),
        &[dm.bob.claimed(&keys)],
        &keys,
    )
    .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let roster = dm.roster(&mut tx).await;
    let (state, _) = PublicState::create(
        &created.group_info,
        &expected,
        dm.alice.leaf(),
        &roster,
        &dm.server.public_bytes(),
    )
    .unwrap();
    mls::insert(&mut tx, &state, &created.group_info)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let groups: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mls_groups WHERE conversation_id = $1")
            .bind(conversation)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(groups, 1);
    let old_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mls_group_entries WHERE group_id = $1")
            .bind(&old_group)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(old_rows, 0, "the earlier generation's state is deleted");
    let mut conn = pool.acquire().await.unwrap();
    assert!(mls::load(&mut conn, dm.identity).await.unwrap().is_none());
    assert!(mls::load(&mut conn, next).await.unwrap().is_some());

    // An earlier generation, or the same one, cannot come back.
    let mut tx = pool.begin().await.unwrap();
    let result = mls::insert(&mut tx, &state, &created.group_info).await;
    assert!(
        matches!(result, Err(StateError::GenerationExists)),
        "{result:?}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn one_request_at_a_time_holds_a_group() {
    let pool = pool().await;
    let dm = Dm::new(&pool).await;
    let mut first = pool.begin().await.unwrap();
    mls::load(&mut first, dm.identity).await.unwrap().unwrap();

    let mut second = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '200ms'")
        .execute(&mut *second)
        .await
        .unwrap();
    let result = mls::load(&mut second, dm.identity).await;
    assert!(matches!(result, Err(StateError::Database(_))), "{result:?}");
    drop(second);
    first.rollback().await.unwrap();
}
