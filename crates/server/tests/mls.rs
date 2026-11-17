// SPDX-License-Identifier: AGPL-3.0-or-later

//! The public state of MLS groups in PostgreSQL (ADR 0019, sections 2, 4, 7,
//! 12, 14 and 17): real accounts and devices in the database, DMs made by
//! `tavern-crypto` on the client side, and the server storing, checking and
//! merging their state in transactions.
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
use std::time::Duration;

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
    PublicState, Refusal, Roster, ServerSigner, VerifiedLeaf,
};
use tavern_server::db;
use tavern_server::mls::{self, ServerRoster, StateError};
use uuid::Uuid;

async fn pool() -> PgPool {
    let pool = db::connect(&common::database_url(), 8).await.unwrap();
    db::migrate(&pool).await.unwrap();
    pool
}

/// An account in the database, with its identity key.
struct Account {
    user: Uuid,
    identity: AccountIdentityKey,
}

/// A device: enrolled in the database, or only certified (a forgery).
struct Device {
    user: Uuid,
    id: Uuid,
    key: DeviceKey,
    certificate: Vec<u8>,
    provider: Provider<MemoryStorage>,
}

impl Account {
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
        Self { user, identity }
    }

    /// A device certified by this account, not enrolled.
    fn certify(&self, id: Uuid, key: DeviceKey, issued_at_ms: u64) -> Device {
        let certificate = self.identity.certify_device(
            self.user.as_bytes(),
            id.as_bytes(),
            &key.public(),
            issued_at_ms,
        );
        Device {
            user: self.user,
            id,
            key,
            certificate,
            provider: Provider::new(MemoryStorage::default()),
        }
    }

    /// A new device, enrolled.
    async fn enrol(&self, pool: &PgPool) -> Device {
        let device = self.certify(Uuid::new_v4(), DeviceKey::generate(), 0);
        sqlx::query(
            "INSERT INTO devices (id, user_id, signature_key, certificate, platform) \
             VALUES ($1, $2, $3, $4, 1)",
        )
        .bind(device.id)
        .bind(self.user)
        .bind(device.key.public().to_bytes().to_vec())
        .bind(&device.certificate)
        .execute(pool)
        .await
        .unwrap();
        device
    }
}

impl Device {
    fn leaf(&self) -> VerifiedLeaf {
        VerifiedLeaf {
            user_id: *self.user.as_bytes(),
            device_id: *self.id.as_bytes(),
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

impl Roster for Keys {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.0.get(user_id).copied()
    }
}

/// Alice and Bob's DM, created by Alice's device, joined by Bob's.
struct Dm {
    alice: Account,
    bob: Account,
    alice1: Device,
    bob1: Device,
    server: ExternalSenderKey,
    identity: GroupIdentity,
    participants: [[u8; ID_LEN]; 2],
    alice_group: Group,
    bob_group: Group,
    /// The GroupInfo of the first commit.
    first_group_info: Vec<u8>,
}

impl Dm {
    /// The DM, made on the clients, not stored yet.
    async fn made(pool: &PgPool) -> Self {
        let alice = Account::new(pool).await;
        let bob = Account::new(pool).await;
        let alice1 = alice.enrol(pool).await;
        let bob1 = bob.enrol(pool).await;
        let server = ExternalSenderKey::generate();
        let identity = GroupIdentity {
            conversation_id: *Uuid::new_v4().as_bytes(),
            generation: 0,
        };
        let participants = [*alice.user.as_bytes(), *bob.user.as_bytes()];
        let keys = Keys(
            [
                (*alice.user.as_bytes(), alice.identity.public()),
                (*bob.user.as_bytes(), bob.identity.public()),
            ]
            .into_iter()
            .collect(),
        );
        let expected = ExpectedGroup {
            identity,
            participants: &participants,
        };
        let (mut alice_group, created) = Group::create(
            &alice1.provider,
            &alice1.signer(),
            for_device(&alice1.certificate, &alice1.key.public()),
            &expected,
            &server.public_bytes(),
            &[bob1.claimed(&keys)],
            &keys,
        )
        .unwrap();
        alice_group.merge_pending_commit(&alice1.provider).unwrap();
        let bob_group = Group::join(
            &bob1.provider,
            created.welcome.as_ref().unwrap(),
            &expected,
            &keys,
            &server.public_bytes(),
        )
        .unwrap()
        .group;
        Self {
            alice,
            bob,
            alice1,
            bob1,
            server,
            identity,
            participants,
            alice_group,
            bob_group,
            first_group_info: created.group_info,
        }
    }

    /// The DM, made and stored by the server.
    async fn new(pool: &PgPool) -> Self {
        let dm = Self::made(pool).await;
        let mut tx = pool.begin().await.unwrap();
        let state = dm
            .created_state(&mut tx, &dm.first_group_info, dm.identity)
            .await;
        mls::insert(&mut tx, state).await.unwrap();
        tx.commit().await.unwrap();
        dm
    }

    async fn created_state(
        &self,
        conn: &mut sqlx::PgConnection,
        group_info: &[u8],
        identity: GroupIdentity,
    ) -> PublicState {
        let roster = self.roster(conn).await;
        let expected = ExpectedGroup {
            identity,
            participants: &self.participants,
        };
        let (state, devices) = PublicState::create(
            group_info,
            &expected,
            self.alice1.leaf(),
            &roster,
            &self.server.public_bytes(),
        )
        .unwrap();
        assert!(!devices.is_empty());
        state
    }

    fn expected(&self) -> ExpectedGroup<'_> {
        ExpectedGroup {
            identity: self.identity,
            participants: &self.participants,
        }
    }

    fn keys(&self) -> Keys {
        Keys(
            [
                (*self.alice.user.as_bytes(), self.alice.identity.public()),
                (*self.bob.user.as_bytes(), self.bob.identity.public()),
            ]
            .into_iter()
            .collect(),
        )
    }

    async fn roster(&self, conn: &mut sqlx::PgConnection) -> ServerRoster {
        ServerRoster::load(conn, &[self.alice.user, self.bob.user])
            .await
            .unwrap()
    }

    fn alice_update(&mut self) -> Commit {
        let keys = self.keys();
        self.alice_group
            .self_update(&self.alice1.provider, &self.alice1.signer(), &keys)
            .unwrap()
    }

    fn bob_update(&mut self) -> Commit {
        let keys = self.keys();
        self.bob_group
            .self_update(&self.bob1.provider, &self.bob1.signer(), &keys)
            .unwrap()
    }

    /// The server takes `commit` from `submitter` in a transaction, holding
    /// the group for `hold` before checking it, and commits the transaction
    /// or rolls it back. The new epoch, or why OpenMLS or the policy refused.
    async fn submit(
        &self,
        pool: &PgPool,
        submitter: VerifiedLeaf,
        commit: &Commit,
        hold: Duration,
        keep: bool,
    ) -> Result<(u64, Vec<Vec<u8>>), MlsError> {
        let mut tx = pool.begin().await.unwrap();
        let mut state = mls::load(&mut tx, self.identity).await.unwrap().unwrap();
        tokio::time::sleep(hold).await;
        let roster = self.roster(&mut tx).await;
        let validated = state.validate_commit(
            &commit.commit,
            &commit.group_info,
            submitter,
            &self.expected(),
            &roster,
        )?;
        let merged = state.merge(validated, &ServerSigner::new(&self.server))?;
        mls::save(&mut tx, state).await.unwrap();
        if keep {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        Ok((merged.epoch, merged.reissued))
    }

    async fn stored(&self, pool: &PgPool) -> PublicState {
        let mut conn = pool.acquire().await.unwrap();
        mls::load(&mut conn, self.identity).await.unwrap().unwrap()
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_public_state_moves_with_the_transaction_of_each_commit() {
    let pool = pool().await;
    let mut dm = Dm::new(&pool).await;
    assert_eq!(dm.stored(&pool).await.epoch(), 1);
    assert_eq!(dm.stored(&pool).await.group_info(), dm.first_group_info);

    // Accepted and committed: the next request sees epoch 2 and its
    // GroupInfo.
    let commit = dm.bob_update();
    let bob1 = dm.bob1.leaf();
    let (epoch, _) = dm
        .submit(&pool, bob1, &commit, Duration::ZERO, true)
        .await
        .unwrap();
    assert_eq!(epoch, 2);
    let stored = dm.stored(&pool).await;
    assert_eq!(
        (stored.epoch(), stored.group_info()),
        (2, &commit.group_info[..])
    );
    dm.bob_group
        .merge_pending_commit(&dm.bob1.provider)
        .unwrap();
    let keys = dm.keys();
    dm.alice_group
        .process(&dm.alice1.provider, &commit.commit, &keys)
        .unwrap();

    // Accepted, then the transaction fails: nothing moved. The retry loads
    // the group again (`save` used the state up) and goes through.
    let commit = dm.bob_update();
    dm.submit(&pool, bob1, &commit, Duration::ZERO, false)
        .await
        .unwrap();
    assert_eq!(dm.stored(&pool).await.epoch(), 2);
    let (epoch, _) = dm
        .submit(&pool, bob1, &commit, Duration::ZERO, true)
        .await
        .unwrap();
    assert_eq!(epoch, 3);
    assert_eq!(dm.stored(&pool).await.epoch(), 3, "rows and epoch agree");
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_state_loaded_before_another_commit_cannot_be_saved() {
    let pool = pool().await;
    let mut dm = Dm::new(&pool).await;
    // Loaded, then the lock released without saving.
    let mut tx = pool.begin().await.unwrap();
    let stale = mls::load(&mut tx, dm.identity).await.unwrap().unwrap();
    tx.rollback().await.unwrap();

    let commit = dm.bob_update();
    dm.submit(&pool, dm.bob1.leaf(), &commit, Duration::ZERO, true)
        .await
        .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let result = mls::save(&mut tx, stale).await;
    assert!(
        matches!(result, Err(StateError::Inconsistent)),
        "{result:?}"
    );
}

/// Section 7 and 18: one commit per epoch under concurrent submissions. The
/// second waits for the group, then finds the epoch moved.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn of_two_commits_for_one_epoch_the_second_is_stale() {
    let pool = pool().await;
    let mut dm = Dm::new(&pool).await;
    let alice = dm.alice_update();
    let bob = dm.bob_update();
    let (alice1, bob1) = (dm.alice1.leaf(), dm.bob1.leaf());

    let first = dm.submit(&pool, alice1, &alice, Duration::from_millis(400), true);
    let second = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        dm.submit(&pool, bob1, &bob, Duration::ZERO, true).await
    };
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first.unwrap().0, 2);
    assert!(
        matches!(second, Err(MlsError::Refused(Refusal::PastEpoch))),
        "{second:?}"
    );
    assert_eq!(dm.stored(&pool).await.epoch(), 2);
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_server_s_removals_go_through_save_and_load() {
    let pool = pool().await;
    let dm = Dm::new(&pool).await;
    let bob1 = dm.bob1.leaf();

    let mut tx = pool.begin().await.unwrap();
    let mut state = mls::load(&mut tx, dm.identity).await.unwrap().unwrap();
    let leaf = state.leaf_of(bob1).unwrap();
    state
        .remove(leaf, &ServerSigner::new(&dm.server))
        .unwrap()
        .unwrap();
    mls::save(&mut tx, state).await.unwrap();
    tx.commit().await.unwrap();
    let stored = dm.stored(&pool).await;
    assert_eq!(stored.pending_removals().unwrap(), [leaf]);
    assert_eq!(stored.epoch(), 1, "a proposal does not move the epoch");

    // A new device of Alice's joins by external commit: the removal is asked
    // again for epoch 2, stored, and loaded again.
    let alice2 = dm.alice.enrol(&pool).await;
    let keys = dm.keys();
    let (_, joined, _) = Group::join_by_external_commit(
        &alice2.provider,
        &alice2.signer(),
        for_device(&alice2.certificate, &alice2.key.public()),
        stored.group_info(),
        &dm.expected(),
        &keys,
        &dm.server.public_bytes(),
    )
    .unwrap();
    let (epoch, reissued) = dm
        .submit(&pool, alice2.leaf(), &joined, Duration::ZERO, true)
        .await
        .unwrap();
    assert_eq!((epoch, reissued.len()), (2, 1));
    let stored = dm.stored(&pool).await;
    assert_eq!(stored.epoch(), 2);
    assert_eq!(stored.pending_removals().unwrap(), [leaf]);
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_revoked_device_is_not_accepted_any_more() {
    let pool = pool().await;
    let mut dm = Dm::new(&pool).await;
    let commit = dm.bob_update();
    sqlx::query("UPDATE devices SET revoked_at = now() WHERE id = $1")
        .bind(dm.bob1.id)
        .execute(&pool)
        .await
        .unwrap();
    let result = dm
        .submit(&pool, dm.bob1.leaf(), &commit, Duration::ZERO, true)
        .await;
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::InactiveDevice))),
        "{result:?}"
    );
}

/// Section 2: a leaf is the enrolled device itself. The attack of the review:
/// with Bob's password, an attacker has his identity key and certifies its
/// own key under the id of Bob's second device, enrolled but not in the DM.
/// Bob's clients cannot tell; the server, which knows the key that device
/// enrolled with, refuses both an add of it and its external commit, and a
/// certificate that differs from the enrolled one.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_leaf_must_be_the_device_s_enrolled_key_and_certificate() {
    let pool = pool().await;
    let mut dm = Dm::new(&pool).await;
    let bob2 = dm.bob.enrol(&pool).await;
    let forged = dm.bob.certify(bob2.id, DeviceKey::generate(), 0);
    let recertified = dm
        .bob
        .certify(bob2.id, DeviceKey::from_seed(&bob2.key.seed()), 1);
    let keys = dm.keys();

    // Alice adds it: her client accepts what Bob's identity key certified.
    for device in [&forged, &recertified] {
        let commit = dm
            .alice_group
            .add(
                &dm.alice1.provider,
                &dm.alice1.signer(),
                &[device.claimed(&keys)],
                &keys,
            )
            .unwrap();
        let result = dm
            .submit(&pool, dm.alice1.leaf(), &commit, Duration::ZERO, true)
            .await;
        assert!(
            matches!(result, Err(MlsError::Leaf(LeafError::NotEnrolled))),
            "{result:?}"
        );
        dm.alice_group
            .discard_pending_commit(&dm.alice1.provider)
            .unwrap();
    }

    // It joins on its own by external commit.
    let stored = dm.stored(&pool).await;
    let (_, joined, _) = Group::join_by_external_commit(
        &forged.provider,
        &forged.signer(),
        for_device(&forged.certificate, &forged.key.public()),
        stored.group_info(),
        &dm.expected(),
        &keys,
        &dm.server.public_bytes(),
    )
    .unwrap();
    let result = dm
        .submit(&pool, forged.leaf(), &joined, Duration::ZERO, true)
        .await;
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::NotEnrolled))),
        "{result:?}"
    );

    // The real device, with its enrolled key and certificate, is accepted.
    let commit = dm
        .alice_group
        .add(
            &dm.alice1.provider,
            &dm.alice1.signer(),
            &[bob2.claimed(&keys)],
            &keys,
        )
        .unwrap();
    assert!(
        dm.submit(&pool, dm.alice1.leaf(), &commit, Duration::ZERO, true)
            .await
            .is_ok()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_new_generation_replaces_the_earlier_ones_which_cannot_come_back() {
    let pool = pool().await;
    let dm = Dm::new(&pool).await;
    let old_group = dm.identity.to_group_id().as_slice().to_vec();
    let conversation = Uuid::from_bytes(dm.identity.conversation_id);

    // Recreated (section 17): generation 1.
    let next = dm.identity.next().unwrap();
    let keys = dm.keys();
    let bob = dm.bob.enrol(&pool).await;
    let expected = ExpectedGroup {
        identity: next,
        participants: &dm.participants,
    };
    let (_, created) = Group::create(
        &dm.alice1.provider,
        &dm.alice1.signer(),
        for_device(&dm.alice1.certificate, &dm.alice1.key.public()),
        &expected,
        &dm.server.public_bytes(),
        &[bob.claimed(&keys)],
        &keys,
    )
    .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let state = dm.created_state(&mut tx, &created.group_info, next).await;
    mls::insert(&mut tx, state).await.unwrap();
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

    // Neither the earlier generation nor the same one can come back.
    for (info, identity) in [
        (&dm.first_group_info, dm.identity),
        (&created.group_info, next),
    ] {
        let mut tx = pool.begin().await.unwrap();
        let state = dm.created_state(&mut tx, info, identity).await;
        let result = mls::insert(&mut tx, state).await;
        assert!(
            matches!(result, Err(StateError::GenerationExists)),
            "{result:?}"
        );
    }
}

/// Sections 4 and 17: two devices create the same group at once. The second
/// waits for the first, then gets `GenerationExists`, never a database error.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn of_two_creations_at_once_the_second_finds_the_group_there() {
    let pool = pool().await;
    let dm = Dm::made(&pool).await;
    let (pool_ref, dm_ref) = (&pool, &dm);
    let create = |hold: Duration| async move {
        let (pool, dm) = (pool_ref, dm_ref);
        let mut tx = pool.begin().await.unwrap();
        let state = dm
            .created_state(&mut tx, &dm.first_group_info, dm.identity)
            .await;
        let result = mls::insert(&mut tx, state).await;
        tokio::time::sleep(hold).await;
        tx.commit().await.unwrap();
        result
    };
    let first = create(Duration::from_millis(400));
    let second = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        create(Duration::ZERO).await
    };
    let (first, second) = tokio::join!(first, second);
    assert!(first.is_ok(), "{first:?}");
    assert!(
        matches!(second, Err(StateError::GenerationExists)),
        "{second:?}"
    );

    // A writer that skipped the lock meets the unique index instead: the
    // same answer.
    let dm = Dm::made(&pool).await;
    let conversation = Uuid::from_bytes(dm.identity.conversation_id);
    let mut raw = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO mls_groups (group_id, conversation_id, generation, epoch, group_info) \
         VALUES ($1, $2, 0, 1, '\\x00')",
    )
    .bind(dm.identity.to_group_id().as_slice())
    .bind(conversation)
    .execute(&mut *raw)
    .await
    .unwrap();
    let locked = async {
        let mut tx = pool.begin().await.unwrap();
        let state = dm
            .created_state(&mut tx, &dm.first_group_info, dm.identity)
            .await;
        mls::insert(&mut tx, state).await
    };
    let release = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        raw.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(locked, release);
    assert!(
        matches!(result, Err(StateError::GenerationExists)),
        "{result:?}"
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_stored_epoch_that_disagrees_with_the_rows_is_refused() {
    let pool = pool().await;
    let dm = Dm::new(&pool).await;
    sqlx::query("UPDATE mls_groups SET epoch = 5 WHERE group_id = $1")
        .bind(dm.identity.to_group_id().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let result = mls::load(&mut conn, dm.identity).await;
    assert!(
        matches!(result, Err(StateError::Inconsistent)),
        "{result:?}"
    );
}

/// The schema refuses rows the server would not write: an unknown kind, a
/// group id that is not the conversation id and generation.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_schema_refuses_rows_the_server_would_not_write() {
    let pool = pool().await;
    let dm = Dm::new(&pool).await;
    let check_violation = |result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>| match result
    {
        Err(sqlx::Error::Database(error)) => assert_eq!(error.code().as_deref(), Some("23514")),
        other => panic!("{other:?}"),
    };
    check_violation(
        sqlx::query(
            "INSERT INTO mls_group_entries (group_id, kind, key, value) VALUES ($1, 7, '', '')",
        )
        .bind(dm.identity.to_group_id().as_slice())
        .execute(&pool)
        .await,
    );
    let other = GroupIdentity {
        conversation_id: *Uuid::new_v4().as_bytes(),
        generation: 3,
    };
    check_violation(
        sqlx::query(
            "INSERT INTO mls_groups (group_id, conversation_id, generation, epoch, group_info) \
             VALUES ($1, $2, 4, 1, '\\x00')",
        )
        .bind(other.to_group_id().as_slice())
        .bind(Uuid::from_bytes(other.conversation_id))
        .execute(&pool)
        .await,
    );
    // The right group id is accepted: the check computes it as the code does.
    sqlx::query(
        "INSERT INTO mls_groups (group_id, conversation_id, generation, epoch, group_info) \
         VALUES ($1, $2, 3, 1, '\\x00')",
    )
    .bind(other.to_group_id().as_slice())
    .bind(Uuid::from_bytes(other.conversation_id))
    .execute(&pool)
    .await
    .unwrap();
}
