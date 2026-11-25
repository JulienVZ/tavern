// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests of the MLS state in the local store (ADR 0019, section 13): the
//! scenarios of a group through [`SqlStorage`], the atomicity of an
//! operation with what is written next to it, and forward secrecy in the
//! file itself: what OpenMLS deletes leaves the file and its journal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use std::collections::HashMap;
use std::path::Path;

use tavern_crypto::identity::{
    AccountRootSecret, DeviceKey, ExternalSenderKey, ID_LEN, IdentityPublicKey,
};
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::{
    ClaimedKeyPackage, DeviceSigner, ExpectedGroup, Group, Incoming, MlsError, Provider, Roster,
    VerifiedLeaf, key_package,
};
use tavern_crypto::secret::Secret;
use uuid::Uuid;

use super::mls::SqlStorage;
use super::{Binding, DATABASE_FILE, LocalStore, LocalStoreError, StoredText, store_text};

const NOW_MS: u64 = 1_794_000_000_000;
const CONVERSATION: Uuid = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0c01);

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error(transparent)]
    Store(#[from] LocalStoreError),
    #[error(transparent)]
    Mls(#[from] MlsError),
    #[error("stopped on purpose")]
    OnPurpose,
}

/// The identity keys the devices trust.
#[derive(Clone)]
struct Keys(HashMap<[u8; ID_LEN], IdentityPublicKey>);

impl Roster for Keys {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.0.get(user_id).copied()
    }
}

struct Account {
    user_id: Uuid,
    root: AccountRootSecret,
}

impl Account {
    fn new(n: u128) -> Self {
        Self {
            user_id: Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0000 + n),
            root: AccountRootSecret::generate(),
        }
    }
}

/// A device, its store in a directory of its own.
struct Device {
    user_id: Uuid,
    device_id: Uuid,
    seed: [u8; 32],
    certificate: Vec<u8>,
    store: LocalStore,
    dir: tempfile::TempDir,
}

impl Device {
    fn new(account: &Account, n: u128, encrypted: bool) -> Self {
        let device_id = Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0d00 + n);
        let key = DeviceKey::generate();
        let identity = account.root.identity_key().unwrap();
        let certificate = identity.certify_device(
            account.user_id.as_bytes(),
            device_id.as_bytes(),
            &key.public(),
            NOW_MS,
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DATABASE_FILE);
        let binding = Binding {
            user_id: account.user_id,
            device_id,
        };
        let store = if encrypted {
            LocalStore::open(
                &path,
                &Secret::from_slice(&[7; 32]).unwrap(),
                binding,
                NOW_MS,
            )
        } else {
            LocalStore::open_unencrypted(&path, binding, NOW_MS)
        }
        .unwrap();
        Self {
            user_id: account.user_id,
            device_id,
            seed: *key.seed().expose(),
            certificate,
            store,
            dir,
        }
    }

    fn leaf(&self) -> VerifiedLeaf {
        VerifiedLeaf {
            user_id: *self.user_id.as_bytes(),
            device_id: *self.device_id.as_bytes(),
        }
    }

    /// Runs `work` with this device's key, its credential and a provider
    /// over one transaction of its store.
    async fn mls<T, F>(&self, work: F) -> Result<T, Failure>
    where
        T: Send + 'static,
        F: FnOnce(
                &Provider<SqlStorage<'_>>,
                &DeviceSigner<'_>,
                &rusqlite::Transaction<'_>,
                tavern_crypto::mls::CredentialWithKey,
            ) -> Result<T, Failure>
            + Send
            + 'static,
    {
        let seed = self.seed;
        let certificate = self.certificate.clone();
        self.store
            .transaction(move |transaction| {
                let key = DeviceKey::from_seed(&Secret::from_slice(&seed).unwrap());
                let signer = DeviceSigner::new(&key);
                let credential = for_device(&certificate, &key.public());
                let provider = Provider::new(SqlStorage::new(transaction));
                work(&provider, &signer, transaction, credential)
            })
            .await
    }

    /// A KeyPackage of this device, built in its store and claimed by a
    /// device that trusts `keys`.
    async fn claimed(&self, keys: &Keys) -> ClaimedKeyPackage {
        let bytes = self
            .mls(|provider, signer, _, credential| {
                let package = key_package::build(provider, signer, credential, false)?;
                Ok(key_package::to_bytes(&package)?)
            })
            .await
            .unwrap();
        key_package::validate_claimed(&bytes, self.leaf(), keys).unwrap()
    }

    fn database(&self) -> std::path::PathBuf {
        self.dir.path().join(DATABASE_FILE)
    }

    /// Closes the store and opens it again, as a restart of the client.
    fn reopen(&mut self) {
        self.store.close();
        self.store = LocalStore::open(
            &self.database(),
            &Secret::from_slice(&[7; 32]).unwrap(),
            Binding {
                user_id: self.user_id,
                device_id: self.device_id,
            },
            NOW_MS,
        )
        .unwrap();
    }
}

/// The DM of Alice and Bob, as its devices know it.
#[derive(Clone)]
struct Dm {
    participants: [[u8; ID_LEN]; 2],
    keys: Keys,
    external_sender: [u8; 32],
}

impl Dm {
    fn new(alice: &Account, bob: &Account) -> Self {
        let mut participants = [*alice.user_id.as_bytes(), *bob.user_id.as_bytes()];
        participants.sort();
        Self {
            participants,
            keys: Keys(
                [alice, bob]
                    .into_iter()
                    .map(|account| {
                        (
                            *account.user_id.as_bytes(),
                            account.root.identity_key().unwrap().public(),
                        )
                    })
                    .collect(),
            ),
            external_sender: ExternalSenderKey::generate().public_bytes(),
        }
    }

    fn identity() -> GroupIdentity {
        GroupIdentity {
            conversation_id: *CONVERSATION.as_bytes(),
            generation: 0,
        }
    }
}

fn expected(dm: &Dm) -> ExpectedGroup<'_> {
    ExpectedGroup {
        identity: Dm::identity(),
        participants: &dm.participants,
    }
}

fn load(provider: &Provider<SqlStorage<'_>>) -> Result<Group, Failure> {
    Ok(Group::load(provider, Dm::identity())?.expect("the group is stored"))
}

/// `creator` creates the group with `added`; its commit merged (the server
/// took it). Returns the Welcome.
async fn create(creator: &Device, dm: &Dm, added: Vec<ClaimedKeyPackage>) -> Vec<u8> {
    let dm = dm.clone();
    creator
        .mls(move |provider, signer, _, credential| {
            let (mut group, commit) = Group::create(
                provider,
                signer,
                credential,
                &expected(&dm),
                &dm.external_sender,
                &added,
                &dm.keys,
            )?;
            group.merge_pending_commit(provider)?;
            Ok(commit.welcome.unwrap())
        })
        .await
        .unwrap()
}

async fn join(device: &Device, dm: &Dm, welcome: Vec<u8>) {
    let dm = dm.clone();
    device
        .mls(move |provider, _, _, _| {
            Group::join(
                provider,
                &welcome,
                &expected(&dm),
                &dm.keys,
                &dm.external_sender,
            )?;
            Ok(())
        })
        .await
        .unwrap();
}

async fn encrypt(device: &Device, content: &'static [u8]) -> Vec<u8> {
    device
        .mls(move |provider, signer, _, _| Ok(load(provider)?.encrypt(provider, signer, content)?))
        .await
        .unwrap()
}

/// A commit of `device` that updates its own leaf, merged.
async fn self_update(device: &Device, dm: &Dm) -> tavern_crypto::mls::Commit {
    let keys = dm.keys.clone();
    device
        .mls(move |provider, signer, _, _| {
            let mut group = load(provider)?;
            let commit = group.self_update(provider, signer, &keys)?;
            group.merge_pending_commit(provider)?;
            Ok(commit)
        })
        .await
        .unwrap()
}

async fn process(device: &Device, dm: &Dm, message: Vec<u8>) -> Result<Incoming, Failure> {
    let keys = dm.keys.clone();
    device
        .mls(move |provider, _, _, _| Ok(load(provider)?.process(provider, &message, &keys)?))
        .await
}

async fn epoch(device: &Device) -> u64 {
    device
        .mls(|provider, _, _, _| Ok(load(provider)?.epoch()))
        .await
        .unwrap()
}

fn text_of(incoming: Incoming) -> Vec<u8> {
    match incoming {
        Incoming::Application { content, .. } => content.expose().to_vec(),
        other => panic!("expected a message, got {other:?}"),
    }
}

/// Section 13: a group lives in the store through every operation: its
/// creation with a Welcome, messages both ways, updates, the addition of a
/// device, an external commit, the removal of a device by its user; and
/// across a reopening of the
/// store, which keeps everything.
#[tokio::test]
async fn a_group_lives_in_the_store_through_every_operation() {
    let (alice, bob) = (Account::new(1), Account::new(2));
    let dm = Dm::new(&alice, &bob);
    let mut alice1 = Device::new(&alice, 1, true);
    let mut bob1 = Device::new(&bob, 1, true);

    let welcome = create(&alice1, &dm, vec![bob1.claimed(&dm.keys).await]).await;
    join(&bob1, &dm, welcome).await;
    let message = encrypt(&alice1, b"hello Bob").await;
    assert_eq!(
        text_of(process(&bob1, &dm, message).await.unwrap()),
        b"hello Bob"
    );

    // Bob's store closes and opens again: the group is still there. So
    // after each step below, for every device.
    bob1.reopen();
    let message = encrypt(&bob1, b"hello Alice").await;
    assert_eq!(
        text_of(process(&alice1, &dm, message).await.unwrap()),
        b"hello Alice"
    );

    // Updates both ways.
    let update = self_update(&bob1, &dm).await;
    assert!(matches!(
        process(&alice1, &dm, update.commit).await.unwrap(),
        Incoming::Commit { .. }
    ));
    let update = self_update(&alice1, &dm).await;
    assert!(matches!(
        process(&bob1, &dm, update.commit).await.unwrap(),
        Incoming::Commit { .. }
    ));
    assert_eq!(epoch(&alice1).await, epoch(&bob1).await);
    alice1.reopen();
    bob1.reopen();

    // Alice adds her second device.
    let mut alice2 = Device::new(&alice, 2, true);
    let claimed = alice2.claimed(&dm.keys).await;
    let keys = dm.keys.clone();
    let added = alice1
        .mls(move |provider, signer, _, _| {
            let mut group = load(provider)?;
            let commit = group.add(provider, signer, &[claimed], &keys)?;
            group.merge_pending_commit(provider)?;
            Ok(commit)
        })
        .await
        .unwrap();
    process(&bob1, &dm, added.commit).await.unwrap();
    join(&alice2, &dm, added.welcome.unwrap()).await;
    for device in [&mut alice1, &mut alice2, &mut bob1] {
        device.reopen();
    }

    // Bob's second device joins by external commit.
    let mut bob2 = Device::new(&bob, 2, true);
    let (group_info, dm_for_join) = (added.group_info, dm.clone());
    let external = bob2
        .mls(move |provider, signer, _, credential| {
            let (mut group, commit, _) = Group::join_by_external_commit(
                provider,
                signer,
                credential,
                &group_info,
                &expected(&dm_for_join),
                &dm_for_join.keys,
                &dm_for_join.external_sender,
            )?;
            group.merge_pending_commit(provider)?;
            Ok(commit)
        })
        .await
        .unwrap();
    for device in [&alice1, &alice2, &bob1] {
        process(device, &dm, external.commit.clone()).await.unwrap();
    }
    for device in [&mut alice1, &mut alice2, &mut bob1, &mut bob2] {
        device.reopen();
    }
    let message = encrypt(&bob2, b"from my laptop").await;
    for device in [&alice1, &alice2, &bob1] {
        assert_eq!(
            text_of(process(device, &dm, message.clone()).await.unwrap()),
            b"from my laptop"
        );
    }

    // Bob removes his first device from his second (a device of another
    // user is removed by the server only).
    let (removed, keys) = (bob1.leaf(), dm.keys.clone());
    let removal = bob2
        .mls(move |provider, signer, _, _| {
            let mut group = load(provider)?;
            let leaf = group.leaf_of(&removed.user_id, &removed.device_id).unwrap();
            let commit = group.remove(provider, signer, &[leaf], &keys)?;
            group.merge_pending_commit(provider)?;
            Ok(commit)
        })
        .await
        .unwrap();
    assert!(matches!(
        process(&bob1, &dm, removal.commit.clone()).await.unwrap(),
        Incoming::Commit {
            self_removed: true,
            ..
        }
    ));
    for device in [&alice1, &alice2] {
        process(device, &dm, removal.commit.clone()).await.unwrap();
    }
    assert_eq!(epoch(&alice2).await, epoch(&bob2).await);
}

/// Section 13: processing a message and writing its text commit or fail
/// together. A failure after OpenMLS processed the message, before the
/// transaction ends (as a crash would), leaves neither the text nor the
/// state that consumed the message's key: the same message is processed
/// again, once.
#[tokio::test]
async fn an_operation_that_fails_halfway_writes_nothing() {
    let (alice, bob) = (Account::new(1), Account::new(2));
    let dm = Dm::new(&alice, &bob);
    let alice1 = Device::new(&alice, 1, true);
    let bob1 = Device::new(&bob, 1, true);
    let welcome = create(&alice1, &dm, vec![bob1.claimed(&dm.keys).await]).await;
    join(&bob1, &dm, welcome).await;
    let message = encrypt(&alice1, b"only once").await;

    let receive = |fail: bool, seq: u64| {
        let (message, keys) = (message.clone(), dm.keys.clone());
        bob1.mls(move |provider, _, transaction, _| {
            let text = text_of(load(provider)?.process(provider, &message, &keys)?);
            store_text(
                transaction,
                &StoredText {
                    conversation: CONVERSATION,
                    seq,
                    sender_device: None,
                    sent_at_ms: NOW_MS,
                    body: &text,
                },
            )?;
            if fail {
                return Err(Failure::OnPurpose);
            }
            Ok(text)
        })
    };
    assert!(matches!(receive(true, 2).await, Err(Failure::OnPurpose)));
    let stored: i64 = bob1
        .store
        .run(|connection| {
            connection
                .query_row("SELECT count(*) FROM messages", [], |row| row.get(0))
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
    assert_eq!(stored, 0);
    // Its key was not consumed: processed now, then never again, OpenMLS
    // itself refusing it (stored under another number, it would not
    // collide in the table).
    assert_eq!(receive(false, 2).await.unwrap(), b"only once");
    assert!(matches!(receive(false, 3).await, Err(Failure::Mls(_))));
}

/// The rows of a device's MLS state.
async fn mls_rows(device: &Device) -> Vec<Vec<u8>> {
    device
        .store
        .run(|connection| {
            let mut statement = connection
                .prepare("SELECT value FROM mls_state")
                .map_err(|error| super::database(&error))?;
            let rows = statement
                .query_map([], |row| row.get(0))
                .map_err(|error| super::database(&error))?
                .collect::<Result<Vec<Vec<u8>>, _>>()
                .map_err(|error| super::database(&error))?;
            Ok(rows)
        })
        .await
        .unwrap()
}

/// The bytes of the store's files: the database and its journal.
fn file_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = std::fs::read(path).unwrap();
    for suffix in ["-wal", "-journal"] {
        let companion = path.with_file_name(format!(
            "{}{suffix}",
            path.file_name().unwrap().to_string_lossy()
        ));
        if let Ok(more) = std::fs::read(companion) {
            bytes.extend(more);
        }
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

const WINDOW: usize = 48;

/// What an operation dropped from the MLS state: the pieces of the values
/// before it that no value after it still holds. Overlapping windows, so
/// that a short secret within a value is not missed.
fn dropped(before: &[Vec<u8>], after: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut pieces = Vec::new();
    for value in before {
        for start in (0..value.len().saturating_sub(WINDOW)).step_by(WINDOW / 3) {
            let piece = &value[start..start + WINDOW];
            if !after.iter().any(|now| contains(now, piece))
                && !pieces.iter().any(|p: &Vec<u8>| p == piece)
            {
                pieces.push(piece.to_vec());
            }
        }
    }
    pieces
}

/// Asserts that what `operation` drops from `device`'s MLS state is
/// written in the file before (else the check below would prove nothing),
/// and gone from the file and its journal after, once the journal is
/// erased.
async fn erased_after<F, Fut>(device: &Device, what: &str, operation: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    device.store.erase_journal().await.unwrap();
    let before = mls_rows(device).await;
    let bytes = file_bytes(&device.database());
    operation().await;
    let after = mls_rows(device).await;
    let pieces = dropped(&before, &after);
    assert!(!pieces.is_empty(), "{what}: nothing was dropped");
    let written = pieces
        .iter()
        .filter(|piece| contains(&bytes, piece))
        .count();
    assert!(
        written * 2 > pieces.len(),
        "{what}: the dropped values were not in the file to begin with ({written} of {})",
        pieces.len()
    );
    device.store.erase_journal().await.unwrap();
    let bytes = file_bytes(&device.database());
    let left: Vec<_> = pieces
        .iter()
        .filter(|piece| contains(&bytes, piece))
        .collect();
    assert!(
        left.is_empty(),
        "{what}: {} of {} dropped pieces are still in the file",
        left.len(),
        pieces.len()
    );
}

/// Forward secrecy in the file (requirement of 2026-11-25): what OpenMLS
/// deletes is deleted, not marked, and `secure_delete` with an erased
/// journal leaves none of it in the file. The private parts of the
/// KeyPackage a Welcome used, the keys of a message once decrypted, the
/// secrets of an epoch once the next commit is merged. On a store without
/// encryption, so that the file shows what the encrypted pages hold.
#[tokio::test]
async fn what_openmls_deletes_leaves_the_file() {
    let (alice, bob) = (Account::new(1), Account::new(2));
    let dm = Dm::new(&alice, &bob);
    let alice1 = Device::new(&alice, 1, false);
    let bob1 = Device::new(&bob, 1, false);
    let claimed = bob1.claimed(&dm.keys).await;
    let welcome = create(&alice1, &dm, vec![claimed]).await;

    erased_after(&bob1, "the KeyPackage a Welcome used", || {
        join(&bob1, &dm, welcome)
    })
    .await;

    let message = encrypt(&alice1, b"read once").await;
    erased_after(&bob1, "the key of a message once decrypted", || async {
        assert_eq!(
            text_of(process(&bob1, &dm, message).await.unwrap()),
            b"read once"
        );
    })
    .await;

    let update = self_update(&alice1, &dm).await;
    erased_after(
        &bob1,
        "the secrets of an epoch, at the next commit",
        || async {
            process(&bob1, &dm, update.commit).await.unwrap();
        },
    )
    .await;
}

/// `secure_delete` (requirement of 2026-11-25): a deleted message leaves
/// no trace of its text in the file, once the journal is erased. On a
/// store without encryption, as above.
#[tokio::test]
async fn a_deleted_message_leaves_no_text_in_the_file() {
    const MARKER: &[u8] = b"MARKER-deleted-message-text-8c41f2";
    let account = Account::new(1);
    let device = Device::new(&account, 1, false);
    device
        .store
        .transaction(|transaction| {
            store_text(
                transaction,
                &StoredText {
                    conversation: CONVERSATION,
                    seq: 7,
                    sender_device: None,
                    sent_at_ms: NOW_MS,
                    body: MARKER,
                },
            )
        })
        .await
        .unwrap();
    device.store.erase_journal().await.unwrap();
    assert!(contains(&file_bytes(&device.database()), MARKER));

    assert!(device.store.delete_message(CONVERSATION, 7).await.unwrap());
    device.store.erase_journal().await.unwrap();
    assert!(!contains(&file_bytes(&device.database()), MARKER));
    assert!(!device.store.delete_message(CONVERSATION, 7).await.unwrap());
}

/// The encrypted store has `secure_delete` on.
#[tokio::test]
async fn the_store_deletes_securely() {
    let account = Account::new(1);
    let device = Device::new(&account, 1, true);
    let on: i64 = device
        .store
        .run(|connection| {
            connection
                .query_row("PRAGMA secure_delete", [], |row| row.get(0))
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap();
    assert_eq!(on, 1);
}

// --- The storage format of OpenMLS, across its upgrades --------------------------

const MLS_FIXTURE: &str = "fixtures/mls-state-v2";

fn mls_fixture(extension: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("{MLS_FIXTURE}.{extension}"))
}

fn fixture_key() -> Secret<32> {
    let bytes: Vec<u8> = (100u8..132).collect();
    Secret::from_slice(&bytes).unwrap()
}

/// What the fixture's group needs besides the store: the keys its devices
/// trust, the instance's key, and a message to read. Hex, one per line.
struct FixtureContext {
    keys: Keys,
    participants: [[u8; ID_LEN]; 2],
    external_sender: [u8; 32],
    message: Vec<u8>,
}

impl FixtureContext {
    fn encode(&self) -> String {
        let hex = data_encoding::HEXLOWER;
        let mut users: Vec<_> = self.keys.0.iter().collect();
        users.sort_by_key(|(user, _)| **user);
        let mut lines: Vec<String> = users
            .into_iter()
            .map(|(user, key)| format!("key {} {}", hex.encode(user), hex.encode(&key.to_bytes())))
            .collect();
        lines.push(format!(
            "external_sender {}",
            hex.encode(&self.external_sender)
        ));
        lines.push(format!("message {}", hex.encode(&self.message)));
        lines.join("\n") + "\n"
    }

    fn decode(text: &str) -> Self {
        let hex = data_encoding::HEXLOWER;
        let mut keys = HashMap::new();
        let (mut external_sender, mut message) = (None, None);
        for line in text.lines() {
            let fields: Vec<&str> = line.split(' ').collect();
            match fields.as_slice() {
                ["key", user, key] => {
                    let user: [u8; ID_LEN] =
                        hex.decode(user.as_bytes()).unwrap().try_into().unwrap();
                    let key = IdentityPublicKey::from_bytes(&hex.decode(key.as_bytes()).unwrap())
                        .unwrap();
                    keys.insert(user, key);
                }
                ["external_sender", key] => {
                    external_sender = Some(hex.decode(key.as_bytes()).unwrap().try_into().unwrap());
                }
                ["message", bytes] => message = Some(hex.decode(bytes.as_bytes()).unwrap()),
                _ => panic!("unexpected line in the fixture: {line}"),
            }
        }
        let mut participants: Vec<[u8; ID_LEN]> = keys.keys().copied().collect();
        participants.sort();
        Self {
            keys: Keys(keys),
            participants: participants.try_into().unwrap(),
            external_sender: external_sender.unwrap(),
            message: message.unwrap(),
        }
    }
}

/// ADR 0019, section 13: the MLS state written by the OpenMLS of the first
/// release (0.9.2), committed in the repository, still loads, and its group
/// still reads the message sent to it. Every upgrade of OpenMLS runs it: a
/// change of the storage format fails here, before any user's store.
#[tokio::test]
async fn the_mls_state_of_the_first_release_still_reads() {
    let context = FixtureContext::decode(&std::fs::read_to_string(mls_fixture("txt")).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join(DATABASE_FILE);
    std::fs::copy(mls_fixture("db"), &copy).unwrap();
    let bob = Account::new(2);
    let store = LocalStore::open(
        &copy,
        &fixture_key(),
        Binding {
            user_id: bob.user_id,
            device_id: Uuid::from_u128(0x0000_0000_0000_7000_8000_0000_0000_0d01),
        },
        NOW_MS,
    )
    .unwrap();
    let text = store
        .transaction(move |transaction| {
            let provider = Provider::new(SqlStorage::new(transaction));
            let mut group = load(&provider)?;
            assert_eq!(group.epoch(), 1);
            assert_eq!(group.devices().len(), 2);
            assert!(
                group
                    .participants_without_devices(&context.participants)
                    .is_empty()
            );
            let incoming = group.process(&provider, &context.message, &context.keys)?;
            Ok::<_, Failure>(text_of(incoming))
        })
        .await
        .unwrap();
    assert_eq!(text, b"written by the first release");
}

/// Writes the fixture above. Run once, when the storage format changes on
/// purpose (with a new fixture and its own test); never to make the test
/// above pass.
#[tokio::test]
#[ignore = "writes fixtures/mls-state-v2.*"]
async fn write_the_mls_state_of_the_first_release() {
    let db = mls_fixture("db");
    assert!(!db.exists(), "the fixture exists and is frozen");
    let (alice, bob) = (Account::new(1), Account::new(2));
    let dm = Dm::new(&alice, &bob);
    let alice1 = Device::new(&alice, 1, true);
    let bob1 = Device::new(&bob, 1, true);
    // Bob's store, with the fixture's key, where the fixture goes.
    let fixture_store = LocalStore::open(
        &db,
        &fixture_key(),
        Binding {
            user_id: bob.user_id,
            device_id: bob1.device_id,
        },
        NOW_MS,
    )
    .unwrap();
    let bob1 = Device {
        store: fixture_store,
        ..bob1
    };
    let welcome = create(&alice1, &dm, vec![bob1.claimed(&dm.keys).await]).await;
    join(&bob1, &dm, welcome).await;
    let message = encrypt(&alice1, b"written by the first release").await;
    bob1.store.erase_journal().await.unwrap();
    bob1.store.close();
    let context = FixtureContext {
        keys: dm.keys.clone(),
        participants: dm.participants,
        external_sender: dm.external_sender,
        message,
    };
    std::fs::write(mls_fixture("txt"), context.encode()).unwrap();
}

/// The rows of a device's queue of proposals.
async fn queued(device: &Device) -> i64 {
    device
        .store
        .run(|connection| {
            connection
                .query_row(
                    "SELECT count(*) FROM mls_state \
                     WHERE label IN ('QueuedProposal', 'ProposalQueueRefs')",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| super::database(&error))
        })
        .await
        .unwrap()
}

/// Review of task 10a, point 7: the queue of proposals through the store.
/// The server's `Remove` (an external proposal) is stored by the members,
/// a member's commit carries it by reference, and once merged the queue is
/// empty, its content gone from the file. On stores without encryption, to
/// read the files.
#[tokio::test]
async fn the_queue_of_proposals_goes_through_the_store() {
    use tavern_crypto::mls::{PublicState, ServerSigner};
    let (alice, bob) = (Account::new(1), Account::new(2));
    let mut dm = Dm::new(&alice, &bob);
    let server = ExternalSenderKey::generate();
    dm.external_sender = server.public_bytes();
    let alice1 = Device::new(&alice, 1, false);
    let bob1 = Device::new(&bob, 1, false);
    let bob2 = Device::new(&bob, 2, false);
    let added = vec![bob1.claimed(&dm.keys).await, bob2.claimed(&dm.keys).await];
    let for_create = dm.clone();
    let commit = alice1
        .mls(move |provider, signer, _, credential| {
            let (mut group, commit) = Group::create(
                provider,
                signer,
                credential,
                &expected(&for_create),
                &for_create.external_sender,
                &added,
                &for_create.keys,
            )?;
            group.merge_pending_commit(provider)?;
            Ok(commit)
        })
        .await
        .unwrap();
    for device in [&bob1, &bob2] {
        join(device, &dm, commit.welcome.clone().unwrap()).await;
    }

    // The server removes Bob's second device.
    let (mut state, _) = PublicState::create(
        &commit.group_info,
        &expected(&dm),
        alice1.leaf(),
        &dm.keys,
        &dm.external_sender,
    )
    .unwrap();
    let leaf = state.leaf_of(bob2.leaf()).unwrap();
    let proposal = state
        .remove(leaf, &ServerSigner::new(&server))
        .unwrap()
        .expect("a new removal");
    // Delivered to every member, the removed device included.
    for device in [&alice1, &bob1, &bob2] {
        assert!(matches!(
            process(device, &dm, proposal.clone()).await.unwrap(),
            Incoming::Proposal
        ));
        assert!(queued(device).await > 0, "stored in the queue");
    }

    // Alice commits it, by reference; once merged, nothing is queued, and
    // what the queue held left the file.
    let keys = dm.keys.clone();
    let removal = std::sync::Arc::new(std::sync::Mutex::new(None));
    let kept = std::sync::Arc::clone(&removal);
    let committer = &alice1;
    erased_after(
        &alice1,
        "the queue of proposals, once committed",
        || async move {
            let commit = committer
                .mls(move |provider, signer, _, _| {
                    let mut group = load(provider)?;
                    let commit = group
                        .commit_pending_proposals(provider, signer, &keys)?
                        .expect("the removal to commit");
                    group.merge_pending_commit(provider)?;
                    Ok(commit)
                })
                .await
                .unwrap();
            *kept.lock().unwrap() = Some(commit);
        },
    )
    .await;
    assert_eq!(queued(&alice1).await, 0);
    let removal = removal.lock().unwrap().take().unwrap();
    assert!(matches!(
        process(&bob1, &dm, removal.commit.clone()).await.unwrap(),
        Incoming::Commit { .. }
    ));
    assert_eq!(queued(&bob1).await, 0);
    assert!(matches!(
        process(&bob2, &dm, removal.commit).await.unwrap(),
        Incoming::Commit {
            self_removed: true,
            ..
        }
    ));
}

/// The labels of the rows of one group's state.
const GROUP_LABELS: [&str; 14] = [
    "MlsGroupJoinConfig",
    "OwnLeafNodes",
    "QueuedProposal",
    "ProposalQueueRefs",
    "Tree",
    "InterimTranscriptHash",
    "GroupContext",
    "ConfirmationTag",
    "GroupState",
    "MessageSecrets",
    "ResumptionPsk",
    "OwnLeafNodeIndex",
    "EpochSecrets",
    "EpochKeyPairs",
];

/// Review of task 10a, point 16: a group deleted from a device (left,
/// recreated, or its external commit refused) leaves no row of its state,
/// and nothing of it in the file.
#[tokio::test]
async fn a_deleted_group_leaves_nothing_behind() {
    let (alice, bob) = (Account::new(1), Account::new(2));
    let dm = Dm::new(&alice, &bob);
    let alice1 = Device::new(&alice, 1, false);
    let bob1 = Device::new(&bob, 1, false);
    let welcome = create(&alice1, &dm, vec![bob1.claimed(&dm.keys).await]).await;
    join(&bob1, &dm, welcome).await;
    let message = encrypt(&alice1, b"before leaving").await;
    process(&bob1, &dm, message).await.unwrap();

    erased_after(&bob1, "a deleted group", || async {
        bob1.mls(|provider, _, _, _| Ok(load(provider)?.delete(provider)?))
            .await
            .unwrap();
    })
    .await;
    let left: Vec<String> = bob1
        .store
        .run(|connection| {
            let mut statement = connection
                .prepare("SELECT label FROM mls_state")
                .map_err(|error| super::database(&error))?;
            let rows = statement
                .query_map([], |row| row.get(0))
                .map_err(|error| super::database(&error))?
                .collect::<Result<Vec<String>, _>>()
                .map_err(|error| super::database(&error))?;
            Ok(rows)
        })
        .await
        .unwrap();
    assert!(
        left.iter()
            .all(|label| !GROUP_LABELS.contains(&label.as_str())),
        "{left:?}"
    );
    assert!(
        bob1.mls(|provider, _, _, _| Ok(Group::load(provider, Dm::identity())?.is_none()))
            .await
            .unwrap()
    );
}

/// Review of task 10a, point 1, the reviewer's scenario: a one-time
/// KeyPackage built on day 0, claimed on day 85; its device is offline from
/// day 80 to day 100 (its hourly upkeep, which needs no connection, runs
/// every day), and processes the Welcome on day 100: the private parts are
/// still there, and the join works.
#[tokio::test]
async fn a_welcome_waiting_past_the_lifetime_of_its_package_still_joins() {
    use tavern_crypto::identity::DeviceKey as Key;

    use crate::key_packages::{self, Outcome};
    const DAY: u64 = 24 * 3600 * 1000;
    let (alice, bob) = (Account::new(1), Account::new(2));
    let dm = Dm::new(&alice, &bob);
    let alice1 = Device::new(&alice, 1, false);
    let bob1 = Device::new(&bob, 1, false);
    let upload = key_packages::prepare(
        &bob1.store,
        Key::from_seed(&Secret::from_slice(&bob1.seed).unwrap()),
        bob1.certificate.clone(),
        0,
        false,
        NOW_MS,
    )
    .await
    .unwrap();
    key_packages::settle(&bob1.store, &upload, Outcome::Taken, NOW_MS)
        .await
        .unwrap();
    for day in 1..80 {
        key_packages::forget_due(&bob1.store, NOW_MS + day * DAY)
            .await
            .unwrap();
    }
    // Day 85: Alice claims it and makes the Welcome.
    let claimed =
        key_package::validate_claimed(&upload.one_time[0].1, bob1.leaf(), &dm.keys).unwrap();
    let welcome = create(&alice1, &dm, vec![claimed]).await;
    // Days 80 to 100: Bob is offline; his upkeep runs.
    for day in 80..=100 {
        key_packages::forget_due(&bob1.store, NOW_MS + day * DAY)
            .await
            .unwrap();
    }
    join(&bob1, &dm, welcome).await;
    assert_eq!(epoch(&bob1).await, epoch(&alice1).await);
    let message = encrypt(&alice1, b"welcome, late").await;
    assert_eq!(
        text_of(process(&bob1, &dm, message).await.unwrap()),
        b"welcome, late"
    );
}
