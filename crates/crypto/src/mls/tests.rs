// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests of the MLS wrapper, by section of ADR 0019. OpenMLS's in-memory
//! storage stands in for the encrypted local store here only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use std::collections::HashMap;

use openmls::prelude::tls_codec::{DeserializeBytes, Serialize as _};
use openmls::prelude::{
    BasicCredential, Ciphersuite, Credential, CredentialType, CredentialWithKey, Extension,
    Extensions, ExternalProposal, KeyPackage, LeafNodeParameters, Lifetime, MlsMessageIn,
    NewSignerBundle, PURE_PLAINTEXT_WIRE_FORMAT_POLICY, Proposal, Sender, SenderExtensionIndex,
    WireFormat,
};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use proptest::prelude::*;

use super::credential::{for_device, verify_leaf, verify_members};
use super::group_id::GroupIdentity;
use super::key_package::{self, KeyPackageError, Uploader};
use super::padding::{self, BUCKETS, MAX_CONTENT, PaddingError};
use super::safety_number::{self, Party};
use super::*;
use crate::identity::{
    AccountIdentityKey, AccountRootSecret, DeviceKey, ExternalSenderKey, ID_LEN, IdentityPublicKey,
};

type TestProvider = Provider<MemoryStorage>;

// --- Fixtures ----------------------------------------------------------------------

struct Account {
    user_id: [u8; ID_LEN],
    identity: AccountIdentityKey,
}

impl Account {
    fn new(seed: u8) -> Self {
        Self {
            user_id: [seed; ID_LEN],
            identity: AccountRootSecret::generate().identity_key().unwrap(),
        }
    }

    fn public(&self) -> IdentityPublicKey {
        self.identity.public()
    }

    fn device(&self, seed: u8) -> Device {
        let key = DeviceKey::generate();
        let device_id = [seed; ID_LEN];
        let certificate = self
            .identity
            .certify_device(&self.user_id, &device_id, &key.public(), 0);
        Device {
            user_id: self.user_id,
            device_id,
            certificate,
            key,
            provider: TestProvider::default(),
        }
    }
}

struct Device {
    user_id: [u8; ID_LEN],
    device_id: [u8; ID_LEN],
    certificate: Vec<u8>,
    key: DeviceKey,
    provider: TestProvider,
}

impl Device {
    fn credential(&self) -> CredentialWithKey {
        for_device(&self.certificate, &self.key.public())
    }

    fn signer(&self) -> DeviceSigner<'_> {
        DeviceSigner::new(&self.key)
    }

    fn key_package(&self) -> KeyPackage {
        key_package::build(&self.provider, &self.signer(), self.credential(), false).unwrap()
    }

    /// This device's KeyPackage, claimed and checked by a device that trusts
    /// `roster`.
    fn claimed(&self, roster: &impl Roster) -> ClaimedKeyPackage {
        claim(self, &self.key_package(), roster)
    }

    fn leaf(&self) -> VerifiedLeaf {
        VerifiedLeaf {
            user_id: self.user_id,
            device_id: self.device_id,
        }
    }
}

/// The identity keys a device trusts, by user.
#[derive(Default, Clone)]
struct Pins(HashMap<[u8; ID_LEN], IdentityPublicKey>);

impl Pins {
    fn of(accounts: &[&Account]) -> Self {
        Self(
            accounts
                .iter()
                .map(|account| (account.user_id, account.public()))
                .collect(),
        )
    }
}

impl Roster for Pins {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.0.get(user_id).copied()
    }
}

const CONVERSATION: [u8; ID_LEN] = [0xc0; ID_LEN];
const ALICE: [u8; ID_LEN] = [1; ID_LEN];
const BOB: [u8; ID_LEN] = [2; ID_LEN];
const PARTICIPANTS: [[u8; ID_LEN]; 2] = [ALICE, BOB];

fn expected() -> ExpectedGroup<'static> {
    ExpectedGroup {
        identity: identity(),
        participants: &PARTICIPANTS,
    }
}

fn claim(device: &Device, key_package: &KeyPackage, roster: &impl Roster) -> ClaimedKeyPackage {
    key_package::validate_claimed(
        device.provider.crypto(),
        &key_package::to_bytes(key_package).unwrap(),
        device.leaf(),
        roster,
    )
    .unwrap()
}

fn identity() -> GroupIdentity {
    GroupIdentity {
        conversation_id: CONVERSATION,
        generation: 0,
    }
}

fn wire_format(bytes: &[u8]) -> WireFormat {
    MlsMessageIn::tls_deserialize_bytes(bytes)
        .unwrap()
        .0
        .wire_format()
}

/// Alice (two devices) and Bob (two devices) in one DM created by Alice's
/// first device.
struct Dm {
    alice: Account,
    bob: Account,
    server: ExternalSenderKey,
    devices: Vec<Device>,
    groups: Vec<Group>,
    pins: Pins,
}

impl Dm {
    fn new() -> Self {
        let alice = Account::new(1);
        let bob = Account::new(2);
        let server = ExternalSenderKey::generate();
        let devices = vec![
            alice.device(0xa1),
            alice.device(0xa2),
            bob.device(0xb1),
            bob.device(0xb2),
        ];
        let pins = Pins::of(&[&alice, &bob]);
        let key_packages: Vec<_> = devices[1..]
            .iter()
            .map(|device| device.claimed(&pins))
            .collect();

        let creator = &devices[0];
        let (mut first, commit) = Group::create(
            &creator.provider,
            &creator.signer(),
            creator.credential(),
            &expected(),
            &server.public_bytes(),
            &key_packages,
            &pins,
        )
        .unwrap();
        assert_eq!(wire_format(&commit.commit), WireFormat::PublicMessage);
        first.merge_pending_commit(&creator.provider).unwrap();

        let welcome = commit.welcome.unwrap();
        let mut groups = vec![first];
        for device in &devices[1..] {
            let joined = Group::join(
                &device.provider,
                &welcome,
                &expected(),
                &pins,
                &server.public_bytes(),
            )
            .unwrap();
            assert_eq!(joined.members.len(), 4);
            assert!(!joined.last_resort_used);
            groups.push(joined.group);
        }
        Self {
            alice,
            bob,
            server,
            devices,
            groups,
            pins,
        }
    }

    /// `from` sends `content`; every other device processes it.
    fn send(&mut self, from: usize, content: &[u8]) -> Vec<u8> {
        let device = &self.devices[from];
        let message = self.groups[from]
            .encrypt(&device.provider, &device.signer(), content)
            .unwrap();
        assert_eq!(wire_format(&message), WireFormat::PrivateMessage);
        for index in 0..self.devices.len() {
            if index == from {
                continue;
            }
            match self.deliver(index, &message).unwrap() {
                Incoming::Application {
                    sender,
                    content: got,
                } => {
                    assert_eq!(sender, Some(self.devices[from].leaf()));
                    assert_eq!(got.expose(), content);
                }
                other => panic!("{other:?}"),
            }
        }
        message
    }

    fn deliver(&mut self, to: usize, message: &[u8]) -> Result<Incoming, MlsError> {
        let pins = self.pins.clone();
        self.groups[to].process(&self.devices[to].provider, message, &pins)
    }

    /// Delivers to every device except `skip`.
    fn deliver_all(&mut self, message: &[u8], skip: &[usize]) -> Vec<Incoming> {
        (0..self.devices.len())
            .filter(|index| !skip.contains(index))
            .map(|index| self.deliver(index, message).unwrap())
            .collect()
    }

    fn epochs(&self) -> Vec<u64> {
        self.groups.iter().map(Group::epoch).collect()
    }
}

// --- Section 1: library and parameters ---------------------------------------------------

#[test]
fn the_parameters_are_frozen() {
    let server = ExternalSenderKey::generate();
    let create = create_config(&server.public_bytes()).unwrap();
    let join = join_config();

    assert_eq!(
        CIPHERSUITE,
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    );
    assert_eq!(create.padding_size(), 256);
    assert_eq!(join.padding_size(), 256);
    assert_eq!(create.max_past_epochs(), Some(0));
    assert_eq!(
        create.wire_format_policy(),
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY
    );
    assert_eq!(join.wire_format_policy(), PURE_PLAINTEXT_WIRE_FORMAT_POLICY);
    for ratchet in [
        create.join_config().sender_ratchet_configuration(),
        join.sender_ratchet_configuration(),
    ] {
        assert_eq!(ratchet.out_of_order_tolerance(), 16);
        assert_eq!(ratchet.maximum_forward_distance(), 1000);
    }
    assert_eq!((UPDATE_INTERVAL_DAYS, UPDATE_AFTER_MESSAGES), (7, 100));
    assert_eq!(
        (key_package::ONE_TIME_COUNT, key_package::LOW_WATERMARK),
        (20, 10)
    );
    assert_eq!(key_package::LIFETIME_SECONDS, 90 * 24 * 3600);
    assert!(create.use_ratchet_tree_extension());

    // What the groups actually have, created and joined.
    let mut dm = Dm::new();
    let instance = vec![server_external_sender(&dm.server.public_bytes())];
    for group in &mut dm.groups {
        let group = group.inner_mut();
        assert_eq!(group.ciphersuite(), CIPHERSUITE);
        assert!(matches!(
            group.past_epoch_deletion_policy(),
            openmls::prelude::PastEpochDeletionPolicy::MaxEpochs(0)
        ));
        assert_eq!(group.extensions().external_senders(), Some(&instance));
        assert_eq!(
            group.extensions().required_capabilities(),
            Some(&required_capabilities())
        );
        assert_eq!(group.configuration().padding_size(), 256);
        assert_eq!(
            group.configuration().wire_format_policy(),
            PURE_PLAINTEXT_WIRE_FORMAT_POLICY
        );
        let leaf = group.own_leaf().unwrap();
        let capabilities = leaf.capabilities();
        assert_eq!(capabilities.credentials(), &[CredentialType::Basic]);
        assert_eq!(
            capabilities.extensions(),
            &[openmls::prelude::ExtensionType::LastResort]
        );
        assert_eq!(capabilities.ciphersuites().len(), 1);
    }
}

#[test]
fn a_dm_runs_through_the_wrapper() {
    let mut dm = Dm::new();
    assert_eq!(dm.epochs(), [1, 1, 1, 1]);
    let alice2 = dm.devices[1].leaf();
    assert!(dm.groups[0].devices().contains(&alice2));

    // Every device reads every other one, its own user's included.
    dm.send(0, b"hello Bob");
    dm.send(3, b"hello Alice");
    dm.send(1, &[b'x'; 3000]);

    // An update of Bob's first device, accepted by the server.
    let device = &dm.devices[2];
    let update = dm.groups[2]
        .self_update(&device.provider, &device.signer(), &dm.pins)
        .unwrap();
    assert_eq!(wire_format(&update.commit), WireFormat::PublicMessage);
    assert!(update.welcome.is_none());
    dm.groups[2]
        .merge_pending_commit(&dm.devices[2].provider)
        .unwrap();
    for incoming in dm.deliver_all(&update.commit, &[2]) {
        assert_eq!(
            incoming,
            Incoming::Commit {
                changes: MembershipChanges::default(),
                self_removed: false,
            }
        );
    }
    assert_eq!(dm.epochs(), [2, 2, 2, 2]);

    // The server removes Bob's second device; Alice's first device commits.
    let removed = dm.groups[0]
        .leaf_of(&dm.devices[3].user_id, &dm.devices[3].device_id)
        .unwrap();
    let proposal = ExternalProposal::new_remove::<TestProvider>(
        removed,
        dm.groups[0].inner_mut().group_id().clone(),
        dm.groups[0].inner_mut().epoch(),
        &ServerSigner::new(&dm.server),
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap();
    for incoming in dm.deliver_all(&proposal, &[]) {
        assert_eq!(incoming, Incoming::Proposal);
    }
    let device = &dm.devices[0];
    let commit = dm.groups[0]
        .commit_pending_proposals(&device.provider, &device.signer(), &dm.pins)
        .unwrap()
        .expect("the removal is pending");
    dm.groups[0]
        .merge_pending_commit(&dm.devices[0].provider)
        .unwrap();
    let bob2 = dm.devices[3].leaf();
    for (index, incoming) in [(1, false), (2, false), (3, true)] {
        let got = dm.deliver(index, &commit.commit).unwrap();
        assert_eq!(
            got,
            Incoming::Commit {
                changes: MembershipChanges {
                    added: Vec::new(),
                    removed: vec![bob2],
                },
                self_removed: incoming,
            }
        );
    }
    assert_eq!(dm.groups[0].devices().len(), 3);
    assert_eq!(
        dm.groups[0].identity().unwrap(),
        identity(),
        "group id = conversation id and generation"
    );
}

#[test]
fn a_key_package_of_another_ciphersuite_is_refused() {
    let alice = Account::new(1);
    let other = alice.device(2);
    let foreign = KeyPackage::builder()
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            &other.provider,
            &other.signer(),
            other.credential(),
        )
        .unwrap();
    // Only a ClaimedKeyPackage can be added to a group, and the claim
    // refuses it.
    let result = key_package::validate_claimed(
        other.provider.crypto(),
        &bytes(foreign.key_package()),
        other.leaf(),
        &Pins::of(&[&alice]),
    );
    assert_eq!(result.unwrap_err(), KeyPackageError::WrongCiphersuite);
}

#[test]
fn a_welcome_with_another_external_sender_is_refused() {
    let alice = Account::new(1);
    let (creator, joiner) = (alice.device(1), alice.device(2));
    let rogue = ExternalSenderKey::generate();
    let pins = Pins::of(&[&alice]);
    let only_alice = ExpectedGroup {
        identity: identity(),
        participants: &[ALICE],
    };
    let (_, commit) = Group::create(
        &creator.provider,
        &creator.signer(),
        creator.credential(),
        &only_alice,
        &rogue.public_bytes(),
        &[joiner.claimed(&pins)],
        &pins,
    )
    .unwrap();
    let instance = ExternalSenderKey::generate();
    let result = Group::join(
        &joiner.provider,
        &commit.welcome.unwrap(),
        &only_alice,
        &pins,
        &instance.public_bytes(),
    );
    assert!(matches!(result, Err(MlsError::Parameters)), "{result:?}");
}

// --- Section 2: credentials ----------------------------------------------------------------

fn basic(certificate: &[u8]) -> Credential {
    BasicCredential::new(certificate.to_vec()).into()
}

#[test]
fn a_leaf_is_accepted_only_with_a_verified_certificate_of_its_key() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let device = alice.device(0xa1);
    let pins = Pins::of(&[&alice, &bob]);
    let key = device.key.public().to_bytes();
    let certificate = basic(&device.certificate);

    assert_eq!(verify_leaf(&certificate, &key, &pins), Ok(device.leaf()));

    let x509 = Credential::new(CredentialType::X509, device.certificate.clone());
    assert_eq!(verify_leaf(&x509, &key, &pins), Err(LeafError::NotBasic));
    assert_eq!(
        verify_leaf(&basic(b"not a certificate"), &key, &pins),
        Err(LeafError::Malformed)
    );
    assert_eq!(
        verify_leaf(&certificate, &key, &Pins::of(&[&bob])),
        Err(LeafError::NotParticipant)
    );
    let v2 = alice.identity.certify_device_with_version(
        2,
        &alice.user_id,
        &device.device_id,
        &device.key.public(),
    );
    assert_eq!(
        verify_leaf(&basic(&v2), &key, &pins),
        Err(LeafError::UnsupportedVersion)
    );
    // Signed by another identity key than the one pinned for Alice.
    let impostor = Account::new(1);
    let forged = impostor.device(0xa1);
    assert_eq!(
        verify_leaf(
            &basic(&forged.certificate),
            &forged.key.public().to_bytes(),
            &pins
        ),
        Err(LeafError::Untrusted)
    );
    // Alice's certificate on another key.
    let other_key = DeviceKey::generate().public().to_bytes();
    assert_eq!(
        verify_leaf(&certificate, &other_key, &pins),
        Err(LeafError::KeyMismatch)
    );
}

#[test]
fn a_device_cannot_have_two_leaves() {
    let alice = Account::new(1);
    let first = alice.device(0xa1);
    // Same device id, another key and certificate.
    let twin = alice.device(0xa1);
    let pins = Pins::of(&[&alice]);
    let (c1, c2) = (basic(&first.certificate), basic(&twin.certificate));
    let (k1, k2) = (first.key.public().to_bytes(), twin.key.public().to_bytes());

    assert_eq!(
        verify_members([(&c1, k1.as_slice()), (&c2, k2.as_slice())], &pins),
        Err(LeafError::DuplicateDevice)
    );
}

#[test]
fn an_update_may_not_swap_the_leaf_for_another_device() {
    let mut dm = Dm::new();
    let replacement = dm.alice.device(0xa9);
    let device = &dm.devices[0];
    let bundle = dm.groups[0]
        .inner_mut()
        .self_update_with_new_signer(
            &device.provider,
            &device.signer(),
            NewSignerBundle {
                signer: &replacement.signer(),
                credential_with_key: replacement.credential(),
            },
            LeafNodeParameters::default(),
        )
        .unwrap();
    let commit = bundle.into_commit().tls_serialize_detached().unwrap();
    let before = dm.groups[1].epoch();

    let result = dm.deliver(1, &commit);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Leaf(LeafError::DeviceChanged)))
        ),
        "{result:?}"
    );
    assert!(result.unwrap_err().is_alarm());
    assert_eq!(dm.groups[1].epoch(), before, "not merged");
}

// --- Section 3: KeyPackages ------------------------------------------------------------

fn uploader(account: &Account, device: &Device) -> Uploader {
    Uploader {
        user_id: account.user_id,
        device_id: device.device_id,
        identity_key: account.public(),
    }
}

fn bytes(key_package: &KeyPackage) -> Vec<u8> {
    key_package::to_bytes(key_package).unwrap()
}

#[test]
fn key_packages_last_ninety_days_and_say_whether_they_are_last_resort() {
    let alice = Account::new(1);
    let device = alice.device(1);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for last_resort in [false, true] {
        let package = key_package::build(
            &device.provider,
            &device.signer(),
            device.credential(),
            last_resort,
        )
        .unwrap();
        assert_eq!(package.last_resort(), last_resort);
        assert_eq!(package.ciphersuite(), CIPHERSUITE);
        let not_after = package.life_time().not_after();
        assert!(not_after.abs_diff(now + key_package::LIFETIME_SECONDS) < 60);
    }
}

#[test]
fn the_server_accepts_a_device_s_own_valid_key_packages() {
    let alice = Account::new(1);
    let device = alice.device(1);
    let crypto = device.provider.crypto();
    let who = uploader(&alice, &device);
    let one_time = device.key_package();
    let last_resort = key_package::build(
        &device.provider,
        &device.signer(),
        device.credential(),
        true,
    )
    .unwrap();

    assert!(key_package::validate_upload(crypto, &bytes(&one_time), &who, false).is_ok());
    let result = key_package::validate_upload(crypto, &bytes(&last_resort), &who, true);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        key_package::validate_upload(crypto, &bytes(&one_time), &who, true).unwrap_err(),
        KeyPackageError::LastResortMismatch
    );
    assert_eq!(
        key_package::validate_upload(crypto, &bytes(&last_resort), &who, false).unwrap_err(),
        KeyPackageError::LastResortMismatch
    );
}

#[test]
fn the_server_refuses_foreign_expired_or_malformed_key_packages() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let device = alice.device(1);
    let crypto = device.provider.crypto();
    let who = uploader(&alice, &device);
    let check =
        |bytes: &[u8]| key_package::validate_upload(crypto, bytes, &who, false).unwrap_err();

    assert_eq!(check(b"garbage"), KeyPackageError::Malformed);
    assert_eq!(
        check(&[0u8; key_package::MAX_SIZE + 1]),
        KeyPackageError::Malformed
    );
    let mut trailing = bytes(&device.key_package());
    trailing.push(0);
    assert_eq!(check(&trailing), KeyPackageError::Malformed);

    // Another device of the same account.
    let sibling = alice.device(2);
    assert_eq!(
        check(&bytes(&sibling.key_package())),
        KeyPackageError::WrongDevice
    );
    // A device of another account.
    let stranger = bob.device(1);
    assert_eq!(
        check(&bytes(&stranger.key_package())),
        KeyPackageError::Leaf(LeafError::NotParticipant)
    );

    let other_suite = KeyPackage::builder()
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            &device.provider,
            &device.signer(),
            device.credential(),
        )
        .unwrap();
    assert_eq!(
        check(&bytes(other_suite.key_package())),
        KeyPackageError::WrongCiphersuite
    );

    let expired = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(1_000, 2_000))
        .build(
            CIPHERSUITE,
            &device.provider,
            &device.signer(),
            device.credential(),
        )
        .unwrap();
    assert!(matches!(
        check(&bytes(expired.key_package())),
        KeyPackageError::Invalid(_)
    ));

    let too_long = KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(200 * 24 * 3600))
        .build(
            CIPHERSUITE,
            &device.provider,
            &device.signer(),
            device.credential(),
        )
        .unwrap();
    assert_eq!(
        check(&bytes(too_long.key_package())),
        KeyPackageError::LifetimeTooLong
    );
}

// --- Section 6: external proposals and external senders ---------------------------------

#[test]
fn the_server_may_propose_removals_only() {
    let mut dm = Dm::new();
    let add = ExternalProposal::new_add::<TestProvider>(
        dm.bob.device(0xb9).key_package(),
        dm.groups[0].inner_mut().group_id().clone(),
        dm.groups[0].inner_mut().epoch(),
        &ServerSigner::new(&dm.server),
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap();

    let result = dm.deliver(1, &add);
    assert!(
        matches!(
            result,
            Err(MlsError::Policy(PolicyError::ExternalProposalNotRemove))
        ),
        "{result:?}"
    );
    assert_eq!(dm.groups[1].inner_mut().pending_proposals().count(), 0);
}

#[test]
fn a_proposal_signed_by_an_unknown_external_key_is_refused() {
    let mut dm = Dm::new();
    let removed = dm.groups[0]
        .leaf_of(&dm.devices[3].user_id, &dm.devices[3].device_id)
        .unwrap();
    let rogue = ExternalSenderKey::generate();
    let proposal = ExternalProposal::new_remove::<TestProvider>(
        removed,
        dm.groups[0].inner_mut().group_id().clone(),
        dm.groups[0].inner_mut().epoch(),
        &ServerSigner::new(&rogue),
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap();

    let result = dm.deliver(1, &proposal);
    assert!(
        matches!(result, Err(MlsError::Refused(Refusal::InvalidSignature))),
        "{result:?}"
    );
    assert_eq!(dm.groups[1].inner_mut().pending_proposals().count(), 0);
}

#[test]
fn nobody_may_change_the_external_senders() {
    let mut dm = Dm::new();
    let current = dm.groups[0].inner_mut().extensions().clone();
    let rogue = ExternalSenderKey::generate();
    let changed = Extensions::from_vec(
        current
            .iter()
            .map(|extension| match extension {
                Extension::ExternalSenders(_) => {
                    Extension::ExternalSenders(vec![server_external_sender(&rogue.public_bytes())])
                }
                other => other.clone(),
            })
            .collect(),
    )
    .unwrap();

    // A commit that changes them is an alarm, and is not merged.
    let device = &dm.devices[0];
    let (commit, _, _) = dm.groups[0]
        .inner_mut()
        .update_group_context_extensions(&device.provider, changed, &device.signer())
        .unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let before = dm.groups[2].epoch();
    let result = dm.deliver(2, &commit);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Policy(
                PolicyError::ExternalSendersChange
            )))
        ),
        "{result:?}"
    );
    assert_eq!(dm.groups[2].epoch(), before);

    // One that keeps them is accepted.
    let device = &dm.devices[0];
    dm.groups[0]
        .discard_pending_commit(&device.provider)
        .unwrap();
    let (commit, _, _) = dm.groups[0]
        .inner_mut()
        .update_group_context_extensions(&device.provider, current, &device.signer())
        .unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    assert!(matches!(
        dm.deliver(2, &commit).unwrap(),
        Incoming::Commit { .. }
    ));
}

// --- Section 5: external commits ------------------------------------------------------------

/// The GroupInfo of the current epoch, as the server keeps it.
fn group_info(dm: &mut Dm, from: usize) -> Vec<u8> {
    let device = &dm.devices[from];
    dm.groups[from]
        .inner_mut()
        .export_group_info(device.provider.crypto(), &device.signer(), true)
        .unwrap()
        .tls_serialize_detached()
        .unwrap()
}

/// A device of `account` with id `device_id`, whose certificate (signed by
/// `account`) certifies the key of `key_of`.
fn device_with_key_of(account: &Account, device_id: u8, key_of: &Device) -> Device {
    let key = DeviceKey::from_seed(&key_of.key.seed());
    let device_id = [device_id; ID_LEN];
    let certificate =
        account
            .identity
            .certify_device(&account.user_id, &device_id, &key.public(), 0);
    Device {
        user_id: account.user_id,
        device_id,
        certificate,
        key,
        provider: TestProvider::default(),
    }
}

fn join_externally(dm: &mut Dm, joiner: &Device) -> Result<(Group, Commit), MlsError> {
    let info = group_info(dm, 0);
    Group::join_by_external_commit(
        &joiner.provider,
        &joiner.signer(),
        joiner.credential(),
        &info,
        &expected(),
        &dm.pins,
        &dm.server.public_bytes(),
    )
    .map(|(group, commit, members)| {
        assert!(members.contains(&joiner.leaf()));
        (group, commit)
    })
}

#[test]
fn a_new_device_joins_by_external_commit() {
    let mut dm = Dm::new();
    let bob3 = dm.bob.device(0xb3);
    let (group, commit) = join_externally(&mut dm, &bob3).unwrap();
    assert_eq!(wire_format(&commit.commit), WireFormat::PublicMessage);
    assert!(commit.welcome.is_none());

    for incoming in dm.deliver_all(&commit.commit, &[]) {
        assert_eq!(
            incoming,
            Incoming::Commit {
                changes: MembershipChanges {
                    added: vec![bob3.leaf()],
                    removed: Vec::new(),
                },
                self_removed: false,
            }
        );
    }
    dm.devices.push(bob3);
    dm.groups.push(group);
    assert_eq!(dm.epochs(), [2, 2, 2, 2, 2]);
    dm.send(0, b"welcome, new device");
    dm.send(4, b"thanks");
}

#[test]
fn a_device_that_lost_its_state_resyncs_by_external_commit() {
    let mut dm = Dm::new();
    // Bob's second device, same key and certificate, empty storage.
    let lost = &dm.devices[3];
    let fresh = Device {
        user_id: lost.user_id,
        device_id: lost.device_id,
        certificate: lost.certificate.clone(),
        key: DeviceKey::from_seed(&lost.key.seed()),
        provider: TestProvider::default(),
    };
    let (group, commit) = join_externally(&mut dm, &fresh).unwrap();

    for incoming in dm.deliver_all(&commit.commit, &[3]) {
        assert_eq!(
            incoming,
            Incoming::Commit {
                changes: MembershipChanges {
                    added: vec![fresh.leaf()],
                    removed: vec![fresh.leaf()],
                },
                self_removed: false,
            }
        );
    }
    dm.devices[3] = fresh;
    dm.groups[3] = group;
    assert_eq!(dm.groups[0].devices().len(), 4);
    dm.send(3, b"back");
}

#[test]
fn an_external_commit_may_not_remove_another_device_of_its_user() {
    let mut dm = Dm::new();
    // Certified by Bob as a new device, with the key of Bob's first device:
    // OpenMLS takes the external commit for a resync and removes that leaf.
    let joiner = device_with_key_of(&dm.bob, 0xb3, &dm.devices[2]);
    let (_, commit) = join_externally(&mut dm, &joiner).unwrap();

    let before = dm.groups[0].epoch();
    let result = dm.deliver(0, &commit.commit);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Policy(
                PolicyError::ExternalCommitContent
            )))
        ),
        "{result:?}"
    );
    assert_eq!(dm.groups[0].epoch(), before, "not merged");
}

#[test]
fn an_external_commit_may_not_remove_a_device_of_another_user() {
    let mut dm = Dm::new();
    let joiner = device_with_key_of(&dm.bob, 0xb3, &dm.devices[1]);
    let (_, commit) = join_externally(&mut dm, &joiner).unwrap();

    let result = dm.deliver(0, &commit.commit);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Policy(
                PolicyError::ExternalCommitContent
            )))
        ),
        "{result:?}"
    );
    assert_eq!(dm.groups[0].devices().len(), 4);
}

// --- Section 6: proposals and removals from members -------------------------------------

#[test]
fn members_may_not_send_proposals_on_their_own() {
    let mut dm = Dm::new();
    // Bob's first device proposes, alone, an Add of an unpinned device.
    let intruder = Account::new(2).device(0xb7);
    let device = &dm.devices[2];
    let (proposal, _) = dm.groups[2]
        .inner_mut()
        .propose_add_member(&device.provider, &device.signer(), &intruder.key_package())
        .unwrap();
    let proposal = proposal.tls_serialize_detached().unwrap();
    let result = dm.deliver(0, &proposal);
    assert!(
        matches!(result, Err(MlsError::Policy(PolicyError::MemberProposal))),
        "{result:?}"
    );
    assert!(!result.unwrap_err().is_alarm(), "dropped, not an alarm");
    assert_eq!(dm.groups[0].inner_mut().pending_proposals().count(), 0);

    // When Alice's first device later commits the server's removal, the
    // commit carries that removal and nothing else.
    let removed = dm.groups[0]
        .leaf_of(&dm.devices[3].user_id, &dm.devices[3].device_id)
        .unwrap();
    let server_remove = server_remove(&mut dm, removed);
    dm.deliver(0, &server_remove).unwrap();
    let device = &dm.devices[0];
    let commit = dm.groups[0]
        .commit_pending_proposals(&device.provider, &device.signer(), &dm.pins)
        .unwrap()
        .unwrap();
    assert!(commit.welcome.is_none(), "nobody is added");
    let staged = dm.groups[0].inner_mut().pending_commit().unwrap();
    let proposals: Vec<_> = staged.queued_proposals().collect();
    assert_eq!(proposals.len(), 1);
    assert!(matches!(proposals[0].proposal(), Proposal::Remove(_)));
    assert!(matches!(proposals[0].sender(), Sender::External(_)));
}

fn server_remove(dm: &mut Dm, removed: openmls::prelude::LeafNodeIndex) -> Vec<u8> {
    ExternalProposal::new_remove::<TestProvider>(
        removed,
        dm.groups[0].inner_mut().group_id().clone(),
        dm.groups[0].inner_mut().epoch(),
        &ServerSigner::new(&dm.server),
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap()
}

#[test]
fn a_commit_that_refers_to_a_refused_proposal_raises_the_alarm() {
    let mut dm = Dm::new();
    let intruder = Account::new(2).device(0xb7);
    let device = &dm.devices[2];
    let (proposal, _) = dm.groups[2]
        .inner_mut()
        .propose_add_member(&device.provider, &device.signer(), &intruder.key_package())
        .unwrap();
    let proposal = proposal.tls_serialize_detached().unwrap();
    assert!(dm.deliver(0, &proposal).is_err());

    // Bob's device commits its own proposal, by reference.
    let device = &dm.devices[2];
    let (commit, _, _) = dm.groups[2]
        .inner_mut()
        .commit_to_pending_proposals(&device.provider, &device.signer())
        .unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let result = dm.deliver(0, &commit);
    assert!(
        matches!(result, Err(MlsError::Alarm(Alarm::UnknownProposal))),
        "{result:?}"
    );
    assert!(result.unwrap_err().is_alarm());
}

#[test]
fn proposals_tavern_never_uses_are_refused_in_commits() {
    use openmls::prelude::PreSharedKeyProposal;
    use openmls::schedule::{ExternalPsk, PreSharedKeyId, Psk};

    let mut dm = Dm::new();
    let psk = PreSharedKeyId::new(
        CIPHERSUITE,
        dm.devices[2].provider.rand(),
        Psk::External(ExternalPsk::new(b"shared".to_vec())),
    )
    .unwrap();
    for index in [0, 2] {
        psk.store(&dm.devices[index].provider, &[7; 32]).unwrap();
    }
    let device = &dm.devices[2];
    let bundle = dm.groups[2]
        .inner_mut()
        .commit_builder()
        .add_proposal(Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(
            psk,
        ))))
        .load_psks(device.provider.storage())
        .unwrap()
        .build(
            device.provider.rand(),
            device.provider.crypto(),
            &device.signer(),
            |_| true,
        )
        .unwrap()
        .stage_commit(&device.provider)
        .unwrap();
    let commit = bundle.into_commit().tls_serialize_detached().unwrap();

    let result = dm.deliver(0, &commit);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Policy(
                PolicyError::ForbiddenProposal
            )))
        ),
        "{result:?}"
    );
}

#[test]
fn a_member_removes_its_own_devices_or_those_the_server_asked_for() {
    let mut dm = Dm::new();
    let bob2 = dm.groups[0]
        .leaf_of(&dm.devices[3].user_id, &dm.devices[3].device_id)
        .unwrap();
    let alice2 = dm.groups[0]
        .leaf_of(&dm.devices[1].user_id, &dm.devices[1].device_id)
        .unwrap();

    // Alice may not remove Bob's device on her own.
    let device = &dm.devices[0];
    let result = dm.groups[0].remove(&device.provider, &device.signer(), &[bob2], &dm.pins);
    assert!(
        matches!(result, Err(MlsError::Policy(PolicyError::RemoveNotAllowed))),
        "{result:?}"
    );
    assert!(dm.groups[0].inner_mut().pending_commit().is_none());

    // A commit that does it anyway is an alarm for the others.
    let device = &dm.devices[0];
    let (commit, _, _) = dm.groups[0]
        .inner_mut()
        .remove_members(&device.provider, &device.signer(), &[bob2])
        .unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let result = dm.deliver(2, &commit);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Policy(
                PolicyError::RemoveNotAllowed
            )))
        ),
        "{result:?}"
    );
    let device = &dm.devices[0];
    dm.groups[0]
        .discard_pending_commit(&device.provider)
        .unwrap();

    // Once the server asked for it, she may.
    let request = server_remove(&mut dm, bob2);
    dm.deliver_all(&request, &[]);
    let device = &dm.devices[0];
    let commit = dm.groups[0]
        .remove(&device.provider, &device.signer(), &[bob2], &dm.pins)
        .unwrap();
    let device = &dm.devices[0];
    dm.groups[0].merge_pending_commit(&device.provider).unwrap();
    assert!(matches!(
        dm.deliver(2, &commit.commit).unwrap(),
        Incoming::Commit { .. }
    ));

    // And she may always remove her own other device.
    let device = &dm.devices[0];
    let commit = dm.groups[0]
        .remove(&device.provider, &device.signer(), &[alice2], &dm.pins)
        .unwrap();
    let device = &dm.devices[0];
    dm.groups[0].merge_pending_commit(&device.provider).unwrap();
    let alice2_leaf = dm.devices[1].leaf();
    assert_eq!(
        dm.deliver(2, &commit.commit).unwrap(),
        Incoming::Commit {
            changes: MembershipChanges {
                added: Vec::new(),
                removed: vec![alice2_leaf],
            },
            self_removed: false,
        }
    );
}

/// Section 6: removals come first. Whatever this device commits while a
/// removal requested by the server is pending carries it: merging a commit
/// empties the store, so a commit that left it out would lose it.
#[test]
fn every_commit_carries_the_server_s_pending_removals() {
    #[derive(Debug, Clone, Copy)]
    enum Operation {
        Update,
        Add,
        RemoveOwnDevice,
        RemoveRequested,
    }
    for operation in [
        Operation::Update,
        Operation::Add,
        Operation::RemoveOwnDevice,
        Operation::RemoveRequested,
    ] {
        let mut dm = Dm::new();
        let bob2 = dm.devices[3].leaf();
        let bob2_index = dm.groups[0]
            .leaf_of(&bob2.user_id, &bob2.device_id)
            .unwrap();
        let request = server_remove(&mut dm, bob2_index);
        for incoming in dm.deliver_all(&request, &[]) {
            assert_eq!(incoming, Incoming::Proposal);
        }

        let alice2 = dm.devices[1].leaf();
        let alice2_index = dm.groups[0]
            .leaf_of(&alice2.user_id, &alice2.device_id)
            .unwrap();
        let bob3 = dm.bob.device(0xb3);
        let device = &dm.devices[0];
        let (provider, signer) = (&device.provider, device.signer());
        let group = &mut dm.groups[0];
        let (commit, mut expected) = match operation {
            Operation::Update => (
                group.self_update(provider, &signer, &dm.pins).unwrap(),
                MembershipChanges {
                    added: vec![],
                    removed: vec![bob2],
                },
            ),
            Operation::Add => (
                group
                    .add(provider, &signer, &[bob3.claimed(&dm.pins)], &dm.pins)
                    .unwrap(),
                MembershipChanges {
                    added: vec![bob3.leaf()],
                    removed: vec![bob2],
                },
            ),
            Operation::RemoveOwnDevice => (
                group
                    .remove(provider, &signer, &[alice2_index], &dm.pins)
                    .unwrap(),
                MembershipChanges {
                    added: vec![],
                    removed: vec![bob2, alice2],
                },
            ),
            // Not twice: once, by reference.
            Operation::RemoveRequested => (
                group
                    .remove(provider, &signer, &[bob2_index], &dm.pins)
                    .unwrap(),
                MembershipChanges {
                    added: vec![],
                    removed: vec![bob2],
                },
            ),
        };
        let staged = group.inner_mut().pending_commit().unwrap();
        let by_reference: Vec<_> = staged
            .queued_proposals()
            .filter(|queued| {
                queued.proposal_or_ref_type() == openmls::prelude::ProposalOrRefType::Reference
            })
            .collect();
        assert_eq!(by_reference.len(), 1, "{operation:?}");
        assert!(matches!(by_reference[0].sender(), Sender::External(_)));
        dm.groups[0]
            .merge_pending_commit(&dm.devices[0].provider)
            .unwrap();

        expected.removed.sort_by_key(|leaf| leaf.device_id);
        for index in [1, 2, 3] {
            match dm.deliver(index, &commit.commit) {
                Ok(Incoming::Commit {
                    mut changes,
                    self_removed,
                }) => {
                    changes.removed.sort_by_key(|leaf| leaf.device_id);
                    assert_eq!(changes, expected, "{operation:?}");
                    let gone = expected.removed.contains(&dm.devices[index].leaf());
                    assert_eq!(self_removed, gone, "{operation:?}");
                }
                other => panic!("{operation:?}: {other:?}"),
            }
        }
        assert!(!dm.groups[0].devices().contains(&bob2), "{operation:?}");
        assert_eq!(dm.groups[0].inner_mut().pending_proposals().count(), 0);
        assert!(
            dm.groups[0]
                .commit_pending_proposals(
                    &dm.devices[0].provider,
                    &dm.devices[0].signer(),
                    &dm.pins
                )
                .unwrap()
                .is_none(),
            "nothing left to commit"
        );
    }
}

/// An external commit cannot carry the server's removals (the joining
/// device does not have them, and may not refer to them): merging it
/// empties the members' stores, and the server has to ask again in the new
/// epoch (ADR 0019, section 6).
#[test]
fn an_external_commit_leaves_the_server_s_removals_to_be_asked_again() {
    let mut dm = Dm::new();
    let bob2 = dm.devices[3].leaf();
    let bob2_index = dm.groups[0]
        .leaf_of(&bob2.user_id, &bob2.device_id)
        .unwrap();
    let request = server_remove(&mut dm, bob2_index);
    dm.deliver_all(&request, &[]);

    let alice3 = dm.alice.device(0xa3);
    let (_, commit) = join_externally(&mut dm, &alice3).unwrap();
    for incoming in dm.deliver_all(&commit.commit, &[]) {
        assert_eq!(
            incoming,
            Incoming::Commit {
                changes: MembershipChanges {
                    added: vec![alice3.leaf()],
                    removed: vec![],
                },
                self_removed: false,
            }
        );
    }
    assert!(dm.groups[0].devices().contains(&bob2));
    assert_eq!(dm.groups[0].inner_mut().pending_proposals().count(), 0);
}

#[test]
fn devices_are_told_apart_by_user_and_device_id() {
    let mut dm = Dm::new();
    // Alice certifies a device whose id is the id of Bob's first device.
    let bob1 = dm.devices[2].leaf();
    let lookalike = dm.alice.device(bob1.device_id[0]);
    assert_eq!(lookalike.device_id, bob1.device_id);

    let claimed = lookalike.claimed(&dm.pins);
    let device = &dm.devices[0];
    let commit = dm.groups[0]
        .add(&device.provider, &device.signer(), &[claimed], &dm.pins)
        .unwrap();
    assert!(commit.welcome.is_some(), "not taken for Bob's device");
    let device = &dm.devices[0];
    dm.groups[0].merge_pending_commit(&device.provider).unwrap();
    assert_eq!(
        dm.groups[0].leaf_of(&bob1.user_id, &bob1.device_id),
        dm.groups[2].leaf_of(&bob1.user_id, &bob1.device_id),
    );
    assert_ne!(
        dm.groups[0].leaf_of(&bob1.user_id, &bob1.device_id),
        dm.groups[0].leaf_of(&lookalike.user_id, &lookalike.device_id),
    );
}

// --- Other refusals, conflicts and own commits ---------------------------------------------

#[test]
fn a_welcome_for_a_group_id_that_is_not_tavern_s_is_refused() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let server = ExternalSenderKey::generate();
    let pins = Pins::of(&[&alice, &bob]);
    let creator = alice.device(0xa1);
    let joiner = bob.device(0xb1);
    let config = create_config(&server.public_bytes()).unwrap();
    let mut group = openmls::prelude::MlsGroup::new_with_group_id(
        &creator.provider,
        &creator.signer(),
        &config,
        openmls::prelude::GroupId::from_slice(b"short"),
        creator.credential(),
    )
    .unwrap();
    let (_, welcome, _) = group
        .add_members(
            &creator.provider,
            &creator.signer(),
            &[joiner.key_package()],
        )
        .unwrap();
    let result = Group::join(
        &joiner.provider,
        &welcome.tls_serialize_detached().unwrap(),
        &expected(),
        &pins,
        &server.public_bytes(),
    );
    assert!(
        matches!(result, Err(MlsError::UnexpectedGroup)),
        "{result:?}"
    );
}

#[test]
fn a_commit_giving_a_device_two_leaves_raises_the_alarm() {
    let mut dm = Dm::new();
    // Another leaf for Bob's first device (same user and device ids).
    let twin = dm.bob.device(0xb1);
    let device = &dm.devices[0];
    let (commit, _, _) = dm.groups[0]
        .inner_mut()
        .add_members(&device.provider, &device.signer(), &[twin.key_package()])
        .unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let result = dm.deliver(3, &commit);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Leaf(LeafError::DuplicateDevice)))
        ),
        "{result:?}"
    );
}

#[test]
fn external_join_proposals_are_refused() {
    let mut dm = Dm::new();
    let bob3 = dm.bob.device(0xb3);
    let proposal = openmls::prelude::JoinProposal::new::<MemoryStorage>(
        bob3.key_package(),
        dm.groups[0].inner_mut().group_id().clone(),
        dm.groups[0].inner_mut().epoch(),
        &bob3.signer(),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap();
    let result = dm.deliver(0, &proposal);
    assert!(
        matches!(
            result,
            Err(MlsError::Policy(PolicyError::ExternalJoinProposal))
        ),
        "{result:?}"
    );
    assert!(!result.unwrap_err().is_alarm());
    assert_eq!(dm.groups[0].inner_mut().pending_proposals().count(), 0);
}

#[test]
fn a_message_for_a_later_epoch_waits_for_its_commit() {
    let mut dm = Dm::new();
    let device = &dm.devices[2];
    let update = dm.groups[2]
        .self_update(&device.provider, &device.signer(), &dm.pins)
        .unwrap();
    let device = &dm.devices[2];
    dm.groups[2].merge_pending_commit(&device.provider).unwrap();
    let device = &dm.devices[2];
    let message = dm.groups[2]
        .encrypt(&device.provider, &device.signer(), b"after the update")
        .unwrap();

    let result = dm.deliver(0, &message);
    assert!(
        matches!(result, Err(MlsError::Refused(Refusal::WrongEpoch))),
        "{result:?}"
    );
    dm.deliver(0, &update.commit).unwrap();
    assert!(matches!(
        dm.deliver(0, &message).unwrap(),
        Incoming::Application { .. }
    ));
}

/// Two devices commit in the same epoch; the server accepts the first and
/// answers `STALE_EPOCH` to the second, which drops its commit, applies the
/// accepted one and commits again in the new epoch (section 7).
#[test]
fn a_commit_that_lost_the_race_is_discarded_and_made_again() {
    let mut dm = Dm::new();
    let device = &dm.devices[0];
    let winner = dm.groups[0]
        .self_update(&device.provider, &device.signer(), &dm.pins)
        .unwrap();
    let device = &dm.devices[2];
    let loser = dm.groups[2]
        .self_update(&device.provider, &device.signer(), &dm.pins)
        .unwrap();
    assert_ne!(winner.commit, loser.commit);

    // Accepted: its author merges, the others apply it.
    let device = &dm.devices[0];
    dm.groups[0].merge_pending_commit(&device.provider).unwrap();
    let device = &dm.devices[2];
    dm.groups[2]
        .discard_pending_commit(&device.provider)
        .unwrap();
    assert!(dm.groups[2].inner_mut().pending_commit().is_none());
    for incoming in dm.deliver_all(&winner.commit, &[0]) {
        assert!(matches!(incoming, Incoming::Commit { .. }), "{incoming:?}");
    }
    assert_eq!(dm.epochs(), [2, 2, 2, 2]);

    // The refused commit is for a past epoch now: nobody takes it.
    let result = dm.deliver(1, &loser.commit);
    assert!(
        matches!(result, Err(MlsError::Refused(Refusal::PastEpoch))),
        "{result:?}"
    );

    // Made again in the new epoch, it goes through.
    let device = &dm.devices[2];
    let again = dm.groups[2]
        .self_update(&device.provider, &device.signer(), &dm.pins)
        .unwrap();
    let device = &dm.devices[2];
    dm.groups[2].merge_pending_commit(&device.provider).unwrap();
    dm.deliver_all(&again.commit, &[2]);
    assert_eq!(dm.epochs(), [3, 3, 3, 3]);
    dm.send(2, b"in sync");
}

#[test]
fn an_own_commit_sent_back_by_the_server_is_merged() {
    let mut dm = Dm::new();
    let device = &dm.devices[1];
    let commit = dm.groups[1]
        .self_update(&device.provider, &device.signer(), &dm.pins)
        .unwrap();
    // Not merged yet: the server fans the commit out to its author too.
    assert_eq!(dm.groups[1].epoch(), 1);
    assert_eq!(dm.deliver(1, &commit.commit).unwrap(), Incoming::OwnCommit);
    assert_eq!(dm.groups[1].epoch(), 2);
    dm.deliver_all(&commit.commit, &[1]);
    assert_eq!(dm.epochs(), [2, 2, 2, 2]);
    dm.send(1, b"merged");
}

// --- Serialization round trips ------------------------------------------------------------

proptest! {
    // A safety number costs 10,400 SHA-512: fewer cases than the default.
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn group_ids_round_trip(conversation in any::<[u8; ID_LEN]>(), generation in any::<u32>()) {
        let identity = GroupIdentity { conversation_id: conversation, generation };
        prop_assert_eq!(GroupIdentity::from_group_id(&identity.to_group_id()).unwrap(), identity);
    }

    #[test]
    fn safety_numbers_do_not_depend_on_the_side(a in any::<[u8; ID_LEN]>(), b in any::<[u8; ID_LEN]>()) {
        let (key_a, key_b) = (key(KEY_1), key(KEY_2));
        let one = safety_number::safety_number(
            Party { user_id: &a, identity_key: &key_a },
            Party { user_id: &b, identity_key: &key_b },
        );
        let other = safety_number::safety_number(
            Party { user_id: &b, identity_key: &key_b },
            Party { user_id: &a, identity_key: &key_a },
        );
        prop_assert_eq!(one, other);
    }
}

#[test]
fn key_packages_round_trip_through_their_bytes() {
    let alice = Account::new(1);
    let pins = Pins::of(&[&alice]);
    let mut runner =
        proptest::test_runner::TestRunner::new(proptest::test_runner::Config::with_cases(8));
    runner
        .run(&(any::<u8>(), any::<bool>()), |(device_id, last_resort)| {
            let device = alice.device(device_id);
            let package = key_package::build(
                &device.provider,
                &device.signer(),
                device.credential(),
                last_resort,
            )
            .unwrap();
            let encoded = bytes(&package);
            let claimed = claim(&device, &package, &pins);
            prop_assert_eq!(bytes(claimed.key_package()), encoded);
            prop_assert_eq!(claimed.device(), Some(device.leaf()));
            Ok(())
        })
        .unwrap();
}

#[test]
fn any_content_round_trips_through_a_group() {
    let dm = std::cell::RefCell::new(Dm::new());
    let mut runner =
        proptest::test_runner::TestRunner::new(proptest::test_runner::Config::with_cases(24));
    runner
        .run(
            &proptest::collection::vec(any::<u8>(), 0..3000),
            |content| {
                let mut guard = dm.borrow_mut();
                let dm = &mut *guard;
                let device = &dm.devices[0];
                let message = dm.groups[0]
                    .encrypt(&device.provider, &device.signer(), &content)
                    .unwrap();
                let bucket = padding::pad(&content).unwrap().len();
                match dm.deliver(3, &message).unwrap() {
                    Incoming::Application { content: got, .. } => {
                        prop_assert_eq!(got.expose(), content.as_slice());
                    }
                    other => prop_assert!(false, "{other:?}"),
                }
                // Messages of one bucket all have one size.
                let device = &dm.devices[0];
                let same_bucket = dm.groups[0]
                    .encrypt(&device.provider, &device.signer(), &vec![0; bucket - 4])
                    .unwrap();
                prop_assert_eq!(same_bucket.len(), message.len());
                dm.deliver(3, &same_bucket).unwrap();
                Ok(())
            },
        )
        .unwrap();
}

// --- Section 8: padding -------------------------------------------------------------------

proptest! {
    #[test]
    fn padding_round_trips_into_a_bucket(content in proptest::collection::vec(any::<u8>(), 0..5000)) {
        let padded = padding::pad(&content).unwrap();
        prop_assert!(BUCKETS.contains(&padded.len()));
        prop_assert!(padded.len() >= content.len() + 4);
        prop_assert_eq!(padding::unpad(&padded).unwrap(), content.as_slice());
    }
}

#[test]
fn padding_uses_the_smallest_bucket_and_has_a_maximum() {
    assert_eq!(padding::pad(b"").unwrap().len(), 256);
    assert_eq!(padding::pad(&[1; 252]).unwrap().len(), 256);
    assert_eq!(padding::pad(&[1; 253]).unwrap().len(), 512);
    assert_eq!(padding::pad(&[1; 1021]).unwrap().len(), 2048);
    assert_eq!(
        padding::pad(&vec![1; MAX_CONTENT]).unwrap().len(),
        64 * 1024
    );
    assert_eq!(
        padding::pad(&vec![1; MAX_CONTENT + 1]).unwrap_err(),
        PaddingError::TooLarge
    );
}

#[test]
fn padding_refuses_a_length_beyond_the_data() {
    let mut padded = padding::pad(b"hello").unwrap();
    padded[..4].copy_from_slice(&253u32.to_be_bytes());
    assert_eq!(
        padding::unpad(&padded).unwrap_err(),
        PaddingError::LengthBeyondData
    );
    padded[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        padding::unpad(&padded).unwrap_err(),
        PaddingError::LengthBeyondData
    );
    // Exactly the space available is fine.
    padded[..4].copy_from_slice(&252u32.to_be_bytes());
    padded[4..].fill(7);
    assert!(padding::unpad(&padded).is_ok());
}

#[test]
fn padding_refuses_a_size_that_is_not_a_bucket() {
    let padded = padding::pad(b"hello").unwrap();
    for size in [0, 3, 4, 255, 257, 300, 1025, 64 * 1024 + 256] {
        let mut wrong = padded.clone();
        wrong.resize(size, 0);
        assert_eq!(
            padding::unpad(&wrong).unwrap_err(),
            PaddingError::NotABucket,
            "{size}"
        );
    }
}

#[test]
fn padding_refuses_a_padding_byte_that_is_not_zero() {
    let mut padded = padding::pad(b"hello").unwrap();
    let last = padded.len() - 1;
    padded[last] = 1;
    assert_eq!(
        padding::unpad(&padded).unwrap_err(),
        PaddingError::NonZeroPadding
    );
    let mut padded = padding::pad(b"hello").unwrap();
    padded[4 + 5] = 0x80;
    assert_eq!(
        padding::unpad(&padded).unwrap_err(),
        PaddingError::NonZeroPadding
    );
}

#[test]
fn a_padding_tampered_with_by_a_member_is_refused_by_the_receiver() {
    let mut dm = Dm::new();
    for (tamper, error) in [
        (
            Box::new(|padded: &mut Vec<u8>| padded[200] = 1) as Box<dyn Fn(&mut Vec<u8>)>,
            PaddingError::NonZeroPadding,
        ),
        (
            Box::new(|padded: &mut Vec<u8>| padded[..4].copy_from_slice(&253u32.to_be_bytes())),
            PaddingError::LengthBeyondData,
        ),
    ] {
        let mut padded = padding::pad(b"hello").unwrap().to_vec();
        tamper(&mut padded);
        let device = &dm.devices[0];
        let raw = dm.groups[0]
            .inner_mut()
            .create_message(&device.provider, &device.signer(), &padded)
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
        let result = dm.deliver(1, &raw);
        assert!(
            matches!(result, Err(MlsError::Padding(got)) if got == error),
            "{result:?}"
        );
    }
}

#[test]
fn an_unpadded_message_is_refused_by_the_receiver() {
    // Padding is checked after decryption: a device can only receive what a
    // member padded, so this exercises `unpad` on the receiving path.
    let mut dm = Dm::new();
    let device = &dm.devices[0];
    let raw = dm.groups[0]
        .inner_mut()
        .create_message(&device.provider, &device.signer(), &[0u8; 300])
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let result = dm.deliver(1, &raw);
    assert!(
        matches!(result, Err(MlsError::Padding(PaddingError::NotABucket))),
        "{result:?}"
    );
}

#[test]
fn decrypted_content_is_never_printed() {
    let mut dm = Dm::new();
    let device = &dm.devices[0];
    let message = dm.groups[0]
        .encrypt(&device.provider, &device.signer(), b"secret plans")
        .unwrap();
    let incoming = dm.deliver(1, &message).unwrap();
    let printed = format!("{incoming:?}");
    assert!(!printed.contains("secret"), "{printed}");
    assert!(printed.contains("<redacted>"));
}

// --- Section 9: forward secrecy and message order ------------------------------------------

#[test]
fn a_message_of_a_past_epoch_can_no_longer_be_read() {
    let mut dm = Dm::new();
    let device = &dm.devices[0];
    let late = dm.groups[0]
        .encrypt(
            &device.provider,
            &device.signer(),
            b"sent before the update",
        )
        .unwrap();
    let device = &dm.devices[2];
    let update = dm.groups[2]
        .self_update(&device.provider, &device.signer(), &dm.pins)
        .unwrap();
    dm.groups[2]
        .merge_pending_commit(&dm.devices[2].provider)
        .unwrap();
    dm.deliver(1, &update.commit).unwrap();

    let result = dm.deliver(1, &late);
    assert!(
        matches!(result, Err(MlsError::Refused(Refusal::PastEpoch))),
        "{result:?}"
    );
}

#[test]
fn messages_of_one_sender_may_arrive_out_of_order() {
    let mut dm = Dm::new();
    let device = &dm.devices[0];
    let first = dm.groups[0]
        .encrypt(&device.provider, &device.signer(), b"first")
        .unwrap();
    let second = dm.groups[0]
        .encrypt(&device.provider, &device.signer(), b"second")
        .unwrap();
    for (message, content) in [(&second, b"second".as_slice()), (&first, b"first")] {
        match dm.deliver(2, message).unwrap() {
            Incoming::Application { content: got, .. } => assert_eq!(got.expose(), content),
            other => panic!("{other:?}"),
        }
    }
    // A message is read once only: its key is deleted.
    let result = dm.deliver(2, &first);
    assert!(
        matches!(result, Err(MlsError::Refused(Refusal::AlreadyRead))),
        "{result:?}"
    );
}

// --- Section 10: safety numbers ------------------------------------------------------------

/// RFC 8032 test keys 1 and 2: valid public keys with known bytes.
const KEY_1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const KEY_2: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

fn key(hex: &str) -> IdentityPublicKey {
    IdentityPublicKey::from_bytes(&data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap()).unwrap()
}

#[test]
fn safety_numbers_match_frozen_vectors() {
    let (user_1, user_2) = ([1u8; ID_LEN], [2u8; ID_LEN]);
    let (key_1, key_2) = (key(KEY_1), key(KEY_2));
    let number = safety_number::safety_number(
        Party {
            user_id: &user_2,
            identity_key: &key_2,
        },
        Party {
            user_id: &user_1,
            identity_key: &key_1,
        },
    );
    // Computed independently (Python, hashlib), see the module documentation.
    assert_eq!(number.digits(), FROZEN_SAFETY_NUMBER);
    assert_eq!(number.groups().len(), 12);
    assert_eq!(number.to_string().len(), 60 + 11);
}

const FROZEN_SAFETY_NUMBER: &str = "074749105012177600572368630481949686908612441785971637399538";

#[test]
fn safety_numbers_are_symmetric_and_follow_every_key() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let (a, b) = (alice.public(), bob.public());
    let party = |user: &'static [u8; ID_LEN], key| Party {
        user_id: user,
        identity_key: key,
    };
    static ALICE: [u8; ID_LEN] = [1; ID_LEN];
    static BOB: [u8; ID_LEN] = [2; ID_LEN];

    let ab = safety_number::safety_number(party(&ALICE, &a), party(&BOB, &b));
    let ba = safety_number::safety_number(party(&BOB, &b), party(&ALICE, &a));
    assert_eq!(ab, ba);
    assert_eq!(ab.digits().len(), 60);
    assert!(ab.digits().bytes().all(|digit| digit.is_ascii_digit()));

    let new_bob = Account::new(2).public();
    let changed = safety_number::safety_number(party(&ALICE, &a), party(&BOB, &new_bob));
    assert_ne!(ab, changed);
    assert_eq!(
        ab.digits()[..30],
        changed.digits()[..30],
        "Alice's half stays"
    );

    let qr = safety_number::qr_payload(party(&ALICE, &a), party(&BOB, &b));
    assert!(safety_number::qr_matches(
        &qr,
        party(&BOB, &b),
        party(&ALICE, &a)
    ));
    assert!(!safety_number::qr_matches(
        &qr,
        party(&ALICE, &a),
        party(&BOB, &new_bob)
    ));
    let mut other_version = qr;
    other_version[0] = 2;
    assert!(!safety_number::qr_matches(
        &other_version,
        party(&ALICE, &a),
        party(&BOB, &b)
    ));
    assert!(!safety_number::qr_matches(
        &qr[..64],
        party(&ALICE, &a),
        party(&BOB, &b)
    ));
}

// --- Section 11: a leaf that fails validation -------------------------------------------

#[test]
fn a_device_with_an_unpinned_identity_is_never_added() {
    // The server hands out KeyPackages: it could slip in a device that
    // claims to be Bob's, certified by another identity key.
    let mut dm = Dm::new();
    let impostor_account = Account::new(2);
    let impostor = impostor_account.device(0xb7);
    let pins = dm.pins.clone();

    // The claim refuses it...
    let result = key_package::validate_claimed(
        impostor.provider.crypto(),
        &bytes(&impostor.key_package()),
        impostor.leaf(),
        &pins,
    );
    assert_eq!(
        result.unwrap_err(),
        KeyPackageError::Leaf(LeafError::Untrusted)
    );
    // ...and so does the group, if it was claimed with another roster.
    let claimed = impostor.claimed(&Pins::of(&[&impostor_account]));
    let device = &dm.devices[0];
    let result = dm.groups[0].add(&device.provider, &device.signer(), &[claimed], &pins);
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::Untrusted))),
        "{result:?}"
    );
    // Nor twice the same device.
    let twin = dm.bob.device(0xb1);
    let claimed = twin.claimed(&pins);
    let device = &dm.devices[0];
    let result = dm.groups[0].add(&device.provider, &device.signer(), &[claimed], &pins);
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::DuplicateDevice))),
        "{result:?}"
    );
    assert!(dm.groups[0].inner_mut().pending_commit().is_none());
}

#[test]
fn a_commit_adding_a_device_with_an_unpinned_identity_is_not_merged() {
    let mut dm = Dm::new();
    // A member that skipped the check (or a forged commit) adds it anyway.
    let impostor = Account::new(2).device(0xb7);
    let device = &dm.devices[0];
    let (commit, _, _) = dm.groups[0]
        .inner_mut()
        .add_members(
            &device.provider,
            &device.signer(),
            &[impostor.key_package()],
        )
        .unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let before = dm.groups[1].epoch();

    let result = dm.deliver(1, &commit);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Leaf(LeafError::Untrusted)))
        ),
        "{result:?}"
    );
    assert!(result.unwrap_err().is_alarm());
    assert_eq!(dm.groups[1].epoch(), before, "not merged");
    assert_eq!(dm.groups[1].devices().len(), 4);
}

// --- Claimed KeyPackages, creation, expected groups --------------------------------------

#[test]
fn a_claimed_key_package_must_be_the_announced_device_of_a_pinned_user() {
    let dm = Dm::new();
    let bob3 = dm.bob.device(0xb3);
    let package = bytes(&bob3.key_package());
    let crypto = bob3.provider.crypto();

    assert_eq!(
        key_package::validate_claimed(crypto, &package, bob3.leaf(), &dm.pins)
            .unwrap()
            .device(),
        Some(bob3.leaf())
    );
    // The server said it was another device.
    let other = dm.devices[2].leaf();
    assert_eq!(
        key_package::validate_claimed(crypto, &package, other, &dm.pins).unwrap_err(),
        KeyPackageError::WrongDevice
    );
    // A user this device does not know.
    assert_eq!(
        key_package::validate_claimed(crypto, &package, bob3.leaf(), &Pins::of(&[&dm.alice]))
            .unwrap_err(),
        KeyPackageError::Leaf(LeafError::NotParticipant)
    );
}

fn storage_is_empty(device: &Device) -> bool {
    device.provider.storage.values.read().unwrap().is_empty()
}

#[test]
fn creating_a_group_writes_nothing_when_a_device_is_refused() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let server = ExternalSenderKey::generate();
    let pins = Pins::of(&[&alice, &bob]);
    let creator = alice.device(0xa1);
    let bob1 = bob.device(0xb1);
    assert!(storage_is_empty(&creator));
    let create = |key_packages: &[ClaimedKeyPackage], expected: &ExpectedGroup<'_>| {
        Group::create(
            &creator.provider,
            &creator.signer(),
            creator.credential(),
            expected,
            &server.public_bytes(),
            key_packages,
            &pins,
        )
        .map(|_| ())
    };

    // A device certified by an identity key that is not Bob's pinned one.
    let impostor_account = Account::new(2);
    let impostor = impostor_account.device(0xb7);
    let unpinned = impostor.claimed(&Pins::of(&[&impostor_account]));
    let result = create(&[bob1.claimed(&pins), unpinned], &expected());
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::Untrusted))),
        "{result:?}"
    );
    assert!(storage_is_empty(&creator));

    // The same device twice.
    let result = create(&[bob1.claimed(&pins), bob1.claimed(&pins)], &expected());
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::DuplicateDevice))),
        "{result:?}"
    );
    assert!(storage_is_empty(&creator));

    // A device of a user outside the conversation, even a pinned one.
    let carol = Account::new(3);
    let carol1 = carol.device(0xc1);
    let pins_with_carol = Pins::of(&[&alice, &bob, &carol]);
    let result = Group::create(
        &creator.provider,
        &creator.signer(),
        creator.credential(),
        &expected(),
        &server.public_bytes(),
        &[bob1.claimed(&pins), carol1.claimed(&pins_with_carol)],
        &pins_with_carol,
    );
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::NotParticipant))),
        "{result:?}"
    );
    assert!(storage_is_empty(&creator));

    // The creator itself outside the conversation.
    let between_bob_and_carol = ExpectedGroup {
        identity: identity(),
        participants: &[BOB, [3; ID_LEN]],
    };
    let result = create(&[bob1.claimed(&pins)], &between_bob_and_carol);
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::NotParticipant))),
        "{result:?}"
    );
    assert!(storage_is_empty(&creator));

    // And when everything is right, the group is written.
    create(&[bob1.claimed(&pins)], &expected()).unwrap();
    assert!(!storage_is_empty(&creator));
}

/// A participant may have no device in the group: Bob, away for longer than
/// the inactivity period or with no active device, does not stop Alice from
/// creating the DM, from joining it with a new device (by Welcome or by
/// external commit), or from recreating it (sections 4, 15, 17).
#[test]
fn a_dm_lives_while_a_participant_has_no_device() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let server = ExternalSenderKey::generate();
    let pins = Pins::of(&[&alice, &bob]);
    let (alice1, alice2, alice3) = (alice.device(0xa1), alice.device(0xa2), alice.device(0xa3));

    // Created with no KeyPackage at all: Alice's only active device.
    let (mut group1, created) = Group::create(
        &alice1.provider,
        &alice1.signer(),
        alice1.credential(),
        &expected(),
        &server.public_bytes(),
        &[],
        &pins,
    )
    .unwrap();
    assert!(created.welcome.is_none(), "nobody to welcome");
    group1.merge_pending_commit(&alice1.provider).unwrap();
    assert_eq!(group1.participants_without_devices(&PARTICIPANTS), [BOB]);

    // Alice's new computer joins by external commit.
    let (mut group2, joined, members) = Group::join_by_external_commit(
        &alice2.provider,
        &alice2.signer(),
        alice2.credential(),
        &created.group_info,
        &expected(),
        &pins,
        &server.public_bytes(),
    )
    .unwrap();
    assert_eq!(members.len(), 2);
    group2.merge_pending_commit(&alice2.provider).unwrap();
    assert!(matches!(
        group1
            .process(&alice1.provider, &joined.commit, &pins)
            .unwrap(),
        Incoming::Commit { .. }
    ));
    let message = group1
        .encrypt(&alice1.provider, &alice1.signer(), b"note to self")
        .unwrap();
    assert!(matches!(
        group2.process(&alice2.provider, &message, &pins).unwrap(),
        Incoming::Application { .. }
    ));

    // Another one, added by Welcome.
    let added = group1
        .add(
            &alice1.provider,
            &alice1.signer(),
            &[alice3.claimed(&pins)],
            &pins,
        )
        .unwrap();
    group1.merge_pending_commit(&alice1.provider).unwrap();
    group2
        .process(&alice2.provider, &added.commit, &pins)
        .unwrap();
    let group3 = Group::join(
        &alice3.provider,
        &added.welcome.unwrap(),
        &expected(),
        &pins,
        &server.public_bytes(),
    )
    .unwrap()
    .group;
    assert_eq!(group3.participants_without_devices(&PARTICIPANTS), [BOB]);

    // Bob comes back and joins by external commit: nobody is missing now.
    let bob1 = bob.device(0xb1);
    let (mut group_bob, bob_joined, _) = Group::join_by_external_commit(
        &bob1.provider,
        &bob1.signer(),
        bob1.credential(),
        &added.group_info,
        &expected(),
        &pins,
        &server.public_bytes(),
    )
    .unwrap();
    group_bob.merge_pending_commit(&bob1.provider).unwrap();
    group1
        .process(&alice1.provider, &bob_joined.commit, &pins)
        .unwrap();
    assert!(
        group1
            .participants_without_devices(&PARTICIPANTS)
            .is_empty()
    );
    let message = group1
        .encrypt(&alice1.provider, &alice1.signer(), b"welcome back")
        .unwrap();
    match group_bob.process(&bob1.provider, &message, &pins).unwrap() {
        Incoming::Application { content, .. } => assert_eq!(content.expose(), b"welcome back"),
        other => panic!("{other:?}"),
    }

    // Recreated (generation 1) while Bob has no active device again.
    let generation_1 = ExpectedGroup {
        identity: identity().next().unwrap(),
        participants: &PARTICIPANTS,
    };
    let (mut recreated, commit) = Group::create(
        &alice1.provider,
        &alice1.signer(),
        alice1.credential(),
        &generation_1,
        &server.public_bytes(),
        &[alice2.claimed(&pins)],
        &pins,
    )
    .unwrap();
    recreated.merge_pending_commit(&alice1.provider).unwrap();
    let joined = Group::join(
        &alice2.provider,
        &commit.welcome.unwrap(),
        &generation_1,
        &pins,
        &server.public_bytes(),
    )
    .unwrap();
    assert_eq!(
        joined.group.participants_without_devices(&PARTICIPANTS),
        [BOB]
    );
}

#[test]
fn a_welcome_is_accepted_only_for_the_expected_group() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let server = ExternalSenderKey::generate();
    let pins = Pins::of(&[&alice, &bob]);
    let joiner = bob.device(0xb1);
    // OpenMLS consumes a one-time KeyPackage as soon as a Welcome for it is
    // staged, even if the group is then refused: each attempt needs a new
    // Welcome.
    let attempt = |expected: &ExpectedGroup<'_>, roster: &Pins| {
        let creator = alice.device(0xa1);
        let (_, commit) = Group::create(
            &creator.provider,
            &creator.signer(),
            creator.credential(),
            &self::expected(),
            &server.public_bytes(),
            &[joiner.claimed(&pins)],
            &pins,
        )
        .unwrap();
        Group::join(
            &joiner.provider,
            &commit.welcome.unwrap(),
            expected,
            roster,
            &server.public_bytes(),
        )
        .map(|joined| {
            let without = joined
                .group
                .participants_without_devices(expected.participants);
            joined.group.delete(&joiner.provider).unwrap();
            without
        })
    };

    let next_generation = ExpectedGroup {
        identity: identity().next().unwrap(),
        participants: &PARTICIPANTS,
    };
    assert!(matches!(
        attempt(&next_generation, &pins),
        Err(MlsError::UnexpectedGroup)
    ));
    let other_conversation = ExpectedGroup {
        identity: GroupIdentity {
            conversation_id: [0xc1; ID_LEN],
            generation: 0,
        },
        participants: &PARTICIPANTS,
    };
    assert!(matches!(
        attempt(&other_conversation, &pins),
        Err(MlsError::UnexpectedGroup)
    ));
    let without_bob = ExpectedGroup {
        identity: identity(),
        participants: &[ALICE],
    };
    let result = attempt(&without_bob, &pins);
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Leaf(LeafError::NotParticipant)))
        ),
        "{result:?}"
    );
    // A participant with no device in the group is not a reason to refuse.
    let with_carol = ExpectedGroup {
        identity: identity(),
        participants: &[ALICE, BOB, [3; ID_LEN]],
    };
    assert_eq!(attempt(&with_carol, &pins).unwrap(), [[3; ID_LEN]]);
    // A member outside the roster.
    let result = attempt(&expected(), &Pins::of(&[&bob]));
    assert!(
        matches!(
            result,
            Err(MlsError::Alarm(Alarm::Leaf(LeafError::NotParticipant)))
        ),
        "{result:?}"
    );
    // The right one.
    assert!(attempt(&expected(), &pins).unwrap().is_empty());
}

#[test]
fn a_welcome_without_tavern_s_required_capabilities_is_refused() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let server = ExternalSenderKey::generate();
    let pins = Pins::of(&[&alice, &bob]);
    let creator = alice.device(0xa1);
    let joiner = bob.device(0xb1);
    // Built with OpenMLS directly: Tavern's external sender, no required
    // capabilities.
    let config = openmls::prelude::MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities())
        .use_ratchet_tree_extension(true)
        .with_group_context_extensions(
            Extensions::single(Extension::ExternalSenders(vec![server_external_sender(
                &server.public_bytes(),
            )]))
            .unwrap(),
        )
        .build();
    let mut group = openmls::prelude::MlsGroup::new_with_group_id(
        &creator.provider,
        &creator.signer(),
        &config,
        identity().to_group_id(),
        creator.credential(),
    )
    .unwrap();
    let (_, welcome, _) = group
        .add_members(
            &creator.provider,
            &creator.signer(),
            &[joiner.key_package()],
        )
        .unwrap();
    let result = Group::join(
        &joiner.provider,
        &welcome.tls_serialize_detached().unwrap(),
        &expected(),
        &pins,
        &server.public_bytes(),
    );
    assert!(matches!(result, Err(MlsError::Parameters)), "{result:?}");
}

#[test]
fn a_used_last_resort_key_package_is_deleted_and_an_old_welcome_cannot_be_replayed() {
    let alice = Account::new(1);
    let bob = Account::new(2);
    let server = ExternalSenderKey::generate();
    let pins = Pins::of(&[&alice, &bob]);
    let creator = alice.device(0xa1);
    let joiner = bob.device(0xb1);

    // Generation 0, with Bob's last-resort KeyPackage.
    let last_resort = key_package::build(
        &joiner.provider,
        &joiner.signer(),
        joiner.credential(),
        true,
    )
    .unwrap();
    let reference = last_resort.hash_ref(joiner.provider.crypto()).unwrap();
    let (_, commit) = Group::create(
        &creator.provider,
        &creator.signer(),
        creator.credential(),
        &expected(),
        &server.public_bytes(),
        &[claim(&joiner, &last_resort, &pins)],
        &pins,
    )
    .unwrap();
    let old_welcome = commit.welcome.unwrap();
    let joined = Group::join(
        &joiner.provider,
        &old_welcome,
        &expected(),
        &pins,
        &server.public_bytes(),
    )
    .unwrap();
    assert!(joined.last_resort_used, "the caller must upload a new one");
    let kept: Option<openmls::prelude::KeyPackageBundle> =
        openmls_traits::storage::StorageProvider::key_package(
            joiner.provider.storage(),
            &reference,
        )
        .unwrap();
    assert!(kept.is_none(), "the used last-resort package is deleted");

    // The conversation is recreated (generation 1); the old group is gone.
    let generation_1 = ExpectedGroup {
        identity: identity().next().unwrap(),
        participants: &PARTICIPANTS,
    };
    let creator_2 = alice.device(0xa1);
    let (_, commit) = Group::create(
        &creator_2.provider,
        &creator_2.signer(),
        creator_2.credential(),
        &generation_1,
        &server.public_bytes(),
        &[joiner.claimed(&pins)],
        &pins,
    )
    .unwrap();
    Group::join(
        &joiner.provider,
        &commit.welcome.unwrap(),
        &generation_1,
        &pins,
        &server.public_bytes(),
    )
    .unwrap();
    joined.group.delete(&joiner.provider).unwrap();

    // The server replays the Welcome of generation 0.
    for expecting in [generation_1, expected()] {
        let result = Group::join(
            &joiner.provider,
            &old_welcome,
            &expecting,
            &pins,
            &server.public_bytes(),
        );
        assert!(
            matches!(result, Err(MlsError::UnexpectedGroup)),
            "{result:?}"
        );
    }
}

// --- Section 17: group ids ------------------------------------------------------------------

#[test]
fn group_ids_carry_the_conversation_and_the_generation() {
    let first = identity();
    let group_id = first.to_group_id();
    assert_eq!(group_id.as_slice().len(), 20);
    assert_eq!(&group_id.as_slice()[..16], &CONVERSATION);
    assert_eq!(&group_id.as_slice()[16..], &[0, 0, 0, 0]);
    assert_eq!(GroupIdentity::from_group_id(&group_id).unwrap(), first);

    let next = first.next().unwrap();
    assert_eq!(next.generation, 1);
    assert_eq!(
        GroupIdentity::from_group_id(&next.to_group_id()).unwrap(),
        next
    );
    let last = GroupIdentity {
        generation: u32::MAX,
        ..first
    };
    assert_eq!(last.next(), None);

    for wrong in [&[0u8; 16][..], &[0u8; 21][..], &[][..]] {
        assert!(matches!(
            GroupIdentity::from_group_id(&openmls::prelude::GroupId::from_slice(wrong)),
            Err(MlsError::Parameters)
        ));
    }
}
