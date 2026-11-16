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
    NewSignerBundle, PURE_PLAINTEXT_WIRE_FORMAT_POLICY, SenderExtensionIndex, WireFormat,
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
        DeviceSigner(&self.key)
    }

    fn key_package(&self) -> KeyPackage {
        key_package::build(&self.provider, &self.signer(), self.credential(), false)
            .unwrap()
            .key_package()
            .clone()
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
        let key_packages: Vec<_> = devices[1..].iter().map(Device::key_package).collect();

        let creator = &devices[0];
        let (mut first, commit) = Group::create(
            &creator.provider,
            &creator.signer(),
            creator.credential(),
            &identity(),
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
            let (group, members) =
                Group::join(&device.provider, &welcome, &pins, &server.public_bytes()).unwrap();
            assert_eq!(members.len(), 4);
            groups.push(group);
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
            let incoming = self.deliver(index, &message).unwrap();
            assert_eq!(
                incoming,
                Incoming::Application {
                    sender: Some(self.devices[from].leaf()),
                    content: content.to_vec(),
                }
            );
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
        .self_update(&device.provider, &device.signer())
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
    let removed = dm.groups[0].leaf_of(&dm.devices[3].device_id).unwrap();
    let proposal = ExternalProposal::new_remove::<TestProvider>(
        removed,
        dm.groups[0].inner_mut().group_id().clone(),
        dm.groups[0].inner_mut().epoch(),
        &ServerSigner(&dm.server),
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
        .commit_pending_proposals(&device.provider, &device.signer())
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
    let (creator, other) = (alice.device(1), alice.device(2));
    let foreign = KeyPackage::builder()
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            &other.provider,
            &other.signer(),
            other.credential(),
        )
        .unwrap();
    let server = ExternalSenderKey::generate();
    let result = Group::create(
        &creator.provider,
        &creator.signer(),
        creator.credential(),
        &identity(),
        &server.public_bytes(),
        &[foreign.key_package().clone()],
        &Pins::of(&[&alice]),
    );
    assert!(matches!(result, Err(MlsError::Parameters)), "{result:?}");
}

#[test]
fn a_welcome_with_another_external_sender_is_refused() {
    let alice = Account::new(1);
    let (creator, joiner) = (alice.device(1), alice.device(2));
    let rogue = ExternalSenderKey::generate();
    let (_, commit) = Group::create(
        &creator.provider,
        &creator.signer(),
        creator.credential(),
        &identity(),
        &rogue.public_bytes(),
        &[joiner.key_package()],
        &Pins::of(&[&alice]),
    )
    .unwrap();
    let instance = ExternalSenderKey::generate();
    let result = Group::join(
        &joiner.provider,
        &commit.welcome.unwrap(),
        &Pins::of(&[&alice]),
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
        matches!(result, Err(MlsError::Leaf(LeafError::DeviceChanged))),
        "{result:?}"
    );
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
        let bundle = key_package::build(
            &device.provider,
            &device.signer(),
            device.credential(),
            last_resort,
        )
        .unwrap();
        let package = bundle.key_package();
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
    .unwrap()
    .key_package()
    .clone();

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
        &ServerSigner(&dm.server),
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
    let removed = dm.groups[0].leaf_of(&dm.devices[3].device_id).unwrap();
    let rogue = ExternalSenderKey::generate();
    let proposal = ExternalProposal::new_remove::<TestProvider>(
        removed,
        dm.groups[0].inner_mut().group_id().clone(),
        dm.groups[0].inner_mut().epoch(),
        &ServerSigner(&rogue),
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap();

    assert!(dm.deliver(1, &proposal).is_err());
    assert_eq!(dm.groups[1].inner_mut().pending_proposals().count(), 0);
}

#[test]
fn nobody_may_change_the_external_senders() {
    let mut dm = Dm::new();
    let rogue = ExternalSenderKey::generate();
    let extensions = Extensions::single(Extension::ExternalSenders(vec![server_external_sender(
        &rogue.public_bytes(),
    )]))
    .unwrap();
    let device = &dm.devices[0];
    let (proposal, _) = dm.groups[0]
        .inner_mut()
        .propose_group_context_extensions(&device.provider, extensions, &device.signer())
        .unwrap();
    let proposal = proposal.tls_serialize_detached().unwrap();

    let result = dm.deliver(2, &proposal);
    assert!(
        matches!(
            result,
            Err(MlsError::Policy(PolicyError::ExternalSendersChange))
        ),
        "{result:?}"
    );
    assert_eq!(dm.groups[2].inner_mut().pending_proposals().count(), 0);
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
fn a_tampered_padding_inside_a_message_is_refused_by_the_receiver() {
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
        .self_update(&device.provider, &device.signer())
        .unwrap();
    dm.groups[2]
        .merge_pending_commit(&dm.devices[2].provider)
        .unwrap();
    dm.deliver(1, &update.commit).unwrap();

    assert!(
        dm.deliver(1, &late).is_err(),
        "past epoch secrets are deleted"
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
            Incoming::Application { content: got, .. } => assert_eq!(got, content),
            other => panic!("{other:?}"),
        }
    }
    // A message is read once only: its key is deleted.
    assert!(dm.deliver(2, &first).is_err());
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
    let impostor = Account::new(2).device(0xb7);
    let device = &dm.devices[0];
    let pins = dm.pins.clone();
    let result = dm.groups[0].add(
        &device.provider,
        &device.signer(),
        &[impostor.key_package()],
        &pins,
    );
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::Untrusted))),
        "{result:?}"
    );
    // Nor twice the same device.
    let twin = dm.bob.device(0xb1);
    let result = dm.groups[0].add(
        &device.provider,
        &device.signer(),
        &[twin.key_package()],
        &pins,
    );
    assert!(
        matches!(result, Err(MlsError::Leaf(LeafError::DuplicateDevice))),
        "{result:?}"
    );
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
        matches!(result, Err(MlsError::Leaf(LeafError::Untrusted))),
        "{result:?}"
    );
    assert_eq!(dm.groups[1].epoch(), before, "not merged");
    assert_eq!(dm.groups[1].devices().len(), 4);
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
