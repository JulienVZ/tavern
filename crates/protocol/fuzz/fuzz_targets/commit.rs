// SPDX-License-Identifier: AGPL-3.0-or-later

//! Commits, which the server checks against a group's public state
//! (`SubmitCommit`, ADR 0019, sections 7 and 18).
//!
//! The state is a DM's group at epoch 1, built once as the server builds
//! it. Checking arbitrary bytes as a commit of it must never panic.

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use openmls_memory_storage::MemoryStorage;
use tavern_crypto::identity::{
    AccountRootSecret, DeviceKey, ExternalSenderKey, ID_LEN, IdentityPublicKey,
};
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::{
    DeviceSigner, ExpectedGroup, Group, Provider, PublicState, Roster, VerifiedLeaf, key_package,
};

struct Keys(HashMap<[u8; ID_LEN], IdentityPublicKey>);

impl Roster for Keys {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.0.get(user_id).copied()
    }
}

const PARTICIPANTS: [[u8; ID_LEN]; 2] = [[1; ID_LEN], [2; ID_LEN]];

fn expected() -> ExpectedGroup<'static> {
    ExpectedGroup {
        identity: GroupIdentity {
            conversation_id: [9; ID_LEN],
            generation: 0,
        },
        participants: &PARTICIPANTS,
    }
}

struct Fixture {
    state: PublicState,
    group_info: Vec<u8>,
    submitter: VerifiedLeaf,
    keys: Keys,
}

fn fixture() -> Fixture {
    let alice = AccountRootSecret::generate().identity_key().expect("a key");
    let bob = AccountRootSecret::generate().identity_key().expect("a key");
    let keys = Keys(
        [(PARTICIPANTS[0], alice.public()), (PARTICIPANTS[1], bob.public())]
            .into_iter()
            .collect(),
    );
    let device = |identity: &tavern_crypto::identity::AccountIdentityKey, user: [u8; ID_LEN], id| {
        let key = DeviceKey::generate();
        let certificate = identity.certify_device(&user, &id, &key.public(), 0);
        (key, certificate, Provider::new(MemoryStorage::default()))
    };
    let (alice_key, alice_certificate, alice_provider) = device(&alice, PARTICIPANTS[0], [0xa1; ID_LEN]);
    let (bob_key, bob_certificate, bob_provider) = device(&bob, PARTICIPANTS[1], [0xb1; ID_LEN]);
    let package = key_package::build(
        &bob_provider,
        &DeviceSigner::new(&bob_key),
        for_device(&bob_certificate, &bob_key.public()),
        false,
    )
    .expect("a package");
    let bob_leaf = VerifiedLeaf {
        user_id: PARTICIPANTS[1],
        device_id: [0xb1; ID_LEN],
    };
    let claimed = key_package::validate_claimed(
        &key_package::to_bytes(&package).expect("bytes"),
        bob_leaf,
        &keys,
    )
    .expect("a valid package");
    let server = ExternalSenderKey::generate();
    let (_, commit) = Group::create(
        &alice_provider,
        &DeviceSigner::new(&alice_key),
        for_device(&alice_certificate, &alice_key.public()),
        &expected(),
        &server.public_bytes(),
        &[claimed],
        &keys,
    )
    .expect("a group");
    let submitter = VerifiedLeaf {
        user_id: PARTICIPANTS[0],
        device_id: [0xa1; ID_LEN],
    };
    let (state, _) = PublicState::create(
        &commit.group_info,
        &expected(),
        submitter,
        &keys,
        &server.public_bytes(),
    )
    .expect("the server's state");
    Fixture {
        state,
        group_info: commit.group_info,
        submitter,
        keys,
    }
}

thread_local! {
    static FIXTURE: Fixture = fixture();
}

fuzz_target!(|data: &[u8]| {
    FIXTURE.with(|fixture| {
        let _ = fixture.state.validate_commit(
            data,
            &fixture.group_info,
            fixture.submitter,
            &expected(),
            &fixture.keys,
        );
    });
});
