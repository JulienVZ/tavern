// SPDX-License-Identifier: AGPL-3.0-or-later

//! The client's KeyPackage calls against the real server (ADR 0019, section
//! 3). A client builds its packages with its device's MLS store, which comes
//! with tasks 10 and 11 of M2: here, the counts and refusals the client gets,
//! and the client's own check of what it is served. The server's side, with
//! real packages, is tested in `crates/server/tests/key_packages.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use openmls_memory_storage::MemoryStorage;
use tavern_client_core::{Client, ClientError, InstanceClient, LoginStep, NewAccount};
use tavern_crypto::identity::{AccountRootSecret, DeviceKey, ID_LEN, IdentityPublicKey};
use tavern_crypto::mls::credential::for_device;
use tavern_crypto::mls::{DeviceSigner, Provider, Roster, key_package};
use tavern_e2e_tests::{PASSWORD, Server, random_handle};
use tavern_protocol::rest::ErrorCode;
use uuid::Uuid;

/// The identity key a device trusts for its own account.
struct Own(Uuid, IdentityPublicKey);

impl Roster for Own {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        (user_id == self.0.as_bytes()).then_some(self.1)
    }
}

async fn register(server: &Server, computer: &InstanceClient) -> String {
    let invite = server.host_invite(false).await;
    let registered = computer
        .register(NewAccount {
            invite_code: &invite,
            handle: &random_handle("kp"),
            display_name: "KeyPackage Test",
            password: PASSWORD,
        })
        .await
        .unwrap();
    registered.handle.as_str().to_owned()
}

async fn sign_in(computer: &InstanceClient, handle: &str) -> Client {
    match computer.login(handle, PASSWORD).await.unwrap() {
        LoginStep::Done(signed_in) => signed_in.client,
        LoginStep::TotpRequired(_) => panic!("unexpected TOTP step"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_client_counts_claims_and_checks_what_it_is_served() {
    let server = Server::spawn().await;
    let first_computer = server.new_computer();
    let handle = register(&server, &first_computer).await;
    let laptop = sign_in(&first_computer, &handle).await;
    let phone = sign_in(&server.new_computer(), &handle).await;
    let other_computer = server.new_computer();
    let other_handle = register(&server, &other_computer).await;
    let other = sign_in(&other_computer, &other_handle).await;
    let me = laptop.me().await.unwrap();
    let own = Own(
        laptop.user_id(),
        IdentityPublicKey::from_bytes(me.identity_key.as_slice()).unwrap(),
    );

    assert_eq!(laptop.key_package_count().await.unwrap(), 0);
    let refused = laptop
        .upload_key_packages(vec![b"not a KeyPackage".to_vec()], None)
        .await
        .unwrap_err();
    assert_eq!(refused.api_code(), Some(ErrorCode::InvalidKeyPackage));
    // The phone has no package yet: nothing to serve.
    assert!(
        laptop
            .claim_key_packages(laptop.user_id(), &own)
            .await
            .unwrap()
            .is_empty()
    );
    // Until task 6, another user's KeyPackages are not claimable.
    let forbidden = laptop
        .claim_key_packages(other.user_id(), &own)
        .await
        .unwrap_err();
    assert_eq!(forbidden.api_code(), Some(ErrorCode::Forbidden));

    // A server that serves, for the phone, a package certified by another
    // identity key: the client refuses it.
    let impostor = AccountRootSecret::generate().identity_key().unwrap();
    let key = DeviceKey::generate();
    let certificate = impostor.certify_device(
        laptop.user_id().as_bytes(),
        phone.device_id().as_bytes(),
        &key.public(),
        0,
    );
    let package = key_package::build(
        &Provider::new(MemoryStorage::default()),
        &DeviceSigner::new(&key),
        for_device(&certificate, &key.public()),
        false,
    )
    .unwrap();
    sqlx::query(
        "INSERT INTO key_packages (device_id, key_package, reference, expires_at) \
         VALUES ($1, $2, $3, now() + interval '30 days')",
    )
    .bind(phone.device_id())
    .bind(key_package::to_bytes(&package).unwrap())
    .bind(Uuid::new_v4().as_bytes().as_slice())
    .execute(&server.state.db)
    .await
    .unwrap();
    assert!(matches!(
        laptop.claim_key_packages(laptop.user_id(), &own).await,
        Err(ClientError::UntrustedKeyMaterial)
    ));
}
