// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device identity and sign-out, end to end (ADR 0017): a computer keeps one
//! device per account, signing out keeps it and its local store key, and
//! only an explicit erasure gives it up.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use tavern_client_core::{Client, ClientError, InstanceClient, LoginStep, NewAccount, SignedIn};
use tavern_e2e_tests::{PASSWORD, Server, random_handle};
use uuid::Uuid;

const NEW_PASSWORD: &str = "a-second-quite-long-passphrase-58";

struct Account {
    handle: String,
    recovery_key: String,
}

async fn register(server: &Server, computer: &InstanceClient, prefix: &str) -> Account {
    let invite = server.host_invite(false).await;
    let registered = computer
        .register(NewAccount {
            invite_code: &invite,
            handle: &random_handle(prefix),
            display_name: "Device Test",
            password: PASSWORD,
        })
        .await
        .unwrap();
    Account {
        handle: registered.handle.as_str().to_owned(),
        recovery_key: registered.recovery_key.display().to_string(),
    }
}

async fn sign_in(computer: &InstanceClient, handle: &str, password: &str) -> SignedIn {
    match computer.login(handle, password).await.unwrap() {
        LoginStep::Done(signed_in) => *signed_in,
        LoginStep::TotpRequired(_) => panic!("unexpected TOTP step"),
    }
}

fn store_key(client: &Client) -> [u8; 32] {
    *client.local_store_key().expose()
}

async fn active_devices(server: &Server, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM devices WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user_id)
        .fetch_one(&server.state.db)
        .await
        .unwrap()
}

/// Requirements 1 and 4: signing out and back in finds the same device and
/// the same store key, and while signed out the computer holds neither the
/// store key nor the session token.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn signing_out_and_back_in_finds_the_same_device_and_store() {
    let server = Server::spawn().await;
    let (computer, store) = server.new_computer_with_store();
    let account = register(&server, &computer, "back").await;

    let first = sign_in(&computer, &account.handle, PASSWORD).await;
    assert!(first.new_device && !first.store_reset);
    let (device_id, key) = (first.client.device_id(), store_key(&first.client));
    let user_id = first.client.user_id();

    first.client.logout().await.unwrap();
    // Signed out: nothing on the computer opens the store or the session.
    let kept = store.all_bytes();
    assert!(!kept.is_empty());
    assert!(
        !kept.windows(32).any(|window| window == key),
        "the store key must not stay on the computer"
    );
    let as_text = String::from_utf8_lossy(&kept).into_owned();
    assert!(!as_text.contains("\"session_token\":\"") && !as_text.contains("\"store_key\":\""));
    assert!(computer.resume().await.unwrap().is_none());

    let again = sign_in(&computer, &account.handle, PASSWORD).await;
    assert!(!again.new_device && !again.store_reset);
    assert_eq!(again.client.device_id(), device_id);
    assert_eq!(store_key(&again.client), key);
    assert_eq!(active_devices(&server, user_id).await, 1);

    // Signed in, the computer resumes on its own, with the same key.
    let resumed = computer.resume().await.unwrap().expect("still signed in");
    assert_eq!(store_key(&resumed), key);
}

/// Requirement 2: several accounts in one profile each keep their device.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn accounts_alternating_in_one_profile_keep_their_devices() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let alice = register(&server, &computer, "alt_a").await;
    let bob = register(&server, &computer, "alt_b").await;

    let a1 = sign_in(&computer, &alice.handle, PASSWORD).await;
    let (a_device, a_key, a_user) = (
        a1.client.device_id(),
        store_key(&a1.client),
        a1.client.user_id(),
    );
    a1.client.logout().await.unwrap();
    let b1 = sign_in(&computer, &bob.handle, PASSWORD).await;
    let (b_device, b_user) = (b1.client.device_id(), b1.client.user_id());
    b1.client.logout().await.unwrap();

    for _ in 0..3 {
        let a = sign_in(&computer, &alice.handle, PASSWORD).await;
        assert!(!a.new_device);
        assert_eq!(a.client.device_id(), a_device);
        assert_eq!(store_key(&a.client), a_key);
        a.client.logout().await.unwrap();
        let b = sign_in(&computer, &bob.handle, PASSWORD).await;
        assert!(!b.new_device);
        assert_eq!(b.client.device_id(), b_device);
        b.client.logout().await.unwrap();
    }
    assert_eq!(active_devices(&server, a_user).await, 1);
    assert_eq!(active_devices(&server, b_user).await, 1);

    let known = computer.known_accounts().unwrap();
    let handles: Vec<&str> = known.accounts.iter().map(|a| a.handle.as_str()).collect();
    assert_eq!(handles, [alice.handle.as_str(), bob.handle.as_str()]);
    assert_eq!(known.last, Some(b_user));
    assert_eq!(
        computer.remembered_handle().unwrap().as_deref(),
        Some(bob.handle.as_str())
    );
    // Another profile on the same computer knows none of them.
    let (_, store) = server.new_computer_with_store();
    assert!(
        server
            .computer(&store, Some("second"))
            .known_accounts()
            .unwrap()
            .accounts
            .is_empty()
    );
}

/// Requirement 3: erasing revokes the device, destroys the server's part of
/// the store key and forgets the account on this computer.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn erasing_a_device_revokes_it_and_leaves_nothing() {
    let server = Server::spawn().await;
    let (computer, store) = server.new_computer_with_store();
    let account = register(&server, &computer, "erase").await;
    let first = sign_in(&computer, &account.handle, PASSWORD).await;
    let (device_id, key, user_id) = (
        first.client.device_id(),
        store_key(&first.client),
        first.client.user_id(),
    );

    first.client.erase_device().await.unwrap();

    let share: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT local_store_share FROM devices WHERE id = $1 AND revoked_at IS NOT NULL",
    )
    .bind(device_id)
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(share, None, "the server's part is destroyed");
    assert!(computer.known_accounts().unwrap().accounts.is_empty());
    assert!(computer.remembered_handle().unwrap().is_none());
    let left = String::from_utf8_lossy(&store.all_bytes()).into_owned();
    assert!(!left.contains(&device_id.to_string()));

    // The next sign-in is a new device, with a new store.
    let next = sign_in(&computer, &account.handle, PASSWORD).await;
    assert!(next.new_device);
    assert_ne!(next.client.device_id(), device_id);
    assert_ne!(store_key(&next.client), key);
    assert_eq!(active_devices(&server, user_id).await, 1);
}

/// The store of a signed-out device opens again after the password was
/// changed on another device, and after a recovery: both keep the account
/// root secret.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_signed_out_store_survives_a_password_change_and_a_recovery() {
    let server = Server::spawn().await;
    let laptop = server.new_computer();
    let desktop = server.new_computer();
    let account = register(&server, &laptop, "keep").await;

    let on_laptop = sign_in(&laptop, &account.handle, PASSWORD).await.client;
    let (laptop_device, laptop_key) = (on_laptop.device_id(), store_key(&on_laptop));
    on_laptop.logout().await.unwrap();

    // Password changed on the desktop.
    let on_desktop = sign_in(&desktop, &account.handle, PASSWORD).await.client;
    let reauth = on_desktop.reauthenticate(PASSWORD, None).await.unwrap();
    on_desktop
        .change_password(reauth, NEW_PASSWORD)
        .await
        .unwrap();

    let back = sign_in(&laptop, &account.handle, NEW_PASSWORD).await;
    assert!(!back.new_device && !back.store_reset);
    assert_eq!(back.client.device_id(), laptop_device);
    assert_eq!(store_key(&back.client), laptop_key);
    back.client.logout().await.unwrap();

    // Recovery with the recovery key, from a computer never used before.
    server
        .new_computer()
        .recover(&account.handle, &account.recovery_key, PASSWORD)
        .await
        .unwrap();
    let back = sign_in(&laptop, &account.handle, PASSWORD).await;
    assert!(!back.new_device && !back.store_reset);
    assert_eq!(store_key(&back.client), laptop_key);
}

/// If the instance lost its part (an old backup restored), the device signs
/// in but its store cannot be opened: the client says so and starts a new
/// one, which then survives sign-out as usual.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_lost_server_part_resets_the_store_and_says_so() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let account = register(&server, &computer, "lost").await;
    let first = sign_in(&computer, &account.handle, PASSWORD).await.client;
    let (device_id, key) = (first.device_id(), store_key(&first));
    first.logout().await.unwrap();

    sqlx::query("UPDATE devices SET local_store_share = NULL WHERE id = $1")
        .bind(device_id)
        .execute(&server.state.db)
        .await
        .unwrap();

    let back = sign_in(&computer, &account.handle, PASSWORD).await;
    assert!(!back.new_device, "still the same device");
    assert!(back.store_reset);
    assert_eq!(back.client.device_id(), device_id);
    let new_key = store_key(&back.client);
    assert_ne!(new_key, key);
    back.client.logout().await.unwrap();

    let again = sign_in(&computer, &account.handle, PASSWORD).await;
    assert!(!again.store_reset);
    assert_eq!(store_key(&again.client), new_key);
}

/// A revoked device is told so at sign-in and forgets the account.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_device_revoked_while_signed_out_is_forgotten_at_sign_in() {
    let server = Server::spawn().await;
    let laptop = server.new_computer();
    let account = register(&server, &laptop, "gone").await;
    let on_laptop = sign_in(&laptop, &account.handle, PASSWORD).await.client;
    let laptop_device = on_laptop.device_id();
    on_laptop.logout().await.unwrap();

    let on_desktop = sign_in(&server.new_computer(), &account.handle, PASSWORD)
        .await
        .client;
    on_desktop.revoke_device(laptop_device).await.unwrap();

    let error = laptop.login(&account.handle, PASSWORD).await.unwrap_err();
    assert!(matches!(error, ClientError::DeviceRevoked), "{error:?}");
    assert!(laptop.known_accounts().unwrap().accounts.is_empty());
    let next = sign_in(&laptop, &account.handle, PASSWORD).await;
    assert!(next.new_device);
}
