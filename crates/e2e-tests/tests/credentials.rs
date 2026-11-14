// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end scenarios for credential changes: recovery with the recovery
//! key, password change, recovery key rotation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use tavern_client_core::{
    Client, ClientError, GatewayEvent, InstanceClient, LoginStep, NewAccount, SessionEnd,
};
use tavern_e2e_tests::{PASSWORD, Server, next_event, random_handle};
use tavern_protocol::rest::ErrorCode;

const NEW_PASSWORD: &str = "girafe-orage-71-lanterne";

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
            display_name: "Credential Test",
            password: PASSWORD,
        })
        .await
        .unwrap();
    Account {
        handle: registered.handle.as_str().to_owned(),
        recovery_key: registered.recovery_key.display().to_string(),
    }
}

async fn login(computer: &InstanceClient, handle: &str, password: &str) -> (Client, bool) {
    match computer.login(handle, password).await.unwrap() {
        LoginStep::Done(signed_in) => (signed_in.client, signed_in.new_device),
        LoginStep::TotpRequired(_) => panic!("unexpected TOTP step"),
    }
}

/// The recovery key is shown at registration, so it must work: a user who
/// forgot their password sets a new one and keeps their identity.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_forgotten_password_is_replaced_with_the_recovery_key() {
    let server = Server::spawn().await;
    let laptop = server.new_computer();
    let account = register(&server, &laptop, "forgot").await;
    let (laptop_client, _) = login(&laptop, &account.handle, PASSWORD).await;
    let identity_before = laptop_client.me().await.unwrap().identity_key;
    let device_before = laptop_client.device_id();
    let (_gateway, mut events) = laptop_client.connect_gateway().unwrap();
    assert!(matches!(
        next_event(&mut events).await,
        GatewayEvent::Connected { .. }
    ));

    // The key is typed back by hand: lower case, spaces instead of hyphens.
    let retyped = account.recovery_key.to_lowercase().replace('-', " ");
    server
        .new_computer()
        .recover(&account.handle, &retyped, NEW_PASSWORD)
        .await
        .unwrap();

    // Every session ended, and the connected device was told why.
    assert_eq!(
        next_event(&mut events).await,
        GatewayEvent::SessionEnded(SessionEnd::CredentialsChanged)
    );
    assert!(matches!(
        laptop_client.me().await.unwrap_err(),
        ClientError::SessionEnded
    ));

    // The old password is dead, the new one works.
    let error = laptop.login(&account.handle, PASSWORD).await.unwrap_err();
    assert!(
        matches!(error, ClientError::InvalidCredentials),
        "{error:?}"
    );
    let (client, new_device) = login(&laptop, &account.handle, NEW_PASSWORD).await;

    // Same identity, and the known computer is still the same device.
    assert_eq!(client.me().await.unwrap().identity_key, identity_before);
    assert!(!new_device);
    assert_eq!(client.device_id(), device_before);

    // A brand-new computer can enrol with the new password: the identity key
    // was wrapped again under it.
    let (other, new_device) = login(&server.new_computer(), &account.handle, NEW_PASSWORD).await;
    assert!(new_device);
    assert_eq!(other.me().await.unwrap().identity_key, identity_before);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn recovery_fails_alike_for_a_wrong_key_and_an_unknown_handle() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let alice = register(&server, &computer, "alice").await;
    let bob = register(&server, &computer, "bob").await;

    let wrong_key = computer
        .recover(&alice.handle, &bob.recovery_key, NEW_PASSWORD)
        .await;
    let unknown = computer
        .recover(&random_handle("ghost"), &bob.recovery_key, NEW_PASSWORD)
        .await;
    let malformed = computer
        .recover(&alice.handle, "not a recovery key", NEW_PASSWORD)
        .await;

    for result in [wrong_key, unknown, malformed] {
        let error = result.unwrap_err();
        assert!(
            matches!(error, ClientError::InvalidRecoveryKey),
            "{error:?}"
        );
    }
    // Nothing changed for Alice.
    login(&computer, &alice.handle, PASSWORD).await;

    // A weak new password is refused before anything is sent.
    let weak = computer
        .recover(&alice.handle, &alice.recovery_key, "password1234")
        .await;
    assert!(matches!(weak.unwrap_err(), ClientError::WeakPassword(_)));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn changing_the_password_signs_out_the_other_devices_only() {
    let server = Server::spawn().await;
    let laptop = server.new_computer();
    let desktop = server.new_computer();
    let account = register(&server, &laptop, "change").await;
    let (laptop_client, _) = login(&laptop, &account.handle, PASSWORD).await;
    let (desktop_client, _) = login(&desktop, &account.handle, PASSWORD).await;
    let (_gateway, mut desktop_events) = desktop_client.connect_gateway().unwrap();
    assert!(matches!(
        next_event(&mut desktop_events).await,
        GatewayEvent::Connected { .. }
    ));

    // The current password is required again, and must be right.
    let error = laptop_client
        .reauthenticate("definitely-not-it-9913", None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ClientError::InvalidCredentials),
        "{error:?}"
    );
    let reauth = laptop_client.reauthenticate(PASSWORD, None).await.unwrap();
    let weak = laptop_client
        .change_password(reauth, "password1234")
        .await
        .unwrap_err();
    assert!(matches!(weak, ClientError::WeakPassword(_)));

    let reauth = laptop_client.reauthenticate(PASSWORD, None).await.unwrap();
    laptop_client
        .change_password(reauth, NEW_PASSWORD)
        .await
        .unwrap();

    // This device stays signed in; the other one is signed out and told why.
    assert!(laptop_client.me().await.is_ok());
    assert_eq!(
        next_event(&mut desktop_events).await,
        GatewayEvent::SessionEnded(SessionEnd::CredentialsChanged)
    );
    assert!(matches!(
        desktop_client.me().await.unwrap_err(),
        ClientError::SessionEnded
    ));

    // Only the new password works, and the other device comes back with it
    // as the same device.
    assert!(matches!(
        desktop.login(&account.handle, PASSWORD).await.unwrap_err(),
        ClientError::InvalidCredentials
    ));
    let (again, new_device) = login(&desktop, &account.handle, NEW_PASSWORD).await;
    assert!(!new_device);
    assert_eq!(again.device_id(), desktop_client.device_id());

    // The recovery key still belongs to the account after a password change.
    server
        .new_computer()
        .recover(&account.handle, &account.recovery_key, PASSWORD)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_new_recovery_key_replaces_the_old_one() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let account = register(&server, &computer, "rotate").await;
    let (client, _) = login(&computer, &account.handle, PASSWORD).await;

    let reauth = client.reauthenticate(PASSWORD, None).await.unwrap();
    let new_key = client
        .rotate_recovery_key(reauth)
        .await
        .unwrap()
        .display()
        .to_string();
    assert_ne!(new_key, account.recovery_key);

    // The old key is dead: this is the remedy when a key may have leaked.
    let old = computer
        .recover(&account.handle, &account.recovery_key, NEW_PASSWORD)
        .await;
    assert!(matches!(old.unwrap_err(), ClientError::InvalidRecoveryKey));
    login(&computer, &account.handle, PASSWORD).await;

    // The new key works.
    computer
        .recover(&account.handle, &new_key, NEW_PASSWORD)
        .await
        .unwrap();
    login(&computer, &account.handle, NEW_PASSWORD).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_reauthentication_authorises_one_change_only() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let account = register(&server, &computer, "once").await;
    let (client, _) = login(&computer, &account.handle, PASSWORD).await;

    // Two changes need two re-authentications.
    let reauth = client.reauthenticate(PASSWORD, None).await.unwrap();
    client.rotate_recovery_key(reauth).await.unwrap();
    let reauth = client.reauthenticate(PASSWORD, None).await.unwrap();
    client.change_password(reauth, NEW_PASSWORD).await.unwrap();

    // After the change the old password no longer re-authenticates.
    let error = client.reauthenticate(PASSWORD, None).await.unwrap_err();
    assert!(
        matches!(error, ClientError::InvalidCredentials),
        "{error:?}"
    );
    assert!(client.reauthenticate(NEW_PASSWORD, None).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn recovery_does_not_disable_totp() {
    use std::time::{SystemTime, UNIX_EPOCH};
    use totp_rs::{Algorithm, Builder, Secret};

    let server = Server::spawn().await;
    let computer = server.new_computer();
    let account = register(&server, &computer, "keep2fa").await;
    let (client, _) = login(&computer, &account.handle, PASSWORD).await;
    let enrolment = client.totp_enable().await.unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(&enrolment.secret).unwrap())
        .with_account_name("test")
        .build()
        .unwrap()
        .generate(now)
        .to_string();
    let recovery_codes = client.totp_confirm(&code).await.unwrap().recovery_codes;

    // Re-authentication without the second factor is refused.
    let error = client.reauthenticate(PASSWORD, None).await.unwrap_err();
    assert_eq!(error.api_code(), Some(ErrorCode::TotpRequired));

    computer
        .recover(&account.handle, &account.recovery_key, NEW_PASSWORD)
        .await
        .unwrap();

    // The new password alone is still not enough.
    let LoginStep::TotpRequired(pending) =
        computer.login(&account.handle, NEW_PASSWORD).await.unwrap()
    else {
        panic!("TOTP must still be required after a recovery");
    };
    let signed_in = pending.submit(&recovery_codes[0]).await.unwrap();
    assert!(signed_in.client.me().await.unwrap().totp_enabled);
}
