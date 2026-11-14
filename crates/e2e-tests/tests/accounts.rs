// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end account scenarios: the real client core against the real
//! server and a real PostgreSQL database.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use std::time::{SystemTime, UNIX_EPOCH};

use tavern_client_core::{
    Client, ClientError, GatewayEvent, InstanceClient, InstanceUrl, LoginStep, MemoryStore,
    NewAccount, NewDevice, SessionEnd,
};
use tavern_e2e_tests::{PASSWORD, Server, next_event, random_handle};
use tavern_protocol::rest::ErrorCode;
use totp_rs::{Algorithm, Builder, Secret as TotpSecret};

/// Registers an account from `computer`; returns its canonical handle.
async fn register(server: &Server, computer: &InstanceClient, prefix: &str, admin: bool) -> String {
    let invite = server.host_invite(admin).await;
    let registered = computer
        .register(NewAccount {
            invite_code: &invite,
            handle: &random_handle(prefix),
            display_name: "End To End",
            password: PASSWORD,
        })
        .await
        .unwrap();
    assert_eq!(registered.is_admin, admin);
    assert_eq!(registered.recovery_key.display().len(), 64);
    registered.handle.as_str().to_owned()
}

/// Logs in from `computer`; panics if a TOTP step is requested.
async fn login(computer: &InstanceClient, handle: &str) -> (Client, bool) {
    match computer.login(handle, PASSWORD).await.unwrap() {
        LoginStep::Done(signed_in) => (signed_in.client, signed_in.new_device),
        LoginStep::TotpRequired(_) => panic!("unexpected TOTP step"),
    }
}

fn totp_code(secret_base32: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(TotpSecret::try_from_base32(secret_base32).unwrap())
        .with_account_name("test")
        .build()
        .unwrap()
        .generate(now)
        .to_string()
}

/// The end criterion of milestone M1: a user registers with an invitation
/// code and logs in from two devices.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_user_registers_with_an_invitation_and_logs_in_from_two_devices() {
    let server = Server::spawn().await;
    let laptop = server.new_computer();
    let desktop = server.new_computer();

    // Registration on the laptop, with an invitation created on the host.
    let handle = register(&server, &laptop, "m1", false).await;

    // First login: the laptop is enrolled as a new device.
    let (laptop_client, new_device) = login(&laptop, &handle).await;
    assert!(new_device, "the first login on a computer enrols it");
    let (laptop_gateway, mut laptop_events) = laptop_client.connect_gateway().unwrap();
    assert_eq!(
        next_event(&mut laptop_events).await,
        GatewayEvent::Connected {
            new_devices: Vec::new()
        }
    );

    // Second login, from another computer: a second device.
    let (desktop_client, new_device) = login(&desktop, &handle).await;
    assert!(new_device);
    assert_ne!(desktop_client.device_id(), laptop_client.device_id());
    assert_eq!(desktop_client.user_id(), laptop_client.user_id());

    // The laptop is told at once about the new device.
    assert_eq!(
        next_event(&mut laptop_events).await,
        GatewayEvent::DeviceAdded(desktop_client.device_id())
    );

    // Both devices are signed in and see each other.
    for client in [&laptop_client, &desktop_client] {
        let me = client.me().await.unwrap();
        assert_eq!(me.handle, handle);
        assert_eq!(me.device_id, client.device_id());
        let devices = client.devices().await.unwrap().devices;
        assert_eq!(devices.len(), 2);
        assert!(
            devices
                .iter()
                .any(|d| d.current && d.device_id == client.device_id())
        );
    }
    drop(laptop_gateway);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_known_computer_reopens_its_session_instead_of_enrolling_again() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let handle = register(&server, &computer, "again", false).await;
    let (client, _) = login(&computer, &handle).await;
    let device_id = client.device_id();
    assert_eq!(
        computer.remembered_handle().unwrap().as_deref(),
        Some(handle.as_str())
    );

    // A valid session is resumed without the password.
    let resumed = computer
        .resume()
        .await
        .unwrap()
        .expect("the session is still valid");
    assert_eq!(resumed.device_id(), device_id);

    // After signing out there is nothing to resume, but the device is remembered.
    client.logout().await.unwrap();
    assert!(computer.resume().await.unwrap().is_none());

    let (client, new_device) = login(&computer, &handle).await;
    assert!(!new_device, "the same computer must not be enrolled twice");
    assert_eq!(client.device_id(), device_id);
    assert_eq!(client.devices().await.unwrap().devices.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_device_that_was_away_learns_about_new_devices_when_it_reconnects() {
    let server = Server::spawn().await;
    let laptop = server.new_computer();
    let handle = register(&server, &laptop, "away", false).await;
    let (laptop_client, _) = login(&laptop, &handle).await;

    // Enrolled while the laptop has no connection.
    let (desktop_client, _) = login(&server.new_computer(), &handle).await;

    let (gateway, mut events) = laptop_client.connect_gateway().unwrap();
    let GatewayEvent::Connected { new_devices } = next_event(&mut events).await else {
        panic!("expected Connected");
    };
    assert_eq!(new_devices.len(), 1);
    assert!(
        matches!(new_devices[0], NewDevice { device_id, .. } if device_id == desktop_client.device_id())
    );

    // Once the user has seen it, it is not reported again.
    gateway.ack_device_list().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drop(gateway);
    let (_gateway, mut events) = laptop_client.connect_gateway().unwrap();
    assert_eq!(
        next_event(&mut events).await,
        GatewayEvent::Connected {
            new_devices: Vec::new()
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn wrong_passwords_and_unknown_handles_are_indistinguishable() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let handle = register(&server, &computer, "who", false).await;

    let wrong = computer
        .login(&handle, "not-the-password-at-all-17")
        .await
        .unwrap_err();
    let unknown = computer
        .login(&random_handle("ghost"), PASSWORD)
        .await
        .unwrap_err();
    let impossible = computer
        .login("No Such Handle!", PASSWORD)
        .await
        .unwrap_err();

    for error in [wrong, unknown, impossible] {
        assert!(
            matches!(error, ClientError::InvalidCredentials),
            "{error:?}"
        );
    }
    // Nothing was remembered or enrolled by the failures.
    assert!(computer.remembered_handle().unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_weak_password_is_refused_before_anything_is_sent() {
    // Nothing listens there: reaching the network would fail differently.
    let nowhere = InstanceUrl::parse("http://127.0.0.1:1").unwrap();
    let computer =
        InstanceClient::new(nowhere, std::sync::Arc::new(MemoryStore::default()), None).unwrap();

    for password in ["short", "passwordpassword", "alice_wonder_2026"] {
        let error = computer
            .register(NewAccount {
                invite_code: "0000-0000-0000-0000-0000-0000-00",
                handle: "alice_wonder",
                display_name: "Alice",
                password,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(error, ClientError::WeakPassword(_)),
            "{password}: {error:?}"
        );
    }

    // An invalid handle is refused locally too, with its reason.
    let error = computer
        .register(NewAccount {
            invite_code: "x",
            handle: "Alice Wonder",
            display_name: "Alice",
            password: PASSWORD,
        })
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::InvalidHandle(_)), "{error:?}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn handles_are_canonicalised_by_the_client() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let invite = server.host_invite(false).await;
    let typed = format!("Mixed_{}", random_handle("Case"));

    let registered = computer
        .register(NewAccount {
            invite_code: &invite,
            handle: &typed,
            display_name: "Mixed Case",
            password: PASSWORD,
        })
        .await
        .unwrap();

    assert_eq!(registered.handle.as_str(), typed.to_lowercase());
    // Logging in with either spelling reaches the same account.
    let (client, _) = login(&computer, &typed).await;
    assert_eq!(client.me().await.unwrap().handle, typed.to_lowercase());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn totp_is_asked_at_login_once_enabled() {
    let server = Server::spawn().await;
    let computer = server.new_computer();
    let handle = register(&server, &computer, "totp", false).await;
    let (client, _) = login(&computer, &handle).await;

    let enrolment = client.totp_enable().await.unwrap();
    let codes = client
        .totp_confirm(&totp_code(&enrolment.secret))
        .await
        .unwrap();
    assert_eq!(codes.recovery_codes.len(), 10);
    assert!(client.me().await.unwrap().totp_enabled);
    client.logout().await.unwrap();

    let LoginStep::TotpRequired(pending) = computer.login(&handle, PASSWORD).await.unwrap() else {
        panic!("expected the TOTP step");
    };
    // A wrong code can be corrected without starting over.
    let error = pending.submit("000000").await.unwrap_err();
    assert_eq!(error.api_code(), Some(ErrorCode::TotpInvalid));
    // The confirmation used the current time step, so sign in with a recovery code.
    let signed_in = pending.submit(&codes.recovery_codes[0]).await.unwrap();
    assert!(!signed_in.new_device);
    assert!(signed_in.client.me().await.unwrap().totp_enabled);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_revoked_device_is_signed_out_and_must_enrol_again() {
    let server = Server::spawn().await;
    let laptop = server.new_computer();
    let desktop = server.new_computer();
    let handle = register(&server, &laptop, "revoke", false).await;
    let (laptop_client, _) = login(&laptop, &handle).await;
    let (desktop_client, _) = login(&desktop, &handle).await;
    let (_gateway, mut desktop_events) = desktop_client.connect_gateway().unwrap();
    assert!(matches!(
        next_event(&mut desktop_events).await,
        GatewayEvent::Connected { .. }
    ));

    laptop_client
        .revoke_device(desktop_client.device_id())
        .await
        .unwrap();

    // The desktop is told, and its session no longer works.
    assert_eq!(
        next_event(&mut desktop_events).await,
        GatewayEvent::SessionEnded(SessionEnd::Revoked)
    );
    assert!(matches!(
        desktop_client.me().await.unwrap_err(),
        ClientError::SessionEnded
    ));
    assert!(desktop.resume().await.unwrap().is_none());

    // Its key is refused even with the right password; the record is dropped...
    let error = desktop.login(&handle, PASSWORD).await.unwrap_err();
    assert!(matches!(error, ClientError::DeviceRevoked), "{error:?}");
    // ...and the next login enrols the computer as a new device.
    let (again, new_device) = login(&desktop, &handle).await;
    assert!(new_device);
    assert_ne!(again.device_id(), desktop_client.device_id());
    assert_eq!(laptop_client.devices().await.unwrap().devices.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn an_administrator_invites_a_friend_who_registers() {
    let server = Server::spawn().await;
    let admin_computer = server.new_computer();
    let admin_handle = register(&server, &admin_computer, "admin", true).await;
    let (admin, _) = login(&admin_computer, &admin_handle).await;
    assert!(admin.me().await.unwrap().is_admin);

    let invite = admin.create_invite(None, None).await.unwrap();
    assert!(
        admin
            .invites()
            .await
            .unwrap()
            .invites
            .iter()
            .any(|i| i.invite_id == invite.invite.invite_id)
    );

    let friend_computer = server.new_computer();
    let friend_handle = random_handle("friend");
    let registered = friend_computer
        .register(NewAccount {
            invite_code: &invite.code,
            handle: &friend_handle,
            display_name: "A Friend",
            password: PASSWORD,
        })
        .await
        .unwrap();
    assert!(!registered.is_admin);
    let (friend, _) = login(&friend_computer, &friend_handle).await;

    // The friend is an ordinary user.
    let error = friend.create_invite(None, None).await.unwrap_err();
    assert_eq!(error.api_code(), Some(ErrorCode::Forbidden));
    // The invitation is used up.
    let second = server
        .new_computer()
        .register(NewAccount {
            invite_code: &invite.code,
            handle: &random_handle("late"),
            display_name: "Too Late",
            password: PASSWORD,
        })
        .await
        .unwrap_err();
    assert_eq!(second.api_code(), Some(ErrorCode::InvalidInvite));

    // The administrator sees the friend and can disable the account.
    let users = admin.users().await.unwrap().users;
    assert!(
        users
            .iter()
            .any(|u| u.user_id == friend.user_id() && u.device_count == 1)
    );
    admin
        .set_user_disabled(friend.user_id(), true)
        .await
        .unwrap();
    assert!(matches!(
        friend.me().await.unwrap_err(),
        ClientError::SessionEnded
    ));
    let error = friend_computer
        .login(&friend_handle, PASSWORD)
        .await
        .unwrap_err();
    assert_eq!(error.api_code(), Some(ErrorCode::AccountDisabled));
}
