// SPDX-License-Identifier: AGPL-3.0-or-later

//! Security notices, end to end: every device of an account learns about a
//! security-relevant event, whether it was connected when it happened or not
//! (ADR 0016).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tavern_client_core::{
    Client, GatewayEvent, InstanceClient, LoginStep, NewAccount, SecurityNotice, SecurityNoticeKind,
};
use tavern_e2e_tests::{PASSWORD, Server, next_event, random_handle};
use totp_rs::{Algorithm, Builder, Secret as TotpSecret};

const NEW_PASSWORD: &str = "a-second-quite-long-passphrase-58";

struct Account {
    handle: String,
    recovery_key: String,
}

async fn register(
    server: &Server,
    computer: &InstanceClient,
    prefix: &str,
    admin: bool,
) -> Account {
    let invite = server.host_invite(admin).await;
    let registered = computer
        .register(NewAccount {
            invite_code: &invite,
            handle: &random_handle(prefix),
            display_name: "Notice Test",
            password: PASSWORD,
        })
        .await
        .unwrap();
    Account {
        handle: registered.handle.as_str().to_owned(),
        recovery_key: registered.recovery_key.display().to_string(),
    }
}

async fn login(computer: &InstanceClient, handle: &str, password: &str) -> Client {
    match computer.login(handle, password).await.unwrap() {
        LoginStep::Done(signed_in) => signed_in.client,
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
        .build()
        .unwrap()
        .generate(now)
        .to_string()
}

/// Connects, returns the notices listed in `Ready`, and disconnects.
async fn pending(client: &Client) -> Vec<SecurityNotice> {
    let (_gateway, mut events) = client.connect_gateway().unwrap();
    let GatewayEvent::Connected {
        security_notices, ..
    } = next_event(&mut events).await
    else {
        panic!("expected Connected");
    };
    security_notices
}

fn kinds(notices: &[SecurityNotice]) -> Vec<SecurityNoticeKind> {
    notices.iter().map(|notice| notice.kind).collect()
}

/// The scenario of the bug report: an administrator disables a user's TOTP
/// from the client. The device that is connected is told at once, the one
/// that is not is told when it connects, each acknowledges for itself, and
/// the action is in the audit log.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn an_administrator_disables_totp_and_every_device_of_the_user_is_told() {
    let server = Server::spawn().await;
    let admin_computer = server.new_computer();
    let admin_account = register(&server, &admin_computer, "boss", true).await;
    let admin = login(&admin_computer, &admin_account.handle, PASSWORD).await;

    let laptop_computer = server.new_computer();
    let account = register(&server, &laptop_computer, "uma", false).await;
    let laptop = login(&laptop_computer, &account.handle, PASSWORD).await;
    let desktop = login(&server.new_computer(), &account.handle, PASSWORD).await;
    let enrolment = laptop.totp_enable().await.unwrap();
    laptop
        .totp_confirm(&totp_code(&enrolment.secret))
        .await
        .unwrap();

    // The laptop is connected, the desktop is not.
    let (laptop_gateway, mut laptop_events) = laptop.connect_gateway().unwrap();
    assert!(matches!(
        next_event(&mut laptop_events).await,
        GatewayEvent::Connected { security_notices, .. } if security_notices.is_empty()
    ));

    let users = admin.users().await.unwrap().users;
    let target = users
        .iter()
        .find(|user| user.user_id == laptop.user_id())
        .unwrap();
    assert!(target.totp_enabled);
    admin.disable_user_totp(target.user_id).await.unwrap();

    // Connected device: told at once.
    let GatewayEvent::SecurityNotice(live) = next_event(&mut laptop_events).await else {
        panic!("expected a security notice");
    };
    assert_eq!(live.kind, SecurityNoticeKind::TotpDisabledByAdmin);
    assert!(live.created_at_ms > 0);

    // Offline device: told when it connects, and again until it acknowledges.
    assert_eq!(pending(&desktop).await, [live]);
    let (desktop_gateway, mut desktop_events) = desktop.connect_gateway().unwrap();
    assert!(matches!(
        next_event(&mut desktop_events).await,
        GatewayEvent::Connected { security_notices, .. } if security_notices == [live]
    ));
    desktop_gateway
        .ack_security_notices(&[live.notice_id])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(desktop_gateway);
    assert_eq!(pending(&desktop).await, []);

    // The laptop saw the event but did not acknowledge it: still pending there.
    drop(laptop_gateway);
    assert_eq!(pending(&laptop).await, [live]);
    // The administrator's own account has nothing to be told.
    assert_eq!(pending(&admin).await, []);

    // Logged, and effective: sign-in no longer asks for a code.
    let logged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_audit_log WHERE actor_id = $1 AND target_id = $2 AND action = 5",
    )
    .bind(admin.user_id())
    .bind(laptop.user_id())
    .fetch_one(&server.state.db)
    .await
    .unwrap();
    assert_eq!(logged, 1);
    assert!(!laptop.me().await.unwrap().totp_enabled);
    laptop.logout().await.unwrap();
    login(&laptop_computer, &account.handle, PASSWORD).await;
}

/// The events of M1 that used to reach connected devices only, or no device
/// at all: each leaves a notice for the devices that did not do it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn credential_and_device_changes_leave_a_notice_on_the_other_devices() {
    let server = Server::spawn().await;
    let laptop_computer = server.new_computer();
    let desktop_computer = server.new_computer();
    let account = register(&server, &laptop_computer, "ned", false).await;
    let laptop = login(&laptop_computer, &account.handle, PASSWORD).await;
    let desktop = login(&desktop_computer, &account.handle, PASSWORD).await;
    let spare = login(&server.new_computer(), &account.handle, PASSWORD).await;

    // A device is revoked, then the recovery key is replaced, from the laptop.
    laptop.revoke_device(spare.device_id()).await.unwrap();
    let reauth = laptop.reauthenticate(PASSWORD, None).await.unwrap();
    let new_key = laptop
        .rotate_recovery_key(reauth)
        .await
        .unwrap()
        .display()
        .to_string();
    assert_ne!(new_key, account.recovery_key);

    // The laptop did it: nothing to tell. The desktop, offline, learns both.
    assert_eq!(pending(&laptop).await, []);
    assert_eq!(
        kinds(&pending(&desktop).await),
        [
            SecurityNoticeKind::DeviceRevoked,
            SecurityNoticeKind::RecoveryKeyReplaced
        ]
    );

    // The password is changed from the laptop: the desktop is signed out,
    // and finds the notice when its user signs in again.
    let reauth = laptop.reauthenticate(PASSWORD, None).await.unwrap();
    laptop.change_password(reauth, NEW_PASSWORD).await.unwrap();
    assert_eq!(pending(&laptop).await, []);
    let desktop = login(&desktop_computer, &account.handle, NEW_PASSWORD).await;
    let listed = pending(&desktop).await;
    assert_eq!(
        kinds(&listed),
        [
            SecurityNoticeKind::DeviceRevoked,
            SecurityNoticeKind::RecoveryKeyReplaced,
            SecurityNoticeKind::PasswordChanged
        ]
    );

    // Dismissing all of them empties the list on that device.
    let (gateway, mut events) = desktop.connect_gateway().unwrap();
    next_event(&mut events).await;
    let ids: Vec<_> = listed.iter().map(|notice| notice.notice_id).collect();
    gateway.ack_security_notices(&ids).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(gateway);
    assert_eq!(pending(&desktop).await, []);

    // The account is recovered with the recovery key from a computer that
    // was never enrolled. No device is known to have done it, so the notice
    // is shown everywhere, including on computers enrolled afterwards, until
    // one device of the account acknowledges it.
    let newcomer_computer = server.new_computer();
    newcomer_computer
        .recover(&account.handle, &new_key, PASSWORD)
        .await
        .unwrap();
    let newcomer = login(&newcomer_computer, &account.handle, PASSWORD).await;
    let listed = pending(&newcomer).await;
    assert_eq!(kinds(&listed), [SecurityNoticeKind::AccountRecovered]);
    let laptop = login(&laptop_computer, &account.handle, PASSWORD).await;
    assert_eq!(pending(&laptop).await, listed);

    // Acknowledged on the laptop: computers enrolled from now on are not
    // told, the newcomer no longer is, and the desktop, which existed when
    // it happened, still is.
    let (gateway, mut events) = laptop.connect_gateway().unwrap();
    next_event(&mut events).await;
    gateway
        .ack_security_notices(&[listed[0].notice_id])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(gateway);
    assert_eq!(pending(&laptop).await, []);
    assert_eq!(pending(&newcomer).await, []);
    let latecomer = login(&server.new_computer(), &account.handle, PASSWORD).await;
    assert_eq!(pending(&latecomer).await, []);
    let desktop = login(&desktop_computer, &account.handle, PASSWORD).await;
    assert_eq!(pending(&desktop).await, listed);
}

/// Found in manual testing: the user had signed out everywhere when the
/// administrator disabled TOTP, and signed in next from a computer that had
/// to be enrolled. Sign-in no longer asked for a code and nothing said why.
/// A device enrolled after the event is told too, until some device of the
/// account acknowledges the notice or TOTP is enabled again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn a_computer_enrolled_after_totp_was_disabled_is_told_too() {
    let server = Server::spawn().await;
    let admin_computer = server.new_computer();
    let admin_account = register(&server, &admin_computer, "boss", true).await;
    let admin = login(&admin_computer, &admin_account.handle, PASSWORD).await;

    let laptop_computer = server.new_computer();
    let account = register(&server, &laptop_computer, "ola", false).await;
    let laptop = login(&laptop_computer, &account.handle, PASSWORD).await;
    let enrolment = laptop.totp_enable().await.unwrap();
    laptop
        .totp_confirm(&totp_code(&enrolment.secret))
        .await
        .unwrap();
    let user_id = laptop.user_id();
    // Signed out everywhere when it happens.
    laptop.logout().await.unwrap();
    admin.disable_user_totp(user_id).await.unwrap();

    // Next sign-in, from a computer enrolled only now: told.
    let newcomer = login(&server.new_computer(), &account.handle, PASSWORD).await;
    let listed = pending(&newcomer).await;
    assert_eq!(kinds(&listed), [SecurityNoticeKind::TotpDisabledByAdmin]);
    // And again at the next connection, as long as it is not acknowledged.
    assert_eq!(pending(&newcomer).await, listed);

    // Once a device of the account acknowledged it, computers enrolled later
    // are no longer told; the laptop, which existed then, still is.
    let (gateway, mut events) = newcomer.connect_gateway().unwrap();
    next_event(&mut events).await;
    gateway
        .ack_security_notices(&[listed[0].notice_id])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(gateway);
    assert_eq!(pending(&newcomer).await, []);
    let latecomer = login(&server.new_computer(), &account.handle, PASSWORD).await;
    assert_eq!(pending(&latecomer).await, []);
    let laptop = login(&laptop_computer, &account.handle, PASSWORD).await;
    assert_eq!(pending(&laptop).await, listed);

    // Enabling TOTP again settles the matter on every device.
    let enrolment = laptop.totp_enable().await.unwrap();
    laptop
        .totp_confirm(&totp_code(&enrolment.secret))
        .await
        .unwrap();
    assert_eq!(pending(&laptop).await, []);
}
