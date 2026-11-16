// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests of accounts: registration, login, devices, sessions,
//! TOTP and administration, against a real PostgreSQL database.
//!
//! ```sh
//! TAVERN_TEST_DATABASE_URL=postgres://... cargo test -p tavern-server -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use common::{Account, Device, PASSWORD, TestApp, random_handle, session_proof};
use reqwest::{Method, StatusCode};
use tavern_crypto::identity::{AccountRootSecret, DeviceKey};
use tavern_protocol::rest::*;
use tavern_server::gateway::{Event, RevocationReason};
use tavern_server::notices::{self, NoticeKind};
use tavern_server::session::Session;
use totp_rs::{Algorithm, Builder, Secret as TotpSecret};
use uuid::Uuid;

const NO_BODY: Option<&()> = None;

fn totp_code(secret_base32: &str, offset_steps: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let time = (now as i64 + offset_steps * 30) as u64;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(TotpSecret::try_from_base32(secret_base32).unwrap())
        .with_account_name("test")
        .build()
        .unwrap()
        .generate(time)
        .to_string()
}

/// Enables TOTP on an account and returns its secret and recovery codes.
async fn enable_totp(app: &TestApp, session: &B64) -> (String, Vec<String>) {
    let enrolment: TotpEnrolment = app
        .post("/v1/account/totp/enable", Some(session), &())
        .await;
    let codes: TotpRecoveryCodes = app
        .post(
            "/v1/account/totp/confirm",
            Some(session),
            &TotpCodeRequest {
                code: totp_code(&enrolment.secret, -1),
            },
        )
        .await;
    (enrolment.secret, codes.recovery_codes)
}

// --- The M1 criterion ---------------------------------------------------------

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_user_registers_with_an_invite_and_logs_in_from_two_devices() {
    let app = TestApp::spawn().await;
    let account = app.register("alice", false).await;

    let first = app.enrol(&account).await;
    let mut first_connection = app.state.gateway.connect(account.user_id, first.device_id);
    let second = app.enrol(&account).await;

    // The first device is told about the second one.
    assert_eq!(
        first_connection.events.try_recv().unwrap(),
        Event::DeviceListChanged {
            device_id: second.device_id,
            added: true
        }
    );

    // Both sessions work and see both devices.
    for device in [&first, &second] {
        let me: Me = app.get("/v1/users/me", &device.session_token).await;
        assert_eq!(me.user_id, account.user_id);
        assert_eq!(me.handle, account.handle.as_str());
        assert_eq!(me.device_id, device.device_id);
        assert!(!me.is_admin);

        let list: DeviceList = app.get("/v1/devices", &device.session_token).await;
        assert_eq!(list.devices.len(), 2);
        assert_eq!(list.devices.iter().filter(|d| d.current).count(), 1);
        assert!(
            list.devices
                .iter()
                .any(|d| d.current && d.device_id == device.device_id)
        );
    }
}

// --- Registration ---------------------------------------------------------------

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn registration_requires_a_usable_invitation() {
    let app = TestApp::spawn().await;

    let unknown = app
        .register_with(&random_handle("bob"), PASSWORD, "0000-0000-0000-0000")
        .await;
    assert_eq!(
        unknown.err().unwrap(),
        (StatusCode::FORBIDDEN, ErrorCode::InvalidInvite)
    );
    let garbage = app
        .register_with(&random_handle("bob"), PASSWORD, "not a code!")
        .await;
    assert_eq!(garbage.err().unwrap().1, ErrorCode::InvalidInvite);

    // A single-use invitation works once.
    let invite = app.invite(false).await;
    assert!(
        app.register_with(&random_handle("bob"), PASSWORD, &invite)
            .await
            .is_ok()
    );
    let reused = app
        .register_with(&random_handle("bob"), PASSWORD, &invite)
        .await;
    assert_eq!(reused.err().unwrap().1, ErrorCode::InvalidInvite);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_revoked_invitation_cannot_be_used() {
    let app = TestApp::spawn().await;
    let (_, admin_device) = app.account_with_device("admin", true).await;

    let created: CreatedInvite = app
        .post(
            "/v1/admin/invites",
            Some(&admin_device.session_token),
            &CreateInviteRequest {
                max_uses: Some(3),
                expires_in_hours: None,
            },
        )
        .await;
    assert_eq!(created.invite.max_uses, 3);
    let path = format!("/v1/admin/invites/{}", created.invite.invite_id);
    assert_eq!(
        app.status(
            Method::DELETE,
            &path,
            Some(&admin_device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::NO_CONTENT
    );

    let result = app
        .register_with(&random_handle("late"), PASSWORD, &created.code)
        .await;
    assert_eq!(result.err().unwrap().1, ErrorCode::InvalidInvite);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn handles_are_unique_and_must_be_canonical() {
    let app = TestApp::spawn().await;
    let account = app.register("carol", false).await;

    let invite = app.invite(false).await;
    let taken = app
        .register_with(account.handle.as_str(), PASSWORD, &invite)
        .await;
    assert_eq!(
        taken.err().unwrap(),
        (StatusCode::CONFLICT, ErrorCode::HandleTaken)
    );

    // The server never lower-cases or repairs: it refuses.
    for raw in ["Carol_Upper", " carol", "car ol", "c\u{0430}rol", "c"] {
        let request = RegisterStartRequest {
            invite_code: invite.clone(),
            handle: raw.to_owned(),
            registration_request: B64(vec![0; 32]),
        };
        let (status, code) = app
            .post_err("/v1/auth/register/start", None, &request)
            .await;
        assert_eq!(
            (status, code),
            (StatusCode::BAD_REQUEST, ErrorCode::InvalidHandle),
            "{raw:?}"
        );
    }
    // The invitation was not consumed by the failures.
    assert!(
        app.register_with(&random_handle("carol"), PASSWORD, &invite)
            .await
            .is_ok()
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn the_bootstrap_invitation_creates_an_administrator() {
    let app = TestApp::spawn().await;
    let (_, admin_device) = app.account_with_device("root", true).await;
    let (_, user_device) = app.account_with_device("user", false).await;

    let me: Me = app.get("/v1/users/me", &admin_device.session_token).await;
    assert!(me.is_admin);

    let users: AdminUserList = app
        .get("/v1/admin/users", &admin_device.session_token)
        .await;
    assert!(
        users
            .users
            .iter()
            .any(|u| u.user_id == me.user_id && u.is_admin)
    );

    // Ordinary accounts cannot use the administration routes.
    for (method, path) in [
        (Method::GET, "/v1/admin/users".to_owned()),
        (Method::GET, "/v1/admin/invites".to_owned()),
        (
            Method::POST,
            format!("/v1/admin/users/{}/disable", me.user_id),
        ),
        (
            Method::POST,
            format!("/v1/admin/users/{}/totp/disable", me.user_id),
        ),
    ] {
        let status = app
            .status(method, &path, Some(&user_device.session_token), NO_BODY)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    let status = app
        .status(
            Method::POST,
            "/v1/admin/invites",
            Some(&user_device.session_token),
            Some(&CreateInviteRequest {
                max_uses: None,
                expires_in_hours: None,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// --- Login ------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_wrong_password_and_an_unknown_handle_fail_identically() {
    let app = TestApp::spawn().await;
    let account = app.register("dave", false).await;

    let wrong = app
        .login(account.handle.as_str(), "not the password at all")
        .await
        .err()
        .unwrap();
    let unknown = app
        .login(&random_handle("ghost"), PASSWORD)
        .await
        .err()
        .unwrap();

    assert_eq!(
        wrong,
        (StatusCode::UNAUTHORIZED, ErrorCode::InvalidCredentials)
    );
    assert_eq!(unknown, wrong);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn login_start_answers_alike_for_real_and_missing_accounts() {
    let app = TestApp::spawn().await;
    let account = app.register("erin", false).await;
    let request = B64(tavern_crypto::opaque::client::Login::start(
        &tavern_crypto::opaque::Password::new("x"),
    )
    .unwrap()
    .1);

    let ask = |handle: String| {
        let request = request.clone();
        let app = &app;
        async move {
            app.post::<_, LoginStartResponse>(
                "/v1/auth/login/start",
                None,
                &LoginStartRequest {
                    handle,
                    credential_request: request,
                },
            )
            .await
        }
    };
    let real = ask(account.handle.as_str().to_owned()).await;
    let ghost_handle = random_handle("ghost");
    let ghost_1 = ask(ghost_handle.clone()).await;
    let ghost_2 = ask(ghost_handle).await;

    assert_eq!(
        real.credential_response.0.len(),
        ghost_1.credential_response.0.len()
    );
    assert_eq!(real.opaque_suite, ghost_1.opaque_suite);
    assert_eq!(real.login_id.0.len(), ghost_1.login_id.0.len());
    // The repeatable part is stable for a missing account, as for a real one.
    assert_eq!(
        ghost_1.credential_response.0[..32],
        ghost_2.credential_response.0[..32]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_login_exchange_works_once() {
    let app = TestApp::spawn().await;
    let account = app.register("frank", false).await;
    let (_, login_id) = app.login(account.handle.as_str(), PASSWORD).await.unwrap();

    let replay = LoginFinishRequest {
        login_id,
        credential_finalization: B64(vec![0; 64]),
    };
    let (status, code) = app.post_err("/v1/auth/login/finish", None, &replay).await;

    assert_eq!(
        (status, code),
        (StatusCode::GONE, ErrorCode::ExchangeExpired)
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn login_attempts_are_limited_per_handle() {
    let app = TestApp::spawn().await;
    let handle = random_handle("target");
    let request = LoginStartRequest {
        handle,
        credential_request: B64(vec![0; 96]),
    };

    let mut limited = false;
    for _ in 0..8 {
        let (status, _) = app
            .send(Method::POST, "/v1/auth/login/start", None, Some(&request))
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "the per-handle limit never triggered");

    // Another handle is not affected.
    let other = LoginStartRequest {
        handle: random_handle("other"),
        credential_request: B64(vec![0; 96]),
    };
    let (status, _) = app
        .send(Method::POST, "/v1/auth/login/start", None, Some(&other))
        .await;
    assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
}

// --- Devices and sessions -----------------------------------------------------------

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn an_enrolment_token_works_once() {
    let app = TestApp::spawn().await;
    let account = app.register("gina", false).await;
    let grant = app.grant(&account).await;
    app.enrol_with(&account, &grant).await;

    let key = DeviceKey::generate();
    let device_id = Uuid::new_v4();
    let certificate = account.identity.certify_device(
        account.user_id.as_bytes(),
        device_id.as_bytes(),
        &key.public(),
        0,
    );
    let request = EnrolDeviceRequest {
        certificate: B64(certificate),
        name_encrypted: None,
        platform: Platform::Macos,
    };
    let (status, code) = app
        .post_err("/v1/devices", Some(&grant.enrolment_token), &request)
        .await;

    assert_eq!(
        (status, code),
        (StatusCode::UNAUTHORIZED, ErrorCode::Unauthenticated)
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_device_certificate_must_come_from_the_account_itself() {
    let app = TestApp::spawn().await;
    let account = app.register("hank", false).await;
    let other = app.register("ivy", false).await;
    let key = DeviceKey::generate();
    let device_id = Uuid::new_v4();
    let enrol = |certificate: Vec<u8>| EnrolDeviceRequest {
        certificate: B64(certificate),
        name_encrypted: None,
        platform: Platform::Windows,
    };

    // Signed by a key that is not the account's identity key.
    let forged = AccountRootSecret::generate()
        .identity_key()
        .unwrap()
        .certify_device(
            account.user_id.as_bytes(),
            device_id.as_bytes(),
            &key.public(),
            0,
        );
    let grant = app.grant(&account).await;
    let (status, code) = app
        .post_err("/v1/devices", Some(&grant.enrolment_token), &enrol(forged))
        .await;
    assert_eq!(
        (status, code),
        (StatusCode::BAD_REQUEST, ErrorCode::InvalidDeviceCertificate)
    );

    // Correctly signed by another account, presented with this account's token.
    let foreign = other.identity.certify_device(
        other.user_id.as_bytes(),
        device_id.as_bytes(),
        &key.public(),
        0,
    );
    let grant = app.grant(&account).await;
    let (_, code) = app
        .post_err("/v1/devices", Some(&grant.enrolment_token), &enrol(foreign))
        .await;
    assert_eq!(code, ErrorCode::InvalidDeviceCertificate);

    // Signed by this account but naming another one.
    let misdirected = account.identity.certify_device(
        other.user_id.as_bytes(),
        device_id.as_bytes(),
        &key.public(),
        0,
    );
    let grant = app.grant(&account).await;
    let (_, code) = app
        .post_err(
            "/v1/devices",
            Some(&grant.enrolment_token),
            &enrol(misdirected),
        )
        .await;
    assert_eq!(code, ErrorCode::InvalidDeviceCertificate);

    // Garbage.
    let grant = app.grant(&account).await;
    let (_, code) = app
        .post_err(
            "/v1/devices",
            Some(&grant.enrolment_token),
            &enrol(vec![1, 2, 3]),
        )
        .await;
    assert_eq!(code, ErrorCode::InvalidDeviceCertificate);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn an_existing_device_reopens_its_session_with_a_signed_nonce() {
    let app = TestApp::spawn().await;
    let (account, device) = app.account_with_device("jack", false).await;

    let grant = app.grant(&account).await;
    let path = format!("/v1/devices/{}/session", device.device_id);
    let proof = session_proof(&grant, &account, &device);
    let reopened: SessionResponse = app
        .post(
            &path,
            Some(&grant.enrolment_token),
            &ReopenSessionRequest {
                proof: proof.clone(),
            },
        )
        .await;

    // The new token works, the old one no longer does, and no device was added.
    assert_eq!(reopened.device_id, device.device_id);
    let list: DeviceList = app.get("/v1/devices", &reopened.session_token).await;
    assert_eq!(list.devices.len(), 1);
    assert_eq!(
        app.status(
            Method::GET,
            "/v1/users/me",
            Some(&device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::UNAUTHORIZED
    );

    // Replaying the same token and proof fails: the token was consumed.
    let (status, _) = app
        .post_err(
            &path,
            Some(&grant.enrolment_token),
            &ReopenSessionRequest { proof },
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_session_proof_is_refused_when_it_does_not_match() {
    let app = TestApp::spawn().await;
    let (account, device) = app.account_with_device("kate", false).await;
    let (other, other_device) = app.account_with_device("liam", false).await;
    let path = format!("/v1/devices/{}/session", device.device_id);
    let refused = (StatusCode::UNAUTHORIZED, ErrorCode::InvalidProof);

    // A proof made for an earlier nonce.
    let old_grant = app.direct_grant(&account);
    let old_proof = session_proof(&old_grant, &account, &device);
    let grant = app.direct_grant(&account);
    let request = ReopenSessionRequest { proof: old_proof };
    assert_eq!(
        app.post_err(&path, Some(&grant.enrolment_token), &request)
            .await,
        refused
    );

    // A proof signed by another device's key.
    let grant = app.direct_grant(&account);
    let stranger = common::Device {
        device_id: device.device_id,
        key: DeviceKey::generate(),
        session_token: B64(vec![]),
    };
    let request = ReopenSessionRequest {
        proof: session_proof(&grant, &account, &stranger),
    };
    assert_eq!(
        app.post_err(&path, Some(&grant.enrolment_token), &request)
            .await,
        refused
    );

    // Another account's login cannot reopen this device, even with that
    // account's own valid device key.
    let grant = app.direct_grant(&other);
    let request = ReopenSessionRequest {
        proof: session_proof(&grant, &other, &other_device),
    };
    assert_eq!(
        app.post_err(&path, Some(&grant.enrolment_token), &request)
            .await,
        refused
    );

    // An unknown device.
    let grant = app.direct_grant(&account);
    let unknown = format!("/v1/devices/{}/session", Uuid::new_v4());
    let request = ReopenSessionRequest {
        proof: session_proof(&grant, &account, &device),
    };
    assert_eq!(
        app.post_err(&unknown, Some(&grant.enrolment_token), &request)
            .await,
        refused
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_revoked_device_loses_its_session_and_cannot_come_back() {
    let app = TestApp::spawn().await;
    let (account, first) = app.account_with_device("mona", false).await;
    let second = app.enrol(&account).await;
    let mut second_connection = app.state.gateway.connect(account.user_id, second.device_id);
    let mut first_connection = app.state.gateway.connect(account.user_id, first.device_id);

    let path = format!("/v1/devices/{}", second.device_id);
    assert_eq!(
        app.status(Method::DELETE, &path, Some(&first.session_token), NO_BODY)
            .await,
        StatusCode::NO_CONTENT
    );

    assert_eq!(
        second_connection.events.try_recv().unwrap(),
        Event::SessionRevoked(RevocationReason::Revoked)
    );
    assert_eq!(
        first_connection.events.try_recv().unwrap(),
        Event::DeviceListChanged {
            device_id: second.device_id,
            added: false
        }
    );
    assert_eq!(
        app.status(
            Method::GET,
            "/v1/users/me",
            Some(&second.session_token),
            NO_BODY
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    // Even with the right password and its own key, the revoked device is refused.
    let grant = app.grant(&account).await;
    let request = ReopenSessionRequest {
        proof: session_proof(&grant, &account, &second),
    };
    let reopen = format!("/v1/devices/{}/session", second.device_id);
    let (status, code) = app
        .post_err(&reopen, Some(&grant.enrolment_token), &request)
        .await;
    assert_eq!(
        (status, code),
        (StatusCode::UNAUTHORIZED, ErrorCode::InvalidProof)
    );

    // Revoking it again, or revoking someone else's device, finds nothing.
    assert_eq!(
        app.status(Method::DELETE, &path, Some(&first.session_token), NO_BODY)
            .await,
        StatusCode::NOT_FOUND
    );
    let (_, stranger_device) = app.account_with_device("nina", false).await;
    let foreign = format!("/v1/devices/{}", stranger_device.device_id);
    assert_eq!(
        app.status(
            Method::DELETE,
            &foreign,
            Some(&first.session_token),
            NO_BODY
        )
        .await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn requests_without_a_valid_session_are_refused() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("omar", false).await;

    for bearer in [None, Some(B64(vec![0; 32])), Some(B64(vec![1, 2, 3]))] {
        for path in ["/v1/users/me", "/v1/devices", "/v1/admin/users"] {
            let status = app
                .status(Method::GET, path, bearer.as_ref(), NO_BODY)
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    // Logging out ends the session; the device stays enrolled.
    assert_eq!(
        app.status(
            Method::POST,
            "/v1/auth/logout",
            Some(&device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.status(
            Method::GET,
            "/v1/users/me",
            Some(&device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn an_account_cannot_exceed_ten_devices() {
    let app = TestApp::spawn().await;
    let account = app.register("pete", false).await;

    let enrol_one = |app: &TestApp, account: &Account| {
        let grant = app.direct_grant(account);
        let key = DeviceKey::generate();
        let device_id = Uuid::new_v4();
        let certificate = account.identity.certify_device(
            account.user_id.as_bytes(),
            device_id.as_bytes(),
            &key.public(),
            0,
        );
        let request = EnrolDeviceRequest {
            certificate: B64(certificate),
            name_encrypted: Some(B64(vec![7; 40])),
            platform: Platform::Linux,
        };
        (grant.enrolment_token, request)
    };

    for _ in 0..10 {
        let (token, request) = enrol_one(&app, &account);
        let _: SessionResponse = app.post("/v1/devices", Some(&token), &request).await;
    }
    let (token, request) = enrol_one(&app, &account);
    let (status, code) = app.post_err("/v1/devices", Some(&token), &request).await;

    assert_eq!(
        (status, code),
        (StatusCode::CONFLICT, ErrorCode::TooManyDevices)
    );
}

// --- TOTP ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn totp_becomes_a_required_second_step_once_confirmed() {
    let app = TestApp::spawn().await;
    let (account, device) = app.account_with_device("quinn", false).await;

    // A wrong code does not confirm the enrolment.
    let enrolment: TotpEnrolment = app
        .post("/v1/account/totp/enable", Some(&device.session_token), &())
        .await;
    assert!(enrolment.otpauth_url.starts_with("otpauth://totp/Tavern:"));
    let wrong = TotpCodeRequest {
        code: "000000".to_owned(),
    };
    let (status, code) = app
        .post_err(
            "/v1/account/totp/confirm",
            Some(&device.session_token),
            &wrong,
        )
        .await;
    assert_eq!(
        (status, code),
        (StatusCode::UNAUTHORIZED, ErrorCode::TotpInvalid)
    );
    let me: Me = app.get("/v1/users/me", &device.session_token).await;
    assert!(!me.totp_enabled);
    assert!(matches!(
        app.login(account.handle.as_str(), PASSWORD)
            .await
            .unwrap()
            .0,
        LoginOutcome::Ok(_)
    ));

    let codes: TotpRecoveryCodes = app
        .post(
            "/v1/account/totp/confirm",
            Some(&device.session_token),
            &TotpCodeRequest {
                code: totp_code(&enrolment.secret, -1),
            },
        )
        .await;
    assert_eq!(codes.recovery_codes.len(), 10);
    let me: Me = app.get("/v1/users/me", &device.session_token).await;
    assert!(me.totp_enabled);

    // The password alone no longer yields the wrapped key or a token.
    let (outcome, login_id) = app.login(account.handle.as_str(), PASSWORD).await.unwrap();
    assert_eq!(outcome, LoginOutcome::TotpRequired);

    // A wrong code leaves the exchange open; the right one completes it.
    let request = LoginTotpRequest {
        login_id: login_id.clone(),
        code: "123456".to_owned(),
    };
    let (_, code) = app.post_err("/v1/auth/login/totp", None, &request).await;
    assert_eq!(code, ErrorCode::TotpInvalid);
    let current = totp_code(&enrolment.secret, 0);
    let request = LoginTotpRequest {
        login_id,
        code: current.clone(),
    };
    let outcome: LoginOutcome = app.post("/v1/auth/login/totp", None, &request).await;
    let LoginOutcome::Ok(grant) = outcome else {
        panic!("expected a grant")
    };
    assert_eq!(grant.user_id, account.user_id);
    assert!(!grant.wrapped_password_copy.0.is_empty());

    // The same code cannot be used a second time.
    let (outcome, login_id) = app.login(account.handle.as_str(), PASSWORD).await.unwrap();
    assert_eq!(outcome, LoginOutcome::TotpRequired);
    let request = LoginTotpRequest {
        login_id,
        code: current,
    };
    let (_, code) = app.post_err("/v1/auth/login/totp", None, &request).await;
    assert_eq!(code, ErrorCode::TotpInvalid);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_totp_recovery_code_works_once() {
    let app = TestApp::spawn().await;
    let (account, device) = app.account_with_device("rosa", false).await;
    let (_, recovery_codes) = enable_totp(&app, &device.session_token).await;
    let code = recovery_codes[0].to_lowercase().replace('-', " ");

    let (_, login_id) = app.login(account.handle.as_str(), PASSWORD).await.unwrap();
    let request = LoginTotpRequest {
        login_id,
        code: code.clone(),
    };
    let outcome: LoginOutcome = app.post("/v1/auth/login/totp", None, &request).await;
    assert!(matches!(outcome, LoginOutcome::Ok(_)));

    let (_, login_id) = app.login(account.handle.as_str(), PASSWORD).await.unwrap();
    let request = LoginTotpRequest { login_id, code };
    let (_, error) = app.post_err("/v1/auth/login/totp", None, &request).await;
    assert_eq!(error, ErrorCode::TotpInvalid);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn too_many_wrong_totp_codes_close_the_login() {
    let app = TestApp::spawn().await;
    let (account, device) = app.account_with_device("sami", false).await;
    let (secret, _) = enable_totp(&app, &device.session_token).await;
    let (_, login_id) = app.login(account.handle.as_str(), PASSWORD).await.unwrap();

    for _ in 0..5 {
        let request = LoginTotpRequest {
            login_id: login_id.clone(),
            code: "000001".to_owned(),
        };
        let (_, code) = app.post_err("/v1/auth/login/totp", None, &request).await;
        assert_eq!(code, ErrorCode::TotpInvalid);
    }
    // Even the right code is now refused: the login must be restarted.
    let request = LoginTotpRequest {
        login_id,
        code: totp_code(&secret, 0),
    };
    let (status, code) = app.post_err("/v1/auth/login/totp", None, &request).await;
    assert_eq!(
        (status, code),
        (StatusCode::GONE, ErrorCode::ExchangeExpired)
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_user_can_disable_totp_with_a_code() {
    let app = TestApp::spawn().await;
    let (account, device) = app.account_with_device("tara", false).await;
    let (secret, _) = enable_totp(&app, &device.session_token).await;

    let wrong = TotpCodeRequest {
        code: "999999".to_owned(),
    };
    let (_, code) = app
        .post_err(
            "/v1/account/totp/disable",
            Some(&device.session_token),
            &wrong,
        )
        .await;
    assert_eq!(code, ErrorCode::TotpInvalid);

    let right = TotpCodeRequest {
        code: totp_code(&secret, 0),
    };
    let status = app
        .status(
            Method::POST,
            "/v1/account/totp/disable",
            Some(&device.session_token),
            Some(&right),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(matches!(
        app.login(account.handle.as_str(), PASSWORD)
            .await
            .unwrap()
            .0,
        LoginOutcome::Ok(_)
    ));
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn an_administrator_can_disable_a_users_totp_with_a_trace() {
    let app = TestApp::spawn().await;
    let (admin, admin_device) = app.account_with_device("boss", true).await;
    let (user, user_device) = app.account_with_device("uma", false).await;
    enable_totp(&app, &user_device.session_token).await;
    let mut connection = app
        .state
        .gateway
        .connect(user.user_id, user_device.device_id);

    let path = format!("/v1/admin/users/{}/totp/disable", user.user_id);
    assert_eq!(
        app.status(
            Method::POST,
            &path,
            Some(&admin_device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // The user's devices are told, the action is logged, and login no longer asks for a code.
    let Event::SecurityNotice(notice) = connection.events.try_recv().unwrap() else {
        panic!("expected a security notice");
    };
    assert_eq!(notice.kind, NoticeKind::TotpDisabledByAdmin);
    // It is stored for the devices that were not connected.
    let stored: i16 = sqlx::query_scalar("SELECT kind FROM security_notices WHERE id = $1")
        .bind(notice.id)
        .fetch_one(&app.state.db)
        .await
        .unwrap();
    assert_eq!(stored, NoticeKind::TotpDisabledByAdmin as i16);
    let logged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_audit_log WHERE actor_id = $1 AND target_id = $2 AND action = 5",
    )
    .bind(admin.user_id)
    .bind(user.user_id)
    .fetch_one(&app.state.db)
    .await
    .unwrap();
    assert_eq!(logged, 1);
    assert!(matches!(
        app.login(user.handle.as_str(), PASSWORD).await.unwrap().0,
        LoginOutcome::Ok(_)
    ));
    let codes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM totp_recovery_codes WHERE user_id = $1")
            .bind(user.user_id)
            .fetch_one(&app.state.db)
            .await
            .unwrap();
    assert_eq!(codes, 0);

    // An administrator cannot target their own account this way.
    let own = format!("/v1/admin/users/{}/totp/disable", admin.user_id);
    assert_eq!(
        app.status(
            Method::POST,
            &own,
            Some(&admin_device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::BAD_REQUEST
    );
}

// --- Administration -------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_disabled_account_is_logged_out_and_cannot_log_in() {
    let app = TestApp::spawn().await;
    let (_, admin_device) = app.account_with_device("chief", true).await;
    let (user, user_device) = app.account_with_device("vera", false).await;
    let mut connection = app
        .state
        .gateway
        .connect(user.user_id, user_device.device_id);

    let disable = format!("/v1/admin/users/{}/disable", user.user_id);
    assert_eq!(
        app.status(
            Method::POST,
            &disable,
            Some(&admin_device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::NO_CONTENT
    );

    assert_eq!(
        connection.events.try_recv().unwrap(),
        Event::SessionRevoked(RevocationReason::AccountDisabled)
    );
    assert_eq!(
        app.status(
            Method::GET,
            "/v1/users/me",
            Some(&user_device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    // Told only after the right password.
    let login = app
        .login(user.handle.as_str(), PASSWORD)
        .await
        .err()
        .unwrap();
    assert_eq!(login, (StatusCode::FORBIDDEN, ErrorCode::AccountDisabled));
    let wrong = app
        .login(user.handle.as_str(), "some other password")
        .await
        .err()
        .unwrap();
    assert_eq!(wrong.1, ErrorCode::InvalidCredentials);

    let enable = format!("/v1/admin/users/{}/enable", user.user_id);
    assert_eq!(
        app.status(
            Method::POST,
            &enable,
            Some(&admin_device.session_token),
            NO_BODY
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert!(app.login(user.handle.as_str(), PASSWORD).await.is_ok());
}

// --- What the database holds -----------------------------------------------------------

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn the_database_holds_no_password_token_or_private_key() {
    let app = TestApp::spawn().await;
    let password = "a very recognisable passphrase 4217";
    let handle = random_handle("zoe");
    let invite = app.invite(false).await;
    let account = app.register_with(&handle, password, &invite).await.unwrap();
    let grant = match app.login(&handle, password).await.unwrap().0 {
        LoginOutcome::Ok(grant) => grant,
        LoginOutcome::TotpRequired => panic!("unexpected TOTP step"),
    };
    let device = app.enrol_with(&account, &grant).await;
    let (totp_secret, recovery_codes) = enable_totp(&app, &device.session_token).await;

    // Everything the server stores about this account, as one byte string.
    let mut stored: Vec<u8> = Vec::new();
    for query in [
        "SELECT convert_to(row_to_json(u)::text, 'UTF8') FROM users u WHERE id = $1",
        "SELECT convert_to(row_to_json(d)::text, 'UTF8') FROM devices d WHERE user_id = $1",
        "SELECT convert_to(row_to_json(s)::text, 'UTF8') FROM sessions s \
         JOIN devices d ON d.id = s.device_id WHERE d.user_id = $1",
        "SELECT convert_to(row_to_json(c)::text, 'UTF8') FROM totp_recovery_codes c WHERE user_id = $1",
    ] {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(query)
            .bind(account.user_id)
            .fetch_all(&app.state.db)
            .await
            .unwrap();
        assert!(!rows.is_empty(), "{query}");
        stored.extend(rows.concat());
    }
    for query in [
        "SELECT opaque_record || identity_key_wrapped_pw || identity_key_wrapped_rk || totp_secret \
         FROM users WHERE id = $1",
        "SELECT signature_key || certificate FROM devices WHERE user_id = $1",
        "SELECT s.token_hash FROM sessions s JOIN devices d ON d.id = s.device_id WHERE d.user_id = $1",
        "SELECT code_hash FROM totp_recovery_codes WHERE user_id = $1",
    ] {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(query)
            .bind(account.user_id)
            .fetch_all(&app.state.db)
            .await
            .unwrap();
        stored.extend(rows.concat());
    }
    let contains = |needle: &[u8]| stored.windows(needle.len()).any(|window| window == needle);

    assert!(
        contains(handle.as_bytes()),
        "the scan must see the stored rows"
    );
    assert!(!contains(password.as_bytes()), "password");
    assert!(!contains(device.session_token.as_slice()), "session token");
    assert!(
        !contains(grant.enrolment_token.as_slice()),
        "enrolment token"
    );
    assert!(!contains(device.key.seed().expose()), "device private key");
    assert!(!contains(totp_secret.as_bytes()), "TOTP secret (base32)");
    let raw_totp = TotpSecret::try_from_base32(&totp_secret).unwrap();
    assert!(!contains(raw_totp.as_ref()), "TOTP secret (raw)");
    assert!(
        !contains(recovery_codes[0].as_bytes()),
        "TOTP recovery code"
    );
    assert!(
        !contains(account.recovery_key.display().as_bytes()),
        "recovery key"
    );
    assert!(!contains(invite.as_bytes()), "invitation code");
}

fn session_of(account: &Account, device: &Device) -> Session {
    Session {
        user_id: account.user_id,
        device_id: device.device_id,
        is_admin: false,
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn security_notices_are_acknowledged_per_device_and_per_account() {
    let app = TestApp::spawn().await;
    let (ann, ann_laptop) = app.account_with_device("ann", false).await;
    let ann_phone = app.enrol(&ann).await;
    let (bob, bob_laptop) = app.account_with_device("bob", false).await;
    let state = &app.state;

    // The acting device is not told; the other one is.
    let acting = Some(ann_laptop.device_id);
    let notice = notices::record(state, ann.user_id, NoticeKind::RecoveryKeyReplaced, acting)
        .await
        .unwrap();
    let laptop = session_of(&ann, &ann_laptop);
    let phone = session_of(&ann, &ann_phone);
    assert_eq!(notices::pending(state, &laptop).await.unwrap(), []);
    assert_eq!(notices::pending(state, &phone).await.unwrap(), [notice]);

    // Another account neither sees it nor can acknowledge it.
    let stranger = session_of(&bob, &bob_laptop);
    assert_eq!(notices::pending(state, &stranger).await.unwrap(), []);
    notices::acknowledge(state, &stranger, &[notice.id, Uuid::new_v4()])
        .await
        .unwrap();
    assert_eq!(notices::pending(state, &phone).await.unwrap(), [notice]);

    // Acknowledging is idempotent and concerns one device.
    for _ in 0..2 {
        notices::acknowledge(state, &phone, &[notice.id])
            .await
            .unwrap();
    }
    assert_eq!(notices::pending(state, &phone).await.unwrap(), []);

    // A device enrolled later is not told about the past.
    let second = notices::record(state, ann.user_id, NoticeKind::PasswordChanged, None)
        .await
        .unwrap();
    let ann_tablet = app.enrol(&ann).await;
    let tablet = session_of(&ann, &ann_tablet);
    assert_eq!(notices::pending(state, &tablet).await.unwrap(), []);
    assert_eq!(notices::pending(state, &laptop).await.unwrap(), [second]);

    // Except what the user would otherwise observe without an explanation:
    // an administrator disabling TOTP is shown to a later device too, until
    // one device of the account acknowledges it.
    let totp = notices::record(state, ann.user_id, NoticeKind::TotpDisabledByAdmin, None)
        .await
        .unwrap();
    let ann_watch = app.enrol(&ann).await;
    let watch = session_of(&ann, &ann_watch);
    assert_eq!(notices::pending(state, &watch).await.unwrap(), [totp]);
    notices::acknowledge(state, &tablet, &[totp.id])
        .await
        .unwrap();
    assert_eq!(notices::pending(state, &watch).await.unwrap(), []);
    assert_eq!(
        notices::pending(state, &phone).await.unwrap(),
        [second, totp]
    );
    notices::acknowledge(state, &laptop, &[totp.id])
        .await
        .unwrap();

    // Past the retention period a notice is no longer listed, and the next
    // one recorded for the account deletes it.
    sqlx::query(
        "UPDATE security_notices SET created_at = now() - make_interval(days => $2) WHERE id = $1",
    )
    .bind(second.id)
    .bind(notices::RETENTION_DAYS + 1)
    .execute(&state.db)
    .await
    .unwrap();
    assert_eq!(notices::pending(state, &laptop).await.unwrap(), []);
    notices::record(state, ann.user_id, NoticeKind::DeviceRevoked, None)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM security_notices WHERE id = $1")
        .bind(second.id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}
