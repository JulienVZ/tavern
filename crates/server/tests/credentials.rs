// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests of credential changes at the level of the REST API:
//! what the server reveals and what it refuses. The complete flows are
//! covered end to end in `crates/e2e-tests`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

mod common;

use common::{Account, PASSWORD, TestApp, random_handle};
use reqwest::StatusCode;
use tavern_crypto::identity::{
    AccountRootSecret, CredentialUpdate, CredentialUpdatePurpose, IdentityPublicKey, WrappingKey,
};
use tavern_crypto::opaque::Password;
use tavern_crypto::opaque::client::{Login, Registration};
use tavern_protocol::rest::*;

const NEW_PASSWORD: &str = "girafe-orage-71-lanterne";

fn registration_request() -> (Registration, B64) {
    let (state, request) = Registration::start(&Password::new(NEW_PASSWORD)).unwrap();
    (state, B64(request))
}

async fn recover_start(app: &TestApp, handle: &str) -> (Registration, RecoverStartResponse) {
    let (state, registration_request) = registration_request();
    let response = app
        .post(
            "/v1/auth/recover/start",
            None,
            &RecoverStartRequest {
                handle: handle.to_owned(),
                registration_request,
            },
        )
        .await;
    (state, response)
}

/// Builds a valid `recover/finish` request for `account`.
fn recover_finish(
    account: &Account,
    state: Registration,
    start: &RecoverStartResponse,
) -> RecoverFinishRequest {
    let password = Password::new(NEW_PASSWORD);
    let output = state
        .finish(
            &password,
            start.registration_response.as_slice(),
            &account.handle,
        )
        .unwrap();
    let expected = IdentityPublicKey::from_bytes(start.identity_key.as_slice()).unwrap();
    let root = AccountRootSecret::unwrap(
        start.wrapped_recovery_copy.as_slice(),
        &WrappingKey::from_recovery_key(&account.recovery_key).unwrap(),
        &expected,
    )
    .unwrap();
    let identity = root.identity_key().unwrap();
    let wrapped = root
        .wrap(&WrappingKey::from_export_key(&output.export_key).unwrap())
        .unwrap();
    let challenge: [u8; 32] = start.challenge.as_slice().try_into().unwrap();
    let signature = identity.sign_credential_update(&CredentialUpdate {
        purpose: CredentialUpdatePurpose::Recovery,
        challenge: &challenge,
        handle: &account.handle,
        opaque_upload: &output.upload,
        wrapped_password_copy: &wrapped,
        wrapped_recovery_copy: &[],
    });
    RecoverFinishRequest {
        recovery_id: start.recovery_id.clone(),
        registration_upload: B64(output.upload),
        wrapped_password_copy: B64(wrapped),
        signature: B64::from(signature),
    }
}

async fn password_record(app: &TestApp, account: &Account) -> Vec<u8> {
    sqlx::query_scalar("SELECT opaque_record || identity_key_wrapped_pw FROM users WHERE id = $1")
        .bind(account.user_id)
        .fetch_one(&app.state.db)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn recover_start_gives_stable_decoys_for_unknown_handles() {
    let app = TestApp::spawn().await;
    let account = app.register("real", false).await;
    let ghost = random_handle("ghost");

    let (_, real_1) = recover_start(&app, account.handle.as_str()).await;
    let (_, real_2) = recover_start(&app, account.handle.as_str()).await;
    let (_, ghost_1) = recover_start(&app, &ghost).await;
    let (_, ghost_2) = recover_start(&app, &ghost).await;
    let (_, other) = recover_start(&app, &random_handle("other")).await;

    // Asking twice gives the same key material, for a real account and for a
    // missing one alike: repetition tells them apart no better than chance.
    assert_eq!(real_1.identity_key, real_2.identity_key);
    assert_eq!(real_1.wrapped_recovery_copy, real_2.wrapped_recovery_copy);
    assert_eq!(ghost_1.identity_key, ghost_2.identity_key);
    assert_eq!(ghost_1.wrapped_recovery_copy, ghost_2.wrapped_recovery_copy);
    // Decoys differ per handle, and have the shape of the real thing.
    assert_ne!(ghost_1.wrapped_recovery_copy, other.wrapped_recovery_copy);
    assert_eq!(
        ghost_1.wrapped_recovery_copy.0.len(),
        real_1.wrapped_recovery_copy.0.len()
    );
    assert_eq!(
        ghost_1.wrapped_recovery_copy.0[0],
        real_1.wrapped_recovery_copy.0[0]
    );
    assert_eq!(ghost_1.identity_key.0.len(), real_1.identity_key.0.len());
    assert!(IdentityPublicKey::from_bytes(ghost_1.identity_key.as_slice()).is_ok());
    assert_eq!(
        ghost_1.registration_response.0.len(),
        real_1.registration_response.0.len()
    );
    assert_eq!(ghost_1.opaque_suite, real_1.opaque_suite);
    // The challenge is fresh every time.
    assert_ne!(real_1.challenge, real_2.challenge);
    assert_ne!(ghost_1.challenge, ghost_2.challenge);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_recovery_cannot_be_replayed_or_altered() {
    let app = TestApp::spawn_unlimited().await;
    let account = app.register("victim", false).await;
    let refused = (StatusCode::UNAUTHORIZED, ErrorCode::InvalidProof);
    let record_before = password_record(&app, &account).await;

    // Altered after signing: another wrapped copy.
    let (state, start) = recover_start(&app, account.handle.as_str()).await;
    let mut request = recover_finish(&account, state, &start);
    request.wrapped_password_copy.0[10] ^= 1;
    assert_eq!(
        app.post_err("/v1/auth/recover/finish", None, &request)
            .await,
        refused
    );

    // A signature made for one challenge, presented for another exchange.
    let (state_a, start_a) = recover_start(&app, account.handle.as_str()).await;
    let (_, start_b) = recover_start(&app, account.handle.as_str()).await;
    let mut request = recover_finish(&account, state_a, &start_a);
    request.recovery_id = start_b.recovery_id;
    assert_eq!(
        app.post_err("/v1/auth/recover/finish", None, &request)
            .await,
        refused
    );

    // Signed by a key that is not the account's.
    let (state, start) = recover_start(&app, account.handle.as_str()).await;
    let mut request = recover_finish(&account, state, &start);
    let stranger = AccountRootSecret::generate().identity_key().unwrap();
    let challenge: [u8; 32] = start.challenge.as_slice().try_into().unwrap();
    request.signature = B64::from(stranger.sign_credential_update(&CredentialUpdate {
        purpose: CredentialUpdatePurpose::Recovery,
        challenge: &challenge,
        handle: &account.handle,
        opaque_upload: request.registration_upload.as_slice(),
        wrapped_password_copy: request.wrapped_password_copy.as_slice(),
        wrapped_recovery_copy: &[],
    }));
    assert_eq!(
        app.post_err("/v1/auth/recover/finish", None, &request)
            .await,
        refused
    );

    // The password is unchanged by all of the above.
    assert_eq!(password_record(&app, &account).await, record_before);
    assert!(app.login(account.handle.as_str(), PASSWORD).await.is_ok());

    // A valid recovery works once; replaying it finds no exchange.
    let (state, start) = recover_start(&app, account.handle.as_str()).await;
    let request = recover_finish(&account, state, &start);
    let (status, _) = app
        .send(
            reqwest::Method::POST,
            "/v1/auth/recover/finish",
            None,
            Some(&request),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let replay = app
        .post_err("/v1/auth/recover/finish", None, &request)
        .await;
    assert_eq!(replay, (StatusCode::GONE, ErrorCode::ExchangeExpired));
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_recovery_for_an_unknown_handle_can_never_complete() {
    let app = TestApp::spawn().await;
    let (state, start) = recover_start(&app, &random_handle("ghost")).await;
    let handle = tavern_protocol::handle::Handle::parse_canonical("ghost").unwrap();
    let output = state
        .finish(
            &Password::new(NEW_PASSWORD),
            start.registration_response.as_slice(),
            &handle,
        )
        .unwrap();
    let request = RecoverFinishRequest {
        recovery_id: start.recovery_id,
        registration_upload: B64(output.upload),
        wrapped_password_copy: B64(vec![1; 73]),
        signature: B64(vec![0; 64]),
    };

    let (status, code) = app
        .post_err("/v1/auth/recover/finish", None, &request)
        .await;

    assert_eq!(
        (status, code),
        (StatusCode::UNAUTHORIZED, ErrorCode::InvalidProof)
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_reauthentication_token_belongs_to_the_session_that_obtained_it() {
    let app = TestApp::spawn().await;
    let (alice, alice_device) = app.account_with_device("alice", false).await;
    let (_, mallory_device) = app.account_with_device("mallory", false).await;

    // Alice re-authenticates.
    let password = Password::new(PASSWORD);
    let (state, request) = Login::start(&password).unwrap();
    let start: LoginStartResponse = app
        .post(
            "/v1/auth/reauth/start",
            Some(&alice_device.session_token),
            &ReauthStartRequest {
                credential_request: B64(request),
            },
        )
        .await;
    let output = state
        .finish(
            &password,
            start.credential_response.as_slice(),
            &alice.handle,
        )
        .unwrap();
    let finish = ReauthFinishRequest {
        login_id: start.login_id,
        credential_finalization: B64(output.finalization),
        totp_code: None,
    };

    // Mallory cannot finish Alice's exchange from her own session...
    let stolen = app
        .post_err(
            "/v1/auth/reauth/finish",
            Some(&mallory_device.session_token),
            &finish,
        )
        .await;
    assert_eq!(stolen, (StatusCode::GONE, ErrorCode::ExchangeExpired));

    // ...and the attempt consumed nothing Alice could still use by replaying.
    let replay = app
        .post_err(
            "/v1/auth/reauth/finish",
            Some(&alice_device.session_token),
            &finish,
        )
        .await;
    assert_eq!(replay.1, ErrorCode::ExchangeExpired);

    // A token obtained by Alice is useless in Mallory's session.
    let grant = {
        let (state, request) = Login::start(&password).unwrap();
        let start: LoginStartResponse = app
            .post(
                "/v1/auth/reauth/start",
                Some(&alice_device.session_token),
                &ReauthStartRequest {
                    credential_request: B64(request),
                },
            )
            .await;
        let output = state
            .finish(
                &password,
                start.credential_response.as_slice(),
                &alice.handle,
            )
            .unwrap();
        app.post::<_, ReauthGrant>(
            "/v1/auth/reauth/finish",
            Some(&alice_device.session_token),
            &ReauthFinishRequest {
                login_id: start.login_id,
                credential_finalization: B64(output.finalization),
                totp_code: None,
            },
        )
        .await
    };
    let (_, registration_request) = registration_request();
    let request = PasswordStartRequest {
        reauth_token: grant.reauth_token.clone(),
        registration_request,
    };
    let foreign = app
        .post_err(
            "/v1/account/password/start",
            Some(&mallory_device.session_token),
            &request,
        )
        .await;
    assert_eq!(foreign, (StatusCode::GONE, ErrorCode::ExchangeExpired));
    let rotate = RotateRecoveryKeyRequest {
        reauth_token: grant.reauth_token,
        wrapped_recovery_copy: B64(vec![1; 73]),
        signature: B64(vec![0; 64]),
    };
    let foreign = app
        .post_err(
            "/v1/account/recovery-key",
            Some(&mallory_device.session_token),
            &rotate,
        )
        .await;
    assert_eq!(foreign.1, ErrorCode::ExchangeExpired);

    // Without a session none of these routes answer.
    let (status, _) = app
        .send(
            reqwest::Method::POST,
            "/v1/account/recovery-key",
            None,
            Some(&rotate),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
