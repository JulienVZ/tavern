// SPDX-License-Identifier: AGPL-3.0-or-later

//! KeyPackages (ADR 0019, section 3): uploads, counts and claims, against a
//! real server and database, with KeyPackages built by `tavern-crypto` as a
//! client builds them.
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

use common::{Device, TestApp};
use reqwest::{Method, StatusCode};
use tavern_crypto::identity::{DeviceKey, ID_LEN, IdentityPublicKey};
use tavern_crypto::mls::{Roster, VerifiedLeaf, key_package};
use tavern_protocol::rest::{
    B64, ErrorBody, ErrorCode, KeyPackageClaim, KeyPackageCount, UploadKeyPackagesRequest,
};
use uuid::Uuid;

const UPLOAD: &str = "/v1/devices/me/key-packages";
const COUNT: &str = "/v1/devices/me/key-packages/count";

fn upload_request(one_time: Vec<B64>, last_resort: Option<B64>) -> UploadKeyPackagesRequest {
    UploadKeyPackagesRequest {
        key_packages: one_time,
        last_resort,
    }
}

async fn upload(
    app: &TestApp,
    device: &Device,
    one_time: Vec<B64>,
    last_resort: Option<B64>,
) -> u32 {
    let count: KeyPackageCount = app
        .post(
            UPLOAD,
            Some(&device.session_token),
            &upload_request(one_time, last_resort),
        )
        .await;
    count.one_time
}

async fn upload_err(
    app: &TestApp,
    device: &Device,
    one_time: Vec<B64>,
    last_resort: Option<B64>,
) -> (StatusCode, ErrorCode) {
    app.post_err(
        UPLOAD,
        Some(&device.session_token),
        &upload_request(one_time, last_resort),
    )
    .await
}

async fn count(app: &TestApp, device: &Device) -> u32 {
    let count: KeyPackageCount = app.get(COUNT, &device.session_token).await;
    count.one_time
}

async fn claim(
    app: &TestApp,
    device: &Device,
    user: Uuid,
) -> Result<KeyPackageClaim, (StatusCode, ErrorCode, Option<u64>)> {
    let (status, bytes) = app
        .send::<()>(
            Method::POST,
            &format!("/v1/users/{user}/key-packages/claim"),
            Some(&device.session_token),
            None,
        )
        .await;
    if status.is_success() {
        return Ok(serde_json::from_slice(&bytes).unwrap());
    }
    let error: ErrorBody = serde_json::from_slice(&bytes).unwrap();
    Err((status, error.code, error.retry_after_ms))
}

/// The devices a claim served, in order.
async fn claimed_devices(app: &TestApp, device: &Device, user: Uuid) -> Vec<Uuid> {
    claim(app, device, user)
        .await
        .unwrap()
        .key_packages
        .iter()
        .map(|served| served.device_id)
        .collect()
}

/// The one-time packages of `device` still to serve, and its last resort,
/// which stays stored once served (its first serving is recorded).
async fn stored(app: &TestApp, device: &Device) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE NOT last_resort AND served_at IS NULL), \
                count(*) FILTER (WHERE last_resort) \
         FROM key_packages WHERE device_id = $1",
    )
    .bind(device.device_id)
    .fetch_one(&app.state.db)
    .await
    .unwrap()
}

/// The identity key a claiming device trusts for one user.
struct Keys(Uuid, IdentityPublicKey);

impl Roster for Keys {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        (user_id == self.0.as_bytes()).then_some(self.1)
    }
}

/// Makes `device` look away for `days` whole days, enrolled long before.
async fn away(app: &TestApp, device: &Device, days: i32) {
    sqlx::query(
        "UPDATE devices SET created_at = now() - interval '90 days', \
         last_seen_at = date_trunc('day', now()) - make_interval(days => $2) WHERE id = $1",
    )
    .bind(device.device_id)
    .bind(days)
    .execute(&app.state.db)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn uploads_are_counted_kept_once_and_replace_the_last_resort() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("kp", false).await;
    assert_eq!(count(&app, &device).await, 0);

    let one_time = device.key_packages(3);
    let last_resort = device.key_package(true);
    assert_eq!(
        upload(&app, &device, one_time.clone(), Some(last_resort.clone())).await,
        3
    );
    assert_eq!(count(&app, &device).await, 3);
    // A retried upload stores nothing twice.
    assert_eq!(upload(&app, &device, one_time, Some(last_resort)).await, 3);
    assert_eq!(stored(&app, &device).await, (3, 1));

    // A new last-resort package replaces the current one.
    let newer = device.key_package(true);
    assert_eq!(upload(&app, &device, vec![], Some(newer.clone())).await, 3);
    let kept: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT key_package FROM key_packages WHERE device_id = $1 AND last_resort",
    )
    .bind(device.device_id)
    .fetch_all(&app.state.db)
    .await
    .unwrap();
    assert_eq!(kept, [newer.0]);
}

/// One refused package refuses the whole upload: garbage, another device's
/// package, or one of this device's id that does not carry the key and
/// certificate it enrolled with (ADR 0019, section 2), or a package in the
/// wrong slot.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn an_upload_is_refused_whole_for_one_refused_package() {
    let app = TestApp::spawn().await;
    let (account, device) = app.account_with_device("kp", false).await;
    let sibling = app.enrol(&account).await;
    let (_, stranger) = app.account_with_device("kp", false).await;
    // Both certified by the account's identity key, under this device's id.
    let recertified = Device::unenrolled(
        device.device_id,
        DeviceKey::from_seed(&device.key.seed()),
        account.identity.certify_device(
            account.user_id.as_bytes(),
            device.device_id.as_bytes(),
            &device.key.public(),
            1,
        ),
    );
    let forged_key = DeviceKey::generate();
    let forged_public = forged_key.public();
    let forged = Device::unenrolled(
        device.device_id,
        forged_key,
        account.identity.certify_device(
            account.user_id.as_bytes(),
            device.device_id.as_bytes(),
            &forged_public,
            1_700_000_000_000,
        ),
    );

    let good = device.key_packages(2);
    let refused = (StatusCode::BAD_REQUEST, ErrorCode::InvalidKeyPackage);
    for bad in [
        B64(b"not a KeyPackage".to_vec()),
        sibling.key_package(false),
        stranger.key_package(false),
        recertified.key_package(false),
        forged.key_package(false),
        // A last-resort package in a one-time slot.
        device.key_package(true),
    ] {
        let mut batch = good.clone();
        batch.push(bad);
        assert_eq!(upload_err(&app, &device, batch, None).await, refused);
    }
    // A one-time package as the last resort, or another device's.
    for bad in [device.key_package(false), sibling.key_package(true)] {
        assert_eq!(
            upload_err(&app, &device, good.clone(), Some(bad)).await,
            refused
        );
    }
    assert_eq!(
        stored(&app, &device).await,
        (0, 0),
        "nothing of a refused upload is kept"
    );
    assert_eq!(upload(&app, &device, good, None).await, 2);
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn an_upload_holds_at_most_100_packages_and_a_device_keeps_at_most_200() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("kp", false).await;
    let too_large = (StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::PayloadTooLarge);

    assert_eq!(
        upload_err(&app, &device, device.key_packages(101), None).await,
        too_large
    );
    // A hundred packages need the upload's larger body limit.
    assert_eq!(
        upload(&app, &device, device.key_packages(100), None).await,
        100
    );
    assert_eq!(
        upload(&app, &device, device.key_packages(100), None).await,
        200
    );
    assert_eq!(
        upload_err(&app, &device, device.key_packages(1), None).await,
        too_large
    );
    assert_eq!(count(&app, &device).await, 200);
}

/// A one-time package is served once, oldest first; then the last-resort
/// one, which is kept. The requesting device is never served, and a device
/// with no package is absent.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_claim_serves_each_one_time_package_once_then_the_last_resort() {
    let app = TestApp::spawn().await;
    let (account, claimer) = app.account_with_device("kp", false).await;
    let laptop = app.enrol(&account).await;
    let _phone_without_packages = app.enrol(&account).await;
    let one_time = laptop.key_packages(2);
    let last_resort = laptop.key_package(true);
    upload(&app, &laptop, one_time.clone(), Some(last_resort.clone())).await;
    upload(&app, &claimer, claimer.key_packages(1), None).await;

    let keys = Keys(account.user_id, account.identity.public());
    let leaf = VerifiedLeaf {
        user_id: *account.user_id.as_bytes(),
        device_id: *laptop.device_id.as_bytes(),
    };
    let mut served = Vec::new();
    for _ in 0..4 {
        let claim = claim(&app, &claimer, account.user_id).await.unwrap();
        assert_eq!(claim.key_packages.len(), 1);
        let package = &claim.key_packages[0];
        assert_eq!(package.device_id, laptop.device_id);
        // What the claiming device checks before it adds anyone.
        let checked =
            key_package::validate_claimed(package.key_package.as_slice(), leaf, &keys).unwrap();
        assert_eq!(checked.device(), Some(leaf));
        served.push(package.key_package.clone());
    }
    assert_eq!(
        served,
        [
            one_time[0].clone(),
            one_time[1].clone(),
            last_resort.clone(),
            last_resort
        ]
    );
    assert_eq!(count(&app, &laptop).await, 0);
    assert_eq!(stored(&app, &laptop).await, (0, 1));
    assert_eq!(
        count(&app, &claimer).await,
        1,
        "the claimer's own packages are not touched"
    );
}

/// The scenario of the review of tasks 5 to 7: a device sends its packages,
/// a claim takes the first, and the same upload comes again (its answer was
/// lost). The package served stays served: it is not stored again, and no
/// claim gets it a second time. Its row keeps its reference only.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_package_sent_again_after_its_claim_is_never_served_again() {
    let app = TestApp::spawn().await;
    let (account, claimer) = app.account_with_device("kp", false).await;
    let laptop = app.enrol(&account).await;
    let batch = laptop.key_packages(3);
    assert_eq!(upload(&app, &laptop, batch.clone(), None).await, 3);
    let first = claim(&app, &claimer, account.user_id).await.unwrap();
    assert_eq!(first.key_packages[0].key_package, batch[0]);

    assert_eq!(
        upload(&app, &laptop, batch.clone(), None).await,
        2,
        "the served package is not stored again"
    );
    let mut served = Vec::new();
    for _ in 0..3 {
        let claim = claim(&app, &claimer, account.user_id).await.unwrap();
        served.extend(claim.key_packages.into_iter().map(|p| p.key_package));
    }
    assert_eq!(served, [batch[1].clone(), batch[2].clone()]);
    let kept: Vec<(i32, bool)> = sqlx::query_as(
        "SELECT octet_length(key_package), served_at IS NOT NULL FROM key_packages \
         WHERE device_id = $1 ORDER BY created_at, id",
    )
    .bind(laptop.device_id)
    .fetch_all(&app.state.db)
    .await
    .unwrap();
    assert_eq!(kept, [(0, true), (0, true), (0, true)], "references only");
}

/// Two claims at once never get the same one-time package: one that another
/// claim is taking is skipped.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn two_claims_never_get_the_same_one_time_package() {
    let app = TestApp::spawn().await;
    let (account, claimer) = app.account_with_device("kp", false).await;
    let laptop = app.enrol(&account).await;
    let one_time = laptop.key_packages(2);
    let last_resort = laptop.key_package(true);
    upload(&app, &laptop, one_time.clone(), Some(last_resort.clone())).await;
    let served = |claim: KeyPackageClaim| claim.key_packages[0].key_package.clone();

    // A claim in progress holds the oldest package: this one gets the next.
    let mut in_progress = app.state.db.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM key_packages WHERE device_id = $1 AND NOT last_resort \
         ORDER BY created_at, id LIMIT 1 FOR UPDATE",
    )
    .bind(laptop.device_id)
    .execute(&mut *in_progress)
    .await
    .unwrap();
    let next = claim(&app, &claimer, account.user_id).await.unwrap();
    assert_eq!(served(next), one_time[1]);
    // That one gave up: its package is served after all, then the last resort.
    in_progress.rollback().await.unwrap();
    let next = claim(&app, &claimer, account.user_id).await.unwrap();
    assert_eq!(served(next), one_time[0]);
    let next = claim(&app, &claimer, account.user_id).await.unwrap();
    assert_eq!(served(next), last_resort);

    // Five claims at once for five packages: each gets its own.
    let five = laptop.key_packages(5);
    upload(&app, &laptop, five.clone(), None).await;
    let claims =
        futures_util::future::join_all((0..5).map(|_| claim(&app, &claimer, account.user_id)))
            .await;
    let mut got: Vec<B64> = claims.into_iter().map(|c| served(c.unwrap())).collect();
    let mut expected = five;
    got.sort_by(|a, b| a.0.cmp(&b.0));
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(got, expected);
}

/// A claim serves active devices only: not revoked, and seen within the
/// window (`TAVERN_DEVICE_INACTIVE_DAYS`, whole days). A revoked device's
/// packages are deleted with it.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_claim_serves_active_devices_only() {
    // Five logins of one account: past the authentication limit per handle.
    let app = TestApp::spawn_unlimited().await;
    let (account, claimer) = app.account_with_device("kp", false).await;
    let active = app.enrol(&account).await;
    let recent = app.enrol(&account).await;
    let gone = app.enrol(&account).await;
    let revoked = app.enrol(&account).await;
    for device in [&active, &recent, &gone, &revoked] {
        upload(
            &app,
            device,
            device.key_packages(1),
            Some(device.key_package(true)),
        )
        .await;
    }
    away(&app, &recent, 30).await;
    away(&app, &gone, 31).await;
    let status = app
        .status::<()>(
            Method::DELETE,
            &format!("/v1/devices/{}", revoked.device_id),
            Some(&claimer.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(stored(&app, &revoked).await, (0, 0));

    let mut served = claimed_devices(&app, &claimer, account.user_id).await;
    served.sort();
    let mut expected = vec![active.device_id, recent.device_id];
    expected.sort();
    assert_eq!(served, expected);
    assert_eq!(stored(&app, &gone).await, (1, 1), "nothing taken from it");

    // The window is the instance's.
    let app = TestApp::spawn_configured(|settings| {
        settings.device_inactive_days = 7;
        settings.auth_per_handle_per_minute = 10_000;
    })
    .await;
    let (account, claimer) = app.account_with_device("kp", false).await;
    let week = app.enrol(&account).await;
    let longer = app.enrol(&account).await;
    for device in [&week, &longer] {
        upload(&app, device, device.key_packages(1), None).await;
    }
    away(&app, &week, 7).await;
    away(&app, &longer, 8).await;
    assert_eq!(
        claimed_devices(&app, &claimer, account.user_id).await,
        [week.device_id]
    );
}

/// A friend's packages are claimable, at most 3 times an hour per pair;
/// claims of one's own devices are not counted per pair. A request that is
/// not accepted yet, or an unfriending, makes them forbidden, with nothing
/// consumed.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_friend_s_key_packages_are_claimable_within_the_pair_limit() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("kp", false).await;
    let alice2 = app.enrol(&alice).await;
    let (bob, bob1) = app.account_with_device("kp", false).await;
    let (carol, carol1) = app.account_with_device("kp", false).await;
    upload(&app, &bob1, bob1.key_packages(10), None).await;
    upload(&app, &alice2, alice2.key_packages(10), None).await;

    let _: tavern_protocol::rest::FriendRequestAnswer = app
        .post(
            "/v1/friends/requests",
            Some(&alice1.session_token),
            &tavern_protocol::rest::FriendRequest {
                handle: bob.handle.as_str().to_owned(),
            },
        )
        .await;
    let (status, ..) = claim(&app, &alice1, bob.user_id).await.unwrap_err();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a request is not a friendship"
    );
    app.status::<()>(
        Method::POST,
        &format!("/v1/friends/requests/{}/accept", alice.user_id),
        Some(&bob1.session_token),
        None,
    )
    .await;

    for _ in 0..3 {
        assert_eq!(
            claimed_devices(&app, &alice1, bob.user_id).await,
            [bob1.device_id]
        );
    }
    let (status, code, _) = claim(&app, &alice1, bob.user_id).await.unwrap_err();
    assert_eq!(
        (status, code),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );
    for _ in 0..4 {
        assert_eq!(
            claimed_devices(&app, &alice1, alice.user_id).await,
            [alice2.device_id],
            "one's own devices are not counted per pair"
        );
    }
    // Per pair: another friend of Bob's is not affected.
    app.befriend((&carol, &carol1), (&bob, &bob1)).await;
    assert_eq!(
        claimed_devices(&app, &carol1, bob.user_id).await,
        [bob1.device_id]
    );
    assert_eq!(count(&app, &bob1).await, 6);

    let status = app
        .status::<()>(
            Method::DELETE,
            &format!("/v1/friends/{}", carol.user_id),
            Some(&bob1.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, ..) = claim(&app, &carol1, bob.user_id).await.unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(count(&app, &bob1).await, 6, "nothing consumed");
}

/// A claim after a block is refused, and takes nothing: the friendship is
/// read under the pair's turn, which the block takes too.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_claim_after_a_block_is_forbidden_and_takes_nothing() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("kp", false).await;
    let (bob, bob1) = app.account_with_device("kp", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;
    upload(
        &app,
        &bob1,
        bob1.key_packages(2),
        Some(bob1.key_package(true)),
    )
    .await;
    let status = app
        .status::<()>(
            Method::PUT,
            &format!("/v1/blocks/{}", alice.user_id),
            Some(&bob1.session_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, ..) = claim(&app, &alice1, bob.user_id).await.unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(stored(&app, &bob1).await, (2, 1), "nothing consumed");
}

/// A friend whose account is disabled has no active device: a claim serves
/// nothing, and takes nothing.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_friend_whose_account_is_disabled_has_nothing_to_serve() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("kp", false).await;
    let (bob, bob1) = app.account_with_device("kp", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;
    upload(
        &app,
        &bob1,
        bob1.key_packages(2),
        Some(bob1.key_package(true)),
    )
    .await;
    sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
        .bind(bob.user_id)
        .execute(&app.state.db)
        .await
        .unwrap();

    assert!(claimed_devices(&app, &alice1, bob.user_id).await.is_empty());
    assert_eq!(stored(&app, &bob1).await, (2, 1), "nothing consumed");
}

/// Anyone but oneself and one's friends is refused, an unknown user too,
/// and nothing is consumed.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn another_user_s_key_packages_are_forbidden_and_nothing_is_consumed() {
    let app = TestApp::spawn().await;
    let (_, alice1) = app.account_with_device("kp", false).await;
    let (bob, bob1) = app.account_with_device("kp", false).await;
    upload(
        &app,
        &bob1,
        bob1.key_packages(2),
        Some(bob1.key_package(true)),
    )
    .await;

    for target in [bob.user_id, Uuid::new_v4()] {
        let (status, code, _) = claim(&app, &alice1, target).await.unwrap_err();
        assert_eq!(
            (status, code),
            (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
        );
    }
    assert_eq!(stored(&app, &bob1).await, (2, 1));
}

/// Every claim counts against its requester, refused ones included.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn claims_are_limited_per_requesting_user() {
    let app = TestApp::spawn_configured(|settings| {
        settings.claim_limits.per_requester_per_hour = 3;
    })
    .await;
    let (alice, alice1) = app.account_with_device("kp", false).await;
    let alice2 = app.enrol(&alice).await;
    let (bob, bob1) = app.account_with_device("kp", false).await;

    assert!(claim(&app, &alice1, alice.user_id).await.is_ok());
    assert!(claim(&app, &alice1, bob.user_id).await.is_err());
    // Another device of the same user: the same requester.
    assert!(claim(&app, &alice2, alice.user_id).await.is_ok());
    let (status, code, retry_after) = claim(&app, &alice1, alice.user_id).await.unwrap_err();
    assert_eq!(
        (status, code),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );
    assert!(retry_after.is_some_and(|ms| ms > 0));
    assert!(
        claim(&app, &bob1, bob.user_id).await.is_ok(),
        "other users are not affected"
    );
}

/// A package expired, or expiring within the hour, is neither served nor
/// counted; the device's expired packages go at its next upload.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn packages_about_to_expire_are_not_served() {
    let app = TestApp::spawn().await;
    let (account, claimer) = app.account_with_device("kp", false).await;
    let laptop = app.enrol(&account).await;
    let last_resort = laptop.key_package(true);
    upload(
        &app,
        &laptop,
        laptop.key_packages(2),
        Some(last_resort.clone()),
    )
    .await;
    let expire_one_time = |minutes: i32| {
        sqlx::query(
            "UPDATE key_packages SET expires_at = now() + make_interval(mins => $2) \
             WHERE device_id = $1 AND NOT last_resort",
        )
        .bind(laptop.device_id)
        .bind(minutes)
        .execute(&app.state.db)
    };

    expire_one_time(30).await.unwrap();
    assert_eq!(count(&app, &laptop).await, 0);
    let served = claim(&app, &claimer, account.user_id).await.unwrap();
    assert_eq!(served.key_packages[0].key_package, last_resort);

    expire_one_time(-24 * 60).await.unwrap();
    let fresh = laptop.key_packages(1);
    assert_eq!(upload(&app, &laptop, fresh.clone(), None).await, 1);
    assert_eq!(
        stored(&app, &laptop).await,
        (1, 1),
        "the expired ones are gone"
    );
    let served = claim(&app, &claimer, account.user_id).await.unwrap();
    assert_eq!(served.key_packages[0].key_package, fresh[0]);

    sqlx::query(
        "UPDATE key_packages SET expires_at = now() + interval '30 minutes' \
         WHERE device_id = $1 AND last_resort",
    )
    .bind(laptop.device_id)
    .execute(&app.state.db)
    .await
    .unwrap();
    assert!(
        claimed_devices(&app, &claimer, account.user_id)
            .await
            .is_empty()
    );
}
