// SPDX-License-Identifier: AGPL-3.0-or-later

//! Friends and blocks (ADR 0020), against a real server and database. The
//! events the gateway sends for them are tested in `tests/gateway.rs`.
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

use common::{Account, Device, TestApp};
use reqwest::{Method, StatusCode};
use tavern_protocol::rest::{
    ErrorCode, FriendList, FriendRequest, FriendRequestAnswer, RequestOutcome,
};
use uuid::Uuid;

const NO_BODY: Option<&()> = None;

async fn request(app: &TestApp, from: &Device, to: &Account) -> FriendRequestAnswer {
    app.post(
        "/v1/friends/requests",
        Some(&from.session_token),
        &FriendRequest {
            handle: to.handle.as_str().to_owned(),
        },
    )
    .await
}

async fn request_err(app: &TestApp, from: &Device, handle: &str) -> (StatusCode, ErrorCode) {
    app.post_err(
        "/v1/friends/requests",
        Some(&from.session_token),
        &FriendRequest {
            handle: handle.to_owned(),
        },
    )
    .await
}

async fn act(app: &TestApp, device: &Device, method: Method, path: String) -> StatusCode {
    app.status(method, &path, Some(&device.session_token), NO_BODY)
        .await
}

async fn accept(app: &TestApp, device: &Device, user: Uuid) -> StatusCode {
    act(
        app,
        device,
        Method::POST,
        format!("/v1/friends/requests/{user}/accept"),
    )
    .await
}

async fn remove_request(app: &TestApp, device: &Device, user: Uuid) -> StatusCode {
    act(
        app,
        device,
        Method::DELETE,
        format!("/v1/friends/requests/{user}"),
    )
    .await
}

async fn unfriend(app: &TestApp, device: &Device, user: Uuid) -> StatusCode {
    act(app, device, Method::DELETE, format!("/v1/friends/{user}")).await
}

async fn block(app: &TestApp, device: &Device, user: Uuid) -> StatusCode {
    act(app, device, Method::PUT, format!("/v1/blocks/{user}")).await
}

async fn unblock(app: &TestApp, device: &Device, user: Uuid) -> StatusCode {
    act(app, device, Method::DELETE, format!("/v1/blocks/{user}")).await
}

async fn list(app: &TestApp, device: &Device) -> FriendList {
    app.get("/v1/friends", &device.session_token).await
}

/// The users of each part of a list: friends, received, sent, blocked.
async fn parts(app: &TestApp, device: &Device) -> [Vec<Uuid>; 4] {
    let list = list(app, device).await;
    let ids = |part: &[tavern_protocol::rest::UserSummary]| {
        part.iter().map(|user| user.user_id).collect::<Vec<_>>()
    };
    [
        ids(&list.friends),
        ids(&list.received),
        ids(&list.sent),
        ids(&list.blocked),
    ]
}

fn none() -> [Vec<Uuid>; 4] {
    [vec![], vec![], vec![], vec![]]
}

async fn rows_of_pair(app: &TestApp, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM friendships WHERE user_low = LEAST($1, $2) AND user_high = GREATEST($1, $2)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&app.state.db)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_request_accepted_makes_friends_until_one_of_them_unfriends() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("fr", false).await;
    let (bob, bob1) = app.account_with_device("fr", false).await;

    let answer = request(&app, &alice1, &bob).await;
    assert_eq!(answer.user_id, bob.user_id);
    assert_eq!(answer.outcome, RequestOutcome::RequestSent);
    let sent = list(&app, &alice1).await.sent;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].handle, bob.handle.as_str());
    assert_eq!(sent[0].identity_key.0, bob.identity.public().to_bytes());
    assert_eq!(
        parts(&app, &bob1).await,
        [vec![], vec![alice.user_id], vec![], vec![]]
    );
    // Sent again: still one request.
    assert_eq!(
        request(&app, &alice1, &bob).await.outcome,
        RequestOutcome::RequestSent
    );
    assert_eq!(rows_of_pair(&app, alice.user_id, bob.user_id).await, 1);

    assert_eq!(
        accept(&app, &alice1, bob.user_id).await,
        StatusCode::NOT_FOUND,
        "only the recipient accepts"
    );
    assert_eq!(
        accept(&app, &bob1, alice.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        parts(&app, &alice1).await,
        [vec![bob.user_id], vec![], vec![], vec![]]
    );
    assert_eq!(
        parts(&app, &bob1).await,
        [vec![alice.user_id], vec![], vec![], vec![]]
    );
    assert_eq!(
        request_err(&app, &alice1, bob.handle.as_str()).await,
        (StatusCode::CONFLICT, ErrorCode::AlreadyExists)
    );

    assert_eq!(
        unfriend(&app, &bob1, alice.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(parts(&app, &alice1).await, none());
    assert_eq!(parts(&app, &bob1).await, none());
    assert_eq!(
        unfriend(&app, &bob1, alice.user_id).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_request_is_declined_by_its_recipient_or_cancelled_by_its_sender() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("fr", false).await;
    let (bob, bob1) = app.account_with_device("fr", false).await;

    request(&app, &alice1, &bob).await;
    assert_eq!(
        remove_request(&app, &bob1, alice.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(parts(&app, &alice1).await, none());
    assert_eq!(parts(&app, &bob1).await, none());

    request(&app, &alice1, &bob).await;
    assert_eq!(
        remove_request(&app, &alice1, bob.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(parts(&app, &bob1).await, none());
    assert_eq!(
        remove_request(&app, &alice1, bob.user_id).await,
        StatusCode::NOT_FOUND
    );

    // A friendship is not a request.
    request(&app, &alice1, &bob).await;
    accept(&app, &bob1, alice.user_id).await;
    assert_eq!(
        remove_request(&app, &alice1, bob.user_id).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn crossed_requests_make_friends() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("fr", false).await;
    let (bob, bob1) = app.account_with_device("fr", false).await;

    request(&app, &alice1, &bob).await;
    let answer = request(&app, &bob1, &alice).await;
    assert_eq!(answer.outcome, RequestOutcome::Friends);
    assert_eq!(
        parts(&app, &alice1).await,
        [vec![bob.user_id], vec![], vec![], vec![]]
    );
    assert_eq!(
        parts(&app, &bob1).await,
        [vec![alice.user_id], vec![], vec![], vec![]]
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn an_unknown_handle_is_not_found() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("fr", false).await;

    assert_eq!(
        request_err(&app, &alice1, &common::random_handle("nobody")).await,
        (StatusCode::NOT_FOUND, ErrorCode::NotFound)
    );
    assert_eq!(
        request_err(&app, &alice1, alice.handle.as_str()).await,
        (StatusCode::BAD_REQUEST, ErrorCode::InvalidArgument)
    );
    assert_eq!(
        request_err(&app, &alice1, "Not Canonical").await,
        (StatusCode::BAD_REQUEST, ErrorCode::InvalidHandle)
    );
}

/// A block ends a friendship and is never disclosed: the blocked user sees
/// what an unfriending shows, and a request they send looks sent, stays
/// theirs alone, and is deleted when the block is lifted.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_block_ends_the_friendship_and_is_not_disclosed() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("fr", false).await;
    let (bob, bob1) = app.account_with_device("fr", false).await;
    let (carol, _) = app.account_with_device("fr", false).await;
    request(&app, &alice1, &bob).await;
    accept(&app, &bob1, alice.user_id).await;

    assert_eq!(
        block(&app, &bob1, alice.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        block(&app, &bob1, alice.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        parts(&app, &bob1).await,
        [vec![], vec![], vec![], vec![alice.user_id]]
    );
    assert_eq!(parts(&app, &alice1).await, none());
    assert_eq!(
        request_err(&app, &bob1, alice.handle.as_str()).await,
        (StatusCode::FORBIDDEN, ErrorCode::Blocked)
    );

    // Alice's request to Bob gets the answer any request gets.
    let to_blocker = request(&app, &alice1, &bob).await;
    let to_carol = request(&app, &alice1, &carol).await;
    assert_eq!(
        (to_blocker.outcome, to_carol.outcome),
        (RequestOutcome::RequestSent, RequestOutcome::RequestSent)
    );
    assert_eq!(
        parts(&app, &alice1).await[2].len(),
        2,
        "both requests show as sent"
    );
    assert_eq!(
        parts(&app, &bob1).await,
        [vec![], vec![], vec![], vec![alice.user_id]],
        "Bob never sees it"
    );
    assert_eq!(
        accept(&app, &bob1, alice.user_id).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        remove_request(&app, &bob1, alice.user_id).await,
        StatusCode::NOT_FOUND
    );

    // Lifting the block deletes it: reachable again, nothing accepted.
    assert_eq!(
        unblock(&app, &bob1, alice.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        unblock(&app, &bob1, alice.user_id).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(parts(&app, &bob1).await, none());
    assert_eq!(parts(&app, &alice1).await[2], [carol.user_id]);
    assert_eq!(rows_of_pair(&app, alice.user_id, bob.user_id).await, 0);
    request(&app, &bob1, &alice).await;
    assert_eq!(parts(&app, &alice1).await[1], [bob.user_id]);

    // Its sender may cancel such a request too; and blocking ends a
    // pending request as it ends a friendship.
    assert_eq!(
        block(&app, &alice1, bob.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(parts(&app, &bob1).await, none());
    request(&app, &bob1, &alice).await;
    assert_eq!(
        remove_request(&app, &bob1, alice.user_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(rows_of_pair(&app, alice.user_id, bob.user_id).await, 0);
    assert_eq!(
        block(&app, &alice1, Uuid::new_v4()).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn friend_requests_are_limited_per_user() {
    let app = TestApp::spawn_configured(|settings| settings.friend_requests_per_hour = 2).await;
    let (_, alice1) = app.account_with_device("fr", false).await;
    let (bob, bob1) = app.account_with_device("fr", false).await;
    let (carol, _) = app.account_with_device("fr", false).await;

    // An unknown handle counts too.
    assert_eq!(
        request_err(&app, &alice1, &common::random_handle("nobody"))
            .await
            .1,
        ErrorCode::NotFound
    );
    request(&app, &alice1, &bob).await;
    assert_eq!(
        request_err(&app, &alice1, carol.handle.as_str()).await,
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );
    // Per user: Bob is not affected.
    request(&app, &bob1, &carol).await;
}

/// The schema refuses what the server never writes.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn the_schema_keeps_requests_and_blocks_consistent() {
    let app = TestApp::spawn().await;
    let (alice, _) = app.account_with_device("fr", false).await;
    let (bob, _) = app.account_with_device("fr", false).await;
    let (low, high) = if alice.user_id < bob.user_id {
        (alice.user_id, bob.user_id)
    } else {
        (bob.user_id, alice.user_id)
    };
    let refused = |result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>| match result {
        Err(sqlx::Error::Database(error)) => assert_eq!(error.code().as_deref(), Some("23514")),
        other => panic!("{other:?}"),
    };
    // Asked by someone outside the pair; hidden once accepted; accepted
    // without a date; pending with one.
    for (requested_by, hidden, status, dated) in [
        (Uuid::new_v4(), false, "pending", false),
        (low, true, "accepted", true),
        (low, false, "accepted", false),
        (low, false, "pending", true),
    ] {
        refused(
            sqlx::query(
                "INSERT INTO friendships \
                 (user_low, user_high, status, requested_by, hidden, accepted_at) \
                 VALUES ($1, $2, $3::friendship_status, $4, $5, CASE WHEN $6 THEN now() END)",
            )
            .bind(low)
            .bind(high)
            .bind(status)
            .bind(requested_by)
            .bind(hidden)
            .bind(dated)
            .execute(&app.state.db)
            .await,
        );
    }
    refused(
        sqlx::query("INSERT INTO friendships (user_low, user_high, status, requested_by) VALUES ($2, $1, 'pending', $1)")
            .bind(low)
            .bind(high)
            .execute(&app.state.db)
            .await,
    );
    refused(
        sqlx::query("INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $1)")
            .bind(low)
            .execute(&app.state.db)
            .await,
    );
}
