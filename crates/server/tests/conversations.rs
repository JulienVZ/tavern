// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conversations (ADR 0019, section 4): one DM per pair of friends, against
//! a real server and database.
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

use std::time::Duration;

use common::{Device, TestApp};
use reqwest::{Method, StatusCode};
use tavern_protocol::rest::{
    Conversation, ConversationKind, ConversationList, CreateDmRequest, ErrorBody, ErrorCode,
    FriendRequest, FriendRequestAnswer,
};
use uuid::Uuid;

async fn create(
    app: &TestApp,
    device: &Device,
    peer: Uuid,
) -> (StatusCode, Result<Conversation, ErrorCode>) {
    let (status, bytes) = app
        .send(
            Method::POST,
            "/v1/conversations",
            Some(&device.session_token),
            Some(&CreateDmRequest { user_id: peer }),
        )
        .await;
    if status.is_success() {
        (status, Ok(serde_json::from_slice(&bytes).unwrap()))
    } else {
        let error: ErrorBody = serde_json::from_slice(&bytes).unwrap();
        (status, Err(error.code))
    }
}

async fn list(app: &TestApp, device: &Device) -> Vec<Conversation> {
    let list: ConversationList = app.get("/v1/conversations", &device.session_token).await;
    list.conversations
}

fn pair(a: Uuid, b: Uuid) -> Vec<Uuid> {
    if a < b { vec![a, b] } else { vec![b, a] }
}

async fn status(app: &TestApp, device: &Device, method: Method, path: String) -> StatusCode {
    app.status::<()>(method, &path, Some(&device.session_token), None)
        .await
}

#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_dm_is_created_once_per_pair_of_friends() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("cv", false).await;
    let (bob, bob1) = app.account_with_device("cv", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;

    let (status, created) = create(&app, &alice1, bob.user_id).await;
    assert_eq!(status, StatusCode::CREATED);
    let created = created.unwrap();
    assert_eq!(created.kind, ConversationKind::Dm);
    assert_eq!(created.members, pair(alice.user_id, bob.user_id));
    assert_eq!(
        (created.generation, created.epoch),
        (None, None),
        "no group yet"
    );
    assert_eq!((created.last_seq, created.read_only), (0, false));

    // Asked again, from either side: the same DM.
    for (device, peer) in [(&alice1, bob.user_id), (&bob1, alice.user_id)] {
        let (status, again) = create(&app, device, peer).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again.unwrap(), created);
    }
    assert_eq!(list(&app, &alice1).await, std::slice::from_ref(&created));
    assert_eq!(list(&app, &bob1).await, [created]);
}

/// Anyone who is not a friend gets the same refusal: a stranger, someone
/// with a request pending, an unknown user, a blocked or a blocking user.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn only_friends_get_a_dm_and_nothing_tells_why_not() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("cv", false).await;
    let (bob, _) = app.account_with_device("cv", false).await;
    let (carol, carol1) = app.account_with_device("cv", false).await;
    let refused = (StatusCode::FORBIDDEN, Err(ErrorCode::NotFriends));

    assert_eq!(create(&app, &alice1, bob.user_id).await, refused);
    assert_eq!(create(&app, &alice1, Uuid::new_v4()).await, refused);
    let _: FriendRequestAnswer = app
        .post(
            "/v1/friends/requests",
            Some(&alice1.session_token),
            &FriendRequest {
                handle: bob.handle.as_str().to_owned(),
            },
        )
        .await;
    assert_eq!(
        create(&app, &alice1, bob.user_id).await,
        refused,
        "a request is not a friendship"
    );

    app.befriend((&carol, &carol1), (&alice, &alice1)).await;
    assert_eq!(
        status(
            &app,
            &carol1,
            Method::PUT,
            format!("/v1/blocks/{}", alice.user_id)
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(create(&app, &alice1, carol.user_id).await, refused);
    assert_eq!(create(&app, &carol1, alice.user_id).await, refused);

    assert_eq!(
        create(&app, &alice1, alice.user_id).await,
        (StatusCode::BAD_REQUEST, Err(ErrorCode::InvalidArgument))
    );
    assert!(list(&app, &alice1).await.is_empty());
}

/// ADR 0019, section 16: unfriending keeps the DM, read-only, and it cannot
/// be created again; friends again, the same DM is usable again, never a
/// new one.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn an_ex_friend_s_dm_stays_read_only_and_comes_back_the_same() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("cv", false).await;
    let (bob, bob1) = app.account_with_device("cv", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;
    let dm = create(&app, &alice1, bob.user_id).await.1.unwrap();

    assert_eq!(
        status(
            &app,
            &bob1,
            Method::DELETE,
            format!("/v1/friends/{}", alice.user_id)
        )
        .await,
        StatusCode::NO_CONTENT
    );
    for device in [&alice1, &bob1] {
        let listed = list(&app, device).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].conversation_id, dm.conversation_id);
        assert!(listed[0].read_only);
    }
    assert_eq!(
        create(&app, &alice1, bob.user_id).await,
        (StatusCode::FORBIDDEN, Err(ErrorCode::NotFriends))
    );

    app.befriend((&bob, &bob1), (&alice, &alice1)).await;
    let (status, again) = create(&app, &alice1, bob.user_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again.unwrap(), dm);
    assert_eq!(list(&app, &bob1).await, [dm]);
}

/// ADR 0019, section 18: two creations at once get the same DM. Both wait
/// for the pair's turn, held here until PostgreSQL shows them waiting; then
/// one creates the DM and the other finds it.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn two_creations_at_once_get_the_same_dm() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("cv", false).await;
    let (bob, bob1) = app.account_with_device("cv", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;
    let ids = pair(alice.user_id, bob.user_id);

    let mut turn = app.state.db.begin().await.unwrap();
    let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *turn)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("tavern.friendships:{}:{}", ids[0], ids[1]))
        .execute(&mut *turn)
        .await
        .unwrap();
    let release = async {
        // PostgreSQL announces no such event, so it is polled; the timeout
        // only keeps a broken test from hanging.
        let both_wait = async {
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
                )
                .bind(holder)
                .fetch_one(&app.state.db)
                .await
                .unwrap();
                if waiting == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(Duration::from_secs(60), both_wait)
            .await
            .expect("the two creations never waited for the pair's turn");
        turn.commit().await.unwrap();
    };
    let (first, second, ()) = tokio::join!(
        create(&app, &alice1, bob.user_id),
        create(&app, &bob1, alice.user_id),
        release
    );

    let mut statuses = [first.0, second.0];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CREATED]);
    assert_eq!(first.1.unwrap(), second.1.unwrap());
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dm_conversations WHERE user_low = $1 AND user_high = $2",
    )
    .bind(ids[0])
    .bind(ids[1])
    .fetch_one(&app.state.db)
    .await
    .unwrap();
    assert_eq!(rows, 1);
}

/// A conversation shows its group once there is one; until then any device
/// of a member may create it.
#[tokio::test]
#[ignore = "needs PostgreSQL, see the module documentation"]
async fn a_dm_shows_its_group_once_there_is_one() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("cv", false).await;
    let (bob, bob1) = app.account_with_device("cv", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;
    let dm = create(&app, &alice1, bob.user_id).await.1.unwrap();

    // As the server stores a group's first commit (tasks 8 and 9).
    sqlx::query(
        "INSERT INTO mls_groups (group_id, conversation_id, generation, epoch, group_info) \
         VALUES (uuid_send($1) || substring(int8send(0) FROM 5 FOR 4), $1, 0, 1, '\\x00')",
    )
    .bind(dm.conversation_id)
    .execute(&app.state.db)
    .await
    .unwrap();
    let listed = list(&app, &bob1).await;
    assert_eq!((listed[0].generation, listed[0].epoch), (Some(0), Some(1)));
}
