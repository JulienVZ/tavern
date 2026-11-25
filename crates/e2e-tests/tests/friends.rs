// SPDX-License-Identifier: AGPL-3.0-or-later

//! Friends and blocks through the client core (ADR 0020): two users become
//! friends, each told by the gateway, and may then claim each other's
//! KeyPackages; a block ends it, without telling the blocked user.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use tavern_client_core::{Client, GatewayEvent, InstanceClient, LoginStep, NewAccount, Relation};
use tavern_crypto::identity::{ID_LEN, IdentityPublicKey};
use tavern_crypto::mls::Roster;
use tavern_e2e_tests::{PASSWORD, Server, next_event, random_handle};
use tavern_protocol::rest::{ErrorCode, RequestOutcome};
use uuid::Uuid;

/// Trusts no identity key: these claims serve no package to check.
struct Nobody;

/// Trusts one user's identity key.
struct Only(Uuid, IdentityPublicKey);

impl Roster for Only {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        (user_id == self.0.as_bytes()).then_some(self.1)
    }
}

impl Roster for Nobody {
    fn identity_key(&self, _: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        None
    }
}

async fn signed_in(server: &Server, computer: &InstanceClient) -> (Client, String) {
    let invite = server.host_invite(false).await;
    let handle = computer
        .register(NewAccount {
            invite_code: &invite,
            handle: &random_handle("fr"),
            display_name: "Friend Test",
            password: PASSWORD,
        })
        .await
        .unwrap()
        .handle
        .as_str()
        .to_owned();
    match computer.login(&handle, PASSWORD).await.unwrap() {
        LoginStep::Done(signed_in) => (signed_in.client, handle),
        LoginStep::TotpRequired(_) => panic!("unexpected TOTP step"),
    }
}

async fn expect_relation(
    events: &mut tokio::sync::mpsc::Receiver<GatewayEvent>,
    user_id: Uuid,
    relation: Relation,
) {
    loop {
        match next_event(events).await {
            GatewayEvent::Connected { .. } => {}
            event => {
                assert_eq!(event, GatewayEvent::FriendshipChanged { user_id, relation });
                return;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn two_users_become_friends_and_a_block_ends_it() {
    let server = Server::spawn().await;
    let (alice, alice_handle) = signed_in(&server, &server.new_computer()).await;
    let (bob, bob_handle) = signed_in(&server, &server.new_computer()).await;
    let (_alice_gateway, mut alice_events) = alice.connect_gateway().unwrap();
    let (_bob_gateway, mut bob_events) = bob.connect_gateway().unwrap();
    // Connected before anything happens.
    assert!(matches!(
        next_event(&mut alice_events).await,
        GatewayEvent::Connected { .. }
    ));
    assert!(matches!(
        next_event(&mut bob_events).await,
        GatewayEvent::Connected { .. }
    ));

    let refused = alice
        .claim_key_packages(bob.user_id(), &Nobody)
        .await
        .unwrap_err();
    assert_eq!(refused.api_code(), Some(ErrorCode::Forbidden));
    let unknown = alice
        .send_friend_request(&random_handle("nobody"))
        .await
        .unwrap_err();
    assert_eq!(unknown.api_code(), Some(ErrorCode::NotFound));

    // Typed with capitals: the client canonicalises it.
    let answer = alice
        .send_friend_request(&bob_handle.to_uppercase())
        .await
        .unwrap();
    assert_eq!(
        (answer.user_id, answer.outcome),
        (bob.user_id(), RequestOutcome::RequestSent)
    );
    expect_relation(&mut alice_events, bob.user_id(), Relation::RequestSent).await;
    expect_relation(&mut bob_events, alice.user_id(), Relation::RequestReceived).await;
    let received = bob.friends().await.unwrap().received;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].user_id, alice.user_id());

    bob.accept_friend_request(alice.user_id()).await.unwrap();
    expect_relation(&mut alice_events, bob.user_id(), Relation::Friends).await;
    expect_relation(&mut bob_events, alice.user_id(), Relation::Friends).await;
    assert_eq!(
        alice.friends().await.unwrap().friends[0].user_id,
        bob.user_id()
    );
    // Friends: allowed. Bob's connected device uploaded its packages by
    // itself; Alice is served one, which checks out under Bob's key.
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while bob.key_package_count().await.unwrap() < 20 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Bob's device never uploaded its KeyPackages");
    let bob_key =
        IdentityPublicKey::from_bytes(bob.me().await.unwrap().identity_key.as_slice()).unwrap();
    let served = alice
        .claim_key_packages(bob.user_id(), &Only(bob.user_id(), bob_key))
        .await
        .unwrap();
    assert_eq!(served.len(), 1);

    bob.block(alice.user_id()).await.unwrap();
    expect_relation(&mut bob_events, alice.user_id(), Relation::Blocked).await;
    expect_relation(&mut alice_events, bob.user_id(), Relation::None).await;
    assert!(alice.friends().await.unwrap().friends.is_empty());
    assert_eq!(
        bob.friends().await.unwrap().blocked[0].user_id,
        alice.user_id()
    );
    let blocked = bob.send_friend_request(&alice_handle).await.unwrap_err();
    assert_eq!(blocked.api_code(), Some(ErrorCode::Blocked));
    bob.unblock(alice.user_id()).await.unwrap();
    expect_relation(&mut bob_events, alice.user_id(), Relation::None).await;
    bob.remove_friend_request(alice.user_id())
        .await
        .expect_err("nothing pending");
}
