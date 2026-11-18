// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conversations through the client core (ADR 0019, section 4): two friends
//! create their DM, both told by the gateway, and get the same one whoever
//! asks; an unfriending leaves it read-only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]

use tavern_client_core::{Client, GatewayEvent, InstanceClient, LoginStep, NewAccount};
use tavern_e2e_tests::{PASSWORD, Server, next_event, random_handle};
use tavern_protocol::rest::ErrorCode;

async fn signed_in(server: &Server, computer: &InstanceClient) -> (Client, String) {
    let invite = server.host_invite(false).await;
    let handle = computer
        .register(NewAccount {
            invite_code: &invite,
            handle: &random_handle("cv"),
            display_name: "Conversation Test",
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

/// The next event that is not about the connection or the friendship.
async fn conversation_event(
    events: &mut tokio::sync::mpsc::Receiver<GatewayEvent>,
) -> GatewayEvent {
    loop {
        match next_event(events).await {
            GatewayEvent::Connected { .. } | GatewayEvent::FriendshipChanged { .. } => {}
            event => return event,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PostgreSQL"]
async fn two_friends_get_one_dm() {
    let server = Server::spawn().await;
    let (alice, _) = signed_in(&server, &server.new_computer()).await;
    let (bob, bob_handle) = signed_in(&server, &server.new_computer()).await;
    let (_alice_gateway, mut alice_events) = alice.connect_gateway().unwrap();
    let (_bob_gateway, mut bob_events) = bob.connect_gateway().unwrap();

    let refused = alice.create_dm(bob.user_id()).await.unwrap_err();
    assert_eq!(refused.api_code(), Some(ErrorCode::NotFriends));
    alice.send_friend_request(&bob_handle).await.unwrap();
    bob.accept_friend_request(alice.user_id()).await.unwrap();

    let dm = alice.create_dm(bob.user_id()).await.unwrap();
    assert_eq!(dm.epoch, None, "the creating device builds the group next");
    let mut members = vec![alice.user_id(), bob.user_id()];
    members.sort();
    let announced = GatewayEvent::ConversationCreated {
        conversation_id: dm.conversation_id,
        members: members.clone(),
    };
    assert_eq!(conversation_event(&mut alice_events).await, announced);
    assert_eq!(conversation_event(&mut bob_events).await, announced);
    assert_eq!(bob.create_dm(alice.user_id()).await.unwrap(), dm);

    bob.remove_friend(alice.user_id()).await.unwrap();
    let listed = alice.conversations().await.unwrap().conversations;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].conversation_id, dm.conversation_id);
    assert!(listed[0].read_only);
}
