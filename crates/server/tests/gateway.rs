// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests of the WebSocket gateway.
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

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::extract::{State, WebSocketUpgrade};
use axum::routing::get;

use common::{Device, TestApp};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use reqwest::{Method, StatusCode};
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::client_frame::Payload as ClientPayload;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_protocol::rest::B64;
use tavern_protocol::{GATEWAY_PATH, GATEWAY_SUBPROTOCOL, close_code};
use tavern_server::gateway::Event;
use tavern_server::{AppState, routes, with_layers};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

const NO_BODY: Option<&()> = None;

async fn open(app: &TestApp, subprotocol: Option<&str>) -> Result<Socket, StatusCode> {
    open_at(app.addr, subprotocol).await
}

async fn open_at(addr: SocketAddr, subprotocol: Option<&str>) -> Result<Socket, StatusCode> {
    let mut request = format!("ws://{addr}{GATEWAY_PATH}")
        .into_client_request()
        .unwrap();
    if let Some(subprotocol) = subprotocol {
        request
            .headers_mut()
            .insert("sec-websocket-protocol", subprotocol.parse().unwrap());
    }
    match tokio_tungstenite::connect_async(request).await {
        Ok((socket, _)) => Ok(socket),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            Err(StatusCode::from_u16(response.status().as_u16()).unwrap())
        }
        Err(error) => panic!("unexpected connection error: {error}"),
    }
}

async fn send(socket: &mut Socket, request_id: u64, payload: ClientPayload) {
    let frame = proto::ClientFrame {
        request_id,
        payload: Some(payload),
    };
    socket
        .send(Message::Binary(frame.encode_to_vec().into()))
        .await
        .unwrap();
}

/// What the server sent next: a frame, or the code it closed with.
#[derive(Debug)]
enum Received {
    Frame(proto::ServerFrame),
    Closed(Option<u16>),
}

async fn receive(socket: &mut Socket) -> Received {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("the server did not answer in time");
        match message {
            Some(Ok(Message::Binary(bytes))) => {
                return Received::Frame(proto::ServerFrame::decode(bytes.as_ref()).unwrap());
            }
            Some(Ok(Message::Close(frame))) => {
                return Received::Closed(frame.map(|frame| u16::from(frame.code)));
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(other)) => panic!("unexpected message: {other:?}"),
            Some(Err(_)) | None => return Received::Closed(None),
        }
    }
}

async fn expect_frame(socket: &mut Socket) -> proto::ServerFrame {
    match receive(socket).await {
        Received::Frame(frame) => frame,
        Received::Closed(code) => panic!("the server closed the connection ({code:?})"),
    }
}

async fn expect_close(socket: &mut Socket) -> Option<u16> {
    match receive(socket).await {
        Received::Closed(code) => code,
        Received::Frame(frame) => panic!("expected a close, got {frame:?}"),
    }
}

fn hello(token: &B64) -> ClientPayload {
    ClientPayload::Hello(proto::Hello {
        session_token: token.0.clone(),
        protocol_minor: 0,
        client_version: "test".to_owned(),
        client_platform: "linux".to_owned(),
    })
}

/// Opens an authenticated connection and returns it with its `Ready`.
async fn connect(app: &TestApp, device: &Device) -> (Socket, proto::Ready) {
    connect_at(app.addr, device).await
}

async fn connect_at(addr: SocketAddr, device: &Device) -> (Socket, proto::Ready) {
    let mut socket = open_at(addr, Some(GATEWAY_SUBPROTOCOL)).await.unwrap();
    send(&mut socket, 1, hello(&device.session_token)).await;
    let frame = expect_frame(&mut socket).await;
    assert_eq!(frame.request_id, 1);
    let Some(ServerPayload::Ready(ready)) = frame.payload else {
        panic!("expected Ready, got {frame:?}");
    };
    (socket, ready)
}

/// The event the test gateway below panics on.
const PANICS: Event = Event::KeyPackagesLow { remaining: 4242 };

fn panicking_translate(event: Event) -> (ServerPayload, Option<u16>) {
    assert_ne!(event, PANICS, "translating the test's event");
    routes::gateway::event_payload(event)
}

/// ADR 0019, section 18: a panic while the gateway handles a connection's
/// event closes that connection with 1011 and takes it out of the registry;
/// the other connections go on.
#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_panic_closes_its_connection_and_the_others_go_on() {
    let app = TestApp::spawn().await;
    let (_, alice1) = app.account_with_device("gw", false).await;
    let (_, bob1) = app.account_with_device("gw", false).await;
    // The server's state (database, registry), under its layers, with a
    // gateway whose translation of events panics on one of them.
    let routes = Router::new().route(
        GATEWAY_PATH,
        get(
            |State(state): State<AppState>, upgrade: WebSocketUpgrade| async move {
                routes::gateway::upgrade_with(state, upgrade, panicking_translate)
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = with_layers(routes, app.state.clone());
    tokio::spawn(async move {
        axum::serve(
            listener,
            server.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let (mut alice_socket, _) = connect_at(addr, &alice1).await;
    let (mut bob_socket, _) = connect_at(addr, &bob1).await;
    assert_eq!(app.state.gateway.connected(), 2);

    app.state.gateway.notify_device(bob1.device_id, PANICS);
    assert_eq!(
        expect_close(&mut bob_socket).await,
        Some(close_code::INTERNAL_ERROR)
    );
    assert_eq!(app.state.gateway.connected(), 1, "out of the registry");

    // Alice's connection goes on: an event, then a heartbeat.
    app.state
        .gateway
        .notify_device(alice1.device_id, Event::KeyPackagesLow { remaining: 3 });
    assert_eq!(
        expect_frame(&mut alice_socket).await.payload,
        Some(ServerPayload::KeyPackagesLow(proto::KeyPackagesLow {
            remaining: 3
        }))
    );
    send(
        &mut alice_socket,
        2,
        ClientPayload::Heartbeat(proto::Heartbeat {}),
    )
    .await;
    assert!(matches!(
        expect_frame(&mut alice_socket).await.payload,
        Some(ServerPayload::HeartbeatAck(_))
    ));
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_device_connects_and_exchanges_heartbeats() {
    let app = TestApp::spawn().await;
    let (account, device) = app.account_with_device("gw", false).await;

    let (mut socket, ready) = connect(&app, &device).await;

    assert_eq!(ready.user_id, account.user_id.as_bytes());
    assert_eq!(ready.device_id, device.device_id.as_bytes());
    assert_eq!(ready.mls_external_sender_key.len(), 32);
    assert!(ready.new_devices.is_empty());
    let limits = ready.limits.unwrap();
    assert_eq!(limits.heartbeat_interval_ms, 30_000);
    assert_eq!(limits.max_frame_bytes, 1024 * 1024);

    send(
        &mut socket,
        2,
        ClientPayload::Heartbeat(proto::Heartbeat {}),
    )
    .await;
    let frame = expect_frame(&mut socket).await;
    assert_eq!(frame.request_id, 2);
    assert!(matches!(
        frame.payload,
        Some(ServerPayload::HeartbeatAck(_))
    ));
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn the_subprotocol_is_required() {
    let app = TestApp::spawn().await;

    assert_eq!(open(&app, None).await.err(), Some(StatusCode::BAD_REQUEST));
    assert_eq!(
        open(&app, Some("tavern.v9")).await.err(),
        Some(StatusCode::BAD_REQUEST)
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn an_invalid_session_is_refused() {
    let app = TestApp::spawn().await;

    let mut socket = open(&app, Some(GATEWAY_SUBPROTOCOL)).await.unwrap();
    send(&mut socket, 1, hello(&B64(vec![9; 32]))).await;
    let frame = expect_frame(&mut socket).await;
    let Some(ServerPayload::Error(error)) = frame.payload else {
        panic!("expected an error")
    };
    assert_eq!(error.code, i32::from(proto::ErrorCode::Unauthenticated));
    assert_eq!(
        expect_close(&mut socket).await,
        Some(close_code::AUTHENTICATION_FAILED)
    );

    // Anything other than Hello as the first frame is refused too.
    let mut socket = open(&app, Some(GATEWAY_SUBPROTOCOL)).await.unwrap();
    send(
        &mut socket,
        1,
        ClientPayload::Heartbeat(proto::Heartbeat {}),
    )
    .await;
    assert_eq!(
        expect_close(&mut socket).await,
        Some(close_code::AUTHENTICATION_FAILED)
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn malformed_frames_close_the_connection() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("gw", false).await;

    // Before authentication.
    let mut socket = open(&app, Some(GATEWAY_SUBPROTOCOL)).await.unwrap();
    socket
        .send(Message::Binary(vec![0xFF, 0xFF, 0xFF, 0xFF].into()))
        .await
        .unwrap();
    assert_eq!(
        expect_close(&mut socket).await,
        Some(close_code::MALFORMED_FRAME)
    );

    // After authentication, as text and as garbage.
    let (mut socket, _) = connect(&app, &device).await;
    socket.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(
        expect_close(&mut socket).await,
        Some(close_code::MALFORMED_FRAME)
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn an_unknown_payload_gets_an_error_and_keeps_the_connection() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("gw", false).await;
    let (mut socket, _) = connect(&app, &device).await;

    // request_id = 5, then field 999 that this server does not know.
    socket
        .send(Message::Binary(vec![0x08, 0x05, 0xba, 0x3e, 0x00].into()))
        .await
        .unwrap();
    let frame = expect_frame(&mut socket).await;
    assert_eq!(frame.request_id, 5);
    let Some(ServerPayload::Error(error)) = frame.payload else {
        panic!("expected an error")
    };
    assert_eq!(error.code, i32::from(proto::ErrorCode::UnsupportedMessage));

    send(
        &mut socket,
        6,
        ClientPayload::Heartbeat(proto::Heartbeat {}),
    )
    .await;
    assert!(matches!(
        expect_frame(&mut socket).await.payload,
        Some(ServerPayload::HeartbeatAck(_))
    ));
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn every_other_device_is_told_about_an_enrolment() {
    let app = TestApp::spawn().await;
    let (account, first) = app.account_with_device("gw", false).await;
    let (mut socket, _) = connect(&app, &first).await;

    let second = app.enrol(&account).await;

    let frame = expect_frame(&mut socket).await;
    assert_eq!(frame.request_id, 0);
    let Some(ServerPayload::DeviceListChanged(event)) = frame.payload else {
        panic!("expected DeviceListChanged, got {frame:?}");
    };
    assert_eq!(event.device_id, second.device_id.as_bytes());
    assert!(event.added);
}

/// `Ready` gives the one-time KeyPackages the server can still serve, and a
/// claim that leaves fewer than 10 tells the device to upload more (ADR 0019,
/// section 3).
#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_device_learns_when_its_key_packages_run_low() {
    let app = TestApp::spawn().await;
    let (account, claimer) = app.account_with_device("gw", false).await;
    let laptop = app.enrol(&account).await;
    let _: tavern_protocol::rest::KeyPackageCount = app
        .post(
            "/v1/devices/me/key-packages",
            Some(&laptop.session_token),
            &tavern_protocol::rest::UploadKeyPackagesRequest {
                key_packages: laptop.key_packages(11),
                last_resort: None,
            },
        )
        .await;
    let (mut socket, ready) = connect(&app, &laptop).await;
    assert_eq!(ready.key_packages_remaining, 11);
    assert_eq!(ready.protocol_minor, tavern_protocol::GATEWAY_MINOR_VERSION);

    let claim = format!("/v1/users/{}/key-packages/claim", account.user_id);
    for _ in 0..2 {
        let status = app
            .status(Method::POST, &claim, Some(&claimer.session_token), NO_BODY)
            .await;
        assert_eq!(status, StatusCode::OK);
    }
    // Ten left after the first claim: no event. Nine after the second.
    let frame = expect_frame(&mut socket).await;
    assert_eq!(frame.request_id, 0);
    assert_eq!(
        frame.payload,
        Some(ServerPayload::KeyPackagesLow(proto::KeyPackagesLow {
            remaining: 9
        }))
    );
}

/// The next frame, which must be a `FriendshipChanged`: its user and state.
async fn friendship(socket: &mut Socket) -> (Vec<u8>, proto::FriendshipState) {
    let frame = expect_frame(socket).await;
    let Some(ServerPayload::FriendshipChanged(change)) = frame.payload else {
        panic!("expected FriendshipChanged, got {frame:?}");
    };
    let state = change.state();
    (change.user_id, state)
}

async fn send_request(app: &TestApp, from: &Device, to: &common::Account) {
    let _: tavern_protocol::rest::FriendRequestAnswer = app
        .post(
            "/v1/friends/requests",
            Some(&from.session_token),
            &tavern_protocol::rest::FriendRequest {
                handle: to.handle.as_str().to_owned(),
            },
        )
        .await;
}

/// ADR 0020: both users' devices are told of a request and of its answer.
#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn both_users_are_told_of_a_request_and_its_answer() {
    use proto::FriendshipState as State;
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("gw", false).await;
    let (bob, bob1) = app.account_with_device("gw", false).await;
    let (mut alice_socket, _) = connect(&app, &alice1).await;
    let (mut bob_socket, _) = connect(&app, &bob1).await;
    let (alice_id, bob_id) = (
        alice.user_id.as_bytes().to_vec(),
        bob.user_id.as_bytes().to_vec(),
    );

    send_request(&app, &alice1, &bob).await;
    assert_eq!(
        friendship(&mut alice_socket).await,
        (bob_id.clone(), State::RequestSent)
    );
    assert_eq!(
        friendship(&mut bob_socket).await,
        (alice_id.clone(), State::RequestReceived)
    );
    let status = app
        .status(
            Method::POST,
            &format!("/v1/friends/requests/{}/accept", alice.user_id),
            Some(&bob1.session_token),
            NO_BODY,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        friendship(&mut alice_socket).await,
        (bob_id, State::Friends)
    );
    assert_eq!(
        friendship(&mut bob_socket).await,
        (alice_id, State::Friends)
    );
}

/// ADR 0020: the blocked user is told what an unfriending tells, the blocker
/// is told nothing of the request sent meanwhile, and lifting the block
/// deletes that request on both sides.
#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_block_is_not_disclosed_by_events() {
    use proto::FriendshipState as State;
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("gw", false).await;
    let (bob, bob1) = app.account_with_device("gw", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;
    let (mut alice_socket, _) = connect(&app, &alice1).await;
    let (mut bob_socket, _) = connect(&app, &bob1).await;
    let (alice_id, bob_id) = (
        alice.user_id.as_bytes().to_vec(),
        bob.user_id.as_bytes().to_vec(),
    );
    let bob_acts = |method: Method, path: String| {
        let token = bob1.session_token.clone();
        let app = &app;
        async move { app.status(method, &path, Some(&token), NO_BODY).await }
    };

    let status = bob_acts(Method::PUT, format!("/v1/blocks/{}", alice.user_id)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        friendship(&mut bob_socket).await,
        (alice_id.clone(), State::Blocked)
    );
    assert_eq!(
        friendship(&mut alice_socket).await,
        (bob_id.clone(), State::None),
        "what an unfriending tells"
    );

    send_request(&app, &alice1, &bob).await;
    assert_eq!(
        friendship(&mut alice_socket).await,
        (bob_id.clone(), State::RequestSent)
    );
    let status = bob_acts(Method::DELETE, format!("/v1/blocks/{}", alice.user_id)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Bob's next frame is the unblock: the request never reached him.
    assert_eq!(friendship(&mut bob_socket).await, (alice_id, State::None));
    assert_eq!(friendship(&mut alice_socket).await, (bob_id, State::None));
}

/// ADR 0019, section 4: both users' devices are told when their DM is
/// created, and only then.
#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn both_users_are_told_when_their_dm_is_created() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("gw", false).await;
    let (bob, bob1) = app.account_with_device("gw", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;
    let (mut alice_socket, _) = connect(&app, &alice1).await;
    let (mut bob_socket, _) = connect(&app, &bob1).await;
    let request = tavern_protocol::rest::CreateDmRequest {
        user_id: bob.user_id,
    };
    let dm: tavern_protocol::rest::Conversation = app
        .post("/v1/conversations", Some(&alice1.session_token), &request)
        .await;

    let mut members = [alice.user_id, bob.user_id];
    members.sort();
    let expected = Some(ServerPayload::ConversationCreated(
        proto::ConversationCreated {
            conversation_id: dm.conversation_id.as_bytes().to_vec(),
            kind: proto::ConversationKind::Dm.into(),
            member_user_ids: members.iter().map(|id| id.as_bytes().to_vec()).collect(),
        },
    ));
    assert_eq!(expected_frame_payload(&mut alice_socket).await, expected);
    assert_eq!(expected_frame_payload(&mut bob_socket).await, expected);

    // Asked again: it exists, nothing is announced. Bob's next frame is the
    // unfriending that follows.
    let _: tavern_protocol::rest::Conversation = app
        .post("/v1/conversations", Some(&alice1.session_token), &request)
        .await;
    let status = app
        .status(
            Method::DELETE,
            &format!("/v1/friends/{}", alice.user_id),
            Some(&bob1.session_token),
            NO_BODY,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        friendship(&mut bob_socket).await,
        (
            alice.user_id.as_bytes().to_vec(),
            proto::FriendshipState::None
        )
    );
}

async fn expected_frame_payload(socket: &mut Socket) -> Option<ServerPayload> {
    let frame = expect_frame(socket).await;
    assert_eq!(frame.request_id, 0);
    frame.payload
}

/// Protocol, section 5.2: a user's friends are told when they enrol or
/// revoke a device; other users are not.
#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn friends_are_told_of_each_other_s_devices() {
    let app = TestApp::spawn().await;
    let (alice, alice1) = app.account_with_device("gw", false).await;
    let (bob, bob1) = app.account_with_device("gw", false).await;
    let (carol, carol1) = app.account_with_device("gw", false).await;
    app.befriend((&alice, &alice1), (&bob, &bob1)).await;
    let (mut bob_socket, _) = connect(&app, &bob1).await;
    let (mut carol_socket, _) = connect(&app, &carol1).await;

    let alice2 = app.enrol(&alice).await;
    let status = app
        .status(
            Method::DELETE,
            &format!("/v1/devices/{}", alice2.device_id),
            Some(&alice1.session_token),
            NO_BODY,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for added in [true, false] {
        let frame = expect_frame(&mut bob_socket).await;
        assert_eq!(
            frame.payload,
            Some(ServerPayload::UserDevicesChanged(
                proto::UserDevicesChanged {
                    user_id: alice.user_id.as_bytes().to_vec(),
                    device_id: alice2.device_id.as_bytes().to_vec(),
                    added,
                }
            ))
        );
    }

    // Carol is not Alice's friend: her next frame is about her own device.
    let carol2 = app.enrol(&carol).await;
    let frame = expect_frame(&mut carol_socket).await;
    let Some(ServerPayload::DeviceListChanged(event)) = frame.payload else {
        panic!("expected DeviceListChanged, got {frame:?}");
    };
    assert_eq!(event.device_id, carol2.device_id.as_bytes());
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn an_offline_device_learns_about_enrolments_when_it_reconnects() {
    let app = TestApp::spawn().await;
    let (account, first) = app.account_with_device("gw", false).await;

    // Enrolled while the first device is not connected.
    let second = app.enrol(&account).await;

    let (socket, ready) = connect(&app, &first).await;
    assert_eq!(ready.new_devices.len(), 1);
    assert_eq!(ready.new_devices[0].device_id, second.device_id.as_bytes());
    assert_eq!(
        ready.new_devices[0].platform,
        i32::from(proto::Platform::Linux)
    );

    // Until acknowledged, it is reported again.
    drop(socket);
    let (mut socket, ready) = connect(&app, &first).await;
    assert_eq!(ready.new_devices.len(), 1);

    send(
        &mut socket,
        2,
        ClientPayload::AckDeviceList(proto::AckDeviceList {}),
    )
    .await;
    assert!(matches!(
        expect_frame(&mut socket).await.payload,
        Some(ServerPayload::Ack(_))
    ));
    drop(socket);
    let (_socket, ready) = connect(&app, &first).await;
    assert!(ready.new_devices.is_empty());

    // The new device itself has nothing to be told about.
    let (_socket, ready) = connect(&app, &second).await;
    assert!(ready.new_devices.is_empty());
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn revoking_a_device_closes_its_connection() {
    let app = TestApp::spawn().await;
    let (account, first) = app.account_with_device("gw", false).await;
    let second = app.enrol(&account).await;
    let (mut socket, _) = connect(&app, &second).await;

    let path = format!("/v1/devices/{}", second.device_id);
    assert_eq!(
        app.status(Method::DELETE, &path, Some(&first.session_token), NO_BODY)
            .await,
        StatusCode::NO_CONTENT
    );

    let frame = expect_frame(&mut socket).await;
    let Some(ServerPayload::SessionRevoked(event)) = frame.payload else {
        panic!("expected SessionRevoked, got {frame:?}");
    };
    assert_eq!(event.reason, i32::from(proto::RevocationReason::Revoked));
    assert_eq!(
        expect_close(&mut socket).await,
        Some(close_code::SESSION_REVOKED)
    );

    // It cannot come back with the same token.
    let mut socket = open(&app, Some(GATEWAY_SUBPROTOCOL)).await.unwrap();
    send(&mut socket, 1, hello(&second.session_token)).await;
    assert!(matches!(
        expect_frame(&mut socket).await.payload,
        Some(ServerPayload::Error(_))
    ));
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_second_connection_of_the_same_device_replaces_the_first() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("gw", false).await;
    let (mut first, _) = connect(&app, &device).await;

    let (mut second, _) = connect(&app, &device).await;

    let frame = expect_frame(&mut first).await;
    let Some(ServerPayload::SessionRevoked(event)) = frame.payload else {
        panic!("expected SessionRevoked, got {frame:?}");
    };
    assert_eq!(event.reason, i32::from(proto::RevocationReason::Replaced));
    assert_eq!(expect_close(&mut first).await, Some(close_code::REPLACED));

    // The new connection is the one that receives events from now on.
    send(
        &mut second,
        2,
        ClientPayload::Heartbeat(proto::Heartbeat {}),
    )
    .await;
    assert!(matches!(
        expect_frame(&mut second).await.payload,
        Some(ServerPayload::HeartbeatAck(_))
    ));
    assert_eq!(app.state.gateway.connected(), 1);
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn a_session_that_ended_is_noticed_at_the_next_heartbeat() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("gw", false).await;
    let (mut socket, _) = connect(&app, &device).await;

    // Ended behind the gateway's back, as an expiry would.
    sqlx::query(
        "UPDATE sessions SET expires_at = now() - interval '1 second' WHERE device_id = $1",
    )
    .bind(Uuid::from_bytes(*device.device_id.as_bytes()))
    .execute(&app.state.db)
    .await
    .unwrap();

    send(
        &mut socket,
        2,
        ClientPayload::Heartbeat(proto::Heartbeat {}),
    )
    .await;
    assert_eq!(
        expect_close(&mut socket).await,
        Some(close_code::SESSION_REVOKED)
    );
}

#[tokio::test]
#[ignore = "needs PostgreSQL"]
async fn an_oversized_frame_is_refused() {
    let app = TestApp::spawn().await;
    let (_, device) = app.account_with_device("gw", false).await;
    let (mut socket, _) = connect(&app, &device).await;

    // Larger than the 1 MiB frame limit; the send may fail once the server hangs up.
    let _ = socket
        .send(Message::Binary(vec![0u8; 2 * 1024 * 1024].into()))
        .await;

    assert!(matches!(receive(&mut socket).await, Received::Closed(_)));
}
