// SPDX-License-Identifier: AGPL-3.0-or-later

//! A gateway client for the tests: frames in and out of a WebSocket.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use reqwest::StatusCode;
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::client_frame::Payload as ClientPayload;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_protocol::rest::B64;
use tavern_protocol::{GATEWAY_PATH, GATEWAY_SUBPROTOCOL};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::{Device, TestApp};

pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn open(app: &TestApp, subprotocol: Option<&str>) -> Result<Socket, StatusCode> {
    open_at(app.addr, subprotocol).await
}

pub async fn open_at(addr: SocketAddr, subprotocol: Option<&str>) -> Result<Socket, StatusCode> {
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

pub async fn send(socket: &mut Socket, request_id: u64, payload: ClientPayload) {
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
pub enum Received {
    /// A frame.
    Frame(proto::ServerFrame),
    /// The close, with its code.
    Closed(Option<u16>),
}

pub async fn receive(socket: &mut Socket) -> Received {
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

pub async fn expect_frame(socket: &mut Socket) -> proto::ServerFrame {
    match receive(socket).await {
        Received::Frame(frame) => frame,
        Received::Closed(code) => panic!("the server closed the connection ({code:?})"),
    }
}

pub async fn expect_close(socket: &mut Socket) -> Option<u16> {
    match receive(socket).await {
        Received::Closed(code) => code,
        Received::Frame(frame) => panic!("expected a close, got {frame:?}"),
    }
}

pub fn hello(token: &B64) -> ClientPayload {
    ClientPayload::Hello(proto::Hello {
        session_token: token.0.clone(),
        protocol_minor: 0,
        client_version: "test".to_owned(),
        client_platform: "linux".to_owned(),
    })
}

/// Opens an authenticated connection and returns it with its `Ready`.
pub async fn connect(app: &TestApp, device: &Device) -> (Socket, proto::Ready) {
    connect_at(app.addr, device).await
}

pub async fn connect_at(addr: SocketAddr, device: &Device) -> (Socket, proto::Ready) {
    let mut socket = open_at(addr, Some(GATEWAY_SUBPROTOCOL)).await.unwrap();
    send(&mut socket, 1, hello(&device.session_token)).await;
    let frame = expect_frame(&mut socket).await;
    assert_eq!(frame.request_id, 1);
    let Some(ServerPayload::Ready(ready)) = frame.payload else {
        panic!("expected Ready, got {frame:?}");
    };
    (socket, ready)
}
