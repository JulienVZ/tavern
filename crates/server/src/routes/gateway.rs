// SPDX-License-Identifier: AGPL-3.0-or-later

//! The real-time gateway: one WebSocket per device, protobuf frames.
//!
//! Life of a connection (see `docs/protocol.md`):
//!
//! 1. the client opens the socket with the `tavern.v1` subprotocol;
//! 2. it sends `Hello` with its session token within ten seconds;
//! 3. the server answers `Ready`, which lists the devices enrolled since this
//!    device last acknowledged the list, and the security notices it has not
//!    acknowledged;
//! 4. the client sends `Heartbeat` every thirty seconds; the server checks on
//!    each one that the session is still valid;
//! 5. the server pushes events from the [`Registry`](crate::gateway::Registry).
//!
//! Every frame is decoded from untrusted bytes: sizes are bounded by the
//! WebSocket layer, and anything malformed closes the connection. Each frame
//! is handled under [`panics::guard`]: a panic closes its connection with
//! 1011, and the server goes on.

use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use prost::Message as _;
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::client_frame::Payload as ClientPayload;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_protocol::{
    DEFAULT_MAX_FRAME_BYTES, GATEWAY_HEARTBEAT_INTERVAL_MS, GATEWAY_HEARTBEAT_TIMEOUT_MS,
    GATEWAY_HELLO_DEADLINE_MS, GATEWAY_MINOR_VERSION, GATEWAY_SUBPROTOCOL,
    MAX_SECURITY_NOTICE_ACKS, close_code,
};
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiResult;
use crate::gateway::{Event, RevocationReason};
use crate::notices;
use crate::panics::{self, Panicked};
use crate::routes::key_packages;
use crate::session::{self, Session};

/// Largest application message announced to clients (used from milestone M2).
const MAX_APPLICATION_MESSAGE_BYTES: u32 = 64 * 1024;
/// Largest upload announced to clients (used from milestone M5).
const MAX_UPLOAD_BYTES: u64 = 500 * 1024 * 1024;

/// Upgrades to a WebSocket. Refused unless the client asks for `tavern.v1`.
pub(crate) async fn connect(State(state): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    let upgrade = upgrade
        .protocols([GATEWAY_SUBPROTOCOL])
        .max_message_size(DEFAULT_MAX_FRAME_BYTES as usize)
        .max_frame_size(DEFAULT_MAX_FRAME_BYTES as usize);
    if upgrade.selected_protocol().is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "the tavern.v1 WebSocket subprotocol is required",
        )
            .into_response();
    }
    upgrade.on_upgrade(move |socket| serve(state, socket))
}

fn frame(request_id: u64, payload: ServerPayload) -> Message {
    let frame = proto::ServerFrame {
        request_id,
        payload: Some(payload),
    };
    Message::Binary(frame.encode_to_vec().into())
}

fn error_frame(request_id: u64, code: proto::ErrorCode, message: &str) -> Message {
    frame(
        request_id,
        ServerPayload::Error(proto::Error {
            code: code.into(),
            message: message.to_owned(),
            retry_after_ms: 0,
        }),
    )
}

async fn close(mut socket: WebSocket, code: u16) {
    // The peer may already be gone; nothing to do about a failed close.
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: "".into(),
        })))
        .await;
}

/// What the next message from the client turned out to be.
enum Incoming {
    Frame(proto::ClientFrame),
    /// The peer closed, or the socket failed.
    Gone,
    /// Text, or bytes that are not a `ClientFrame`.
    Malformed,
    /// A ping or pong, handled by the WebSocket layer.
    Control,
}

fn classify(message: Option<Result<Message, axum::Error>>) -> Incoming {
    match message {
        Some(Ok(Message::Binary(bytes))) => match proto::ClientFrame::decode(bytes.as_ref()) {
            Ok(frame) => Incoming::Frame(frame),
            Err(_) => Incoming::Malformed,
        },
        Some(Ok(Message::Text(_))) => Incoming::Malformed,
        Some(Ok(Message::Ping(_) | Message::Pong(_))) => Incoming::Control,
        Some(Ok(Message::Close(_)) | Err(_)) | None => Incoming::Gone,
    }
}

fn platform(db_value: i16) -> proto::Platform {
    match db_value {
        1 => proto::Platform::Windows,
        2 => proto::Platform::Macos,
        3 => proto::Platform::Linux,
        _ => proto::Platform::Unspecified,
    }
}

/// Devices enrolled on the account since `device_id` last acknowledged the list.
async fn new_devices(state: &AppState, session: &Session) -> ApiResult<Vec<proto::DeviceSummary>> {
    let rows: Vec<(Uuid, i16, i64)> = sqlx::query_as(
        "SELECT d.id, d.platform, (extract(epoch FROM d.created_at) * 1000)::bigint \
         FROM devices d JOIN devices me ON me.id = $2 \
         WHERE d.user_id = $1 AND d.id <> $2 AND d.revoked_at IS NULL \
           AND d.created_at > me.devices_seen_at \
         ORDER BY d.created_at",
    )
    .bind(session.user_id)
    .bind(session.device_id)
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(device_id, platform_value, created)| proto::DeviceSummary {
                device_id: device_id.as_bytes().to_vec(),
                platform: platform(platform_value).into(),
                created_at_ms: u64::try_from(created).unwrap_or_default(),
            },
        )
        .collect())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Waits for `Hello` and authenticates it. On failure the socket is closed
/// with the matching code and `None` is returned.
async fn handshake(state: &AppState, mut socket: WebSocket) -> Option<(WebSocket, Session, u64)> {
    let deadline = Duration::from_millis(GATEWAY_HELLO_DEADLINE_MS);
    let first = loop {
        match tokio::time::timeout(deadline, socket.recv()).await {
            Err(_) => {
                close(socket, close_code::HELLO_TIMEOUT).await;
                return None;
            }
            Ok(message) => match classify(message) {
                Incoming::Control => {}
                Incoming::Gone => return None,
                Incoming::Malformed => {
                    close(socket, close_code::MALFORMED_FRAME).await;
                    return None;
                }
                Incoming::Frame(frame) => break frame,
            },
        }
    };

    let Some(ClientPayload::Hello(hello)) = first.payload else {
        close(socket, close_code::AUTHENTICATION_FAILED).await;
        return None;
    };
    let session = session::lookup(&state.db, &hello.session_token, state.settings.session_ttl)
        .await
        .ok()
        .flatten();
    let Some(session) = session else {
        let _ = socket
            .send(error_frame(
                first.request_id,
                proto::ErrorCode::Unauthenticated,
                "invalid session",
            ))
            .await;
        close(socket, close_code::AUTHENTICATION_FAILED).await;
        return None;
    };
    Some((socket, session, first.request_id))
}

/// The close code for a step that failed, or panicked.
fn failed<T, E>(result: Result<Result<T, E>, Panicked>) -> Result<T, u16> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(close_code::AUTHENTICATION_FAILED),
        Err(Panicked) => Err(close_code::INTERNAL_ERROR),
    }
}

async fn serve(state: AppState, socket: WebSocket) {
    // A panic while handling Hello drops the socket: the connection closes.
    let Ok(Some((mut socket, session, hello_id))) = panics::guard(handshake(&state, socket)).await
    else {
        return;
    };
    let new_devices = match failed(panics::guard(new_devices(&state, &session)).await) {
        Ok(new_devices) => new_devices,
        Err(code) => {
            close(socket, code).await;
            return;
        }
    };

    // Subscribe before reading the pending notices, so that none is lost in
    // between: one recorded meanwhile arrives twice, and clients go by its id.
    let mut subscription = state.gateway.connect(session.user_id, session.device_id);
    let pending = async {
        let notices = notices::pending(&state, &session).await?;
        let key_packages = key_packages::remaining(&state.db, session.device_id).await?;
        Ok::<_, crate::error::ApiError>((notices, key_packages))
    };
    let (security_notices, key_packages_remaining) = match failed(panics::guard(pending).await) {
        Ok(pending) => pending,
        Err(code) => {
            state
                .gateway
                .disconnect(session.device_id, subscription.generation);
            close(socket, code).await;
            return;
        }
    };
    let ready = proto::Ready {
        user_id: session.user_id.as_bytes().to_vec(),
        device_id: session.device_id.as_bytes().to_vec(),
        protocol_minor: GATEWAY_MINOR_VERSION,
        server_time_ms: now_ms(),
        limits: Some(proto::Limits {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_application_message_bytes: MAX_APPLICATION_MESSAGE_BYTES,
            max_upload_bytes: MAX_UPLOAD_BYTES,
            heartbeat_interval_ms: GATEWAY_HEARTBEAT_INTERVAL_MS,
        }),
        mls_external_sender_key: state.secrets.external_sender.public_bytes().to_vec(),
        key_packages_remaining,
        new_devices,
        security_notices: security_notices
            .into_iter()
            .map(notices::Notice::to_proto)
            .collect(),
    };

    let close_with = if socket
        .send(frame(hello_id, ServerPayload::Ready(ready)))
        .await
        .is_err()
    {
        None
    } else {
        run(&state, &mut socket, &session, &mut subscription.events).await
    };
    state
        .gateway
        .disconnect(session.device_id, subscription.generation);
    if let Some(code) = close_with {
        close(socket, code).await;
    }
}

/// Serves an authenticated connection until it ends. Returns the close code
/// to send, or `None` when the peer is already gone.
async fn run(
    state: &AppState,
    socket: &mut WebSocket,
    session: &Session,
    events: &mut tokio::sync::mpsc::Receiver<Event>,
) -> Option<u16> {
    let silence = Duration::from_millis(GATEWAY_HEARTBEAT_TIMEOUT_MS);
    loop {
        tokio::select! {
            incoming = tokio::time::timeout(silence, socket.recv()) => {
                let Ok(message) = incoming else {
                    return Some(close_code::HEARTBEAT_TIMEOUT);
                };
                // Untrusted input: a panic while handling it closes this
                // connection only.
                let next = match panics::guard(on_message(state, session, message)).await {
                    Ok(next) => next,
                    Err(Panicked) => return Some(close_code::INTERNAL_ERROR),
                };
                let (request_id, reply) = match next {
                    Next::Reply(request_id, reply) => (request_id, reply),
                    Next::Continue => continue,
                    Next::Close(code) => return Some(code),
                    Next::Gone => return None,
                };
                if socket.send(frame(request_id, reply)).await.is_err() {
                    return None;
                }
            }
            event = events.recv() => {
                let Some(event) = event else {
                    // The registry dropped this connection.
                    return Some(close_code::REPLACED);
                };
                let (payload, then_close) = event_payload(event);
                if socket.send(frame(0, payload)).await.is_err() {
                    return None;
                }
                if let Some(code) = then_close {
                    return Some(code);
                }
            }
        }
    }
}

/// What to do after a message from the client.
enum Next {
    /// Answer the request.
    Reply(u64, ServerPayload),
    /// Nothing to answer.
    Continue,
    /// Close with this code.
    Close(u16),
    /// The peer is gone.
    Gone,
}

/// Decodes and handles one message from the client.
async fn on_message(
    state: &AppState,
    session: &Session,
    message: Option<Result<Message, axum::Error>>,
) -> Next {
    let request = match classify(message) {
        Incoming::Control => return Next::Continue,
        Incoming::Gone => return Next::Gone,
        Incoming::Malformed => return Next::Close(close_code::MALFORMED_FRAME),
        Incoming::Frame(frame) => frame,
    };
    let reply = match request.payload {
        Some(ClientPayload::Heartbeat(_)) => {
            // The cheapest place to notice an expired session.
            if !session_is_live(state, session).await {
                return Next::Close(close_code::SESSION_REVOKED);
            }
            ServerPayload::HeartbeatAck(proto::HeartbeatAck {
                server_time_ms: now_ms(),
            })
        }
        Some(ClientPayload::AckDeviceList(_)) => {
            let updated = sqlx::query("UPDATE devices SET devices_seen_at = now() WHERE id = $1")
                .bind(session.device_id)
                .execute(&state.db)
                .await;
            if updated.is_err() {
                ServerPayload::Error(proto::Error {
                    code: proto::ErrorCode::Internal.into(),
                    message: "internal error".to_owned(),
                    retry_after_ms: 0,
                })
            } else {
                ServerPayload::Ack(proto::Ack {})
            }
        }
        Some(ClientPayload::AckSecurityNotices(ack)) => {
            acknowledge_notices(state, session, &ack.notice_ids).await
        }
        // A second Hello makes no sense on an open connection.
        Some(ClientPayload::Hello(_)) => ServerPayload::Error(proto::Error {
            code: proto::ErrorCode::InvalidArgument.into(),
            message: "already authenticated".to_owned(),
            retry_after_ms: 0,
        }),
        // A payload this server does not know: a newer client.
        None => ServerPayload::Error(proto::Error {
            code: proto::ErrorCode::UnsupportedMessage.into(),
            message: "unsupported message".to_owned(),
            retry_after_ms: 0,
        }),
    };
    Next::Reply(request.request_id, reply)
}

fn error(code: proto::ErrorCode, message: &str) -> ServerPayload {
    ServerPayload::Error(proto::Error {
        code: code.into(),
        message: message.to_owned(),
        retry_after_ms: 0,
    })
}

/// Handles `AckSecurityNotices`: bounded, and every identifier must be a UUID.
async fn acknowledge_notices(
    state: &AppState,
    session: &Session,
    notice_ids: &[Vec<u8>],
) -> ServerPayload {
    if notice_ids.len() > MAX_SECURITY_NOTICE_ACKS {
        return error(proto::ErrorCode::InvalidArgument, "too many notices");
    }
    let ids: Option<Vec<Uuid>> = notice_ids
        .iter()
        .map(|bytes| Uuid::from_slice(bytes).ok())
        .collect();
    let Some(ids) = ids else {
        return error(proto::ErrorCode::InvalidArgument, "invalid notice id");
    };
    match notices::acknowledge(state, session, &ids).await {
        Ok(()) => ServerPayload::Ack(proto::Ack {}),
        Err(_) => error(proto::ErrorCode::Internal, "internal error"),
    }
}

/// Whether the session behind a connection still exists and is usable.
async fn session_is_live(state: &AppState, session: &Session) -> bool {
    let live: Result<bool, sqlx::Error> = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions s \
             JOIN devices d ON d.id = s.device_id \
             JOIN users u ON u.id = d.user_id \
         WHERE s.device_id = $1 AND s.revoked_at IS NULL AND s.expires_at > now() \
           AND d.revoked_at IS NULL AND u.disabled_at IS NULL)",
    )
    .bind(session.device_id)
    .fetch_one(&state.db)
    .await;
    // A database hiccup must not log everyone out.
    live.unwrap_or(true)
}

/// Translates a registry event into a frame, and the close code that follows it, if any.
fn event_payload(event: Event) -> (ServerPayload, Option<u16>) {
    match event {
        Event::DeviceListChanged { device_id, added } => (
            ServerPayload::DeviceListChanged(proto::DeviceListChanged {
                device_id: device_id.as_bytes().to_vec(),
                added,
            }),
            None,
        ),
        Event::SecurityNotice(notice) => (ServerPayload::SecurityNotice(notice.to_proto()), None),
        Event::KeyPackagesLow { remaining } => (
            ServerPayload::KeyPackagesLow(proto::KeyPackagesLow { remaining }),
            None,
        ),
        Event::SessionRevoked(reason) => {
            let (reason, code) = match reason {
                RevocationReason::Revoked => (
                    proto::RevocationReason::Revoked,
                    close_code::SESSION_REVOKED,
                ),
                RevocationReason::CredentialsChanged => (
                    proto::RevocationReason::CredentialsChanged,
                    close_code::SESSION_REVOKED,
                ),
                RevocationReason::AccountDisabled => (
                    proto::RevocationReason::AccountDisabled,
                    close_code::SESSION_REVOKED,
                ),
                RevocationReason::Replaced => {
                    (proto::RevocationReason::Replaced, close_code::REPLACED)
                }
            };
            (
                ServerPayload::SessionRevoked(proto::SessionRevoked {
                    reason: reason.into(),
                }),
                Some(code),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocations_close_the_connection_and_other_events_do_not() {
        let device_id = Uuid::from_u128(7);

        assert_eq!(
            event_payload(Event::DeviceListChanged {
                device_id,
                added: true
            })
            .1,
            None
        );
        let notice = notices::Notice {
            id: Uuid::from_u128(9),
            kind: notices::NoticeKind::PasswordChanged,
            created_at_ms: 1,
        };
        assert_eq!(event_payload(Event::SecurityNotice(notice)).1, None);
        assert_eq!(
            event_payload(Event::SessionRevoked(RevocationReason::Revoked)).1,
            Some(close_code::SESSION_REVOKED)
        );
        assert_eq!(
            event_payload(Event::SessionRevoked(RevocationReason::Replaced)).1,
            Some(close_code::REPLACED)
        );
    }

    #[test]
    fn text_and_garbage_are_malformed() {
        assert!(matches!(
            classify(Some(Ok(Message::Text("hi".into())))),
            Incoming::Malformed
        ));
        assert!(matches!(
            classify(Some(Ok(Message::Binary(vec![0xFF, 0xFF, 0xFF].into())))),
            Incoming::Malformed
        ));
        assert!(matches!(classify(None), Incoming::Gone));
        // An empty frame is a valid ClientFrame with no payload.
        assert!(matches!(
            classify(Some(Ok(Message::Binary(Vec::new().into())))),
            Incoming::Frame(_)
        ));
    }
}
