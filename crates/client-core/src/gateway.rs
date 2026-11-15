// SPDX-License-Identifier: AGPL-3.0-or-later

//! The device's real-time connection to its instance.
//!
//! A background task keeps one WebSocket open: it authenticates with the
//! session token, sends heartbeats, turns server frames into
//! [`GatewayEvent`]s and reconnects with exponential backoff when the
//! connection drops. It stops for good when the instance says the session
//! ended; the user must then log in again.
//!
//! Frames from the instance are untrusted input: anything that does not
//! decode ends the connection, which is then re-established.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use tavern_crypto::token;
use tavern_protocol::gateway::v1 as proto;
use tavern_protocol::gateway::v1::client_frame::Payload as ClientPayload;
use tavern_protocol::gateway::v1::server_frame::Payload as ServerPayload;
use tavern_protocol::rest::B64;
use tavern_protocol::{
    DEFAULT_MAX_FRAME_BYTES, GATEWAY_HEARTBEAT_INTERVAL_MS, GATEWAY_HEARTBEAT_TIMEOUT_MS,
    GATEWAY_MINOR_VERSION, GATEWAY_SUBPROTOCOL, MAX_SECURITY_NOTICE_ACKS, close_code,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;
use uuid::Uuid;

use crate::error::ClientError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const EVENT_QUEUE: usize = 64;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Why the session of this device ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The user signed out, or the device was revoked from another device.
    Revoked,
    /// The password was changed or recovered on another device.
    CredentialsChanged,
    /// An administrator disabled the account.
    AccountDisabled,
    /// The session is no longer valid (expired, or unknown to the instance).
    Invalid,
    /// Another connection of the same device took over.
    Replaced,
}

/// A device enrolled on the account while this device was away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewDevice {
    /// The device.
    pub device_id: Uuid,
    /// When it was enrolled, in milliseconds since the Unix epoch.
    pub created_at_ms: u64,
}

/// What a security notice reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityNoticeKind {
    /// An administrator disabled TOTP on the account.
    TotpDisabledByAdmin,
    /// The password was changed.
    PasswordChanged,
    /// The account was recovered with the recovery key.
    AccountRecovered,
    /// A device of the account was revoked.
    DeviceRevoked,
    /// The recovery key was replaced.
    RecoveryKeyReplaced,
    /// A kind introduced by an instance newer than this client. Still shown:
    /// the user must know that something happened.
    Other,
}

/// Something security-relevant that happened to the account. The user must
/// be told, then [`Gateway::ack_security_notices`] called, on every device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityNotice {
    /// Identifies the notice when acknowledging it.
    pub notice_id: Uuid,
    /// What happened.
    pub kind: SecurityNoticeKind,
    /// When, in milliseconds since the Unix epoch.
    pub created_at_ms: u64,
}

impl SecurityNotice {
    /// `None` for a notice without a usable identifier: it could not be
    /// acknowledged, so it is not shown.
    fn from_proto(notice: &proto::SecurityNotice) -> Option<Self> {
        let kind = match proto::SecurityNoticeKind::try_from(notice.kind) {
            Ok(proto::SecurityNoticeKind::TotpDisabledByAdmin) => {
                SecurityNoticeKind::TotpDisabledByAdmin
            }
            Ok(proto::SecurityNoticeKind::PasswordChanged) => SecurityNoticeKind::PasswordChanged,
            Ok(proto::SecurityNoticeKind::AccountRecovered) => SecurityNoticeKind::AccountRecovered,
            Ok(proto::SecurityNoticeKind::DeviceRevoked) => SecurityNoticeKind::DeviceRevoked,
            Ok(proto::SecurityNoticeKind::RecoveryKeyReplaced) => {
                SecurityNoticeKind::RecoveryKeyReplaced
            }
            Ok(proto::SecurityNoticeKind::Unspecified) | Err(_) => SecurityNoticeKind::Other,
        };
        Some(Self {
            notice_id: uuid(&notice.notice_id)?,
            kind,
            created_at_ms: notice.created_at_ms,
        })
    }
}

/// What the gateway tells the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayEvent {
    /// Connected and authenticated. `new_devices` lists the devices enrolled
    /// since this device last acknowledged the list: the user must be told,
    /// then [`Gateway::ack_device_list`] called.
    Connected {
        /// Devices the user has not been told about yet.
        new_devices: Vec<NewDevice>,
        /// Every security notice this device has not acknowledged, including
        /// those already announced by [`GatewayEvent::SecurityNotice`].
        security_notices: Vec<SecurityNotice>,
    },
    /// A device was just enrolled on the account. The user must be notified
    /// and offered to revoke it.
    DeviceAdded(Uuid),
    /// A device of the account was revoked.
    DeviceRemoved(Uuid),
    /// Something security-relevant just happened to the account.
    SecurityNotice(SecurityNotice),
    /// The connection dropped; the gateway is reconnecting.
    Disconnected,
    /// The session ended. The gateway stopped; the user must log in again.
    SessionEnded(SessionEnd),
}

#[derive(Debug)]
enum Command {
    AckDeviceList,
    AckSecurityNotices(Vec<Uuid>),
}

/// Handle to the background connection. Dropping it closes the connection.
#[derive(Debug)]
pub struct Gateway {
    commands: mpsc::Sender<Command>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Gateway {
    /// Starts the connection task. Events arrive on the returned receiver.
    pub(crate) fn start(
        url: Url,
        session_token: B64,
    ) -> Result<(Self, mpsc::Receiver<GatewayEvent>), ClientError> {
        // One TLS provider for the whole client; a no-op if already installed.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let (commands, command_queue) = mpsc::channel(8);
        let (events, event_queue) = mpsc::channel(EVENT_QUEUE);
        let task = tokio::spawn(run(url, session_token, command_queue, events));
        Ok((Self { commands, task }, event_queue))
    }

    /// Tells the instance that the user has seen the current device list, so
    /// that already announced devices are not reported again.
    pub async fn ack_device_list(&self) -> Result<(), ClientError> {
        self.commands
            .send(Command::AckDeviceList)
            .await
            .map_err(|_| ClientError::Interrupted)
    }

    /// Tells the instance that the user dismissed these notices on this
    /// device, so that they are not listed at the next connection.
    pub async fn ack_security_notices(&self, notice_ids: &[Uuid]) -> Result<(), ClientError> {
        // One frame names a bounded number of notices.
        for chunk in notice_ids.chunks(MAX_SECURITY_NOTICE_ACKS) {
            self.commands
                .send(Command::AckSecurityNotices(chunk.to_vec()))
                .await
                .map_err(|_| ClientError::Interrupted)?;
        }
        Ok(())
    }
}

/// How one connection ended.
enum Ended {
    /// Worth reconnecting.
    Dropped,
    /// The session is over.
    Session(SessionEnd),
    /// The application dropped the gateway.
    Stopped,
}

async fn run(
    url: Url,
    session_token: B64,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<GatewayEvent>,
) {
    let mut backoff = BACKOFF_MIN;
    loop {
        let mut connected = false;
        let ended = connection(&url, &session_token, &mut commands, &events, &mut connected).await;
        match ended {
            Ended::Stopped => return,
            Ended::Session(reason) => {
                let _ = events.send(GatewayEvent::SessionEnded(reason)).await;
                return;
            }
            Ended::Dropped => {
                if connected {
                    backoff = BACKOFF_MIN;
                    if events.send(GatewayEvent::Disconnected).await.is_err() {
                        return;
                    }
                }
            }
        }
        // Exponential backoff with jitter, so that the clients of an instance
        // do not all reconnect at the same instant after a restart.
        let jitter = u64::from(token::random_bytes::<1>()[0]) * 4;
        tokio::time::sleep(backoff + Duration::from_millis(jitter)).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

fn encode(request_id: u64, payload: ClientPayload) -> Message {
    let frame = proto::ClientFrame {
        request_id,
        payload: Some(payload),
    };
    Message::Binary(frame.encode_to_vec().into())
}

async fn open(url: &Url) -> Option<Socket> {
    let mut request = url.as_str().into_client_request().ok()?;
    request
        .headers_mut()
        .insert("sec-websocket-protocol", GATEWAY_SUBPROTOCOL.parse().ok()?);
    let config = WebSocketConfig::default()
        .max_message_size(Some(DEFAULT_MAX_FRAME_BYTES as usize))
        .max_frame_size(Some(DEFAULT_MAX_FRAME_BYTES as usize));
    let attempt = tokio_tungstenite::connect_async_with_config(request, Some(config), false);
    match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
        Ok(Ok((socket, _))) => Some(socket),
        _ => None,
    }
}

fn session_end_for_close(code: Option<u16>) -> Option<SessionEnd> {
    match code {
        Some(close_code::SESSION_REVOKED | close_code::AUTHENTICATION_FAILED) => {
            Some(SessionEnd::Invalid)
        }
        Some(close_code::REPLACED) => Some(SessionEnd::Replaced),
        _ => None,
    }
}

/// Decodes the next server frame. `Err` says how the connection ended.
async fn next_frame(socket: &mut Socket, patience: Duration) -> Result<proto::ServerFrame, Ended> {
    loop {
        let message = match tokio::time::timeout(patience, socket.next()).await {
            Ok(Some(Ok(message))) => message,
            _ => return Err(Ended::Dropped),
        };
        match message {
            Message::Binary(bytes) => {
                return proto::ServerFrame::decode(bytes.as_ref()).map_err(|_| Ended::Dropped);
            }
            Message::Close(frame) => {
                let code = frame.map(|frame| u16::from(frame.code));
                return Err(session_end_for_close(code).map_or(Ended::Dropped, Ended::Session));
            }
            Message::Ping(_) | Message::Pong(_) => {}
            // Text and raw frames are not part of the protocol.
            _ => return Err(Ended::Dropped),
        }
    }
}

fn uuid(bytes: &[u8]) -> Option<Uuid> {
    Uuid::from_slice(bytes).ok()
}

async fn connection(
    url: &Url,
    session_token: &B64,
    commands: &mut mpsc::Receiver<Command>,
    events: &mpsc::Sender<GatewayEvent>,
    connected: &mut bool,
) -> Ended {
    let Some(mut socket) = open(url).await else {
        return Ended::Dropped;
    };

    let hello = ClientPayload::Hello(proto::Hello {
        session_token: session_token.0.clone(),
        protocol_minor: GATEWAY_MINOR_VERSION,
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        client_platform: std::env::consts::OS.to_owned(),
    });
    if socket.send(encode(1, hello)).await.is_err() {
        return Ended::Dropped;
    }
    let ready = match next_frame(&mut socket, READY_TIMEOUT).await {
        Ok(proto::ServerFrame {
            payload: Some(ServerPayload::Ready(ready)),
            ..
        }) => ready,
        // The instance answers an invalid session with an error, then closes.
        Ok(proto::ServerFrame {
            payload: Some(ServerPayload::Error(_)),
            ..
        }) => {
            return Ended::Session(SessionEnd::Invalid);
        }
        Ok(_) => return Ended::Dropped,
        Err(ended) => return ended,
    };

    *connected = true;
    let new_devices = ready
        .new_devices
        .iter()
        .filter_map(|device| {
            Some(NewDevice {
                device_id: uuid(&device.device_id)?,
                created_at_ms: device.created_at_ms,
            })
        })
        .collect();
    let security_notices = ready
        .security_notices
        .iter()
        .filter_map(SecurityNotice::from_proto)
        .collect();
    if events
        .send(GatewayEvent::Connected {
            new_devices,
            security_notices,
        })
        .await
        .is_err()
    {
        return Ended::Stopped;
    }

    let interval = ready
        .limits
        .map_or(GATEWAY_HEARTBEAT_INTERVAL_MS, |limits| {
            limits.heartbeat_interval_ms
        })
        .clamp(1_000, GATEWAY_HEARTBEAT_INTERVAL_MS);
    let mut heartbeat = tokio::time::interval(Duration::from_millis(u64::from(interval)));
    heartbeat.tick().await;
    let patience = Duration::from_millis(GATEWAY_HEARTBEAT_TIMEOUT_MS);
    let mut request_id: u64 = 1;

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                request_id += 1;
                let frame = encode(request_id, ClientPayload::Heartbeat(proto::Heartbeat {}));
                if socket.send(frame).await.is_err() {
                    return Ended::Dropped;
                }
            }
            command = commands.recv() => {
                let payload = match command {
                    Some(Command::AckDeviceList) => {
                        ClientPayload::AckDeviceList(proto::AckDeviceList {})
                    }
                    Some(Command::AckSecurityNotices(ids)) => {
                        ClientPayload::AckSecurityNotices(proto::AckSecurityNotices {
                            notice_ids: ids.iter().map(|id| id.as_bytes().to_vec()).collect(),
                        })
                    }
                    None => {
                        let _ = socket.close(None).await;
                        return Ended::Stopped;
                    }
                };
                request_id += 1;
                if socket.send(encode(request_id, payload)).await.is_err() {
                    return Ended::Dropped;
                }
            }
            frame = next_frame(&mut socket, patience) => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(ended) => return ended,
                };
                let event = match frame.payload {
                    Some(ServerPayload::DeviceListChanged(change)) => {
                        uuid(&change.device_id).map(|device_id| {
                            if change.added {
                                GatewayEvent::DeviceAdded(device_id)
                            } else {
                                GatewayEvent::DeviceRemoved(device_id)
                            }
                        })
                    }
                    Some(ServerPayload::SecurityNotice(notice)) => {
                        SecurityNotice::from_proto(&notice).map(GatewayEvent::SecurityNotice)
                    }
                    Some(ServerPayload::SessionRevoked(revoked)) => {
                        return Ended::Session(session_end(revoked.reason));
                    }
                    // Acks, heartbeat acks, errors and payloads this version
                    // does not know: nothing to tell the application.
                    _ => None,
                };
                if let Some(event) = event
                    && events.send(event).await.is_err()
                {
                    return Ended::Stopped;
                }
            }
        }
    }
}

fn session_end(reason: i32) -> SessionEnd {
    match proto::RevocationReason::try_from(reason) {
        Ok(proto::RevocationReason::Revoked) => SessionEnd::Revoked,
        Ok(proto::RevocationReason::CredentialsChanged) => SessionEnd::CredentialsChanged,
        Ok(proto::RevocationReason::AccountDisabled) => SessionEnd::AccountDisabled,
        Ok(proto::RevocationReason::Replaced) => SessionEnd::Replaced,
        Ok(proto::RevocationReason::Unspecified) | Err(_) => SessionEnd::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_codes_that_end_the_session_stop_reconnection() {
        assert_eq!(session_end_for_close(Some(4002)), Some(SessionEnd::Invalid));
        assert_eq!(session_end_for_close(Some(4003)), Some(SessionEnd::Invalid));
        assert_eq!(
            session_end_for_close(Some(4004)),
            Some(SessionEnd::Replaced)
        );
        // Timeouts, malformed frames and plain closes are worth a retry.
        for code in [
            None,
            Some(1000),
            Some(1006),
            Some(4001),
            Some(4006),
            Some(4008),
        ] {
            assert_eq!(session_end_for_close(code), None, "{code:?}");
        }
    }

    #[test]
    fn notices_of_an_unknown_kind_are_still_shown() {
        let id = Uuid::from_u128(3);
        let notice = |kind: i32| proto::SecurityNotice {
            kind,
            notice_id: id.as_bytes().to_vec(),
            created_at_ms: 42,
        };
        let kind = |value: i32| SecurityNotice::from_proto(&notice(value)).map(|n| n.kind);

        assert_eq!(kind(1), Some(SecurityNoticeKind::TotpDisabledByAdmin));
        assert_eq!(kind(2), Some(SecurityNoticeKind::PasswordChanged));
        assert_eq!(kind(3), Some(SecurityNoticeKind::AccountRecovered));
        assert_eq!(kind(4), Some(SecurityNoticeKind::DeviceRevoked));
        assert_eq!(kind(5), Some(SecurityNoticeKind::RecoveryKeyReplaced));
        assert_eq!(kind(0), Some(SecurityNoticeKind::Other));
        assert_eq!(kind(99), Some(SecurityNoticeKind::Other));

        // A notice that cannot be acknowledged (an instance older than minor
        // 1 sends no identifier) is dropped rather than shown for ever.
        let unidentified = proto::SecurityNotice {
            kind: 1,
            notice_id: Vec::new(),
            created_at_ms: 0,
        };
        assert_eq!(SecurityNotice::from_proto(&unidentified), None);
    }

    #[test]
    fn unknown_revocation_reasons_still_end_the_session() {
        assert_eq!(session_end(1), SessionEnd::Revoked);
        assert_eq!(session_end(2), SessionEnd::CredentialsChanged);
        assert_eq!(session_end(3), SessionEnd::AccountDisabled);
        assert_eq!(session_end(4), SessionEnd::Replaced);
        assert_eq!(session_end(0), SessionEnd::Invalid);
        assert_eq!(session_end(99), SessionEnd::Invalid);
    }
}
