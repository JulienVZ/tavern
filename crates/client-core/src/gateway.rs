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

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
use tokio::sync::{mpsc, oneshot};
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
/// How long a request waits for its answer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

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
    /// The instance was restored from a backup: what the user changed after
    /// it ([`SecurityNotice::backup_taken_at_ms`]) is undone, and every
    /// device was signed out.
    InstanceRestored,
    /// The same restore, told to an administrator: what administrators did
    /// after the backup is undone, and every invitation was revoked.
    InstanceRestoredAdmin,
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
    /// The notices of a restore: when the restored backup was
    /// taken, in milliseconds since the Unix epoch, if the instance knows.
    pub backup_taken_at_ms: Option<u64>,
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
            Ok(proto::SecurityNoticeKind::InstanceRestored) => SecurityNoticeKind::InstanceRestored,
            Ok(proto::SecurityNoticeKind::InstanceRestoredAdmin) => {
                SecurityNoticeKind::InstanceRestoredAdmin
            }
            Ok(proto::SecurityNoticeKind::Unspecified) | Err(_) => SecurityNoticeKind::Other,
        };
        Some(Self {
            notice_id: uuid(&notice.notice_id)?,
            kind,
            created_at_ms: notice.created_at_ms,
            backup_taken_at_ms: (matches!(
                kind,
                SecurityNoticeKind::InstanceRestored | SecurityNoticeKind::InstanceRestoredAdmin
            ) && notice.backup_taken_at_ms != 0)
                .then_some(notice.backup_taken_at_ms),
        })
    }
}

/// Where this user stands with another one (ADR 0020).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// Nothing between them.
    None,
    /// This user sent a request.
    RequestSent,
    /// The other user sent a request.
    RequestReceived,
    /// Friends.
    Friends,
    /// This user blocks the other one.
    Blocked,
}

impl Relation {
    fn from_proto(state: i32) -> Option<Self> {
        match proto::FriendshipState::try_from(state).ok()? {
            proto::FriendshipState::None => Some(Self::None),
            proto::FriendshipState::RequestSent => Some(Self::RequestSent),
            proto::FriendshipState::RequestReceived => Some(Self::RequestReceived),
            proto::FriendshipState::Friends => Some(Self::Friends),
            proto::FriendshipState::Blocked => Some(Self::Blocked),
        }
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
        /// The instance generation: when it differs from the one seen last,
        /// the instance was restored from a backup, and the groups of the
        /// conversations are to be recreated (0 before gateway minor 7).
        instance_generation: u64,
        /// The one-time KeyPackages of this device the instance can still
        /// serve.
        key_packages_remaining: u32,
    },
    /// A message, commit or proposal of a conversation's sequence: a
    /// notification, not a reliable source (`protocol.md`, section 3). The
    /// sequence is read in the order of its numbers, gaps filled with
    /// [`Gateway::fetch_messages`].
    Sequenced(proto::StoredMessage),
    /// A Welcome for this device, sent again at each connection until
    /// [`Gateway::ack_welcome`].
    Welcome(proto::WelcomeEvent),
    /// A claim left this device fewer than 10 one-time KeyPackages.
    KeyPackagesLow {
        /// How many the instance can still serve.
        remaining: u32,
    },
    /// A device was just enrolled on the account. The user must be notified
    /// and offered to revoke it.
    DeviceAdded(Uuid),
    /// A device of the account was revoked.
    DeviceRemoved(Uuid),
    /// Something security-relevant just happened to the account.
    SecurityNotice(SecurityNotice),
    /// The relation with another user changed (ADR 0020). The friend list
    /// is to be read again.
    FriendshipChanged {
        /// The other user.
        user_id: Uuid,
        /// Where this user now stands with them.
        relation: Relation,
    },
    /// A conversation of this user was created; it has no MLS group yet.
    ConversationCreated {
        /// The conversation.
        conversation_id: Uuid,
        /// Its members.
        members: Vec<Uuid>,
    },
    /// This device is not in the MLS group of a conversation of its user,
    /// or the server is removing it: it joins by external commit (ADR 0019,
    /// sections 4 and 15; the sync engine of tasks 10 and 11).
    JoinConversation {
        /// The conversation.
        conversation_id: Uuid,
    },
    /// A friend enrolled (`added`) or revoked a device.
    UserDevicesChanged {
        /// The friend.
        user_id: Uuid,
        /// The device.
        device_id: Uuid,
        /// `true` for an enrolment.
        added: bool,
    },
    /// The connection dropped; the gateway is reconnecting.
    Disconnected,
    /// The session ended. The gateway stopped; the user must log in again.
    SessionEnded(SessionEnd),
}

/// A request of the gateway that got no usable answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The instance refused it.
    #[error("the instance refused the request ({code:?})")]
    Refused {
        /// Why.
        code: proto::ErrorCode,
        /// With `RATE_LIMITED`, how long to wait; 0 otherwise.
        retry_after_ms: u32,
        /// With `STALE_EPOCH`, the group's current epoch when known.
        current_epoch: u64,
    },
    /// No answer came in time, the connection being up.
    #[error("the instance did not answer in time")]
    TimedOut,
    /// Not connected, or the connection dropped before the answer. Nothing
    /// says whether the instance handled it: a request is safe to send
    /// again (messages are idempotent by `client_message_id`).
    #[error("the gateway is not connected")]
    Disconnected,
    /// An answer of another kind than the request's.
    #[error("the instance gave an unexpected answer")]
    Unexpected,
}

type Reply = oneshot::Sender<Result<ServerPayload, RequestError>>;

#[derive(Debug)]
enum Command {
    AckDeviceList,
    AckSecurityNotices(Vec<Uuid>),
    Request(ClientPayload, Reply),
}

/// Handle to the background connection. Dropping it closes the connection.
#[derive(Debug)]
pub struct Gateway {
    commands: mpsc::Sender<Command>,
    connected: Arc<AtomicBool>,
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

        let (commands, command_queue) = mpsc::channel(64);
        let (events, event_queue) = mpsc::channel(EVENT_QUEUE);
        let connected = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run(
            url,
            session_token,
            command_queue,
            events,
            Arc::clone(&connected),
        ));
        Ok((
            Self {
                commands,
                connected,
                task,
            },
            event_queue,
        ))
    }

    /// Whether the connection is up and authenticated.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Sends a request and waits for its answer, at most
    /// [`REQUEST_TIMEOUT`]. Refused at once while not connected.
    pub async fn request(&self, payload: ClientPayload) -> Result<ServerPayload, RequestError> {
        if !self.is_connected() {
            return Err(RequestError::Disconnected);
        }
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Request(payload, reply))
            .await
            .map_err(|_| RequestError::Disconnected)?;
        match tokio::time::timeout(REQUEST_TIMEOUT, answer).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(RequestError::Disconnected),
            Err(_) => Err(RequestError::TimedOut),
        }
    }

    /// `SendMessage`: an application message for the group's current epoch.
    pub async fn send_message(
        &self,
        request: proto::SendMessage,
    ) -> Result<proto::SendMessageAck, RequestError> {
        match self.request(ClientPayload::SendMessage(request)).await? {
            ServerPayload::SendMessageAck(ack) => Ok(ack),
            _ => Err(RequestError::Unexpected),
        }
    }

    /// `SubmitCommit`: a commit for the group's current epoch, or a group's
    /// first commit.
    pub async fn submit_commit(
        &self,
        request: proto::SubmitCommit,
    ) -> Result<proto::CommitAck, RequestError> {
        match self.request(ClientPayload::SubmitCommit(request)).await? {
            ServerPayload::CommitAck(ack) => Ok(ack),
            _ => Err(RequestError::Unexpected),
        }
    }

    /// `FetchMessages`: the sequence of a conversation after `after_seq`.
    pub async fn fetch_messages(
        &self,
        request: proto::FetchMessages,
    ) -> Result<proto::MessageBatch, RequestError> {
        match self.request(ClientPayload::FetchMessages(request)).await? {
            ServerPayload::MessageBatch(batch) => Ok(batch),
            _ => Err(RequestError::Unexpected),
        }
    }

    /// `AckMessages`: everything up to a number is durably processed.
    pub async fn ack_messages(&self, request: proto::AckMessages) -> Result<(), RequestError> {
        match self.request(ClientPayload::AckMessages(request)).await? {
            ServerPayload::Ack(_) => Ok(()),
            _ => Err(RequestError::Unexpected),
        }
    }

    /// `AckWelcome`: a Welcome is processed, or ignored for good.
    pub async fn ack_welcome(&self, request: proto::AckWelcome) -> Result<(), RequestError> {
        match self.request(ClientPayload::AckWelcome(request)).await? {
            ServerPayload::Ack(_) => Ok(()),
            _ => Err(RequestError::Unexpected),
        }
    }

    /// `FetchGroupInfo`: the group's latest GroupInfo, to join it by
    /// external commit.
    pub async fn fetch_group_info(
        &self,
        request: proto::FetchGroupInfo,
    ) -> Result<proto::GroupInfo, RequestError> {
        match self.request(ClientPayload::FetchGroupInfo(request)).await? {
            ServerPayload::GroupInfo(info) => Ok(info),
            _ => Err(RequestError::Unexpected),
        }
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
    up: Arc<AtomicBool>,
) {
    let mut backoff = BACKOFF_MIN;
    loop {
        let mut connected = false;
        let ended = connection(
            &url,
            &session_token,
            &mut commands,
            &events,
            &mut connected,
            &up,
        )
        .await;
        up.store(false, Ordering::Release);
        // Requests sent while it was down get no answer: they fail now.
        while let Ok(command) = commands.try_recv() {
            if let Command::Request(_, reply) = command {
                let _ = reply.send(Err(RequestError::Disconnected));
            }
        }
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
    up: &AtomicBool,
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
    up.store(true, Ordering::Release);
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
            instance_generation: ready.instance_generation,
            key_packages_remaining: ready.key_packages_remaining,
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
    // Requests waiting for their answer. Dropped with the connection: their
    // callers get `Disconnected`.
    let mut pending: HashMap<u64, Reply> = HashMap::new();

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
                    Some(Command::Request(payload, reply)) => {
                        request_id += 1;
                        if socket.send(encode(request_id, payload)).await.is_err() {
                            let _ = reply.send(Err(RequestError::Disconnected));
                            return Ended::Dropped;
                        }
                        pending.insert(request_id, reply);
                        continue;
                    }
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
                if frame.request_id != 0
                    && let Some(reply) = pending.remove(&frame.request_id)
                {
                    let _ = reply.send(answer(frame.payload));
                    continue;
                }
                let event = match frame.payload {
                    Some(
                        ServerPayload::MessageEvent(proto::MessageEvent { message })
                        | ServerPayload::CommitEvent(proto::CommitEvent { message })
                        | ServerPayload::ProposalEvent(proto::ProposalEvent { message }),
                    ) => message.map(GatewayEvent::Sequenced),
                    Some(ServerPayload::WelcomeEvent(welcome)) => Some(GatewayEvent::Welcome(welcome)),
                    Some(ServerPayload::KeyPackagesLow(low)) => Some(GatewayEvent::KeyPackagesLow {
                        remaining: low.remaining,
                    }),
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
                    Some(ServerPayload::FriendshipChanged(change)) => uuid(&change.user_id)
                        .zip(Relation::from_proto(change.state))
                        .map(|(user_id, relation)| GatewayEvent::FriendshipChanged {
                            user_id,
                            relation,
                        }),
                    Some(ServerPayload::ConversationCreated(created)) => {
                        let members: Option<Vec<Uuid>> =
                            created.member_user_ids.iter().map(|id| uuid(id)).collect();
                        uuid(&created.conversation_id).zip(members).map(
                            |(conversation_id, members)| GatewayEvent::ConversationCreated {
                                conversation_id,
                                members,
                            },
                        )
                    }
                    Some(ServerPayload::JoinConversation(join)) => uuid(&join.conversation_id)
                        .map(|conversation_id| GatewayEvent::JoinConversation { conversation_id }),
                    Some(ServerPayload::UserDevicesChanged(change)) => uuid(&change.user_id)
                        .zip(uuid(&change.device_id))
                        .map(|(user_id, device_id)| GatewayEvent::UserDevicesChanged {
                            user_id,
                            device_id,
                            added: change.added,
                        }),
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

/// The answer to a request: its payload, or the instance's refusal.
fn answer(payload: Option<ServerPayload>) -> Result<ServerPayload, RequestError> {
    match payload {
        Some(ServerPayload::Error(error)) => Err(RequestError::Refused {
            code: proto::ErrorCode::try_from(error.code).unwrap_or(proto::ErrorCode::Unspecified),
            retry_after_ms: error.retry_after_ms,
            current_epoch: error.current_epoch,
        }),
        Some(payload) => Ok(payload),
        None => Err(RequestError::Unexpected),
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

    /// A request while the gateway is not connected fails at once, with
    /// nothing sent: the caller may send it again later.
    #[tokio::test]
    async fn a_request_without_a_connection_fails_at_once() {
        // Nothing listens there: the gateway never connects.
        let url = Url::parse("ws://127.0.0.1:9/gateway/v1").unwrap();
        let (gateway, _events) = Gateway::start(url, B64(vec![0; 32])).unwrap();
        assert!(!gateway.is_connected());
        let answer = tokio::time::timeout(
            Duration::from_secs(1),
            gateway.request(ClientPayload::Heartbeat(proto::Heartbeat {})),
        )
        .await
        .expect("answered at once");
        assert_eq!(answer, Err(RequestError::Disconnected));
    }

    /// An answer is the request's payload, or the instance's refusal with
    /// its code, its wait and the group's epoch.
    #[test]
    fn an_answer_is_a_payload_or_a_typed_refusal() {
        let ack = ServerPayload::Ack(proto::Ack {});
        assert_eq!(answer(Some(ack.clone())), Ok(ack));
        let refusal = ServerPayload::Error(proto::Error {
            code: proto::ErrorCode::StaleEpoch.into(),
            message: "for a past epoch".to_owned(),
            retry_after_ms: 0,
            current_epoch: 4,
        });
        assert_eq!(
            answer(Some(refusal)),
            Err(RequestError::Refused {
                code: proto::ErrorCode::StaleEpoch,
                retry_after_ms: 0,
                current_epoch: 4,
            })
        );
        assert_eq!(answer(None), Err(RequestError::Unexpected));
    }

    #[test]
    fn notices_of_an_unknown_kind_are_still_shown() {
        let id = Uuid::from_u128(3);
        let notice = |kind: i32| proto::SecurityNotice {
            kind,
            notice_id: id.as_bytes().to_vec(),
            created_at_ms: 42,
            backup_taken_at_ms: 0,
        };
        let kind = |value: i32| SecurityNotice::from_proto(&notice(value)).map(|n| n.kind);

        assert_eq!(kind(1), Some(SecurityNoticeKind::TotpDisabledByAdmin));
        assert_eq!(kind(2), Some(SecurityNoticeKind::PasswordChanged));
        assert_eq!(kind(3), Some(SecurityNoticeKind::AccountRecovered));
        assert_eq!(kind(4), Some(SecurityNoticeKind::DeviceRevoked));
        assert_eq!(kind(5), Some(SecurityNoticeKind::RecoveryKeyReplaced));
        assert_eq!(kind(6), Some(SecurityNoticeKind::InstanceRestored));
        assert_eq!(kind(7), Some(SecurityNoticeKind::InstanceRestoredAdmin));
        assert_eq!(kind(0), Some(SecurityNoticeKind::Other));
        assert_eq!(kind(99), Some(SecurityNoticeKind::Other));

        // A notice that cannot be acknowledged (an instance older than minor
        // 1 sends no identifier) is dropped rather than shown for ever.
        let unidentified = proto::SecurityNotice {
            kind: 1,
            notice_id: Vec::new(),
            created_at_ms: 0,
            backup_taken_at_ms: 0,
        };
        assert_eq!(SecurityNotice::from_proto(&unidentified), None);

        // The date of the backup, for a restore only; 0 is unknown.
        let restored = |backup_taken_at_ms| proto::SecurityNotice {
            kind: 6,
            backup_taken_at_ms,
            ..notice(6)
        };
        let backup = |notice: proto::SecurityNotice| {
            SecurityNotice::from_proto(&notice).map(|n| n.backup_taken_at_ms)
        };
        assert_eq!(backup(restored(1_700)), Some(Some(1_700)));
        assert_eq!(backup(restored(0)), Some(None));
        assert_eq!(
            backup(proto::SecurityNotice {
                backup_taken_at_ms: 1_700,
                ..notice(2)
            }),
            Some(None)
        );
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
