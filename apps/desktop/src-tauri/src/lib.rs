// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tauri shell of the Tavern desktop client.
//!
//! This crate only maps commands and events onto `tavern-client-core`. It
//! contains no business logic. The webview never receives keys, tokens or
//! ciphertext: commands take what the user typed and return what must be
//! displayed. The one secret that crosses over is the recovery key, because
//! the user has to read it; it is returned once, by `register`, and by the
//! recovery-key rotation.

mod error;

use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tavern_client_core::local::{LocalStoreError, ProfileLock};
use tavern_client_core::password::{self, PasswordStrength};
use tavern_client_core::qr::{self, QrMatrix};
use tavern_client_core::{
    Client, ClientError, Compatibility, Gateway, GatewayEvent, InstanceClient, InstanceUrl,
    KeychainStore, LoginStep, NewAccount, PendingTotp, SecretStore, SecurityNotice,
    SecurityNoticeKind, SessionEnd, SignedIn, compatibility, fetch_health, fetch_version,
};
use tavern_protocol::rest::{
    AdminUser, CreatedInvite, DeviceInfo, HealthResponse, InviteInfo, Platform,
};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::CommandError;

/// Name of the event that carries gateway notifications to the webview.
const GATEWAY_EVENT: &str = "tavern://gateway";

/// What the shell keeps between commands.
#[derive(Default)]
struct Session {
    /// The instance chosen on the first screen.
    instance: Option<InstanceClient>,
    /// A login waiting for its TOTP code.
    pending_totp: Option<Box<PendingTotp>>,
    /// The signed-in client.
    client: Option<Client>,
    /// The real-time connection. Dropping it closes the connection.
    gateway: Option<Gateway>,
}

struct Shell {
    store: Arc<dyn SecretStore>,
    /// The application's local data directory: the accounts' local stores.
    local_data: PathBuf,
    /// Separates several accounts on one computer (`TAVERN_PROFILE`), for
    /// development: two clients can then run side by side.
    profile: Option<String>,
    /// This window's hold of the profile, for as long as it runs; `Err`
    /// when another window has it, and every account operation is refused.
    profile_lock: std::result::Result<ProfileLock, LocalStoreError>,
    session: Mutex<Session>,
}

type Result<T> = std::result::Result<T, CommandError>;

/// The signed-in account, as displayed.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountView {
    user_id: Uuid,
    device_id: Uuid,
    handle: String,
    display_name: String,
    is_admin: bool,
    totp_enabled: bool,
}

/// Result of probing an instance, as shown by the "instance" screen.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstanceProbe {
    /// The URL after validation and normalisation.
    url: String,
    /// What `GET /health` answered.
    health: HealthResponse,
    /// Version of the server software.
    server_version: String,
    /// `true` when the instance is older than this client: some features
    /// will not work until its administrator updates it.
    server_outdated: bool,
    /// The handle last used on this computer for this instance.
    remembered_handle: Option<String>,
    /// Handles of the accounts that have a device on this computer for this
    /// instance, to offer them at sign-in.
    known_handles: Vec<String>,
    /// The account, when a saved session is still valid.
    account: Option<AccountView>,
    /// With `account`: its local store could not be opened and starts empty.
    store_reset: bool,
}

/// A new account. `recovery_key` is displayed once and never stored.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisteredView {
    handle: String,
    is_admin: bool,
    recovery_key: String,
}

/// Where a login stands.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum LoginView {
    TotpRequired,
    #[serde(rename_all = "camelCase")]
    SignedIn {
        account: AccountView,
        /// The device was enrolled by this login: explain that it has no history.
        new_device: bool,
        /// The device was known but its local store could not be opened and
        /// starts empty: explain that the local history is gone.
        store_reset: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceView {
    device_id: Uuid,
    platform: Platform,
    created_at_ms: u64,
    last_seen_at_ms: Option<u64>,
    current: bool,
}

impl From<DeviceInfo> for DeviceView {
    fn from(device: DeviceInfo) -> Self {
        Self {
            device_id: device.device_id,
            platform: device.platform,
            created_at_ms: device.created_at_ms,
            last_seen_at_ms: device.last_seen_at_ms,
            current: device.current,
        }
    }
}

/// A security notice, as sent to the webview.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityNoticeView {
    notice_id: Uuid,
    kind: &'static str,
    created_at_ms: u64,
    /// The notices of a restore, when the instance knows the backup's date.
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_taken_at_ms: Option<u64>,
}

impl From<SecurityNotice> for SecurityNoticeView {
    fn from(notice: SecurityNotice) -> Self {
        Self {
            notice_id: notice.notice_id,
            kind: match notice.kind {
                SecurityNoticeKind::TotpDisabledByAdmin => "totp_disabled_by_admin",
                SecurityNoticeKind::PasswordChanged => "password_changed",
                SecurityNoticeKind::AccountRecovered => "account_recovered",
                SecurityNoticeKind::DeviceRevoked => "device_revoked",
                SecurityNoticeKind::RecoveryKeyReplaced => "recovery_key_replaced",
                SecurityNoticeKind::InstanceRestored => "instance_restored",
                SecurityNoticeKind::InstanceRestoredAdmin => "instance_restored_admin",
                SecurityNoticeKind::Other => "other",
            },
            created_at_ms: notice.created_at_ms,
            backup_taken_at_ms: notice.backup_taken_at_ms,
        }
    }
}

/// A gateway notification, as sent to the webview.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GatewayView {
    #[serde(rename_all = "camelCase")]
    Connected {
        new_devices: Vec<Uuid>,
        security_notices: Vec<SecurityNoticeView>,
    },
    #[serde(rename_all = "camelCase")]
    DeviceAdded {
        device_id: Uuid,
    },
    #[serde(rename_all = "camelCase")]
    DeviceRemoved {
        device_id: Uuid,
    },
    SecurityNotice {
        notice: SecurityNoticeView,
    },
    Disconnected,
    SessionEnded {
        reason: &'static str,
    },
}

impl GatewayView {
    /// What the webview is told of `event`. Friends, their devices and
    /// conversations are not shown before the interface of M2's task 12.
    fn of(event: GatewayEvent) -> Option<Self> {
        Some(match event {
            // The instance generation is for the recreation of groups, from
            // M2's tasks 10 and 11.
            GatewayEvent::Connected {
                new_devices,
                security_notices,
                instance_generation: _,
                key_packages_remaining: _,
                server_time_ms: _,
            } => Self::Connected {
                new_devices: new_devices
                    .into_iter()
                    .map(|device| device.device_id)
                    .collect(),
                security_notices: security_notices.into_iter().map(Into::into).collect(),
            },
            GatewayEvent::DeviceAdded(device_id) => Self::DeviceAdded { device_id },
            GatewayEvent::DeviceRemoved(device_id) => Self::DeviceRemoved { device_id },
            GatewayEvent::SecurityNotice(notice) => Self::SecurityNotice {
                notice: notice.into(),
            },
            GatewayEvent::Disconnected => Self::Disconnected,
            GatewayEvent::SessionEnded(reason) => Self::SessionEnded {
                reason: match reason {
                    SessionEnd::Revoked => "revoked",
                    SessionEnd::CredentialsChanged => "credentials_changed",
                    SessionEnd::AccountDisabled => "account_disabled",
                    SessionEnd::Invalid => "invalid",
                    SessionEnd::Replaced => "replaced",
                },
            },
            GatewayEvent::FriendshipChanged { .. }
            | GatewayEvent::UserDevicesChanged { .. }
            | GatewayEvent::ConversationCreated { .. }
            | GatewayEvent::JoinConversation { .. }
            | GatewayEvent::Sequenced(_)
            | GatewayEvent::Welcome(_)
            | GatewayEvent::KeyPackagesLow { .. }
            // Shown by the interface of task 12.
            | GatewayEvent::ClockSkew { .. }
            // The engine of task 10b reads the sequences again.
            | GatewayEvent::EventsMissed => return None,
        })
    }
}

async fn account_view(client: &Client) -> Result<AccountView> {
    let me = client.me().await?;
    Ok(AccountView {
        user_id: me.user_id,
        device_id: me.device_id,
        handle: me.handle,
        display_name: me.display_name,
        is_admin: me.is_admin,
        totp_enabled: me.totp_enabled,
    })
}

/// Stores the signed-in client and starts forwarding gateway events.
fn attach(app: &AppHandle, session: &mut Session, client: Client) -> Result<()> {
    let (gateway, mut events) = client.connect_gateway()?;
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            let ended = matches!(event, GatewayEvent::SessionEnded(_));
            // The window may be closing; nothing to do about a failed emit.
            if let Some(view) = GatewayView::of(event) {
                let _ = app.emit(GATEWAY_EVENT, view);
            }
            if ended {
                break;
            }
        }
    });
    session.pending_totp = None;
    session.client = Some(client);
    session.gateway = Some(gateway);
    Ok(())
}

async fn signed_in(app: &AppHandle, session: &mut Session, done: SignedIn) -> Result<LoginView> {
    let account = account_view(&done.client).await?;
    attach(app, session, done.client)?;
    Ok(LoginView::SignedIn {
        account,
        new_device: done.new_device,
        store_reset: done.store_reset,
    })
}

fn instance(session: &Session) -> Result<&InstanceClient> {
    session
        .instance
        .as_ref()
        .ok_or(CommandError::code("no_instance"))
}

fn client(session: &Session) -> Result<&Client> {
    session
        .client
        .as_ref()
        .ok_or(CommandError::code("not_signed_in"))
}

// --- Instance -----------------------------------------------------------------

/// Validates the URL typed by the user, queries the instance's health, and
/// resumes the saved session when there is one.
#[tauri::command]
async fn probe_instance(
    app: AppHandle,
    shell: State<'_, Shell>,
    url: String,
) -> Result<InstanceProbe> {
    // One window per profile: the first command of every start.
    if let Err(error) = &shell.profile_lock {
        return Err(ClientError::LocalStore(match error {
            LocalStoreError::ProfileInUse => LocalStoreError::ProfileInUse,
            _ => LocalStoreError::Database("the profile cannot be locked".to_owned()),
        })
        .into());
    }
    let instance_url = InstanceUrl::parse(&url)?;
    let health = fetch_health(&instance_url).await?;
    let version = fetch_version(&instance_url).await?;
    let server_outdated = match compatibility(&version) {
        Compatibility::Compatible => false,
        Compatibility::ServerOlder => true,
        // Nothing would work reliably: refuse now, with a clear reason.
        Compatibility::ServerNewer => return Err(ClientError::ClientTooOld.into()),
    };
    let instance = InstanceClient::new(
        instance_url,
        shell.store.clone(),
        &shell.local_data,
        shell.profile.as_deref(),
    )?;

    let mut session = shell.session.lock().await;
    *session = Session::default();
    let remembered_handle = instance.remembered_handle()?;
    let known_handles = known_handles(&instance)?;
    let (account, store_reset) = match instance.resume().await? {
        Some(resumed) => {
            let view = account_view(&resumed.client).await?;
            attach(&app, &mut session, resumed.client)?;
            (Some(view), resumed.store_reset)
        }
        None => (None, false),
    };
    let url = instance.instance().as_str().to_owned();
    session.instance = Some(instance);
    Ok(InstanceProbe {
        url,
        health,
        server_version: version.version,
        server_outdated,
        remembered_handle,
        known_handles,
        account,
        store_reset,
    })
}

/// The accounts that have a device on this computer for this instance.
fn known_handles(instance: &InstanceClient) -> Result<Vec<String>> {
    Ok(instance
        .known_accounts()?
        .accounts
        .into_iter()
        .map(|account| account.handle)
        .collect())
}

// --- Registration and login -------------------------------------------------------

/// Scores a password for the strength meter. Runs locally; nothing is sent.
#[tauri::command]
fn assess_password(password: String, handle: String, display_name: String) -> PasswordStrength {
    password::assess(&password, &[handle.as_str(), display_name.as_str()])
}

/// Creates an account. The recovery key in the answer must be shown now.
#[tauri::command]
async fn register(
    shell: State<'_, Shell>,
    invite_code: String,
    handle: String,
    display_name: String,
    password: String,
) -> Result<RegisteredView> {
    let session = shell.session.lock().await;
    let registered = instance(&session)?
        .register(NewAccount {
            invite_code: invite_code.trim(),
            handle: handle.trim(),
            display_name: display_name.trim(),
            password: &password,
        })
        .await?;
    Ok(RegisteredView {
        handle: registered.handle.as_str().to_owned(),
        is_admin: registered.is_admin,
        recovery_key: registered.recovery_key.display().to_string(),
    })
}

/// Signs in with a handle and a password.
#[tauri::command]
async fn login(
    app: AppHandle,
    shell: State<'_, Shell>,
    handle: String,
    password: String,
) -> Result<LoginView> {
    let mut session = shell.session.lock().await;
    session.pending_totp = None;
    match instance(&session)?.login(handle.trim(), &password).await? {
        LoginStep::TotpRequired(pending) => {
            session.pending_totp = Some(pending);
            Ok(LoginView::TotpRequired)
        }
        LoginStep::Done(done) => signed_in(&app, &mut session, *done).await,
    }
}

/// Completes a login with a TOTP code or a TOTP recovery code.
#[tauri::command]
async fn submit_totp(app: AppHandle, shell: State<'_, Shell>, code: String) -> Result<LoginView> {
    let mut session = shell.session.lock().await;
    let pending = session
        .pending_totp
        .take()
        .ok_or(CommandError::code("exchange_expired"))?;
    match pending.submit(code.trim()).await {
        Ok(done) => signed_in(&app, &mut session, done).await,
        Err(error) => {
            let error = CommandError::from(error);
            // A wrong code can be corrected; anything else ends the attempt.
            if error.is("totp_invalid") {
                session.pending_totp = Some(pending);
            }
            Err(error)
        }
    }
}

/// Signs out. The device stays enrolled.
#[tauri::command]
async fn logout(shell: State<'_, Shell>) -> Result<()> {
    let mut session = shell.session.lock().await;
    session.gateway = None;
    session.pending_totp = None;
    if let Some(client) = session.client.take() {
        client.logout().await?;
    }
    Ok(())
}

/// Signs out and erases this device: it is revoked on the instance and its
/// keys are deleted from this computer. The next sign-in enrols a new device,
/// without history.
///
/// Returns the accounts still known on this computer. The window cannot work
/// them out itself: the instance's revocation notice reaches it through the
/// gateway, often before this answer, and signs it out first.
#[tauri::command]
async fn erase_device(shell: State<'_, Shell>) -> Result<Vec<String>> {
    let mut session = shell.session.lock().await;
    let client = session
        .client
        .clone()
        .ok_or(CommandError::code("not_signed_in"))?;
    // Revoke first: if the instance cannot be reached, nothing is erased and
    // the user is still signed in, so the action can be retried.
    client.erase_device().await?;
    session.gateway = None;
    session.pending_totp = None;
    session.client = None;
    match session.instance.as_ref() {
        Some(instance) => known_handles(instance),
        None => Ok(Vec::new()),
    }
}

/// Forgets the local session after the instance ended it.
#[tauri::command]
async fn session_ended(shell: State<'_, Shell>) -> Result<()> {
    let mut session = shell.session.lock().await;
    session.gateway = None;
    if let Some(client) = session.client.take() {
        client.forget_session()?;
    }
    Ok(())
}

// --- Account ------------------------------------------------------------------------

#[tauri::command]
async fn account(shell: State<'_, Shell>) -> Result<AccountView> {
    let session = shell.session.lock().await;
    account_view(client(&session)?).await
}

#[tauri::command]
async fn devices(shell: State<'_, Shell>) -> Result<Vec<DeviceView>> {
    let session = shell.session.lock().await;
    let list = client(&session)?.devices().await?;
    Ok(list.devices.into_iter().map(DeviceView::from).collect())
}

#[tauri::command]
async fn revoke_device(shell: State<'_, Shell>, device_id: Uuid) -> Result<()> {
    let session = shell.session.lock().await;
    Ok(client(&session)?.revoke_device(device_id).await?)
}

/// The user has seen the devices announced by the gateway.
#[tauri::command]
async fn ack_new_devices(shell: State<'_, Shell>) -> Result<()> {
    let session = shell.session.lock().await;
    match &session.gateway {
        Some(gateway) => Ok(gateway.ack_device_list().await?),
        None => Ok(()),
    }
}

/// The user dismissed these security notices on this device.
#[tauri::command]
async fn ack_security_notices(shell: State<'_, Shell>, notice_ids: Vec<Uuid>) -> Result<()> {
    let session = shell.session.lock().await;
    match &session.gateway {
        Some(gateway) => Ok(gateway.ack_security_notices(&notice_ids).await?),
        None => Err(CommandError::code("not_signed_in")),
    }
}

/// What the user needs to add the account to an authenticator app.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TotpEnrolmentView {
    /// The secret, for manual entry.
    secret: String,
    /// The same information as a link.
    otpauth_url: String,
    /// The link as a QR code, computed on this device.
    qr: QrMatrix,
}

#[tauri::command]
async fn totp_enable(shell: State<'_, Shell>) -> Result<TotpEnrolmentView> {
    let session = shell.session.lock().await;
    let enrolment = client(&session)?.totp_enable().await?;
    let qr = qr::encode(&enrolment.otpauth_url)?;
    Ok(TotpEnrolmentView {
        secret: enrolment.secret,
        otpauth_url: enrolment.otpauth_url,
        qr,
    })
}

#[tauri::command]
async fn totp_confirm(shell: State<'_, Shell>, code: String) -> Result<Vec<String>> {
    let session = shell.session.lock().await;
    Ok(client(&session)?
        .totp_confirm(code.trim())
        .await?
        .recovery_codes)
}

#[tauri::command]
async fn totp_disable(shell: State<'_, Shell>, code: String) -> Result<()> {
    let session = shell.session.lock().await;
    Ok(client(&session)?.totp_disable(code.trim()).await?)
}

// --- Credential changes -----------------------------------------------------------------

/// Sets a new password with the recovery key, for a user who forgot theirs.
#[tauri::command]
async fn recover(
    shell: State<'_, Shell>,
    handle: String,
    recovery_key: String,
    new_password: String,
) -> Result<()> {
    let session = shell.session.lock().await;
    Ok(instance(&session)?
        .recover(handle.trim(), &recovery_key, &new_password)
        .await?)
}

/// Changes the password. The current one is checked again first; every other
/// device of the account is signed out.
#[tauri::command]
async fn change_password(
    shell: State<'_, Shell>,
    current_password: String,
    totp_code: Option<String>,
    new_password: String,
) -> Result<()> {
    let session = shell.session.lock().await;
    let client = client(&session)?;
    // Refuse a weak password before asking the instance for anything.
    let me = client.me().await?;
    if let Err(issue) = password::check(&new_password, &[&me.handle, &me.display_name]) {
        return Err(ClientError::WeakPassword(issue).into());
    }
    let code = totp_code
        .as_deref()
        .map(str::trim)
        .filter(|code| !code.is_empty());
    let reauth = client.reauthenticate(&current_password, code).await?;
    Ok(client.change_password(reauth, &new_password).await?)
}

/// Replaces the recovery key and returns the new one, to be shown once.
/// The previous key stops working.
#[tauri::command]
async fn rotate_recovery_key(
    shell: State<'_, Shell>,
    current_password: String,
    totp_code: Option<String>,
) -> Result<String> {
    let session = shell.session.lock().await;
    let client = client(&session)?;
    let code = totp_code
        .as_deref()
        .map(str::trim)
        .filter(|code| !code.is_empty());
    let reauth = client.reauthenticate(&current_password, code).await?;
    Ok(client
        .rotate_recovery_key(reauth)
        .await?
        .display()
        .to_string())
}

// --- Administration -------------------------------------------------------------------

#[tauri::command]
async fn admin_create_invite(
    shell: State<'_, Shell>,
    max_uses: Option<u32>,
    expires_in_hours: Option<u32>,
) -> Result<CreatedInvite> {
    let session = shell.session.lock().await;
    Ok(client(&session)?
        .create_invite(max_uses, expires_in_hours)
        .await?)
}

#[tauri::command]
async fn admin_invites(shell: State<'_, Shell>) -> Result<Vec<InviteInfo>> {
    let session = shell.session.lock().await;
    Ok(client(&session)?.invites().await?.invites)
}

#[tauri::command]
async fn admin_revoke_invite(shell: State<'_, Shell>, invite_id: Uuid) -> Result<()> {
    let session = shell.session.lock().await;
    Ok(client(&session)?.revoke_invite(invite_id).await?)
}

#[tauri::command]
async fn admin_users(shell: State<'_, Shell>) -> Result<Vec<AdminUser>> {
    let session = shell.session.lock().await;
    Ok(client(&session)?.users().await?.users)
}

#[tauri::command]
async fn admin_set_user_disabled(
    shell: State<'_, Shell>,
    user_id: Uuid,
    disabled: bool,
) -> Result<()> {
    let session = shell.session.lock().await;
    Ok(client(&session)?
        .set_user_disabled(user_id, disabled)
        .await?)
}

#[tauri::command]
async fn admin_disable_user_totp(shell: State<'_, Shell>, user_id: Uuid) -> Result<()> {
    let session = shell.session.lock().await;
    Ok(client(&session)?.disable_user_totp(user_id).await?)
}

/// Starts the desktop application and blocks until it exits.
pub fn run() -> std::result::Result<(), tauri::Error> {
    tauri::Builder::default()
        .setup(|app| {
            let identifier = app.config().identifier.clone();
            let profile = std::env::var("TAVERN_PROFILE")
                .ok()
                .filter(|p| !p.trim().is_empty());
            // Several clients on one computer: say which window is which.
            if let (Some(profile), Some(window)) = (&profile, app.get_webview_window("main")) {
                window.set_title(&format!("Tavern ({profile})"))?;
            }
            // Local, not roaming, on Windows: the store is useless on any other
            // computer, its key being this device's.
            let local_data = app.path().app_local_data_dir()?;
            let profile_lock = ProfileLock::acquire(&local_data, profile.as_deref());
            app.manage(Shell {
                store: Arc::new(KeychainStore::new(&identifier)),
                local_data,
                profile_lock,
                profile,
                session: Mutex::new(Session::default()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            probe_instance,
            assess_password,
            register,
            login,
            submit_totp,
            logout,
            erase_device,
            session_ended,
            account,
            devices,
            revoke_device,
            ack_new_devices,
            ack_security_notices,
            totp_enable,
            totp_confirm,
            totp_disable,
            recover,
            change_password,
            rotate_recovery_key,
            admin_create_invite,
            admin_invites,
            admin_revoke_invite,
            admin_users,
            admin_set_user_disabled,
            admin_disable_user_totp,
        ])
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_events_are_tagged_for_the_webview() {
        let id = Uuid::from_u128(7);
        let json =
            |event: GatewayEvent| serde_json::to_string(&GatewayView::of(event).unwrap()).unwrap();
        assert!(
            GatewayView::of(GatewayEvent::UserDevicesChanged {
                user_id: id,
                device_id: id,
                added: true,
            })
            .is_none()
        );

        assert_eq!(
            json(GatewayEvent::DeviceAdded(id)),
            format!(r#"{{"type":"device_added","deviceId":"{id}"}}"#)
        );
        assert_eq!(
            json(GatewayEvent::SessionEnded(SessionEnd::Revoked)),
            r#"{"type":"session_ended","reason":"revoked"}"#
        );
        assert_eq!(
            json(GatewayEvent::Disconnected),
            r#"{"type":"disconnected"}"#
        );
        assert_eq!(
            json(GatewayEvent::Connected {
                new_devices: Vec::new(),
                security_notices: Vec::new(),
                instance_generation: 3,
                key_packages_remaining: 20,
                server_time_ms: 1,
            }),
            r#"{"type":"connected","newDevices":[],"securityNotices":[]}"#
        );
        assert_eq!(
            json(GatewayEvent::SecurityNotice(SecurityNotice {
                notice_id: id,
                kind: SecurityNoticeKind::RecoveryKeyReplaced,
                created_at_ms: 5,
                backup_taken_at_ms: None,
            })),
            format!(
                r#"{{"type":"security_notice","notice":{{"noticeId":"{id}","kind":"recovery_key_replaced","createdAtMs":5}}}}"#
            )
        );
        assert_eq!(
            json(GatewayEvent::SecurityNotice(SecurityNotice {
                notice_id: id,
                kind: SecurityNoticeKind::InstanceRestored,
                created_at_ms: 5,
                backup_taken_at_ms: Some(2),
            })),
            format!(
                r#"{{"type":"security_notice","notice":{{"noticeId":"{id}","kind":"instance_restored","createdAtMs":5,"backupTakenAtMs":2}}}}"#
            )
        );
    }

    #[test]
    fn login_views_are_tagged_by_status() {
        assert_eq!(
            serde_json::to_string(&LoginView::TotpRequired).unwrap(),
            r#"{"status":"totp_required"}"#
        );
        let id = Uuid::from_u128(1);
        let signed_in = serde_json::to_value(LoginView::SignedIn {
            account: AccountView {
                user_id: id,
                device_id: id,
                handle: "ann".into(),
                display_name: "Ann".into(),
                is_admin: false,
                totp_enabled: false,
            },
            new_device: false,
            store_reset: true,
        })
        .unwrap();
        assert_eq!(signed_in["status"], "signed_in");
        assert_eq!(signed_in["newDevice"], false);
        assert_eq!(signed_in["storeReset"], true);
    }

    #[test]
    fn the_strength_meter_runs_locally() {
        let weak = assess_password("password".into(), "alice".into(), "Alice".into());
        let strong = assess_password(
            "tournesol-vexant-42-brume".into(),
            "alice".into(),
            "Alice".into(),
        );

        assert!(!weak.is_acceptable());
        assert!(strong.is_acceptable());
    }
}
