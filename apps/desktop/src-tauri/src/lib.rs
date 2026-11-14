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

use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tavern_client_core::password::{self, PasswordStrength};
use tavern_client_core::{
    Client, Gateway, GatewayEvent, InstanceClient, InstanceUrl, KeychainStore, LoginStep,
    NewAccount, PendingTotp, SecretStore, SessionEnd, SignedIn, fetch_health,
};
use tavern_protocol::rest::{
    AdminUser, CreatedInvite, DeviceInfo, HealthResponse, InviteInfo, Platform, TotpEnrolment,
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
    /// Separates several accounts on one computer (`TAVERN_PROFILE`), for
    /// development: two clients can then run side by side.
    profile: Option<String>,
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
    /// The handle last used on this computer for this instance.
    remembered_handle: Option<String>,
    /// The account, when a saved session is still valid.
    account: Option<AccountView>,
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

/// A gateway notification, as sent to the webview.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GatewayView {
    #[serde(rename_all = "camelCase")]
    Connected {
        new_devices: Vec<Uuid>,
    },
    #[serde(rename_all = "camelCase")]
    DeviceAdded {
        device_id: Uuid,
    },
    #[serde(rename_all = "camelCase")]
    DeviceRemoved {
        device_id: Uuid,
    },
    TotpDisabledByAdmin,
    Disconnected,
    SessionEnded {
        reason: &'static str,
    },
}

impl From<GatewayEvent> for GatewayView {
    fn from(event: GatewayEvent) -> Self {
        match event {
            GatewayEvent::Connected { new_devices } => Self::Connected {
                new_devices: new_devices
                    .into_iter()
                    .map(|device| device.device_id)
                    .collect(),
            },
            GatewayEvent::DeviceAdded(device_id) => Self::DeviceAdded { device_id },
            GatewayEvent::DeviceRemoved(device_id) => Self::DeviceRemoved { device_id },
            GatewayEvent::TotpDisabledByAdmin => Self::TotpDisabledByAdmin,
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
        }
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
            let _ = app.emit(GATEWAY_EVENT, GatewayView::from(event));
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
    let instance_url = InstanceUrl::parse(&url)?;
    let health = fetch_health(&instance_url).await?;
    let instance =
        InstanceClient::new(instance_url, shell.store.clone(), shell.profile.as_deref())?;

    let mut session = shell.session.lock().await;
    *session = Session::default();
    let remembered_handle = instance.remembered_handle()?;
    let account = match instance.resume().await? {
        Some(resumed) => {
            let view = account_view(&resumed).await?;
            attach(&app, &mut session, resumed)?;
            Some(view)
        }
        None => None,
    };
    let url = instance.instance().as_str().to_owned();
    session.instance = Some(instance);
    Ok(InstanceProbe {
        url,
        health,
        remembered_handle,
        account,
    })
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

#[tauri::command]
async fn totp_enable(shell: State<'_, Shell>) -> Result<TotpEnrolment> {
    let session = shell.session.lock().await;
    Ok(client(&session)?.totp_enable().await?)
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
            app.manage(Shell {
                store: Arc::new(KeychainStore::new(&identifier)),
                profile: std::env::var("TAVERN_PROFILE")
                    .ok()
                    .filter(|p| !p.trim().is_empty()),
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
            session_ended,
            account,
            devices,
            revoke_device,
            ack_new_devices,
            totp_enable,
            totp_confirm,
            totp_disable,
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
        let json = |event: GatewayEvent| serde_json::to_string(&GatewayView::from(event)).unwrap();

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
                new_devices: Vec::new()
            }),
            r#"{"type":"connected","newDevices":[]}"#
        );
    }

    #[test]
    fn login_views_are_tagged_by_status() {
        assert_eq!(
            serde_json::to_string(&LoginView::TotpRequired).unwrap(),
            r#"{"status":"totp_required"}"#
        );
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
