// SPDX-License-Identifier: AGPL-3.0-or-later

// Typed wrappers around the Tauri commands exposed by `src-tauri`.
//
// The interface never handles keys, tokens or ciphertext: it sends what the
// user typed and receives what must be displayed. Passwords are passed to the
// Rust core and are not kept in any store here.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type ComponentStatus = "ok" | "unavailable";
export type Platform = "windows" | "macos" | "linux";

export interface Account {
  userId: string;
  deviceId: string;
  handle: string;
  displayName: string;
  isAdmin: boolean;
  totpEnabled: boolean;
}

export interface InstanceProbe {
  url: string;
  health: { status: ComponentStatus; database: ComponentStatus };
  serverVersion: string;
  /** The instance is older than this client: some features will not work. */
  serverOutdated: boolean;
  rememberedHandle: string | null;
  /** Accounts that have a device on this computer for this instance. */
  knownHandles: string[];
  account: Account | null;
}

export type PasswordIssue = "too_short" | "too_long" | "too_guessable";

export interface PasswordStrength {
  score: number;
  length: number;
  issue: PasswordIssue | null;
}

export interface Registered {
  handle: string;
  isAdmin: boolean;
  recoveryKey: string;
}

export type LoginResult =
  | { status: "totp_required" }
  | { status: "signed_in"; account: Account; newDevice: boolean; storeReset: boolean };

export interface Device {
  deviceId: string;
  platform: Platform;
  createdAtMs: number;
  lastSeenAtMs: number | null;
  current: boolean;
}

/** A QR code as rows of "0" (light) and "1" (dark) modules. */
export interface QrMatrix {
  size: number;
  rows: string[];
}

export interface TotpEnrolment {
  secret: string;
  otpauthUrl: string;
  qr: QrMatrix;
}

export interface Invite {
  invite_id: string;
  max_uses: number;
  uses: number;
  grants_admin: boolean;
  revoked: boolean;
  created_at_ms: number;
  expires_at_ms: number | null;
}

export interface CreatedInvite {
  code: string;
  invite: Invite;
}

export interface AdminUser {
  user_id: string;
  handle: string;
  display_name: string;
  is_admin: boolean;
  disabled: boolean;
  totp_enabled: boolean;
  device_count: number;
  created_at_ms: number;
}

export type SessionEndReason =
  | "revoked"
  | "credentials_changed"
  | "account_disabled"
  | "invalid"
  | "replaced";

/** `other` is a kind introduced by an instance newer than this client. */
export type SecurityNoticeKind =
  | "totp_disabled_by_admin"
  | "password_changed"
  | "account_recovered"
  | "device_revoked"
  | "recovery_key_replaced"
  | "other";

/** Something security-relevant that happened to the account. */
export interface SecurityNotice {
  noticeId: string;
  kind: SecurityNoticeKind;
  createdAtMs: number;
}

export type GatewayEvent =
  | { type: "connected"; newDevices: string[]; securityNotices: SecurityNotice[] }
  | { type: "device_added"; deviceId: string }
  | { type: "device_removed"; deviceId: string }
  | { type: "security_notice"; notice: SecurityNotice }
  | { type: "disconnected" }
  | { type: "session_ended"; reason: SessionEndReason };

/** Failure of a command: a code the interface maps to a localised message. */
export interface CommandError {
  code: string;
  detail?: string;
  retryAfterMs?: number;
}

export function isCommandError(value: unknown): value is CommandError {
  return (
    typeof value === "object" &&
    value !== null &&
    "code" in value &&
    typeof (value as { code: unknown }).code === "string"
  );
}

/** Normalises whatever a command threw into a `CommandError`. */
export function toCommandError(value: unknown): CommandError {
  return isCommandError(value) ? value : { code: "internal" };
}

const GATEWAY_EVENT = "tavern://gateway";

export function onGatewayEvent(handler: (event: GatewayEvent) => void): Promise<UnlistenFn> {
  return listen<GatewayEvent>(GATEWAY_EVENT, (event) => handler(event.payload));
}

export const api = {
  probeInstance: (url: string) => invoke<InstanceProbe>("probe_instance", { url }),
  assessPassword: (password: string, handle: string, displayName: string) =>
    invoke<PasswordStrength>("assess_password", { password, handle, displayName }),
  register: (inviteCode: string, handle: string, displayName: string, password: string) =>
    invoke<Registered>("register", { inviteCode, handle, displayName, password }),
  login: (handle: string, password: string) => invoke<LoginResult>("login", { handle, password }),
  submitTotp: (code: string) => invoke<LoginResult>("submit_totp", { code }),
  logout: () => invoke<void>("logout"),
  eraseDevice: () => invoke<void>("erase_device"),
  sessionEnded: () => invoke<void>("session_ended"),
  account: () => invoke<Account>("account"),
  devices: () => invoke<Device[]>("devices"),
  revokeDevice: (deviceId: string) => invoke<void>("revoke_device", { deviceId }),
  ackNewDevices: () => invoke<void>("ack_new_devices"),
  ackSecurityNotices: (noticeIds: string[]) =>
    invoke<void>("ack_security_notices", { noticeIds }),
  totpEnable: () => invoke<TotpEnrolment>("totp_enable"),
  totpConfirm: (code: string) => invoke<string[]>("totp_confirm", { code }),
  totpDisable: (code: string) => invoke<void>("totp_disable", { code }),
  recover: (handle: string, recoveryKey: string, newPassword: string) =>
    invoke<void>("recover", { handle, recoveryKey, newPassword }),
  changePassword: (currentPassword: string, totpCode: string | null, newPassword: string) =>
    invoke<void>("change_password", { currentPassword, totpCode, newPassword }),
  rotateRecoveryKey: (currentPassword: string, totpCode: string | null) =>
    invoke<string>("rotate_recovery_key", { currentPassword, totpCode }),
  adminCreateInvite: (maxUses: number | null, expiresInHours: number | null) =>
    invoke<CreatedInvite>("admin_create_invite", { maxUses, expiresInHours }),
  adminInvites: () => invoke<Invite[]>("admin_invites"),
  adminRevokeInvite: (inviteId: string) => invoke<void>("admin_revoke_invite", { inviteId }),
  adminUsers: () => invoke<AdminUser[]>("admin_users"),
  adminSetUserDisabled: (userId: string, disabled: boolean) =>
    invoke<void>("admin_set_user_disabled", { userId, disabled }),
  adminDisableUserTotp: (userId: string) => invoke<void>("admin_disable_user_totp", { userId }),
};
