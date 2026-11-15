// SPDX-License-Identifier: AGPL-3.0-or-later

// Interface state. It holds only what is displayed: no key, no token.
// A password is kept here for the few seconds between "create my account"
// and the first sign-in that follows the recovery key screen, then erased.

import {
  api,
  toCommandError,
  type Account,
  type GatewayEvent,
  type LoginResult,
  type SecurityNotice,
} from "./api";
import type { MessageKey } from "./i18n";

export type Screen = "instance" | "auth" | "recovery" | "totp" | "home";

interface PendingRegistration {
  handle: string;
  password: string;
  recoveryKey: string;
  isAdmin: boolean;
}

export const session = $state({
  screen: "instance" as Screen,
  instanceUrl: "",
  rememberedHandle: null as string | null,
  /** The instance is older than this client. */
  serverOutdated: false,
  account: null as Account | null,
  /** Set between registration and the first sign-in. */
  registration: null as PendingRegistration | null,
  /** This sign-in enrolled the device: explain the missing history. */
  showHistoryNotice: false,
  /** Devices added to the account that the user has not acknowledged. */
  newDevices: [] as string[],
  /** The real-time connection is down. */
  offline: false,
  /** Security notices of the account that this device has not acknowledged. */
  securityNotices: [] as SecurityNotice[],
  /** Why the user is back on the sign-in screen, if the instance ended the session. */
  endedMessage: null as MessageKey | null,
});

/** Applies the result of `login` or `submit_totp`. */
export function applyLogin(result: LoginResult): void {
  if (result.status === "totp_required") {
    session.screen = "totp";
    return;
  }
  session.account = result.account;
  session.showHistoryNotice = result.newDevice;
  session.registration = null;
  session.endedMessage = null;
  session.newDevices = [];
  session.securityNotices = [];
  session.offline = false;
  session.screen = "home";
}

/** Returns to the sign-in screen, forgetting everything about the account. */
export function signedOut(reason: MessageKey | null): void {
  if (session.account !== null) {
    session.rememberedHandle = session.account.handle;
  }
  session.account = null;
  session.registration = null;
  session.newDevices = [];
  session.showHistoryNotice = false;
  session.securityNotices = [];
  session.offline = false;
  session.endedMessage = reason;
  session.screen = session.instanceUrl === "" ? "instance" : "auth";
}

function addNewDevices(ids: readonly string[]): void {
  const own = session.account?.deviceId;
  for (const id of ids) {
    if (id !== own && !session.newDevices.includes(id)) {
      session.newDevices.push(id);
    }
  }
}

/** Reacts to a notification from the gateway. */
export function handleGatewayEvent(event: GatewayEvent): void {
  switch (event.type) {
    case "connected":
      session.offline = false;
      addNewDevices(event.newDevices);
      // The instance lists everything this device has not acknowledged.
      session.securityNotices = event.securityNotices;
      break;
    case "device_added":
      addNewDevices([event.deviceId]);
      break;
    case "device_removed":
      session.newDevices = session.newDevices.filter((id) => id !== event.deviceId);
      break;
    case "security_notice":
      if (!session.securityNotices.some((known) => known.noticeId === event.notice.noticeId)) {
        session.securityNotices.push(event.notice);
      }
      if (event.notice.kind === "totp_disabled_by_admin" && session.account !== null) {
        session.account.totpEnabled = false;
      }
      break;
    case "disconnected":
      session.offline = true;
      break;
    case "session_ended":
      void api.sessionEnded().catch(() => undefined);
      signedOut(`ended.${event.reason}`);
      break;
  }
}

/**
 * Runs a command of the signed-in area. A session that ended on the instance
 * sends the user back to the sign-in screen; other errors are returned.
 */
export async function guarded<T>(
  action: () => Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false; error: ReturnType<typeof toCommandError> }> {
  try {
    return { ok: true, value: await action() };
  } catch (thrown: unknown) {
    const error = toCommandError(thrown);
    if (error.code === "session_ended" || error.code === "not_signed_in") {
      void api.sessionEnded().catch(() => undefined);
      signedOut("ended.invalid");
    }
    return { ok: false, error };
  }
}
