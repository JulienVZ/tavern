// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { fireEvent, render, screen, within } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AdminUser } from "../lib/api";
import { setLocale } from "../lib/i18n";
import { session } from "../lib/session.svelte";
import { callsTo, onCommand, resetCommands } from "../test/tauri";
import Admin from "./Admin.svelte";

vi.mock("@tauri-apps/api/core", async () => ({ invoke: (await import("../test/tauri")).invoke }));

const uma: AdminUser = {
  user_id: "00000000-0000-7000-8000-000000000002",
  handle: "uma",
  display_name: "Uma",
  is_admin: false,
  disabled: false,
  totp_enabled: true,
  device_count: 1,
  created_at_ms: 0,
};

beforeEach(() => {
  resetCommands();
  setLocale("en");
  session.account = {
    userId: "00000000-0000-7000-8000-000000000001",
    deviceId: "00000000-0000-7000-8000-0000000000d1",
    handle: "boss",
    displayName: "Boss",
    isAdmin: true,
    totpEnabled: false,
  };
  onCommand("admin_invites", () => []);
  onCommand("admin_users", () => [uma]);
});

async function askToDisableTotp(): Promise<HTMLElement> {
  render(Admin);
  await fireEvent.click(await screen.findByRole("button", { name: "Disable 2FA" }));
  return screen.getByRole("alertdialog");
}

describe("disabling a user's two-factor authentication", () => {
  it("asks first, then calls the instance and confirms", async () => {
    onCommand("admin_disable_user_totp", () => undefined);
    const dialog = await askToDisableTotp();

    // Nothing is sent before the administrator confirms, and Enter would cancel.
    expect(callsTo("admin_disable_user_totp")).toEqual([]);
    expect(dialog.textContent).toContain("@uma");
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: "Cancel" }));

    await fireEvent.click(within(dialog).getByRole("button", { name: "Disable 2FA" }));

    expect(callsTo("admin_disable_user_totp")).toEqual([{ userId: uma.user_id }]);
    expect((await screen.findByRole("status")).textContent).toContain(
      "Two-factor authentication is disabled for @uma",
    );
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("does nothing when cancelled, with the button or with Escape", async () => {
    let dialog = await askToDisableTotp();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();

    await fireEvent.click(screen.getByRole("button", { name: "Disable 2FA" }));
    dialog = screen.getByRole("alertdialog");
    await fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("alertdialog")).toBeNull();

    expect(callsTo("admin_disable_user_totp")).toEqual([]);
  });

  it("keeps the error on screen after the lists are refreshed", async () => {
    onCommand("admin_disable_user_totp", () => {
      throw { code: "forbidden" };
    });
    const dialog = await askToDisableTotp();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Disable 2FA" }));

    const alert = await screen.findByText("You are not allowed to do this.");
    // The refresh that follows the action ran, and did not erase the error.
    expect(callsTo("admin_users")).toHaveLength(2);
    expect(alert.closest('[role="alert"]')).not.toBeNull();
    expect(screen.getByRole("status").textContent?.trim()).toBe("");
  });
});

describe("the other administration actions", () => {
  it("confirm that an account was disabled", async () => {
    onCommand("admin_set_user_disabled", () => undefined);
    render(Admin);
    await fireEvent.click(await screen.findByRole("button", { name: "Disable" }));

    expect(callsTo("admin_set_user_disabled")).toEqual([{ userId: uma.user_id, disabled: true }]);
    expect((await screen.findByRole("status")).textContent).toContain("@uma is disabled");
  });

  it("show the error when disabling an account fails", async () => {
    onCommand("admin_set_user_disabled", () => {
      throw { code: "unreachable" };
    });
    render(Admin);
    await fireEvent.click(await screen.findByRole("button", { name: "Disable" }));

    await vi.waitFor(() => {
      expect(screen.getByRole("alert").textContent?.trim()).not.toBe("");
    });
  });

  it("confirm that an invitation was revoked", async () => {
    onCommand("admin_invites", () => [
      {
        invite_id: "00000000-0000-7000-8000-0000000000a1",
        max_uses: 1,
        uses: 0,
        grants_admin: false,
        revoked: false,
        created_at_ms: 0,
        expires_at_ms: null,
      },
    ]);
    onCommand("admin_revoke_invite", () => undefined);
    render(Admin);
    await fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));

    expect(callsTo("admin_revoke_invite")).toEqual([
      { inviteId: "00000000-0000-7000-8000-0000000000a1" },
    ]);
    expect((await screen.findByRole("status")).textContent).toContain("Invitation revoked.");
  });
});
