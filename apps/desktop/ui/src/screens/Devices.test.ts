// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { fireEvent, render, screen, within } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Device } from "../lib/api";
import { setLocale } from "../lib/i18n";
import { handleGatewayEvent, session } from "../lib/session.svelte";
import { callsTo, onCommand, resetCommands } from "../test/tauri";
import Devices from "./Devices.svelte";

vi.mock("@tauri-apps/api/core", async () => ({ invoke: (await import("../test/tauri")).invoke }));

const here: Device = {
  deviceId: "00000000-0000-7000-8000-0000000000d1",
  platform: "macos",
  createdAtMs: 0,
  lastSeenAtMs: null,
  current: true,
};
const other: Device = { ...here, deviceId: "00000000-0000-7000-8000-0000000000d2", current: false };

beforeEach(() => {
  resetCommands();
  setLocale("en");
  session.screen = "home";
  session.instanceUrl = "http://localhost:8080";
  session.account = {
    userId: "00000000-0000-7000-8000-000000000001",
    deviceId: here.deviceId,
    handle: "ann",
    displayName: "Ann",
    isAdmin: false,
    totpEnabled: false,
  };
  session.knownHandles = ["ann", "bob"];
  session.rememberedHandle = "ann";
  session.endedMessage = null;
  session.newDevices = [other.deviceId];
  onCommand("devices", () => [here, other]);
});

async function askToRevoke(): Promise<HTMLElement> {
  render(Devices);
  await fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
  return screen.getByRole("alertdialog");
}

describe("revoking a device", () => {
  it("asks first, then calls the instance and confirms", async () => {
    onCommand("revoke_device", () => undefined);
    const dialog = await askToRevoke();
    expect(callsTo("revoke_device")).toEqual([]);

    await fireEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));

    expect(callsTo("revoke_device")).toEqual([{ deviceId: other.deviceId }]);
    expect((await screen.findByRole("status")).textContent).toContain("Device revoked.");
    expect(session.newDevices).toEqual([]);
  });

  it("does nothing when cancelled", async () => {
    const dialog = await askToRevoke();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(callsTo("revoke_device")).toEqual([]);
  });

  it("keeps the error on screen after the list is refreshed", async () => {
    onCommand("revoke_device", () => {
      throw { code: "not_found" };
    });
    const dialog = await askToRevoke();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));

    await vi.waitFor(() => {
      expect(screen.getByRole("alert").textContent?.trim()).not.toBe("");
    });
    expect(session.newDevices).toEqual([other.deviceId]);
  });
});

describe("erasing this device", () => {
  async function askToErase(): Promise<HTMLElement> {
    render(Devices);
    await fireEvent.click(
      await screen.findByRole("button", { name: "Sign out and erase this device" }),
    );
    return screen.getByRole("alertdialog");
  }

  it("is offered on this device only, and asks first", async () => {
    const dialog = await askToErase();

    expect(screen.getAllByRole("button", { name: "Sign out and erase this device" })).toHaveLength(1);
    expect(dialog.textContent).toContain("cannot be undone");
    expect(callsTo("erase_device")).toEqual([]);
    await fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(callsTo("erase_device")).toEqual([]);
  });

  it("signs out and forgets the account on this computer", async () => {
    onCommand("erase_device", () => ["bob"]);
    const dialog = await askToErase();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Erase this device" }));

    await vi.waitFor(() => {
      expect(session.screen).toBe("auth");
    });
    expect(callsTo("erase_device")).toHaveLength(1);
    expect(session.endedMessage).toEqual({ key: "ended.erased", params: { handle: "ann" } });
    expect(session.account).toBeNull();
    expect(session.knownHandles).toEqual(["bob"]);
    expect(session.rememberedHandle).toBeNull();
  });

  it("forgets the account even when the revocation notice arrives first", async () => {
    // The instance tells the device it is revoked before it answers the
    // request that revoked it: the window is signed out by then.
    onCommand("session_ended", () => undefined);
    onCommand("erase_device", () => {
      handleGatewayEvent({ type: "session_ended", reason: "revoked" });
      return ["bob"];
    });
    const dialog = await askToErase();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Erase this device" }));

    await vi.waitFor(() => {
      expect(session.endedMessage?.key).toBe("ended.erased");
    });
    expect(session.endedMessage?.params).toEqual({ handle: "ann" });
    expect(session.screen).toBe("auth");
    expect(session.knownHandles).toEqual(["bob"]);
    expect(session.rememberedHandle).toBeNull();
  });

  it("keeps the user signed in, with the error, when the instance refuses", async () => {
    onCommand("erase_device", () => {
      throw { code: "unreachable" };
    });
    const dialog = await askToErase();
    await fireEvent.click(within(dialog).getByRole("button", { name: "Erase this device" }));

    expect(await screen.findByText(/The instance cannot be reached/)).toBeTruthy();
    expect(session.screen).toBe("home");
    expect(session.knownHandles).toEqual(["ann", "bob"]);
  });
});
