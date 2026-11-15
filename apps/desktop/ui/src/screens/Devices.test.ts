// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { fireEvent, render, screen, within } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Device } from "../lib/api";
import { setLocale } from "../lib/i18n";
import { session } from "../lib/session.svelte";
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
