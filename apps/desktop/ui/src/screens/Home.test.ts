// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { SecurityNotice } from "../lib/api";
import { setLocale } from "../lib/i18n";
import { handleGatewayEvent, session } from "../lib/session.svelte";
import { callsTo, onCommand, resetCommands } from "../test/tauri";
import Home from "./Home.svelte";

vi.mock("@tauri-apps/api/core", async () => ({ invoke: (await import("../test/tauri")).invoke }));

const notice: SecurityNotice = {
  noticeId: "00000000-0000-7000-8000-0000000000f1",
  kind: "totp_disabled_by_admin",
  createdAtMs: 1_800_000_000_000,
};

beforeEach(() => {
  resetCommands();
  setLocale("en");
  session.screen = "home";
  session.instanceUrl = "http://localhost:8080";
  session.account = {
    userId: "00000000-0000-7000-8000-000000000002",
    deviceId: "00000000-0000-7000-8000-0000000000d1",
    handle: "uma",
    displayName: "Uma",
    isAdmin: false,
    totpEnabled: true,
  };
  session.newDevices = [];
  session.securityNotices = [];
  session.showStoreResetNotice = false;
  session.endedMessage = null;
  onCommand("devices", () => []);
  onCommand("session_ended", () => undefined);
});

describe("security notices", () => {
  it("are shown when pushed, and update what the notice changed", () => {
    render(Home);
    handleGatewayEvent({ type: "security_notice", notice });
    handleGatewayEvent({ type: "security_notice", notice });

    expect(session.securityNotices).toEqual([notice]);
    expect(session.account?.totpEnabled).toBe(false);
  });

  it("are replayed on connection and stay until acknowledged", async () => {
    onCommand("ack_security_notices", () => undefined);
    render(Home);
    handleGatewayEvent({ type: "connected", newDevices: [], securityNotices: [notice] });

    expect(await screen.findByText(/An administrator disabled two-factor/)).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: "OK, noted" }));

    expect(callsTo("ack_security_notices")).toEqual([{ noticeIds: [notice.noticeId] }]);
    await vi.waitFor(() => {
      expect(screen.queryByText(/An administrator disabled two-factor/)).toBeNull();
    });
  });

  it("stay on screen, with an error, when the acknowledgement fails", async () => {
    onCommand("ack_security_notices", () => {
      throw { code: "unreachable" };
    });
    render(Home);
    handleGatewayEvent({ type: "connected", newDevices: [], securityNotices: [notice] });
    await fireEvent.click(await screen.findByRole("button", { name: "OK, noted" }));

    expect(await screen.findByText(/The instance cannot be reached/)).toBeTruthy();
    expect(session.securityNotices).toEqual([notice]);
  });

  it("have a message for every kind", () => {
    const kinds: SecurityNotice["kind"][] = [
      "totp_disabled_by_admin",
      "password_changed",
      "account_recovered",
      "device_revoked",
      "recovery_key_replaced",
      "other",
    ];
    render(Home);
    handleGatewayEvent({
      type: "connected",
      newDevices: [],
      securityNotices: kinds.map((kind, index) => ({ ...notice, kind, noticeId: `n${index}` })),
    });
    expect(session.securityNotices).toHaveLength(kinds.length);
  });
});

describe("acknowledging new devices", () => {
  it("keeps the warning, with an error, when the instance was not told", async () => {
    onCommand("ack_new_devices", () => {
      throw { code: "unreachable" };
    });
    session.newDevices = ["00000000-0000-7000-8000-0000000000d2"];
    render(Home);
    await fireEvent.click(screen.getByRole("button", { name: "It was me" }));

    expect(await screen.findByText(/The instance cannot be reached/)).toBeTruthy();
    expect(session.newDevices).toHaveLength(1);
  });
});

describe("signing out", () => {
  it("says so when the instance could not be told", async () => {
    onCommand("logout", () => {
      throw { code: "unreachable" };
    });
    render(Home);
    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));

    await vi.waitFor(() => {
      expect(session.screen).toBe("auth");
    });
    expect(session.endedMessage).toBe("ended.logout_unconfirmed");
  });
});

describe("a local store that could not be opened", () => {
  it("is explained until dismissed", async () => {
    session.showStoreResetNotice = true;
    render(Home);

    expect(screen.getByText("The local data of this device could not be opened")).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: "I understand" }));
    expect(session.showStoreResetNotice).toBe(false);
  });
});
