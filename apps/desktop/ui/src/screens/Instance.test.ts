// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { InstanceProbe } from "../lib/api";
import { setLocale } from "../lib/i18n";
import { session } from "../lib/session.svelte";
import { callsTo, onCommand, resetCommands } from "../test/tauri";
import Instance from "./Instance.svelte";

vi.mock("@tauri-apps/api/core", async () => ({ invoke: (await import("../test/tauri")).invoke }));

const PROBE: InstanceProbe = {
  url: "http://localhost:8080/",
  health: { status: "ok", database: "ok" },
  serverVersion: "0.0.1",
  serverOutdated: false,
  rememberedHandle: "ann",
  knownHandles: ["ann"],
  account: null,
  storeReset: false,
};

const ANN = {
  userId: "00000000-0000-7000-8000-000000000001",
  deviceId: "00000000-0000-7000-8000-0000000000d1",
  handle: "ann",
  displayName: "Ann",
  isAdmin: false,
  totpEnabled: false,
};

beforeEach(() => {
  resetCommands();
  setLocale("en");
  session.screen = "instance";
  session.instanceUrl = "";
  session.account = null;
  session.showStoreResetNotice = false;
});

async function connect(): Promise<void> {
  render(Instance);
  await fireEvent.input(screen.getByLabelText("Instance address"), {
    target: { value: "localhost:8080" },
  });
  await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
}

describe("connecting to an instance", () => {
  it("goes to the sign-in screen when no session is saved", async () => {
    onCommand("probe_instance", () => PROBE);
    await connect();

    await vi.waitFor(() => {
      expect(session.screen).toBe("auth");
    });
    expect(callsTo("probe_instance")).toEqual([{ url: "localhost:8080" }]);
    expect(session.knownHandles).toEqual(["ann"]);
  });

  it("resumes a saved session, and says when its local store started empty", async () => {
    onCommand("probe_instance", () => ({ ...PROBE, account: ANN, storeReset: true }));
    await connect();

    await vi.waitFor(() => {
      expect(session.screen).toBe("home");
    });
    expect(session.account).toEqual(ANN);
    expect(session.showStoreResetNotice).toBe(true);
  });

  it("shows why the local store cannot be opened", async () => {
    onCommand("probe_instance", () => {
      throw { code: "local_store_unavailable" };
    });
    await connect();

    expect((await screen.findByText(/cannot be opened/)).textContent).toContain("try again");
    expect(session.screen).toBe("instance");
  });
});
