// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { setLocale } from "../lib/i18n";
import { session } from "../lib/session.svelte";
import { callsTo, onCommand, resetCommands } from "../test/tauri";
import Auth from "./Auth.svelte";

vi.mock("@tauri-apps/api/core", async () => ({ invoke: (await import("../test/tauri")).invoke }));

const ACCOUNT = {
  userId: "00000000-0000-7000-8000-000000000001",
  deviceId: "00000000-0000-7000-8000-0000000000d1",
  handle: "bob",
  displayName: "Bob",
  isAdmin: false,
  totpEnabled: false,
};

beforeEach(() => {
  resetCommands();
  setLocale("en");
  session.screen = "auth";
  session.instanceUrl = "http://localhost:8080";
  session.account = null;
  session.rememberedHandle = "ann";
  session.knownHandles = ["ann", "bob"];
  session.endedMessage = null;
});

describe("the accounts known on this computer", () => {
  it("are offered, and picking one fills the handle", async () => {
    render(Auth);
    const handle = screen.getByLabelText<HTMLInputElement>("Handle");
    expect(handle.value).toBe("ann");
    expect(screen.getByText(/already a device of this account/)).toBeTruthy();

    await fireEvent.click(screen.getByRole("button", { name: "@bob" }));
    expect(handle.value).toBe("bob");
    expect(document.activeElement).toBe(screen.getByLabelText("Password"));
  });

  it("are not mentioned for another handle", async () => {
    render(Auth);
    const handle = screen.getByLabelText<HTMLInputElement>("Handle");
    await fireEvent.input(handle, { target: { value: "carol" } });

    expect(screen.queryByText(/already a device of this account/)).toBeNull();
  });

  it("include an account signed in for the first time", async () => {
    session.knownHandles = [];
    onCommand("login", () => ({
      status: "signed_in",
      account: ACCOUNT,
      newDevice: true,
      storeReset: false,
    }));
    render(Auth);
    await fireEvent.input(screen.getByLabelText("Handle"), { target: { value: "bob" } });
    await fireEvent.input(screen.getByLabelText("Password"), {
      target: { value: "tournesol-vexant-42-brume" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await vi.waitFor(() => {
      expect(session.screen).toBe("home");
    });
    expect(callsTo("login")).toHaveLength(1);
    expect(session.knownHandles).toEqual(["bob"]);
    expect(session.showHistoryNotice).toBe(true);
    expect(session.showStoreResetNotice).toBe(false);
  });
});

describe("a sign-in that the keys of the account stop", () => {
  async function signInFailingWith(code: string): Promise<string> {
    onCommand("login", () => {
      throw { code };
    });
    render(Auth);
    await fireEvent.input(screen.getByLabelText("Password"), {
      target: { value: "tournesol-vexant-42-brume" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    let text = "";
    await vi.waitFor(() => {
      text = screen.getByRole("alert").textContent ?? "";
      expect(text.trim()).not.toBe("");
    });
    expect(session.screen).toBe("auth");
    return text;
  }

  it("says calmly that an account in a retired format is too old", async () => {
    const text = await signInFailingWith("account_too_old");

    expect(text).toContain("created with a version of Tavern that is too old");
    expect(text).toContain("Contact the administrator of the instance");
    expect(text).not.toContain("do not match");
    expect(text).not.toContain("Do not continue");
  });

  it("raises the alarm when the keys do not match the account", async () => {
    const text = await signInFailingWith("untrusted_key_material");

    expect(text).toContain("keys that do not match this account");
    expect(text).toContain("Do not continue");
    expect(text).not.toContain("too old");
  });
});
