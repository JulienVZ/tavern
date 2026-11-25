// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";

import { isCommandError, toCommandError } from "./api";
import { isMessageKey } from "./i18n";

describe("isCommandError", () => {
  it("accepts objects with a string code only", () => {
    expect(isCommandError({ code: "unreachable" })).toBe(true);
    expect(isCommandError({ code: "weak_password", detail: "too_short" })).toBe(true);
    expect(isCommandError("unreachable")).toBe(false);
    expect(isCommandError({ code: 4 })).toBe(false);
    expect(isCommandError(null)).toBe(false);
    expect(isCommandError(undefined)).toBe(false);
  });
});

describe("toCommandError", () => {
  it("keeps command errors and wraps anything else", () => {
    expect(toCommandError({ code: "rate_limited", retryAfterMs: 1200 })).toEqual({
      code: "rate_limited",
      retryAfterMs: 1200,
    });
    expect(toCommandError(new Error("boom"))).toEqual({ code: "internal" });
    expect(toCommandError("boom")).toEqual({ code: "internal" });
  });
});

describe("error codes produced by the shell", () => {
  // Codes built in apps/desktop/src-tauri/src/error.rs and lib.rs.
  const codes = [
    "invalid_url",
    "insecure_url",
    "unreachable",
    "not_an_instance",
    "incompatible_server",
    "client_too_old",
    "server_error",
    "invalid_credentials",
    "invalid_invite",
    "handle_taken",
    "invalid_handle",
    "weak_password",
    "totp_invalid",
    "totp_required",
    "invalid_recovery_key",
    "invalid_proof",
    "exchange_expired",
    "account_disabled",
    "rate_limited",
    "too_many_devices",
    "device_revoked",
    "session_ended",
    "forbidden",
    "invalid_argument",
    "already_exists",
    "not_found",
    "unavailable",
    "keychain_unavailable",
    "local_store_unavailable",
    "local_store_too_new",
    "untrusted_key_material",
    "clock_skew",
    "account_too_old",
    "internal",
  ];

  it("all have a localised message", () => {
    for (const code of codes) {
      expect(isMessageKey(`error.${code}`), code).toBe(true);
    }
  });
});
