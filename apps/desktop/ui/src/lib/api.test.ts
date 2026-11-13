// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";

import { COMMAND_ERRORS, isCommandError } from "./api";
import { catalogues } from "./i18n";

describe("isCommandError", () => {
  it("accepts known codes only", () => {
    expect(isCommandError("unreachable")).toBe(true);
    expect(isCommandError("nope")).toBe(false);
    expect(isCommandError(undefined)).toBe(false);
    expect(isCommandError({ code: "unreachable" })).toBe(false);
  });
});

describe("command errors", () => {
  it("all have a localised message", () => {
    for (const code of COMMAND_ERRORS) {
      expect(catalogues.en).toHaveProperty([`error.${code}`]);
    }
  });
});
