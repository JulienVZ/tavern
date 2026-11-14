// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";

import { DEFAULT_LOCALE, catalogues, errorMessage, pickLocale, setLocale, t } from "./i18n";

function placeholders(message: string): string[] {
  return [...message.matchAll(/\{(\w+)\}/g)].map((match) => match[1] ?? "").sort();
}

describe("catalogues", () => {
  it("define the same keys in every locale", () => {
    const reference = Object.keys(catalogues[DEFAULT_LOCALE]).sort();
    for (const [locale, catalogue] of Object.entries(catalogues)) {
      expect(Object.keys(catalogue).sort(), locale).toEqual(reference);
    }
  });

  it("have no empty message", () => {
    for (const catalogue of Object.values(catalogues)) {
      for (const [key, message] of Object.entries(catalogue)) {
        expect(message.trim(), key).not.toBe("");
      }
    }
  });

  it("use the same placeholders in every locale", () => {
    const reference = catalogues[DEFAULT_LOCALE];
    for (const [locale, catalogue] of Object.entries(catalogues)) {
      for (const [key, message] of Object.entries(catalogue)) {
        const expected = placeholders(reference[key as keyof typeof reference]);
        expect(placeholders(message), `${locale}:${key}`).toEqual(expected);
      }
    }
  });
});

describe("pickLocale", () => {
  it("matches on the language subtag", () => {
    expect(pickLocale(["fr-CH", "en"])).toBe("fr");
    expect(pickLocale(["EN-gb"])).toBe("en");
  });

  it("skips unsupported languages", () => {
    expect(pickLocale(["de-CH", "fr"])).toBe("fr");
  });

  it("falls back to the default locale", () => {
    expect(pickLocale([])).toBe(DEFAULT_LOCALE);
    expect(pickLocale(["ja"])).toBe(DEFAULT_LOCALE);
  });
});

describe("t", () => {
  it("follows the current locale", () => {
    setLocale("fr");
    expect(t("auth.login.submit")).toBe("Se connecter");
    setLocale("en");
    expect(t("auth.login.submit")).toBe("Sign in");
  });

  it("fills placeholders", () => {
    setLocale("en");
    expect(t("admin.invites.uses", { uses: 1, max: 3 })).toBe("1 of 3 used");
    expect(t("home.signed_in_as", { name: "Alice", handle: "alice" })).toBe(
      "Signed in as Alice (@alice)",
    );
  });
});

describe("errorMessage", () => {
  it("prefers the detailed message", () => {
    setLocale("en");
    expect(errorMessage({ code: "weak_password", detail: "too_short" })).toBe(
      "The password is too short (12 characters minimum).",
    );
    expect(errorMessage({ code: "weak_password", detail: "unknown_detail" })).toBe(
      "This password is too weak.",
    );
  });

  it("falls back to a generic message for unknown codes", () => {
    expect(errorMessage({ code: "something_new" })).toBe("Something went wrong.");
  });

  it("never claims that a wrong handle differs from a wrong password", () => {
    for (const catalogue of Object.values(catalogues)) {
      const message = catalogue["error.invalid_credentials"].toLowerCase();
      expect(message).not.toMatch(/unknown|does not exist|n'existe pas|inconnu/);
    }
  });
});
