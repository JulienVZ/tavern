// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";

import { DEFAULT_LOCALE, catalogues, pickLocale, setLocale, t } from "./i18n";

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
    expect(t("instance.submit")).toBe("Vérifier l'instance");
    setLocale("en");
    expect(t("instance.submit")).toBe("Check instance");
  });
});
