// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";

// `alert`, `confirm` and `prompt` are not shown by WKWebView or WebKitGTK
// unless the embedder implements them, and Tauri does not: `confirm` returns
// `false` at once, so the action behind it silently never runs. Use
// `lib/ConfirmDialog.svelte` instead.

const FORBIDDEN = /(?<![.\w$])(?:(?:window|globalThis|self)\s*\.\s*)?(alert|confirm|prompt)\s*\(/;

// Every source of the interface, as text. Tests are left out: they may name
// the forbidden calls.
const sources = Object.entries(
  import.meta.glob<string>("./**/*.{svelte,ts}", { query: "?raw", import: "default", eager: true }),
).filter(([path]) => !path.endsWith(".test.ts"));

describe("browser dialogs", () => {
  it("are recognised by the check", () => {
    expect(FORBIDDEN.test("if (!window.confirm(question)) {")).toBe(true);
    expect(FORBIDDEN.test("  alert('done');")).toBe(true);
    expect(FORBIDDEN.test("const name = globalThis.prompt (label);")).toBe(true);
    expect(FORBIDDEN.test("onconfirm();")).toBe(false);
    expect(FORBIDDEN.test("dialog.confirm()")).toBe(false);
    expect(FORBIDDEN.test('<div role="alert">')).toBe(false);
  });

  it("are not used anywhere in the interface", () => {
    expect(sources.length).toBeGreaterThan(10);
    const offenders = sources
      .filter(([, text]) => text.split("\n").some((line) => FORBIDDEN.test(line)))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });
});
