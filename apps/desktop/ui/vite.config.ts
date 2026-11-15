// SPDX-License-Identifier: AGPL-3.0-or-later
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { svelteTesting } from "@testing-library/svelte/vite";
import { defineConfig } from "vitest/config";

// The port is fixed because `tauri.conf.json` points the webview at it.
export default defineConfig({
  // `svelteTesting` only acts under Vitest: it resolves Svelte for the browser
  // and unmounts components after each test.
  plugins: [svelte(), svelteTesting()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "localhost",
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    target: "es2022",
    sourcemap: false,
  },
  test: {
    // Component tests ask for jsdom with a `@vitest-environment` comment.
    environment: "node",
  },
});
