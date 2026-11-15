// SPDX-License-Identifier: AGPL-3.0-or-later

// Starts one more desktop client next to a running `pnpm tauri dev`, with its
// own keychain profile, to try several accounts or devices on one computer:
//
//   pnpm tauri dev          # first client (default profile), in one terminal
//   pnpm client bob         # another client, in another terminal
//   pnpm client alice-2     # and so on
//
// `pnpm tauri dev` cannot be started twice: it also runs the development
// server of the interface, on a fixed port. The extra clients reuse that
// server and the application `tauri dev` has just built, so they need it to
// be running, and must be restarted to pick up a change to the Rust code.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DEV_URL = "http://localhost:1420";

const profile = process.argv[2]?.trim();
if (!profile || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(profile)) {
  console.error("Usage: pnpm client <profile>");
  console.error("  <profile>: a short name such as bob or alice-2 (a-z, 0-9, - and _).");
  process.exit(2);
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const targetDir = process.env.CARGO_TARGET_DIR ?? join(root, "target");
const binary = join(
  targetDir,
  "debug",
  process.platform === "win32" ? "tavern-desktop.exe" : "tavern-desktop",
);

function notReady(reason) {
  console.error(`pnpm client: ${reason}`);
  console.error("Start the first client with `pnpm tauri dev` and wait for its window, then retry.");
  process.exit(1);
}

if (!existsSync(binary)) {
  notReady(`the application is not built yet (${binary}).`);
}
try {
  await fetch(DEV_URL, { signal: AbortSignal.timeout(2000) });
} catch {
  notReady(`the interface is not being served on ${DEV_URL}.`);
}

console.log(`Starting a client with the profile "${profile}".`);
const child = spawn(binary, [], {
  stdio: "inherit",
  env: { ...process.env, TAVERN_PROFILE: profile },
});
child.on("exit", (code) => process.exit(code ?? 0));
