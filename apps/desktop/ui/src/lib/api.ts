// SPDX-License-Identifier: AGPL-3.0-or-later

// Typed wrappers around the Tauri commands exposed by `src-tauri`.
// The UI only ever receives already-decrypted view models through this layer.

import { invoke } from "@tauri-apps/api/core";

export type ComponentStatus = "ok" | "unavailable";

export interface InstanceProbe {
  url: string;
  health: {
    status: ComponentStatus;
    database: ComponentStatus;
  };
}

export const COMMAND_ERRORS = [
  "invalid_url",
  "insecure_url",
  "unreachable",
  "not_an_instance",
] as const;

export type CommandError = (typeof COMMAND_ERRORS)[number];

export function isCommandError(value: unknown): value is CommandError {
  return typeof value === "string" && (COMMAND_ERRORS as readonly string[]).includes(value);
}

/** Validates the address and asks the instance for its health. */
export function probeInstance(url: string): Promise<InstanceProbe> {
  return invoke<InstanceProbe>("probe_instance", { url });
}
