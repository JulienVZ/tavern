// SPDX-License-Identifier: AGPL-3.0-or-later

// Stand-in for the Tauri bridge in component tests. A test file mocks
// `@tauri-apps/api/core` with `invoke` below, then scripts the answer of each
// command. A command without a scripted answer fails the test, so that a
// screen cannot call something the test did not expect.

import { vi } from "vitest";

type Handler = (args: Record<string, unknown> | undefined) => unknown;

const handlers = new Map<string, Handler>();

export const invoke = vi.fn(
  async (command: string, args?: Record<string, unknown>): Promise<unknown> => {
    const handler = handlers.get(command);
    if (handler === undefined) {
      throw new Error(`unexpected command: ${command}`);
    }
    return handler(args);
  },
);

/** Scripts the answer of a command. Throw from `handler` to make it fail. */
export function onCommand(command: string, handler: Handler): void {
  handlers.set(command, handler);
}

/** Calls made to one command, in order. */
export function callsTo(command: string): unknown[] {
  return invoke.mock.calls.filter(([name]) => name === command).map(([, args]) => args);
}

export function resetCommands(): void {
  handlers.clear();
  invoke.mockClear();
}
