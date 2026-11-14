// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";

import { QUIET_ZONE, qrPath } from "./qr";

describe("qrPath", () => {
  it("draws one rectangle per horizontal run of dark modules", () => {
    const path = qrPath({ size: 3, rows: ["110", "000", "101"] });

    expect(path).toBe(
      `M${QUIET_ZONE} ${QUIET_ZONE}h2v1h-2z` +
        `M${QUIET_ZONE} ${QUIET_ZONE + 2}h1v1h-1z` +
        `M${QUIET_ZONE + 2} ${QUIET_ZONE + 2}h1v1h-1z`,
    );
  });

  it("draws nothing for an empty or all-light code", () => {
    expect(qrPath({ size: 0, rows: [] })).toBe("");
    expect(qrPath({ size: 2, rows: ["00", "00"] })).toBe("");
  });

  it("covers exactly the dark modules", () => {
    const rows = ["1011", "0110", "1111", "0001"];
    const dark = rows.join("").split("").filter((cell) => cell === "1").length;
    const widths = [...qrPath({ size: 4, rows }).matchAll(/h(\d+)v1/g)].map((m) => Number(m[1]));

    expect(widths.reduce((sum, width) => sum + width, 0)).toBe(dark);
  });
});
