// SPDX-License-Identifier: AGPL-3.0-or-later

import type { QrMatrix } from "./api";

/** Light modules left around the code, as the QR specification requires. */
export const QUIET_ZONE = 4;

/**
 * Builds the SVG path that draws the dark modules of a QR code, one unit per
 * module, shifted by the quiet zone. Horizontal runs are merged so that the
 * path stays short.
 */
export function qrPath(matrix: QrMatrix): string {
  let path = "";
  matrix.rows.forEach((row, y) => {
    let x = 0;
    while (x < row.length) {
      if (row[x] !== "1") {
        x += 1;
        continue;
      }
      let end = x;
      while (end < row.length && row[end] === "1") {
        end += 1;
      }
      path += `M${x + QUIET_ZONE} ${y + QUIET_ZONE}h${end - x}v1h-${end - x}z`;
      x = end;
    }
  });
  return path;
}
