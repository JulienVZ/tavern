<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // Renders a QR code computed by the Rust core. Always dark on white, in
  // both themes: scanners need the contrast.
  import type { QrMatrix } from "./api";
  import { QUIET_ZONE, qrPath } from "./qr";

  interface Props {
    matrix: QrMatrix;
    /** Text alternative, e.g. "QR code to scan with your authenticator app". */
    label: string;
  }

  let { matrix, label }: Props = $props();

  const side = $derived(matrix.size + 2 * QUIET_ZONE);
</script>

<svg
  class="qr"
  role="img"
  aria-label={label}
  viewBox="0 0 {side} {side}"
  shape-rendering="crispEdges"
>
  <rect width={side} height={side} fill="#ffffff" />
  <path d={qrPath(matrix)} fill="#000000" />
</svg>

<style>
  .qr {
    display: block;
    width: 12rem;
    height: 12rem;
    border-radius: 0.5rem;
  }
</style>
