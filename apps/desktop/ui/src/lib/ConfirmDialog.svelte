<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!--
  In-app confirmation. `window.confirm` cannot be used: WKWebView (macOS) and
  WebKitGTK only show JavaScript dialogs when the embedder implements them, and
  Tauri does not, so the call returns `false` without showing anything.

  Built from plain elements rather than `<dialog>`, whose modal behaviour is
  missing from the oldest webviews Tauri supports. Render it only while a
  confirmation is pending: it takes focus when mounted and gives it back when
  removed. Cancel is focused first, so that Enter never confirms by accident.
-->
<script lang="ts">
  import { onMount } from "svelte";

  import { t } from "./i18n";

  interface Props {
    title: string;
    message: string;
    confirmLabel: string;
    onconfirm: () => void;
    oncancel: () => void;
  }

  let { title, message, confirmLabel, onconfirm, oncancel }: Props = $props();

  let cancelButton: HTMLButtonElement;
  let confirmButton: HTMLButtonElement;

  onMount(() => {
    const previous = document.activeElement;
    cancelButton.focus();
    return () => {
      if (previous instanceof HTMLElement) {
        previous.focus();
      }
    };
  });

  function onkeydown(event: KeyboardEvent): void {
    if (event.key === "Escape") {
      event.preventDefault();
      oncancel();
    } else if (event.key === "Tab") {
      // Two controls: Tab and Shift+Tab both move to the other one.
      event.preventDefault();
      (document.activeElement === cancelButton ? confirmButton : cancelButton).focus();
    }
  }
</script>

<div class="backdrop">
  <div
    class="dialog stack"
    role="alertdialog"
    aria-modal="true"
    aria-labelledby="confirm-title"
    aria-describedby="confirm-message"
    tabindex="-1"
    {onkeydown}
  >
    <h2 id="confirm-title">{title}</h2>
    <p id="confirm-message">{message}</p>
    <div class="row">
      <button type="button" bind:this={cancelButton} onclick={oncancel}>
        {t("common.cancel")}
      </button>
      <button class="danger" type="button" bind:this={confirmButton} onclick={onconfirm}>
        {confirmLabel}
      </button>
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    z-index: 10;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1rem;
    background: rgb(0 0 0 / 55%);
  }

  .dialog {
    width: min(100%, 28rem);
    padding: 1.25rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
  }

  .row {
    justify-content: flex-end;
  }
</style>
