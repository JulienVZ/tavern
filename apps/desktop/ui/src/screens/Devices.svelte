<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, type CommandError, type Device } from "../lib/api";
  import ConfirmDialog from "../lib/ConfirmDialog.svelte";
  import { errorMessage, formatDate, t } from "../lib/i18n";
  import { erased, guarded, session } from "../lib/session.svelte";

  let devices = $state<Device[]>([]);
  let loading = $state(true);
  let error = $state<CommandError | null>(null);
  let working = $state(false);
  /** A device was revoked: confirmation shown until the next action. */
  let revoked = $state(false);
  /** The device whose revocation awaits confirmation. */
  let target = $state<Device | null>(null);
  /** Erasing this device awaits confirmation. */
  let erasing = $state(false);

  async function erase(): Promise<void> {
    erasing = false;
    working = true;
    error = null;
    revoked = false;
    const result = await guarded(() => api.eraseDevice());
    working = false;
    if (result.ok) {
      erased();
    } else {
      // Nothing was erased: the device is still signed in and can retry.
      error = result.error;
    }
  }

  async function load(): Promise<void> {
    const result = await guarded(() => api.devices());
    loading = false;
    if (result.ok) {
      devices = result.value;
    } else if (error === null) {
      // The outcome of a revocation stays on screen over a failed refresh.
      error = result.error;
    }
  }

  async function revoke(): Promise<void> {
    const device = target;
    target = null;
    if (device === null) {
      return;
    }
    working = true;
    error = null;
    revoked = false;
    const result = await guarded(() => api.revokeDevice(device.deviceId));
    if (result.ok) {
      revoked = true;
      session.newDevices = session.newDevices.filter((id) => id !== device.deviceId);
    } else {
      error = result.error;
    }
    await load();
    working = false;
  }

  // Reload when the gateway reports a change in the device list.
  $effect(() => {
    void session.newDevices.length;
    void load();
  });
</script>

<section class="stack" aria-labelledby="devices-title">
  <div>
    <h2 id="devices-title">{t("devices.title")}</h2>
    <p class="muted small">{t("devices.intro")}</p>
  </div>

  {#if loading}
    <p class="muted" role="status">{t("common.loading")}</p>
  {:else}
    <ul class="plain">
      {#each devices as device (device.deviceId)}
        <li class="row spread">
          <div>
            <strong>{t(`platform.${device.platform}`)}</strong>
            {#if device.current}
              <span class="badge neutral">{t("devices.this")}</span>
            {/if}
            {#if session.newDevices.includes(device.deviceId)}
              <span class="badge">{t("devices.new")}</span>
            {/if}
            <br />
            <span class="muted small">
              {t("devices.added", { date: formatDate(device.createdAtMs) })}{#if device.lastSeenAtMs !== null},
                {t("devices.last_seen", { date: formatDate(device.lastSeenAtMs) })}{/if}
            </span>
          </div>
          {#if device.current}
            <button class="danger" type="button" disabled={working} onclick={() => (erasing = true)}>
              {t("devices.erase")}
            </button>
          {:else}
            <button class="danger" type="button" disabled={working} onclick={() => (target = device)}>
              {t("devices.revoke")}
            </button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  <div role="status">
    {#if revoked}
      <p class="alert">{t("devices.revoke.done")}</p>
    {/if}
  </div>
  <div role="alert">
    {#if error !== null}
      <p class="alert error">{errorMessage(error)}</p>
    {/if}
  </div>
</section>

{#if erasing}
  <ConfirmDialog
    title={t("devices.erase")}
    message={t("devices.erase.confirm")}
    confirmLabel={t("devices.erase.submit")}
    onconfirm={erase}
    oncancel={() => (erasing = false)}
  />
{/if}

{#if target !== null}
  <ConfirmDialog
    title={t("devices.revoke.title")}
    message={t("devices.revoke.confirm")}
    confirmLabel={t("devices.revoke")}
    onconfirm={revoke}
    oncancel={() => (target = null)}
  />
{/if}
