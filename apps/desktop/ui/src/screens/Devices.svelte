<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, type CommandError, type Device } from "../lib/api";
  import { errorMessage, formatDate, t } from "../lib/i18n";
  import { guarded, session } from "../lib/session.svelte";

  let devices = $state<Device[]>([]);
  let loading = $state(true);
  let error = $state<CommandError | null>(null);

  async function load(): Promise<void> {
    const result = await guarded(() => api.devices());
    loading = false;
    if (result.ok) {
      devices = result.value;
      error = null;
    } else {
      error = result.error;
    }
  }

  async function revoke(device: Device): Promise<void> {
    if (!window.confirm(t("devices.revoke.confirm"))) {
      return;
    }
    const result = await guarded(() => api.revokeDevice(device.deviceId));
    if (!result.ok) {
      error = result.error;
      return;
    }
    session.newDevices = session.newDevices.filter((id) => id !== device.deviceId);
    await load();
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
          {#if !device.current}
            <button class="danger" type="button" onclick={() => revoke(device)}>
              {t("devices.revoke")}
            </button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  <div role="alert">
    {#if error !== null}
      <p class="alert error">{errorMessage(error)}</p>
    {/if}
  </div>
</section>
