<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api } from "../lib/api";
  import { t } from "../lib/i18n";
  import { guarded, session, signedOut } from "../lib/session.svelte";
  import Admin from "./Admin.svelte";
  import Credentials from "./Credentials.svelte";
  import Devices from "./Devices.svelte";
  import Security from "./Security.svelte";

  let signingOut = $state(false);

  async function logout(): Promise<void> {
    signingOut = true;
    await guarded(() => api.logout());
    signingOut = false;
    signedOut(null);
  }

  async function acknowledgeDevices(): Promise<void> {
    await guarded(() => api.ackNewDevices());
    session.newDevices = [];
  }

  function reviewDevices(): void {
    document.getElementById("devices-title")?.scrollIntoView({ block: "start" });
  }
</script>

{#if session.account !== null}
  <main class="page stack">
    <header class="row spread">
      <div>
        <h1>{t("app.name")}</h1>
        <p class="muted">
          {t("home.signed_in_as", {
            name: session.account.displayName,
            handle: session.account.handle,
          })}
          {#if session.account.isAdmin}
            <span class="badge">{t("home.admin_badge")}</span>
          {/if}
        </p>
      </div>
      <button type="button" disabled={signingOut} onclick={logout}>{t("home.logout")}</button>
    </header>

    <div class="stack" aria-live="polite">
      {#if session.offline}
        <p class="alert warn" role="status">{t("home.connection.offline")}</p>
      {/if}

      {#if session.newDevices.length > 0}
        <section class="alert warn stack" role="alert" aria-labelledby="newdevice-title">
          <h2 id="newdevice-title">{t("newdevice.title")}</h2>
          <p>
            {session.newDevices.length === 1
              ? t("newdevice.body.one")
              : t("newdevice.body.many", { count: session.newDevices.length })}
          </p>
          <div class="row">
            <button class="primary" type="button" onclick={reviewDevices}>
              {t("newdevice.review")}
            </button>
            <button type="button" onclick={acknowledgeDevices}>{t("newdevice.ack")}</button>
          </div>
        </section>
      {/if}

      {#if session.totpDisabledByAdmin}
        <p class="alert warn" role="alert">{t("notice.totp_disabled_by_admin")}</p>
      {/if}

      {#if session.showHistoryNotice}
        <section class="alert stack" aria-labelledby="history-title">
          <h2 id="history-title">{t("history.title")}</h2>
          <p>{t("history.body")}</p>
          <div>
            <button type="button" onclick={() => (session.showHistoryNotice = false)}>
              {t("history.dismiss")}
            </button>
          </div>
        </section>
      {/if}
    </div>

    <p class="muted">{t("home.empty")}</p>

    <div class="panel"><Devices /></div>
    <div class="panel"><Security /></div>
    <div class="panel"><Credentials /></div>
    {#if session.account.isAdmin}
      <div class="panel"><Admin /></div>
    {/if}
  </main>
{/if}

<style>
  .page {
    width: min(100%, 44rem);
    margin: 0 auto;
    padding: 1.5rem;
  }

  .panel {
    padding: 1.25rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
  }
</style>
