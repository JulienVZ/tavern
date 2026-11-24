<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, type CommandError, type SecurityNotice } from "../lib/api";
  import { errorMessage, formatDate, t } from "../lib/i18n";
  import { guarded, session, signedOut } from "../lib/session.svelte";
  import Admin from "./Admin.svelte";
  import Credentials from "./Credentials.svelte";
  import Devices from "./Devices.svelte";
  import Security from "./Security.svelte";

  let signingOut = $state(false);
  /** An acknowledgement that the instance did not receive. */
  let error = $state<CommandError | null>(null);

  async function logout(): Promise<void> {
    signingOut = true;
    const result = await guarded(() => api.logout());
    signingOut = false;
    // The local session is forgotten either way. If the instance was not
    // told, say so: the session stays valid there until it expires.
    signedOut(result.ok ? null : "ended.logout_unconfirmed");
  }

  /** A notice's text; a restore's gives the date of the backup, if known. */
  function noticeText(notice: SecurityNotice): string {
    if (notice.kind === "instance_restored") {
      return notice.backupTakenAtMs === undefined
        ? t("notice.instance_restored_undated")
        : t("notice.instance_restored", { backup: formatDate(notice.backupTakenAtMs) });
    }
    return t(`notice.${notice.kind}`, { date: formatDate(notice.createdAtMs) });
  }

  async function acknowledgeDevices(): Promise<void> {
    error = null;
    const result = await guarded(() => api.ackNewDevices());
    if (result.ok) {
      session.newDevices = [];
    } else {
      error = result.error;
    }
  }

  async function acknowledgeNotice(notice: SecurityNotice): Promise<void> {
    error = null;
    const result = await guarded(() => api.ackSecurityNotices([notice.noticeId]));
    if (result.ok) {
      session.securityNotices = session.securityNotices.filter(
        (other) => other.noticeId !== notice.noticeId,
      );
    } else {
      error = result.error;
    }
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
      {#if session.serverOutdated}
        <p class="alert warn" role="status">{t("instance.outdated")}</p>
      {/if}
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

      {#each session.securityNotices as notice (notice.noticeId)}
        <section class="alert warn stack" role="alert">
          <p>{noticeText(notice)}</p>
          <div>
            <button type="button" onclick={() => acknowledgeNotice(notice)}>
              {t("notice.ack")}
            </button>
          </div>
        </section>
      {/each}

      {#if error !== null}
        <p class="alert error" role="alert">{errorMessage(error)}</p>
      {/if}

      {#if session.showStoreResetNotice}
        <section class="alert warn stack" role="alert" aria-labelledby="storereset-title">
          <h2 id="storereset-title">{t("storereset.title")}</h2>
          <p>{t("storereset.body")}</p>
          <div>
            <button type="button" onclick={() => (session.showStoreResetNotice = false)}>
              {t("history.dismiss")}
            </button>
          </div>
        </section>
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
