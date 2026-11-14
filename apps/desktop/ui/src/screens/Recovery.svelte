<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, toCommandError, type CommandError } from "../lib/api";
  import { errorMessage, t } from "../lib/i18n";
  import { applyLogin, session } from "../lib/session.svelte";

  let saved = $state(false);
  let copied = $state(false);
  let working = $state(false);
  let error = $state<CommandError | null>(null);

  async function copy(): Promise<void> {
    const key = session.registration?.recoveryKey;
    if (key === undefined) {
      return;
    }
    try {
      await navigator.clipboard.writeText(key);
      copied = true;
    } catch {
      // The clipboard may be unavailable; the key is selectable on screen.
      copied = false;
    }
  }

  async function proceed(): Promise<void> {
    const registration = session.registration;
    if (registration === null || working) {
      return;
    }
    working = true;
    error = null;
    try {
      const result = await api.login(registration.handle, registration.password);
      // `applyLogin` erases the registration, and with it the password and key.
      applyLogin(result);
    } catch (thrown: unknown) {
      error = toCommandError(thrown);
      // Let the user sign in by hand rather than keep the password around.
      session.rememberedHandle = registration.handle;
      session.registration = null;
      session.screen = "auth";
    } finally {
      working = false;
    }
  }
</script>

<main class="centered">
  <section class="card stack" aria-labelledby="recovery-title">
    <h1 id="recovery-title">{t("recovery.title")}</h1>
    <p>{t("recovery.intro")}</p>
    <p class="muted">{t("recovery.where")}</p>

    {#if session.registration !== null}
      <div>
        <h2 id="recovery-label" class="small muted">{t("recovery.label")}</h2>
        <code class="secret" aria-labelledby="recovery-label">{session.registration.recoveryKey}</code>
        <p class="hint row">
          <button type="button" onclick={copy}>{t("common.copy")}</button>
          <span role="status">{copied ? t("common.copied") : ""}</span>
        </p>
      </div>
      {#if session.registration.isAdmin}
        <p><span class="badge">{t("home.admin_badge")}</span> {t("recovery.admin")}</p>
      {/if}
    {/if}

    <label class="row">
      <input type="checkbox" bind:checked={saved} />
      <span>{t("recovery.confirm")}</span>
    </label>

    <button class="primary wide" type="button" disabled={!saved || working} onclick={proceed}>
      {working ? t("auth.login.working") : t("common.continue")}
    </button>

    <div role="alert">
      {#if error !== null}
        <p class="alert error">{errorMessage(error)}</p>
      {/if}
    </div>
  </section>
</main>

<style>
  label.row {
    font-weight: 400;
  }
</style>
