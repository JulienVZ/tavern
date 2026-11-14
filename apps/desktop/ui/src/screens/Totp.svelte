<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, toCommandError, type CommandError } from "../lib/api";
  import { errorMessage, t } from "../lib/i18n";
  import { applyLogin, session } from "../lib/session.svelte";

  let code = $state("");
  let working = $state(false);
  let error = $state<CommandError | null>(null);

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (working) {
      return;
    }
    working = true;
    error = null;
    try {
      applyLogin(await api.submitTotp(code));
    } catch (thrown: unknown) {
      error = toCommandError(thrown);
      code = "";
      // Only a wrong code can be retried; anything else restarts the sign-in.
      if (error.code !== "totp_invalid") {
        session.screen = "auth";
      }
    } finally {
      working = false;
    }
  }

  function cancel(): void {
    session.screen = "auth";
  }
</script>

<main class="centered">
  <section class="card" aria-labelledby="totp-title">
    <h1 id="totp-title">{t("totp.title")}</h1>
    <p class="muted">{t("totp.intro")}</p>

    <form class="stack" onsubmit={submit} novalidate>
      <div class="field">
        <label for="totp-code">{t("totp.code")}</label>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          id="totp-code"
          type="text"
          class="mono"
          inputmode="numeric"
          autocomplete="one-time-code"
          autocapitalize="characters"
          spellcheck="false"
          autofocus
          aria-invalid={error !== null}
          bind:value={code}
        />
      </div>
      <div class="row">
        <button class="primary" type="submit" disabled={working || code.trim() === ""}>
          {t("totp.submit")}
        </button>
        <button type="button" onclick={cancel}>{t("common.cancel")}</button>
      </div>
      <div role="alert">
        {#if error !== null}
          <p class="alert error">{errorMessage(error)}</p>
        {/if}
      </div>
    </form>
  </section>
</main>
