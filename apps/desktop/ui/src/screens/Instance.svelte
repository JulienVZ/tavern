<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, toCommandError, type CommandError } from "../lib/api";
  import { errorMessage, t } from "../lib/i18n";
  import { session } from "../lib/session.svelte";

  let url = $state(session.instanceUrl);
  let checking = $state(false);
  let error = $state<CommandError | null>(null);
  let unhealthy = $state(false);

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (checking) {
      return;
    }
    checking = true;
    error = null;
    unhealthy = false;
    try {
      const probe = await api.probeInstance(url);
      if (probe.health.status !== "ok") {
        unhealthy = true;
        return;
      }
      session.instanceUrl = probe.url;
      session.rememberedHandle = probe.rememberedHandle;
      session.serverOutdated = probe.serverOutdated;
      session.endedMessage = null;
      if (probe.account !== null) {
        session.account = probe.account;
        session.showHistoryNotice = false;
        session.screen = "home";
      } else {
        session.screen = "auth";
      }
    } catch (thrown: unknown) {
      error = toCommandError(thrown);
    } finally {
      checking = false;
    }
  }
</script>

<main class="centered">
  <section class="card" aria-labelledby="instance-title">
    <h1 id="instance-title">{t("instance.title")}</h1>
    <p class="muted">{t("instance.intro")}</p>

    <form class="stack" onsubmit={submit} novalidate>
      <div class="field">
        <label for="instance-url">{t("instance.url.label")}</label>
        <input
          id="instance-url"
          name="instance-url"
          type="text"
          inputmode="url"
          autocomplete="url"
          autocapitalize="off"
          spellcheck="false"
          placeholder={t("instance.url.placeholder")}
          aria-describedby="instance-url-hint"
          aria-invalid={error !== null}
          bind:value={url}
        />
        <p id="instance-url-hint" class="hint">{t("instance.url.hint")}</p>
      </div>

      <button class="primary wide" type="submit" disabled={checking || url.trim() === ""}>
        {checking ? t("instance.checking") : t("instance.submit")}
      </button>

      <div role="alert">
        {#if error !== null}
          <p class="alert error">{errorMessage(error)}</p>
        {:else if unhealthy}
          <p class="alert warn">{t("instance.unhealthy")}</p>
        {/if}
      </div>
    </form>
  </section>
</main>
