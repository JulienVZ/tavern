<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { isCommandError, probeInstance, type InstanceProbe } from "./lib/api";
  import { t, type MessageKey } from "./lib/i18n";

  let url = $state("");
  let checking = $state(false);
  let probe = $state<InstanceProbe | null>(null);
  let errorKey = $state<MessageKey | null>(null);

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (checking) {
      return;
    }
    checking = true;
    probe = null;
    errorKey = null;
    try {
      probe = await probeInstance(url);
    } catch (error: unknown) {
      errorKey = isCommandError(error) ? `error.${error}` : "error.unknown";
    } finally {
      checking = false;
    }
  }
</script>

<main>
  <section class="card" aria-labelledby="instance-title">
    <h1 id="instance-title">{t("instance.title")}</h1>
    <p class="intro">{t("instance.intro")}</p>

    <form onsubmit={submit} novalidate>
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
        aria-invalid={errorKey !== null}
        bind:value={url}
      />
      <p id="instance-url-hint" class="hint">{t("instance.url.hint")}</p>

      <button type="submit" disabled={checking || url.trim() === ""}>
        {checking ? t("instance.checking") : t("instance.submit")}
      </button>
    </form>

    <div class="feedback" role="status" aria-live="polite">
      {#if errorKey !== null}
        <p class="error">{t(errorKey)}</p>
      {:else if probe !== null}
        <h2>{t("instance.result.title")}</h2>
        <dl>
          <dt>{t("instance.result.url")}</dt>
          <dd>{probe.url}</dd>
          <dt>{t("instance.result.server")}</dt>
          <dd class={probe.health.status}>{t(`status.${probe.health.status}`)}</dd>
          <dt>{t("instance.result.database")}</dt>
          <dd class={probe.health.database}>{t(`status.${probe.health.database}`)}</dd>
        </dl>
      {/if}
    </div>
  </section>
</main>

<style>
  main {
    min-height: 100%;
    display: grid;
    place-items: center;
    padding: 1.5rem;
  }

  .card {
    width: min(100%, 28rem);
    padding: 2rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 0.75rem;
  }

  h1 {
    margin: 0 0 0.5rem;
    font-size: 1.5rem;
    line-height: 1.25;
  }

  h2 {
    margin: 0 0 0.5rem;
    font-size: 1rem;
  }

  .intro,
  .hint {
    color: var(--text-muted);
  }

  .intro {
    margin: 0 0 1.5rem;
  }

  .hint {
    margin: 0.375rem 0 1.25rem;
    font-size: 0.875rem;
  }

  label {
    display: block;
    margin-bottom: 0.375rem;
    font-weight: 600;
  }

  input {
    width: 100%;
    padding: 0.625rem 0.75rem;
    font: inherit;
    color: var(--text);
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
  }

  input[aria-invalid="true"] {
    border-color: var(--error);
  }

  button {
    width: 100%;
    padding: 0.625rem 1rem;
    font: inherit;
    font-weight: 600;
    color: var(--accent-text);
    background: var(--accent);
    border: none;
    border-radius: 0.5rem;
    cursor: pointer;
  }

  button:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }

  .feedback {
    min-height: 1.5rem;
    margin-top: 1.25rem;
  }

  .error {
    margin: 0;
    color: var(--error);
  }

  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.25rem 1rem;
    margin: 0;
  }

  dt {
    color: var(--text-muted);
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  dd.ok {
    color: var(--ok);
  }

  dd.unavailable {
    color: var(--error);
  }
</style>
