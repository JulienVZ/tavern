<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, type CommandError, type TotpEnrolment } from "../lib/api";
  import { errorMessage, t } from "../lib/i18n";
  import QrCode from "../lib/QrCode.svelte";
  import { guarded, session } from "../lib/session.svelte";

  type Step = "idle" | "setup" | "codes" | "disable";

  let step = $state<Step>("idle");
  let enrolment = $state<TotpEnrolment | null>(null);
  let recoveryCodes = $state<string[]>([]);
  let code = $state("");
  let working = $state(false);
  let error = $state<CommandError | null>(null);
  /** TOTP was just disabled: confirmation shown until the next action. */
  let disabled = $state(false);

  const enabled = $derived(session.account?.totpEnabled ?? false);

  async function run<T>(action: () => Promise<T>): Promise<T | undefined> {
    working = true;
    error = null;
    disabled = false;
    const result = await guarded(action);
    working = false;
    if (result.ok) {
      return result.value;
    }
    error = result.error;
    return undefined;
  }

  async function start(): Promise<void> {
    const result = await run(() => api.totpEnable());
    if (result !== undefined) {
      enrolment = result;
      code = "";
      step = "setup";
    }
  }

  async function confirmEnrolment(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const codes = await run(() => api.totpConfirm(code));
    if (codes !== undefined) {
      recoveryCodes = codes;
      enrolment = null;
      code = "";
      step = "codes";
      if (session.account !== null) {
        session.account.totpEnabled = true;
      }
    }
  }

  async function disable(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const done = await run(async () => {
      await api.totpDisable(code);
      return true;
    });
    if (done === true) {
      code = "";
      step = "idle";
      disabled = true;
      if (session.account !== null) {
        session.account.totpEnabled = false;
      }
    }
  }

  function reset(): void {
    step = "idle";
    enrolment = null;
    recoveryCodes = [];
    code = "";
    error = null;
  }
</script>

<section class="stack" aria-labelledby="security-title">
  <h2 id="security-title">{t("security.title")}</h2>

  {#if step === "idle"}
    <div class="row spread">
      <p class="muted small">{enabled ? t("security.totp.on") : t("security.totp.off")}</p>
      {#if enabled}
        <button type="button" onclick={() => (step = "disable")}>
          {t("security.totp.disable")}
        </button>
      {:else}
        <button type="button" disabled={working} onclick={start}>
          {t("security.totp.enable")}
        </button>
      {/if}
    </div>
  {:else if step === "setup" && enrolment !== null}
    <form class="stack" onsubmit={confirmEnrolment} novalidate>
      <p>{t("security.totp.setup")}</p>
      <QrCode matrix={enrolment.qr} label={t("security.totp.qr")} />
      <div>
        <h3 id="totp-secret-label" class="small muted">{t("security.totp.secret")}</h3>
        <code class="secret" aria-labelledby="totp-secret-label">{enrolment.secret}</code>
      </div>
      <details>
        <summary class="small muted">{t("security.totp.url")}</summary>
        <code class="secret small">{enrolment.otpauthUrl}</code>
      </details>
      <div class="field">
        <label for="totp-confirm-code">{t("totp.code")}</label>
        <input
          id="totp-confirm-code"
          type="text"
          class="mono"
          inputmode="numeric"
          autocomplete="one-time-code"
          bind:value={code}
        />
      </div>
      <div class="row">
        <button class="primary" type="submit" disabled={working || code.trim() === ""}>
          {t("security.totp.confirm")}
        </button>
        <button type="button" onclick={reset}>{t("common.cancel")}</button>
      </div>
    </form>
  {:else if step === "codes"}
    <div class="stack">
      <h3>{t("security.totp.codes.title")}</h3>
      <p>{t("security.totp.codes.body")}</p>
      <code class="secret">
        {#each recoveryCodes as recoveryCode (recoveryCode)}
          {recoveryCode}<br />
        {/each}
      </code>
      <button class="primary" type="button" onclick={reset}>
        {t("security.totp.codes.done")}
      </button>
    </div>
  {:else if step === "disable"}
    <form class="stack" onsubmit={disable} novalidate>
      <div class="field">
        <label for="totp-disable-code">{t("security.totp.disable.prompt")}</label>
        <input
          id="totp-disable-code"
          type="text"
          class="mono"
          autocomplete="one-time-code"
          autocapitalize="characters"
          spellcheck="false"
          bind:value={code}
        />
      </div>
      <div class="row">
        <button class="danger" type="submit" disabled={working || code.trim() === ""}>
          {t("security.totp.disable")}
        </button>
        <button type="button" onclick={reset}>{t("common.cancel")}</button>
      </div>
    </form>
  {/if}

  <div role="status">
    {#if disabled}
      <p class="alert">{t("security.totp.disabled")}</p>
    {/if}
  </div>
  <div role="alert">
    {#if error !== null}
      <p class="alert error">{errorMessage(error)}</p>
    {/if}
  </div>
</section>
