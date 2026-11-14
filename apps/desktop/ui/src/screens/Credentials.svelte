<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, type CommandError } from "../lib/api";
  import { errorMessage, t } from "../lib/i18n";
  import PasswordMeter from "../lib/PasswordMeter.svelte";
  import { guarded, session } from "../lib/session.svelte";

  type Step = "idle" | "password" | "recovery" | "new-key";

  let step = $state<Step>("idle");
  let currentPassword = $state("");
  let totpCode = $state("");
  let newPassword = $state("");
  let confirmation = $state("");
  let newPasswordOk = $state(false);
  let newKey = $state<string | null>(null);
  let working = $state(false);
  let error = $state<CommandError | null>(null);
  let changed = $state(false);

  const totpEnabled = $derived(session.account?.totpEnabled ?? false);
  const mismatch = $derived(confirmation !== "" && confirmation !== newPassword);
  const secondFactorOk = $derived(!totpEnabled || totpCode.trim() !== "");
  const canChange = $derived(
    currentPassword !== "" && secondFactorOk && newPasswordOk && confirmation === newPassword,
  );

  function reset(): void {
    step = "idle";
    currentPassword = "";
    totpCode = "";
    newPassword = "";
    confirmation = "";
    newKey = null;
    error = null;
  }

  function open(next: Step): void {
    reset();
    changed = false;
    step = next;
  }

  async function changePassword(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (working || !canChange) {
      return;
    }
    working = true;
    error = null;
    const result = await guarded(() =>
      api.changePassword(currentPassword, totpEnabled ? totpCode : null, newPassword),
    );
    working = false;
    if (result.ok) {
      reset();
      changed = true;
    } else {
      error = result.error;
    }
  }

  async function rotate(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (working || currentPassword === "" || !secondFactorOk) {
      return;
    }
    working = true;
    error = null;
    const result = await guarded(() =>
      api.rotateRecoveryKey(currentPassword, totpEnabled ? totpCode : null),
    );
    working = false;
    if (result.ok) {
      reset();
      newKey = result.value;
      step = "new-key";
    } else {
      error = result.error;
    }
  }
</script>

{#snippet currentCredentials(prefix: string)}
  <div class="field">
    <label for="{prefix}-current">{t("password.current")}</label>
    <input
      id="{prefix}-current"
      type="password"
      autocomplete="current-password"
      bind:value={currentPassword}
    />
  </div>
  {#if totpEnabled}
    <div class="field">
      <label for="{prefix}-totp">{t("password.totp")}</label>
      <input
        id="{prefix}-totp"
        type="text"
        class="mono"
        inputmode="numeric"
        autocomplete="one-time-code"
        aria-describedby="{prefix}-totp-hint"
        bind:value={totpCode}
      />
      <p id="{prefix}-totp-hint" class="hint">{t("password.totp.hint")}</p>
    </div>
  {/if}
{/snippet}

<section class="stack" aria-labelledby="credentials-title">
  <h2 id="credentials-title">{t("password.title")}</h2>

  {#if step === "idle"}
    {#if changed}
      <p class="alert" role="status">{t("password.changed")}</p>
    {/if}
    <div class="row">
      <button type="button" onclick={() => open("password")}>{t("password.change")}</button>
      <button type="button" onclick={() => open("recovery")}>{t("recoverykey.new")}</button>
    </div>
  {:else if step === "password"}
    <form onsubmit={changePassword} novalidate>
      {@render currentCredentials("change")}
      <div class="field">
        <label for="change-new">{t("password.new")}</label>
        <input
          id="change-new"
          type="password"
          autocomplete="new-password"
          aria-describedby="change-new-hint change-new-strength"
          aria-invalid={newPassword !== "" && !newPasswordOk}
          bind:value={newPassword}
        />
        <p id="change-new-hint" class="hint">{t("register.password.hint")}</p>
        <PasswordMeter
          id="change-new-strength"
          password={newPassword}
          handle={session.account?.handle ?? ""}
          displayName={session.account?.displayName ?? ""}
          bind:acceptable={newPasswordOk}
        />
      </div>
      <div class="field">
        <label for="change-confirm">{t("register.password.confirm")}</label>
        <input
          id="change-confirm"
          type="password"
          autocomplete="new-password"
          aria-invalid={mismatch}
          aria-describedby="change-confirm-error"
          bind:value={confirmation}
        />
        <p id="change-confirm-error" class="hint" aria-live="polite">
          {mismatch ? t("register.password.mismatch") : ""}
        </p>
      </div>
      <div class="field">
        <p class="hint">{t("password.change.note")}</p>
        <div class="row">
          <button class="primary" type="submit" disabled={working || !canChange}>
            {working ? t("password.working") : t("password.change.submit")}
          </button>
          <button type="button" onclick={reset}>{t("common.cancel")}</button>
        </div>
      </div>
    </form>
  {:else if step === "recovery"}
    <form onsubmit={rotate} novalidate>
      <p class="muted">{t("recoverykey.intro")}</p>
      {@render currentCredentials("rotate")}
      <div class="field row">
        <button
          class="primary"
          type="submit"
          disabled={working || currentPassword === "" || !secondFactorOk}
        >
          {working ? t("password.working") : t("recoverykey.submit")}
        </button>
        <button type="button" onclick={reset}>{t("common.cancel")}</button>
      </div>
    </form>
  {:else if newKey !== null}
    <div class="stack">
      <p>{t("recoverykey.shown")}</p>
      <code class="secret" aria-label={t("recovery.label")}>{newKey}</code>
      <div>
        <button class="primary" type="button" onclick={reset}>{t("recoverykey.done")}</button>
      </div>
    </div>
  {/if}

  <div role="alert">
    {#if error !== null}
      <p class="alert error">{errorMessage(error)}</p>
    {/if}
  </div>
</section>
