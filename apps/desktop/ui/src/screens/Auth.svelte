<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, toCommandError, type CommandError } from "../lib/api";
  import { errorMessage, t, type MessageKey } from "../lib/i18n";
  import PasswordMeter from "../lib/PasswordMeter.svelte";
  import { applyLogin, session } from "../lib/session.svelte";

  const TABS = ["login", "register", "recover"] as const;
  type Tab = (typeof TABS)[number];
  const TAB_LABELS: Record<Tab, MessageKey> = {
    login: "auth.tab.login",
    register: "auth.tab.register",
    recover: "auth.tab.recover",
  };

  let tab = $state<Tab>("login");
  let working = $state(false);
  let error = $state<CommandError | null>(null);
  let notice = $state<MessageKey | null>(null);

  // Sign in
  let handle = $state(session.rememberedHandle ?? "");
  let password = $state("");

  // Create an account
  let inviteCode = $state("");
  let newHandle = $state("");
  let displayName = $state("");
  let newPassword = $state("");
  let confirmation = $state("");
  let newPasswordOk = $state(false);

  // Forgot password
  let recoverHandle = $state(session.rememberedHandle ?? "");
  let recoveryKey = $state("");
  let recoverPassword = $state("");
  let recoverConfirmation = $state("");
  let recoverPasswordOk = $state(false);

  /** The handle typed is an account this computer is already a device of. */
  const knownDevice = $derived(session.knownHandles.includes(handle.trim().toLowerCase()));

  function pick(known: string): void {
    handle = known;
    document.getElementById("login-password")?.focus();
  }

  const mismatch = $derived(confirmation !== "" && confirmation !== newPassword);
  const canRegister = $derived(
    inviteCode.trim() !== "" &&
      newHandle.trim() !== "" &&
      displayName.trim() !== "" &&
      newPasswordOk &&
      confirmation === newPassword,
  );
  const recoverMismatch = $derived(
    recoverConfirmation !== "" && recoverConfirmation !== recoverPassword,
  );
  const canRecover = $derived(
    recoverHandle.trim() !== "" &&
      recoveryKey.trim() !== "" &&
      recoverPasswordOk &&
      recoverConfirmation === recoverPassword,
  );

  function select(next: Tab): void {
    tab = next;
    error = null;
    notice = null;
  }

  function onTabKey(event: KeyboardEvent): void {
    const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (step === 0) {
      return;
    }
    const next = TABS[(TABS.indexOf(tab) + step + TABS.length) % TABS.length];
    if (next !== undefined) {
      select(next);
      document.getElementById(`tab-${next}`)?.focus();
    }
  }

  async function login(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (working) {
      return;
    }
    working = true;
    error = null;
    notice = null;
    try {
      const result = await api.login(handle, password);
      password = "";
      applyLogin(result);
    } catch (thrown: unknown) {
      error = toCommandError(thrown);
    } finally {
      working = false;
    }
  }

  async function register(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (working || !canRegister) {
      return;
    }
    working = true;
    error = null;
    try {
      const registered = await api.register(inviteCode, newHandle, displayName, newPassword);
      // Kept only until the first sign-in that follows the recovery key screen.
      session.registration = {
        handle: registered.handle,
        password: newPassword,
        recoveryKey: registered.recoveryKey,
        isAdmin: registered.isAdmin,
      };
      newPassword = "";
      confirmation = "";
      session.screen = "recovery";
    } catch (thrown: unknown) {
      error = toCommandError(thrown);
    } finally {
      working = false;
    }
  }

  async function recover(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (working || !canRecover) {
      return;
    }
    working = true;
    error = null;
    try {
      await api.recover(recoverHandle, recoveryKey, recoverPassword);
      handle = recoverHandle.trim().toLowerCase();
      recoveryKey = "";
      recoverPassword = "";
      recoverConfirmation = "";
      select("login");
      notice = "recover.done";
    } catch (thrown: unknown) {
      error = toCommandError(thrown);
    } finally {
      working = false;
    }
  }

  function changeInstance(): void {
    session.screen = "instance";
  }
</script>

<main class="centered">
  <section class="card stack">
    <p class="muted small row spread">
      <span>{t("auth.on", { instance: session.instanceUrl })}</span>
      <button class="link" type="button" onclick={changeInstance}>{t("instance.change")}</button>
    </p>

    {#if session.serverOutdated}
      <p class="alert warn" role="status">{t("instance.outdated")}</p>
    {/if}
    {#if session.endedMessage !== null}
      <p class="alert warn" role="status">
        {t(session.endedMessage.key, session.endedMessage.params)}
      </p>
    {/if}
    {#if notice !== null}
      <p class="alert" role="status">{t(notice)}</p>
    {/if}

    <div class="row" role="tablist" aria-label={t("app.name")}>
      {#each TABS as name (name)}
        <button
          id="tab-{name}"
          type="button"
          role="tab"
          aria-selected={tab === name}
          aria-controls="panel-{name}"
          tabindex={tab === name ? 0 : -1}
          class:primary={tab === name}
          onclick={() => select(name)}
          onkeydown={onTabKey}
        >
          {t(TAB_LABELS[name])}
        </button>
      {/each}
    </div>

    <div id="panel-{tab}" role="tabpanel" aria-labelledby="tab-{tab}">
      {#if tab === "login"}
        <form onsubmit={login} novalidate>
          {#if session.knownHandles.length > 0}
            <div class="field">
              <h2 id="known-accounts" class="small muted">{t("auth.known.title")}</h2>
              <div class="row" role="group" aria-labelledby="known-accounts">
                {#each session.knownHandles as known (known)}
                  <button type="button" aria-pressed={handle === known} onclick={() => pick(known)}>
                    @{known}
                  </button>
                {/each}
              </div>
            </div>
          {/if}
          <div class="field">
            <label for="login-handle">{t("auth.handle")}</label>
            <input
              id="login-handle"
              type="text"
              autocomplete="username"
              autocapitalize="off"
              spellcheck="false"
              aria-describedby="login-handle-hint"
              bind:value={handle}
            />
            <p id="login-handle-hint" class="hint">
              {knownDevice ? t("auth.known.hint") : ""}
            </p>
          </div>
          <div class="field">
            <label for="login-password">{t("auth.password")}</label>
            <input
              id="login-password"
              type="password"
              autocomplete="current-password"
              bind:value={password}
            />
          </div>
          <div class="field">
            <button
              class="primary wide"
              type="submit"
              disabled={working || handle.trim() === "" || password === ""}
            >
              {working ? t("auth.login.working") : t("auth.login.submit")}
            </button>
            {#if working}
              <p class="hint" role="status">{t("auth.login.slow")}</p>
            {/if}
          </div>
        </form>
      {:else if tab === "register"}
        <form onsubmit={register} novalidate>
          <div class="field">
            <label for="register-invite">{t("register.invite")}</label>
            <input
              id="register-invite"
              type="text"
              class="mono"
              autocomplete="off"
              autocapitalize="characters"
              spellcheck="false"
              aria-describedby="register-invite-hint"
              bind:value={inviteCode}
            />
            <p id="register-invite-hint" class="hint">{t("register.invite.hint")}</p>
          </div>
          <div class="field">
            <label for="register-handle">{t("auth.handle")}</label>
            <input
              id="register-handle"
              type="text"
              autocomplete="username"
              autocapitalize="off"
              spellcheck="false"
              maxlength="32"
              aria-describedby="register-handle-hint"
              bind:value={newHandle}
            />
            <p id="register-handle-hint" class="hint">{t("register.handle.hint")}</p>
          </div>
          <div class="field">
            <label for="register-name">{t("register.display_name")}</label>
            <input
              id="register-name"
              type="text"
              autocomplete="name"
              maxlength="64"
              bind:value={displayName}
            />
          </div>
          <div class="field">
            <label for="register-password">{t("auth.password")}</label>
            <input
              id="register-password"
              type="password"
              autocomplete="new-password"
              aria-describedby="register-password-hint register-password-strength"
              aria-invalid={newPassword !== "" && !newPasswordOk}
              bind:value={newPassword}
            />
            <p id="register-password-hint" class="hint">{t("register.password.hint")}</p>
            <PasswordMeter
              id="register-password-strength"
              password={newPassword}
              handle={newHandle}
              {displayName}
              bind:acceptable={newPasswordOk}
            />
          </div>
          <div class="field">
            <label for="register-confirm">{t("register.password.confirm")}</label>
            <input
              id="register-confirm"
              type="password"
              autocomplete="new-password"
              aria-invalid={mismatch}
              aria-describedby="register-confirm-error"
              bind:value={confirmation}
            />
            <p id="register-confirm-error" class="hint" aria-live="polite">
              {mismatch ? t("register.password.mismatch") : ""}
            </p>
          </div>
          <div class="field">
            <button class="primary wide" type="submit" disabled={working || !canRegister}>
              {working ? t("register.working") : t("register.submit")}
            </button>
          </div>
        </form>
      {:else}
        <form onsubmit={recover} novalidate>
          <p class="muted">{t("recover.intro")}</p>
          <div class="field">
            <label for="recover-handle">{t("auth.handle")}</label>
            <input
              id="recover-handle"
              type="text"
              autocomplete="username"
              autocapitalize="off"
              spellcheck="false"
              bind:value={recoverHandle}
            />
          </div>
          <div class="field">
            <label for="recover-key">{t("recover.key")}</label>
            <input
              id="recover-key"
              type="text"
              class="mono"
              autocomplete="off"
              autocapitalize="characters"
              spellcheck="false"
              aria-describedby="recover-key-hint"
              bind:value={recoveryKey}
            />
            <p id="recover-key-hint" class="hint">{t("recover.key.hint")}</p>
          </div>
          <div class="field">
            <label for="recover-password">{t("recover.new_password")}</label>
            <input
              id="recover-password"
              type="password"
              autocomplete="new-password"
              aria-describedby="recover-password-hint recover-password-strength"
              aria-invalid={recoverPassword !== "" && !recoverPasswordOk}
              bind:value={recoverPassword}
            />
            <p id="recover-password-hint" class="hint">{t("register.password.hint")}</p>
            <PasswordMeter
              id="recover-password-strength"
              password={recoverPassword}
              handle={recoverHandle}
              bind:acceptable={recoverPasswordOk}
            />
          </div>
          <div class="field">
            <label for="recover-confirm">{t("register.password.confirm")}</label>
            <input
              id="recover-confirm"
              type="password"
              autocomplete="new-password"
              aria-invalid={recoverMismatch}
              aria-describedby="recover-confirm-error"
              bind:value={recoverConfirmation}
            />
            <p id="recover-confirm-error" class="hint" aria-live="polite">
              {recoverMismatch ? t("register.password.mismatch") : ""}
            </p>
          </div>
          <div class="field">
            <button class="primary wide" type="submit" disabled={working || !canRecover}>
              {working ? t("recover.working") : t("recover.submit")}
            </button>
            <p class="hint">{t("recover.totp_note")}</p>
          </div>
        </form>
      {/if}
    </div>

    <div role="alert">
      {#if error !== null}
        <p class="alert error">{errorMessage(error)}</p>
      {/if}
    </div>
  </section>
</main>
