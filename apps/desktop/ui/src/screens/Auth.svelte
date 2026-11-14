<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { api, toCommandError, type CommandError, type PasswordStrength } from "../lib/api";
  import { errorMessage, isMessageKey, t } from "../lib/i18n";
  import { applyLogin, session } from "../lib/session.svelte";

  type Tab = "login" | "register";

  let tab = $state<Tab>("login");
  let working = $state(false);
  let error = $state<CommandError | null>(null);

  // Sign in
  let handle = $state(session.rememberedHandle ?? "");
  let password = $state("");

  // Create an account
  let inviteCode = $state("");
  let newHandle = $state("");
  let displayName = $state("");
  let newPassword = $state("");
  let confirmation = $state("");
  let strength = $state<PasswordStrength | null>(null);

  const mismatch = $derived(confirmation !== "" && confirmation !== newPassword);
  const canRegister = $derived(
    inviteCode.trim() !== "" &&
      newHandle.trim() !== "" &&
      displayName.trim() !== "" &&
      strength !== null &&
      strength.issue === null &&
      confirmation === newPassword,
  );

  // The meter is computed by the Rust core, locally. Debounced so that it
  // does not run on every keystroke; stale answers are dropped.
  let assessment = 0;
  $effect(() => {
    const current = newPassword;
    const context: [string, string] = [newHandle.trim(), displayName.trim()];
    if (current === "") {
      strength = null;
      return;
    }
    const ticket = ++assessment;
    const timer = setTimeout(() => {
      void api.assessPassword(current, context[0], context[1]).then((result) => {
        if (ticket === assessment) {
          strength = result;
        }
      });
    }, 150);
    return () => clearTimeout(timer);
  });

  function select(next: Tab): void {
    tab = next;
    error = null;
  }

  function onTabKey(event: KeyboardEvent): void {
    if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
      select(tab === "login" ? "register" : "login");
      const id = tab === "login" ? "tab-login" : "tab-register";
      document.getElementById(id)?.focus();
    }
  }

  async function login(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (working) {
      return;
    }
    working = true;
    error = null;
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

  function changeInstance(): void {
    session.screen = "instance";
  }

  function strengthLabel(score: number): string {
    const key = `register.strength.${score}`;
    return isMessageKey(key) ? t(key) : "";
  }
</script>

<main class="centered">
  <section class="card stack">
    <p class="muted small row spread">
      <span>{t("auth.on", { instance: session.instanceUrl })}</span>
      <button class="link" type="button" onclick={changeInstance}>{t("instance.change")}</button>
    </p>

    {#if session.endedMessage !== null}
      <p class="alert warn" role="status">{t(session.endedMessage)}</p>
    {/if}

    <div class="row" role="tablist" aria-label={t("app.name")}>
      <button
        id="tab-login"
        type="button"
        role="tab"
        aria-selected={tab === "login"}
        aria-controls="panel-login"
        tabindex={tab === "login" ? 0 : -1}
        class:primary={tab === "login"}
        onclick={() => select("login")}
        onkeydown={onTabKey}
      >
        {t("auth.tab.login")}
      </button>
      <button
        id="tab-register"
        type="button"
        role="tab"
        aria-selected={tab === "register"}
        aria-controls="panel-register"
        tabindex={tab === "register" ? 0 : -1}
        class:primary={tab === "register"}
        onclick={() => select("register")}
        onkeydown={onTabKey}
      >
        {t("auth.tab.register")}
      </button>
    </div>

    {#if tab === "login"}
      <div id="panel-login" role="tabpanel" aria-labelledby="tab-login">
      <form onsubmit={login} novalidate>
        <div class="field">
          <label for="login-handle">{t("auth.handle")}</label>
          <input
            id="login-handle"
            type="text"
            autocomplete="username"
            autocapitalize="off"
            spellcheck="false"
            bind:value={handle}
          />
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
      </div>
    {:else}
      <div id="panel-register" role="tabpanel" aria-labelledby="tab-register">
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
            aria-invalid={strength !== null && strength.issue !== null}
            bind:value={newPassword}
          />
          <p id="register-password-hint" class="hint">{t("register.password.hint")}</p>
          <div id="register-password-strength" aria-live="polite">
            {#if strength !== null}
              <meter
                min="0"
                max="4"
                low="2"
                high="3"
                optimum="4"
                value={strength.score}
                aria-label={t("register.strength")}
              ></meter>
              <span class="small">{strengthLabel(strength.score)}</span>
              {#if strength.issue !== null}
                <p class="hint">
                  {errorMessage({ code: "weak_password", detail: strength.issue })}
                </p>
              {/if}
            {/if}
          </div>
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
      </div>
    {/if}

    <div role="alert">
      {#if error !== null}
        <p class="alert error">{errorMessage(error)}</p>
      {/if}
    </div>
  </section>
</main>

<style>
  meter {
    width: 8rem;
    height: 0.75rem;
    vertical-align: middle;
    margin: 0.5rem 0.5rem 0 0;
  }
</style>
