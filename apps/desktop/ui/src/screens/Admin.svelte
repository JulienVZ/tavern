<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";

  import { api, type AdminUser, type CommandError, type Invite } from "../lib/api";
  import ConfirmDialog from "../lib/ConfirmDialog.svelte";
  import { errorMessage, formatDate, t } from "../lib/i18n";
  import { guarded, session } from "../lib/session.svelte";

  let invites = $state<Invite[]>([]);
  let users = $state<AdminUser[]>([]);
  let createdCode = $state<string | null>(null);
  let working = $state(false);
  let error = $state<CommandError | null>(null);
  /** Confirmation of the last action that succeeded. */
  let done = $state<string | null>(null);
  /** The account whose TOTP removal awaits confirmation. */
  let totpTarget = $state<AdminUser | null>(null);

  /**
   * Refreshes both lists. A failure is shown unless an action already
   * reported one: the outcome of the action must stay on screen.
   */
  async function reload(): Promise<void> {
    const loaded = await guarded(async () => ({
      invites: await api.adminInvites(),
      users: await api.adminUsers(),
    }));
    if (loaded.ok) {
      invites = loaded.value.invites;
      users = loaded.value.users;
    } else if (error === null) {
      error = loaded.error;
    }
  }

  /**
   * Runs an action, then shows either `success` or the error, and refreshes
   * the lists. Returns the value of the action, or `null` if it failed.
   */
  async function act<T>(action: () => Promise<T>, success: string | null): Promise<T | null> {
    working = true;
    error = null;
    done = null;
    const result = await guarded(action);
    if (result.ok) {
      done = success;
    } else {
      error = result.error;
    }
    await reload();
    working = false;
    return result.ok ? result.value : null;
  }

  async function createInvite(): Promise<void> {
    // The code itself is the confirmation.
    const created = await act(() => api.adminCreateInvite(null, null), null);
    if (created !== null) {
      createdCode = created.code;
    }
  }

  async function revokeInvite(invite: Invite): Promise<void> {
    await act(() => api.adminRevokeInvite(invite.invite_id), t("admin.invites.revoked.done"));
  }

  async function setDisabled(user: AdminUser, disabled: boolean): Promise<void> {
    await act(
      () => api.adminSetUserDisabled(user.user_id, disabled),
      t(disabled ? "admin.users.disable.done" : "admin.users.enable.done", {
        handle: user.handle,
      }),
    );
  }

  async function disableTotp(): Promise<void> {
    const user = totpTarget;
    totpTarget = null;
    if (user === null) {
      return;
    }
    await act(
      () => api.adminDisableUserTotp(user.user_id),
      t("admin.users.disable_totp.done", { handle: user.handle }),
    );
  }

  function usable(invite: Invite): boolean {
    return !invite.revoked && invite.uses < invite.max_uses;
  }

  onMount(() => {
    void reload();
  });
</script>

<section class="stack" aria-labelledby="admin-title">
  <h2 id="admin-title">{t("admin.title")}</h2>

  <div class="stack">
    <div class="row spread">
      <h3>{t("admin.invites.title")}</h3>
      <button type="button" disabled={working} onclick={createInvite}>
        {t("admin.invites.create")}
      </button>
    </div>
    {#if createdCode !== null}
      <div class="alert warn" role="status">
        <p>{t("admin.invites.created")}</p>
        <code class="secret">{createdCode}</code>
        <p class="hint">
          <button type="button" onclick={() => (createdCode = null)}>{t("common.close")}</button>
        </p>
      </div>
    {/if}
    {#if invites.length === 0}
      <p class="muted small">{t("admin.invites.empty")}</p>
    {:else}
      <ul class="plain">
        {#each invites as invite (invite.invite_id)}
          <li class="row spread">
            <span class="small">
              {t("admin.invites.uses", { uses: invite.uses, max: invite.max_uses })}{#if invite.expires_at_ms !== null},
                {t("admin.invites.expires", { date: formatDate(invite.expires_at_ms) })}{/if}
              {#if invite.grants_admin}
                <span class="badge neutral">{t("admin.invites.grants_admin")}</span>
              {/if}
              {#if invite.revoked}
                <span class="badge neutral">{t("admin.invites.revoked")}</span>
              {/if}
            </span>
            {#if usable(invite)}
              <button class="danger" type="button" disabled={working} onclick={() => revokeInvite(invite)}>
                {t("admin.invites.revoke")}
              </button>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </div>

  <div class="stack">
    <h3>{t("admin.users.title")}</h3>
    <ul class="plain">
      {#each users as user (user.user_id)}
        <li class="row spread">
          <div>
            <strong>{user.display_name}</strong> <span class="muted">@{user.handle}</span>
            {#if user.is_admin}<span class="badge">{t("home.admin_badge")}</span>{/if}
            {#if user.disabled}<span class="badge neutral">{t("admin.users.disabled")}</span>{/if}
            {#if user.totp_enabled}<span class="badge neutral">{t("admin.users.totp")}</span>{/if}
            <br />
            <span class="muted small">{t("admin.users.devices", { count: user.device_count })}</span>
          </div>
          {#if user.user_id !== session.account?.userId}
            <div class="row">
              {#if user.totp_enabled}
                <button type="button" disabled={working} onclick={() => (totpTarget = user)}>
                  {t("admin.users.disable_totp")}
                </button>
              {/if}
              {#if user.disabled}
                <button type="button" disabled={working} onclick={() => setDisabled(user, false)}>
                  {t("admin.users.enable")}
                </button>
              {:else}
                <button class="danger" type="button" disabled={working} onclick={() => setDisabled(user, true)}>
                  {t("admin.users.disable")}
                </button>
              {/if}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  </div>

  <div role="status">
    {#if done !== null}
      <p class="alert">{done}</p>
    {/if}
  </div>
  <div role="alert">
    {#if error !== null}
      <p class="alert error">{errorMessage(error)}</p>
    {/if}
  </div>
</section>

{#if totpTarget !== null}
  <ConfirmDialog
    title={t("admin.users.disable_totp")}
    message={t("admin.users.disable_totp.confirm", { handle: totpTarget.handle })}
    confirmLabel={t("admin.users.disable_totp")}
    onconfirm={disableTotp}
    oncancel={() => (totpTarget = null)}
  />
{/if}
