<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";

  import { api, type AdminUser, type CommandError, type Invite } from "../lib/api";
  import { errorMessage, formatDate, t } from "../lib/i18n";
  import { guarded, session } from "../lib/session.svelte";

  let invites = $state<Invite[]>([]);
  let users = $state<AdminUser[]>([]);
  let createdCode = $state<string | null>(null);
  let working = $state(false);
  let error = $state<CommandError | null>(null);

  async function run<T>(action: () => Promise<T>): Promise<T | undefined> {
    working = true;
    error = null;
    const result = await guarded(action);
    working = false;
    if (result.ok) {
      return result.value;
    }
    error = result.error;
    return undefined;
  }

  async function load(): Promise<void> {
    const loaded = await run(async () => ({
      invites: await api.adminInvites(),
      users: await api.adminUsers(),
    }));
    if (loaded !== undefined) {
      invites = loaded.invites;
      users = loaded.users;
    }
  }

  async function createInvite(): Promise<void> {
    const created = await run(() => api.adminCreateInvite(null, null));
    if (created !== undefined) {
      createdCode = created.code;
      await load();
    }
  }

  async function revokeInvite(invite: Invite): Promise<void> {
    await run(() => api.adminRevokeInvite(invite.invite_id));
    await load();
  }

  async function setDisabled(user: AdminUser, disabled: boolean): Promise<void> {
    await run(() => api.adminSetUserDisabled(user.user_id, disabled));
    await load();
  }

  async function disableTotp(user: AdminUser): Promise<void> {
    if (!window.confirm(t("admin.users.disable_totp.confirm", { handle: user.handle }))) {
      return;
    }
    await run(() => api.adminDisableUserTotp(user.user_id));
    await load();
  }

  function usable(invite: Invite): boolean {
    return !invite.revoked && invite.uses < invite.max_uses;
  }

  onMount(() => {
    void load();
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
                <button type="button" disabled={working} onclick={() => disableTotp(user)}>
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

  <div role="alert">
    {#if error !== null}
      <p class="alert error">{errorMessage(error)}</p>
    {/if}
  </div>
</section>
