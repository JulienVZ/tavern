<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // Strength meter for a new password. The score is computed by the Rust
  // core, locally: the password is never sent anywhere.
  import { api, type PasswordStrength } from "./api";
  import { errorMessage, isMessageKey, t } from "./i18n";

  interface Props {
    /** Identifier of the element, referenced by the field's aria-describedby. */
    id: string;
    password: string;
    /** Words an attacker would try first. */
    handle?: string;
    displayName?: string;
    /** Set to true when the password meets the requirement. */
    acceptable?: boolean;
  }

  let {
    id,
    password,
    handle = "",
    displayName = "",
    acceptable = $bindable(false),
  }: Props = $props();

  let strength = $state<PasswordStrength | null>(null);
  let ticket = 0;

  // Debounced, and stale answers are dropped.
  $effect(() => {
    const current = password;
    const context: [string, string] = [handle.trim(), displayName.trim()];
    if (current === "") {
      strength = null;
      acceptable = false;
      return;
    }
    const mine = ++ticket;
    const timer = setTimeout(() => {
      void api.assessPassword(current, context[0], context[1]).then((result) => {
        if (mine === ticket) {
          strength = result;
          acceptable = result.issue === null;
        }
      });
    }, 150);
    return () => clearTimeout(timer);
  });

  function label(score: number): string {
    const key = `register.strength.${score}`;
    return isMessageKey(key) ? t(key) : "";
  }
</script>

<div {id} aria-live="polite">
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
    <span class="small">{label(strength.score)}</span>
    {#if strength.issue !== null}
      <p class="hint">{errorMessage({ code: "weak_password", detail: strength.issue })}</p>
    {/if}
  {/if}
</div>

<style>
  meter {
    width: 8rem;
    height: 0.75rem;
    vertical-align: middle;
    margin: 0.5rem 0.5rem 0 0;
  }
</style>
