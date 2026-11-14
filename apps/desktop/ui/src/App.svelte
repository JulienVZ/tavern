<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";

  import { onGatewayEvent } from "./lib/api";
  import { handleGatewayEvent, session } from "./lib/session.svelte";
  import Auth from "./screens/Auth.svelte";
  import Home from "./screens/Home.svelte";
  import Instance from "./screens/Instance.svelte";
  import Recovery from "./screens/Recovery.svelte";
  import Totp from "./screens/Totp.svelte";

  onMount(() => {
    const subscription = onGatewayEvent(handleGatewayEvent);
    return () => {
      void subscription.then((unlisten) => unlisten());
    };
  });
</script>

{#if session.screen === "instance"}
  <Instance />
{:else if session.screen === "auth"}
  <Auth />
{:else if session.screen === "recovery"}
  <Recovery />
{:else if session.screen === "totp"}
  <Totp />
{:else}
  <Home />
{/if}
