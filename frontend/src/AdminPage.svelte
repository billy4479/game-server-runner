<script lang="ts">
  import { Button } from "flowbite-svelte";
  import { getAuthConfig, startAdminSso, type AuthConfig } from "$lib/api";
  import { getLocalMe } from "$lib/state.svelte";
  import AdminPanel from "./AdminPanel.svelte";
  import LoginScreen from "./LoginScreen.svelte";

  let config = $state<AuthConfig | null>(null);

  getAuthConfig().then((loaded) => (config = loaded));

  // What may run on this page. The gate is deliberate: this path exists
  // for the admin alone, so an unauthenticated visitor goes straight into
  // the SSO flow (landing back here through the stored return path), a
  // logged-in non-admin gets bounced to the console, and users never have
  // a reason to see any of it.
  let mode = $derived.by(() => {
    const me = getLocalMe();
    if (me === null) return "loading";
    if (me.isError) {
      if (me.status !== 401) return "error";
      return config?.oidc ? "sso" : "login";
    }
    if (me.user === null) return "loading";
    return me.user.is_admin ? "panel" : "bounce";
  });

  $effect(() => {
    switch (mode) {
      case "sso":
        startAdminSso("/admin");
        break;
      case "bounce":
        window.location.replace("/");
        break;
      default:
        break;
    }
  });
</script>

{#if mode === "panel"}
  <div class="flex w-4/5 max-w-2xl flex-col gap-4">
    <div class="flex items-center justify-between">
      <h2 class="text-2xl">Admin dashboard</h2>
      <Button href="/" size="xs" outline color="light">Back to console</Button>
    </div>
    <AdminPanel />
  </div>
{:else if mode === "loading" || mode === "sso"}
  <div class="text-gray-500">Loading...</div>
{:else if mode === "error"}
  <div>
    <span> An error has occurred </span>
    <pre>{JSON.stringify(getLocalMe()?.error, null, 2)}</pre>
  </div>
{:else}
  <!-- login or bounce: both brief states before a navigation -->
  <LoginScreen />
{/if}
