<script lang="ts">
  import { Button, Card, Helper } from "flowbite-svelte";
  import {
    getAuthConfig,
    startAdminSso,
    telegramLogin,
    type AuthConfig,
    type TelegramLoginOutcome,
  } from "$lib/api";
  import { updateMeFromAPI } from "$lib/state.svelte";

  let config = $state<AuthConfig | null>(null);
  let message = $state<string | null>(null);

  $effect(() => {
    getAuthConfig()
      .then((loaded) => {
        config = loaded;
        // A browser that completed an admin SSO login before never sees
        // the login page: it goes straight into the provider, which the
        // friends' browsers cannot even reach. `?sso=skip` is the way out
        // of a failed redirection, linked from the login's error page.
        if (loaded.oidc && loaded.was_admin && !ssoSkipped()) {
          startAdminSso();
        }
      })
      .catch(() => {
        message = "Could not reach the server.";
      });
  });

  function ssoSkipped(): boolean {
    return new URLSearchParams(window.location.search).has("sso");
  }

  // The telegram widget script builds its button at load time, so it can
  // only be injected once the config named the bot.
  $effect(() => {
    if (config?.bot_username) {
      loadTelegramWidget(config.bot_username);
    }
  });

  function loadTelegramWidget(botUsername: string) {
    if (document.getElementById("telegram-login-script")) return;

    (window as unknown as Record<string, unknown>).onTelegramAuth = (
      user: unknown,
    ) => {
      void handleTelegramAuth(user);
    };

    const script = document.createElement("script");
    script.id = "telegram-login-script";
    script.src = "https://telegram.org/js/telegram-widget.js?22";
    script.async = true;
    script.setAttribute("data-telegram-login", botUsername);
    script.setAttribute("data-size", "large");
    script.setAttribute("data-onauth", "onTelegramAuth(user)");
    script.setAttribute("data-request-access", "write");
    document.getElementById("telegram-widget")?.appendChild(script);
  }

  async function handleTelegramAuth(user: unknown) {
    message = null;
    const outcome: TelegramLoginOutcome = await telegramLogin(
      (user as Record<string, unknown>) ?? {},
    );
    switch (outcome.kind) {
      case "session":
        await updateMeFromAPI();
        break;
      case "pending":
        message =
          "You are in the queue and the admin has been notified. If the " +
          "request is not approved within an hour, simply log in again.";
        break;
      case "already_pending":
        message =
          "You are already waiting for approval. Try again once the " +
          "admin has approved you.";
        break;
      case "banned":
        message = "This account is banned.";
        break;
      case "error":
        message = outcome.message;
        break;
    }
  }
</script>

<Card class="p-3">
  <h2 class="mb-6 text-2xl">Login</h2>
  {#if !config}
    <Helper>Loading...</Helper>
  {:else if config.oidc && config.was_admin && !ssoSkipped()}
    <Helper>Redirecting to the login provider...</Helper>
  {:else if config.bot_username}
    <div id="telegram-widget" class="flex min-h-10 items-center justify-center"></div>
  {:else if config.oidc}
    <!-- No telegram login: SSO is the only way into this runner, and the
         only people who log in are on the tailnet, so showing it hides
         nothing and leaves the admin a way in. -->
    <a href="/api/auth/oidc/login">
      <Button>Sign in with SSO</Button>
    </a>
    <Helper class="mt-4 max-w-48 text-center">
      Only reachable from the tailnet.
    </Helper>
  {:else}
    <Helper>No login method is configured on this server.</Helper>
  {/if}
  {#if message}
    <Helper class="mt-4 max-w-64 text-center">{message}</Helper>
  {/if}
</Card>
