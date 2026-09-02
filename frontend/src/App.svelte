<script lang="ts">
  import { getLocalMe, updateMeFromAPI } from "$lib/state.svelte";
  import LoginScreen from "./LoginScreen.svelte";
  import MainPage from "./MainPage.svelte";

  $effect(() => {
    updateMeFromAPI();
  });
</script>

<main class="flex h-screen items-center justify-center gap-4">
  {#if getLocalMe() === null}
    Loading...
  {:else if getLocalMe()?.isError}
    {#if getLocalMe()?.status === 401}
      <LoginScreen />
    {:else}
      <div>
        <span> An error has occurred </span>
        <pre>{JSON.stringify(getLocalMe()?.error, null, 2)}</pre>
      </div>
    {/if}
  {:else}
    <MainPage />
  {/if}
</main>
