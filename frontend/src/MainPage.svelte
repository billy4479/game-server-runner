<script lang="ts">
  import { getLocalMe, updateMeFromAPI } from "$lib/state.svelte";
  import { logout } from "$lib/api";
  import { ServerSocket } from "$lib/ws.svelte";

  import { Button } from "flowbite-svelte";

  let consoleOutput: HTMLDivElement;

  let serverSocket = new ServerSocket();

  $effect(() => {
    serverSocket.chatHistory;
    consoleOutput.scrollTo(0, consoleOutput.scrollHeight);
  });

  $effect(() => {
    serverSocket.connect();

    return () => {
      serverSocket.close();
    };
  });

  let timeBeforeStop = $state(0);

  function formatDuration(seconds: number) {
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return [mins, secs].map((v) => (v < 10 ? "0" + v : v)).join(":");
  }

  $effect(() => {
    if (serverSocket.isConnected && serverSocket.serverState?.is_running) {
      const interval = setInterval(() => {
        if (!serverSocket.serverState) return;

        timeBeforeStop =
          serverSocket.serverState?.auto_stop_time * 1000 - Date.now();
      }, 1000);
      return () => clearInterval(interval);
    }
  });
</script>

<div class="flex w-4/5 flex-col gap-4">
  <div class="rounded border border-gray-300">
  <div
    class="flex flex-row items-center justify-between border-b border-gray-300 px-5 py-3"
  >
    <div>
      Welcome <b> {getLocalMe()?.user?.name} </b>

      <span class="text-gray-600">
        - {#if serverSocket.isConnected}
          <b>Connected </b>
          to
          <span class="inline font-mono">
            game-server-runner@{serverSocket.serverState?.version}
          </span>
          for server "<b> {serverSocket.serverState?.server_name} </b>"
        {:else if serverSocket.isConnecting}
          <b> Connecting... </b>
        {:else}
          <b> Disconnected </b>
        {/if}
      </span>
    </div>

    <div>
      {#if getLocalMe()?.user?.is_admin}
        <Button href="/admin" size="xs" outline color="light" class="mr-2">
          Admin dashboard
        </Button>
      {/if}
      <Button
        size="xs"
        outline
        color="light"
        onclick={async () => {
          await logout();
          await updateMeFromAPI();
        }}
      >
        Logout
      </Button>
    </div>
  </div>
  <div class="flex flex-row">
    <div
      bind:this={consoleOutput}
      class="mx-5 my-3 h-64 w-full overflow-scroll rounded border-gray-300 bg-gray-100 px-3 py-2 font-mono text-sm whitespace-pre"
    >
      {#if !serverSocket.serverState?.is_running}
        <div class="relative h-full">
          <div class="blur-sm select-none">
            This is dummy text
            <br />
            if you're reading this
            <br />
            you should reconsider
            <br />
            your life choices.
            <br />
            join the club!
            <br />
            Since you're here though,
            <br />
            tell me something about you're life
            <br />
            how's it going lately?
          </div>
          <div
            class="absolute top-0 left-0 flex h-full w-full items-center justify-center font-sans text-base"
          >
            {#if serverSocket.isConnected}
              The server is not running.
            {:else}
              The server is not connected.
            {/if}
          </div>
        </div>
      {:else}
        {serverSocket.chatHistory}
      {/if}
    </div>
    <div class="border-l border-gray-300"></div>
    <div class="flex w-2/5 flex-col items-center py-3 whitespace-nowrap">
      <Button
        color="green"
        disabled={!serverSocket.serverState ||
          serverSocket.serverState.is_running ||
          !serverSocket.isConnected}
        class="mx-5 mb-3"
        onclick={() => {
          serverSocket.startServer();
        }}
      >
        Start server
      </Button>
      <div class="w-full border-t border-gray-300 px-5 py-3">
        {#if !serverSocket.isConnected}
          The server is not connected.
        {:else if serverSocket.serverState?.is_running}
          {serverSocket.serverState?.online_players.length} players online:
          <ul class="list-inside list-disc break-words whitespace-break-spaces">
            {#each serverSocket.serverState?.online_players as player}
              <li>{player}</li>
            {/each}
          </ul>
          {#if serverSocket.serverState?.online_players.length === 0}
            <b class="break-words whitespace-break-spaces">
              The server will close in {formatDuration(
                Math.floor(timeBeforeStop / 1000),
              )} minutes.
            </b>
          {/if}
        {:else}
          The server is not running.
        {/if}
      </div>
    </div>
  </div>
  </div>
</div>
