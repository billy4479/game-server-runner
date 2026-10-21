<script lang="ts">
  import { Button, Card } from "flowbite-svelte";
  import {
    approvePending,
    banUser,
    denyPending,
    listPending,
    listUsers,
    unbanUser,
    type PendingUser,
    type UserRow,
  } from "$lib/api";

  let pending = $state<PendingUser[]>([]);
  let users = $state<UserRow[]>([]);
  let error = $state<string | null>(null);
  let retryTimer: ReturnType<typeof setTimeout> | undefined;

  function describe(pending: PendingUser): string {
    if (pending.username) return `@${pending.username}`;
    if (pending.name) return pending.name;
    return `id ${pending.telegram_id}`;
  }

  async function refresh(retried = false) {
    try {
      [pending, users] = await Promise.all([listPending(), listUsers()]);
      error = null;
    } catch (err) {
      // Every authenticated request rotates the session cookie, and this
      // panel fires alongside the websocket connect: the two can race and
      // one loses its just-rotated token. One retry settles that.
      if (!retried) {
        retryTimer = setTimeout(() => void refresh(true), 400);
        return;
      }
      error = err instanceof Error ? err.message : String(err);
    }
  }

  $effect(() => {
    void refresh();
    return () => clearTimeout(retryTimer);
  });

  async function approve(id: number) {
    await approvePending(id);
    await refresh();
  }

  async function deny(id: number) {
    await denyPending(id);
    await refresh();
  }

  async function ban(id: number) {
    await banUser(id);
    await refresh();
  }

  async function unban(id: number) {
    await unbanUser(id);
    await refresh();
  }
</script>

<Card class="w-full p-3" size="xl">
  <div class="mb-4 flex justify-end">
    <Button size="xs" outline color="light" onclick={() => refresh()}>
      Refresh
    </Button>
  </div>

  {#if error}
    <p class="mb-3 text-red-600">{error}</p>
  {/if}

  <h3 class="mb-2 font-semibold">Registration requests</h3>
  {#if pending.length === 0}
    <p class="mb-4 text-gray-600">No pending requests.</p>
  {:else}
    <ul class="mb-4">
      {#each pending as p (p.telegram_id)}
        <li class="mb-1 flex items-center justify-between gap-4">
          <span class="truncate">
            {describe(p)}
            <span class="text-gray-500">(id {p.telegram_id})</span>
          </span>
          <span class="flex gap-1">
            <Button size="xs" color="green" onclick={() => approve(p.telegram_id)}>
              Approve
            </Button>
            <Button size="xs" color="red" onclick={() => deny(p.telegram_id)}>
              Deny
            </Button>
          </span>
        </li>
      {/each}
    </ul>
  {/if}

  <h3 class="mb-2 font-semibold">Users</h3>
  <ul>
    {#each users as u (u.id)}
      <li class="mb-1 flex items-center justify-between gap-4">
        <span>
          {#if u.id === 0}
            <b>admin</b>
          {:else if u.name}
            {u.name}
          {:else}
            id {u.id}
          {/if}
          {#if u.banned}
            <span class="text-red-600">(banned)</span>
          {/if}
        </span>
        {#if u.id !== 0}
          {#if u.banned}
            <Button size="xs" color="green" onclick={() => unban(u.id)}>
              Unban
            </Button>
          {:else}
            <Button size="xs" color="red" onclick={() => ban(u.id)}>Ban</Button>
          {/if}
        {/if}
      </li>
    {/each}
  </ul>
</Card>
