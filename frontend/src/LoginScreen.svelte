<script lang="ts">
  import { Button, Card, Label, Helper, Input } from "flowbite-svelte";
  import { register, login } from "$lib/api";
  import { updateMeFromAPI } from "$lib/state.svelte";

  async function submitRegistration(event: Event) {
    event.preventDefault();

    const data = new FormData(event.target as HTMLFormElement);
    await register(data.get("token") as string, data.get("name") as string);
    await updateMeFromAPI();
  }

  async function submitLogin(event: Event) {
    event.preventDefault();

    const data = new FormData(event.target as HTMLFormElement);
    await login(data.get("token") as string);
    await updateMeFromAPI();
  }
</script>

<div class="flex flex-row gap-4">
  <Card class="p-3">
    <h2 class="mb-6 text-2xl">Register</h2>
    <form
      action=""
      onsubmit={submitRegistration}
      class="flex h-full flex-col items-start gap-3"
    >
      <div>
        <Label for="name">Name</Label>
        <Input placeholder="Name" name="name" id="name" />
        <Helper>A name of your choice.</Helper>
      </div>
      <div class="mb-6">
        <Label for="token">Token</Label>
        <Input placeholder="Token" name="token" id="token" />
        <Helper>This should have been given to you by the admin.</Helper>
      </div>
      <Button type="submit" class="mt-auto">Register</Button>
    </form>
  </Card>
  <Card class="p-3">
    <h2 class="mb-6 text-2xl">Login</h2>
    <form
      action=""
      onsubmit={submitLogin}
      class="flex h-full flex-col items-start"
    >
      <div class="mb-6">
        <Label for="token">Token</Label>
        <Input placeholder="Token" name="token" id="token" />
        <Helper>
          You can generate one from a device you are logged in already. If you
          have lost access to all your devices contact the admin.
        </Helper>
      </div>
      <Button type="submit" class="mt-auto">Login</Button>
    </form>
  </Card>
</div>
