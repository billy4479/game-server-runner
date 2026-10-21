export async function ping() {
  await fetch("/api/ping")
    .then((res) => res.text())
    .then(console.log);
}

export interface User {
  id: number;
  name: string;
  is_admin: boolean;
}

export interface GetMeResult {
  isError: boolean;
  user: User | null;
  status: number;
  error: any;
}

export interface AuthConfig {
  bot_username: string | null;
  oidc: boolean;
  /** This browser completed an admin SSO login before. */
  was_admin: boolean;
}

/**
 * Send the browser into the admin SSO flow. `returnTo` is stored server
 * side, so the admin lands back on the admin page after the provider.
 */
export function startAdminSso(returnTo?: string) {
  const query = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : "";
  window.location.assign(`/api/auth/oidc/login${query}`);
}

export async function getAuthConfig(): Promise<AuthConfig> {
  const res = await fetch("/api/auth/config");
  if (!res.ok) throw new Error(`could not load the login config: ${res.status}`);
  return res.json();
}

export type TelegramLoginOutcome =
  | { kind: "session" }
  | { kind: "pending" }
  | { kind: "already_pending" }
  | { kind: "banned" }
  | { kind: "error"; message: string };

export async function telegramLogin(
  payload: Record<string, unknown>,
): Promise<TelegramLoginOutcome> {
  const res = await fetch("/api/auth/telegram", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (res.status === 201) return { kind: "session" };
  const body = await res.json().catch(() => ({}) as { error?: string });
  if (res.status === 202) return { kind: "pending" };
  if (res.status === 409) return { kind: "already_pending" };
  if (res.status === 403) return { kind: "banned" };
  return { kind: "error", message: body.error ?? "login failed" };
}

export interface PendingUser {
  telegram_id: number;
  name: string | null;
  username: string | null;
  created: number;
}

export interface UserRow {
  id: number;
  name: string | null;
  telegram_id: number | null;
  banned: boolean;
}

async function adminGet<T>(path: string): Promise<T> {
  const res = await authedFetch(path);
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`);
  return res.json() as Promise<T>;
}

async function adminPost(path: string): Promise<void> {
  const res = await authedFetch(path, { method: "POST" });
  if (!res.ok) throw new Error(`${path} failed: ${res.status}`);
}

// Every authenticated request rotates the session cookie, so two authed
// requests in flight at once always race: whichever lands second carries a
// token the first one already burned. Serializing them keeps the browser
// cookie always current.
let authChain: Promise<unknown> = Promise.resolve();

async function authedFetch(path: string, init?: RequestInit): Promise<Response> {
  const result = authChain.then(() => fetch(path, init), () => fetch(path, init));
  authChain = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

export async function listPending(): Promise<PendingUser[]> {
  return adminGet<PendingUser[]>("/api/admin/pending");
}

export function approvePending(telegramId: number): Promise<void> {
  return adminPost(`/api/admin/pending/${telegramId}/approve`);
}

export function denyPending(telegramId: number): Promise<void> {
  return adminPost(`/api/admin/pending/${telegramId}/deny`);
}

export async function listUsers(): Promise<UserRow[]> {
  return adminGet<UserRow[]>("/api/admin/users");
}

export function banUser(id: number): Promise<void> {
  return adminPost(`/api/admin/users/${id}/ban`);
}

export function unbanUser(id: number): Promise<void> {
  return adminPost(`/api/admin/users/${id}/unban`);
}

export async function getMe(): Promise<GetMeResult> {
  const res = await authedFetch("/api/auth/me");
  const j = await res.json();

  if (!res.ok) {
    return { isError: true, user: null, status: res.status, error: j };
  }

  return { isError: false, user: j, error: null, status: res.status };
}

export async function logout() {
  await authedFetch("/api/auth/logout", {
    method: "DELETE",
  })
    .then((res) => res.json())
    .then(console.log);
}
