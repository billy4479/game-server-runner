export async function ping() {
  await fetch("/api/ping")
    .then((res) => res.text())
    .then(console.log);
}

export interface User {
  id: number;
  name: string;
}

export interface GetMeResult {
  isError: boolean;
  user: User | null;
  status: number;
  error: any;
}

export async function register(token: string, name: string) {
  await fetch("/api/auth/register", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ invitation_token: token, name: name }),
  });
}

export async function login(token: string) {
  await fetch("/api/auth/login", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ login_token: token }),
  });
}

export async function invite() {
  await fetch("/api/auth/invite", {
    method: "POST",
  })
    .then((res) => res.json())
    .then((res) => {
      const token = res.invitation_token;
      console.log(token);
      return navigator.clipboard.writeText(token);
    });
}

export async function addDevice() {
  await fetch("/api/auth/addDevice", { method: "POST" })
    .then((res) => res.json())
    .then((res) => {
      const token = res.login_token;
      console.log(token);
      return navigator.clipboard.writeText(token);
    });
}

export async function getMe(): Promise<GetMeResult> {
  const res = await fetch("/api/auth/me");
  const j = await res.json();

  if (!res.ok) {
    return { isError: true, user: null, status: res.status, error: j };
  }

  return { isError: false, user: j, error: null, status: res.status };
}

export async function logout() {
  await fetch("/api/auth/logout", {
    method: "DELETE",
  })
    .then((res) => res.json())
    .then(console.log);
}
