const BASE = "";

let accessToken: string | null = null;

export function setAccessToken(t: string | null) {
  accessToken = t;
  if (t) sessionStorage.setItem("access_token", t);
  else sessionStorage.removeItem("access_token");
}

export function getAccessToken(): string | null {
  if (accessToken) return accessToken;
  if (typeof window !== "undefined") {
    accessToken = sessionStorage.getItem("access_token");
  }
  return accessToken;
}

async function refreshAccess(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/api/v1/auth/refresh`, {
      method: "POST",
      credentials: "include",
    });
    if (!res.ok) return false;
    const data = await res.json();
    setAccessToken(data.access_token);
    return true;
  } catch {
    return false;
  }
}

export async function api<T = unknown>(
  path: string,
  opts: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers as Record<string, string>),
  };
  const token = getAccessToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers,
    credentials: "include",
  });

  if (res.status === 401 && token) {
    const ok = await refreshAccess();
    if (ok) {
      headers["Authorization"] = `Bearer ${getAccessToken()}`;
      res = await fetch(`${BASE}${path}`, {
        ...opts,
        headers,
        credentials: "include",
      });
    }
  }

  if (res.status === 401) {
    setAccessToken(null);
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login/";
    }
    throw new Error("unauthorized");
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${res.status}`);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

export async function login(username: string, password: string) {
  const res = await fetch(`${BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || "login failed");
  }
  const data = await res.json();
  setAccessToken(data.access_token);
  return data;
}

export async function logout() {
  await fetch(`${BASE}/api/v1/auth/logout`, {
    method: "POST",
    credentials: "include",
  }).catch(() => {});
  setAccessToken(null);
}
