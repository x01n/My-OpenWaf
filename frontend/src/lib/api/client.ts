/**
 * API 客户端核心封装。
 *
 * 后端契约（internal/admin/router.go 及各 handler）：
 * - 认证：Authorization: Bearer <JWT|API Key>；refresh token 在 HttpOnly cookie，credentials 需 include
 * - 成功：直接返回数据对象；列表为 { items, total, page? }
 * - 失败：{"error":"..."}，4xx/5xx
 * - 401 时自动尝试 /auth/refresh 一次并重放请求
 */

export class ApiError extends Error {
  status: number;
  /** reload 失败等场景下后端附带的原始负载 */
  payload: unknown;

  constructor(status: number, message: string, payload?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

/** GET /api/v1<path>?query */
export function apiGet<T>(path: string, query?: QueryParams): Promise<T> {
  return request<T>(path, { query });
}

/** POST /api/v1<path>，body 序列化为 JSON */
export function apiPost<T>(path: string, body?: unknown, query?: QueryParams): Promise<T> {
  return request<T>(path, { method: "POST", body, query });
}

const BASE = "/api/v1";

/* ---------- token 存取 ---------- */

const TOKEN_KEY = "owaf_access_token";
const USER_KEY = "owaf_user";

export type CurrentUser = {
  username: string;
  role: "admin" | "operator" | "readonly";
};

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setSession(token: string, user: CurrentUser) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function getUser(): CurrentUser | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as CurrentUser;
  } catch {
    return null;
  }
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

/* ---------- 请求核心 ---------- */

type QueryParams = Record<string, string | number | boolean | undefined | null>;

type RequestOptions = {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  query?: QueryParams;
  body?: unknown;
  /** 401 后不再重试刷新（内部用） */
  _retried?: boolean;
};

function buildUrl(path: string, query?: QueryParams): string {
  const url = BASE + path;
  if (!query) return url;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") {
      params.set(k, String(v));
    }
  }
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

/** 解析后端错误响应为可读消息 */
async function extractError(res: Response): Promise<ApiError> {
  let message = `请求失败（${res.status}）`;
  let payload: unknown;
  try {
    payload = await res.json();
    if (payload && typeof payload === "object" && "error" in payload) {
      message = String((payload as { error: unknown }).error);
    }
  } catch {
    /* 非 JSON 响应，保留默认消息 */
  }
  return new ApiError(res.status, message, payload);
}

/** 会话过期后的统一跳转 */
function redirectToLogin() {
  clearSession();
  window.location.href = "/login";
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", query, body, _retried } = options;

  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  let res: Response;
  try {
    res = await fetch(buildUrl(path, query), {
      method,
      headers,
      credentials: "include",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "网络连接失败，请检查服务是否可达");
  }

  // 会话过期：尝试刷新一次后重放
  if (res.status === 401 && !_retried && path !== "/auth/refresh") {
    const refreshed = await tryRefresh();
    if (refreshed) {
      return request<T>(path, { ...options, _retried: true });
    }
    redirectToLogin();
    throw new ApiError(401, "登录已过期，请重新登录");
  }

  if (!res.ok) {
    throw await extractError(res);
  }

  // 204 无 body
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

async function tryRefresh(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/auth/refresh`, {
      method: "POST",
      credentials: "include",
    });
    if (!res.ok) return false;
    const data = (await res.json()) as LoginResponse;
    setSession(data.access_token, { username: data.username, role: data.role });
    return true;
  } catch {
    return false;
  }
}

/* ---------- 高层方法 ---------- */

export const api = {
  get: <T>(path: string, query?: RequestOptions["query"]) => request<T>(path, { query }),
  post: <T>(path: string, body?: unknown, query?: RequestOptions["query"]) =>
    request<T>(path, { method: "POST", body, query }),
  del: <T>(path: string, body?: unknown) => request<T>(path, { method: "POST", body }),
};

/* ---------- 列表响应通用形状 ---------- */

export type ListResponse<T> = {
  items: T[];
  total: number;
  page?: number;
};

/* ---------- 认证专用 ---------- */

export type LoginResponse = {
  access_token: string;
  expires_at: number;
  username: string;
  role: CurrentUser["role"];
};

export async function login(username: string, password: string): Promise<LoginResponse> {
  const data = await api.post<LoginResponse>("/auth/login", { username, password });
  setSession(data.access_token, { username: data.username, role: data.role });
  return data;
}

export async function logout(): Promise<void> {
  try {
    await fetch(`${BASE}/auth/logout`, { method: "POST", credentials: "include" });
  } finally {
    clearSession();
  }
}

export async function fetchMe(): Promise<CurrentUser> {
  return api.get<CurrentUser>("/auth/me");
}
