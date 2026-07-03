/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * API 客户端封装
 * 统一 fetch 调用，处理 JWT 认证、Token 刷新、错误处理
 */

const API_BASE = "/api/v1";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data?: any
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * 获取存储的 access token
 */
function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("token");
}

/**
 * 设置 access token
 */
function setToken(token: string): void {
  if (typeof window === "undefined") return;
  localStorage.setItem("token", token);
}

/**
 * 清除 token
 */
function clearToken(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem("token");
}

/**
 * 刷新 token
 */
async function refreshToken(): Promise<string | null> {
  try {
    const resp = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      credentials: "include",
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (data.access_token) {
      setToken(data.access_token);
      return data.access_token;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * 统一的 API 请求函数
 */
export async function apiRequest<T = any>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${path}`;
  const token = getToken();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const config: RequestInit = {
    ...options,
    headers,
    credentials: "include",
  };

  // 开发模式打印请求
  if (process.env.NODE_ENV === "development") {
    console.log(`[API] ${config.method || "GET"} ${url}`);
  }

  let response = await fetch(url, config);

  // 401 时尝试刷新 token
  if (response.status === 401) {
    const newToken = await refreshToken();
    if (newToken) {
      headers["Authorization"] = `Bearer ${newToken}`;
      config.headers = headers;
      response = await fetch(url, config);
    } else {
      clearToken();
      if (typeof window !== "undefined") {
        window.location.href = "/login";
      }
      throw new ApiError(401, "会话已过期，请重新登录");
    }
  }

  let data: any;
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    data = await response.json();
  } else {
    const text = await response.text();
    data = text ? { text } : null;
  }

  if (!response.ok) {
    const message = data?.error || `请求失败: ${response.status}`;
    throw new ApiError(response.status, message, data);
  }

  return data as T;
}

/**
 * GET 请求快捷方法
 */
export function get<T = any>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const query = params
    ? "?" + Object.entries(params)
        .filter(([, v]) => v !== undefined && v !== "")
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
        .join("&")
    : "";
  return apiRequest<T>(`${path}${query}`);
}

/**
 * POST 请求快捷方法
 */
export function post<T = any>(path: string, body?: any): Promise<T> {
  return apiRequest<T>(path, {
    method: "POST",
    body: body ? JSON.stringify(body) : undefined,
  });
}

/**
 * PUT 请求快捷方法
 */
export function put<T = any>(path: string, body?: any): Promise<T> {
  return apiRequest<T>(path, {
    method: "PUT",
    body: body ? JSON.stringify(body) : undefined,
  });
}

/**
 * DELETE 请求快捷方法
 */
export function del<T = any>(path: string): Promise<T> {
  return apiRequest<T>(path, { method: "DELETE" });
}

/**
 * 认证相关 API
 */
export const authApi = {
  login: (username: string, password: string) =>
    post<{ access_token: string; username: string; role: string }>("/auth/login", { username, password }),
  logout: () => post("/auth/logout"),
  me: () => get<{ username: string; role: string }>("/auth/me"),
};

/**
 * 站点相关 API
 */
export const siteApi = {
  list: (params?: { page?: number; page_size?: number }) =>
    get<{ items: Site[]; total: number }>("/sites", params),
  get: (id: string | number) => get<Site>(`/sites/${id}`),
  create: (data: Partial<Site>) => post<Site>("/sites", data),
  update: (id: string | number, data: Partial<Site>) =>
    post<Site>(`/sites/${id}/update`, data),
  delete: (id: string | number) => post(`/sites/${id}/delete`),
  start: (id: string | number) => post(`/sites/${id}/start`),
  stop: (id: string | number) => post(`/sites/${id}/stop`),
  getStatus: (id: string | number) => get<{ status: string }>(`/sites/${id}/status`),
  getListeners: (id: string | number) => get<{ items: SiteListener[]; total: number }>(`/sites/${id}/listeners`),
  createListener: (id: string | number, data: Partial<SiteListener>) =>
    post(`/sites/${id}/listeners`, data),
  updateListener: (id: string | number, lid: string | number, data: Partial<SiteListener>) =>
    post(`/sites/${id}/listeners/${lid}/update`, data),
  deleteListener: (id: string | number, lid: string | number) =>
    post(`/sites/${id}/listeners/${lid}/delete`),
  getSecurityEvents: (id: string | number, params?: any) =>
    get(`/sites/${id}/security-events`, params),
  getAccessLogs: (id: string | number, params?: any) =>
    get(`/sites/${id}/access-logs`, params),
  getRules: (id: string | number) => get<{ items: Rule[]; total: number; policy_id?: number }>(`/sites/${id}/rules`),
  getRouteRules: (id: string | number) =>
    get<AppRouteRule[]>(`/sites/${id}/application-route-rules`),
  getRecordedResources: (id: string | number) =>
    get<RecordedResource[]>(`/sites/${id}/recorded-resources`),
  getErrorPages: (id: string | number) => get(`/sites/${id}/error-pages`),
  updateErrorPages: (id: string | number, data: any) =>
    post(`/sites/${id}/error-pages`, data),
};

/**
 * 证书相关 API
 */
export const certificateApi = {
  list: () => get<Certificate[]>("/certificates"),
  get: (id: string | number) => get<Certificate>(`/certificates/${id}`),
  create: (data: Partial<Certificate>) => post<Certificate>("/certificates", data),
  update: (id: string | number, data: Partial<Certificate>) =>
    post(`/certificates/${id}/update`, data),
  delete: (id: string | number) => post(`/certificates/${id}/delete`),
  applyToSites: (id: string | number, siteIds: number[]) =>
    post(`/certificates/${id}/apply-to-sites`, { site_ids: siteIds }),
  getACMEConfig: () => get("/certificates/acme/config"),
  updateACMEConfig: (data: any) => post("/certificates/acme/config", data),
  acmeApply: (data: any) => post("/certificates/acme/apply", data),
  acmeRenew: (id: string | number) => post(`/certificates/acme/${id}/renew`),
};

/**
 * 规则相关 API
 */
export const ruleApi = {
  list: (params?: any) => get<{ items: Rule[]; total: number }>("/rules", params),
  get: (id: string | number) => get<Rule>(`/rules/${id}`),
  create: (data: Partial<Rule>) => post<Rule>("/rules", data),
  update: (id: string | number, data: Partial<Rule>) =>
    post(`/rules/${id}/update`, data),
  delete: (id: string | number) => post(`/rules/${id}/delete`),
  test: (data: any) => post("/rules/test", data),
  validate: (data: any) => post("/rules/validate", data),
  import: (data: any) => post("/rules/import", data),
  export: () => get("/rules/export"),
  getTemplates: () => get("/rules/templates"),
};

/**
 * 策略相关 API
 */
export const policyApi = {
  list: () => get<Policy[]>("/policies"),
  get: (id: string | number) => get<Policy>(`/policies/${id}`),
  create: (data: Partial<Policy>) => post<Policy>("/policies", data),
  update: (id: string | number, data: Partial<Policy>) =>
    post(`/policies/${id}/update`, data),
  delete: (id: string | number) => post(`/policies/${id}/delete`),
};

/**
 * 防护设置相关 API
 */
export const protectionApi = {
  getSettings: () => get("/protection-settings"),
  updateSettings: (data: any) => post("/protection-settings", data),
  getSensitivity: (id: string | number) => get(`/protection/${id}/sensitivity`),
  updateSensitivity: (id: string | number, data: any) =>
    post(`/protection/${id}/sensitivity`, data),
  getEscalation: (id: string | number) => get(`/protection/${id}/escalation`),
  updateEscalation: (id: string | number, data: any) =>
    post(`/protection/${id}/escalation`, data),
  getEscalationStatus: (ip: string) => get(`/escalation/status/${ip}`),
  resetEscalation: (ip: string) => post(`/escalation/status/${ip}/reset`),
};

/**
 * IP 列表相关 API
 */
export const ipListApi = {
  list: () => get<{ items: any[]; total: number }>("/ip-lists"),
  get: (id: string | number) => get(`/ip-lists/${id}`),
  create: (data: any) => post("/ip-lists", data),
  update: (id: string | number, data: any) => post(`/ip-lists/${id}/update`, data),
  delete: (id: string | number) => post(`/ip-lists/${id}/delete`),
};

/**
 * 安全事件相关 API
 */
export const securityEventApi = {
  list: (params?: any) =>
    get<{ items: SecurityEvent[]; total: number; page: number }>("/security-events", params),
  get: (id: string | number) => get<SecurityEvent>(`/security-events/${id}`),
  getStats: (params?: any) => get("/security-events/stats", params),
  getTimeline: (params?: any) => get("/security-events/timeline", params),
  getSiteStats: (id: string | number, params?: any) =>
    get(`/sites/${id}/security-events/stats`, params),
  getSiteTimeline: (id: string | number, params?: any) =>
    get(`/sites/${id}/security-events/timeline`, params),
};

/**
 * 访问日志相关 API
 */
export const accessLogApi = {
  list: (params?: any) =>
    get<{ items: AccessLog[]; total: number }>("/access-logs", params),
  get: (id: string | number) => get<AccessLog>(`/access-lists/${id}`),
  getSiteStats: (id: string | number, params?: any) =>
    get(`/sites/${id}/access-logs/stats`, params),
};

/**
 * Dashboard 相关 API
 */
export const dashboardApi = {
  getSummary: () => get<DashboardSummary>("/dashboard/summary"),
};

/**
 * Bot 相关 API
 */
export const botApi = {
  getSettings: () => get("/bot-settings"),
  updateSettings: (data: any) => post("/bot-settings/update", data),
  getStats: () => get("/bot-stats"),
  getScores: () => get("/bot-scores"),
};

/**
 * 验证码相关 API
 */
export const captchaApi = {
  getConfig: () => get("/captcha/config"),
  updateConfig: (data: any) => post("/captcha/config", data),
  test: () => post("/captcha/test"),
};

/**
 * 链式验证相关 API
 */
export const chainApi = {
  getConfig: () => get("/chain/config"),
  updateConfig: (data: any) => post("/chain/config", data),
  getSessions: () => get("/chain/sessions"),
  deleteSession: (id: string | number) => post(`/chain/sessions/${id}/delete`),
};

/**
 * CVE 规则相关 API
 */
export const cveApi = {
  list: () => get("/cve-rules"),
  getStats: () => get("/cve-rules/stats"),
  getFeedStatus: () => get("/cve-feed/status"),
  toggle: (id: string | number) => post(`/cve-rules/${id}/toggle`),
  patch: (id: string | number, data: any) => post(`/cve-rules/${id}/patch`, data),
  batch: (data: any) => post("/cve-rules/batch", data),
  sync: () => post("/cve-rules/sync"),
};

/**
 * OWASP 规则相关 API
 */
export const owaspApi = {
  list: () => get("/owasp-rules"),
  getStats: () => get("/owasp-rules/stats"),
  update: (id: string | number, data: any) => post(`/owasp-rules/${id}/update`, data),
  batch: (data: any) => post("/owasp-rules/batch", data),
};

/**
 * 丢弃策略相关 API
 */
export const dropApi = {
  getPolicy: () => get("/drop-policy"),
  updatePolicy: (data: any) => post("/drop-policy/update", data),
  getStats: () => get("/drop-stats"),
  getEvents: (params?: any) => get("/drop-events", params),
};

/**
 * 系统设置相关 API
 */
export const settingsApi = {
  list: () => get("/settings"),
  get: (key: string) => get(`/settings/${key}`),
  set: (key: string, value: any) => post(`/settings/${key}`, { value }),
  delete: (key: string) => post(`/settings/${key}/delete`),
  getNetwork: () => get("/network-config"),
  updateNetwork: (data: any) => post("/network-config", data),
  getHTTP2: () => get("/http2-config"),
  updateHTTP2: (data: any) => post("/http2-config", data),
  getLog: () => get("/log-config"),
  updateLog: (data: any) => post("/log-config", data),
  getTLS: () => get("/tls-config"),
  updateTLS: (data: any) => post("/tls-config", data),
  getCipherSuites: () => get("/tls-cipher-suites"),
};

/**
 * 上游相关 API
 */
export const upstreamApi = {
  getStatus: () => get("/upstreams/status"),
};

/**
 * 运行时配置相关 API
 */
export const runtimeApi = {
  getConfig: () => get("/runtime-config"),
};

/**
 * API 密钥相关 API
 */
export const apiKeyApi = {
  list: () => get("/api-keys"),
  create: (data: any) => post("/api-keys", data),
  delete: (id: string | number) => post(`/api-keys/${id}/delete`),
};

/**
 * 错误页面相关 API
 */
export const errorPageApi = {
  getDefaults: () => get("/error-pages/defaults"),
  preview: (data: any) => post("/error-pages/preview", data),
};

/**
 * 系统相关 API
 */
export const systemApi = {
  reload: () => post("/reload"),
};

// 引入类型（避免循环依赖，在文件末尾导入类型声明）
import type {
  Site, SiteListener, Certificate, Rule, Policy,
  SecurityEvent, AccessLog, DashboardSummary,
  AppRouteRule, RecordedResource,
} from "./types";
