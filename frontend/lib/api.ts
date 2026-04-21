const BASE = "";

// Access token stored in module-level closure (not sessionStorage) for XSS mitigation.
// Refresh token continues to use HttpOnly cookie (handled by browser automatically).
let accessToken: string | null = null;

const TOKEN_KEY = "owaf_access_token";

export function setAccessToken(t: string | null) {
  accessToken = t;
  if (typeof window !== "undefined") {
    if (t) {
      sessionStorage.setItem(TOKEN_KEY, t);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  }
}

export function getAccessToken(): string | null {
  if (accessToken) return accessToken;
  if (typeof window !== "undefined") {
    const stored = sessionStorage.getItem(TOKEN_KEY);
    if (stored) {
      accessToken = stored;
      return stored;
    }
  }
  return null;
}

export async function refreshAccess(): Promise<boolean> {
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

  // Handle session blacklisted / revoked (401 after refresh failed).
  if (res.status === 401) {
    setAccessToken(null);
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login/?reason=session_expired";
    }
    throw new Error("unauthorized");
  }

  // Handle forbidden (RBAC insufficient permissions).
  if (res.status === 403) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || "access denied: insufficient permissions");
  }

  // Handle rate limiting (brute force lockout).
  if (res.status === 429) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || "too many requests");
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
  const token = getAccessToken();
  await fetch(`${BASE}/api/v1/auth/logout`, {
    method: "POST",
    credentials: "include",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  }).catch(() => {});
  setAccessToken(null);
}

// ── Types ──

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
}

export interface BotSettings {
  enabled: boolean;
  score_threshold: number;
  high_risk_countries: string[];
  datacenter_asns: number[];
  vpn_proxy_asns: number[];
  geoip_db_path: string;
}

export interface BotScoreLog {
  id: number;
  client_ip: string;
  host: string;
  path: string;
  total_score: number;
  geoip_score: number;
  fingerprint_score: number;
  behavior_score: number;
  ip_rep_score: number;
  is_high_risk: boolean;
  action: string;
  details: string;
  created_at: string;
}

export interface BotScoreQuery {
  page?: number;
  page_size?: number;
  min_score?: number;
  max_score?: number;
  ip?: string;
  start_time?: string;
  end_time?: string;
}

export interface FingerprintStats {
  ja3_top: { hash: string; count: number }[];
  ja4_top: { hash: string; count: number }[];
  browser_distribution: { name: string; count: number }[];
  anomalies: { hash: string; reason: string; count: number; last_seen: string }[];
}

export interface CVERule {
  id: number;
  cve_id: string;
  category: string;
  pattern: string;
  target: string;
  severity: string;
  action: string;
  enabled: boolean;
  source: string;
  description: string;
  created_at: string;
}

export interface CreateCVERuleReq {
  cve_id: string;
  category: string;
  pattern: string;
  target: string;
  severity: string;
  action: string;
  description: string;
  enabled?: boolean;
}

export interface CVERuleQuery {
  page?: number;
  page_size?: number;
  category?: string;
  severity?: string;
  enabled?: string;
}

export interface CVEFeedStatus {
  last_sync_time: string;
  last_sync_status: string;
  rules_added: number;
  pending_approval: number;
  error: string;
}

export interface DropPolicy {
  enabled: boolean;
  bot_score_threshold: number;
  cve_auto_drop_critical: boolean;
  cve_auto_drop_high: boolean;
}

export interface DropStats {
  total_dropped: number;
  dropped_by_bot: number;
  dropped_by_cve: number;
  dropped_by_rule: number;
  dropped_by_ip_rep: number;
}

export interface DropEvent {
  id: number;
  client_ip: string;
  source: string;
  rule_id: string;
  detail: string;
  host: string;
  path: string;
  created_at: string;
}

export interface DropEventQuery {
  page?: number;
  page_size?: number;
  ip?: string;
  source?: string;
  start_time?: string;
  end_time?: string;
}

// ── Bot Management API ──

function toParams(obj: Record<string, unknown>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  return p.toString();
}

export async function getBotSettings(): Promise<BotSettings> {
  return api<BotSettings>("/api/v1/bot-settings");
}

export async function updateBotSettings(settings: BotSettings): Promise<void> {
  await api("/api/v1/bot-settings", { method: "PUT", body: JSON.stringify(settings) });
}

export async function getBotScores(params: BotScoreQuery): Promise<PaginatedResponse<BotScoreLog>> {
  const q = toParams(params as Record<string, unknown>);
  return api<PaginatedResponse<BotScoreLog>>(`/api/v1/bot-scores?${q}`);
}

export async function getFingerprints(): Promise<FingerprintStats> {
  return api<FingerprintStats>("/api/v1/fingerprints");
}

// ── CVE Rules API ──

export async function getCVERules(params: CVERuleQuery): Promise<PaginatedResponse<CVERule>> {
  const q = toParams(params as Record<string, unknown>);
  return api<PaginatedResponse<CVERule>>(`/api/v1/cve-rules?${q}`);
}

export async function createCVERule(rule: CreateCVERuleReq): Promise<CVERule> {
  return api<CVERule>("/api/v1/cve-rules", { method: "POST", body: JSON.stringify(rule) });
}

export async function updateCVERule(id: number, rule: Partial<CVERule>): Promise<void> {
  await api(`/api/v1/cve-rules/${id}`, { method: "PUT", body: JSON.stringify(rule) });
}

export async function deleteCVERule(id: number): Promise<void> {
  await api(`/api/v1/cve-rules/${id}`, { method: "DELETE" });
}

export async function toggleCVERule(id: number): Promise<void> {
  await api(`/api/v1/cve-rules/${id}/toggle`, { method: "PUT" });
}

export async function syncCVERules(): Promise<{ message: string }> {
  return api<{ message: string }>("/api/v1/cve-rules/sync", { method: "POST" });
}

export async function getCVEFeedStatus(): Promise<CVEFeedStatus> {
  return api<CVEFeedStatus>("/api/v1/cve-feed/status");
}

// ── Drop Policy API ──

export async function getDropPolicy(): Promise<DropPolicy> {
  return api<DropPolicy>("/api/v1/drop-policy");
}

export async function updateDropPolicy(policy: DropPolicy): Promise<void> {
  await api("/api/v1/drop-policy", { method: "PUT", body: JSON.stringify(policy) });
}

export async function getDropStats(): Promise<DropStats> {
  return api<DropStats>("/api/v1/drop-stats");
}

export async function getDropEvents(params: DropEventQuery): Promise<PaginatedResponse<DropEvent>> {
  const q = toParams(params as Record<string, unknown>);
  return api<PaginatedResponse<DropEvent>>(`/api/v1/drop-events?${q}`);
}
