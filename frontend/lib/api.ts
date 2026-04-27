const BASE = "";

let accessToken: string | null = null;
const TOKEN_KEY = "owaf_access_token";

export function setAccessToken(token: string | null) {
  accessToken = token;
  if (typeof window !== "undefined") {
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
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

export interface AuthResponse {
  access_token: string;
  expires_at: string;
  username: string;
  role: string;
}

export async function refreshAccess(): Promise<boolean> {
  try {
    const response = await fetch(`${BASE}/api/v1/auth/refresh`, {
      method: "POST",
      credentials: "include",
    });
    if (!response.ok) return false;
    const data = (await response.json()) as AuthResponse;
    setAccessToken(data.access_token);
    return true;
  } catch {
    return false;
  }
}

function buildHeaders(opts: RequestInit): Headers {
  const headers = new Headers(opts.headers ?? {});
  if (!headers.has("Content-Type") && opts.body) {
    headers.set("Content-Type", "application/json");
  }
  const token = getAccessToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return headers;
}

export async function api<T = unknown>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers = buildHeaders(opts);

  let response = await fetch(`${BASE}${path}`, {
    ...opts,
    headers,
    credentials: "include",
  });

  if (response.status === 401 && getAccessToken()) {
    const refreshed = await refreshAccess();
    if (refreshed) {
      const retryHeaders = buildHeaders(opts);
      response = await fetch(`${BASE}${path}`, {
        ...opts,
        headers: retryHeaders,
        credentials: "include",
      });
    }
  }

  if (response.status === 401) {
    setAccessToken(null);
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login/?reason=session_expired";
    }
    throw new Error("unauthorized");
  }

  if (response.status === 403) {
    const body = (await response.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error || "access denied");
  }

  if (response.status === 429) {
    const body = (await response.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error || "too many requests");
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error || `HTTP ${response.status}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export async function login(username: string, password: string) {
  const response = await fetch(`${BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error || "login failed");
  }

  const data = (await response.json()) as AuthResponse;
  setAccessToken(data.access_token);
  return data;
}

export async function logout() {
  const token = getAccessToken();
  await fetch(`${BASE}/api/v1/auth/logout`, {
    method: "POST",
    credentials: "include",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  }).catch(() => undefined);
  setAccessToken(null);
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page?: number;
}

export interface Certificate {
  id: number;
  name: string;
  cert_pem: string;
  key_pem: string;
  created_at: string;
  updated_at: string;
}

export interface Policy {
  id: number;
  name: string;
  created_at: string;
  updated_at: string;
}

export interface Rule {
  id: number;
  name: string;
  policy_id: number;
  phase: string;
  pattern: string;
  action: string;
  priority: number;
  enabled: boolean;
  status_code: number;
  redirect_to: string;
  created_at: string;
  updated_at: string;
}

export interface SiteCacheRule {
  path: string;
  ttl: number;
}

export interface Site {
  id: number;
  host: string;
  upstream_urls: string;
  bind: string;
  network: string;
  enabled: boolean;
  tls_enabled: boolean;
  cert_id?: number | null;
  min_tls_version?: string;
  max_tls_version?: string;
  cipher_suites?: string;
  alpn?: string;
  policy_id?: number | null;
  bot_protection_enabled: boolean;
  bot_protection_level?: string;
  attack_protection_level?: string;
  owasp_enabled?: boolean | null;
  owasp_sensitivity?: string;
  owasp_action?: string;
  cve_enabled?: boolean | null;
  cve_action?: string;
  rate_limit_enabled?: boolean | null;
  rate_limit_window?: number;
  rate_limit_max?: number;
  rate_limit_action?: string;
  xff_mode?: string;
  trusted_cidr?: string;
  preserve_original_host?: boolean;
  max_body_bytes?: number;
  upstream_tls_skip_verify?: boolean;
  upstream_tls_server_name?: string;
  cache_enabled?: boolean;
  cache_default_ttl?: number;
  cache_rules?: SiteCacheRule[] | string;
  maintenance_enabled: boolean;
  maintenance_html?: string;
  maintenance_status?: number;
  block_html?: string;
  block_status?: number;
  listener_id?: number;
  forwarding_profile_id?: number | null;
  inherit_listener_cert?: boolean;
  created_at: string;
  updated_at: string;
}

export interface SiteStatus {
  id: number;
  host: string;
  status: string;
}

export interface DashboardSummary {
  qps_1s: number;
  qps_5s: number;
  requests_total: number;
  status_2xx: number;
  errors_upstream_4xx: number;
  errors_upstream_5xx: number;
  waf_blocks: number;
  waf_observes: number;
  builtin_hits: number;
  uptime_sec: number;
  revision: number;
  bot_total_24h: number;
  bot_blocked_24h: number;
  bot_high_risk_24h: number;
  cve_total_24h: number;
  cve_by_type_24h: Array<{ category: string; count: number }>;
  drop_total_24h: number;
  drop_by_source_24h: Record<string, number>;
  fingerprint_anomaly_24h: number;
}

export interface SecurityEvent {
  id: number;
  site_id?: number;
  created_at: string;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  method: string;
  user_agent: string;
  rule_id: number;
  rule_id_str: string;
  phase: string;
  action: string;
  category: string;
  match_desc: string;
  geo_country: string;
  geo_city: string;
  status_code: number;
}

export interface SecurityStats {
  total: number;
  hours: number;
  categories: Array<{ category: string; count: number }>;
  top_ips: Array<{ client_ip: string; count: number }>;
  top_paths: Array<{ path: string; count: number }>;
  top_rules: Array<{ rule_id_str: string; count: number }>;
}

export interface SiteSecurityStats extends SecurityStats {
  intercepts: number;
  observes: number;
  requests: number;
}

export interface TimelineBucket {
  bucket: string;
  count: number;
}

export interface AccessLog {
  id: number;
  created_at: string;
  site_id: number;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  method: string;
  status_code: number;
  waf_action: string;
  cache_state: string;
  upstream: string;
  user_agent: string;
}

export interface AccessLogQuery {
  page?: number;
  page_size?: number;
  site_id?: number;
  client_ip?: string;
  host?: string;
  path?: string;
  method?: string;
  waf_action?: string;
  cache_state?: string;
  since?: string;
  until?: string;
}

export interface IPListItem {
  id: number;
  kind: "blacklist" | "whitelist" | string;
  value: string;
  note: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface SystemSetting {
  id: number;
  key: string;
  value: string;
}

export interface ProtectionSettings {
  request_ratelimit_enabled: boolean;
  request_ratelimit_window: number;
  request_ratelimit_max: number;
  request_ratelimit_action: string;
  error_ratelimit_enabled: boolean;
  error_ratelimit_window: number;
  error_ratelimit_max: number;
  error_ratelimit_count_4xx: boolean;
  error_ratelimit_count_5xx: boolean;
  error_ratelimit_count_block: boolean;
  error_ratelimit_action: string;
  builtin_owasp_enabled: boolean;
  builtin_owasp_sensitivity: string;
  builtin_owasp_on_hit: string;
  maintenance_global_enabled: boolean;
  maintenance_global_html: string;
  maintenance_global_status: number;
  bot_detection_enabled: boolean;
  auto_ban_enabled: boolean;
  auto_ban_threshold: number;
  auto_ban_window: number;
  auto_ban_duration: number;
  waiting_room_enabled?: boolean;
  cc_use_custom?: boolean;
  cc_rules?: unknown[];
  owasp_modules?: Record<string, string>;
  cve_enabled: boolean;
  cve_action: string;
  login_min_password_length: number;
  login_max_attempts: number;
  login_lockout_minutes: number;
}

export interface APIKey {
  id: number;
  name: string;
  token?: string;
  created_at: string;
  updated_at?: string;
  last_used_at?: string | null;
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
  top_ja3: Array<{ ja3_hash: string; count: number; is_known_good: boolean }>;
  browser_distribution: Array<{ browser: string; count: number }>;
  total_count: number;
}

export interface DropPolicy {
  enabled: boolean;
  bot_score_threshold: number;
  cve_auto_drop_critical: boolean;
  cve_auto_drop_high: boolean;
}

export interface DropStats {
  total_24h: number;
  by_bot: number;
  by_cve: number;
  by_rule: number;
  by_ip_reputation: number;
}

export interface DropEvent {
  id: number;
  site_id?: number;
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
  client_ip?: string;
  source?: string;
  start_time?: string;
  end_time?: string;
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
  description: string;
  source: string;
  approved?: boolean;
  cvss_score?: number;
  cwe_type?: string;
  created_at: string;
  updated_at?: string;
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
  last_sync: string | null;
  last_error: string;
  syncing: boolean;
  pending_review: number;
}

export interface SiteRulesResponse {
  items: Rule[];
  total: number;
  policy_id?: number;
}

export function buildQuery(params: Record<string, unknown>) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

export async function getDashboardSummary() {
  return api<DashboardSummary>("/api/v1/dashboard/summary");
}

export async function getSecurityEvents(params: Record<string, unknown>) {
  return api<PaginatedResponse<SecurityEvent>>(`/api/v1/security-events${buildQuery(params)}`);
}

export async function getSecurityEventStats(hours = 24) {
  return api<SecurityStats>(`/api/v1/security-events/stats${buildQuery({ hours })}`);
}

export async function getSecurityTimeline(hours = 24) {
  return api<{ buckets: TimelineBucket[] }>(`/api/v1/security-events/timeline${buildQuery({ hours })}`);
}

export async function getAccessLogs(params: AccessLogQuery = {}) {
  return api<PaginatedResponse<AccessLog>>(`/api/v1/access-logs${buildQuery(params as Record<string, unknown>)}`);
}

export async function getSiteSecurityEvents(siteId: string | number, params: Record<string, unknown> = {}) {
  return api<PaginatedResponse<SecurityEvent>>(`/api/v1/sites/${siteId}/security-events${buildQuery(params)}`);
}

export async function getSiteSecurityStats(siteId: string | number, hours = 24) {
  return api<SiteSecurityStats>(`/api/v1/sites/${siteId}/security-events/stats${buildQuery({ hours })}`);
}

export async function getSiteSecurityTimeline(siteId: string | number, hours = 24) {
  return api<{ buckets: TimelineBucket[] }>(`/api/v1/sites/${siteId}/security-events/timeline${buildQuery({ hours })}`);
}

export async function getSiteAccessLogs(siteId: string | number, params: AccessLogQuery = {}) {
  return api<PaginatedResponse<AccessLog>>(`/api/v1/sites/${siteId}/access-logs${buildQuery(params as Record<string, unknown>)}`);
}

export async function getSiteDropEvents(siteId: string | number, params: DropEventQuery = {}) {
  return api<PaginatedResponse<DropEvent>>(`/api/v1/sites/${siteId}/drop-events${buildQuery(params as Record<string, unknown>)}`);
}

export async function getSiteDropStats(siteId: string | number) {
  return api<DropStats>(`/api/v1/sites/${siteId}/drop-stats`);
}

export async function getSiteRules(siteId: string | number) {
  return api<SiteRulesResponse>(`/api/v1/sites/${siteId}/rules`);
}

export async function listSites(params: Record<string, unknown> = {}) {
  return api<PaginatedResponse<Site>>(`/api/v1/sites${buildQuery(params)}`);
}

export async function getSite(id: string | number) {
  return api<Site>(`/api/v1/sites/${id}`);
}

export async function getSiteStatus(id: string | number) {
  return api<SiteStatus>(`/api/v1/sites/${id}/status`);
}

export async function createSite(payload: Partial<Site>) {
  return api<Site>("/api/v1/sites", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateSite(id: string | number, payload: Partial<Site>) {
  return api<Site>(`/api/v1/sites/${id}/update`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteSite(id: string | number) {
  return api(`/api/v1/sites/${id}/delete`, { method: "POST" });
}

export async function startSite(id: string | number) {
  return api(`/api/v1/sites/${id}/start`, { method: "POST" });
}

export async function stopSite(id: string | number) {
  return api(`/api/v1/sites/${id}/stop`, { method: "POST" });
}

export async function getProtectionSettings() {
  return api<ProtectionSettings>("/api/v1/protection-settings");
}

export async function updateProtectionSettings(payload: ProtectionSettings) {
  return api<ProtectionSettings>("/api/v1/protection-settings", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getSystemSettings() {
  const result = await api<{ items: SystemSetting[] } | SystemSetting[]>("/api/v1/settings");
  return Array.isArray(result) ? result : result.items;
}

export async function updateSystemSetting(key: string, value: string) {
  return api<SystemSetting>(`/api/v1/settings/${key}/update`, {
    method: "POST",
    body: JSON.stringify({ key, value }),
  });
}

export async function createSystemSetting(payload: { key: string; value: string }) {
  return api<SystemSetting>("/api/v1/settings", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteSystemSetting(key: string) {
  return api(`/api/v1/settings/${key}/delete`, { method: "POST" });
}

export async function getAPIKeys() {
  return api<{ items: APIKey[] }>("/api/v1/api-keys");
}

export async function createAPIKey(name: string) {
  return api<APIKey>("/api/v1/api-keys", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

export async function removeAPIKey(id: number) {
  return api(`/api/v1/api-keys/${id}/delete`, { method: "POST" });
}

export async function getBotSettings(): Promise<BotSettings> {
  return api<BotSettings>("/api/v1/bot-settings");
}

export async function updateBotSettings(settings: BotSettings): Promise<BotSettings> {
  return api<BotSettings>("/api/v1/bot-settings/update", {
    method: "POST",
    body: JSON.stringify(settings),
  });
}

export async function getBotScores(params: BotScoreQuery): Promise<PaginatedResponse<BotScoreLog>> {
  return api<PaginatedResponse<BotScoreLog>>(`/api/v1/bot-scores${buildQuery(params as Record<string, unknown>)}`);
}

export async function getFingerprints(): Promise<FingerprintStats> {
  return api<FingerprintStats>("/api/v1/fingerprints");
}

export async function getCVERules(params: CVERuleQuery): Promise<PaginatedResponse<CVERule>> {
  return api<PaginatedResponse<CVERule>>(`/api/v1/cve-rules${buildQuery(params as Record<string, unknown>)}`);
}

export async function createCVERule(rule: CreateCVERuleReq): Promise<CVERule> {
  return api<CVERule>("/api/v1/cve-rules", {
    method: "POST",
    body: JSON.stringify(rule),
  });
}

export async function updateCVERule(id: number, rule: Partial<CVERule | CreateCVERuleReq>): Promise<CVERule> {
  return api<CVERule>(`/api/v1/cve-rules/${id}/update`, {
    method: "POST",
    body: JSON.stringify(rule),
  });
}

export async function deleteCVERule(id: number): Promise<void> {
  await api(`/api/v1/cve-rules/${id}/delete`, { method: "POST" });
}

export async function toggleCVERule(id: number): Promise<void> {
  await api(`/api/v1/cve-rules/${id}/toggle`, { method: "POST" });
}

export async function syncCVERules(): Promise<{ message?: string }> {
  return api<{ message?: string }>("/api/v1/cve-rules/sync", { method: "POST" });
}

export async function getCVEFeedStatus(): Promise<CVEFeedStatus> {
  return api<CVEFeedStatus>("/api/v1/cve-feed/status");
}

export async function getDropPolicy(): Promise<DropPolicy> {
  return api<DropPolicy>("/api/v1/drop-policy");
}

export async function updateDropPolicy(policy: DropPolicy): Promise<DropPolicy> {
  return api<DropPolicy>("/api/v1/drop-policy/update", {
    method: "POST",
    body: JSON.stringify(policy),
  });
}

export async function getDropStats(): Promise<DropStats> {
  return api<DropStats>("/api/v1/drop-stats");
}

export async function getDropEvents(params: DropEventQuery): Promise<PaginatedResponse<DropEvent>> {
  return api<PaginatedResponse<DropEvent>>(`/api/v1/drop-events${buildQuery(params as Record<string, unknown>)}`);
}
