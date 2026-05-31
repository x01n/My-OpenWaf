const BASE = ""

let accessToken: string | null = null
const TOKEN_KEY = "owaf_access_token"
let refreshPromise: Promise<boolean> | null = null

export function setAccessToken(token: string | null) {
  accessToken = token
  if (typeof window !== "undefined") {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token)
    } else {
      localStorage.removeItem(TOKEN_KEY)
    }
  }
}

export function getAccessToken(): string | null {
  if (accessToken) return accessToken
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem(TOKEN_KEY)
    if (stored) {
      accessToken = stored
      return stored
    }
  }
  return null
}

export interface AuthResponse {
  access_token: string
  expires_at: number | string
  username: string
  role: string
}

export async function refreshAccess(): Promise<boolean> {
  if (refreshPromise) return refreshPromise

  refreshPromise = (async () => {
    // Retry up to 2 times in case of transient network errors (e.g., server just restarted).
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await fetch(`${BASE}/api/v1/auth/refresh`, {
          method: "POST",
          credentials: "include",
        })
        if (response.ok) {
          const data = (await response.json()) as AuthResponse
          setAccessToken(data.access_token)
          return true
        }
        // 401/403 means refresh token is genuinely invalid — don't retry.
        if (response.status === 401 || response.status === 403) {
          return false
        }
        // 5xx or network issue — wait briefly then retry.
        if (attempt < 1) {
          await new Promise((r) => setTimeout(r, 1000))
        }
      } catch {
        // Network error — wait and retry.
        if (attempt < 1) {
          await new Promise((r) => setTimeout(r, 1000))
        }
      }
    }
    return false
  })()

  try {
    return await refreshPromise
  } finally {
    refreshPromise = null
  }
}

function buildHeaders(opts: RequestInit): Headers {
  const headers = new Headers(opts.headers ?? {})
  if (!headers.has("Content-Type") && opts.body) {
    headers.set("Content-Type", "application/json")
  }
  const token = getAccessToken()
  if (token) {
    headers.set("Authorization", `Bearer ${token}`)
  }
  return headers
}

function shouldIncludeCredentials(path: string): boolean {
  return path.startsWith("/api/v1/auth/")
}

export async function api<T = unknown>(
  path: string,
  opts: RequestInit = {}
): Promise<T> {
  const headers = buildHeaders(opts)
  const credentials = shouldIncludeCredentials(path) ? "include" : "same-origin"

  let response = await fetch(`${BASE}${path}`, {
    ...opts,
    headers,
    credentials,
  })

  if (response.status === 401) {
    const refreshed = await refreshAccess()
    if (refreshed) {
      const retryHeaders = buildHeaders(opts)
      response = await fetch(`${BASE}${path}`, {
        ...opts,
        headers: retryHeaders,
        credentials,
      })
    }
  }

  if (response.status === 401) {
    setAccessToken(null)
    if (
      typeof window !== "undefined" &&
      !window.location.pathname.startsWith("/login")
    ) {
      window.location.href = "/login/?reason=session_expired"
    }
    throw new Error("unauthorized")
  }

  if (response.status === 403) {
    const body = (await response.json().catch(() => ({}))) as { error?: string }
    throw new Error(body.error || "access denied")
  }

  if (response.status === 429) {
    const body = (await response.json().catch(() => ({}))) as { error?: string }
    throw new Error(body.error || "too many requests")
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error?: string }
    throw new Error(body.error || `HTTP ${response.status}`)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return response.json() as Promise<T>
}

export async function login(username: string, password: string) {
  const response = await fetch(`${BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ username, password }),
  })

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error?: string }
    throw new Error(body.error || "login failed")
  }

  const data = (await response.json()) as AuthResponse
  setAccessToken(data.access_token)
  return data
}

export async function logout() {
  const token = getAccessToken()
  await fetch(`${BASE}/api/v1/auth/logout`, {
    method: "POST",
    credentials: "include",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  }).catch(() => undefined)
  setAccessToken(null)
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page?: number
}

export interface Certificate {
  id: number
  name: string
  cert_pem: string
  key_pem: string
  source?: string
  domain?: string
  acme_email?: string
  expires_at?: string
  auto_renew?: boolean
  renew_error?: string
  error?: string
  created_at: string
  updated_at: string
}

export interface Policy {
  id: number
  name: string
  created_at: string
  updated_at: string
}

export async function getCertificates() {
  return api<{ items: Certificate[] }>("/api/v1/certificates")
}

export async function createCertificate(
  payload: Pick<Certificate, "name" | "cert_pem" | "key_pem">
) {
  return api<Certificate>("/api/v1/certificates", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function updateCertificate(
  id: number,
  payload: Pick<Certificate, "name" | "cert_pem" | "key_pem">
) {
  return api<Certificate>(`/api/v1/certificates/${id}/update`, {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function deleteCertificate(id: number) {
  return api(`/api/v1/certificates/${id}/delete`, { method: "POST" })
}

export interface Rule {
  id: number
  name: string
  policy_id: number
  phase: string
  pattern: string
  action: string
  priority: number
  enabled: boolean
  status_code: number
  redirect_to: string
  created_at: string
  updated_at: string
}

export interface SiteCacheRule {
  /** prefix | exact | suffix | contains | regex */
  type?: "prefix" | "exact" | "suffix" | "contains" | "regex" | string
  value?: string
  path?: string
  ttl: number
  /** When true, match and cache key use path only (strip ?query). */
  ignore_query?: boolean
  /** When true, compare using lowercased path/pattern; cache key path segment is lowercased. */
  case_insensitive?: boolean
}

export interface Site {
  id: number
  host: string
  upstream_urls: string
  bind: string
  network: string
  enabled: boolean
  tls_enabled: boolean
  cert_id?: number | null
  min_tls_version?: string
  max_tls_version?: string
  cipher_suites?: string
  alpn?: string
  policy_id?: number | null
  bot_protection_enabled: boolean
  bot_protection_level?: string
  attack_protection_level?: string
  owasp_enabled?: boolean | null
  owasp_sensitivity?: string
  owasp_action?: string
  cve_enabled?: boolean | null
  cve_action?: string
  rate_limit_enabled?: boolean | null
  rate_limit_window?: number
  rate_limit_max?: number
  rate_limit_action?: string
  anti_replay_enabled?: boolean
  anti_replay_ttl?: number
  anti_replay_action?: string
  listener_summary?: string
  tls_summary?: string
  managed_listener_count?: number
  xff_mode?: string
  trusted_cidr?: string
  preserve_original_host?: boolean
  max_body_bytes?: number
  upstream_tls_skip_verify?: boolean
  upstream_tls_server_name?: string
  cache_enabled?: boolean
  cache_default_ttl?: number
  cache_rules?: SiteCacheRule[] | string
  maintenance_enabled: boolean
  maintenance_html?: string
  maintenance_status?: number
  block_html?: string
  block_status?: number
  listener_id?: number
  forwarding_profile_id?: number | null
  inherit_listener_cert?: boolean
  created_at: string
  updated_at: string
}

export interface SiteListener {
  id: number
  site_id: number
  bind: string
  network: string
  tls_enabled: boolean
  cert_id: number | null
  enabled: boolean
  note: string
  created_at: string
  updated_at: string
}

export async function listSiteListeners(
  siteId: number
): Promise<{ items: SiteListener[] }> {
  return api<{ items: SiteListener[] }>(`/api/v1/sites/${siteId}/listeners`)
}

export async function createSiteListener(
  siteId: number,
  data: Partial<SiteListener>
): Promise<SiteListener> {
  return api<SiteListener>(`/api/v1/sites/${siteId}/listeners`, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function updateSiteListener(
  siteId: number,
  listenerId: number,
  data: Partial<SiteListener>
): Promise<SiteListener> {
  return api<SiteListener>(
    `/api/v1/sites/${siteId}/listeners/${listenerId}/update`,
    {
      method: "POST",
      body: JSON.stringify(data),
    }
  )
}

export async function deleteSiteListener(
  siteId: number,
  listenerId: number
): Promise<void> {
  await api(`/api/v1/sites/${siteId}/listeners/${listenerId}/delete`, {
    method: "POST",
  })
}

export interface SiteStatus {
  id: number
  host: string
  status: string
}

export interface SiteAccessLogStats {
  requests: number
  intercepts: number
  observes: number
}

export interface DashboardSummary {
  qps_1s: number
  qps_5s: number
  requests_total: number
  status_2xx: number
  errors_upstream_4xx: number
  errors_upstream_5xx: number
  waf_blocks: number
  waf_observes: number
  builtin_hits: number
  uptime_sec: number
  unique_ips: number
  attack_ips: number
  revision: number
  bot_total_24h: number
  bot_blocked_24h: number
  bot_high_risk_24h: number
  cve_total_24h: number
  cve_by_type_24h: Array<{ category: string; count: number }>
  drop_total_24h: number
  drop_by_source_24h: Record<string, number>
}

export interface UpstreamStatusItem {
  url: string
  healthy: boolean
  fail_count: number
  checked_at?: string
}

export interface UpstreamStatusResponse {
  items: UpstreamStatusItem[]
  total: number
}

export interface SecurityEvent {
  id: number
  site_id?: number
  created_at: string
  request_id: string
  client_ip: string
  host: string
  path: string
  method: string
  user_agent: string
  rule_id: number
  rule_id_str: string
  phase: string
  action: string
  category: string
  match_desc: string
  geo_country: string
  geo_city: string
  status_code: number
}

export interface SecurityStats {
  total: number
  hours: number
  categories: Array<{ category: string; count: number }>
  top_ips: Array<{ client_ip: string; count: number }>
  top_paths: Array<{ path: string; count: number }>
  top_rules: Array<{ rule_id_str: string; count: number }>
}

export interface SiteSecurityStats extends SecurityStats {
  intercepts: number
  observes: number
  requests: number
}

export interface TimelineBucket {
  bucket: string
  count: number
}

export interface AccessLog {
  id: number
  created_at: string
  site_id: number
  request_id: string
  client_ip: string
  host: string
  path: string
  query_string: string
  method: string
  status_code: number
  waf_action: string
  cache_state: string
  upstream: string
  user_agent: string
  http_protocol: string
  tls_version: string
  tls_sni: string
  tls_alpn: string
  tls_ja3: string
  tls_ja3_hash: string
  tls_ja4: string
  header_order: string
  upstream_latency_ms: number
  response_size: number
}

export interface FingerprintSummary {
  tls_ja3_hash: string
  tls_ja4: string
  tls_version: string
  tls_alpn: string
  tls_sni: string
  count: number
  last_seen: string
}

export interface AccessLogQuery {
  page?: number
  page_size?: number
  site_id?: number
  id?: string | number
  request_id?: string
  client_ip?: string
  host?: string
  path?: string
  method?: string
  waf_action?: string
  cache_state?: string
  status_group?: string
  since?: string
  until?: string
}

export interface IPListItem {
  id: number
  kind: "blacklist" | "whitelist" | string
  value: string
  note: string
  action?: "intercept" | "block" | string
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface SystemSetting {
  id: number
  key: string
  value: string
}

export interface EscalationStep {
  threshold: number
  action: string
}

export interface ChainStepConfig {
  type: "env" | "pow" | "captcha" | string
  condition?: string
}

export interface ProtectionSettings {
  request_ratelimit_enabled: boolean
  request_ratelimit_window: number
  request_ratelimit_max: number
  request_ratelimit_action: string
  error_ratelimit_enabled: boolean
  error_ratelimit_window: number
  error_ratelimit_max: number
  error_ratelimit_count_4xx: boolean
  error_ratelimit_count_5xx: boolean
  error_ratelimit_count_block: boolean
  error_ratelimit_action: string
  builtin_owasp_enabled: boolean
  builtin_owasp_sensitivity: string
  builtin_owasp_on_hit: string
  maintenance_global_enabled: boolean
  maintenance_global_html: string
  maintenance_global_status: number
  bot_detection_enabled: boolean
  auto_ban_enabled: boolean
  auto_ban_threshold: number
  auto_ban_window: number
  auto_ban_duration: number
  auto_ban_action?: string
  waiting_room_enabled?: boolean
  cc_use_custom?: boolean
  cc_rules?: unknown[]
  owasp_modules?: Record<string, string>
  cve_enabled: boolean
  cve_action: string
  cve_auto_drop_critical?: boolean
  cve_auto_drop_high?: boolean
  cve_rules_config?: string
  owasp_rules_config?: string
  captcha_enabled?: boolean
  captcha_type?: string
  captcha_timeout?: number
  captcha_pass_ttl?: number
  shield_enabled?: boolean
  shield_difficulty?: number
  shield_timeout_secs?: number
  shield_auto_start_delay?: number
  shield_max_retries?: number
  shield_env_strictness?: number
  shield_require_http2?: boolean
  shield_require_http3?: boolean
  shield_allow_http1?: boolean
  shield_enable_wasm?: boolean
  shield_enable_js_challenge?: boolean
  shield_enable_env_check?: boolean
  shield_enable_devtools?: boolean
  chain_enabled?: boolean
  chain_steps?: ChainStepConfig[] | string
  escalation_enabled?: boolean
  escalation_window_secs?: number
  escalation_steps?: EscalationStep[] | string
  login_min_password_length: number
  login_max_attempts: number
  login_lockout_minutes: number
}

export interface APIKey {
  id: number
  name: string
  token?: string
  created_at: string
  updated_at?: string
  last_used_at?: string | null
}

export interface BotSettings {
  enabled: boolean
  score_threshold: number
  high_risk_countries: string[]
  datacenter_asns: number[]
  vpn_proxy_asns: number[]
  geoip_db_path: string
}

export interface BotScoreLog {
  id: number
  client_ip: string
  host: string
  path: string
  total_score: number
  geoip_score: number
  fingerprint_score: number
  behavior_score: number
  ip_rep_score: number
  is_high_risk: boolean
  action: string
  details: string
  created_at: string
}

export interface BotScoreQuery {
  page?: number
  page_size?: number
  min_score?: number
  max_score?: number
  ip?: string
  start_time?: string
  end_time?: string
}

export interface DropPolicy {
  enabled: boolean
  bot_score_threshold: number
  cve_auto_drop_critical: boolean
  cve_auto_drop_high: boolean
}

export interface DropStats {
  total_24h: number
  by_bot: number
  by_cve: number
  by_rule: number
  by_ip_reputation: number
}

export interface DropEvent {
  id: number
  site_id?: number
  client_ip: string
  source: string
  rule_id: string
  detail: string
  host: string
  path: string
  created_at: string
}

export interface DropEventQuery {
  page?: number
  page_size?: number
  ip?: string
  client_ip?: string
  source?: string
  start_time?: string
  end_time?: string
}

export interface CVERule {
  id: number
  cve_id: string
  category: string
  pattern: string
  target: string
  severity: string
  action: string
  enabled: boolean
  description: string
  source: string
  approved?: boolean
  cvss_score?: number
  cwe_type?: string
  created_at: string
  updated_at?: string
}

export interface CreateCVERuleReq {
  cve_id: string
  category: string
  pattern: string
  target: string
  severity: string
  action: string
  description: string
  enabled?: boolean
}

export interface CVERuleQuery {
  page?: number
  page_size?: number
  category?: string
  severity?: string
  enabled?: string
}

export interface CVEFeedStatus {
  last_sync: string | null
  last_error: string
  syncing: boolean
  pending_review: number
}

export interface SiteRulesResponse {
  items: Rule[]
  total: number
  policy_id?: number
}

export function buildQuery(params: Record<string, unknown>) {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue
    search.set(key, String(value))
  }
  const query = search.toString()
  return query ? `?${query}` : ""
}

export async function getDashboardSummary() {
  return api<DashboardSummary>("/api/v1/dashboard/summary")
}

export async function getUpstreamStatus() {
  return api<UpstreamStatusResponse>("/api/v1/upstreams/status")
}

export async function getSecurityEvents(params: Record<string, unknown>) {
  return api<PaginatedResponse<SecurityEvent>>(
    `/api/v1/security-events${buildQuery(params)}`
  )
}

export async function getSecurityEventStats(hours = 24) {
  return api<SecurityStats>(
    `/api/v1/security-events/stats${buildQuery({ hours })}`
  )
}

export async function getSecurityTimeline(hours = 24) {
  return api<{ buckets: TimelineBucket[] }>(
    `/api/v1/security-events/timeline${buildQuery({ hours })}`
  )
}

export async function getAccessLogs(params: AccessLogQuery = {}) {
  return api<PaginatedResponse<AccessLog>>(
    `/api/v1/access-logs${buildQuery(params as Record<string, unknown>)}`
  )
}

export async function getFingerprints(
  params: { page?: number; page_size?: number } = {}
) {
  return api<PaginatedResponse<FingerprintSummary>>(
    `/api/v1/fingerprints${buildQuery(params)}`
  )
}

export async function getSiteSecurityEvents(
  siteId: string | number,
  params: Record<string, unknown> = {}
) {
  return api<PaginatedResponse<SecurityEvent>>(
    `/api/v1/sites/${siteId}/security-events${buildQuery(params)}`
  )
}

export async function getSiteSecurityStats(
  siteId: string | number,
  hours = 24
) {
  return api<SiteSecurityStats>(
    `/api/v1/sites/${siteId}/security-events/stats${buildQuery({ hours })}`
  )
}

export async function getSiteSecurityTimeline(
  siteId: string | number,
  hours = 24
) {
  return api<{ buckets: TimelineBucket[] }>(
    `/api/v1/sites/${siteId}/security-events/timeline${buildQuery({ hours })}`
  )
}

export async function getSiteAccessLogs(
  siteId: string | number,
  params: AccessLogQuery = {}
) {
  return api<PaginatedResponse<AccessLog>>(
    `/api/v1/sites/${siteId}/access-logs${buildQuery(params as Record<string, unknown>)}`
  )
}

export async function getSiteAccessLogStats(
  siteId: string | number,
  hours = 24
) {
  return api<SiteAccessLogStats>(
    `/api/v1/sites/${siteId}/access-logs/stats${buildQuery({ hours })}`
  )
}

export async function getSiteDropEvents(
  siteId: string | number,
  params: DropEventQuery = {}
) {
  return api<PaginatedResponse<DropEvent>>(
    `/api/v1/sites/${siteId}/drop-events${buildQuery(params as Record<string, unknown>)}`
  )
}

export async function getSiteDropStats(siteId: string | number) {
  return api<DropStats>(`/api/v1/sites/${siteId}/drop-stats`)
}

export async function getSiteRules(siteId: string | number) {
  return api<SiteRulesResponse>(`/api/v1/sites/${siteId}/rules`)
}

export async function listSites(params: Record<string, unknown> = {}) {
  return api<PaginatedResponse<Site>>(`/api/v1/sites${buildQuery(params)}`)
}

export async function getSite(id: string | number) {
  return api<Site>(`/api/v1/sites/${id}`)
}

export async function getSiteStatus(id: string | number) {
  return api<SiteStatus>(`/api/v1/sites/${id}/status`)
}

export async function createSite(payload: Partial<Site>) {
  return api<Site>("/api/v1/sites", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function updateSite(id: string | number, payload: Partial<Site>) {
  return api<Site>(`/api/v1/sites/${id}/update`, {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function deleteSite(id: string | number) {
  return api(`/api/v1/sites/${id}/delete`, { method: "POST" })
}

export async function startSite(id: string | number) {
  return api(`/api/v1/sites/${id}/start`, { method: "POST" })
}

export async function stopSite(id: string | number) {
  return api(`/api/v1/sites/${id}/stop`, { method: "POST" })
}

/** 应用路由：匹配命中后写入 recorded_resources */
export interface ApplicationRouteRule {
  id?: number
  site_id?: number
  name?: string
  enabled?: boolean
  priority?: number
  /** request_header | request_body | response_body | ... */
  target: string
  /** eq | ne | contains | not_contains | prefix | suffix | regex | fuzzy */
  op: string
  pattern: string
  /** target 为 request_header 时必填 */
  header_key?: string
  created_at?: string
  updated_at?: string
}

export interface RecordedResource {
  id: number
  site_id: number
  method: string
  host: string
  path: string
  client_ip?: string
  status_code: number
  content_type?: string
  ja3_hash?: string
  user_agent?: string
  matched_rule_ids?: string
  primary_rule_id?: number
  hit_count: number
  first_seen: string
  last_seen: string
}

export async function listApplicationRouteRules(
  siteId: string | number,
  params: { page?: number; page_size?: number } = {}
) {
  return api<{ items: ApplicationRouteRule[]; total: number; page?: number }>(
    `/api/v1/sites/${siteId}/application-route-rules${buildQuery(params as Record<string, unknown>)}`
  )
}

export async function createApplicationRouteRule(
  siteId: string | number,
  body: Partial<ApplicationRouteRule>
) {
  return api<ApplicationRouteRule>(
    `/api/v1/sites/${siteId}/application-route-rules`,
    {
      method: "POST",
      body: JSON.stringify(body),
    }
  )
}

export async function updateApplicationRouteRule(
  siteId: string | number,
  ruleId: number,
  body: Partial<ApplicationRouteRule>
) {
  return api<ApplicationRouteRule>(
    `/api/v1/sites/${siteId}/application-route-rules/${ruleId}/update`,
    {
      method: "POST",
      body: JSON.stringify(body),
    }
  )
}

export async function deleteApplicationRouteRule(
  siteId: string | number,
  ruleId: number
) {
  return api(
    `/api/v1/sites/${siteId}/application-route-rules/${ruleId}/delete`,
    { method: "POST" }
  )
}

export async function listRecordedResources(
  siteId: string | number,
  params: { page?: number; page_size?: number } = {}
) {
  return api<{ items: RecordedResource[]; total: number; page?: number }>(
    `/api/v1/sites/${siteId}/recorded-resources${buildQuery(params as Record<string, unknown>)}`
  )
}

export async function clearRecordedResources(siteId: string | number) {
  return api(`/api/v1/sites/${siteId}/recorded-resources/clear`, {
    method: "POST",
  })
}

export async function getProtectionSettings() {
  return api<ProtectionSettings>("/api/v1/protection-settings")
}

export async function updateProtectionSettings(payload: ProtectionSettings) {
  return api<ProtectionSettings>("/api/v1/protection-settings", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export interface NetworkConfig {
  ipv6_enabled: boolean
  http2_enabled: boolean
  http3_enabled: boolean
  default_alpn: string
  default_network: string
}

export interface TLSDefaultConfig {
  min_version: string
  max_version: string
  cipher_suites: string
  default_alpn: string
  curve_preferences: string
  prefer_server_cipher_suites: boolean
  self_signed_on_ip: boolean
}

export interface LogConfig {
  level: string
  file_path: string
  also_stdout: boolean
}

export async function getNetworkConfig() {
  return api<NetworkConfig>("/api/v1/network-config")
}

export async function updateNetworkConfig(payload: NetworkConfig) {
  return api<NetworkConfig>("/api/v1/network-config", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function getTLSDefaultConfig() {
  return api<TLSDefaultConfig>("/api/v1/tls-config")
}

export async function updateTLSDefaultConfig(payload: TLSDefaultConfig) {
  return api<TLSDefaultConfig>("/api/v1/tls-config", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function getLogConfig() {
  return api<LogConfig>("/api/v1/log-config")
}

export async function updateLogConfig(payload: LogConfig) {
  return api<LogConfig>("/api/v1/log-config", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function getTLSCipherSuites() {
  return api<{
    secure: Array<{ id: number; name: string }>
    insecure: Array<{ id: number; name: string }>
    curves: Array<{ id: number; name: string }>
  }>("/api/v1/tls-cipher-suites")
}

export async function getACMECertStatus() {
  return api<{
    items: Array<{
      id: number
      name: string
      domain: string
      expires_at?: string
      auto_renew: boolean
      error?: string
      renew_error?: string
    }>
  }>("/api/v1/certificates/acme/status")
}

export async function getSystemSettings() {
  const result = await api<{ items: SystemSetting[] } | SystemSetting[]>(
    "/api/v1/settings"
  )
  return Array.isArray(result) ? result : result.items
}

export async function updateSystemSetting(key: string, value: string) {
  return api<SystemSetting>(`/api/v1/settings/${key}/update`, {
    method: "POST",
    body: JSON.stringify({ key, value }),
  })
}

export async function createSystemSetting(payload: {
  key: string
  value: string
}) {
  return api<SystemSetting>("/api/v1/settings", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function deleteSystemSetting(key: string) {
  return api(`/api/v1/settings/${key}/delete`, { method: "POST" })
}

export async function getAPIKeys() {
  return api<{ items: APIKey[] }>("/api/v1/api-keys")
}

export async function createAPIKey(name: string) {
  return api<APIKey>("/api/v1/api-keys", {
    method: "POST",
    body: JSON.stringify({ name }),
  })
}

export async function removeAPIKey(id: number) {
  return api(`/api/v1/api-keys/${id}/delete`, { method: "POST" })
}

export async function getBotSettings(): Promise<BotSettings> {
  return api<BotSettings>("/api/v1/bot-settings")
}

export async function updateBotSettings(
  settings: BotSettings
): Promise<BotSettings> {
  return api<BotSettings>("/api/v1/bot-settings/update", {
    method: "POST",
    body: JSON.stringify(settings),
  })
}

export async function getBotScores(
  params: BotScoreQuery
): Promise<PaginatedResponse<BotScoreLog>> {
  return api<PaginatedResponse<BotScoreLog>>(
    `/api/v1/bot-scores${buildQuery(params as Record<string, unknown>)}`
  )
}

export async function getCVERules(
  params: CVERuleQuery
): Promise<PaginatedResponse<CVERule>> {
  return api<PaginatedResponse<CVERule>>(
    `/api/v1/cve-rules${buildQuery(params as Record<string, unknown>)}`
  )
}

export async function createCVERule(rule: CreateCVERuleReq): Promise<CVERule> {
  return api<CVERule>("/api/v1/cve-rules", {
    method: "POST",
    body: JSON.stringify(rule),
  })
}

export async function updateCVERule(
  id: number,
  rule: Partial<CVERule | CreateCVERuleReq>
): Promise<CVERule> {
  return api<CVERule>(`/api/v1/cve-rules/${id}/update`, {
    method: "POST",
    body: JSON.stringify(rule),
  })
}

export async function patchCVERule(
  id: number,
  rule: Partial<Pick<CVERule, "enabled" | "action" | "severity">>
): Promise<CVERule> {
  return api<CVERule>(`/api/v1/cve-rules/${id}/patch`, {
    method: "POST",
    body: JSON.stringify(rule),
  })
}

export async function deleteCVERule(id: number): Promise<void> {
  await api(`/api/v1/cve-rules/${id}/delete`, { method: "POST" })
}

export async function toggleCVERule(
  id: number,
  enabled?: boolean
): Promise<void> {
  await api(`/api/v1/cve-rules/${id}/toggle`, {
    method: "POST",
    body: enabled === undefined ? undefined : JSON.stringify({ enabled }),
  })
}

export async function syncCVERules(): Promise<{ message?: string }> {
  return api<{ message?: string }>("/api/v1/cve-rules/sync", { method: "POST" })
}

export async function getCVEFeedStatus(): Promise<CVEFeedStatus> {
  return api<CVEFeedStatus>("/api/v1/cve-feed/status")
}

export async function getDropPolicy(): Promise<DropPolicy> {
  return api<DropPolicy>("/api/v1/drop-policy")
}

export async function updateDropPolicy(
  policy: DropPolicy
): Promise<DropPolicy> {
  return api<DropPolicy>("/api/v1/drop-policy/update", {
    method: "POST",
    body: JSON.stringify(policy),
  })
}

export async function getDropStats(): Promise<DropStats> {
  return api<DropStats>("/api/v1/drop-stats")
}

export async function getDropEvents(
  params: DropEventQuery
): Promise<PaginatedResponse<DropEvent>> {
  return api<PaginatedResponse<DropEvent>>(
    `/api/v1/drop-events${buildQuery(params as Record<string, unknown>)}`
  )
}
