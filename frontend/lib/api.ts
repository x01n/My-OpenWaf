import type { CaptchaType } from "./security-api"

const BASE = ""

let accessToken: string | null = null
const TOKEN_KEY = "owaf_access_token"
const APPLIED_RELOAD_FAILED_WIRE_PREFIX = "config applied but reload failed"
const APPLIED_RELOAD_FAILED_WIRE_DETAIL_PREFIX = `${APPLIED_RELOAD_FAILED_WIRE_PREFIX}: `
const APPLIED_RELOAD_FAILED_MESSAGE_PREFIX =
  "配置已保存，但运行时重新加载失败："
let refreshPromise: Promise<boolean> | null = null

export class ConfigAppliedReloadFailureError extends Error {
  readonly item: unknown
  readonly details: Record<string, unknown> | null

  constructor(
    message: string,
    item?: unknown,
    details?: Record<string, unknown>
  ) {
    super(message)
    this.name = "ConfigAppliedReloadFailureError"
    this.item = item
    this.details = details ?? null
  }
}

export function isConfigAppliedReloadFailureError(
  error: unknown
): error is Error {
  return (
    error instanceof Error &&
    error.message.startsWith(APPLIED_RELOAD_FAILED_MESSAGE_PREFIX)
  )
}

export function getConfigAppliedReloadFailureItem<T>(error: unknown): T | null {
  if (error instanceof ConfigAppliedReloadFailureError) {
    return (error.item ?? null) as T | null
  }
  return null
}

export function getConfigAppliedReloadFailureDetails<T>(
  error: unknown
): T | null {
  if (error instanceof ConfigAppliedReloadFailureError) {
    return (error.details ?? null) as T | null
  }
  return null
}

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

export interface AuthUser {
  username: string
  role: string
}

export interface AuthSession {
  id: number
  username: string
  jti: string
  ip: string
  user_agent: string
  device_info: string
  login_at: string
  last_active_at: string
  expires_at: string
}

export interface AdminHealth {
  status: string
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
    const body = (await response.json().catch(() => ({}))) as Record<
      string,
      unknown
    > & {
      error?: string
      item?: unknown
      imported?: number
      total?: number
      site_refs?: number
      listener_refs?: number
    }
    let message = body.error || `HTTP ${response.status}`
    if (body.error === "certificate is still referenced") {
      message = `证书仍被引用，无法删除（站点 ${body.site_refs ?? 0} 个，监听端口 ${body.listener_refs ?? 0} 个）`
    }
    if (body.error === "policy is still referenced") {
      message = `策略仍被 ${body.site_refs ?? 0} 个站点引用，无法删除`
    }
    if (body.error?.startsWith(APPLIED_RELOAD_FAILED_WIRE_PREFIX)) {
      throw new ConfigAppliedReloadFailureError(
        `${APPLIED_RELOAD_FAILED_MESSAGE_PREFIX}${body.error.replace(APPLIED_RELOAD_FAILED_WIRE_DETAIL_PREFIX, "")}`,
        body.item,
        body
      )
    }
    if (typeof body.imported === "number" && typeof body.total === "number") {
      throw new Error(`${message}（已导入 ${body.imported}/${body.total}）`)
    }
    throw new Error(message)
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

export async function getAdminHealth(): Promise<AdminHealth> {
  return api<AdminHealth>("/api/v1/health")
}

export async function getAuthMe(): Promise<AuthUser> {
  return api<AuthUser>("/api/v1/auth/me")
}

export interface AuthSessionListResponse {
  sessions: AuthSession[]
}

export async function listAuthSessions(all = false) {
  return api<AuthSessionListResponse>(
    `/api/v1/auth/sessions${all ? "?all=true" : ""}`
  )
}

export async function forceLogoutSession(jti: string): Promise<void> {
  await api<OperationStatusResponse>("/api/v1/auth/sessions/force-logout", {
    method: "POST",
    body: JSON.stringify({ jti }),
  })
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page?: number
}

export interface OperationStatusResponse {
  status: string
}

export interface SitePowerResponse {
  status: string
  message: string
}

export interface PaginationQuery {
  page?: number
  page_size?: number
}

export type QueryValue = string | number | boolean | null | undefined

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

export interface ACMEConfig {
  enabled: boolean
  email: string
  directory_url: string
  auto_renew: boolean
  renew_before_days: number
}

export interface CertificateMatchedSite {
  id: number
  host: string
  tls_enabled: boolean
  cert_id?: number
  matched_name: string
}

export interface CertificateParseResponse {
  common_name: string
  dns_names: string[]
  ip_addresses: string[]
  expires_at: string
  matched_sites: CertificateMatchedSite[]
}

export interface CertificateApplyResponse {
  certificate_id: number
  applied_sites: CertificateMatchedSite[]
  site_count: number
  listener_count: number
}

export interface ACMECertStatusItem {
  id: number
  name: string
  domain: string
  expires_at: string | null
  auto_renew: boolean
  error?: string
}

export interface ACMECertStatusResponse {
  items: ACMECertStatusItem[]
}

export type ACMEApplyResponse = Certificate & {
  applied_sites: CertificateMatchedSite[]
  site_count: number
  listener_count: number
}

export interface ACMEApplyRequest {
  domain: string
  email?: string
  name?: string
}

export interface ACMERenewResponse {
  message: string
  domain: string
  expires_at: string
}

export interface Policy {
  id: number
  name: string
  description?: string
  created_at: string
  updated_at: string
}

export interface PolicyPayload {
  name: string
  description?: string
}

export interface RuleTemplate {
  name: string
  description: string
  pattern: string
  category: string
}

export interface RuleValidationResponse {
  valid: boolean
  message?: string
  kind?: string
  arg?: string
  errors?: string[]
}

export interface RuleTestRequest {
  pattern: string
  client_ip?: string
  path?: string
  query?: string
  headers?: Record<string, string>
  method?: string
  body?: string
}

export interface RuleTestResponse {
  matched: boolean
  kind: string
  arg: string
}

export interface RuleImportResponse {
  imported: number
  total: number
}

export interface RuleTemplateListResponse {
  templates: RuleTemplate[]
  total: number
}

export interface RuleExportResponse {
  rules: Rule[]
}

export async function getCertificates(params: PaginationQuery = {}) {
  return api<PaginatedResponse<Certificate>>(
    `/api/v1/certificates${buildQuery(params)}`
  )
}

export async function getCertificate(id: string | number) {
  return api<Certificate>(`/api/v1/certificates/${id}`)
}

export async function listAllCertificates() {
  const pageSize = 200
  let page = 1
  let total = 0
  const items: Certificate[] = []

  do {
    const result = await getCertificates({ page, page_size: pageSize })
    const nextItems = result.items ?? []
    total = Number(result.total) || nextItems.length
    items.push(...nextItems)
    if (nextItems.length === 0) break
    page += 1
  } while (items.length < total)

  return { items, total, page: page - 1 }
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

export async function deleteCertificate(id: number): Promise<void> {
  await api<void>(`/api/v1/certificates/${id}/delete`, { method: "POST" })
}

export async function parseCertificate(certPEM: string) {
  return api<CertificateParseResponse>("/api/v1/certificates/parse", {
    method: "POST",
    body: JSON.stringify({ cert_pem: certPEM }),
  })
}

export async function applyCertificateToSites(id: number) {
  return api<CertificateApplyResponse>(
    `/api/v1/certificates/${id}/apply-to-sites`,
    { method: "POST" }
  )
}

export async function getACMEConfig() {
  return api<ACMEConfig>("/api/v1/certificates/acme/config")
}

export async function updateACMEConfig(payload: Partial<ACMEConfig>) {
  return api<ACMEConfig>("/api/v1/certificates/acme/config", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function applyACMECertificate(payload: ACMEApplyRequest) {
  return api<ACMEApplyResponse>("/api/v1/certificates/acme/apply", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function renewACMECertificate(id: number) {
  return api<ACMERenewResponse>(`/api/v1/certificates/acme/${id}/renew`, {
    method: "POST",
  })
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

export interface RuleQuery {
  page?: number
  page_size?: number
  policy_id?: number
  q?: string
}

export type RulePayload = Partial<
  Pick<
    Rule,
    | "name"
    | "policy_id"
    | "phase"
    | "pattern"
    | "action"
    | "priority"
    | "enabled"
    | "status_code"
    | "redirect_to"
  >
>

export async function getPolicies(params: PaginationQuery = {}) {
  return api<PaginatedResponse<Policy>>(
    `/api/v1/policies${buildQuery(params)}`
  )
}

export async function getPolicy(id: string | number) {
  return api<Policy>(`/api/v1/policies/${id}`)
}

export async function listAllPolicies() {
  const pageSize = 200
  let page = 1
  let total = 0
  const items: Policy[] = []

  do {
    const result = await getPolicies({ page, page_size: pageSize })
    const nextItems = result.items ?? []
    total = Number(result.total) || nextItems.length
    items.push(...nextItems)
    if (nextItems.length === 0) break
    page += 1
  } while (items.length < total)

  return { items, total, page: page - 1 }
}

export async function createPolicy(payload: PolicyPayload) {
  return api<Policy>("/api/v1/policies", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function updatePolicy(id: string | number, payload: PolicyPayload) {
  return api<Policy>(`/api/v1/policies/${id}/update`, {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function deletePolicy(id: string | number): Promise<void> {
  await api<void>(`/api/v1/policies/${id}/delete`, { method: "POST" })
}

export async function getRules(params: RuleQuery = {}) {
  return api<PaginatedResponse<Rule>>(
    `/api/v1/rules${buildQuery(params)}`
  )
}

export async function getRule(id: string | number) {
  return api<Rule>(`/api/v1/rules/${id}`)
}

export async function createRule(payload: RulePayload) {
  return api<Rule>("/api/v1/rules", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function updateRule(id: string | number, payload: RulePayload) {
  return api<Rule>(`/api/v1/rules/${id}/update`, {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function deleteRule(id: string | number): Promise<void> {
  await api<void>(`/api/v1/rules/${id}/delete`, { method: "POST" })
}

export async function importRules(rules: RulePayload[]) {
  return api<RuleImportResponse>("/api/v1/rules/import", {
    method: "POST",
    body: JSON.stringify({ rules }),
  })
}

export async function getRuleTemplates() {
  return api<RuleTemplateListResponse>("/api/v1/rules/templates")
}

export async function exportRules() {
  return api<RuleExportResponse>("/api/v1/rules/export")
}

export async function validateRulePattern(pattern: string) {
  return api<RuleValidationResponse>("/api/v1/rules/validate", {
    method: "POST",
    body: JSON.stringify({ pattern }),
  })
}

export async function testRulePattern(payload: RuleTestRequest) {
  return api<RuleTestResponse>("/api/v1/rules/test", {
    method: "POST",
    body: JSON.stringify(payload),
  })
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
  bot_protection_enabled?: boolean | null
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

export interface SiteListenerListResponse {
  items: SiteListener[]
  total?: number
}

export async function listSiteListeners(siteId: number) {
  return api<SiteListenerListResponse>(`/api/v1/sites/${siteId}/listeners`)
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
  await api<void>(`/api/v1/sites/${siteId}/listeners/${listenerId}/delete`, {
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
  user_agent?: string
  rule_id: number
  rule_id_str: string
  phase: string
  action: string
  category: string
  match_desc: string
  geo_country?: string
  geo_city?: string
  status_code: number
  query_string?: string
  request_headers?: string
  request_body_preview?: string
  request_body_truncated?: boolean
  request_size?: number
  tls_version?: string
  tls_sni?: string
  tls_alpn?: string
  tls_ja3?: string
  tls_ja3_hash?: string
  tls_ja4?: string
  header_order?: string
}

export interface SecurityStats {
  total: number
  hours: number
  categories: Array<{ category: string; count: number }>
  top_ips: Array<{ client_ip: string; count: number }>
  top_paths: Array<{ path: string; count: number }>
  top_rules: Array<{ rule_id_str: string; count: number }>
  intercepts: number
  observes: number
  requests: number
  challenges: number
}

export type SiteSecurityStats = SecurityStats

export interface SecurityEventQuery {
  page?: number
  page_size?: number
  id?: string | number
  request_id?: string
  action?: string
  phase?: string
  category?: string
  client_ip?: string
  host?: string
  path?: string
  rule_id?: string | number
  rule_id_str?: string
  tls_version?: string
  tls_sni?: string
  tls_alpn?: string
  tls_ja3_hash?: string
  tls_ja4?: string
  header_order?: string
  since?: string
  until?: string
}

export interface TimelineBucket {
  bucket: string
  count: number
}

export interface SecurityTimelineResponse {
  buckets: TimelineBucket[]
  hours: number
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
  tls_ja3?: string
  tls_ja3_hash: string
  tls_ja4: string
  header_order: string
  upstream_latency_ms: number
  response_size: number
  request_headers?: string
  request_body_preview?: string
  request_body_truncated?: boolean
  request_size?: number
  response_headers?: string
}

export interface RequestTrace {
  request_id: string
  access_logs: AccessLog[]
  security_events: SecurityEvent[]
}

export interface FingerprintSummary {
  tls_ja3_hash: string
  tls_ja4: string
  tls_version: string
  tls_alpn: string
  tls_sni: string
  count: number
  high_risk_count?: number
  avg_bot_score?: number
  last_seen: string
  last_user_agent?: string
  last_client_ip?: string
  last_header_order?: string
}

export interface AccessLogQuery {
  page?: number
  page_size?: number
  site_id?: string | number
  id?: string | number
  request_id?: string
  client_ip?: string
  host?: string
  path?: string
  method?: string
  waf_action?: string
  cache_state?: string
  status_group?: string
  tls_version?: string
  tls_sni?: string
  tls_alpn?: string
  tls_ja3_hash?: string
  tls_ja4?: string
  since?: string
  until?: string
}

export interface SiteSecurityEventQuery {
  page?: number
  page_size?: number
  request_id?: string
  action?: string
  phase?: string
  category?: string
  client_ip?: string
  path?: string
  tls_version?: string
  tls_sni?: string
  tls_alpn?: string
  tls_ja3_hash?: string
  tls_ja4?: string
  header_order?: string
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

export interface IPListQuery {
  page?: number
  page_size?: number
  kind?: "blacklist" | "whitelist" | string
}

export type IPListPayload = Partial<
  Pick<IPListItem, "kind" | "value" | "note" | "enabled" | "action">
>

export interface SystemSetting {
  id: number
  key: string
  value: string
}

export interface SystemSettingsResponse {
  items: SystemSetting[]
}

export interface EscalationStep {
  threshold: number
  action: string
}

export interface ChainStepConfig {
  type: "env" | "pow" | "captcha"
  condition?: string
  match?: string
  captcha_type?: CaptchaType
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
  category_sensitivity?: Record<string, string>
  cve_enabled: boolean
  cve_action: string
  cve_auto_drop_critical: boolean
  cve_auto_drop_high: boolean
  cve_rules_config?: Record<string, unknown> | string
  owasp_rules_config?: Record<string, unknown> | string
  captcha_enabled?: boolean
  captcha_type?: CaptchaType
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

export interface APIKeyListResponse {
  items: APIKey[]
}

export interface CreateAPIKeyResponse {
  id: number
  name: string
  token: string
}

export interface BotSettings {
  enabled: boolean
  score_threshold: number
  high_risk_countries: string[]
  datacenter_asns: number[]
  vpn_proxy_asns: number[]
  geoip_db_path: string
}

export const defaultBotSettings: BotSettings = {
  enabled: false,
  score_threshold: 60,
  high_risk_countries: [],
  datacenter_asns: [],
  vpn_proxy_asns: [],
  geoip_db_path: "",
}

export function normalizeBotSettings(
  input?: Partial<BotSettings> | null
): BotSettings {
  return {
    enabled: input?.enabled ?? defaultBotSettings.enabled,
    score_threshold:
      input?.score_threshold ?? defaultBotSettings.score_threshold,
    high_risk_countries:
      input?.high_risk_countries ?? defaultBotSettings.high_risk_countries,
    datacenter_asns:
      input?.datacenter_asns ?? defaultBotSettings.datacenter_asns,
    vpn_proxy_asns: input?.vpn_proxy_asns ?? defaultBotSettings.vpn_proxy_asns,
    geoip_db_path: input?.geoip_db_path ?? defaultBotSettings.geoip_db_path,
  }
}

export interface BotScoreLog {
  id: number
  site_id?: number
  request_id?: string
  client_ip: string
  host: string
  path: string
  user_agent?: string
  tls_ja3_hash?: string
  tls_ja4?: string
  tls_version?: string
  tls_sni?: string
  tls_alpn?: string
  header_order?: string
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

export interface BotScoreStats {
  total_24h: number
  blocked_24h: number
  high_risk_24h: number
  avg_score_24h: number
}

export interface BotScoreQuery {
  page?: number
  page_size?: number
  min_score?: number
  max_score?: number
  ip?: string
  host?: string
  path?: string
  user_agent?: string
  request_id?: string
  ja3_hash?: string
  ja4?: string
  tls_sni?: string
  high_risk?: boolean
  start_time?: string
  end_time?: string
}

export interface DropPolicy {
  enabled: boolean
  bot_score_threshold: number
  cve_auto_drop_critical: boolean
  cve_auto_drop_high: boolean
}

export const defaultDropPolicy: DropPolicy = {
  enabled: true,
  bot_score_threshold: 80,
  cve_auto_drop_critical: true,
  cve_auto_drop_high: true,
}

export function normalizeDropPolicy(
  input?: Partial<DropPolicy> | null
): DropPolicy {
  return {
    enabled: input?.enabled ?? defaultDropPolicy.enabled,
    bot_score_threshold:
      input?.bot_score_threshold ?? defaultDropPolicy.bot_score_threshold,
    cve_auto_drop_critical:
      input?.cve_auto_drop_critical ?? defaultDropPolicy.cve_auto_drop_critical,
    cve_auto_drop_high:
      input?.cve_auto_drop_high ?? defaultDropPolicy.cve_auto_drop_high,
  }
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

export interface SiteDropEventQuery {
  page?: number
  page_size?: number
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
  source?: string
}

export interface CVEFeedStatus {
  last_sync: string | null
  last_error: string
  syncing: boolean
  pending_review: number
}

export interface CVERuleSyncResponse {
  message: string
}

export interface CVERuleDeleteResponse {
  message: string
}

export interface CVERuleToggleResponse {
  id: number
  enabled: boolean
  approved: boolean
}

export interface SiteRulesResponse {
  items: Rule[]
  total: number
  policy_id?: number
}

export function buildQuery<T extends object>(
  params: { [K in keyof T]: QueryValue }
) {
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

export async function getSecurityEvents(params: SecurityEventQuery = {}) {
  return api<PaginatedResponse<SecurityEvent>>(
    `/api/v1/security-events${buildQuery(params)}`
  )
}

export async function getSecurityEvent(id: string | number) {
  return api<SecurityEvent>(`/api/v1/security-events/${id}`)
}

export async function getSecurityEventStats(hours = 24) {
  return api<SecurityStats>(
    `/api/v1/security-events/stats${buildQuery({ hours })}`
  )
}

export async function getSecurityTimeline(hours = 24) {
  return api<SecurityTimelineResponse>(
    `/api/v1/security-events/timeline${buildQuery({ hours })}`
  )
}

export async function getAccessLogs(params: AccessLogQuery = {}) {
  return api<PaginatedResponse<AccessLog>>(
    `/api/v1/access-logs${buildQuery(params)}`
  )
}

export async function getAccessLog(id: string | number) {
  return api<AccessLog>(`/api/v1/access-logs/${id}`)
}

export async function getRequestTrace(requestId: string) {
  return api<RequestTrace>(`/api/v1/request/${encodeURIComponent(requestId)}`)
}

export async function getFingerprints(params: PaginationQuery = {}) {
  return api<PaginatedResponse<FingerprintSummary>>(
    `/api/v1/fingerprints${buildQuery(params)}`
  )
}

export async function getIPListEntries(params: IPListQuery = {}) {
  return api<PaginatedResponse<IPListItem>>(
    `/api/v1/ip-lists${buildQuery(params)}`
  )
}

export async function getIPListEntry(id: string | number) {
  return api<IPListItem>(`/api/v1/ip-lists/${id}`)
}

export async function createIPListEntry(payload: IPListPayload) {
  return api<IPListItem>("/api/v1/ip-lists", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function updateIPListEntry(
  id: string | number,
  payload: IPListPayload
) {
  return api<IPListItem>(`/api/v1/ip-lists/${id}/update`, {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function deleteIPListEntry(id: string | number): Promise<void> {
  await api<void>(`/api/v1/ip-lists/${id}/delete`, { method: "POST" })
}

export async function getSiteSecurityEvents(
  siteId: string | number,
  params: SiteSecurityEventQuery = {}
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
  return api<SecurityTimelineResponse>(
    `/api/v1/sites/${siteId}/security-events/timeline${buildQuery({ hours })}`
  )
}

export async function getSiteAccessLogs(
  siteId: string | number,
  params: AccessLogQuery = {}
) {
  return api<PaginatedResponse<AccessLog>>(
    `/api/v1/sites/${siteId}/access-logs${buildQuery(params)}`
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
  params: SiteDropEventQuery = {}
) {
  return api<PaginatedResponse<DropEvent>>(
    `/api/v1/sites/${siteId}/drop-events${buildQuery(params)}`
  )
}

export async function getSiteDropStats(siteId: string | number) {
  return api<DropStats>(`/api/v1/sites/${siteId}/drop-stats`)
}

export async function getSiteRules(siteId: string | number) {
  return api<SiteRulesResponse>(`/api/v1/sites/${siteId}/rules`)
}

export async function listSites(params: PaginationQuery = {}) {
  return api<PaginatedResponse<Site>>(
    `/api/v1/sites${buildQuery(params)}`
  )
}

export async function listAllSites() {
  const pageSize = 200
  let page = 1
  let total = 0
  const items: Site[] = []

  do {
    const result = await listSites({ page, page_size: pageSize })
    const nextItems = result.items ?? []
    total = Number(result.total) || nextItems.length
    items.push(...nextItems)
    if (nextItems.length === 0) break
    page += 1
  } while (items.length < total)

  return { items, total, page: page - 1 }
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

export async function deleteSite(id: string | number): Promise<void> {
  await api<void>(`/api/v1/sites/${id}/delete`, { method: "POST" })
}

export async function startSite(id: string | number) {
  return api<SitePowerResponse>(`/api/v1/sites/${id}/start`, {
    method: "POST",
  })
}

export async function stopSite(id: string | number) {
  return api<SitePowerResponse>(`/api/v1/sites/${id}/stop`, {
    method: "POST",
  })
}

/** 应用路由：匹配命中后写入 recorded_resources */
export interface ApplicationRouteRule {
  id?: number
  site_id?: number
  name?: string
  enabled: boolean
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
  request_headers_json?: string
  response_headers_json?: string
  request_body_snippet?: string
  response_body_snippet?: string
  hit_count: number
  first_seen: string
  last_seen: string
}

export type ApplicationRouteRuleQuery = PaginationQuery
export type ApplicationRouteRuleListResponse =
  PaginatedResponse<ApplicationRouteRule>
export type RecordedResourceQuery = PaginationQuery
export type RecordedResourceListResponse = PaginatedResponse<RecordedResource>

export async function listApplicationRouteRules(
  siteId: string | number,
  params: ApplicationRouteRuleQuery = {}
) {
  return api<ApplicationRouteRuleListResponse>(
    `/api/v1/sites/${siteId}/application-route-rules${buildQuery(params)}`
  )
}

export async function listAllApplicationRouteRules(siteId: string | number) {
  const pageSize = 200
  let page = 1
  let total = 0
  const items: ApplicationRouteRule[] = []

  do {
    const result = await listApplicationRouteRules(siteId, {
      page,
      page_size: pageSize,
    })
    const nextItems = result.items ?? []
    total = Number(result.total) || nextItems.length
    items.push(...nextItems)
    if (nextItems.length === 0) break
    page += 1
  } while (items.length < total)

  return { items, total, page: page - 1 }
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
  return api<OperationStatusResponse>(
    `/api/v1/sites/${siteId}/application-route-rules/${ruleId}/delete`,
    { method: "POST" }
  )
}

export async function listRecordedResources(
  siteId: string | number,
  params: RecordedResourceQuery = {}
) {
  return api<RecordedResourceListResponse>(
    `/api/v1/sites/${siteId}/recorded-resources${buildQuery(params)}`
  )
}

export async function clearRecordedResources(siteId: string | number) {
  return api<OperationStatusResponse>(
    `/api/v1/sites/${siteId}/recorded-resources/clear`,
    {
      method: "POST",
    }
  )
}

export async function getProtectionSettings() {
  return api<ProtectionSettings>("/api/v1/protection-settings")
}

export async function updateProtectionSettings(
  payload: Partial<ProtectionSettings>
) {
  return api<ProtectionSettings>("/api/v1/protection-settings", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export interface NetworkConfig {
  ipv6_enabled: boolean
  http2_enabled: boolean
  http3_enabled: boolean
  http3_bind: string
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

export interface TLSCipherSuiteInfo {
  id: number
  hex_id: string
  name: string
  tls_versions: string[]
  insecure: boolean
}

export interface TLSCurveInfo {
  id: number
  name: string
}

export interface TLSCipherSuitesResponse {
  secure: TLSCipherSuiteInfo[]
  insecure: TLSCipherSuiteInfo[]
  curves: TLSCurveInfo[]
}

export interface LogConfig {
  level: string
  file_path: string
  also_stdout: boolean
}

export interface RuntimeConfig {
  db_driver: string
  db_dsn: string
  log_db_dsn: string
  data_dir: string
  redis_addr: string
  redis_enabled: boolean
  redis_db: number
  admin_bind: string
  admin_static_dir: string
  geoip_db_path: string
  cve_enabled: boolean
  cve_feed_enabled: boolean
  cve_feed_interval: string
  drop_enabled: boolean
  source: string
  editable: boolean
  restart_required: boolean
}

export interface RedisConfig {
  enabled: boolean
  addr: string
  db: number
  password_set: boolean
  source: string
  restart_required: boolean
}

export async function getRuntimeConfig() {
  return api<RuntimeConfig>("/api/v1/runtime-config")
}

export async function reloadRuntimeSnapshot(): Promise<OperationStatusResponse> {
  return api<OperationStatusResponse>("/api/v1/reload", { method: "POST" })
}

export async function getRedisConfig() {
  return api<RedisConfig>("/api/v1/redis-config")
}

export async function updateRedisConfig(
  payload: Partial<Pick<RedisConfig, "enabled" | "addr" | "db">> & {
    password?: string
  }
) {
  return api<RedisConfig>("/api/v1/redis-config", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function getNetworkConfig() {
  return api<NetworkConfig>("/api/v1/network-config")
}

export async function updateNetworkConfig(payload: Partial<NetworkConfig>) {
  return api<NetworkConfig>("/api/v1/network-config", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function getTLSDefaultConfig() {
  return api<TLSDefaultConfig>("/api/v1/tls-config")
}

export async function updateTLSDefaultConfig(
  payload: Partial<TLSDefaultConfig>
) {
  return api<TLSDefaultConfig>("/api/v1/tls-config", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function getLogConfig() {
  return api<LogConfig>("/api/v1/log-config")
}

export async function updateLogConfig(payload: Partial<LogConfig>) {
  return api<LogConfig>("/api/v1/log-config", {
    method: "POST",
    body: JSON.stringify(payload),
  })
}

export async function getTLSCipherSuites() {
  return api<TLSCipherSuitesResponse>("/api/v1/tls-cipher-suites")
}

export async function getACMECertStatus() {
  return api<ACMECertStatusResponse>("/api/v1/certificates/acme/status")
}

export async function getSystemSettings() {
  const result = await api<SystemSettingsResponse>("/api/v1/settings")
  return result.items
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

export async function deleteSystemSetting(key: string): Promise<void> {
  await api<void>(`/api/v1/settings/${key}/delete`, { method: "POST" })
}

export async function getAPIKeys() {
  return api<APIKeyListResponse>("/api/v1/api-keys")
}

export async function createAPIKey(name: string) {
  return api<CreateAPIKeyResponse>("/api/v1/api-keys", {
    method: "POST",
    body: JSON.stringify({ name }),
  })
}

export async function removeAPIKey(id: number): Promise<void> {
  await api<void>(`/api/v1/api-keys/${id}/delete`, { method: "POST" })
}

export async function getBotSettings(): Promise<BotSettings> {
  return normalizeBotSettings(
    await api<Partial<BotSettings>>("/api/v1/bot-settings")
  )
}

export async function updateBotSettings(
  settings: Partial<BotSettings>
): Promise<BotSettings> {
  return normalizeBotSettings(
    await api<Partial<BotSettings>>("/api/v1/bot-settings/update", {
      method: "POST",
      body: JSON.stringify(settings),
    })
  )
}

export async function getBotScores(
  params: BotScoreQuery
): Promise<PaginatedResponse<BotScoreLog>> {
  return api<PaginatedResponse<BotScoreLog>>(
    `/api/v1/bot-scores${buildQuery(params)}`
  )
}

export async function getBotStats(): Promise<BotScoreStats> {
  return api<BotScoreStats>("/api/v1/bot-stats")
}

export async function getCVERules(
  params: CVERuleQuery
): Promise<PaginatedResponse<CVERule>> {
  return api<PaginatedResponse<CVERule>>(
    `/api/v1/cve-rules${buildQuery(params)}`
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

export async function deleteCVERule(id: number): Promise<CVERuleDeleteResponse> {
  return api<CVERuleDeleteResponse>(`/api/v1/cve-rules/${id}/delete`, {
    method: "POST",
  })
}

export async function toggleCVERule(
  id: number,
  enabled?: boolean
): Promise<CVERuleToggleResponse> {
  return api<CVERuleToggleResponse>(`/api/v1/cve-rules/${id}/toggle`, {
    method: "POST",
    body: enabled === undefined ? undefined : JSON.stringify({ enabled }),
  })
}

export async function syncCVERules(): Promise<CVERuleSyncResponse> {
  return api<CVERuleSyncResponse>("/api/v1/cve-rules/sync", { method: "POST" })
}

export async function getCVEFeedStatus(): Promise<CVEFeedStatus> {
  return api<CVEFeedStatus>("/api/v1/cve-feed/status")
}

export async function getDropPolicy(): Promise<DropPolicy> {
  return normalizeDropPolicy(
    await api<Partial<DropPolicy>>("/api/v1/drop-policy")
  )
}

export async function updateDropPolicy(
  policy: Partial<DropPolicy>
): Promise<DropPolicy> {
  return normalizeDropPolicy(
    await api<Partial<DropPolicy>>("/api/v1/drop-policy/update", {
      method: "POST",
      body: JSON.stringify(policy),
    })
  )
}

export async function getDropStats(): Promise<DropStats> {
  return api<DropStats>("/api/v1/drop-stats")
}

export async function getDropEvents(
  params: DropEventQuery
): Promise<PaginatedResponse<DropEvent>> {
  return api<PaginatedResponse<DropEvent>>(
    `/api/v1/drop-events${buildQuery(params)}`
  )
}
