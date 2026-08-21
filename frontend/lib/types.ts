/**
 * TypeScript 类型定义
 * 从后端模型（internal/store/*.go）映射
 */

export interface PaginationResponse<T> {
  items: T[]
  total: number
  page?: number
}

export const SiteXFFMode = {
  Strip: "strip_all_and_set_remote",
  TrustOuter: "trust_outer_waf_cidr_then_take_leftmost",
} as const

export type SiteXFFMode = (typeof SiteXFFMode)[keyof typeof SiteXFFMode]

/** 可按路径跳过的 pipeline phase，精确对齐 store.SkipPathPhaseKeys()。 */
export type SkipPathPhase =
  | "ip_reputation"
  | "anti_replay"
  | "acl"
  | "lua_pre"
  | "owasp_default"
  | "cve_detection"
  | "bot_detection"
  | "browser_sign"
  | "rate_limit"

/** phase 到路径列表的稀疏映射。 */
export type SkipPathByPhase = Partial<Record<SkipPathPhase, string[]>>

export interface Site {
  id: number
  created_at: string
  updated_at: string

  host: string
  upstream_urls: string
  upstream_host?: string

  bind: string
  network?: string
  enabled: boolean

  tls_enabled: boolean
  cert_id?: number
  min_tls_version?: string
  max_tls_version?: string
  cipher_suites?: string
  alpn?: string

  policy_id?: number
  bot_protection_enabled?: boolean | null
  bot_protection_level?: string
  attack_protection_level?: string

  anti_replay_enabled: boolean
  anti_replay_ttl: number
  anti_replay_action: string

  owasp_enabled?: boolean | null
  owasp_sensitivity?: string
  owasp_action?: string
  cve_enabled?: boolean | null
  cve_action?: string
  rate_limit_enabled?: boolean | null
  rate_limit_window: number
  rate_limit_max: number
  rate_limit_action?: string

  /** null/undefined = 继承全局；"{}" 或 {} = 显式不跳过；其余值 = 整体覆盖。 */
  skip_path_by_phase?: SkipPathByPhase | string | null

  xff_mode: SiteXFFMode
  trusted_cidr: string
  client_ip_header_order?: string[]
  preserve_original_host: boolean

  max_body_bytes: number
  upstream_tls_skip_verify: boolean
  upstream_tls_server_name?: string

  cache_enabled: boolean
  cache_default_ttl: number
  cache_rules?: string

  maintenance_enabled: boolean
  maintenance_html?: string
  maintenance_status: number

  block_html?: string
  block_status: number

  custom_error_pages?: string

  // 动态保护站点级覆盖（null/undefined = 继承全局）
  dynamic_protection_enabled?: boolean | null
  dynamic_html_enabled?: boolean | null
  dynamic_js_enabled?: boolean | null
  dynamic_js_mode?: string
  dynamic_js_paths?: string | string[] // JSON 数组字符串
  dynamic_decrypt_cache_ttl?: number | null

  // 站点级 CC 规则覆盖（null/undefined = 继承全局；true = 站点自定义；false = 站点关闭）
  cc_use_custom?: boolean | null
  cc_rules?: string // CC 规则 JSON 数组字符串

  // 列表返回的扩展字段
  listener_summary?: string
  tls_summary?: string
  managed_listener_count?: number
}

export type SiteUpdate = Partial<
  Omit<
    Site,
    | "id"
    | "created_at"
    | "updated_at"
    | "listener_summary"
    | "tls_summary"
    | "managed_listener_count"
  >
>

export interface SiteListener {
  id: number
  created_at: string
  updated_at: string

  site_id: number
  bind: string
  network?: string
  tls_enabled: boolean
  cert_id?: number
  enabled: boolean
  note?: string
}

export interface SiteCacheRule {
  type: "prefix" | "exact" | "suffix" | "contains" | "regex"
  value: string
  path?: string
  ttl: number
  case_insensitive?: boolean
  ignore_query?: boolean
}

export interface SiteForwardingRule {
  id?: string
  note?: string
  path_prefix: string
  upstreams: string[]
  enabled: boolean
}

export interface SiteHeaderOp {
  id?: string
  phase: "request" | "response"
  action: "add" | "set" | "remove"
  name: string
  value?: string
}

export interface Certificate {
  id: number
  created_at: string
  updated_at: string

  name: string
  cert_pem: string
  /** GET 列表/详情响应中后端一律置空，私钥不回显 */
  key_pem: string
  ocsp_staple_pem?: string

  source: "manual" | "acme" | "self_signed"
  domain?: string
  acme_email?: string
  expires_at?: string
  auto_renew: boolean
  last_renew_at?: string
  renew_error?: string
}

/**
 * 证书解析命中的站点。
 *
 * 契约见 internal/admin/system/certificate.go 的 certificateMatchedSite。
 */
export interface CertificateMatchedSite {
  id: number
  host: string
  tls_enabled: boolean
  cert_id?: number
  matched_name: string
}

/**
 * 证书 PEM 解析结果。
 *
 * 契约见 internal/admin/system/certificate.go 的 certificateParseResponse
 * (POST /api/v1/certificates/parse)。dns_names / ip_addresses 在证书未包含
 * 对应扩展时为 null。
 */
export interface CertificateParseResult {
  common_name: string
  dns_names: string[] | null
  ip_addresses: string[] | null
  expires_at: string
  matched_sites: CertificateMatchedSite[] | null
}

export type RulePhase =
  "acl" | "rate_limit" | "owasp_default" | "signature" | "custom"

export type RuleAction =
  | "allow"
  | "intercept"
  | "observe"
  | "drop"
  | "challenge"
  | "captcha_challenge"
  | "shield_challenge"
  | "chain_challenge"
  | "redirect"
  | "rate_limit"
  | "tag"
  | "block"
  | "log_only"

export interface Policy {
  id: number
  created_at: string
  updated_at: string
  name: string
  description?: string
  is_default?: boolean
  site_count?: number
  rule_count?: number
}

export interface OWASPRuleItem {
  id: string
  catalog_id?: number
  builtin_id?: string
  policy_id: number
  category: string
  name: string
  description?: string
  default_enabled: boolean
  default_action?: string
  default_sensitivity?: string
  enabled: boolean
  action?: string
  sensitivity?: string
  status_code?: number
  redirect_to?: string
  whitelist?: string[]
  overridden?: boolean
}

export interface OWASPStats {
  total: number
  enabled_count: number
  disabled_count: number
  by_category: Record<string, number>
  policy_id: number
}

export type CVEScopeType = "global" | "policy" | "site"

export interface CVEEffectiveConfig {
  enabled: boolean
  action?: string
  sensitivity?: string
  status_code?: number
  redirect_to?: string
}

export interface CVERuleItem {
  id: number
  cve_id?: string
  cve?: string
  name?: string
  description?: string
  category?: string
  severity?: string
  source?: string
  enabled: boolean
  action?: string
  effective?: CVEEffectiveConfig
  override?: Record<string, unknown> | null
  overridden?: boolean
  inherited_from?: string
}

export interface CVEStats {
  total: number
  enabled_count: number
  disabled_count: number
  by_category?: Record<string, number>
  by_severity?: Record<string, number>
}

export interface Rule {
  id: number
  created_at: string
  updated_at: string
  name?: string
  policy_id: number
  phase: RulePhase
  pattern: string
  action: RuleAction
  priority: number
  enabled: boolean
  status_code: number
  redirect_to?: string
  /** 空值继承全局验证码类型，仅对 captcha_challenge 生效。 */
  captcha_type?: CaptchaType
}

export interface SecurityEvent {
  id: number
  created_at: string

  site_id: number
  request_id: string
  client_ip: string
  host: string
  path: string
  query_string?: string
  method: string
  user_agent?: string

  rule_id: number
  rule_id_str?: string
  phase: string
  action: string
  category: string
  match_desc?: string

  request_headers?: string
  request_body_preview?: string
  request_body_truncated: boolean
  request_size: number

  tls_version?: string
  tls_sni?: string
  tls_alpn?: string
  tls_ja3?: string
  tls_ja3_hash?: string
  tls_ja4?: string
  tls_cipher_suites?: string
  tls_extensions?: string
  tls_curves?: string
  tls_point_formats?: string
  header_order?: string

  geo_country?: string
  geo_city?: string
  status_code: number
}

export interface SecurityEventStats {
  total: number
  hours: number
  categories: Array<{ category: string; count: number }>
  top_ips: Array<{ client_ip: string; count: number }>
  top_paths: Array<{ path: string; count: number }>
  top_rules: Array<{ rule_id_str: string; count: number }>
  /** 攻击来源国家/地区排行，country 为 ISO 3166-1 alpha-2 代码 */
  top_countries?: Array<{ country: string; count: number }>
  intercepts: number
  observes: number
  requests: number
  challenges: number
}

/**
 * 请求级安全事件聚合项
 * 后端契约：GET /api/v1/security-events/requests
 * 字段逐字匹配 internal/store/repository/security_event.go SecurityEventRequest
 */
export interface SecurityEventRequest {
  request_id: string
  event_count: number
  last_seen: string
}

export interface TimelineBucket {
  time: string
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
  query_string?: string
  method: string
  status_code: number
  waf_action?: string
  cache_state?: string
  upstream?: string
  user_agent?: string

  request_headers?: string
  request_body_preview?: string
  request_body_truncated: boolean
  request_size: number
  response_headers?: string

  http_protocol?: string
  upstream_http_protocol?: string
  tls_version?: string
  tls_sni?: string
  tls_alpn?: string
  tls_ja3?: string
  tls_ja3_hash?: string
  tls_ja4?: string
  tls_cipher_suites?: string
  tls_extensions?: string
  tls_curves?: string
  tls_point_formats?: string
  header_order?: string
  visitor_fusion_class?: string
  visitor_fusion_score?: number
  visitor_fusion_client_family?: string
  visitor_fusion_ua_claim?: string
  visitor_fusion_consistency?: string
  visitor_fusion_evidence_sufficient?: boolean
  visitor_fusion_reasons?: string

  upstream_latency_ms: number
  response_size: number
}

/**
 * 请求追踪结果
 * 后端契约：GET /api/v1/request/:request_id
 * internal/admin/event/request.go 返回 {
 *   request_id, access_logs, security_events
 * }
 */
export interface RequestTrace {
  request_id: string
  access_logs: AccessLog[] | null
  security_events: SecurityEvent[] | null
  /** 同 request_id 的 Bot 评分记录，用于展示人机访问判定依据。 */
  bot_scores: BotScoreLog[]
}

export interface DropEvent {
  id: number
  site_id: number
  client_ip: string
  source: string
  rule_id?: string
  detail?: string
  host?: string
  path?: string
  created_at: string
}

export interface BotScoreLog {
  id: number
  site_id: number
  request_id: string
  client_ip: string
  host?: string
  path?: string
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
  details?: string
  created_at: string
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
  unique_visitors_24h: number
  visitor_fusion_https_released_total_24h: number
  visitor_fusion_human_24h: number
  visitor_fusion_bot_24h: number
  visitor_fusion_unknown_24h: number
  revision: number
  human_visits_24h?: number
  bot_visits_24h?: number
  /** 未经 bot 判定即被拦截的唯一 request_id 数（OWASP/CVE/ACL 短路，未进入 BotDetection）。 */
  unclassified_intercept_24h?: number
  /** 窗口内唯一 request_id 总数；三类之和与它的差额为其他非安全类动作。 */
  visit_kind_total_24h?: number
  bot_total_24h: number
  bot_blocked_24h: number
  bot_high_risk_24h: number
  cve_total_24h: number
  cve_by_type_24h: Array<{ category: string; count: number }>
  drop_total_24h: number
  drop_by_source_24h: Record<string, number>
}

export interface AppRouteRule {
  id: number
  site_id: number
  path: string
  method: string
  resource_type?: string
  created_at: string
  updated_at: string
}

export interface RecordedResource {
  id: number
  site_id: number
  path: string
  method: string
  content_type?: string
  visit_count_24h: number
  last_visit_at?: string
  created_at: string
}

export interface IPEntry {
  id: number
  created_at: string
  updated_at: string
  /** 名单类型：黑名单或白名单，对齐后端 IPListKind */
  kind: "blacklist" | "whitelist"
  /** IP 或 CIDR，后端统一存为 value，不区分 ip/cidr */
  value: string
  /** 备注说明 */
  note?: string
  /** 命中动作：拦截或丢弃（后端 normalizeIPListAction 归一化后返回 intercept/drop） */
  action: "intercept" | "drop"
  enabled: boolean
  /** 作用域站点 ID；null/undefined 表示全局 */
  site_id?: number | null
}

/**
 * 威胁情报 IP 订阅源。
 * 字段严格对齐后端 store.ThreatIntelFeed，不新增后端未定义字段。
 */
export interface ThreatIntelFeed {
  id: number
  created_at: string
  updated_at: string
  /** 订阅源名称 */
  name: string
  /** 订阅 URL */
  url: string
  /** 名单类型：黑名单或白名单 */
  kind: "blacklist" | "whitelist"
  /** 命中动作：拦截或丢弃 */
  action: "intercept" | "drop"
  enabled: boolean
  /** 同步间隔（秒） */
  sync_interval: number
  /** 作用域站点 ID；null/undefined 表示全局 */
  site_id?: number | null
  /** 上次同步时间 */
  last_sync_at?: string | null
  /** 上次同步错误信息 */
  last_error?: string
  /** 当前该源拉取的条目数 */
  entry_count: number
}

/**
 * 威胁情报订阅源单次同步的历史记录。
 * 字段严格对齐后端 store.ThreatIntelSyncLog。
 */
export interface ThreatIntelSyncLog {
  id: number
  created_at: string
  /** 关联订阅源 ID */
  feed_id: number
  /** 冗余存储的订阅源名称，避免关联查询 */
  feed_name: string
  /** 开始时间 */
  started_at: string
  /** 结束时间 */
  finished_at: string
  /** 同步耗时（毫秒） */
  duration_ms: number
  /** HTTP 拉取 + 解析都成功则为 true */
  success: boolean
  /** 本次全量替换后的条目数 */
  entries_added: number
  /** 因格式非法被跳过的条目数 */
  entries_skipped: number
  /** 原始行数 */
  lines_read: number
  /** 触发方式：auto=定时同步，manual=手动触发 */
  trigger: "auto" | "manual"
  /** 失败时的错误信息（≤1000 字符） */
  error?: string
}

/**
 * FalsePositiveReport 是管理员标记的一条误报反馈。
 *
 * 字段严格对齐后端 store.FalsePositiveReport，不新增后端未定义字段。
 */
export interface FalsePositiveReport {
  id: number
  created_at: string
  updated_at: string
  /** 关联的安全事件 ID */
  security_event_id: number
  /** 请求 ID */
  request_id: string
  /** 命中规则的字符串 ID */
  rule_id_str: string
  /** 命中分类：owasp / cve / bot / rate_limit / ip_rep / access ... */
  category: string
  client_ip: string
  host: string
  path: string
  match_desc: string
  /** 提交者用户名，后端从 auth_user 自动填充 */
  submitted_by: string
  /** 提交时的备注 */
  note: string
  /** 审查状态 */
  status: "pending" | "confirmed" | "rejected"
}

/** 提交误报反馈的最小请求；命中上下文仅由后端源安全事件回填。 */
export interface FalsePositiveCreateRequest {
  security_event_id: number
  note: string
}

export interface SystemSetting {
  key: string
  value: string
  description?: string
  updated_at?: string
}

export interface NetworkConfig {
  ipv6_enabled: boolean
  http2_enabled: boolean
  http3_enabled: boolean
  http3_bind: string
  default_alpn: string
  default_network: "tcp" | "tcp4" | "tcp6"
}

export type NetworkConfigUpdate = Partial<NetworkConfig>

export interface LogConfig {
  level: string
  file_path: string
  also_stdout: boolean
}

export type LogConfigUpdate = Partial<LogConfig>

export interface TLSConfig {
  min_version: string
  max_version: string
  cipher_suites: string
  default_alpn: string
  has_explicit_default_alpn: boolean
  curve_preferences: string
  prefer_server_cipher_suites: boolean
  session_tickets_enabled: boolean
  self_signed_on_ip: boolean
}

export type TLSConfigUpdate = Partial<
  Omit<TLSConfig, "has_explicit_default_alpn">
>

/** 快照构建时发现的稳定、脱敏配置诊断。 */
export interface SnapshotConfigDiagnostic {
  source: string
  field: string
  error: string
  handling_strategy: string
  kind: string
  reason: string
  policy_id?: number
  rule_id?: string
  ip_list_entry_id?: number
  certificate_id?: number
  listener_id?: number
  scope?: string
  site_id?: number
}

/** GET /api/v1/runtime-config 中前端实际消费的字段。 */
export interface RuntimeConfig {
  revision: number
  config_diagnostics: SnapshotConfigDiagnostic[]
}

export interface RedisConfigResponse {
  enabled: boolean
  addr: string
  db: number
  redis_addr: string
  redis_db: number
  password_set: boolean
  redis_password_set: boolean
  source: string
  restart_required: boolean
}

export interface RedisConfigUpdate {
  enabled?: boolean
  redis_addr?: string
  redis_password?: string
  redis_db?: number
}

export interface User {
  id: number
  username: string
  role: "admin" | "operator" | "readonly"
  created_at: string
  last_login?: string
}

export interface AuthSession {
  id: string
  user_id: number
  ip: string
  user_agent?: string
  created_at: string
  expires_at: string
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
  waiting_room_enabled: boolean
  cc_use_custom: boolean
  cc_rules: unknown[]
  owasp_modules: Record<string, string>
  cve_enabled: boolean
  cve_action: string
  cve_auto_drop_critical: boolean
  cve_auto_drop_high: boolean
  category_sensitivity: Record<string, string>
  owasp_rules_config: Record<string, unknown>
  cve_rules_config: Record<string, unknown>
  skip_path_by_phase: SkipPathByPhase
  login_min_password_length: number
  login_max_attempts: number
  login_lockout_minutes: number
  captcha_enabled: boolean
  captcha_type: CaptchaType
  captcha_timeout: number
  captcha_pass_ttl: number
  shield_enabled: boolean
  shield_difficulty: number
  shield_timeout_secs: number
  shield_auto_start_delay: number
  shield_max_retries: number
  shield_env_strictness: ShieldEnvStrictness
  shield_require_http2: boolean
  shield_require_http3: boolean
  shield_allow_http1: boolean
  shield_enable_js_challenge: boolean
  shield_enable_env_check: boolean
  shield_enable_devtools: boolean
  chain_enabled: boolean
  chain_steps: unknown[]
  escalation_enabled: boolean
  escalation_window_secs: number
  escalation_steps: unknown[]
  basic_auth_enabled: boolean
  basic_auth_username: string
  basic_auth_password: string
  browser_sign_enabled: boolean
  browser_sign_ttl: number
  browser_sign_action: string
}

/** protection-settings 局部更新载荷；skip_path_by_phase 兼容后端 object/string/null 输入。 */
export type ProtectionSettingsUpdate = Partial<
  Omit<ProtectionSettings, "skip_path_by_phase">
> & {
  skip_path_by_phase?: SkipPathByPhase | string | null
}

export interface BotSettings {
  enabled: boolean
  captcha_enabled: boolean
  dynamic_protection_enabled: boolean
  html_obfuscation: boolean
  js_obfuscation: boolean
  js_protection_mode?: "all" | "paths"
  decrypt_cache_ttl_seconds?: number
  image_watermark: boolean
  anti_replay_enabled: boolean
  anti_replay_ttl: number
  browser_sign_enabled?: boolean
  browser_sign_ttl?: number
  browser_sign_action?: string
  js_obfuscation_paths?: string[]
  image_watermark_paths?: string[]
  watermark_text?: string
  exclude_record_headers?: string[]
}

export type ShieldEnvStrictness = 0 | 1 | 2

export type CaptchaType = "math" | "click" | "slide" | "rotate"

export interface CaptchaConfig {
  captcha_enabled: boolean
  captcha_type: CaptchaType
  captcha_timeout: number
  captcha_pass_ttl: number
  shield_enabled: boolean
  shield_difficulty: number
  shield_timeout_secs: number
  shield_auto_start_delay: number
  shield_max_retries: number
  shield_env_strictness: ShieldEnvStrictness
  shield_require_http2: boolean
  shield_require_http3: boolean
  shield_allow_http1: boolean
  shield_enable_js_challenge: boolean
  shield_enable_env_check: boolean
  shield_enable_devtools: boolean
}

export type CaptchaConfigPatch = Partial<CaptchaConfig>

export interface CaptchaTestResponse {
  session_id: string
  captcha_type: string
  type: string
  master_img: string
  thumb_img: string
  prompt: string
  width: number
  height: number
  timeout: number
  pass_ttl: number
  fallback: boolean
}

export interface ChainConfig {
  enabled: boolean
  steps: number
  timeout: number
}

export interface SensitivityConfig {
  level: "low" | "mid" | "high"
  custom_rules?: string
}

export interface EscalationConfig {
  enabled: boolean
  threshold: number
  window: number
  action: string
}

export interface ErrorPageConfig {
  status_code: number
  title?: string
  message?: string
  html?: string
}

export interface SiteErrorPages {
  site_id: number
  pages: ErrorPageConfig[]
  default_template?: string
}

/**
 * 上游服务器健康状态
 * 后端契约：internal/admin/system/upstream.go 中的 upstreamStatusItem
 */
export interface UpstreamStatus {
  url: string
  configured_protocol?: string
  last_http_protocol?: string
  healthy: boolean
  fail_count: number
  last_failure_kind?: string
  last_error?: string
  last_latency_ms: number
  average_latency_ms: number
  checked_at?: string
  last_success_at?: string
}

export interface UpstreamStatusResponse {
  items: UpstreamStatus[]
  total: number
}

export interface SiteAccessConfig {
  site_id: number
  enabled: boolean
  shared_password_set: boolean
  session_ttl: number
}

export interface OAuthProviderConfig {
  client_id: string
  client_secret?: string
  client_secret_mask?: string
  client_secret_set?: boolean
  auth_url?: string
  token_url?: string
  userinfo_url?: string
  issuer?: string
  scopes?: string[]
  redirect_path?: string
  use_pkce?: boolean
}

export interface AccessProvider {
  id: number
  site_id: number
  type: "password" | "oauth2" | "oidc"
  name: string
  priority: number
  enabled: boolean
  config?: OAuthProviderConfig
  created_at?: string
  updated_at?: string
}

export interface AccessProviderCreateInput {
  type: AccessProvider["type"]
  name: string
  priority: number
  enabled?: boolean
  config?: OAuthProviderConfig
}

export interface AccessProviderUpdateInput {
  name?: string
  priority?: number
  enabled?: boolean
  config?: OAuthProviderConfig
}

export interface AccessUser {
  id: number
  site_id: number
  username: string
  enabled: boolean
  created_at?: string
}

export interface AccessUserCreateInput {
  username: string
  password: string
  enabled?: boolean
}

export interface AccessUserUpdateInput {
  password?: string
  enabled?: boolean
}

export interface AccessPathRule {
  id: number
  site_id: number
  path: string
  action: "require_auth" | "allow" | "deny"
  priority: number
  enabled: boolean
}

export interface AccessPathRuleCreateInput {
  path: string
  action: AccessPathRule["action"]
  priority: number
  enabled?: boolean
}

export interface AccessPathRuleUpdateInput {
  path?: string
  action?: AccessPathRule["action"]
  priority?: number
  enabled?: boolean
}

export interface RealtimeTicket {
  ticket: string
  expires_at: string
}

export interface AdminAPIKey {
  id: number
  created_at: string
  updated_at: string
  name: string
  last_used_at?: string
}

export interface AdminUser {
  id: number
  username: string
  role: "admin" | "operator" | "readonly"
  created_at: string
  last_login?: string
}

/**
 * BackupData 是完整配置备份的载荷。
 *
 * 各数组对前端不透明，作为整体导出/导入，前端不解析其内部结构。
 */
export interface BackupData {
  version: number
  exported_at: string
  certificates: unknown[]
  policies: unknown[]
  rules: unknown[]
  sites: unknown[]
  site_listeners: unknown[]
  ip_list_entries: unknown[]
  threat_intel_feeds: unknown[]
  cve_rule_records: unknown[]
  application_routes: unknown[]
  site_access_configs: unknown[]
  access_providers: unknown[]
  access_users: unknown[]
  access_path_rules: unknown[]
  lua_plugins: unknown[]
  /** 新版备份包含 JS 插件；旧版备份可能缺少该字段。 */
  js_plugins?: unknown[]
  system_settings: unknown[]
}

/**
 * ImportResult 是恢复配置后的统计结果。
 */
export interface ImportResult {
  status: string
  replace_mode: boolean
  sites: number
  certificates: number
  rules: number
  ip_entries: number
}

/**
 * LuaPluginStage 是脚本的执行阶段。
 * - pre：在 ACL 之后、OWASP 之前，可在昂贵检测前提早放行或拦截
 * - post：在全部内置阶段之后，能读到内置判定；只有 allow 能推翻内置拦截
 */
export type LuaPluginStage = "pre" | "post"

/** LuaPluginAction 是脚本可返回的合法动作，对齐后端 action.IsValid 的白名单。 */
export type LuaPluginAction =
  | "allow"
  | "intercept"
  | "observe"
  | "drop"
  | "challenge"
  | "captcha_challenge"
  | "shield_challenge"
  | "chain_challenge"
  | "redirect"
  | "rate_limit"
  | "tag"

/**
 * LuaPlugin 是一段用户自定义的 Lua 策略脚本。
 *
 * 字段严格对齐后端 store.LuaPlugin，不新增后端未定义字段。
 */
export interface LuaPlugin {
  id: number
  created_at: string
  updated_at: string
  /** 脚本名称 */
  name: string
  /** 执行阶段 */
  stage: LuaPluginStage
  /** Lua 源码，必须定义全局函数 handle(ctx) */
  source: string
  enabled: boolean
  /** 同阶段内的执行顺序，数值小者先执行 */
  priority: number
  /** 作用域站点 ID；null/undefined 表示全站生效 */
  site_id?: number | null
  /** 执行超时（毫秒），0 表示用后端默认值 */
  timeout_ms: number
  /** 运维备注 */
  description: string
}

/** LuaValidateResult 是语法校验结果，对齐 POST /lua-plugins/validate 的响应。 */
export interface LuaValidateResult {
  valid: boolean
  /** 仅 valid 为 false 时存在 */
  error?: string
}

/**
 * LuaDryRunRequestView 是试运行的样例请求。
 *
 * 字段与后端 luaDryRunRequest.Request 一一对应，也就是脚本侧可读到的 ctx。
 */
export interface LuaDryRunRequestView {
  client_ip?: string
  method?: string
  path?: string
  query?: string
  host?: string
  user_agent?: string
  site_id?: number
  content_type?: string
  body?: string
  headers?: Record<string, string>
  query_params?: Record<string, string>
  tls_version?: string
  tls_ja3?: string
  tls_ja4?: string
  tls_sni?: string
  /** 模拟内置引擎命中的阶段，仅 post 阶段有意义 */
  phase?: string
  /** 模拟内置引擎的判定动作，仅 post 阶段有意义 */
  action?: string
}

/** LuaDryRunRequest 是试运行的请求体，对齐后端 luaDryRunRequest。 */
export interface LuaDryRunRequest {
  stage: LuaPluginStage
  source: string
  /** 0 或省略表示用后端默认超时 */
  timeout_ms?: number
  iterations?: number
  request: LuaDryRunRequestView
}

/**
 * LuaDecision 是脚本给出的判定。
 *
 * 字段名首字母大写：后端 luaplugin.Decision 未加 json tag，
 * encoding/json 直接输出 Go 字段名，改成小写会读不到值。
 */
export interface LuaDecision {
  /** 空串表示脚本未判定，请求继续走后续阶段 */
  Action: string
  Message: string
  RedirectTo: string
  /** 0 表示用默认响应码 */
  StatusCode: number
  SetHeaders: Record<string, string> | null
  ResponseBody: string
  Tags: string[] | null
}

/**
 * LuaPluginStat 是单个脚本的运行时统计，对齐 GET /lua-plugins/stats 的 items 元素。
 *
 * 计数器挂在引擎内存里的已编译脚本上。配置重载会重新编译脚本、计数随之归零，
 * 因此这些值不是历史总量，只反映当前载入的这一批脚本跑了多少。
 *
 * failures 与 timeouts 互斥：后端在超时分支直接返回、不再累加 failures，
 * 所以成功次数是 runs - failures - timeouts，两个占比可以分别独立解读。
 */
export interface LuaPluginStat {
  /** 脚本名。统计不含数据库 id，与插件列表的关联键就是它 */
  id: number
  name: string
  stage: LuaPluginStage
  /** 累计执行次数，含失败与超时的那几次 */
  runs: number
  /** 累计失败次数，不含超时：handle 报错、panic、缺少入口函数等 */
  failures: number
  /** 累计超时次数 */
  timeouts: number
  /** 平均执行耗时（毫秒）。分母是 runs，所以超时的执行也会把它拉高 */
  avg_ms: number
}

/** LuaPluginStatsResponse 是运行时统计的响应体，对齐 GET /lua-plugins/stats。 */
export interface LuaPluginStatsResponse {
  items: LuaPluginStat[]
  total: number
}

/** LuaDryRunResult 是试运行结果，对齐后端 luaplugin.DryRunBatchResult。 */
export interface LuaDryRunResult {
  /** 非空表示未通过编译，此时其余字段无意义 */
  compile_error?: string
  /** 非空表示脚本执行出错（含超时） */
  runtime_error?: string
  decision: LuaDecision
  /** 执行耗时（毫秒） */
  elapsed_ms: number
  /** 当前结果对应的第几次样例请求 */
  iteration: number
  /** 请求的总试运行次数 */
  iterations: number
  /** Redis KV 是否可用 */
  kv_available: boolean
  /** 每次试运行的明细 */
  runs: LuaDryRunRun[]
}

/** 单次 Lua 试运行明细，对齐后端 luaplugin.DryRunResult。 */
export interface LuaDryRunRun {
  compile_error?: string
  runtime_error?: string
  decision: LuaDecision
  elapsed_ms: number
  iteration: number
}

/** JavaScript 边缘插件持久化阶段；列表接口仍可返回历史 response 记录。 */
export type JSPluginStage = "request" | "response"

/** 当前管理 API 允许写入的 JavaScript 插件阶段。 */
export type JSPluginWritableStage = "request"

/** JavaScript 插件执行失败时的处理模式。 */
export type JSPluginFailureMode = "fail_open" | "fail_closed"

/** JavaScript 边缘插件管理响应，包含数据库配置和当前 snapshot 构建诊断。 */
export interface JSPlugin {
  id: number
  created_at: string
  updated_at: string
  name: string
  source: string
  enabled: boolean
  priority: number
  site_id?: number | null
  stage: JSPluginStage
  failure_mode: JSPluginFailureMode
  timeout_ms: number
  description: string
  compile_error?: string
}

/** JS 插件创建请求。 */
export interface JSPluginCreateRequest {
  name: string
  source: string
  stage: JSPluginWritableStage
  failure_mode?: JSPluginFailureMode
  enabled?: boolean
  priority?: number
  site_id?: number | null
  timeout_ms?: number
  description?: string
}

/** JS 插件更新请求；省略字段保持原值，site_id 为 null 时清除站点作用域。 */
export interface JSPluginUpdateRequest {
  name?: string
  source?: string
  stage?: JSPluginWritableStage
  failure_mode?: JSPluginFailureMode
  enabled?: boolean
  priority?: number
  site_id?: number | null
  timeout_ms?: number
  description?: string
}

/** JS 插件请求字段的统一类型，便于调用方复用。 */
export type JSPluginRequest = JSPluginCreateRequest | JSPluginUpdateRequest

/** JS 插件列表响应。 */
export interface JSPluginListResponse {
  items: JSPlugin[]
  total: number
}

/** JS 插件配置已持久化但 snapshot 重载失败时的响应。 */
export interface JSPluginReloadFailureResponse {
  error: string
  reload_error: string
  item: JSPlugin
}

/** JS 插件开关请求。省略请求体时由后端翻转当前状态。 */
export interface JSPluginToggleRequest {
  enabled?: boolean
}

/** JS 插件开关响应。 */
export interface JSPluginToggleResponse {
  id: number
  enabled: boolean
}

/** JS 插件校验请求。 */
export interface JSPluginValidateRequest {
  stage: JSPluginWritableStage
  source: string
  timeout_ms?: number
}

/** JS 插件校验响应。 */
export interface JSPluginValidateResult {
  valid: boolean
  error?: string
}

/** JS 插件单脚本运行时统计项。 */
export interface JSPluginStatsItem {
  id: number
  name: string
  /** stats 只返回当前 snapshot 中实际可执行的 request-stage 脚本。 */
  stage: JSPluginWritableStage
  runs: number
  failures: number
  timeouts: number
  avg_ms: number
}

/** JS 插件统计响应。 */
export interface JSPluginStatsResponse {
  items: JSPluginStatsItem[]
  total: number
}

/** JavaScript 插件可返回的请求变更计划。 */
export interface JSPluginMutationPlan {
  method?: string
  path?: string
  raw_query?: string
  body?: string
  set_headers?: Record<string, string>
  delete_headers?: string[]
}

/** JavaScript 插件 dry-run 样例请求。 */
export interface JSPluginSampleRequest {
  method?: string
  path?: string
  raw_query?: string
  host?: string
  client_ip?: string
  user_agent?: string
  content_type?: string
  body?: string
  headers?: Record<string, string>
  query_params?: Record<string, string>
}

/** JS 插件 dry-run 请求。 */
export interface JSPluginDryRunRequest {
  source: string
  stage: JSPluginWritableStage
  timeout_ms?: number
  sample_request?: JSPluginSampleRequest
}

/** JS 插件 dry-run 响应。 */
export interface JSPluginDryRunResponse {
  error?: string
  result: JSPluginMutationPlan | null
  execution_time_ms?: number
}
