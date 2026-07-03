/**
 * TypeScript 类型定义
 * 从后端模型（internal/store/*.go）映射
 */

// ============================================================
// 基础通用类型
// ============================================================

export interface PaginationResponse<T> {
  items: T[];
  total: number;
  page?: number;
}

// ============================================================
// 站点相关
// ============================================================

export interface Site {
  id: number;
  created_at: string;
  updated_at: string;

  host: string;
  upstream_urls: string;
  upstream_host?: string;

  bind: string;
  network?: string;
  enabled: boolean;

  tls_enabled: boolean;
  cert_id?: number;
  min_tls_version?: string;
  max_tls_version?: string;
  cipher_suites?: string;
  alpn?: string;

  policy_id?: number;
  bot_protection_enabled?: boolean;
  bot_protection_level?: string;
  attack_protection_level?: string;

  anti_replay_enabled: boolean;
  anti_replay_ttl: number;
  anti_replay_action: string;

  owasp_enabled?: boolean;
  owasp_sensitivity?: string;
  owasp_action?: string;
  cve_enabled?: boolean;
  cve_action?: string;
  rate_limit_enabled?: boolean;
  rate_limit_window: number;
  rate_limit_max: number;
  rate_limit_action?: string;

  xff_mode: string;
  trusted_cidr?: string;
  preserve_original_host: boolean;

  max_body_bytes: number;
  upstream_tls_skip_verify: boolean;
  upstream_tls_server_name?: string;

  cache_enabled: boolean;
  cache_default_ttl: number;
  cache_rules?: string;

  maintenance_enabled: boolean;
  maintenance_html?: string;
  maintenance_status: number;

  block_html?: string;
  block_status: number;

  custom_error_pages?: string;

  // 列表返回的扩展字段
  listener_summary?: string;
  tls_summary?: string;
  managed_listener_count?: number;
}

export interface SiteListener {
  id: number;
  created_at: string;
  updated_at: string;

  site_id: number;
  bind: string;
  network?: string;
  tls_enabled: boolean;
  cert_id?: number;
  enabled: boolean;
  note?: string;
}

export interface SiteCacheRule {
  type: "prefix" | "exact" | "suffix" | "contains" | "regex";
  value: string;
  path?: string;
  ttl: number;
  case_insensitive?: boolean;
  ignore_query?: boolean;
}

export interface SiteForwardingRule {
  id?: string;
  note?: string;
  path_prefix: string;
  upstreams: string[];
  enabled: boolean;
}

export interface SiteHeaderOp {
  id?: string;
  phase: "request" | "response";
  action: "add" | "set" | "remove";
  name: string;
  value?: string;
}

// ============================================================
// 证书相关
// ============================================================

export interface Certificate {
  id: number;
  created_at: string;
  updated_at: string;

  name: string;
  cert_pem: string;
  key_pem: string;
  ocsp_staple_pem?: string;

  source: "manual" | "acme" | "self_signed";
  domain?: string;
  acme_email?: string;
  expires_at?: string;
  auto_renew: boolean;
  last_renew_at?: string;
  renew_error?: string;
}

// ============================================================
// 规则 / 策略相关
// ============================================================

export type RulePhase = "acl" | "rate_limit" | "owasp_default" | "signature" | "custom";

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
  | "log_only";

export interface Policy {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  description?: string;
}

export interface Rule {
  id: number;
  created_at: string;
  updated_at: string;
  name?: string;
  policy_id: number;
  phase: RulePhase;
  pattern: string;
  action: RuleAction;
  priority: number;
  enabled: boolean;
  status_code: number;
  redirect_to?: string;
}

// ============================================================
// 安全事件相关
// ============================================================

export interface SecurityEvent {
  id: number;
  created_at: string;

  site_id: number;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  query_string?: string;
  method: string;
  user_agent?: string;

  rule_id: number;
  rule_id_str?: string;
  phase: string;
  action: string;
  category: string;
  match_desc?: string;

  request_headers?: string;
  request_body_preview?: string;
  request_body_truncated: boolean;
  request_size: number;

  tls_version?: string;
  tls_sni?: string;
  tls_alpn?: string;
  tls_ja3?: string;
  tls_ja3_hash?: string;
  tls_ja4?: string;
  tls_cipher_suites?: string;
  tls_extensions?: string;
  tls_curves?: string;
  tls_point_formats?: string;
  header_order?: string;

  geo_country?: string;
  geo_city?: string;
  status_code: number;
}

export interface SecurityEventStats {
  total: number;
  hours: number;
  categories: Array<{ category: string; count: number }>;
  top_ips: Array<{ ip: string; count: number }>;
  top_paths: Array<{ path: string; count: number }>;
  top_rules: Array<{ rule: string; count: number }>;
  intercepts: number;
  observes: number;
  requests: number;
  challenges: number;
}

export interface TimelineBucket {
  time: string;
  count: number;
}

// ============================================================
// 访问日志相关
// ============================================================

export interface AccessLog {
  id: number;
  created_at: string;
  site_id: number;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  query_string?: string;
  method: string;
  status_code: number;
  waf_action?: string;
  cache_state?: string;
  upstream?: string;
  user_agent?: string;

  request_headers?: string;
  request_body_preview?: string;
  request_body_truncated: boolean;
  request_size: number;
  response_headers?: string;

  http_protocol?: string;
  upstream_http_protocol?: string;
  tls_version?: string;
  tls_sni?: string;
  tls_alpn?: string;
  tls_ja3?: string;
  tls_ja3_hash?: string;
  tls_ja4?: string;
  tls_cipher_suites?: string;
  tls_extensions?: string;
  tls_curves?: string;
  tls_point_formats?: string;
  header_order?: string;

  upstream_latency_ms: number;
  response_size: number;
}

// ============================================================
// 丢弃事件相关
// ============================================================

export interface DropEvent {
  id: number;
  site_id: number;
  client_ip: string;
  source: string;
  rule_id?: string;
  detail?: string;
  host?: string;
  path?: string;
  created_at: string;
}

// ============================================================
// Bot 评分相关
// ============================================================

export interface BotScoreLog {
  id: number;
  site_id: number;
  request_id: string;
  client_ip: string;
  host?: string;
  path?: string;
  user_agent?: string;
  tls_ja3_hash?: string;
  tls_ja4?: string;
  tls_version?: string;
  tls_sni?: string;
  tls_alpn?: string;
  header_order?: string;
  total_score: number;
  geoip_score: number;
  fingerprint_score: number;
  behavior_score: number;
  ip_rep_score: number;
  is_high_risk: boolean;
  action: string;
  details?: string;
  created_at: string;
}

// ============================================================
// Dashboard 相关
// ============================================================

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
  unique_ips: number;
  attack_ips: number;
  revision: number;
  bot_total_24h: number;
  bot_blocked_24h: number;
  bot_high_risk_24h: number;
  cve_total_24h: number;
  cve_by_type_24h: Array<{ category: string; count: number }>;
  drop_total_24h: number;
  drop_by_source_24h: Record<string, number>;
}

// ============================================================
// 应用路由 / 记录资源
// ============================================================

export interface AppRouteRule {
  id: number;
  site_id: number;
  path: string;
  method: string;
  resource_type?: string;
  created_at: string;
  updated_at: string;
}

export interface RecordedResource {
  id: number;
  site_id: number;
  path: string;
  method: string;
  content_type?: string;
  visit_count_24h: number;
  last_visit_at?: string;
  created_at: string;
}

// ============================================================
// IP 列表相关
// ============================================================

export interface IPEntry {
  id: number;
  created_at: string;
  updated_at: string;
  ip?: string;
  cidr?: string;
  type: "allow" | "block";
  reason?: string;
  expires_at?: string;
  source?: string;
}

// ============================================================
// 系统设置相关
// ============================================================

export interface SystemSetting {
  key: string;
  value: string;
  description?: string;
  updated_at?: string;
}

export interface NetworkConfig {
  xff_mode: string;
  trusted_cidr?: string;
  preserve_original_host: boolean;
  listen_ipv6: boolean;
  enable_http10: boolean;
  enable_http2: boolean;
  http_redirect_https: boolean;
  enable_hsts: boolean;
  proxy_host_header: string;
  proxy_x_forwarded: boolean;
  clear_xff: boolean;
  enable_gzip: boolean;
  enable_brotli: boolean;
  enable_sse: boolean;
  enable_ntlm: boolean;
  fallback_cert: boolean;
}

export interface LogConfig {
  level: string;
  format: string;
  output: string;
  max_size: number;
  max_age: number;
  max_backups: number;
  compress: boolean;
}

export interface TLSConfig {
  min_version: string;
  max_version: string;
  cipher_suites: string[];
  prefer_server_cipher_suites: boolean;
  session_tickets: boolean;
  session_ticket_key?: string;
}

// ============================================================
// 认证相关
// ============================================================

export interface User {
  id: number;
  username: string;
  role: "admin" | "operator" | "readonly";
  created_at: string;
  last_login?: string;
}

export interface AuthSession {
  id: string;
  user_id: number;
  ip: string;
  user_agent?: string;
  created_at: string;
  expires_at: string;
}

// ============================================================
// 防护配置相关
// ============================================================

export interface ProtectionSettings {
  global_mode: "protect" | "observe" | "maintenance";
  shield_enabled: boolean;
  shield_ttl: number;
  rate_limit_enabled: boolean;
  rate_limit_window: number;
  rate_limit_max: number;
  rate_limit_action: string;
  bot_protection_enabled: boolean;
  bot_protection_level: string;
  captcha_enabled: boolean;
  captcha_type: string;
  chain_enabled: boolean;
  chain_steps: number;
}

export interface BotSettings {
  enabled: boolean;
  dynamic_protection_enabled: boolean;
  html_obfuscation: boolean;
  js_obfuscation: boolean;
  image_watermark: boolean;
  anti_replay_enabled: boolean;
  anti_replay_ttl: number;
  js_obfuscation_paths?: string[];
  image_watermark_paths?: string[];
  watermark_text?: string;
  exclude_record_headers?: string[];
}

export interface CaptchaConfig {
  enabled: boolean;
  type: "recaptcha" | "hcaptcha" | "turnstile" | "geetest" | "custom";
  site_key?: string;
  secret_key?: string;
  api_server?: string;
}

export interface ChainConfig {
  enabled: boolean;
  steps: number;
  timeout: number;
}

export interface SensitivityConfig {
  level: "low" | "mid" | "high";
  custom_rules?: string;
}

export interface EscalationConfig {
  enabled: boolean;
  threshold: number;
  window: number;
  action: string;
}

// ============================================================
// 错误页面相关
// ============================================================

export interface ErrorPageConfig {
  status_code: number;
  title?: string;
  message?: string;
  html?: string;
}

export interface SiteErrorPages {
  site_id: number;
  pages: ErrorPageConfig[];
  default_template?: string;
}

// ============================================================
// 上游相关
// ============================================================

export interface UpstreamStatus {
  address: string;
  healthy: boolean;
  active: number;
  pending: number;
  last_check?: string;
}

// ============================================================
// 实时相关
// ============================================================

export interface RealtimeTicket {
  ticket: string;
  expires_at: string;
}
