/**
 * 站点与监听器类型（对应 internal/store/site.go）。
 *
 * 站点高级配置字段全部可选：后端按 json tag 输出，空值字段可能被省略。
 * 三态覆盖字段（*bool / *string）为 null 表示「继承全局」。
 */

export type Site = {
  id: number;
  created_at: string;
  updated_at: string;
  host: string;
  enabled: boolean;
  tls_enabled: boolean;
  cert_id: number | null;

  /* ---------- 上游 ---------- */
  bind?: string;
  /** 上游地址（JSON 数组字符串或逗号分隔） */
  upstream_urls?: string;
  upstream_host?: string;
  network?: string;
  /** 请求体大小上限（字节） */
  max_body_bytes?: number;
  upstream_tls_skip_verify?: boolean;
  upstream_tls_server_name?: string;
  /** 是否透传客户端原始 Host */
  preserve_original_host?: boolean;

  /* ---------- TLS 运行参数 ---------- */
  min_tls_version?: string;
  max_tls_version?: string;
  /** JSON 数组字符串；空串表示继承 */
  cipher_suites?: string;
  /** 逗号分隔的 ALPN 列表 */
  alpn?: string;

  /* ---------- 客户端 IP 识别 ---------- */
  xff_mode?: string;
  trusted_cidr?: string;
  /** JSON 数组字符串，元素为 x_forwarded_for / x_real_ip / forwarded */
  client_ip_header_order?: string;

  /* ---------- 防护覆盖（三态） ---------- */
  policy_id?: number | null;
  bot_protection_enabled?: boolean | null;
  bot_protection_level?: string;
  attack_protection_level?: string;
  anti_replay_enabled?: boolean | null;
  anti_replay_ttl?: number;
  anti_replay_action?: string;
  anti_replay_cookie_mode?: string | null;
  challenge_action?: string | null;
  captcha_type?: string | null;
  owasp_enabled?: boolean | null;
  owasp_sensitivity?: string;
  owasp_action?: string;
  cve_enabled?: boolean | null;
  cve_action?: string;
  rate_limit_enabled?: boolean | null;
  rate_limit_window?: number;
  rate_limit_max?: number;
  rate_limit_action?: string;
  /** JSON 对象字符串；null 表示继承全局 */
  skip_path_by_phase?: string | null;

  /* ---------- 缓存 ---------- */
  cache_enabled?: boolean;
  cache_default_ttl?: number;
  /** JSON 数组字符串 */
  cache_rules?: string;

  /* ---------- 维护与拦截页 ---------- */
  maintenance_enabled?: boolean;
  maintenance_html?: string;
  maintenance_status?: number;
  block_html?: string;
  block_status?: number;
  custom_error_pages?: unknown;

  /* ---------- 动态保护（三态） ---------- */
  dynamic_protection_enabled?: boolean | null;
  dynamic_html_enabled?: boolean | null;
  dynamic_js_enabled?: boolean | null;
  dynamic_js_mode?: string;
  /** JSON 数组字符串 */
  dynamic_js_paths?: string;
  dynamic_decrypt_cache_ttl?: number | null;

  /* ---------- 自定义 CC 规则（三态） ---------- */
  cc_use_custom?: boolean | null;
  /** JSON 数组字符串 */
  cc_rules?: string;

  [key: string]: unknown;
};

export type SiteStatus = {
  id: number;
  host: string;
  status: string;
};

export type SiteListener = {
  id: number;
  listener_summary: string;
  tls_summary: string;
  [key: string]: unknown;
};

/** 证书（internal/admin/system/certificate/certificate.go） */
export type Certificate = {
  id: number;
  name: string;
  cert_pem?: string;
  key_pem?: string;
  ocsp_staple_pem?: string;
  source: string;
  domain: string;
  acme_email?: string;
  expires_at: string;
  auto_renew: boolean;
  last_renew_at?: string;
  renew_error?: string;
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
};

export type CertificateParseResult = {
  common_name: string;
  dns_names: string[];
  ip_addresses: string[];
  expires_at: string;
  matched_sites: string[];
};

export type ACMEConfig = {
  enabled: boolean;
  email: string;
  directory_url: string;
  auto_renew: boolean;
  renew_before_days: number;
  caa_check_enabled: boolean;
  caa_allowed_issuers: string;
  caa_dns_server: string;
};

export type ACMEStatusItem = {
  id: number;
  name: string;
  domain: string;
  expires_at: string;
  auto_renew: boolean;
  error?: string;
};
