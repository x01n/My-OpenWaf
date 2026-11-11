/**
 * 防护设置相关类型。
 *
 * 字段名逐一取自后端源码（禁止猜测）：
 * - ProtectionSettings：internal/store/protection.go ProtectionConfig（L13-117），
 *   其中 JSON blob 字段经 internal/admin/protect/protection.go buildProtectionResponse
 *   展开为对象/数组；basic_auth_password 不出现在响应中（后端已 delete）。
 * - BotSettings：internal/admin/shared/helpers.go BotSettingsResponse（L622-646）。
 * - CaptchaConfig：internal/admin/protect/captcha/captcha.go captchaConfigResponse（L16-33）。
 * - ChainConfig / ChainSession：internal/admin/protect/chain/chain.go 与
 *   internal/waf/challenge/chain.go ChainSessionInfo（L38-44）。
 * - SensitivityConfig：internal/admin/protect/sensitivity/sensitivity.go SensitivityRequest。
 * - EscalationConfig / EscalationStep：internal/admin/protect/escalation/escalation.go
 *   与 internal/store/protection.go EscalationStepDef（L437-440）。
 * - DropPolicy / DropStats / DropEvent：internal/admin/protect/drop/drop.go 与
 *   internal/store/repository/drop_event.go DropStatsSummary（L157-163）、
 *   internal/store/events.go DropEvent（L240-250）。
 * - PageTemplateConfig：internal/waf/pageconfig/config.go PageConfig（L23-31）及三类扩展。
 */

/* ---------- 综合防护（GET/POST /protection-settings） ---------- */

export type ProtectionSettings = {
  /* 请求限流 */
  request_ratelimit_enabled: boolean;
  request_ratelimit_window: number;
  request_ratelimit_max: number;
  request_ratelimit_action: string;
  /* 错误限流 */
  error_ratelimit_enabled: boolean;
  error_ratelimit_window: number;
  error_ratelimit_max: number;
  error_ratelimit_count_4xx: boolean;
  error_ratelimit_count_5xx: boolean;
  error_ratelimit_count_block: boolean;
  error_ratelimit_action: string;
  /* OWASP / CVE */
  builtin_owasp_enabled: boolean;
  builtin_owasp_sensitivity: string;
  builtin_owasp_on_hit: string;
  cve_enabled: boolean;
  cve_action: string;
  cve_auto_drop_critical: boolean;
  cve_auto_drop_high: boolean;
  /* 维护页 */
  maintenance_global_enabled: boolean;
  maintenance_global_html: string;
  maintenance_global_status: number;
  /* 开关组 */
  bot_detection_enabled: boolean;
  auto_ban_enabled: boolean;
  auto_ban_threshold: number;
  auto_ban_window: number;
  auto_ban_duration: number;
  auto_ban_action: string;
  waiting_room_enabled: boolean;
  cc_use_custom: boolean;
  cc_rules: unknown[];
  owasp_modules: Record<string, string>;
  /* 浏览器签名 */
  browser_sign_enabled: boolean;
  browser_sign_ttl: number;
  browser_sign_action: string;
  /* 登录安全 */
  login_min_password_length: number;
  login_max_attempts: number;
  login_lockout_minutes: number;
  /* 验证码 / 质询 */
  captcha_enabled: boolean;
  captcha_type: string;
  captcha_timeout: number;
  captcha_pass_ttl: number;
  challenge_action: string;
  anti_replay_enabled: boolean;
  anti_replay_cookie_mode: string;
  /* 5 秒盾 */
  shield_enabled: boolean;
  shield_difficulty: number;
  shield_timeout_secs: number;
  shield_auto_start_delay: number;
  shield_max_retries: number;
  shield_env_strictness: number;
  shield_require_http2: boolean;
  shield_require_http3: boolean;
  shield_allow_http1: boolean;
  shield_enable_js_challenge: boolean;
  shield_enable_env_check: boolean;
  shield_enable_devtools: boolean;
  /* 连锁 / 升级（编辑入口在专属 Tab，此 Tab 保存时原样透传） */
  chain_enabled: boolean;
  chain_steps: ChainStep[];
  escalation_enabled: boolean;
  escalation_window_secs: number;
  escalation_steps: EscalationStep[];
  /* Basic Auth（响应不含 basic_auth_password） */
  basic_auth_enabled: boolean;
  basic_auth_username: string;
  /* OWASP 规则级配置与 pipeline 跳过路径 */
  category_sensitivity: Record<string, string>;
  owasp_rules_config: Record<string, unknown>;
  cve_rules_config: Record<string, unknown>;
  skip_path_by_phase: Record<string, string[]>;
};

/* ---------- Bot 防护（GET /bot-settings、POST /bot-settings/update、GET /bot-stats） ---------- */

export type BotSettings = {
  enabled: boolean;
  score_threshold: number;
  high_risk_countries: string[];
  datacenter_asns: number[];
  vpn_proxy_asns: number[];
  geoip_db_path: string;
  captcha_enabled: boolean;
  dynamic_protection_enabled: boolean;
  html_obfuscation: boolean;
  js_obfuscation: boolean;
  image_watermark: boolean;
  anti_replay_enabled: boolean;
  anti_replay_cookie_mode: string;
  browser_sign_enabled: boolean;
  browser_sign_ttl: number;
  browser_sign_action: string;
  html_to_markdown_enabled: boolean;
  js_obfuscation_paths: string[];
  js_protection_mode: string;
  decrypt_cache_ttl_seconds: number;
  image_watermark_paths: string[];
  watermark_text: string;
  exclude_record_headers: string[];
};

/** internal/store/repository/bot/bot_score.go BotScoreStats（L86-91） */
export type BotStats = {
  total_24h: number;
  blocked_24h: number;
  high_risk_24h: number;
  avg_score_24h: number;
};

/** internal/store/events.go BotScoreLog（L253-280）—— GET /bot-scores 列表项 */
export type BotScoreLog = {
  id: number;
  site_id: number;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  user_agent: string;
  tls_ja3_hash: string;
  tls_ja4: string;
  tls_version: string;
  tls_sni: string;
  tls_alpn: string;
  header_order: string;
  total_score: number;
  ua_score: number;
  geoip_score: number;
  fingerprint_score: number;
  behavior_score: number;
  ip_rep_score: number;
  is_high_risk: boolean;
  dangerous: boolean;
  danger_reasons: string;
  action: string;
  details: string;
  created_at: string;
};

/* ---------- 验证码 / 5 秒盾（GET/POST /captcha/config、POST /captcha/test） ---------- */

export type CaptchaConfig = {
  captcha_enabled: boolean;
  captcha_type: string;
  captcha_timeout: number;
  captcha_pass_ttl: number;
  shield_enabled: boolean;
  shield_difficulty: number;
  shield_timeout_secs: number;
  shield_auto_start_delay: number;
  shield_max_retries: number;
  shield_env_strictness: number;
  shield_require_http2: boolean;
  shield_require_http3: boolean;
  shield_allow_http1: boolean;
  shield_enable_js_challenge: boolean;
  shield_enable_env_check: boolean;
  shield_enable_devtools: boolean;
};

/** internal/waf/challenge/captcha.go CaptchaChallenge 中下发的字段（TestCaptcha 响应） */
export type CaptchaTestResult = {
  session_id: string;
  captcha_type: string;
  type: string;
  master_img: string;
  thumb_img: string;
  prompt: string;
  width: number;
  height: number;
  timeout: number;
  pass_ttl: number;
  fallback: boolean;
};

/* ---------- 连锁验证（GET/POST /chain/config、/chain/sessions） ---------- */

/** internal/waf/challenge/chain.go ChainStepConfig（L31-35）；type 见 ChainStepType（L24-27） */
export type ChainStepType = "env" | "pow" | "captcha";

export type ChainStep = {
  type: ChainStepType;
  condition?: string;
  captcha_type?: string;
};

export type ChainConfig = {
  chain_enabled: boolean;
  chain_steps: ChainStep[];
};

/** internal/waf/challenge/chain.go ChainSessionInfo（L38-44） */
export type ChainSession = {
  id: string;
  current_step: number;
  step_count: number;
  original_url: string;
  started_at: string;
};

/* ---------- 灵敏度（GET/POST /protection/global/sensitivity） ---------- */

/** 等级取值见 internal/store/protection.go normalizeProtectionSensitivityLevel（L206-223） */
export type SensitivityLevel = "off" | "low" | "mid" | "high" | "very_high" | "strict";

export type SensitivityConfig = {
  category_sensitivity: Record<string, SensitivityLevel | string>;
};

/* ---------- 分级升级（GET/POST /protection/global/escalation、/escalation/status/:ip） ---------- */

export type EscalationStep = {
  threshold: number;
  action: string;
};

export type EscalationConfig = {
  escalation_enabled: boolean;
  escalation_window_secs: number;
  escalation_steps: EscalationStep[];
};

/** internal/waf/escalation/escalation.go IPEscalationStatus（L215-220） */
export type EscalationIPStatus = {
  ip: string;
  hit_count: number;
  current_step: number;
  action: string;
  message?: string;
};

/* ---------- 丢弃策略（GET /drop-policy、/drop-stats、/drop-events） ---------- */

export type DropPolicy = {
  enabled: boolean;
  bot_score_threshold: number;
  cve_auto_drop_critical: boolean;
  cve_auto_drop_high: boolean;
};

/** internal/store/repository/drop_event.go DropStatsSummary（L157-163） */
export type DropStats = {
  total_24h: number;
  by_bot: number;
  by_cve: number;
  by_rule: number;
  by_ip_reputation: number;
};

/** internal/store/events.go DropEvent（L240-250） */
export type DropEvent = {
  id: number;
  site_id: number;
  client_ip: string;
  source: string;
  rule_id: string;
  detail: string;
  host: string;
  path: string;
  created_at: string;
};

/* ---------- 页面模板（GET/POST /page-templates/:type 等） ---------- */

export type PageTemplateType = "captcha" | "challenge" | "block";

/** internal/waf/pageconfig/config.go PageConfig（L23-31）+ 三类扩展字段（L36-63） */
export type PageTemplateConfig = {
  brand_name: string;
  primary_color: string;
  bg_gradient: string;
  logo_url: string;
  title: string;
  footer_text: string;
  custom_css: string;
  /* captcha 扩展 */
  subtitle?: string;
  subtitle_zh?: string;
  submit_text?: string;
  /* challenge 扩展 */
  checking_text?: string;
  checking_text_zh?: string;
  wait_text?: string;
  wait_text_zh?: string;
  /* block 扩展 */
  block_title?: string;
  block_message?: string;
  rate_limit_title?: string;
  rate_limit_message?: string;
};

export type PageTemplatesResponse = {
  captcha: PageTemplateConfig;
  challenge: PageTemplateConfig;
  block: PageTemplateConfig;
};
