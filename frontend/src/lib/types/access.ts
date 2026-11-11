/**
 * 站点访问控制扩展类型（对应 internal/admin/access、internal/store/access、
 * internal/store/approute 与 internal/admin/system/upstream 的 JSON 契约）。
 */

/** 认证提供方 OAuth 配置的脱敏视图（providerResp 内嵌的 maskedOAuthResp） */
export type OAuthProviderConfigMasked = {
  client_id: string;
  client_secret_mask?: string;
  client_secret_set: boolean;
  auth_url?: string;
  token_url?: string;
  userinfo_url?: string;
  issuer?: string;
  scopes?: string[];
  redirect_path?: string;
  use_pkce: boolean;
};

/** 认证提供方（providerResp） */
export type AccessProvider = {
  id: number;
  site_id: number;
  type: string;
  name: string;
  priority: number;
  enabled: boolean;
  config?: OAuthProviderConfigMasked | null;
  created_at?: string;
  updated_at?: string;
};

/** GET /sites/:id/access/providers 响应 */
export type AccessProvidersResponse = {
  site_id: number;
  providers: AccessProvider[];
};

/** 本地用户（store.AccessUser，密码哈希 json:"-" 不返回） */
export type AccessUser = {
  id: number;
  site_id: number;
  username: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
};

/** GET /sites/:id/access/users 响应 */
export type AccessUsersResponse = {
  site_id: number;
  users: AccessUser[];
};

/** 路径规则（store.AccessPathRule） */
export type AccessPathRule = {
  id: number;
  site_id: number;
  path: string;
  action: string;
  priority: number;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
};

/** GET /sites/:id/access/rules 响应 */
export type AccessPathRulesResponse = {
  site_id: number;
  rules: AccessPathRule[];
};

/** 录制资源（store/approute.RecordedResource） */
export type RecordedResource = {
  id: number;
  created_at?: string;
  updated_at?: string;
  site_id: number;
  method: string;
  host: string;
  path: string;
  query_string: string;
  client_ip: string;
  status_code: number;
  content_type: string;
  tls_version: string;
  tls_sni: string;
  tls_alpn: string;
  ja3_hash: string;
  ja4: string;
  user_agent: string;
  matched_rule_ids: string;
  primary_rule_id: number;
  request_headers_json?: string;
  response_headers_json?: string;
  request_body_snippet?: string;
  response_body_snippet?: string;
  first_seen: string;
  last_seen: string;
  hit_count: number;
};

/** 上游状态项（internal/admin/system/upstream.UpstreamStatusItem） */
export type UpstreamStatusItem = {
  url: string;
  configured_protocol?: string;
  last_http_protocol?: string;
  healthy: boolean;
  fail_count: number;
  last_failure_kind?: string;
  last_error?: string;
  last_latency_ms: number;
  average_latency_ms: number;
  checked_at?: string;
  last_success_at?: string;
};

/** GET /upstreams/status 响应 */
export type UpstreamStatusResponse = {
  items: UpstreamStatusItem[];
  total: number;
};
