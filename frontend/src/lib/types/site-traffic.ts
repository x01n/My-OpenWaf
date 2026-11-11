/**
 * 站点流量可观测性类型。
 *
 * 字段严格对应后端 JSON tag：
 * - internal/store/repository/access_log.go SiteAccessLogStats
 * - internal/store/repository/drop_event.go DropStatsSummary
 * - internal/store/events.go AccessLog / DropEvent
 */

/** GET /sites/:id/access-logs/stats?hours=24 响应 */
export type SiteAccessLogStats = {
  requests: number;
  intercepts: number;
  observes: number;
  cache_hits: number;
  cache_misses: number;
  cache_bypasses: number;
  cache_stales: number;
};

/** GET /sites/:id/drop-stats 响应（DropStatsSummary） */
export type SiteDropStats = {
  total_24h: number;
  by_bot: number;
  by_cve: number;
  by_rule: number;
  by_ip_reputation: number;
};

/** GET /sites/:id/access-logs 列表项（internal/store/events.go AccessLog） */
export type SiteAccessLog = {
  id: number;
  created_at: string;
  site_id: number;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  query_string: string;
  method: string;
  status_code: number;
  waf_action: string;
  cache_state: string;
  upstream: string;
  user_agent: string;
  request_headers: string;
  request_body_preview: string;
  request_body_truncated: boolean;
  request_size: number;
  response_headers: string;
  http_protocol: string;
  upstream_http_protocol: string;
  tls_version: string;
  tls_sni: string;
  tls_alpn: string;
  tls_ja3: string;
  tls_ja3_hash: string;
  tls_ja4: string;
  tls_cipher_suites: string;
  tls_extensions: string;
  tls_curves: string;
  tls_point_formats: string;
  header_order: string;
  visitor_fusion_class: string;
  visitor_fusion_score: number;
  visitor_fusion_client_family: string;
  visitor_fusion_ua_claim: string;
  visitor_fusion_consistency: string;
  visitor_fusion_evidence_sufficient: boolean;
  visitor_fusion_reasons: string;
  zero_rtt: boolean;
  upstream_latency_ms: number;
  response_size: number;
};

/** GET /sites/:id/drop-events 列表项（internal/store/events.go DropEvent） */
export type SiteDropEvent = {
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
