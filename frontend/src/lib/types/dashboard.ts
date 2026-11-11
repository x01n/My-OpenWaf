/** 仪表盘数据契约（internal/admin/system/dashboard/dashboard.go） */

export type DashboardSummary = {
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
  unique_visitors_24h: number;
  revision: number;
  human_visits_24h: number;
  bot_visits_24h: number;
  unclassified_intercept_24h: number;
  visit_kind_total_24h: number;
  visitor_fusion_https_released_total_24h: number;
  visitor_fusion_human_24h: number;
  visitor_fusion_bot_24h: number;
  visitor_fusion_unknown_24h: number;
  bot_total_24h: number;
  bot_blocked_24h: number;
  bot_high_risk_24h: number;
  cve_total_24h: number;
  cve_by_type_24h: { category: string; count: number }[];
  drop_total_24h: number;
  drop_by_source_24h: Record<string, number>;
};
