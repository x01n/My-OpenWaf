/** 安全事件与可观测性类型（internal/admin/event/） */

export type SecurityEvent = {
  id: number;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  method: string;
  action: string;
  phase: string;
  category: string;
  rule_id: string;
  created_at: string;
  [key: string]: unknown;
};

export type AccessLog = {
  id: number;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  query_string: string;
  method: string;
  status_code: number;
  waf_action: string;
  user_agent: string;
  created_at: string;
  [key: string]: unknown;
};

export type EventStats = Record<string, number>;

/**
 * 全局 / 站点级安全事件统计快照（internal/store/repository SecurityEventStatsSnapshot）。
 *
 * 五组 TOP 排行在窗口内无数据时后端 Go nil slice 会序列化为 JSON `null`，
 * 因此类型标注为可空，调用方必须先兜底再遍历。
 */
export type SecurityEventStats = {
  total: number;
  hours: number;
  categories: { category: string; count: number }[] | null;
  top_ips: { client_ip: string; count: number }[] | null;
  top_paths: { path: string; count: number }[] | null;
  top_rules: { rule_id_str: string; count: number }[] | null;
  top_countries: { country: string; count: number }[] | null;
  intercepts: number;
  observes: number;
  requests: number;
  challenges: number;
};

/** 按 request_id 聚合的请求级事件摘要（internal/store/repository SecurityEventRequest） */
export type SecurityEventRequest = {
  request_id: string;
  event_count: number;
  /** 聚合窗口内最近一次事件时间 */
  last_seen: string;
};

export type TimelineBucket = {
  /** 后端 hourBucketExpr 输出 `YYYY-MM-DD HH:00`（非 ISO，空格分隔） */
  bucket: string;
  count: number;
  [key: string]: unknown;
};

export type FalsePositive = {
  id: number;
  security_event_id: number;
  note: string;
  status: "pending" | "confirmed" | "rejected";
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
};

export type RequestTrace = {
  request_id: string;
  access_logs: AccessLog[];
  security_events: SecurityEvent[];
  bot_scores: unknown[];
};

export type UpstreamStatusItem = {
  url: string;
  configured_protocol: string;
  last_http_protocol: string;
  healthy: boolean;
  fail_count: number;
  last_failure_kind: string;
  last_error: string;
  last_latency_ms: number;
  average_latency_ms: number;
  checked_at: string;
  last_success_at: string;
};
