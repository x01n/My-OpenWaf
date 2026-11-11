/**
 * 系统设置页类型（与后端 internal/admin/system 各 handler 的 JSON 契约逐字对齐）。
 */

/* ---------- 网络配置 GET/POST /network-config ---------- */

export type NetworkConfig = {
  ipv6_enabled: boolean;
  http2_enabled: boolean;
  http3_enabled: boolean;
  http3_bind: string;
  http3_per_port_enabled: boolean;
  default_alpn: string;
  default_network: string;
};

/* ---------- TLS 全局默认 GET/POST /tls-config ---------- */

export type TLSDefaultConfig = {
  min_version: string;
  max_version: string;
  cipher_suites: string;
  default_alpn: string;
  has_explicit_default_alpn: boolean;
  curve_preferences: string;
  prefer_server_cipher_suites: boolean;
  session_tickets_enabled: boolean;
  allow_0rtt: boolean;
  has_explicit_allow_0rtt: boolean;
  self_signed_on_ip: boolean;
};

/* ---------- GET /tls-cipher-suites（只读清单） ---------- */

export type CipherSuiteInfo = {
  id: number;
  hex_id: string;
  name: string;
  tls_versions: string[];
  insecure: boolean;
  configurable: boolean;
};

export type CurveInfo = {
  id: number;
  name: string;
};

export type CipherSuitesResponse = {
  secure: CipherSuiteInfo[];
  insecure: CipherSuiteInfo[];
  curves: CurveInfo[];
};

/* ---------- HTTP/2 GET/POST /http2-config ---------- */

export type HTTP2Config = {
  read_timeout_seconds: number;
  disable_keepalive: boolean;
  permit_prohibited_cipher_suites: boolean;
  max_concurrent_streams: number;
  max_read_frame_size: number;
  idle_timeout_seconds: number;
  max_upload_buffer_per_connection: number;
  max_upload_buffer_per_stream: number;
  max_header_bytes: number;
  max_header_fields: number;
  max_handlers: number;
  max_queued_control_frames: number;
};

/* ---------- Redis GET/POST /redis-config（响应不回显密码） ---------- */

export type RedisConfigResponse = {
  enabled: boolean;
  addr: string;
  db: number;
  redis_addr: string;
  redis_db: number;
  password_set: boolean;
  redis_password_set: boolean;
  source: string;
  restart_required: boolean;
};

/* ---------- 日志 GET/POST /log-config ---------- */

export type LogConfig = {
  level: string;
  file_path: string;
  also_stdout: boolean;
};

/* ---------- 图片处理 GET/POST /image-transform ---------- */

export type ImageTransformConfig = {
  enabled: boolean;
  adaptive_webp: boolean;
  max_pixels: number;
  max_side: number;
  max_bytes: number;
  timeout_ms: number;
  concurrency: number;
  default_quality: number;
};

/* ---------- 运行时配置 GET /runtime-config（只读） ---------- */

export type RuntimeTransportPools = {
  http_transports: number;
  http2_cleartext_transports: number;
  http3_transports: number;
  total_transports: number;
  http_clients: number;
  http_no_timeout_clients: number;
  http3_clients: number;
  http3_no_timeout_clients: number;
  total_clients: number;
};

export type TLSCapabilityStatus = {
  key: string;
  label: string;
  status: string;
  detail: string;
  missing: boolean;
};

export type RuntimeConfig = {
  revision: number;
  db_driver: string;
  data_dir: string;
  redis_addr: string;
  redis_enabled: boolean;
  redis_db: number;
  source: string;
  editable: boolean;
  restart_required: boolean;
  upstream_transport_pools: RuntimeTransportPools;
  tls_capabilities: TLSCapabilityStatus[];
};

/* ---------- 环境变量覆盖 GET/POST /runtime-config/env-overrides ---------- */

export type RuntimeOverrideGroup = {
  key: string;
  label_key: string;
};

export type RuntimeOverrideItem = {
  key: string;
  env: string;
  group: string;
  /** bool / int / string / duration */
  type: string;
  default_value: unknown;
  env_value: unknown;
  effective_value: unknown;
  /** env / db / default */
  source: string;
  overridden: boolean;
  value: unknown;
  sensitive: boolean;
  secret_set: boolean;
  editable: boolean;
  min: number | null;
  max: number | null;
  /** 白名单类键的合法取值（后端 omitempty，可能缺省） */
  enum_values?: string[];
  label_key: string;
  description_key: string;
  restart_required: boolean;
  description: string;
};

export type RuntimeOverridesResponse = {
  groups: RuntimeOverrideGroup[];
  items: RuntimeOverrideItem[];
  warnings: string[];
  stored: string;
};

/* ---------- 备份 GET /backup/export + POST /backup/import ---------- */

export type BackupImportStats = {
  status: string;
  replace_mode: boolean;
  sites: number;
  certificates: number;
  rules: number;
  ip_entries: number;
};

/* ---------- 通用键值 GET /settings ---------- */

export type SettingsListItem = {
  id: number;
  key: string;
  value: string;
};
