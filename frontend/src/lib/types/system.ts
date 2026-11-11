/** 系统设置与账户类型 */

import type { ListResponse } from "@/lib/api/client";

export type SettingEntry = {
  key: string;
  value: string;
  [key: string]: unknown;
};

export type APIKey = {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  last_used_at: string | null;
  user_id: number;
  username: string;
};

export type AdminUser = {
  id: number;
  username: string;
  role: "admin" | "operator" | "readonly";
  created_at: string;
  [key: string]: unknown;
};

export type SessionInfo = {
  id: string;
  username: string;
  jti: string;
  ip: string;
  user_agent: string;
  device_info: string;
  login_at: string;
  last_active_at: string;
  expires_at: string;
};

export type LuaPlugin = {
  id: number;
  name: string;
  stage: "pre" | "post";
  source: string;
  enabled: boolean;
  priority: number;
  timeout_ms: number;
  description: string;
  site_id: number | null;
};

export type JSPlugin = {
  id: number;
  name: string;
  source: string;
  stage: "request" | "response";
  enabled: boolean;
  priority: number;
  site_id: number | null;
  timeout_ms: number;
  description: string;
  failure_mode: "fail_open" | "fail_closed";
};

export type PluginStatsItem = {
  id: number;
  name: string;
  stage: string;
  runs: number;
  failures: number;
  timeouts: number;
  avg_ms: number;
};

/** GET /lua-plugins/stats 响应：kv_executable=false 时请求路径不执行 Lua 脚本（Redis 未启用） */
export type LuaPluginStatsResponse = ListResponse<PluginStatsItem> & {
  kv_executable?: boolean;
};
