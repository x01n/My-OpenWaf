/**
 * 站点列表展示层的数据解析工具。
 *
 * 这里的所有解析规则都对齐后端的真实产出格式，不做格式推测：
 * - `upstream_urls`：见 `internal/admin/shared/site_upstreams.go` 的
 *   `parseSiteUpstreamURLsForValidation`——以 `[` 开头时按 JSON 字符串数组解析，
 *   否则按逗号分隔。支持的 scheme 为 http / https / h2c / h3。
 * - `listener_summary`：见 `internal/admin/site/site.go` 的 `ListSites`——
 *   存在受管监听器时用 `" / "` 连接各 `listener.Bind`，否则直接取 `site.bind`。
 */

import type { Site } from "@/lib/types";

/** 站点在列表中的运行姿态，由后端字段推导而来 */
export type SiteMode = "protection" | "observe" | "maintenance";

/**
 * 解析站点上游地址列表。
 *
 * 后端把 `upstream_urls` 存成两种形态之一：JSON 字符串数组，或逗号分隔串。
 * 只按逗号分割会把 `["http://127.0.0.1:8800"]` 整串当成一个地址显示。
 *
 * @param {string | null | undefined} raw 站点的 `upstream_urls` 原始值
 * @returns {string[]} 去空白后的上游地址列表
 */
export function parseUpstreamUrls(raw?: string | null): string[] {
  const text = (raw || "").trim();
  if (!text) return [];

  if (text.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (Array.isArray(parsed)) {
        return parsed
          .filter((v): v is string => typeof v === "string")
          .map((v) => v.trim())
          .filter(Boolean);
      }
    } catch {
      // JSON 解析失败时退回逗号分隔，与后端的宽松处理保持一致
    }
  }

  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * 从 bind 地址中取端口号。
 * 兼容 `:443`、`0.0.0.0:8080`、`[::]:443` 三种写法。
 *
 * @param {string} bind 监听绑定地址
 * @returns {string} 端口号；无法识别时回退为原始串
 */
function extractPort(bind: string): string {
  const idx = bind.lastIndexOf(":");
  if (idx < 0) return bind;
  return bind.slice(idx + 1) || bind;
}

/** 单条监听端口的展示信息 */
export interface SiteListenerBadge {
  /** 原始 bind 地址，用于 title 提示 */
  bind: string;
  /** 端口号 */
  port: string;
  /**
   * 协议标注。
   *
   * 仅在站点只有一条监听（`managed_listener_count === 0`，此时后端用 `site.bind`
   * 与站点级 `tls_enabled` 生成摘要）时可以确定。多监听场景下列表接口只返回聚合的
   * `tls_summary`，不含逐条监听的 TLS 状态，此时为 `null`，不做推测。
   */
  scheme: "HTTP" | "HTTPS" | null;
}

/**
 * 解析站点的监听端口列表。
 *
 * @param {Site} site 站点列表项
 * @returns {SiteListenerBadge[]} 监听端口展示列表
 */
export function parseSiteListeners(site: Site): SiteListenerBadge[] {
  const isMulti = (site.managed_listener_count ?? 0) > 0;
  const source = (site.listener_summary || site.bind || "").trim();
  if (!source) return [];

  // 受管监听器摘要用 " / " 连接；单监听时整串就是一个 bind
  const binds = isMulti ? source.split(" / ") : [source];

  return binds
    .map((b) => b.trim())
    .filter(Boolean)
    .map((bind) => ({
      bind,
      port: extractPort(bind),
      scheme: isMulti ? null : site.tls_enabled ? "HTTPS" : "HTTP",
    }));
}

/**
 * 推导站点的防护姿态。
 * - `maintenance_enabled` 为 true → 维护中
 * - OWASP 关闭或动作为观察类 → 观察模式
 * - 其余 → 防护模式
 *
 * @param {Site} site 站点
 * @returns {SiteMode} 防护姿态
 */
export function resolveSiteMode(site: Site): SiteMode {
  if (site.maintenance_enabled) return "maintenance";
  const observeAction =
    site.owasp_action === "observe" || site.owasp_action === "log_only";
  if (site.owasp_enabled === false || observeAction) return "observe";
  return "protection";
}

/** 站点已显式开启的防护能力标识 */
export type SiteCapabilityKey =
  | "bot"
  | "cve"
  | "rateLimit"
  | "cache"
  | "antiReplay"
  | "dynamic"
  | "cc";

/**
 * 汇总站点上「显式开启」的防护能力。
 *
 * 站点级可空字段（`boolean | null`）中 `null` 表示继承全局，既不是开也不是关，
 * 因此只收集明确为 `true` 的项，避免把继承状态渲染成站点自身的配置。
 *
 * @param {Site} site 站点
 * @returns {SiteCapabilityKey[]} 显式开启的能力列表
 */
export function resolveSiteCapabilities(site: Site): SiteCapabilityKey[] {
  const caps: SiteCapabilityKey[] = [];
  if (site.bot_protection_enabled === true) caps.push("bot");
  if (site.cve_enabled === true) caps.push("cve");
  if (site.rate_limit_enabled === true) caps.push("rateLimit");
  if (site.cache_enabled) caps.push("cache");
  if (site.anti_replay_enabled) caps.push("antiReplay");
  if (site.dynamic_protection_enabled === true) caps.push("dynamic");
  if (site.cc_use_custom === true) caps.push("cc");
  return caps;
}
