/**
 * 站点管理扩展类型（internal/admin/site、rule、access、errorpage 的响应契约）。
 *
 * 基础 Site/SiteListener/Certificate 类型见 ./site.ts。
 */

import type { Site } from "./site";

/** 站点列表项：store.Site + 监听器摘要（internal/admin/site/site.go siteListItem） */
export type SiteListItem = Site & {
  /** 监听地址（store.Site.bind，站点类型未显式声明故在此补全） */
  bind: string;
  /** 上游地址，逗号分隔或 JSON 数组字符串（store.Site.upstream_urls） */
  upstream_urls: string;
  listener_summary: string;
  tls_summary: string;
  managed_listener_count: number;
};

/** 监听器（store.SiteListener JSON 形态） */
export type SiteListenerItem = {
  id: number;
  site_id: number;
  bind: string;
  network: string;
  tls_enabled: boolean;
  cert_id?: number | null;
  enabled: boolean;
  note?: string;
  created_at?: string;
  updated_at?: string;
};

/** 监听器创建/更新请求体 */
export type SiteListenerPayload = {
  bind: string;
  network: string;
  tls_enabled: boolean;
  cert_id?: number | null;
  enabled: boolean;
  note?: string;
};

/** 站点启动/停止响应（internal/admin/site StartSite/StopSite） */
export type SiteActionResponse = {
  status: string;
  message: string;
};

/** 站点访问控制配置（internal/admin/access accessConfigResp，脱敏响应） */
export type SiteAccessConfig = {
  site_id: number;
  enabled: boolean;
  shared_password_set: boolean;
  session_ttl: number;
};

/** 站点访问控制保存请求体（shared_password 留空表示不变更） */
export type SiteAccessConfigPayload = {
  enabled: boolean;
  shared_password: string;
  session_ttl: number;
};

/** 错误页单条配置（internal/admin/site/errorpage errorPageConfig） */
export type ErrorPageConfig = {
  status_code: number;
  title: string;
  html: string;
  content_type: string;
};

/** GET /sites/:id/error-pages 响应 */
export type SiteErrorPagesResponse = {
  site_id: number;
  error_pages: Record<string, ErrorPageConfig>;
};

/** GET /error-pages/defaults 响应 */
export type DefaultErrorPagesResponse = {
  defaults: Record<string, ErrorPageConfig>;
};

/** POST /sites/:id/error-pages 请求体 */
export type SiteErrorPagesPayload = {
  error_pages: Record<string, ErrorPageConfig>;
};

/** 应用路由规则（internal/store/approute.ApplicationRouteRule） */
export type ApplicationRouteRule = {
  id: number;
  site_id: number;
  name: string;
  enabled: boolean;
  priority: number;
  target: string;
  op: string;
  pattern: string;
  header_key?: string;
  created_at?: string;
  updated_at?: string;
};

/** 应用路由规则创建/更新请求体（internal/admin/rule route.go applicationRouteRuleRequest） */
export type ApplicationRouteRulePayload = {
  name: string;
  enabled: boolean;
  priority: number;
  target: string;
  op: string;
  pattern: string;
  header_key?: string;
};

/** 证书域名匹配到的站点（certificate.certificateMatchedSite） */
export type CertificateMatchedSite = {
  id: number;
  host: string;
  tls_enabled: boolean;
  cert_id?: number | null;
  matched_name: string;
};

/** POST /certificates/:id/apply-to-sites 响应 */
export type CertificateApplyResponse = {
  certificate_id: number;
  applied_sites: CertificateMatchedSite[];
  site_count?: number;
  listener_count?: number;
};
