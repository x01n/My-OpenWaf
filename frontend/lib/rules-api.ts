import { api, buildQuery, type CVERule, type PaginatedResponse } from "./api";

/* -- OWASP Rule Types -- */

export interface OWASPRule {
  id: string;
  category: string;
  name: string;
  description: string;
  enabled: boolean;
}

export interface OWASPRulesResponse {
  items: OWASPRule[];
  grouped: Record<string, OWASPRule[]>;
  total: number;
}

export interface OWASPRuleStats {
  total: number;
  enabled_count: number;
  disabled_count: number;
  by_category: Record<string, number>;
}

/* -- Error Page Types -- */

export interface ErrorPageConfig {
  status_code: number;
  title: string;
  html: string;
  content_type: string;
}

export interface SiteErrorPagesResponse {
  site_id: number;
  error_pages: Record<string, ErrorPageConfig>;
}

export interface DefaultErrorPagesResponse {
  defaults: Record<string, ErrorPageConfig>;
}

export interface PreviewResponse {
  rendered: string;
  status_code: number;
  parse_error?: string;
  execute_error?: string;
}

/* -- Sensitivity Types -- */

export interface SensitivityConfig {
  category_sensitivity: Record<string, string>;
}

/* -- CVE Rules Stats -- */

export interface CVERuleStats {
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  enabled: number;
  disabled: number;
}

/* -- OWASP Rule API -- */

export async function getOWASPRules(category?: string): Promise<OWASPRulesResponse> {
  const q = category ? buildQuery({ category }) : "";
  return api<OWASPRulesResponse>(`/api/v1/owasp-rules${q}`);
}

export async function getOWASPRuleStats(): Promise<OWASPRuleStats> {
  return api<OWASPRuleStats>("/api/v1/owasp-rules/stats");
}

export async function updateOWASPRule(id: string, update: { enabled?: boolean; whitelist?: string[] }): Promise<void> {
  await api(`/api/v1/owasp-rules/${id}/update`, {
    method: "POST",
    body: JSON.stringify(update),
  });
}

export async function batchUpdateOWASPRules(
  rules: Array<{ id: string; enabled?: boolean; whitelist?: string[] }>
): Promise<{ updated: number; total: number }> {
  return api<{ updated: number; total: number }>("/api/v1/owasp-rules/batch", {
    method: "POST",
    body: JSON.stringify({ rules }),
  });
}

/* -- Sensitivity API -- */

export async function getSensitivityConfig(protectionId: number | string): Promise<SensitivityConfig> {
  return api<SensitivityConfig>(`/api/v1/protection/${protectionId}/sensitivity`);
}

export async function updateSensitivityConfig(
  protectionId: number | string,
  config: SensitivityConfig
): Promise<SensitivityConfig> {
  return api<SensitivityConfig>(`/api/v1/protection/${protectionId}/sensitivity`, {
    method: "POST",
    body: JSON.stringify(config),
  });
}

/* -- Error Pages API -- */

export async function getSiteErrorPages(siteId: number): Promise<SiteErrorPagesResponse> {
  return api<SiteErrorPagesResponse>(`/api/v1/sites/${siteId}/error-pages`);
}

export async function updateSiteErrorPages(
  siteId: number,
  errorPages: Record<string, ErrorPageConfig>
): Promise<SiteErrorPagesResponse> {
  return api<SiteErrorPagesResponse>(`/api/v1/sites/${siteId}/error-pages`, {
    method: "POST",
    body: JSON.stringify({ error_pages: errorPages }),
  });
}

export async function getDefaultErrorPages(): Promise<DefaultErrorPagesResponse> {
  return api<DefaultErrorPagesResponse>("/api/v1/error-pages/defaults");
}

export async function previewErrorPage(html: string, statusCode?: number): Promise<PreviewResponse> {
  return api<PreviewResponse>("/api/v1/error-pages/preview", {
    method: "POST",
    body: JSON.stringify({ html, status_code: statusCode ?? 0 }),
  });
}

/* -- CVE Rules Stats -- */

export async function getCVERuleStats(): Promise<CVERuleStats> {
  const res = await api<PaginatedResponse<CVERule>>("/api/v1/cve-rules?page_size=9999");
  const items = res.items ?? [];
  const bySev: Record<string, number> = {};
  const byCat: Record<string, number> = {};
  let enabled = 0;
  let disabled = 0;
  for (const r of items) {
    bySev[r.severity] = (bySev[r.severity] ?? 0) + 1;
    byCat[r.category] = (byCat[r.category] ?? 0) + 1;
    if (r.enabled) enabled++;
    else disabled++;
  }
  return { total: items.length, by_severity: bySev, by_category: byCat, enabled, disabled };
}

export async function batchToggleCVERules(ids: number[], enabled: boolean): Promise<void> {
  await Promise.all(
    ids.map((id) =>
      api(`/api/v1/cve-rules/${id}/update`, {
        method: "POST",
        body: JSON.stringify({ enabled }),
      })
    )
  );
}