/* eslint-disable @typescript-eslint/no-explicit-any */
import useSWR, { mutate, type Key } from "swr";
import { useCallback, useState } from "react";
import {
  siteApi,
  certificateApi,
  ruleApi,
  policyApi,
  protectionApi,
  ipListApi,
  securityEventApi,
  accessLogApi,
  dashboardApi,
  botApi,
  captchaApi,
  chainApi,
  cveApi,
  owaspApi,
  dropApi,
  settingsApi,
  upstreamApi,
  runtimeApi,
  apiKeyApi,
  errorPageApi,
  adminUserApi,
  threatIntelApi,
  falsePositiveApi,
  presetBotWhitelistApi,
  requestTraceApi,
  systemApi,
  pageTemplateApi,
  authApi,
  accessApi,
  fingerprintApi,
} from "@/lib/api";

/**
 * 通用 fetcher
 */
function fetcher<T>(fn: () => Promise<T>) {
  return fn();
}

/**
 * 通用 SWR Hook 工厂
 */
function useApiQuery<T>(
  key: Key,
  fetchFn: () => Promise<T>,
  options?: any
) {
  return useSWR<T>(key, () => fetcher(fetchFn), {
    revalidateOnFocus: false,
    ...options,
  });
}

/**
 * 通用 Mutation Hook
 */
export function useMutation<T, D = any>(
  mutateFn: (data: D) => Promise<T>,
  options?: {
    onSuccess?: (data: T) => void;
    onError?: (error: any) => void;
    invalidateKeys?: Key[];
  }
) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const execute = useCallback(
    async (data: D) => {
      setLoading(true);
      setError(null);
      try {
        const result = await mutateFn(data);
        if (options?.invalidateKeys) {
          options.invalidateKeys.forEach((key) => {
            mutate(
              (cachedKey) =>
                cachedKey === key ||
                (Array.isArray(cachedKey) && cachedKey[0] === key),
              undefined,
              { revalidate: true }
            );
          });
        }
        options?.onSuccess?.(result);
        return result;
      } catch (err) {
        setError(err as Error);
        options?.onError?.(err);
        throw err;
      } finally {
        setLoading(false);
      }
    },
    [mutateFn, options]
  );

  return { execute, loading, error };
}

// ============================================================
// 站点相关 Hook
// ============================================================

export function useSites(params?: { page?: number; page_size?: number }) {
  return useApiQuery(["sites", params], () => siteApi.list(params));
}

export function useSite(id: string | number | undefined) {
  return useApiQuery(id ? ["site", id] : null, () => siteApi.get(id!));
}

export function useSiteListeners(id: string | number | undefined) {
  return useApiQuery(
    id ? ["site-listeners", id] : null,
    () => siteApi.getListeners(id!)
  );
}

export function useSiteRules(id: string | number | undefined) {
  return useApiQuery(
    id ? ["site-rules", id] : null,
    () => siteApi.getRules(id!)
  );
}

export function useSiteRecordedResources(id: string | number | undefined) {
  return useApiQuery(
    id ? ["site-recorded-resources", id] : null,
    () => siteApi.getRecordedResources(id!)
  );
}

export function useSiteStats(
  id: string | number | undefined,
  params?: { hours?: number },
  options?: { refreshInterval?: number }
) {
  return useApiQuery(
    id ? ["site-stats", id, params] : null,
    () => securityEventApi.getSiteStats(id!, params),
    options
  );
}

export function useSiteTimeline(
  id: string | number | undefined,
  params?: { hours?: number },
  options?: { refreshInterval?: number }
) {
  return useApiQuery(
    id ? ["site-timeline", id, params] : null,
    () => securityEventApi.getSiteTimeline(id!, params),
    options
  );
}

export function useSiteAccessStats(id: string | number | undefined) {
  return useApiQuery(
    id ? ["site-access-stats", id] : null,
    () => accessLogApi.getSiteStats(id!)
  );
}

export function useListenerCreate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number | string; data: Partial<any> }) =>
      siteApi.createListener(siteId, data),
    { invalidateKeys: ["site-listeners"] }
  );
}

export function useListenerUpdate() {
  return useMutation(
    async ({ siteId, lid, data }: { siteId: number | string; lid: number | string; data: Partial<any> }) =>
      siteApi.updateListener(siteId, lid, data),
    { invalidateKeys: ["site-listeners"] }
  );
}

export function useListenerDelete() {
  return useMutation(
    async ({ siteId, lid }: { siteId: number | string; lid: number | string }) =>
      siteApi.deleteListener(siteId, lid),
    { invalidateKeys: ["site-listeners"] }
  );
}

// ============================================================
// 证书相关 Hook
// ============================================================

export function useCertificates() {
  return useApiQuery(["certificates"], () => certificateApi.list());
}

export function useCertificate(id: string | number | undefined) {
  return useApiQuery(
    id ? ["certificate", id] : null,
    () => certificateApi.get(id!)
  );
}

// ============================================================
// 规则相关 Hook
// ============================================================

export function useRules(params?: any) {
  return useApiQuery(["rules", params], () => ruleApi.list(params));
}

export function useRule(id: string | number | undefined) {
  return useApiQuery(id ? ["rule", id] : null, () => ruleApi.get(id!));
}

export function useRuleTemplates() {
  return useApiQuery(["rule-templates"], () => ruleApi.getTemplates());
}

// ============================================================
// 策略相关 Hook
// ============================================================

export function usePolicies() {
  return useApiQuery(["policies"], () => policyApi.list());
}

export function usePolicy(id: string | number | undefined) {
  return useApiQuery(
    id ? ["policy", id] : null,
    () => policyApi.get(id!)
  );
}

// ============================================================
// 防护设置相关 Hook
// ============================================================

export function useProtectionSettings() {
  return useApiQuery(["protection-settings"], () => protectionApi.getSettings());
}

export function useBotSettings() {
  return useApiQuery(["bot-settings"], () => botApi.getSettings());
}

export function useCaptchaConfig() {
  return useApiQuery(["captcha-config"], () => captchaApi.getConfig());
}

export function useChainConfig() {
  return useApiQuery(["chain-config"], () => chainApi.getConfig());
}

// ============================================================
// IP 列表相关 Hook
// ============================================================

/**
 * 查询 IP 名单条目。
 * @param params 可选筛选参数；传 site_id 时按站点作用域查询，不传则查全局条目
 * @param enabled 为 false 时跳过请求（SWR key 置空），用于按需触发站点查询
 */
export function useIPLists(
  params?: { site_id?: number; kind?: string },
  enabled = true
) {
  return useApiQuery(
    enabled ? ["ip-lists", params] : null,
    () => ipListApi.list(params)
  );
}

// ============================================================
// 安全事件相关 Hook
// ============================================================

export function useSecurityEvents(params?: any) {
  return useApiQuery(
    ["security-events", params],
    () => securityEventApi.list(params)
  );
}

export function useSecurityEventStats(params?: any) {
  return useApiQuery(
    ["security-event-stats", params],
    () => securityEventApi.getStats(params)
  );
}

export function useDashboardStats(params?: { hours?: number }) {
  return useApiQuery(
    ["dashboard-stats", params],
    () => securityEventApi.getStats(params),
    { refreshInterval: 30000 }
  );
}

export function useSecurityEventTimeline(params?: any) {
  return useApiQuery(
    ["security-event-timeline", params],
    () => securityEventApi.getTimeline(params)
  );
}

// ============================================================
// 访问日志相关 Hook
// ============================================================

export function useAccessLogs(params?: any) {
  return useApiQuery(
    ["access-logs", params],
    () => accessLogApi.list(params)
  );
}

// ============================================================
// 请求追踪相关 Hook
// ============================================================

/**
 * 通过 request_id 拉取全链路
 * requestId 为空时不请求
 */
export function useRequestTrace(requestId: string | null | undefined) {
  return useApiQuery(
    requestId ? ["request-trace", requestId] : null,
    () => requestTraceApi.get(requestId!)
  );
}

// ============================================================
// Dashboard 相关 Hook
// ============================================================

export function useDashboard() {
  return useApiQuery(
    ["dashboard"],
    () => dashboardApi.getSummary(),
    { refreshInterval: 10000 }
  );
}

// ============================================================
// CVE / OWASP 相关 Hook
// ============================================================

export function useCveRules() {
  return useApiQuery(["cve-rules"], () => cveApi.list());
}

export function useOwaspRules() {
  return useApiQuery(["owasp-rules"], () => owaspApi.list());
}

// ============================================================
// 丢弃策略相关 Hook
// ============================================================

export function useDropPolicy() {
  return useApiQuery(["drop-policy"], () => dropApi.getPolicy());
}

export function useDropEvents(params?: any) {
  return useApiQuery(
    ["drop-events", params],
    () => dropApi.getEvents(params)
  );
}

// ============================================================
// 系统设置相关 Hook
// ============================================================

export function useSettings() {
  return useApiQuery(["settings"], () => settingsApi.list());
}

export function useNetworkConfig() {
  return useApiQuery(["network-config"], () => settingsApi.getNetwork());
}

export function useTLSConfig() {
  return useApiQuery(["tls-config"], () => settingsApi.getTLS());
}

export function useLogConfig() {
  return useApiQuery(["log-config"], () => settingsApi.getLog());
}

export function useRuntimeConfig() {
  return useApiQuery(["runtime-config"], () => runtimeApi.getConfig());
}

export function useUpstreamStatus() {
  return useApiQuery<import("@/lib/types").UpstreamStatusResponse>(
    ["upstream-status"],
    () => upstreamApi.getStatus(),
    { refreshInterval: 10000 }
  );
}

// ============================================================
// API 密钥相关 Hook
// ============================================================

export function useApiKeys() {
  return useApiQuery(["api-keys"], () => apiKeyApi.list());
}

// ============================================================
// 错误页面相关 Hook
// ============================================================

export function useDefaultErrorPages() {
  return useApiQuery(["error-pages-defaults"], () => errorPageApi.getDefaults());
}

// ============================================================
// 提交操作 Hook（乐观更新）
// ============================================================

export function useSiteMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<any> }) => {
      if (id) {
        return siteApi.update(id, data);
      }
      return siteApi.create(data);
    },
    { invalidateKeys: ["sites", "site"] }
  );
}

export function useSiteDelete() {
  return useMutation(
    async (id: number) => siteApi.delete(id),
    { invalidateKeys: ["sites"] }
  );
}

export function useSiteStart() {
  return useMutation(
    async (id: number) => siteApi.start(id),
    { invalidateKeys: ["sites", "site"] }
  );
}

export function useSiteStop() {
  return useMutation(
    async (id: number) => siteApi.stop(id),
    { invalidateKeys: ["sites", "site"] }
  );
}

export function useRuleMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<any> }) => {
      if (id) {
        return ruleApi.update(id, data);
      }
      return ruleApi.create(data);
    },
    { invalidateKeys: ["rules"] }
  );
}

export function useRuleDelete() {
  return useMutation(
    async (id: number) => ruleApi.delete(id),
    { invalidateKeys: ["rules"] }
  );
}

export function useCertificateMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<any> }) => {
      if (id) {
        return certificateApi.update(id, data);
      }
      return certificateApi.create(data);
    },
    { invalidateKeys: ["certificates"] }
  );
}

export function useCertificateDelete() {
  return useMutation(
    async (id: number) => certificateApi.delete(id),
    { invalidateKeys: ["certificates"] }
  );
}

export function usePolicyMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<any> }) => {
      if (id) {
        return policyApi.update(id, data);
      }
      return policyApi.create(data);
    }
  );
}

export function usePolicyDelete() {
  return useMutation(
    async (id: number) => policyApi.delete(id),
    { invalidateKeys: ["policies"] }
  );
}

export function useProtectionSettingsUpdate() {
  return useMutation(
    async (data: any) => protectionApi.updateSettings(data),
    { invalidateKeys: ["protection-settings"] }
  );
}

export function useBotSettingsUpdate() {
  return useMutation(
    async (data: any) => botApi.updateSettings(data),
    { invalidateKeys: ["bot-settings"] }
  );
}

export function useCaptchaConfigUpdate() {
  return useMutation(
    async (data: any) => captchaApi.updateConfig(data),
    { invalidateKeys: ["captcha-config"] }
  );
}

export function useChainConfigUpdate() {
  return useMutation(
    async (data: any) => chainApi.updateConfig(data),
    { invalidateKeys: ["chain-config"] }
  );
}

export function useIPListMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: any }) => {
      if (id) {
        return ipListApi.update(id, data);
      }
      return ipListApi.create(data);
    }
  );
}

export function useIPListDelete() {
  return useMutation(
    async (id: number) => ipListApi.delete(id),
    { invalidateKeys: ["ip-lists"] }
  );
}

/**
 * 预览预置爬虫白名单条目（仅只读，不写库）。
 */
export function usePresetBotWhitelist(enabled = true) {
  return useApiQuery(
    enabled ? ["preset-bot-whitelist"] : null,
    () => presetBotWhitelistApi.preview()
  );
}

/**
 * 触发预置爬虫白名单写入 IP 白名单表。写入后自动失效 IP 列表缓存。
 */
export function usePresetBotWhitelistSeed() {
  return useMutation(
    async () => presetBotWhitelistApi.seed(),
    { invalidateKeys: ["ip-lists"] }
  );
}

// ============================================================
// 威胁情报订阅相关 Hook
// ============================================================

/**
 * 查询威胁情报订阅源列表。
 */
export function useThreatIntelFeeds() {
  return useApiQuery(["threat-intel-feeds"], () => threatIntelApi.list());
}

/**
 * 新建 / 更新订阅源。传入 id 走更新，否则走新建。
 */
export function useThreatIntelMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<any> }) => {
      if (id) {
        return threatIntelApi.update(id, data);
      }
      return threatIntelApi.create(data);
    },
    { invalidateKeys: ["threat-intel-feeds"] }
  );
}

/**
 * 删除订阅源（连带删除该源的 IP 条目）。
 */
export function useThreatIntelDelete() {
  return useMutation(
    async (id: number) => threatIntelApi.delete(id),
    { invalidateKeys: ["threat-intel-feeds"] }
  );
}

/**
 * 手动立即同步订阅源。
 */
export function useThreatIntelSync() {
  return useMutation(
    async (id: number) => threatIntelApi.sync(id),
    { invalidateKeys: ["threat-intel-feeds"] }
  );
}

/**
 * 分页查询威胁情报同步历史，30 秒自动刷新。
 */
export function useThreatIntelSyncLogs(params?: {
  page?: number;
  page_size?: number;
  feed_id?: number;
  status?: "success" | "failed";
}) {
  return useApiQuery(
    ["threat-intel-sync-logs", params],
    () => threatIntelApi.listSyncLogs(params),
    { refreshInterval: 30000 }
  );
}

export function useSettingsUpdate() {
  return useMutation(
    async ({ key, value }: { key: string; value: any }) =>
      settingsApi.set(key, value),
    { invalidateKeys: ["settings"] }
  );
}

export function useNetworkConfigUpdate() {
  return useMutation(
    async (data: any) => settingsApi.updateNetwork(data),
    { invalidateKeys: ["network-config"] }
  );
}

export function useTLSConfigUpdate() {
  return useMutation(
    async (data: any) => settingsApi.updateTLS(data),
    { invalidateKeys: ["tls-config"] }
  );
}

export function useLogConfigUpdate() {
  return useMutation(
    async (data: any) => settingsApi.updateLog(data),
    { invalidateKeys: ["log-config"] }
  );
}

export function useRedisConfig() {
  return useApiQuery(["redis-config"], () => settingsApi.getRedis());
}

export function useRedisConfigUpdate() {
  return useMutation(
    async (data: { redis_addr: string; redis_password?: string; redis_db?: number }) =>
      settingsApi.updateRedis(data),
    { invalidateKeys: ["redis-config"] }
  );
}

export function useAdminSessions() {
  return useApiQuery("admin-sessions", () => authApi.listSessions());
}

export function useForceLogout() {
  return useMutation(
    async (sessionId: number) => authApi.forceLogout(sessionId),
    { invalidateKeys: ["admin-sessions"] }
  );
}

export function useDropPolicyUpdate() {
  return useMutation(
    async (data: any) => dropApi.updatePolicy(data),
    { invalidateKeys: ["drop-policy"] }
  );
}

export function useCveBatchUpdate() {
  return useMutation(
    async (data: any) => cveApi.batch(data),
    { invalidateKeys: ["cve-rules"] }
  );
}

export function useOwaspBatchUpdate() {
  return useMutation(
    async (data: any) => owaspApi.batch(data),
    { invalidateKeys: ["owasp-rules"] }
  );
}

export function useApiKeyDelete() {
  return useMutation(
    async (id: number) => apiKeyApi.delete(id),
    { invalidateKeys: ["api-keys"] }
  );
}

export function useApiKeyCreate() {
  return useMutation(
    async (data: { name: string }) => apiKeyApi.create(data),
    { invalidateKeys: ["api-keys"] }
  );
}

// ============================================================
// 管理员账户相关 Hook
// ============================================================

export function useAdminUsers() {
  return useApiQuery(["admin-users"], () => adminUserApi.list());
}

export function useAdminUserCreate() {
  return useMutation(
    async (data: { username: string; password: string; role: string }) =>
      adminUserApi.create(data),
    { invalidateKeys: ["admin-users"] }
  );
}

export function useAdminUserUpdateRole() {
  return useMutation(
    async ({ id, role }: { id: number; role: string }) =>
      adminUserApi.updateRole(id, role),
    { invalidateKeys: ["admin-users"] }
  );
}

export function useAdminUserUpdatePassword() {
  return useMutation(
    async ({ id, password }: { id: number; password: string }) =>
      adminUserApi.updatePassword(id, password),
    { invalidateKeys: ["admin-users"] }
  );
}

export function useAdminUserDelete() {
  return useMutation(
    async (id: number) => adminUserApi.delete(id),
    { invalidateKeys: ["admin-users"] }
  );
}

export function useErrorPagesUpdate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: any }) =>
      siteApi.updateErrorPages(siteId, data),
    { invalidateKeys: ["site-error-pages"] }
  );
}

// ============================================================
// 误报反馈相关 Hook
// ============================================================

/**
 * 分页查询误报反馈记录。
 */
export function useFalsePositives(params?: { page?: number; page_size?: number; status?: string }) {
  return useApiQuery(
    ["false-positives", params],
    () => falsePositiveApi.list(params)
  );
}

/**
 * 提交一条新的误报反馈。
 */
export function useFalsePositiveCreate() {
  return useMutation(
    async (data: Partial<import("@/lib/types").FalsePositiveReport>) =>
      falsePositiveApi.create(data),
    { invalidateKeys: ["false-positives"] }
  );
}

/**
 * 更新一条反馈的审查状态（confirmed / rejected / pending）。
 */
export function useFalsePositiveStatusUpdate() {
  return useMutation(
    async ({ id, status }: { id: number; status: string }) =>
      falsePositiveApi.updateStatus(id, status),
    { invalidateKeys: ["false-positives"] }
  );
}

/**
 * 删除一条反馈记录（仅 admin 可操作）。
 */
export function useFalsePositiveDelete() {
  return useMutation(
    async (id: number) => falsePositiveApi.delete(id),
    { invalidateKeys: ["false-positives"] }
  );
}

export function useSystemReload() {
  return useMutation(async () => systemApi.reload());
}

// ── Page Templates ──

export function usePageTemplate(type: string) {
  return useApiQuery(`page-template-${type}`, () => pageTemplateApi.get(type));
}

export function usePageTemplateUpdate() {
  return useMutation(
    async ({ type, data }: { type: string; data: Record<string, string> }) =>
      pageTemplateApi.update(type, data),
    { invalidateKeys: ["page-template-captcha", "page-template-challenge", "page-template-block"] }
  );
}

export function usePageTemplateReset() {
  return useMutation(
    async (type: string) => pageTemplateApi.reset(type),
    { invalidateKeys: ["page-template-captcha", "page-template-challenge", "page-template-block"] }
  );
}

export function usePageTemplatePreview(type: string) {
  return useApiQuery(`page-template-preview-${type}`, () => pageTemplateApi.preview(type));
}

// ── Access Control (per-site) ──

export function useAccessProviderCreate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: any }) =>
      accessApi.createProvider(siteId, data),
    { invalidateKeys: ["access-providers"] }
  );
}

export function useAccessProviderUpdate() {
  return useMutation(
    async ({ siteId, pid, data }: { siteId: number; pid: number; data: any }) =>
      accessApi.updateProvider(siteId, pid, data),
    { invalidateKeys: ["access-providers"] }
  );
}

export function useAccessUserCreate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: { username: string; password: string; enabled?: boolean } }) =>
      accessApi.createUser(siteId, data),
    { invalidateKeys: ["access-users"] }
  );
}

export function useAccessUserUpdate() {
  return useMutation(
    async ({ siteId, uid, data }: { siteId: number; uid: number; data: any }) =>
      accessApi.updateUser(siteId, uid, data),
    { invalidateKeys: ["access-users"] }
  );
}

export function useAccessPathRuleCreate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: any }) =>
      accessApi.createPathRule(siteId, data),
    { invalidateKeys: ["access-path-rules"] }
  );
}

export function useAccessPathRuleUpdate() {
  return useMutation(
    async ({ siteId, rid, data }: { siteId: number; rid: number; data: any }) =>
      accessApi.updatePathRule(siteId, rid, data),
    { invalidateKeys: ["access-path-rules"] }
  );
}

// ============================================================
// 站点访问控制 Query Hooks
// ============================================================

export function useAccessConfig(siteId: number | string | undefined) {
  return useApiQuery(
    siteId ? ["access-config", siteId] : null,
    () => accessApi.getConfig(siteId!)
  );
}

export function useAccessProviders(siteId: number | string | undefined) {
  return useApiQuery(
    siteId ? ["access-providers", siteId] : null,
    () => accessApi.listProviders(siteId!)
  );
}

export function useAccessUsers(siteId: number | string | undefined) {
  return useApiQuery(
    siteId ? ["access-users", siteId] : null,
    () => accessApi.listUsers(siteId!)
  );
}

export function useAccessPathRules(siteId: number | string | undefined) {
  return useApiQuery(
    siteId ? ["access-path-rules", siteId] : null,
    () => accessApi.listPathRules(siteId!)
  );
}

// ============================================================
// 证书 ACME 状态 Hook
// ============================================================

export function useACMEStatus() {
  return useApiQuery(["acme-status"], () => certificateApi.getACMEStatus());
}

export function useACMEConfig() {
  return useApiQuery(["acme-config"], () => certificateApi.getACMEConfig());
}

// ============================================================
// TLS 指纹 Hook
// ============================================================

export function useFingerprints(params?: { page?: number; page_size?: number }) {
  return useApiQuery(["fingerprints", params], () => fingerprintApi.list(params));
}

// ============================================================
// Drop 统计 Hook
// ============================================================

export function useDropStats() {
  return useApiQuery(["drop-stats"], () => dropApi.getStats());
}

// ============================================================
// Bot 统计 Hook
// ============================================================

export function useBotStats() {
  return useApiQuery(["bot-stats"], () => botApi.getStats());
}

export function useBotScores() {
  return useApiQuery(["bot-scores"], () => botApi.getScores());
}

// ============================================================
// CVE/OWASP 统计 Hook
// ============================================================

export function useCveStats() {
  return useApiQuery(["cve-stats"], () => cveApi.getStats());
}

export function useCveFeedStatus() {
  return useApiQuery(["cve-feed-status"], () => cveApi.getFeedStatus());
}

export function useOwaspStats() {
  return useApiQuery(["owasp-stats"], () => owaspApi.getStats());
}

// ============================================================
// Chain Sessions Hook
// ============================================================

export function useChainSessions() {
  return useApiQuery(["chain-sessions"], () => chainApi.getSessions());
}

// ============================================================
// HTTP2 Config Hook
// ============================================================

export function useHTTP2Config() {
  return useApiQuery(["http2-config"], () => settingsApi.getHTTP2());
}

export function useHTTP2ConfigUpdate() {
  return useMutation(
    async (data: any) => settingsApi.updateHTTP2(data),
    { invalidateKeys: ["http2-config"] }
  );
}

// ============================================================
// TLS Cipher Suites Hook
// ============================================================

export function useCipherSuites() {
  return useApiQuery(["cipher-suites"], () => settingsApi.getCipherSuites());
}
