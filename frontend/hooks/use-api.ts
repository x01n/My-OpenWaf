import useSWR, { mutate } from "swr";
import { useCallback } from "react";
import type { Key } from "swr";
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
          options.invalidateKeys.forEach((k) => mutate(k));
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

import { useState } from "react";

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

export function useIPLists() {
  return useApiQuery(["ip-lists"], () => ipListApi.list());
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
  return useApiQuery(["upstream-status"], () => upstreamApi.getStatus());
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
    }
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
    }
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
    async (data: any) => apiKeyApi.create(data),
    { invalidateKeys: ["api-keys"] }
  );
}

export function useErrorPagesUpdate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: any }) =>
      siteApi.updateErrorPages(siteId, data),
    { invalidateKeys: ["site-error-pages"] }
  );
}

export function useSystemReload() {
  return useMutation(async () => {
    const res = await fetch("/api/v1/reload", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${localStorage.getItem("token") || ""}`,
      },
    });
    if (!res.ok) throw new Error("重载失败");
    return res.json();
  });
}
