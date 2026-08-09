/* eslint-disable @typescript-eslint/no-explicit-any */
import { useCallback, useRef, useState } from "react"
import useSWR, { mutate, type Key } from "swr"
import type { CaptchaConfig } from "@/lib/types"
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
  luaPluginApi,
} from "@/lib/api"
import type {
  Certificate,
  SiteUpdate,
  LogConfig,
  LogConfigUpdate,
  LuaPlugin,
  LuaPluginStage,
  LuaDryRunRequest,
  NetworkConfig,
  NetworkConfigUpdate,
  TLSConfig,
  TLSConfigUpdate,
  RedisConfigUpdate,
  RedisConfigResponse,
} from "@/lib/types"

/**
 * 通用 fetcher
 */
function fetcher<T>(fn: () => Promise<T>) {
  return fn()
}

/**
 * 通用 SWR Hook 工厂
 */
function useApiQuery<T>(key: Key, fetchFn: () => Promise<T>, options?: any) {
  return useSWR<T>(key, () => fetcher(fetchFn), {
    revalidateOnFocus: false,
    ...options,
  })
}

function cacheId(id: string | number | undefined | null): string | undefined {
  if (id === undefined || id === null) return undefined
  const normalized = String(id).trim()
  return normalized === "" ? undefined : normalized
}

function matchesPrefix(cachedKey: Key | undefined, prefix: string): boolean {
  return (
    cachedKey === prefix ||
    (Array.isArray(cachedKey) && cachedKey[0] === prefix)
  )
}

async function revalidatePrefixes(prefixes: string[]) {
  await Promise.all(
    prefixes.map((prefix) =>
      mutate((cachedKey) => matchesPrefix(cachedKey, prefix), undefined, {
        revalidate: true,
      })
    )
  )
}

export async function invalidateSiteCaches(id?: string | number) {
  const normalized = cacheId(id)
  await mutate(
    (cachedKey) => {
      if (!Array.isArray(cachedKey)) return false
      const prefix = cachedKey[0]
      if (prefix === "sites") return true
      if (prefix === "sites-all" && cachedKey.length === 1) return true
      if (!normalized) {
        return [
          "site",
          "site-listeners",
          "site-rules",
          "site-recorded-resources",
          "site-stats",
          "site-timeline",
          "site-access-stats",
        ].includes(String(prefix))
      }
      return (
        [
          "site",
          "site-listeners",
          "site-rules",
          "site-recorded-resources",
          "site-stats",
          "site-timeline",
          "site-access-stats",
        ].includes(String(prefix)) &&
        cacheId(cachedKey[1] as string | number) === normalized
      )
    },
    undefined,
    { revalidate: true }
  )
}

/**
 * 通用 Mutation Hook
 */
export function useMutation<T, D = any>(
  mutateFn: (data: D) => Promise<T>,
  options?: {
    onSuccess?: (data: T) => void
    onError?: (error: any) => void
    invalidateKeys?: Key[]
  }
) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const latestRequestId = useRef(0)
  const inFlightCount = useRef(0)

  const execute = useCallback(
    async (data: D) => {
      const requestId = ++latestRequestId.current
      inFlightCount.current += 1
      setLoading(true)
      setError(null)
      try {
        const result = await mutateFn(data)
        if (options?.invalidateKeys) {
          await revalidatePrefixes(options.invalidateKeys.map(String)).catch(
            () => undefined
          )
        }
        options?.onSuccess?.(result)
        return result
      } catch (err) {
        if (requestId === latestRequestId.current) {
          setError(err as Error)
        }
        options?.onError?.(err)
        throw err
      } finally {
        inFlightCount.current -= 1
        if (inFlightCount.current === 0) {
          setLoading(false)
        }
      }
    },
    [mutateFn, options]
  )

  return { execute, loading, error }
}

// ============================================================
// 站点相关 Hook
// ============================================================

export function useSites(params?: { page?: number; page_size?: number }) {
  return useApiQuery(["sites", params], () => siteApi.list(params))
}

export function useAllSites() {
  return useApiQuery(["sites-all"], async () => {
    const pageSize = 200
    const firstPage = await siteApi.list({ page: 1, page_size: pageSize })
    const items = [...firstPage.items]
    const total = firstPage.total
    for (let page = 2; items.length < total; page++) {
      const nextPage = await siteApi.list({ page, page_size: pageSize })
      if (nextPage.items.length === 0) break
      items.push(...nextPage.items)
    }
    return { items, total }
  })
}

export function useSite(id: string | number | undefined) {
  const normalized = cacheId(id)
  return useApiQuery(normalized ? ["site", normalized] : null, () =>
    siteApi.get(normalized!)
  )
}

export function useSiteListeners(id: string | number | undefined) {
  const normalized = cacheId(id)
  return useApiQuery(normalized ? ["site-listeners", normalized] : null, () =>
    siteApi.getListeners(normalized!)
  )
}

export function useSiteRules(id: string | number | undefined) {
  const normalized = cacheId(id)
  return useApiQuery(normalized ? ["site-rules", normalized] : null, () =>
    siteApi.getRules(normalized!)
  )
}

export function useSiteRecordedResources(id: string | number | undefined) {
  const normalized = cacheId(id)
  return useApiQuery(
    normalized ? ["site-recorded-resources", normalized] : null,
    () => siteApi.getRecordedResources(normalized!)
  )
}

export function useSiteStats(
  id: string | number | undefined,
  params?: { hours?: number },
  options?: { refreshInterval?: number }
) {
  const normalized = cacheId(id)
  return useApiQuery(
    normalized ? ["site-stats", normalized, params] : null,
    () => securityEventApi.getSiteStats(normalized!, params),
    options
  )
}

export function useSiteTimeline(
  id: string | number | undefined,
  params?: { hours?: number },
  options?: { refreshInterval?: number }
) {
  const normalized = cacheId(id)
  return useApiQuery(
    normalized ? ["site-timeline", normalized, params] : null,
    () => securityEventApi.getSiteTimeline(normalized!, params),
    options
  )
}

export function useSiteAccessStats(id: string | number | undefined) {
  const normalized = cacheId(id)
  return useApiQuery(
    normalized ? ["site-access-stats", normalized] : null,
    () => accessLogApi.getSiteStats(normalized!)
  )
}

export function useListenerCreate() {
  return useMutation(
    async ({
      siteId,
      data,
    }: {
      siteId: number | string
      data: Partial<any>
    }) => {
      const result = await siteApi.createListener(siteId, data)
      await invalidateSiteCaches(siteId).catch(() => undefined)
      return result
    }
  )
}

export function useListenerUpdate() {
  return useMutation(
    async ({
      siteId,
      lid,
      data,
    }: {
      siteId: number | string
      lid: number | string
      data: Partial<any>
    }) => {
      const result = await siteApi.updateListener(siteId, lid, data)
      await invalidateSiteCaches(siteId).catch(() => undefined)
      return result
    }
  )
}

export function useListenerDelete() {
  return useMutation(
    async ({
      siteId,
      lid,
    }: {
      siteId: number | string
      lid: number | string
    }) => {
      const result = await siteApi.deleteListener(siteId, lid)
      await invalidateSiteCaches(siteId).catch(() => undefined)
      return result
    }
  )
}

// ============================================================
// 证书相关 Hook
// ============================================================

export function useCertificates() {
  return useApiQuery(["certificates"], () => certificateApi.list())
}

export function useCertificate(id: string | number | undefined) {
  return useApiQuery(id ? ["certificate", id] : null, () =>
    certificateApi.get(id!)
  )
}

// ============================================================
// 规则相关 Hook
// ============================================================

export function useRules(params?: any) {
  return useApiQuery(["rules", params], () => ruleApi.list(params))
}

export function useRule(id: string | number | undefined) {
  return useApiQuery(id ? ["rule", id] : null, () => ruleApi.get(id!))
}

export function useRuleTemplates() {
  return useApiQuery(["rule-templates"], () => ruleApi.getTemplates())
}

// ============================================================
// 策略相关 Hook
// ============================================================

export function usePolicies() {
  return useApiQuery(["policies"], async () => {
    const pageSize = 200
    const firstPage = await policyApi.list({ page: 1, page_size: pageSize })
    const items = [...firstPage.items]
    for (let page = 2; items.length < firstPage.total; page++) {
      const nextPage = await policyApi.list({ page, page_size: pageSize })
      if (nextPage.items.length === 0) break
      items.push(...nextPage.items)
    }
    return items
  })
}

export function useDefaultPolicy() {
  return useApiQuery(["policy-default"], () => policyApi.getDefault())
}

export function usePolicy(id: string | number | undefined) {
  return useApiQuery(id ? ["policy", id] : null, () => policyApi.get(id!))
}

// ============================================================
// 防护设置相关 Hook
// ============================================================

export function useProtectionSettings() {
  return useApiQuery(["protection-settings"], () => protectionApi.getSettings())
}

export function useBotSettings() {
  return useApiQuery(["bot-settings"], () => botApi.getSettings())
}

export function useCaptchaConfig() {
  return useApiQuery(["captcha-config"], () => captchaApi.getConfig())
}

export function useChainConfig() {
  return useApiQuery(["chain-config"], () => chainApi.getConfig())
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
  return useApiQuery(enabled ? ["ip-lists", params] : null, () =>
    ipListApi.list(params)
  )
}

// ============================================================
// 安全事件相关 Hook
// ============================================================

export function useSecurityEvents(params?: any) {
  return useApiQuery(["security-events", params], () =>
    securityEventApi.list(params)
  )
}

export function useSecurityEventStats(params?: any) {
  return useApiQuery(["security-event-stats", params], () =>
    securityEventApi.getStats(params)
  )
}

export function useDashboardStats(params?: { hours?: number }) {
  return useApiQuery(
    ["dashboard-stats", params],
    () => securityEventApi.getStats(params),
    { refreshInterval: 30000 }
  )
}

export function useSecurityEventTimeline(params?: any) {
  return useApiQuery(["security-event-timeline", params], () =>
    securityEventApi.getTimeline(params)
  )
}

// ============================================================
// 访问日志相关 Hook
// ============================================================

export function useAccessLogs(params?: any) {
  return useApiQuery(["access-logs", params], () => accessLogApi.list(params))
}

// ============================================================
// 请求追踪相关 Hook
// ============================================================

/**
 * 通过 request_id 拉取全链路
 * requestId 为空时不请求
 */
export function useRequestTrace(requestId: string | null | undefined) {
  return useApiQuery(requestId ? ["request-trace", requestId] : null, () =>
    requestTraceApi.get(requestId!)
  )
}

// ============================================================
// Dashboard 相关 Hook
// ============================================================

export function useDashboard() {
  return useApiQuery(["dashboard"], () => dashboardApi.getSummary(), {
    refreshInterval: 10000,
  })
}

// ============================================================
// CVE / OWASP 相关 Hook
// ============================================================

export function useCveRules(params?: any | null) {
  return useApiQuery(params === null ? null : ["cve-rules", params], () =>
    cveApi.list(params)
  )
}

export function useOwaspRules(params?: any | null) {
  return useApiQuery(params === null ? null : ["owasp-rules", params], () =>
    owaspApi.list(params)
  )
}

// ============================================================
// 丢弃策略相关 Hook
// ============================================================

export function useDropPolicy() {
  return useApiQuery(["drop-policy"], () => dropApi.getPolicy())
}

export function useDropEvents(params?: any) {
  return useApiQuery(["drop-events", params], () => dropApi.getEvents(params))
}

// ============================================================
// 系统设置相关 Hook
// ============================================================

export function useSettings() {
  return useApiQuery(["settings"], () => settingsApi.list())
}

export function useNetworkConfig() {
  return useApiQuery<NetworkConfig>(["network-config"], () =>
    settingsApi.getNetwork()
  )
}

export function useTLSConfig() {
  return useApiQuery<TLSConfig>(["tls-config"], () => settingsApi.getTLS())
}

export function useLogConfig() {
  return useApiQuery<LogConfig>(["log-config"], () => settingsApi.getLog())
}

export function useRuntimeConfig() {
  return useApiQuery(["runtime-config"], () => runtimeApi.getConfig())
}

export function useUpstreamStatus() {
  return useApiQuery<import("@/lib/types").UpstreamStatusResponse>(
    ["upstream-status"],
    () => upstreamApi.getStatus(),
    { refreshInterval: 10000 }
  )
}

// ============================================================
// API 密钥相关 Hook
// ============================================================

export function useApiKeys() {
  return useApiQuery(["api-keys"], () => apiKeyApi.list())
}

// ============================================================
// 错误页面相关 Hook
// ============================================================

export function useDefaultErrorPages() {
  return useApiQuery(["error-pages-defaults"], () => errorPageApi.getDefaults())
}

// ============================================================
// 提交操作 Hook（乐观更新）
// ============================================================

export function useSiteMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: SiteUpdate }) => {
      const result = id
        ? await siteApi.update(id, data)
        : await siteApi.create(data)
      await invalidateSiteCaches(id).catch(() => undefined)
      return result
    }
  )
}

export function useSiteDelete() {
  return useMutation(async (id: number) => {
    const result = await siteApi.delete(id)
    await invalidateSiteCaches(id).catch(() => undefined)
    return result
  })
}

export function useSiteStart() {
  return useMutation(async (id: number) => {
    const result = await siteApi.start(id)
    await invalidateSiteCaches(id).catch(() => undefined)
    return result
  })
}

export function useSiteStop() {
  return useMutation(async (id: number) => {
    const result = await siteApi.stop(id)
    await invalidateSiteCaches(id).catch(() => undefined)
    return result
  })
}

export function useRuleMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<any> }) => {
      if (id) {
        return ruleApi.update(id, data)
      }
      return ruleApi.create(data)
    },
    { invalidateKeys: ["rules", "site-rules"] }
  )
}

export function useRuleDelete() {
  return useMutation(async (id: number) => ruleApi.delete(id), {
    invalidateKeys: ["rules", "site-rules"],
  })
}

export function useCertificateMutation() {
  return useMutation<Certificate, { id?: number; data: Partial<Certificate> }>(
    async ({ id, data }) => {
      if (id) {
        return certificateApi.update(id, data)
      }
      return certificateApi.create(data)
    },
    { invalidateKeys: ["certificates"] }
  )
}

export function useCertificateDelete() {
  return useMutation(async (id: number) => certificateApi.delete(id), {
    invalidateKeys: ["certificates"],
  })
}

export function usePolicyMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<any> }) => {
      if (id) {
        return policyApi.update(id, data)
      }
      return policyApi.create(data)
    },
    {
      invalidateKeys: [
        "policies",
        "policy",
        "policy-default",
        "rules",
        "site-rules",
        "sites",
      ],
    }
  )
}

export function usePolicySetDefault() {
  return useMutation(async (id: number) => policyApi.setDefault(id), {
    invalidateKeys: [
      "policies",
      "policy",
      "policy-default",
      "rules",
      "site-rules",
      "sites",
    ],
  })
}

export function usePolicyDelete() {
  return useMutation(async (id: number) => policyApi.delete(id), {
    invalidateKeys: ["policies"],
  })
}

export function useProtectionSettingsUpdate() {
  return useMutation(async (data: any) => protectionApi.updateSettings(data), {
    invalidateKeys: [
      "protection-settings",
      "captcha-config",
      "bot-settings",
    ],
  })
}

export function useBotSettingsUpdate() {
  return useMutation(async (data: any) => botApi.updateSettings(data), {
    invalidateKeys: [
      "bot-settings",
      "protection-settings",
      "captcha-config",
    ],
  })
}

export function useCaptchaConfigUpdate() {
  return useMutation<CaptchaConfig, Partial<CaptchaConfig>>(
    async (data) => captchaApi.updateConfig(data),
    {
      invalidateKeys: [
        "captcha-config",
        "protection-settings",
        "bot-settings",
      ],
    }
  )
}

export function useChainConfigUpdate() {
  return useMutation(async (data: any) => chainApi.updateConfig(data), {
    invalidateKeys: ["chain-config"],
  })
}

export function useIPListMutation() {
  return useMutation(async ({ id, data }: { id?: number; data: any }) => {
    if (id) {
      return ipListApi.update(id, data)
    }
    return ipListApi.create(data)
  })
}

export function useIPListDelete() {
  return useMutation(async (id: number) => ipListApi.delete(id), {
    invalidateKeys: ["ip-lists"],
  })
}

/**
 * 预览预置爬虫白名单条目（仅只读，不写库）。
 */
export function usePresetBotWhitelist(enabled = true) {
  return useApiQuery(enabled ? ["preset-bot-whitelist"] : null, () =>
    presetBotWhitelistApi.preview()
  )
}

/**
 * 触发预置爬虫白名单写入 IP 白名单表。写入后自动失效 IP 列表缓存。
 */
export function usePresetBotWhitelistSeed() {
  return useMutation(async () => presetBotWhitelistApi.seed(), {
    invalidateKeys: ["ip-lists"],
  })
}

// ============================================================
// 威胁情报订阅相关 Hook
// ============================================================

/**
 * 查询威胁情报订阅源列表。
 */
export function useThreatIntelFeeds() {
  return useApiQuery(["threat-intel-feeds"], () => threatIntelApi.list())
}

/**
 * 新建 / 更新订阅源。传入 id 走更新，否则走新建。
 */
export function useThreatIntelMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<any> }) => {
      if (id) {
        return threatIntelApi.update(id, data)
      }
      return threatIntelApi.create(data)
    },
    { invalidateKeys: ["threat-intel-feeds"] }
  )
}

/**
 * 删除订阅源（连带删除该源的 IP 条目）。
 */
export function useThreatIntelDelete() {
  return useMutation(async (id: number) => threatIntelApi.delete(id), {
    invalidateKeys: ["threat-intel-feeds"],
  })
}

/**
 * 手动立即同步订阅源。
 */
export function useThreatIntelSync() {
  return useMutation(async (id: number) => threatIntelApi.sync(id), {
    invalidateKeys: ["threat-intel-feeds"],
  })
}

/**
 * 分页查询威胁情报同步历史，30 秒自动刷新。
 */
export function useThreatIntelSyncLogs(params?: {
  page?: number
  page_size?: number
  feed_id?: number
  status?: "success" | "failed"
}) {
  return useApiQuery(
    ["threat-intel-sync-logs", params],
    () => threatIntelApi.listSyncLogs(params),
    { refreshInterval: 30000 }
  )
}

// ============================================================
// Lua 自定义策略插件相关 Hook
// ============================================================

/**
 * 查询全部 Lua 策略脚本。
 */
export function useLuaPlugins() {
  return useApiQuery(["lua-plugins"], () => luaPluginApi.list())
}

/**
 * 查询脚本运行时统计。
 *
 * 计数器只存在于引擎内存中，任何配置改动都会重新编译脚本并让计数归零，
 * 因此写操作后必须连带失效这个 key（见 LUA_MUTATION_KEYS），否则页面会
 * 继续显示上一批脚本的计数。
 */
export function useLuaPluginStats() {
  return useApiQuery(["lua-plugin-stats"], () => luaPluginApi.stats(), {
    refreshInterval: 15000,
  })
}

/**
 * 脚本写操作需要失效的缓存 key。
 * 统计随配置重载归零，与列表同时失效才不会出现「新脚本 + 旧计数」的错配视图。
 */
const LUA_MUTATION_KEYS: Key[] = ["lua-plugins", "lua-plugin-stats"]

/**
 * 新建 / 更新脚本。传入 id 走更新，否则走新建。
 */
export function useLuaPluginMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: Partial<LuaPlugin> }) => {
      if (id) {
        return luaPluginApi.update(id, data)
      }
      return luaPluginApi.create(data)
    },
    { invalidateKeys: LUA_MUTATION_KEYS }
  )
}

/**
 * 删除脚本。
 */
export function useLuaPluginDelete() {
  return useMutation(async (id: number) => luaPluginApi.delete(id), {
    invalidateKeys: LUA_MUTATION_KEYS,
  })
}

/**
 * 切换脚本启用状态。显式传 enabled 避免与列表乐观更新竞态。
 */
export function useLuaPluginToggle() {
  return useMutation(
    async ({ id, enabled }: { id: number; enabled: boolean }) =>
      luaPluginApi.toggle(id, enabled),
    { invalidateKeys: LUA_MUTATION_KEYS }
  )
}

/**
 * 语法校验：只编译，不保存也不执行，因此无需失效任何缓存。
 */
export function useLuaPluginValidate() {
  return useMutation(async (data: { stage: LuaPluginStage; source: string }) =>
    luaPluginApi.validate(data)
  )
}

/**
 * 试运行：用样例请求执行脚本，不触碰线上配置。
 */
export function useLuaPluginDryRun() {
  return useMutation(async (data: LuaDryRunRequest) =>
    luaPluginApi.dryRun(data)
  )
}

export function useSettingsUpdate() {
  return useMutation(
    async ({ key, value }: { key: string; value: any }) =>
      settingsApi.set(key, value),
    { invalidateKeys: ["settings"] }
  )
}

export function useNetworkConfigUpdate() {
  return useMutation<NetworkConfig, NetworkConfigUpdate>(
    (data) => settingsApi.updateNetwork(data),
    { invalidateKeys: ["network-config"] }
  )
}

export function useTLSConfigUpdate() {
  return useMutation<TLSConfig, TLSConfigUpdate>(
    (data) => settingsApi.updateTLS(data),
    { invalidateKeys: ["tls-config"] }
  )
}

export function useLogConfigUpdate() {
  return useMutation<LogConfig, LogConfigUpdate>(
    (data) => settingsApi.updateLog(data),
    { invalidateKeys: ["log-config"] }
  )
}

export function useRedisConfig() {
  return useApiQuery<RedisConfigResponse>(["redis-config"], () =>
    settingsApi.getRedis()
  )
}

export function useRedisConfigUpdate() {
  return useMutation<RedisConfigResponse, RedisConfigUpdate>(
    (data) => settingsApi.updateRedis(data),
    { invalidateKeys: ["redis-config"] }
  )
}

export function useAdminSessions() {
  return useApiQuery("admin-sessions", () => authApi.listSessions())
}

export function useForceLogout() {
  return useMutation(
    async (sessionId: number) => authApi.forceLogout(sessionId),
    { invalidateKeys: ["admin-sessions"] }
  )
}

export function useDropPolicyUpdate() {
  return useMutation(async (data: any) => dropApi.updatePolicy(data), {
    invalidateKeys: ["drop-policy"],
  })
}

export function useCveBatchUpdate() {
  return useMutation(async (data: any) => cveApi.batch(data), {
    invalidateKeys: ["cve-rules"],
  })
}

export function useOwaspBatchUpdate() {
  return useMutation(async (data: any) => owaspApi.batch(data), {
    invalidateKeys: ["owasp-rules"],
  })
}

export function useApiKeyDelete() {
  return useMutation(async (id: number) => apiKeyApi.delete(id), {
    invalidateKeys: ["api-keys"],
  })
}

export function useApiKeyCreate() {
  return useMutation(async (data: { name: string }) => apiKeyApi.create(data), {
    invalidateKeys: ["api-keys"],
  })
}

// ============================================================
// 管理员账户相关 Hook
// ============================================================

export function useAdminUsers() {
  return useApiQuery(["admin-users"], () => adminUserApi.list())
}

export function useAdminUserCreate() {
  return useMutation(
    async (data: { username: string; password: string; role: string }) =>
      adminUserApi.create(data),
    { invalidateKeys: ["admin-users"] }
  )
}

export function useAdminUserUpdateRole() {
  return useMutation(
    async ({ id, role }: { id: number; role: string }) =>
      adminUserApi.updateRole(id, role),
    { invalidateKeys: ["admin-users"] }
  )
}

export function useAdminUserUpdatePassword() {
  return useMutation(
    async ({ id, password }: { id: number; password: string }) =>
      adminUserApi.updatePassword(id, password),
    { invalidateKeys: ["admin-users"] }
  )
}

export function useAdminUserDelete() {
  return useMutation(async (id: number) => adminUserApi.delete(id), {
    invalidateKeys: ["admin-users"],
  })
}

export function useErrorPagesUpdate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: any }) => {
      const result = await siteApi.updateErrorPages(siteId, data)
      await invalidateSiteCaches(siteId).catch(() => undefined)
      return result
    },
    { invalidateKeys: ["site-error-pages"] }
  )
}

// ============================================================
// 误报反馈相关 Hook
// ============================================================

/**
 * 分页查询误报反馈记录。
 */
export function useFalsePositives(params?: {
  page?: number
  page_size?: number
  status?: string
}) {
  return useApiQuery(["false-positives", params], () =>
    falsePositiveApi.list(params)
  )
}

/**
 * 提交一条新的误报反馈。
 */
export function useFalsePositiveCreate() {
  return useMutation(
    async (data: Partial<import("@/lib/types").FalsePositiveReport>) =>
      falsePositiveApi.create(data),
    { invalidateKeys: ["false-positives"] }
  )
}

/**
 * 更新一条反馈的审查状态（confirmed / rejected / pending）。
 */
export function useFalsePositiveStatusUpdate() {
  return useMutation(
    async ({ id, status }: { id: number; status: string }) =>
      falsePositiveApi.updateStatus(id, status),
    { invalidateKeys: ["false-positives"] }
  )
}

/**
 * 删除一条反馈记录（仅 admin 可操作）。
 */
export function useFalsePositiveDelete() {
  return useMutation(async (id: number) => falsePositiveApi.delete(id), {
    invalidateKeys: ["false-positives"],
  })
}

export function useSystemReload() {
  return useMutation(async () => systemApi.reload())
}

// ── Page Templates ──

export function usePageTemplate(type: string) {
  return useApiQuery(`page-template-${type}`, () => pageTemplateApi.get(type))
}

export function usePageTemplateUpdate() {
  return useMutation(
    async ({ type, data }: { type: string; data: Record<string, string> }) =>
      pageTemplateApi.update(type, data),
    {
      invalidateKeys: [
        "page-template-captcha",
        "page-template-challenge",
        "page-template-block",
      ],
    }
  )
}

export function usePageTemplateReset() {
  return useMutation(async (type: string) => pageTemplateApi.reset(type), {
    invalidateKeys: [
      "page-template-captcha",
      "page-template-challenge",
      "page-template-block",
    ],
  })
}

export function usePageTemplatePreview(type: string) {
  return useApiQuery(`page-template-preview-${type}`, () =>
    pageTemplateApi.preview(type)
  )
}

// ── Access Control (per-site) ──

export function useAccessProviderCreate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: any }) =>
      accessApi.createProvider(siteId, data),
    { invalidateKeys: ["access-providers"] }
  )
}

export function useAccessProviderUpdate() {
  return useMutation(
    async ({ siteId, pid, data }: { siteId: number; pid: number; data: any }) =>
      accessApi.updateProvider(siteId, pid, data),
    { invalidateKeys: ["access-providers"] }
  )
}

export function useAccessUserCreate() {
  return useMutation(
    async ({
      siteId,
      data,
    }: {
      siteId: number
      data: { username: string; password: string; enabled?: boolean }
    }) => accessApi.createUser(siteId, data),
    { invalidateKeys: ["access-users"] }
  )
}

export function useAccessUserUpdate() {
  return useMutation(
    async ({ siteId, uid, data }: { siteId: number; uid: number; data: any }) =>
      accessApi.updateUser(siteId, uid, data),
    { invalidateKeys: ["access-users"] }
  )
}

export function useAccessPathRuleCreate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: any }) =>
      accessApi.createPathRule(siteId, data),
    { invalidateKeys: ["access-path-rules"] }
  )
}

export function useAccessPathRuleUpdate() {
  return useMutation(
    async ({ siteId, rid, data }: { siteId: number; rid: number; data: any }) =>
      accessApi.updatePathRule(siteId, rid, data),
    { invalidateKeys: ["access-path-rules"] }
  )
}

// ============================================================
// 站点访问控制 Query Hooks
// ============================================================

export function useAccessConfig(siteId: number | string | undefined) {
  return useApiQuery(siteId ? ["access-config", siteId] : null, () =>
    accessApi.getConfig(siteId!)
  )
}

export function useAccessProviders(siteId: number | string | undefined) {
  return useApiQuery(siteId ? ["access-providers", siteId] : null, () =>
    accessApi.listProviders(siteId!)
  )
}

export function useAccessUsers(siteId: number | string | undefined) {
  return useApiQuery(siteId ? ["access-users", siteId] : null, () =>
    accessApi.listUsers(siteId!)
  )
}

export function useAccessPathRules(siteId: number | string | undefined) {
  return useApiQuery(siteId ? ["access-path-rules", siteId] : null, () =>
    accessApi.listPathRules(siteId!)
  )
}

// ============================================================
// 证书 ACME 状态 Hook
// ============================================================

export function useACMEStatus() {
  return useApiQuery(["acme-status"], () => certificateApi.getACMEStatus())
}

export function useACMEConfig() {
  return useApiQuery(["acme-config"], () => certificateApi.getACMEConfig())
}

// ============================================================
// TLS 指纹 Hook
// ============================================================

export function useFingerprints(params?: {
  page?: number
  page_size?: number
}) {
  return useApiQuery(["fingerprints", params], () =>
    fingerprintApi.list(params)
  )
}

// ============================================================
// Drop 统计 Hook
// ============================================================

export function useDropStats() {
  return useApiQuery(["drop-stats"], () => dropApi.getStats())
}

// ============================================================
// Bot 统计 Hook
// ============================================================

export function useBotStats() {
  return useApiQuery(["bot-stats"], () => botApi.getStats())
}

export function useBotScores() {
  return useApiQuery(["bot-scores"], () => botApi.getScores())
}

// ============================================================
// CVE/OWASP 统计 Hook
// ============================================================

export function useCveStats(params?: any | null) {
  return useApiQuery(params === null ? null : ["cve-stats", params], () =>
    cveApi.getStats(params)
  )
}

export function useCveFeedStatus() {
  return useApiQuery(["cve-feed-status"], () => cveApi.getFeedStatus())
}

export function useOwaspStats(params?: any | null) {
  return useApiQuery(params === null ? null : ["owasp-stats", params], () =>
    owaspApi.getStats(params)
  )
}

// ============================================================
// Chain Sessions Hook
// ============================================================

export function useChainSessions() {
  return useApiQuery(["chain-sessions"], () => chainApi.getSessions())
}

// ============================================================
// HTTP2 Config Hook
// ============================================================

export function useHTTP2Config() {
  return useApiQuery(["http2-config"], () => settingsApi.getHTTP2())
}

export function useHTTP2ConfigUpdate() {
  return useMutation(async (data: any) => settingsApi.updateHTTP2(data), {
    invalidateKeys: ["http2-config"],
  })
}

// ============================================================
// TLS Cipher Suites Hook
// ============================================================

export function useCipherSuites() {
  return useApiQuery(["cipher-suites"], () => settingsApi.getCipherSuites())
}
