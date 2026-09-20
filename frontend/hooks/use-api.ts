/* eslint-disable @typescript-eslint/no-explicit-any */
import { useCallback, useRef, useState } from "react"
import useSWR, { mutate, type Key, type SWRConfiguration } from "swr"
import type {
  ChainConfig,
  CaptchaConfig,
  CaptchaTestResponse,
  EscalationConfig,
  EscalationConfigUpdate,
  RuleListParams,
  SensitivityConfig,
} from "@/lib/types"
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
  jsPluginApi,
} from "@/lib/api"
import type {
  Certificate,
  DefaultErrorPagesResponse,
  SiteErrorPages,
  SiteUpdate,
  LogConfig,
  LogConfigUpdate,
  LuaPlugin,
  LuaPluginStage,
  LuaDryRunRequest,
  JSPluginCreateRequest,
  JSPluginUpdateRequest,
  JSPluginValidateRequest,
  JSPluginDryRunRequest,
  NetworkConfig,
  NetworkConfigUpdate,
  TLSConfig,
  TLSConfigUpdate,
  RedisConfigUpdate,
  RedisConfigResponse,
  ProtectionSettings,
  ProtectionSettingsUpdate,
  AccessProviderCreateInput,
  AccessProviderUpdateInput,
  AccessUserCreateInput,
  AccessUserUpdateInput,
  AccessPathRuleCreateInput,
  AccessPathRuleUpdateInput,
  BotScoreListResponse,
  BotScoreStats,
  BotSettings,
} from "@/lib/types"

/**
 * 通用 fetcher
 */
function fetcher<T>(fn: () => Promise<T>) {
  return fn()
}

/** 低频变化的选择器元数据在工作区内复用五分钟。 */
const REFERENCE_QUERY_OPTIONS = {
  dedupingInterval: 5 * 60 * 1000,
  keepPreviousData: true,
}

const REFERENCE_PAGE_SIZE = 200
const MAX_REFERENCE_PAGES = 10

type ReferencePage<T> = { items: T[]; total: number }

/**
 * 聚合站点/策略选择器数据时限制请求页数，并行读取剩余页。
 * 后端分页上限为 200；异常 total 不得让浏览器无限请求或持续占用内存。
 */
async function getReferencePages<T>(
  fetchPage: (page: number, pageSize: number) => Promise<ReferencePage<T>>
): Promise<{ items: T[]; total: number }> {
  const first = await fetchPage(1, REFERENCE_PAGE_SIZE)
  const firstItems = Array.isArray(first.items) ? first.items : []
  const total = Number.isFinite(first.total)
    ? Math.max(0, Math.floor(first.total))
    : firstItems.length

  // 短页已经是最后一页；同时避免因不一致的 total 触发无意义请求。
  if (firstItems.length < REFERENCE_PAGE_SIZE || total <= firstItems.length) {
    return { items: firstItems, total }
  }

  const pageCount = Math.min(
    MAX_REFERENCE_PAGES,
    Math.max(1, Math.ceil(total / REFERENCE_PAGE_SIZE))
  )
  const pages = await Promise.all(
    Array.from({ length: pageCount - 1 }, (_, index) =>
      fetchPage(index + 2, REFERENCE_PAGE_SIZE)
    )
  )
  const items = [...firstItems]
  for (const page of pages) {
    if (Array.isArray(page.items)) items.push(...page.items)
  }
  return {
    items: items.slice(
      0,
      Math.min(total, REFERENCE_PAGE_SIZE * MAX_REFERENCE_PAGES)
    ),
    total,
  }
}

/** 可写规则数据短时复用；写操作和手动刷新仍会主动触发重验证。 */
const RULE_QUERY_OPTIONS = {
  dedupingInterval: 30 * 1000,
  keepPreviousData: true,
  errorRetryCount: 1,
}

/** 无作用域标识的响应不能安全展示上一作用域数据。 */
const STRICT_RULE_QUERY_OPTIONS = {
  ...RULE_QUERY_OPTIONS,
  keepPreviousData: false,
}

/**
 * 通用 SWR Hook 工厂
 */
function useApiQuery<T>(
  key: Key,
  fetchFn: () => Promise<T>,
  options?: SWRConfiguration<T, Error>
) {
  return useSWR<T, Error>(key, () => fetcher(fetchFn), {
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

/** 备份恢复会替换多类配置，需清空全部 API 快照并只重验当前挂载视图。 */
export async function invalidateAllAPICaches() {
  await mutate(() => true, undefined, { revalidate: true })
}

/** 失效所有 IP 名单作用域缓存；批量写入应在整个批次完成后调用一次。 */
export async function invalidateIPListCaches() {
  await revalidatePrefixes(["ip-lists"])
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
          "site-error-pages",
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
          "site-error-pages",
        ].includes(String(prefix)) &&
        cacheId(cachedKey[1] as string | number) === normalized
      )
    },
    undefined,
    { revalidate: true }
  )
}

/** 清除全部 CVE 规则视图；全局覆盖会影响策略和站点的有效配置。 */
export async function invalidateCVERuleCaches() {
  await revalidatePrefixes(["cve-rules", "cve-stats"])
}

/** 清除全部 OWASP 规则视图；未挂载的分页/筛选缓存同时置空。 */
export async function invalidateOWASPRuleCaches() {
  await revalidatePrefixes(["owasp-rules", "owasp-stats"])
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

export function useSites(params?: { page?: number; page_size?: number }) {
  return useApiQuery(["sites", params], () => siteApi.list(params))
}

export function useAllSites(enabled = true) {
  return useApiQuery(
    enabled ? ["sites-all"] : null,
    () =>
      getReferencePages((page, pageSize) =>
        siteApi.list({ page, page_size: pageSize })
      ),
    REFERENCE_QUERY_OPTIONS
  )
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

export function useCertificates(enabled = true) {
  return useApiQuery(
    enabled ? ["certificates"] : null,
    () => certificateApi.list(),
    REFERENCE_QUERY_OPTIONS
  )
}

export function useCertificate(id: string | number | undefined) {
  return useApiQuery(id ? ["certificate", id] : null, () =>
    certificateApi.get(id!)
  )
}

export function useRules(params?: RuleListParams | null) {
  return useApiQuery(
    params === null ? null : ["rules", params],
    () => ruleApi.list(params ?? undefined),
    STRICT_RULE_QUERY_OPTIONS
  )
}

export function useRule(id: string | number | undefined) {
  return useApiQuery(id ? ["rule", id] : null, () => ruleApi.get(id!))
}

export function useRuleTemplates() {
  return useApiQuery(["rule-templates"], () => ruleApi.getTemplates())
}

export function usePolicies(enabled = true) {
  return useApiQuery(
    enabled ? ["policies"] : null,
    async () =>
      (
        await getReferencePages((page, pageSize) =>
          policyApi.list({ page, page_size: pageSize })
        )
      ).items,
    REFERENCE_QUERY_OPTIONS
  )
}

export function useDefaultPolicy() {
  return useApiQuery(
    ["policy-default"],
    () => policyApi.getDefault(),
    REFERENCE_QUERY_OPTIONS
  )
}

export function usePolicy(id: string | number | undefined) {
  return useApiQuery(id ? ["policy", id] : null, () => policyApi.get(id!))
}

export function useProtectionSettings() {
  return useApiQuery(["protection-settings"], () => protectionApi.getSettings())
}

export function useBotSettings() {
  return useApiQuery(["bot-settings"], () => botApi.getSettings())
}

export function useCaptchaConfig() {
  return useApiQuery(["captcha-config"], () => captchaApi.getConfig())
}

export function useCaptchaTest() {
  return useMutation<CaptchaTestResponse, string | undefined>(async (type) =>
    captchaApi.test(type)
  )
}

export function useChainConfig() {
  return useApiQuery<ChainConfig>(
    ["chain-config"],
    () => chainApi.getConfig(),
    REFERENCE_QUERY_OPTIONS
  )
}

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

export function useSecurityEvents(params?: any | null) {
  return useApiQuery(params === null ? null : ["security-events", params], () =>
    securityEventApi.list(params ?? undefined)
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

/**
 * 请求级安全事件聚合列表
 *
 * 与 useSecurityEvents 共用同一套筛选参数；返回的 total 是按 request_id
 * 去重后的请求数，不是事件条数。
 */
export function useSecurityEventRequests(params?: any) {
  return useApiQuery(["security-event-requests", params], () =>
    securityEventApi.listRequests(params)
  )
}

export function useAccessLogs(params?: any) {
  return useApiQuery(["access-logs", params], () => accessLogApi.list(params))
}

/**
 * 通过 request_id 拉取全链路
 * requestId 为空时不请求
 */
export function useRequestTrace(requestId: string | null | undefined) {
  return useApiQuery(requestId ? ["request-trace", requestId] : null, () =>
    requestTraceApi.get(requestId!)
  )
}

export function useDashboard() {
  return useApiQuery(["dashboard"], () => dashboardApi.getSummary(), {
    refreshInterval: 10000,
  })
}

export function useCveRules(params?: any | null) {
  return useApiQuery(
    params === null ? null : ["cve-rules", params],
    () => cveApi.list(params),
    RULE_QUERY_OPTIONS
  )
}

export function useOwaspRules(params?: any | null) {
  return useApiQuery(
    params === null ? null : ["owasp-rules", params],
    () => owaspApi.list(params),
    RULE_QUERY_OPTIONS
  )
}

export function useDropPolicy() {
  return useApiQuery(["drop-policy"], () => dropApi.getPolicy())
}

export function useDropEvents(params?: any) {
  return useApiQuery(["drop-events", params], () => dropApi.getEvents(params))
}

export function useSettings() {
  return useApiQuery(["settings"], () => settingsApi.list())
}

export function useNetworkConfig(enabled = true) {
  return useApiQuery<NetworkConfig>(enabled ? ["network-config"] : null, () =>
    settingsApi.getNetwork()
  )
}

export function useTLSConfig(enabled = true) {
  return useApiQuery<TLSConfig>(enabled ? ["tls-config"] : null, () =>
    settingsApi.getTLS()
  )
}

export function useLogConfig(enabled = true) {
  return useApiQuery<LogConfig>(enabled ? ["log-config"] : null, () =>
    settingsApi.getLog()
  )
}

export function useRuntimeConfig(enabled = true) {
  return useApiQuery<import("@/lib/types").RuntimeConfig>(
    enabled ? ["runtime-config"] : null,
    () => runtimeApi.getConfig()
  )
}

export function useUpstreamStatus() {
  return useApiQuery<import("@/lib/types").UpstreamStatusResponse>(
    ["upstream-status"],
    () => upstreamApi.getStatus(),
    { refreshInterval: 10000 }
  )
}

export function useApiKeys() {
  return useApiQuery(["api-keys"], () => apiKeyApi.list())
}

export function useDefaultErrorPages() {
  return useApiQuery<DefaultErrorPagesResponse>(
    ["error-pages-defaults"],
    () => errorPageApi.getDefaults(),
    REFERENCE_QUERY_OPTIONS
  )
}

/** 读取站点错误页覆盖；仅在站点标识有效时发起请求。 */
export function useSiteErrorPages(id: string | number | undefined) {
  const normalized = cacheId(id)
  return useApiQuery<SiteErrorPages>(
    normalized ? ["site-error-pages", normalized] : null,
    () => siteApi.getErrorPages(normalized!),
    {
      ...RULE_QUERY_OPTIONS,
      keepPreviousData: false,
    }
  )
}

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

/**
 * 保存站点局部 protection 字段前加载当前站点，以避免在局部配置入口丢失其他字段。
 */
export function useSiteProtectionMutation() {
  return useMutation(async ({ id, data }: { id: number; data: SiteUpdate }) => {
    const current = await siteApi.get(id)
    const result = await siteApi.update(id, { ...current, ...data })
    await invalidateSiteCaches(id).catch(() => undefined)
    return result
  })
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
        "cve-rules",
        "cve-stats",
        "owasp-rules",
        "owasp-stats",
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
      "cve-rules",
      "cve-stats",
      "owasp-rules",
      "owasp-stats",
    ],
  })
}

export function usePolicyDelete() {
  return useMutation(async (id: number) => policyApi.delete(id), {
    invalidateKeys: [
      "policies",
      "policy",
      "policy-default",
      "rules",
      "site-rules",
      "sites",
      "cve-rules",
      "cve-stats",
      "owasp-rules",
      "owasp-stats",
    ],
  })
}

/**
 * 全局保护-类别灵敏度配置（GET /protection/:id/sensitivity）。
 * id 传 "global" 读取全局保护配置；站点级用法传站点 ID。
 */
export function useProtectionSensitivity(id: string | number = "global") {
  return useApiQuery<SensitivityConfig>(["protection-sensitivity", id], () =>
    protectionApi.getSensitivity(id)
  )
}

/**
 * 保存类别灵敏度（POST /protection/:id/sensitivity）。
 * 后端以此 map 为规范来源，并清空旧字段 owasp_modules。
 */
export function useProtectionSensitivityUpdate(id: string | number = "global") {
  return useMutation<SensitivityConfig, SensitivityConfig>(
    (data) => protectionApi.updateSensitivity(id, data),
    {
      invalidateKeys: [
        "protection-sensitivity",
        "protection-settings",
        "owasp-rules",
        "owasp-stats",
      ],
    }
  )
}

/**
 * 全局保护-升级配置（GET /protection/:id/escalation）。
 */
export function useProtectionEscalation(id: string | number = "global") {
  return useApiQuery<EscalationConfig>(["protection-escalation", id], () =>
    protectionApi.getEscalation(id)
  )
}

/**
 * 保存升级配置（POST /protection/:id/escalation）。
 */
export function useProtectionEscalationUpdate(id: string | number = "global") {
  return useMutation<EscalationConfig, EscalationConfigUpdate>(
    (data) => protectionApi.updateEscalation(id, data),
    {
      invalidateKeys: ["protection-escalation", "protection-settings"],
    }
  )
}

/**
 * 保存局部 protection 字段前先读取并合并现有配置，避免任意配置页覆盖无关字段。
 */
export function useProtectionSettingsUpdate() {
  return useMutation<ProtectionSettings, ProtectionSettingsUpdate>(
    async (data) => {
      const current = await protectionApi.getSettings()
      return protectionApi.updateSettings({ ...current, ...data })
    },
    {
      invalidateKeys: ["protection-settings", "captcha-config", "bot-settings"],
    }
  )
}

/**
 * bot 设置局部更新。
 * 载荷为 BotSettingsUpdate 的子集（bot.go 的 BindJSON 语义）：
 * 头部列表字段（high_risk_countries 等）以数组整体提交，
 * 本页的合并载荷已包含全部 geoip 字段，不接受后端对遗漏字段的兜底改造。
 */
export function useBotSettingsUpdate() {
  return useMutation<BotSettings, Partial<BotSettings>>(
    async (data) => botApi.updateSettings(data),
    {
      invalidateKeys: ["bot-settings", "protection-settings", "captcha-config"],
    }
  )
}

export function useCaptchaConfigUpdate() {
  return useMutation<CaptchaConfig, Partial<CaptchaConfig>>(
    async (data) => captchaApi.updateConfig(data),
    {
      invalidateKeys: ["captcha-config", "protection-settings", "bot-settings"],
    }
  )
}

export function useChainConfigUpdate() {
  return useMutation<ChainConfig, Partial<ChainConfig>>(
    async (data) => chainApi.updateConfig(data),
    { invalidateKeys: ["chain-config"] }
  )
}

export function useIPListMutation() {
  return useMutation(
    async ({ id, data }: { id?: number; data: any }) => {
      if (id) {
        return ipListApi.update(id, data)
      }
      return ipListApi.create(data)
    },
    { invalidateKeys: ["ip-lists"] }
  )
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
    { invalidateKeys: ["threat-intel-feeds", "ip-lists"] }
  )
}

/**
 * 删除订阅源（连带删除该源的 IP 条目）。
 */
export function useThreatIntelDelete() {
  return useMutation(async (id: number) => threatIntelApi.delete(id), {
    invalidateKeys: ["threat-intel-feeds", "ip-lists"],
  })
}

/**
 * 手动立即同步订阅源。
 */
export function useThreatIntelSync() {
  return useMutation(async (id: number) => threatIntelApi.sync(id), {
    invalidateKeys: ["threat-intel-feeds", "ip-lists"],
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

/** 使用隔离 KV 编译并执行标准样例，不保存配置。 */
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

/**
 * 查询全部 JavaScript 边缘脚本。
 */
export function useJSPlugins() {
  return useApiQuery(["js-plugins"], () => jsPluginApi.list())
}

/**
 * 查询 JavaScript 运行时统计。运行时不可用时由页面单独降级展示。
 */
export function useJSPluginStats() {
  return useApiQuery(["js-plugin-stats"], () => jsPluginApi.stats(), {
    refreshInterval: 15000,
  })
}

/** 查询后端真实 QuickJS 构建、引擎与 snapshot 装载状态。 */
export function useJSPluginRuntime() {
  return useApiQuery(["js-plugin-runtime"], () => jsPluginApi.runtime(), {
    refreshInterval: 15000,
  })
}

const JS_MUTATION_KEYS: Key[] = [
  "js-plugins",
  "js-plugin-stats",
  "js-plugin-runtime",
]

/**
 * 新建或更新 JavaScript 边缘脚本。
 */
export function useJSPluginMutation() {
  return useMutation(
    async ({
      id,
      data,
    }: {
      id?: number
      data: JSPluginCreateRequest | JSPluginUpdateRequest
    }) => {
      if (id !== undefined) {
        return jsPluginApi.update(id, data)
      }
      return jsPluginApi.create(data as JSPluginCreateRequest)
    },
    { invalidateKeys: JS_MUTATION_KEYS }
  )
}

/**
 * 删除 JavaScript 边缘脚本。
 */
export function useJSPluginDelete() {
  return useMutation(async (id: number) => jsPluginApi.delete(id), {
    invalidateKeys: JS_MUTATION_KEYS,
  })
}

/**
 * 切换 JavaScript 边缘脚本启用状态。
 */
export function useJSPluginToggle() {
  return useMutation(
    async ({ id, enabled }: { id: number; enabled: boolean }) =>
      jsPluginApi.toggle(id, enabled),
    { invalidateKeys: JS_MUTATION_KEYS }
  )
}

/**
 * 校验 JavaScript 源码；当前后端可能因运行时不可用返回 503。
 */
export function useJSPluginValidate() {
  return useMutation(async (data: JSPluginValidateRequest) =>
    jsPluginApi.validate(data)
  )
}

/**
 * 试运行 JavaScript 源码；当前后端可能因运行时不可用返回 503。
 */
export function useJSPluginDryRun() {
  return useMutation(async (data: JSPluginDryRunRequest) =>
    jsPluginApi.dryRun(data)
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

export function useRedisConfig(enabled = true) {
  return useApiQuery<RedisConfigResponse>(
    enabled ? ["redis-config"] : null,
    () => settingsApi.getRedis()
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
  return useMutation(async (jti: string) => authApi.forceLogout(jti), {
    invalidateKeys: ["admin-sessions"],
  })
}

export function useDropPolicyUpdate() {
  return useMutation(async (data: any) => dropApi.updatePolicy(data), {
    invalidateKeys: ["drop-policy"],
  })
}

export function useCveBatchUpdate() {
  return useMutation(async (data: any) => cveApi.batch(data), {
    invalidateKeys: ["cve-rules", "cve-stats"],
  })
}

export function useOwaspBatchUpdate() {
  return useMutation(async (data: any) => owaspApi.batch(data), {
    invalidateKeys: ["owasp-rules", "owasp-stats"],
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
    async ({
      siteId,
      data,
    }: {
      siteId: number
      data: Parameters<typeof siteApi.updateErrorPages>[1]
    }) => {
      const result = await siteApi.updateErrorPages(siteId, data)
      await invalidateSiteCaches(siteId).catch(() => undefined)
      return result
    },
    { invalidateKeys: ["site-error-pages"] }
  )
}

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
    async (data: import("@/lib/types").FalsePositiveCreateRequest) =>
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

export function useAccessProviderCreate() {
  return useMutation(
    async ({
      siteId,
      data,
    }: {
      siteId: number
      data: AccessProviderCreateInput
    }) => accessApi.createProvider(siteId, data),
    { invalidateKeys: ["access-providers"] }
  )
}

export function useAccessProviderUpdate() {
  return useMutation(
    async ({
      siteId,
      pid,
      data,
    }: {
      siteId: number
      pid: number
      data: AccessProviderUpdateInput
    }) => accessApi.updateProvider(siteId, pid, data),
    { invalidateKeys: ["access-providers"] }
  )
}

export function useAccessUserCreate() {
  return useMutation(
    async ({ siteId, data }: { siteId: number; data: AccessUserCreateInput }) =>
      accessApi.createUser(siteId, data),
    { invalidateKeys: ["access-users"] }
  )
}

export function useAccessUserUpdate() {
  return useMutation(
    async ({
      siteId,
      uid,
      data,
    }: {
      siteId: number
      uid: number
      data: AccessUserUpdateInput
    }) => accessApi.updateUser(siteId, uid, data),
    { invalidateKeys: ["access-users"] }
  )
}

export function useAccessPathRuleCreate() {
  return useMutation(
    async ({
      siteId,
      data,
    }: {
      siteId: number
      data: AccessPathRuleCreateInput
    }) => accessApi.createPathRule(siteId, data),
    { invalidateKeys: ["access-path-rules"] }
  )
}

export function useAccessPathRuleUpdate() {
  return useMutation(
    async ({
      siteId,
      rid,
      data,
    }: {
      siteId: number
      rid: number
      data: AccessPathRuleUpdateInput
    }) => accessApi.updatePathRule(siteId, rid, data),
    { invalidateKeys: ["access-path-rules"] }
  )
}

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

export function useACMEStatus() {
  return useApiQuery(["acme-status"], () => certificateApi.getACMEStatus())
}

export function useACMEConfig() {
  return useApiQuery(["acme-config"], () => certificateApi.getACMEConfig())
}

export function useFingerprints(params?: {
  page?: number
  page_size?: number
}) {
  return useApiQuery(["fingerprints", params], () =>
    fingerprintApi.list(params)
  )
}

export function useDropStats() {
  return useApiQuery<import("@/lib/types").DropStatsSummary>(
    ["drop-stats"],
    () => dropApi.getStats()
  )
}

export function useBotStats() {
  return useApiQuery<BotScoreStats>(["bot-stats"], () => botApi.getStats(), {
    refreshInterval: 30000,
  })
}

/**
 * 最近 Bot 评分记录列表；默认取最新 10 条。
 * 后端按 id DESC 排序（bot_score.go List 的 Order("id DESC")）。
 */
export function useBotScores(
  params?: Record<string, string | number | boolean | undefined>
) {
  return useApiQuery<BotScoreListResponse>(
    ["bot-scores", params],
    () => botApi.getScores(params),
    { refreshInterval: 30000 }
  )
}

export function useCveStats(params?: any | null) {
  return useApiQuery(
    params === null ? null : ["cve-stats", params],
    () => cveApi.getStats(params),
    RULE_QUERY_OPTIONS
  )
}

export function useCveFeedStatus() {
  return useApiQuery(["cve-feed-status"], () => cveApi.getFeedStatus())
}

export function useOwaspStats(params?: any | null) {
  return useApiQuery(
    params === null ? null : ["owasp-stats", params],
    () => owaspApi.getStats(params),
    RULE_QUERY_OPTIONS
  )
}

export function useChainSessions() {
  return useApiQuery(["chain-sessions"], () => chainApi.getSessions())
}

export function useHTTP2Config() {
  return useApiQuery(["http2-config"], () => settingsApi.getHTTP2())
}

export function useHTTP2ConfigUpdate() {
  return useMutation(async (data: any) => settingsApi.updateHTTP2(data), {
    invalidateKeys: ["http2-config"],
  })
}

export function useCipherSuites() {
  return useApiQuery(["cipher-suites"], () => settingsApi.getCipherSuites())
}
