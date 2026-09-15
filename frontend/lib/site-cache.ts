import type { SiteCacheRule } from "@/lib/types"

export const SITE_CACHE_LIMITS = {
  maxRules: 128,
  maxPatternBytes: 1024,
  maxRulesJSONBytes: 64 * 1024,
  maxTtlSeconds: 30 * 24 * 60 * 60,
  maxStaleIfErrorSeconds: 24 * 60 * 60,
} as const

export const SITE_CACHE_RULE_TYPES = [
  "prefix",
  "exact",
  "suffix",
  "contains",
  "regex",
] as const

const siteCacheRuleTypeSet = new Set<string>(SITE_CACHE_RULE_TYPES)

export interface ParsedSiteCacheRules {
  rules: SiteCacheRule[]
  error: string | null
}

/** Parse the persisted JSON blob without silently discarding malformed rules. */
export function parseSiteCacheRules(raw: unknown): ParsedSiteCacheRules {
  if (raw === undefined || raw === null || raw === "") {
    return { rules: [], error: null }
  }
  if (
    typeof raw === "string" &&
    (raw.length > SITE_CACHE_LIMITS.maxRulesJSONBytes ||
      new TextEncoder().encode(raw).length >
        SITE_CACHE_LIMITS.maxRulesJSONBytes)
  ) {
    return { rules: [], error: "sites.detail.cacheRulesInvalid" }
  }
  try {
    const decoded = typeof raw === "string" ? JSON.parse(raw) : raw
    if (
      !Array.isArray(decoded) ||
      decoded.length > SITE_CACHE_LIMITS.maxRules
    ) {
      return { rules: [], error: "sites.detail.cacheRulesInvalid" }
    }
    const rules = decoded.map((value): SiteCacheRule => {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("invalid rule")
      }
      const item = value as Record<string, unknown>
      const optionalString = (key: string): string | undefined => {
        if (!(key in item)) return undefined
        if (typeof item[key] !== "string") throw new Error(`invalid ${key}`)
        return item[key] as string
      }
      const optionalBoolean = (key: string): boolean => {
        if (!(key in item)) return false
        if (typeof item[key] !== "boolean") throw new Error(`invalid ${key}`)
        return item[key] as boolean
      }
      const optionalInteger = (key: string): number => {
        if (!(key in item)) return 0
        if (typeof item[key] !== "number" || !Number.isSafeInteger(item[key])) {
          throw new Error(`invalid ${key}`)
        }
        return item[key] as number
      }
      const rawType = optionalString("type")
      const type = (rawType === undefined ? "prefix" : rawType)
        .trim()
        .toLowerCase()
      if (!siteCacheRuleTypeSet.has(type)) {
        throw new Error("invalid type")
      }
      const valuePattern = optionalString("value")
      const legacyPath = optionalString("path")
      const pattern = valuePattern?.trim() ? valuePattern : legacyPath || ""
      return {
        type: type as SiteCacheRule["type"],
        value: pattern,
        ttl: optionalInteger("ttl"),
        case_insensitive: optionalBoolean("case_insensitive"),
        ignore_query: optionalBoolean("ignore_query"),
        disabled: optionalBoolean("disabled"),
        note: optionalString("note") || "",
        stale_if_error_seconds: optionalInteger("stale_if_error_seconds"),
      }
    })
    return { rules, error: null }
  } catch {
    return { rules: [], error: "sites.detail.cacheRulesInvalid" }
  }
}

/** Return an i18n key when a cache form cannot be safely persisted. */
export function validateSiteCacheConfig(
  enabled: boolean,
  defaultTtl: number,
  rules: SiteCacheRule[]
): string | null {
  if (
    !Number.isInteger(defaultTtl) ||
    defaultTtl < 0 ||
    defaultTtl > SITE_CACHE_LIMITS.maxTtlSeconds
  ) {
    return "sites.detail.cacheDefaultTtlInvalid"
  }
  if (rules.length > SITE_CACHE_LIMITS.maxRules) {
    return "sites.detail.cacheRulesTooMany"
  }
  if (enabled && !rules.some((rule) => !rule.disabled)) {
    return "sites.detail.cacheActiveRuleRequired"
  }
  for (const rule of rules) {
    if (!siteCacheRuleTypeSet.has(rule.type)) {
      return "sites.detail.cacheRuleTypeInvalid"
    }
    if (!rule.value.trim()) {
      return "sites.detail.cacheRuleValueRequired"
    }
    if (
      new TextEncoder().encode(rule.value.trim()).length >
      SITE_CACHE_LIMITS.maxPatternBytes
    ) {
      return "sites.detail.cacheRuleValueTooLong"
    }
    if (
      !Number.isInteger(rule.ttl) ||
      rule.ttl < 0 ||
      rule.ttl > SITE_CACHE_LIMITS.maxTtlSeconds ||
      (rule.ttl === 0 && defaultTtl === 0)
    ) {
      return "sites.detail.cacheRuleTtlInvalid"
    }
    const stale = rule.stale_if_error_seconds ?? 0
    if (
      !Number.isInteger(stale) ||
      stale < 0 ||
      stale > SITE_CACHE_LIMITS.maxStaleIfErrorSeconds
    ) {
      return "sites.detail.cacheRuleStaleInvalid"
    }
    if (
      new TextEncoder().encode(rule.note?.trim() ?? "").length >
      SITE_CACHE_LIMITS.maxRulesJSONBytes
    ) {
      return "sites.detail.cacheRuleNoteTooLong"
    }
  }
  const serialized = serializeSiteCacheRules(rules)
  if (
    new TextEncoder().encode(serialized).length >
    SITE_CACHE_LIMITS.maxRulesJSONBytes
  ) {
    return "sites.detail.cacheRulesJSONTooLarge"
  }
  return null
}

export function serializeSiteCacheRules(rules: SiteCacheRule[]): string {
  return JSON.stringify(
    rules.map((rule) => ({
      type: rule.type,
      value: rule.value.trim(),
      ttl: rule.ttl,
      ...(rule.case_insensitive ? { case_insensitive: true } : {}),
      ...(rule.ignore_query ? { ignore_query: true } : {}),
      ...(rule.disabled ? { disabled: true } : {}),
      ...(rule.note?.trim() ? { note: rule.note.trim() } : {}),
      ...(rule.stale_if_error_seconds
        ? { stale_if_error_seconds: rule.stale_if_error_seconds }
        : {}),
    }))
  )
}

/** Preview only key shaping; case-insensitive matching never lowercases this key. */
export function siteCacheKeyPreview(
  rule: SiteCacheRule,
  requestTarget: string
): string {
  const target = requestTarget.trim() || "/"
  const targetWithoutQuery = rule.ignore_query
    ? target.slice(
        0,
        target.indexOf("?") >= 0 ? target.indexOf("?") : target.length
      )
    : target
  // 此函数返回实际存储键的请求目标部分；匹配模式的规范化仅由后端编译器
  // 使用，不能把诊断符号混入键预览，否则会误导管理员和破坏契约检查。
  return targetWithoutQuery
}
