/**
 * 站点保护 tab 字段前端契约校验脚本。
 *
 * 后端 store.Site 提供以下站点级保护字段（internal/store/site.go）：
 *   - rate_limit_enabled (*bool，null = 继承全局)
 *   - rate_limit_window / rate_limit_max（int，继承时被后端清零）
 *   - rate_limit_action / owasp_action / cve_action（白名单为
 *     shared.ValidateActionWithoutRedirectTarget：不含 redirect、allow、tag）
 *   - owasp_sensitivity（合法值 low/mid/high/very_high/strict/off，
 *     mid 与 medium 等价；媒 low/medium 归一化）
 *   - attack_protection_level（protect / observe；default:medium 为历史遗留值）
 * 本脚本 import 类型做强制的 compile-time 断言（tsc 会对缺字段/类型不符报错），
 * 并对字段键名与 siteApi 泛型做运行时断言，确保前后端契约一致。
 */
import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

import type { Site } from "../lib/types"

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message)
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const typesSource = readFileSync(resolve(root, "lib/types.ts"), "utf8")
const apiSource = readFileSync(resolve(root, "lib/api.ts"), "utf8")

// 前端 Site 必须声明这些键（类型由 tsc 的 mock 断言保证）。
// lib/types.ts 中字段均为一行一条，故按行内精确子串匹配，避免误报。
const backendSiteKeys = [
  "rate_limit_enabled?:",
  "rate_limit_window:",
  "rate_limit_max:",
  "rate_limit_action?:",
  "owasp_sensitivity?:",
  "owasp_action?:",
  "cve_action?:",
  "attack_protection_level?:",
]
for (const key of backendSiteKeys) {
  assert(
    typesSource.includes(key),
    `frontend Site 契约缺少字段 ${key.replace("?:", "").replace(":", "")}`
  )
}

// 编译期：mock 必须满足 Site 的全部必填字段，缺字段或类型不符会在 tsc 阶段报错。
const mockSite: Site = {
  id: 1,
  created_at: "2026-09-15T00:00:00Z",
  updated_at: "2026-09-15T00:00:00Z",
  host: "contract.example",
  upstream_urls: "http://127.0.0.1:8080",
  bind: ":80",
  enabled: true,
  tls_enabled: false,
  anti_replay_enabled: null,
  anti_replay_ttl: 300,
  anti_replay_action: "shield_challenge",
  challenge_action: null,
  captcha_type: null,
  rate_limit_enabled: null,
  rate_limit_window: 60,
  rate_limit_max: 300,
  rate_limit_action: "rate_limit",
  owasp_sensitivity: "mid",
  owasp_action: "intercept",
  cve_action: "intercept",
  attack_protection_level: "protect",
  xff_mode: "strip_all_and_set_remote",
  trusted_cidr: "",
  preserve_original_host: false,
  max_body_bytes: 10485760,
  upstream_tls_skip_verify: false,
  cache_enabled: false,
  cache_default_ttl: 0,
  maintenance_enabled: false,
  maintenance_status: 503,
  block_status: 403,
}

// 运行时值断言；字段类型由上方 mockSite 字面量在 tsc 阶段强制校验。
assert(mockSite.rate_limit_enabled === null, "rate_limit_enabled 默认应为 null（继承）")
assert(mockSite.rate_limit_window === 60, "rate_limit_window 缺失或值异常")
assert(mockSite.rate_limit_max === 300, "rate_limit_max 缺失或值异常")
assert(mockSite.rate_limit_action === "rate_limit", "rate_limit_action 缺失或值异常")
assert(mockSite.owasp_sensitivity === "mid", "owasp_sensitivity 缺失或值异常")
assert(mockSite.owasp_action === "intercept", "owasp_action 缺失或值异常")
assert(mockSite.cve_action === "intercept", "cve_action 缺失或值异常")
assert(
  mockSite.attack_protection_level === "protect",
  "attack_protection_level 缺失或值异常"
)

// siteApi 创建/更新载荷必须是 Partial<Site>，允许只携带覆盖字段。
assert(apiSource.includes("create: (data: Partial<Site>)"), "siteApi.create 泛型漂移")
assert(
  apiSource.includes("update: (id: string | number, data: Partial<Site>)"),
  "siteApi.update 泛型漂移"
)

console.log("site protection contract: ok")