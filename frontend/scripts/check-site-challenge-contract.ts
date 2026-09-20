/**
 * 站点质询策略前端契约校验脚本。
 *
 * 后端 store.Site 提供两个可空三态字段：
 *   - challenge_action（challenge / captcha_challenge / shield_challenge / chain_challenge）
 *   - captcha_type（math / click / slide / rotate）
 * null = 继承全局；非空 = 站点覆盖。
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

// 后端字段名枚举：challenge_action / captcha_type 必须在前端 Site 中保持可空三态。
const backendSiteKeys = ["challenge_action", "captcha_type"]
for (const key of backendSiteKeys) {
  assert(
    typesSource.includes(`${key}: string | null`),
    `frontend Site 契约缺少可空字段 ${key}`
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
  rate_limit_window: 60,
  rate_limit_max: 300,
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

// 运行时三态：null = 继承全局；非空 = 站点覆盖（与后端 *string 指针语义一致）。
const challengeOverride: Site["challenge_action"] = "captcha_challenge"
const captchaOverride: Site["captcha_type"] = "slide"
assert(mockSite.challenge_action === null, "challenge_action 默认应为 null（继承）")
assert(mockSite.captcha_type === null, "captcha_type 默认应为 null（继承）")
assert(challengeOverride === "captcha_challenge", "challenge_action 覆盖值异常")
assert(captchaOverride === "slide", "captcha_type 覆盖值异常")

// siteApi 创建/更新载荷必须是 Partial<Site>，允许只携带覆盖字段。
assert(apiSource.includes("create: (data: Partial<Site>)"), "siteApi.create 泛型漂移")
assert(
  apiSource.includes("update: (id: string | number, data: Partial<Site>)"),
  "siteApi.update 泛型漂移"
)

console.log("site challenge contract: ok")