import type { EnvOverrideGroupKey, EnvOverrideItem } from "@/lib/types"

/** 值类型：与后端 item.type 一一对应。 */
export type EnvOverrideValueType = "bool" | "int" | "string" | "duration"

/** 生效值来源：env（环境变量）/ db（页面已保存）/ default（内置默认值）。 */
export type EnvOverrideSource = "env" | "db" | "default"

/**
 * 单个键的前端注册表条目。
 *
 * @property key 稳定键名（小写下划线），与后端 key 逐字一致
 * @property group 所属域
 * @property type 值类型
 */
export interface EnvOverrideKeySpec {
  key: string
  group: EnvOverrideGroupKey
  type: EnvOverrideValueType
}

/** 冻结的 9 个域，顺序即 UI 卡片顺序。 */
export const ENV_OVERRIDE_GROUPS = [
  "network",
  "detection",
  "observability",
  "limits",
  "cache",
  "queue",
  "http3",
  "bootstrap",
  "internal",
] as const satisfies readonly EnvOverrideGroupKey[]

/**
 * 冻结的 45 键清单。
 *
 * 与 CONTRACT-env-override-v2.md 第 3 节的表逐字一致；`internal` 域是
 * 测试专用键（只读展示），与 `bootstrap` 引导类同属不可编辑项。
 *
 * 域内三个键（`cve_auto_drop_critical` / `cve_auto_drop_high` /
 * `bot_enabled`）没有环境变量载体，后端 `env` 字段为空串，其值分别
 * 落在 drop_policy 与 bot_settings 里。
 */
export const ENV_OVERRIDE_KEYS = [
  // network
  { key: "redis_addr", group: "network", type: "string" },
  { key: "redis_password", group: "network", type: "string" },
  { key: "redis_db", group: "network", type: "int" },
  { key: "admin_static_dir", group: "network", type: "string" },
  { key: "captcha_dir", group: "network", type: "string" },
  // detection
  { key: "cve_enabled", group: "detection", type: "bool" },
  { key: "cve_feed_enabled", group: "detection", type: "bool" },
  { key: "cve_feed_interval", group: "detection", type: "duration" },
  { key: "nvd_api_key", group: "detection", type: "string" },
  { key: "cve_auto_approve", group: "detection", type: "bool" },
  { key: "geoip_db_path", group: "detection", type: "string" },
  { key: "bot_threshold", group: "detection", type: "int" },
  { key: "drop_enabled", group: "detection", type: "bool" },
  { key: "drop_bot_threshold", group: "detection", type: "int" },
  { key: "cve_auto_drop_critical", group: "detection", type: "bool" },
  { key: "cve_auto_drop_high", group: "detection", type: "bool" },
  { key: "bot_enabled", group: "detection", type: "bool" },
  // observability
  { key: "trace_enabled", group: "observability", type: "bool" },
  { key: "trace_level", group: "observability", type: "string" },
  { key: "log_level", group: "observability", type: "string" },
  { key: "log_file", group: "observability", type: "string" },
  { key: "log_also_stdout", group: "observability", type: "bool" },
  { key: "log_color", group: "observability", type: "string" },
  { key: "accesslog_sampling", group: "observability", type: "int" },
  // limits
  {
    key: "request_decompress_limit_bytes",
    group: "limits",
    type: "int",
  },
  {
    key: "response_decompress_limit_bytes",
    group: "limits",
    type: "int",
  },
  // cache
  { key: "response_cache_mb", group: "cache", type: "int" },
  { key: "response_cache_ttl_sec", group: "cache", type: "int" },
  // queue
  { key: "queue_event_buffer_size", group: "queue", type: "int" },
  { key: "queue_drop_buffer_size", group: "queue", type: "int" },
  { key: "queue_batch_size", group: "queue", type: "int" },
  { key: "queue_flush_interval", group: "queue", type: "duration" },
  { key: "queue_write_batch_size", group: "queue", type: "int" },
  { key: "queue_write_capacity", group: "queue", type: "int" },
  { key: "queue_write_interval", group: "queue", type: "duration" },
  // http3
  { key: "h3_allow_0rtt", group: "http3", type: "string" },
  // bootstrap（只读展示）
  { key: "db_driver", group: "bootstrap", type: "string" },
  { key: "dsn", group: "bootstrap", type: "string" },
  { key: "data_dir", group: "bootstrap", type: "string" },
  { key: "admin_bind", group: "bootstrap", type: "string" },
  { key: "log_dsn", group: "bootstrap", type: "string" },
  { key: "pprof_bind", group: "bootstrap", type: "string" },
  { key: "jwt_secret", group: "bootstrap", type: "string" },
  // internal（只读展示，测试专用）
  { key: "h2ws_peeker_off", group: "internal", type: "string" },
  { key: "fingerprint_bench_db", group: "internal", type: "string" },
] as const satisfies readonly EnvOverrideKeySpec[]

/** 45 键的快速索引（键名 -> 注册表条目）。 */
export const ENV_OVERRIDE_KEY_MAP: Record<string, EnvOverrideKeySpec> =
  Object.fromEntries(ENV_OVERRIDE_KEYS.map((spec) => [spec.key, spec]))

/**
 * 敏感键集合：后端对这三个键的 env_value/value 一律回掩码，
 * UI 侧走「留空即不修改」分支（输入框留空表示保持原值）。
 */
export const ENV_OVERRIDE_SENSITIVE_KEYS = [
  "redis_password",
  "nvd_api_key",
  "jwt_secret",
] as const

/** 只读域：引导类与测试专用键只展示生效值，不渲染输入控件。 */
export const ENV_OVERRIDE_READONLY_GROUPS = ["bootstrap", "internal"] as const

/**
 * delegated 键的专用写入口端点 -> 该入口在 settings 页的卡片标题 i18n key。
 *
 * 后端 7 个 delegated 键（redis_addr / redis_password / redis_db /
 * log_level / log_file / log_also_stdout / h3_allow_0rtt）的写入口都落在
 * 这三张卡上，且都在 settings 页自身。这里登记的是「端点」而非「键」：
 * 一个入口对应一张卡，键增减时映射不动。
 *
 * 值直接复用 settings 页卡片标题的既有 key，卡片改名时指引同步，不会指向
 * 一个页面上不存在的名字。未登记的端点不猜落点（返回 null），由调用方走
 * 笼统文案——宁可少说，不可指错地方。
 */
export const ENV_OVERRIDE_DELEGATED_TARGETS: Record<string, string> = {
  "/api/v1/redis-config": "settings.redis",
  "/api/v1/log-config": "settings.logging",
  "/api/v1/tls-config": "settings.sslCompliance",
}

/**
 * 判断键是否按只读渲染。
 *
 * 优先信任后端返回的 editable；字段缺失时回落到域级只读判定，
 * 保证旧响应或无该字段时不会把引导类渲染成可写控件。
 *
 * @param item 后端返回的键条目
 * @returns true 表示只读展示
 */
export function isEnvOverrideReadOnly(item: EnvOverrideItem): boolean {
  if (typeof item.editable === "boolean") return !item.editable
  return (ENV_OVERRIDE_READONLY_GROUPS as readonly string[]).includes(
    item.group
  )
}

/**
 * 判断某个只读键是否已经指向了一个「本页就在旁边」的专用入口。
 *
 * 返回端点对应卡片标题的 i18n key，供调用方拼出「到 XX 改」的指引；
 * 未登记或没有 `delegated_to` 时返回 null，此时不许编造落点。
 *
 * @param item 后端返回的键条目
 * @returns 卡片标题的 i18n key，或 null
 */
export function envOverrideDelegatedTargetKey(
  item: EnvOverrideItem
): string | null {
  const endpoint = item.delegated_to
  if (typeof endpoint !== "string" || endpoint === "") return null
  return ENV_OVERRIDE_DELEGATED_TARGETS[endpoint] ?? null
}

/** 判断键是否敏感（掩码 + 留空不改）。 */
export function isEnvOverrideSensitive(key: string): boolean {
  return (ENV_OVERRIDE_SENSITIVE_KEYS as readonly string[]).includes(key)
}

/**
 * 判断某键是否由环境变量决定。
 *
 * `source === "env"` 时 UI 必须打出 ENV 标识；`overridden === true` 时
 * 后端约定 source 必为 "db"，这里不额外推断，只如实回显。
 *
 * 无环境变量载体的键（`env === ""`，例如 `bot_enabled`）恒不成立：后端
 * 对这类键不会返回 `source: "env"`，这里再以空 `env` 兜一道，避免契约
 * 漂移时打出指向空变量的 ENV 标识。
 *
 * @param item 后端返回的键条目
 * @returns true 表示当前值来自环境变量
 */
export function isEnvOverrideFromEnv(item: EnvOverrideItem): boolean {
  return item.env !== "" && item.source === "env"
}

/**
 * 判断某键当前是否落在内置默认值上（既没被页面覆盖，也没被环境变量提供）。
 *
 * 这是逐键三态里的第三态：`overridden === true` 时后端 source 必为 "db"，
 * `source === "env"` 时是第一态之外的跟随态，两者都不会走到这里。
 *
 * @param item 后端返回的键条目
 * @returns true 表示当前生效值来自内置默认值
 */
export function isEnvOverrideFromDefault(item: EnvOverrideItem): boolean {
  return item.source === "default"
}

/**
 * 判断某键是否有环境变量载体（`env` 为空串表示没有）。
 *
 * 没有载体时整行不展示环境变量名。
 *
 * @param item 后端返回的键条目
 * @returns true 表示该键对应一个环境变量
 */
export function hasEnvOverrideEnvName(item: EnvOverrideItem): boolean {
  return typeof item.env === "string" && item.env.trim() !== ""
}

/**
 * 把生效值渲染为只读文本。
 *
 * 布尔按 true/false 回显（由调用方翻译），空字符串回显为「未设置」占位，
 * 其余原样 String()。
 *
 * @param item 后端返回的键条目
 * @returns 展示文本；空值返回空串，由调用方决定占位符
 */
export function formatEnvOverrideValue(item: EnvOverrideItem): string {
  const value = item.effective_value
  if (value === null || value === undefined) return ""
  if (typeof value === "boolean") return value ? "true" : "false"
  const text = String(value)
  return text
}

/**
 * 把草稿值编码为 POST 载荷中的一个值。
 *
 * 空串表示「不修改」由调用方在收集阶段过滤，这里只做类型收敛：
 * int 型转 Number，其余保持字符串。
 *
 * @param spec 键注册表条目
 * @param draft 输入框原始文本
 * @param checked 布尔控件的开关状态
 * @returns 提交给后端的值
 */
export function encodeEnvOverrideDraft(
  spec: EnvOverrideKeySpec,
  draft: string | undefined,
  checked?: boolean
): string | number | boolean {
  if (spec.type === "bool") return Boolean(checked)
  if (spec.type === "int") return Number(String(draft ?? "").trim())
  return String(draft ?? "").trim()
}

/**
 * 收集待提交的覆盖键与待清除键。
 *
 * 语义与后端一致：`overrides` 里出现的键才被改写，`clear` 里的键回到
 * unset（重新跟随 env）。同名键不会同时出现在两边。
 *
 * 清除对四种类型一律可用：非布尔键把输入框清空即表达清除；布尔键的
 * 开关本身只有两个状态，无法表达「回到 unset」，因此以空字符串草稿
 * 作为清除信号（由控件上的「清除覆盖」动作写入）。
 *
 * @param specs 参与提交的键注册表条目
 * @param drafts 各键的本地草稿（原始文本或布尔）
 * @param dirty 被用户改过的键集合
 * @returns overrides 与 clear 两个载荷字段
 */
export function buildEnvOverridePayload(
  specs: readonly EnvOverrideKeySpec[],
  drafts: Record<string, string | boolean>,
  dirty: ReadonlySet<string>
): {
  overrides: Record<string, string | number | boolean>
  clear: string[]
} {
  const overrides: Record<string, string | number | boolean> = {}
  const clear: string[] = []
  for (const spec of specs) {
    if (!dirty.has(spec.key)) continue
    const raw = drafts[spec.key]
    // 空字符串草稿对四种类型都表示「清除覆盖」，布尔键也不例外。
    if (typeof raw === "string" && raw.trim() === "") {
      clear.push(spec.key)
      continue
    }
    if (spec.type === "bool") {
      overrides[spec.key] = Boolean(raw)
      continue
    }
    const text = String(raw ?? "").trim()
    if (text === "") {
      clear.push(spec.key)
      continue
    }
    overrides[spec.key] = spec.type === "int" ? Number(text) : text
  }
  return { overrides, clear }
}