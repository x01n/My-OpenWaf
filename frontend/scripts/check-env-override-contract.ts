import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message)
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const FROZEN_KEYS: Record<string, string> = {
  // bootstrap（只读）
  db_driver: "bootstrap",
  dsn: "bootstrap",
  data_dir: "bootstrap",
  admin_bind: "bootstrap",
  log_dsn: "bootstrap",
  pprof_bind: "bootstrap",
  jwt_secret: "bootstrap",
  // network
  redis_addr: "network",
  redis_password: "network",
  redis_db: "network",
  admin_static_dir: "network",
  captcha_dir: "network",
  // detection
  cve_enabled: "detection",
  cve_feed_enabled: "detection",
  cve_feed_interval: "detection",
  nvd_api_key: "detection",
  cve_auto_approve: "detection",
  geoip_db_path: "detection",
  bot_threshold: "detection",
  drop_enabled: "detection",
  drop_bot_threshold: "detection",
  cve_auto_drop_critical: "detection",
  cve_auto_drop_high: "detection",
  bot_enabled: "detection",
  // observability
  trace_enabled: "observability",
  trace_level: "observability",
  log_level: "observability",
  log_file: "observability",
  log_also_stdout: "observability",
  log_color: "observability",
  accesslog_sampling: "observability",
  // limits
  request_decompress_limit_bytes: "limits",
  response_decompress_limit_bytes: "limits",
  // cache
  response_cache_mb: "cache",
  response_cache_ttl_sec: "cache",
  // queue
  queue_event_buffer_size: "queue",
  queue_drop_buffer_size: "queue",
  queue_batch_size: "queue",
  queue_flush_interval: "queue",
  queue_write_batch_size: "queue",
  queue_write_capacity: "queue",
  queue_write_interval: "queue",
  // http3
  h3_allow_0rtt: "http3",
  // internal（只读，测试专用）
  h2ws_peeker_off: "internal",
  fingerprint_bench_db: "internal",
}

/** 冻结的 9 个域（bootstrap 与 internal 为只读域）。 */
const FROZEN_GROUPS = [
  "bootstrap",
  "network",
  "detection",
  "observability",
  "limits",
  "cache",
  "queue",
  "http3",
  "internal",
]

/** 契约第 3 节按域声明的键数，用于逐域核对清单没有多写或漏写。 */
const FROZEN_GROUP_SIZES: Record<string, number> = {
  bootstrap: 7,
  network: 5,
  detection: 12,
  observability: 7,
  limits: 2,
  cache: 2,
  queue: 7,
  http3: 1,
  internal: 2,
}

/** 本轮新增的 3 个 detection 键：无环境变量载体，值落在 drop_policy / bot_settings。 */
const FROZEN_ENV_LESS_KEYS = [
  "cve_auto_drop_critical",
  "cve_auto_drop_high",
  "bot_enabled",
]

/** 契约规定三键必须声明为 duration（core 曾误用 string）。 */
const FROZEN_DURATION_KEYS = [
  "cve_feed_interval",
  "queue_flush_interval",
  "queue_write_interval",
]

/** 契约规定 sensitive 的键。 */
const FROZEN_SENSITIVE_KEYS = ["redis_password", "nvd_api_key", "jwt_secret"]

/** 契约规定的四种值类型。 */
const FROZEN_TYPES = ["bool", "int", "string", "duration"]

const registrySource = readFileSync(resolve(root, "lib/env-override.ts"), "utf8")
const fieldSource = readFileSync(
  resolve(root, "components/env-override-field.tsx"),
  "utf8"
)
const apiSource = readFileSync(resolve(root, "lib/api.ts"), "utf8")
const zh = JSON.parse(
  readFileSync(resolve(root, "lib/i18n/locales/zh.json"), "utf8")
)
const en = JSON.parse(
  readFileSync(resolve(root, "lib/i18n/locales/en.json"), "utf8")
)

/** 从 lib/env-override.ts 的 ENV_OVERRIDE_KEYS 里解析出 key -> group/type。 */
function readRegistry(): Map<string, { group: string; type: string }> {
  const start = registrySource.indexOf("export const ENV_OVERRIDE_KEYS")
  assert(start >= 0, "lib/env-override.ts 缺少 ENV_OVERRIDE_KEYS 注册表")
  const end = registrySource.indexOf("] as const satisfies", start)
  assert(end > start, "ENV_OVERRIDE_KEYS 注册表的结束标记缺失")
  const body = registrySource.slice(start, end)
  const registry = new Map<string, { group: string; type: string }>()
  const objectEntries = body.matchAll(
    /\{\s*key:\s*"([^"]+)",\s*group:\s*"([^"]+)",\s*type:\s*"([^"]+)",?\s*\}/g
  )
  for (const match of objectEntries) {
    registry.set(match[1], { group: match[2], type: match[3] })
  }
  const multilineEntries = body.matchAll(
    /key:\s*"([^"]+)",\s*\n\s*group:\s*"([^"]+)",\s*\n\s*type:\s*"([^"]+)",/g
  )
  for (const match of multilineEntries) {
    registry.set(match[1], { group: match[2], type: match[3] })
  }
  return registry
}

/** 收集一个 locale 对象里的全部叶子路径。 */
function collectLeaves(
  value: unknown,
  prefix = "",
  leaves = new Set<string>()
): Set<string> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, child] of Object.entries(value)) {
      collectLeaves(child, prefix ? `${prefix}.${key}` : key, leaves)
    }
    return leaves
  }
  leaves.add(prefix)
  return leaves
}

/** 按点分段做深查找；envOverrides.key 之下的键名本身含点，故逐段回溯拼接。 */
function deepFind(root: unknown, path: string): unknown {
  let current: unknown = root
  const parts = path.split(".")
  let index = 0
  while (index < parts.length) {
    if (current === null || typeof current !== "object") return undefined
    const record = current as Record<string, unknown>
    let matched = false
    // 从最长的剩余片段开始尝试，兼容 "queue_batch_size.desc" 这类含点的键名。
    for (let end = parts.length; end > index; end -= 1) {
      const candidate = parts.slice(index, end).join(".")
      if (Object.prototype.hasOwnProperty.call(record, candidate)) {
        current = record[candidate]
        index = end
        matched = true
        break
      }
    }
    if (!matched) return undefined
  }
  return current
}

function checkFrozenKeyCoverage(): void {
  const registry = readRegistry()
  const registryKeys = [...registry.keys()].sort()
  const frozenKeys = Object.keys(FROZEN_KEYS).sort()

  assert(
    frozenKeys.length === 45,
    `冻结键清单应为 45 条，实际 ${frozenKeys.length} 条`
  )
  for (const [group, size] of Object.entries(FROZEN_GROUP_SIZES)) {
    const actual = frozenKeys.filter((key) => FROZEN_KEYS[key] === group).length
    assert(
      actual === size,
      `域 ${group} 的冻结键数应为 ${size}，实际 ${actual}`
    )
  }

  const missing = frozenKeys.filter((key) => !registry.has(key))
  const extra = registryKeys.filter((key) => !(key in FROZEN_KEYS))
  assert(
    missing.length === 0,
    `前端注册表缺少冻结键（共 ${missing.length}）: ${missing.join(", ")}`
  )
  assert(
    extra.length === 0,
    `前端注册表出现契约外的键（共 ${extra.length}）: ${extra.join(", ")}`
  )

  const groupMismatch = frozenKeys.filter(
    (key) => registry.get(key)?.group !== FROZEN_KEYS[key]
  )
  assert(
    groupMismatch.length === 0,
    `以下键的所属域与冻结契约不一致: ${groupMismatch.map((key) => `${key}(注册表=${registry.get(key)?.group}, 契约=${FROZEN_KEYS[key]})`).join(", ")}`
  )

  const badTypes = frozenKeys.filter(
    (key) => !FROZEN_TYPES.includes(registry.get(key)?.type ?? "")
  )
  assert(
    badTypes.length === 0,
    `以下键的 type 不在契约取值内: ${badTypes.join(", ")}`
  )

  // 三个时长键必须声明为 duration，否则前端会退化成普通文本输入。
  const badDurations = FROZEN_DURATION_KEYS.filter(
    (key) => registry.get(key)?.type !== "duration"
  )
  assert(
    badDurations.length === 0,
    `以下键的 type 应为 duration: ${badDurations.map((key) => `${key}(注册表=${registry.get(key)?.type})`).join(", ")}`
  )

  // 本轮新增的 3 键必须在注册表里，且都是 bool。
  const missingNew = FROZEN_ENV_LESS_KEYS.filter((key) => !registry.has(key))
  assert(
    missingNew.length === 0,
    `前端注册表缺少本轮新增键: ${missingNew.join(", ")}`
  )
  const badNewTypes = FROZEN_ENV_LESS_KEYS.filter(
    (key) => registry.get(key)?.type !== "bool"
  )
  assert(
    badNewTypes.length === 0,
    `本轮新增键的 type 应为 bool: ${badNewTypes.join(", ")}`
  )

  console.log(`frozen key coverage: ok (${frozenKeys.length} keys)`)
}

function checkLocaleEntries(): void {
  const zhLeaves = collectLeaves(zh)
  const enLeaves = collectLeaves(en)

  const missingZh: string[] = []
  const missingEn: string[] = []
  for (const key of Object.keys(FROZEN_KEYS)) {
    for (const suffix of ["", ".desc"]) {
      const path = `envOverrides.key.${key}${suffix}`
      if (!zhLeaves.has(path)) missingZh.push(path)
      if (!enLeaves.has(path)) missingEn.push(path)
    }
  }
  assert(
    missingZh.length === 0,
    `zh.json 缺少条目: ${missingZh.join(", ")}`
  )
  assert(
    missingEn.length === 0,
    `en.json 缺少条目: ${missingEn.join(", ")}`
  )

  for (const group of FROZEN_GROUPS) {
    const path = `envOverrides.group.${group}`
    assert(zhLeaves.has(path), `zh.json 缺少域标签: ${path}`)
    assert(enLeaves.has(path), `en.json 缺少域标签: ${path}`)
  }

  // 两语言的 envOverrides 条目集合必须完全相同（zh 是 fallback 语言）。
  const zhEnv = [...zhLeaves].filter((key) => key.startsWith("envOverrides."))
  const enEnv = [...enLeaves].filter((key) => key.startsWith("envOverrides."))
  const onlyZh = zhEnv.filter((key) => !enLeaves.has(key)).sort()
  const onlyEn = enEnv.filter((key) => !zhLeaves.has(key)).sort()
  assert(
    onlyZh.length === 0,
    `envOverrides 条目仅存在于 zh.json: ${onlyZh.join(", ")}`
  )
  assert(
    onlyEn.length === 0,
    `envOverrides 条目仅存在于 en.json: ${onlyEn.join(", ")}`
  )
  assert(
    zhEnv.length === enEnv.length,
    `envOverrides 条目数量不一致: zh=${zhEnv.length}, en=${enEnv.length}`
  )

  // 组件用的 label_key / description_key 必须能在 locale 里解析到。
  for (const key of Object.keys(FROZEN_KEYS)) {
    assert(
      typeof deepFind(zh, `envOverrides.key.${key}`) === "string",
      `zh.json 的 envOverrides.key.${key} 不是一个字符串叶子`
    )
    assert(
      typeof deepFind(zh, `envOverrides.key.${key}.desc`) === "string",
      `zh.json 的 envOverrides.key.${key}.desc 不是一个字符串叶子`
    )
    assert(
      typeof deepFind(en, `envOverrides.key.${key}.desc`) === "string",
      `en.json 的 envOverrides.key.${key}.desc 不是一个字符串叶子`
    )
  }

  console.log(
    `locale entries: ok (${zhEnv.length} envOverrides leaves in each locale)`
  )
}

function checkSensitivePath(): void {
  const block = registrySource.slice(
    registrySource.indexOf("export const ENV_OVERRIDE_SENSITIVE_KEYS"),
    registrySource.indexOf("] as const", registrySource.indexOf("ENV_OVERRIDE_SENSITIVE_KEYS"))
  )
  const sensitiveKeys = [...block.matchAll(/"([^"]+)"/g)].map(
    (match) => match[1]
  )
  assert(
    sensitiveKeys.sort().join(",") === FROZEN_SENSITIVE_KEYS.slice().sort().join(","),
    `敏感键集合与契约不符: ${sensitiveKeys.join(", ")}`
  )
  for (const key of FROZEN_SENSITIVE_KEYS) {
    assert(
      block.includes(`"${key}"`),
      `敏感键集合缺少契约规定的 ${key}`
    )
  }
  // 敏感键必须在 string 分支里切到 password，且注释说明「留空即不修改」。
  assert(
    fieldSource.includes('props.sensitive ? "password" : "text"'),
    "组件未对敏感键切换到 password 输入"
  )
  assert(
    fieldSource.includes("留空即不修改"),
    "组件缺少「留空即不修改」的敏感键语义说明"
  )
  assert(
    fieldSource.includes('t("envOverrides.sensitivePlaceholder")'),
    "组件未使用敏感键的空值占位文案"
  )
  console.log(
    `sensitive path: ok (${FROZEN_SENSITIVE_KEYS.length} keys route to the password branch)`
  )
}

/**
 * 校验无环境变量载体的键不会渲染空的环境变量名。
 *
 * 契约第 2 节规定 `env` 在无载体时是空串；组件对这两种展示位置都必须
 * 先判空，同时 ENV 标识也不能只凭 source 打出。
 */
function checkEnvLessKeys(): void {
  assert(
    fieldSource.includes("hasEnvOverrideEnvName(item)"),
    "组件未用 hasEnvOverrideEnvName 判定环境变量名是否展示"
  )
  assert(
    registrySource.includes("item.env !== \"\" && item.source === \"env\""),
    "isEnvOverrideFromEnv 未对空 env 收口"
  )
  const envUses = [...fieldSource.matchAll(/\{item\.env\}/g)].length
  const guardedUses = [...fieldSource.matchAll(
    /hasEnvOverrideEnvName\(item\)\s*&&/g
  )].length
  assert(
    envUses === guardedUses,
    `组件有 ${envUses} 处渲染 item.env，但只有 ${guardedUses} 处做了判空`
  )
  console.log(
    `env-less keys: ok (${FROZEN_ENV_LESS_KEYS.join(", ")} render without an env name)`
  )
}

function checkTypeBranches(): void {
  const start = fieldSource.indexOf("function renderControl")
  assert(start >= 0, "组件缺少 renderControl 分支函数")
  const end = fieldSource.indexOf("\n}\n", start)
  const block = fieldSource.slice(start, end > start ? end : undefined)
  for (const type of FROZEN_TYPES) {
    assert(
      block.includes(`case "${type}"`),
      `renderControl 缺少 type=${type} 的分支`
    )
  }
  console.log(`control branches: ok (${FROZEN_TYPES.join(" / ")})`)
}

function checkApiEndpoints(): void {
  assert(
    apiSource.includes('"/runtime-config/env-overrides"'),
    "lib/api.ts 未使用契约端点 /runtime-config/env-overrides"
  )
  assert(
    /getEnvOverrides:\s*\(\)\s*=>\s*\n?\s*get<EnvOverridesResponse>\(\s*"\/runtime-config\/env-overrides"\s*\)/.test(
      apiSource
    ),
    "runtimeApi.getEnvOverrides 未按契约读取"
  )
  assert(
    /updateEnvOverrides:\s*\(data: EnvOverridesUpdate\)\s*=>\s*\n?\s*post<EnvOverridesResponse>\(\s*"\/runtime-config\/env-overrides",\s*data\s*\)/.test(
      apiSource
    ),
    "runtimeApi.updateEnvOverrides 未按契约写入"
  )
  // 写载荷只允许 overrides / clear 两个字段，且都是 POST（Admin API 只允许 GET/POST）。
  const typesSource = readFileSync(resolve(root, "lib/types.ts"), "utf8")
  const payloadStart = typesSource.indexOf("export interface EnvOverridesUpdate")
  assert(payloadStart >= 0, "lib/types.ts 缺少 EnvOverridesUpdate")
  const payloadEnd = typesSource.indexOf("}", payloadStart)
  const payload = typesSource.slice(payloadStart, payloadEnd)
  const fields = [...payload.matchAll(/^\s*(\w+)\s*[?:]/gm)].map(
    (match) => match[1]
  )
  assert(
    fields.sort().join(",") === ["clear", "overrides"].sort().join(","),
    `EnvOverridesUpdate 的字段与契约不符: ${fields.join(", ")}`
  )
  assert(
    !apiSource.includes('runtime-config/env-overrides", data, '),
    "写端点使用了契约外的请求形态"
  )
  console.log("api endpoints: ok (GET + POST /runtime-config/env-overrides)")
}

/**
 * 校验分组渲染的分工没有漂移：settings 页渲染七个可写域之外的
 * observability/limits/cache/queue/http3/network 与只读域，detection 域
 * 拆到 CVE 规则页与 CC/Drop 页。
 */
function checkGroupPlacement(): void {
  const settings = readFileSync(
    resolve(root, "app/(dashboard)/settings/page.tsx"),
    "utf8"
  )
  for (const group of [
    "network",
    "observability",
    "limits",
    "cache",
    "queue",
    "http3",
    "bootstrap",
    "internal",
  ]) {
    assert(
      settings.includes(`"${group}"`),
      `settings 页未渲染 ${group} 域`
    )
  }
  const cve = readFileSync(
    resolve(root, "app/(dashboard)/rules/cve/page.tsx"),
    "utf8"
  )
  for (const key of [
    "cve_enabled",
    "cve_feed_enabled",
    "cve_feed_interval",
    "nvd_api_key",
    "cve_auto_approve",
  ]) {
    assert(cve.includes(`"${key}"`), `CVE 规则页未渲染 ${key}`)
  }
  const cc = readFileSync(
    resolve(root, "app/(dashboard)/captcha/page.tsx"),
    "utf8"
  )
  for (const key of [
    "geoip_db_path",
    "bot_threshold",
    "drop_enabled",
    "drop_bot_threshold",
    "cve_auto_drop_critical",
    "cve_auto_drop_high",
    "bot_enabled",
  ]) {
    assert(cc.includes(`"${key}"`), `验证码 / Bot 页未渲染 ${key}`)
  }
  // detection 域的 12 键必须不重不漏地落在两张卡上。
  const cveKeys = [...cve.matchAll(/"([a-z0-9_]+)"/g)]
    .map((match) => match[1])
    .filter((key) => key in FROZEN_KEYS && FROZEN_KEYS[key] === "detection")
  const ccKeys = [...cc.matchAll(/"([a-z0-9_]+)"/g)]
    .map((match) => match[1])
    .filter((key) => key in FROZEN_KEYS && FROZEN_KEYS[key] === "detection")
  const placed = [...new Set([...cveKeys, ...ccKeys])].sort()
  const expected = Object.keys(FROZEN_KEYS)
    .filter((key) => FROZEN_KEYS[key] === "detection")
    .sort()
  assert(
    placed.join(",") === expected.join(","),
    `detection 域的落点与契约不符：页面=(${placed.join(", ")})，契约=(${expected.join(", ")})`
  )
  console.log(
    "group placement: ok (detection 域拆分到 CVE 页与验证码 / Bot 页)"
  )
}

function main(): void {
  checkFrozenKeyCoverage()
  checkLocaleEntries()
  checkSensitivePath()
  checkEnvLessKeys()
  checkTypeBranches()
  checkApiEndpoints()
  checkGroupPlacement()
  console.log("env override contract check passed")
}

main()