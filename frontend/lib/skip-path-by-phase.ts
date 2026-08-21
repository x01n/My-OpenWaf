import type { SkipPathByPhase, SkipPathPhase } from "@/lib/types"

/** 后端 store.SkipPathPhaseKeys() 返回的可配置 pipeline phase。 */
export const SKIP_PATH_PHASES = [
  "ip_reputation",
  "anti_replay",
  "acl",
  "lua_pre",
  "owasp_default",
  "cve_detection",
  "bot_detection",
  "browser_sign",
  "rate_limit",
] as const satisfies readonly SkipPathPhase[]

export const SKIP_PATH_PHASE_LABELS: Record<
  SkipPathPhase,
  { zh: string; en: string }
> = {
  ip_reputation: { zh: "IP 信誉", en: "IP reputation" },
  anti_replay: { zh: "防重放", en: "Anti-replay" },
  acl: { zh: "访问控制列表", en: "Access control list" },
  lua_pre: { zh: "Lua 前置策略", en: "Lua pre-policy" },
  owasp_default: { zh: "OWASP 检测", en: "OWASP detection" },
  cve_detection: { zh: "CVE 检测", en: "CVE detection" },
  bot_detection: { zh: "Bot 检测", en: "Bot detection" },
  browser_sign: { zh: "浏览器签名", en: "Browser signature" },
  rate_limit: { zh: "请求限流", en: "Request rate limit" },
}

function isSkipPathPhase(value: string): value is SkipPathPhase {
  return (SKIP_PATH_PHASES as readonly string[]).includes(value)
}

/**
 * 将 API 的对象或兼容的 JSON string 响应解析为可编辑映射。
 * 无效键与无效值均不进入编辑态，和后端归一化边界保持一致。
 */
export function parseSkipPathByPhase(value: unknown): SkipPathByPhase {
  let raw = value
  if (typeof raw === "string") {
    try {
      raw = JSON.parse(raw)
    } catch {
      return {}
    }
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {}

  const result: SkipPathByPhase = {}
  for (const [phase, paths] of Object.entries(raw)) {
    if (!isSkipPathPhase(phase) || !Array.isArray(paths)) continue
    const validPaths = paths.filter(
      (path): path is string => typeof path === "string"
    )
    if (validPaths.length > 0) result[phase] = [...validPaths]
  }
  return result
}

/** 返回未修剪空路径的精确位置，供 UI 在保存前阻止无效配置。 */
export function findEmptySkipPaths(value: SkipPathByPhase): SkipPathPhase[] {
  const invalid: SkipPathPhase[] = []
  for (const phase of SKIP_PATH_PHASES) {
    if (value[phase]?.some((path) => path.trim() === "")) invalid.push(phase)
  }
  return invalid
}

/**
 * 生成提交载荷：修剪路径、排除空 phase，同时保留空对象以表达显式不跳过。
 */
export function toSkipPathByPhasePayload(
  value: SkipPathByPhase
): SkipPathByPhase {
  const result: SkipPathByPhase = {}
  for (const phase of SKIP_PATH_PHASES) {
    const paths = value[phase]
    if (!paths) continue
    const normalized = paths.map((path) => path.trim()).filter(Boolean)
    if (normalized.length > 0) result[phase] = normalized
  }
  return result
}

/** 执行时验证前端允许 phase 与后端定义的稳定镜像是否一致。 */
export function assertSkipPathByPhaseContract(): void {
  const expected: SkipPathPhase[] = [
    "ip_reputation",
    "anti_replay",
    "acl",
    "lua_pre",
    "owasp_default",
    "cve_detection",
    "bot_detection",
    "browser_sign",
    "rate_limit",
  ]
  if (
    expected.length !== SKIP_PATH_PHASES.length ||
    expected.some((phase, index) => SKIP_PATH_PHASES[index] !== phase)
  ) {
    throw new Error("skip-path-by-phase contract is inconsistent")
  }
  if (Object.keys(SKIP_PATH_PHASE_LABELS).length !== SKIP_PATH_PHASES.length) {
    throw new Error("skip-path-by-phase labels are incomplete")
  }
}
