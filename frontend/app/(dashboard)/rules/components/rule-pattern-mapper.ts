/**
 * 规则条件行（target / method / content）→ 后端 matcher（kind / arg）映射器。
 *
 * 背景：规则对话框的 UI 用 `{target, method, content}` 三元组表达条件，
 * 后端 matcher 消费的字段是 `{kind, arg}` 二元组；前端必须先把这层
 * 翻译做完，最终落到 compound JSON 嵌套结构才能被 `parseCompoundJSON`
 * 正确编译。直接 dump `{target, method, content}` 默认会落到
 * `neverMatcher`，等同于空规则。
 *
 * 字段映射取值严格来自 `internal/core/rules/matcher.go` 中 `buildMatcher`
 * 的 switch 分支与 `knownPrefixes`（`internal/core/rules/compiler.go:110-131`）。
 * 任何新增 kind 必须先同步到 `knownPrefixes`、再补到本映射表，否则会被
 * 后端白名单直接拒绝。
 *
 * 本映射表在不破坏现有 9 个 matchMethods / 13 个 matchTargets 形态的
 * 前提下完成翻译；不引入 5 种新语义（包含 / 不包含 / 等于 / 正则 / 通配符）扩展。
 */

/** UI 行结构。 */
export interface ConditionRow {
  target: string
  method: string
  content: string
  /** 仅 req_header 使用。 */
  headerName?: string
  /** 仅 get_param / post_param 使用。 */
  paramName?: string
  /** 无法安全映射的后端规则，仅允许查看，禁止覆盖保存。 */
  uneditable?: boolean
  rawPattern?: string
  /** 从后端反向映射得到的原始叶子，用于未修改行的语义保真。 */
  source?: {
    kind: string
    arg: string
    format: "dsl" | "json"
    target: string
    method: string
    content: string
    headerName?: string
    paramName?: string
  }
}

/** 后端 matcher 接受的叶子节点。 */
export interface BackendKind {
  kind: string
  arg: string
}

/**
 * 翻译结果。当 UI 选择了一个不被后端支持的 (target, method) 组合时，
 * 返回 invalid，由调用方在表单校验阶段拦截。
 *
 * - ok=true 且 backend 存在 → 简单叶子 {kind,arg}。
 * - ok=true 且 wrapNot=true → 调用方需要把叶子包成
 *   {op:"not", children:[{kind,arg}]}，仅用于没有独立 matcher 的兼容条件。
 */
export interface TranslationResult {
  ok: boolean
  reason?: string
  backend?: BackendKind
  /** 标记"非"语义：调用方需在序列化时用 op:"not" 包一层。 */
  wrapNot?: boolean
}

/**
 * 求 (target, method) 组合对应的后端 matcher kind 与 arg。
 *
 * @param row  UI 输入行
 * @param param  额外参数：req_header 需要 header name；get_param / post_param 需要 param name
 */
export function translateRow(
  row: ConditionRow,
  param: { headerName?: string; paramName?: string; allowIP?: boolean } = {}
): TranslationResult {
  const target = row.target
  const method = row.method
  const rawValue = row.content ?? ""
  const value = method === "wildcard" ? rawValue : rawValue.trim()
  if (rawValue.trim() === "") {
    return { ok: false, reason: "row.content is empty" }
  }
  // 优先使用 param 显式传入的 name，其次从 row 中读取，确保 rowsToCompoundNode
  // 自动转发 row.headerName / row.paramName 时仍能命中。
  const headerName = (param.headerName ?? row.headerName ?? "").trim()
  const paramName = (param.paramName ?? row.paramName ?? "").trim()

  switch (target) {
    case "src_ip":
      return translateSrcIp(method, value, param.allowIP ?? false)
    case "url":
      return translateFullPath(method, value)
    case "url_path":
      return translatePath(method, value)
    case "host":
      return translateHost(method, value)
    case "host_full":
      return translateHostFull(method, value)
    case "get_param":
      return translateQueryParam(method, value, paramName)
    case "post_param":
      // 后端没有独立的 POST 参数 matcher。降级为 query_param 会在保存后
      // 重新打开时伪装成 GET 参数，并且丢失 contains 等 UI 语义。
      return {
        ok: false,
        reason: "post_param matcher is not supported by backend",
      }
    case "req_header":
      return translateHeader(method, value, headerName)
    case "req_body":
      return translateBody(method, value)
    case "resp_body":
      // 后端 matcher.go 中不存在 resp_body* 任何分支，显式拒绝。
      return {
        ok: false,
        reason: "resp_body matcher is not supported by backend",
      }
    case "http_req":
    case "http_resp":
      return {
        ok: false,
        reason: `${target} matcher is not supported by backend`,
      }
    case "method":
      return translateMethod(method, value)
    case "ja4":
      return translateJa4(method, value)
    default:
      return { ok: false, reason: `unknown target: ${target}` }
  }
}

function translateSrcIp(
  method: string,
  value: string,
  allowIP = false
): TranslationResult {
  // 注意：IP/CIDR 合法性检查只能在 IP 类 method 分支里做，不能提到 switch
  // 之前。in_geo / not_in_geo 的 value 是 ISO 3166-1 国家码（如 CN），
  // 前置 isValidIPOrCIDR 会把它们全部判为非法，导致地理条件无法提交。
  const requireIP = (): TranslationResult | null =>
    value.trim() === ""
      ? { ok: false, reason: "src_ip 必须填写 IP 或 CIDR" }
      : null

  switch (method) {
    case "eq":
    case "in_cidr":
      return (
        requireIP() ?? {
          ok: true,
          backend: { kind: allowIP ? "allow_ip" : "block_ip", arg: value },
        }
      )
    case "contains":
    case "in_ip_group":
    case "not_in_ip_group":
      return {
        ok: false,
        reason: `src_ip method ${method} is not supported without a dedicated IP-group matcher`,
      }
    case "not_in_cidr":
      // 后端 IP 匹配为正向 IP/CIDR；"不在" 语义需要在外层包 op:"not"，
      // 由 serializeGroupsToPattern 处理。
      return (
        requireIP() ?? {
          ok: true,
          backend: { kind: "block_ip", arg: value },
          wrapNot: true,
        }
      )
    case "in_geo":
    case "not_in_geo":
      // geo_block arg 是 CSV 国家码（matcher.go 行 1069-1079）。
      // not_in_geo 同样用 op:"not" 包装。
      if (!isValidGeoToken(value)) {
        return {
          ok: false,
          reason: "geo 国家码必须为 ISO 3166-1 alpha-2（例如 CN、US）",
        }
      }
      return {
        ok: true,
        backend: { kind: "geo_block", arg: value.toUpperCase() },
        wrapNot: method === "not_in_geo",
      }
    case "ne":
      // "src_ip 不等于 value" 在正向上等价于"匹配除了 value 之外的所有 IP"，
      // 没有合法的单 leaf 表达；要求用户改用 not_in_cidr。
      return {
        ok: false,
        reason: "src_ip 的 ne 语义请改用 not_in_cidr",
      }
    default:
      return { ok: false, reason: `unsupported method for src_ip: ${method}` }
  }
}

function translateFullPath(method: string, value: string): TranslationResult {
  // UI 的 url 目标含义是「完整 URL」（path + "?" + raw query），对应后端
  // fullURLContainsMatcher / fullURLRegexMatcher（matcher.go 行 808-827），
  // 它们拼接 ctx.Path 与 ctx.Query 后再匹配。
  // 不能落到 path_contains / block_path_* —— 那些 matcher 只看 ctx.Path
  // （matcher.go 行 701-703、443-445），会让「URL」与「URL 路径」两个目标
  // 产出完全相同的规则，且带 query 的条件永远不命中。
  // full_url 的 eq 使用锚定正则，ne 使用独立的 full_url_not_exact matcher。
  switch (method) {
    case "eq":
      return {
        ok: true,
        backend: {
          kind: "full_url_regex",
          arg: `^${escapeRegex(value)}$`,
        },
      }
    case "contains":
      return { ok: true, backend: { kind: "full_url_contains", arg: value } }
    case "regex":
      return { ok: true, backend: { kind: "full_url_regex", arg: value } }
    case "wildcard":
      return { ok: true, backend: { kind: "full_url_wildcard", arg: value } }
    case "ne":
      return {
        ok: true,
        backend: { kind: "full_url_not_exact", arg: value },
      }
    default:
      return {
        ok: false,
        reason: `method ${method} is not meaningful for url target`,
      }
  }
}

function translatePath(method: string, value: string): TranslationResult {
  switch (method) {
    case "eq":
      return { ok: true, backend: { kind: "block_path_exact", arg: value } }
    case "contains":
      return { ok: true, backend: { kind: "path_contains", arg: value } }
    case "regex":
      return { ok: true, backend: { kind: "block_path_regex", arg: value } }
    case "prefix":
      return { ok: true, backend: { kind: "block_path", arg: value } }
    case "wildcard":
      return { ok: true, backend: { kind: "path_wildcard", arg: value } }
    case "ne":
      return { ok: true, backend: { kind: "path_not_exact", arg: value } }
    default:
      return {
        ok: false,
        reason: `method ${method} is not meaningful for url_path target`,
      }
  }
}

function translateHostFull(method: string, value: string): TranslationResult {
  if (method !== "eq") {
    return {
      ok: false,
      reason: `method ${method} is not meaningful for host_full target`,
    }
  }
  return { ok: true, backend: { kind: "host_full", arg: value.toLowerCase() } }
}

function translateHost(method: string, value: string): TranslationResult {
  switch (method) {
    case "eq":
      return { ok: true, backend: { kind: "host", arg: value.toLowerCase() } }
    case "contains":
      return {
        ok: true,
        backend: { kind: "host_contains", arg: value.toLowerCase() },
      }
    case "regex":
      return { ok: true, backend: { kind: "host_regex", arg: value } }
    case "wildcard":
      return {
        ok: true,
        backend: { kind: "host_wildcard", arg: value.toLowerCase() },
      }
    case "ne":
      return {
        ok: true,
        backend: { kind: "host_not_exact", arg: value.toLowerCase() },
      }
    default:
      return {
        ok: false,
        reason: `method ${method} is not meaningful for host target`,
      }
  }
}

function translateQueryParam(
  method: string,
  value: string,
  paramName?: string
): TranslationResult {
  const name = (paramName ?? "").trim()
  if (name === "") {
    return {
      ok: false,
      reason: "get_param / post_param requires paramName (header-name-like)",
    }
  }
  if (name.includes(":")) {
    return {
      ok: false,
      reason: "paramName cannot contain ':' because backend matcher arguments use ':' as a delimiter",
    }
  }
  switch (method) {
    case "eq":
      return {
        ok: true,
        backend: { kind: "query_param", arg: `${name}:${value}` },
      }
    case "contains":
      return {
        ok: true,
        backend: { kind: "query_param", arg: `${name}:${value}` },
      }
    case "regex":
      return {
        ok: true,
        backend: { kind: "query_param_regex", arg: `${name}:${value}` },
      }
    case "ne":
      return {
        ok: true,
        backend: { kind: "query_param_not_exact", arg: `${name}:${value}` },
      }
    default:
      return {
        ok: false,
        reason: `method ${method} is not meaningful for query param`,
      }
  }
}

function translateHeader(
  method: string,
  value: string,
  headerName?: string
): TranslationResult {
  const name = (headerName ?? "").trim()
  if (name === "") {
    return {
      ok: false,
      reason: "req_header requires headerName (header-name-like)",
    }
  }
  if (name.includes(":")) {
    return {
      ok: false,
      reason: "headerName cannot contain ':' because backend matcher arguments use ':' as a delimiter",
    }
  }
  switch (method) {
    case "eq":
      return {
        ok: true,
        backend: { kind: "block_header_exact", arg: `${name}:${value}` },
      }
    case "contains":
      return {
        ok: true,
        backend: { kind: "block_header", arg: `${name}:${value}` },
      }
    case "regex":
      return {
        ok: true,
        backend: { kind: "header_regex", arg: `${name}:${value}` },
      }
    case "prefix":
      return {
        ok: true,
        backend: { kind: "block_header_prefix", arg: `${name}:${value}` },
      }
    case "wildcard":
      return {
        ok: true,
        backend: { kind: "header_wildcard", arg: `${name}:${value}` },
      }
    case "ne":
      return {
        ok: true,
        backend: { kind: "block_header_not_exact", arg: `${name}:${value}` },
      }
    default:
      return {
        ok: false,
        reason: `method ${method} is not meaningful for req_header`,
      }
  }
}

function translateBody(method: string, value: string): TranslationResult {
  switch (method) {
    case "eq":
      return {
        ok: true,
        backend: { kind: "body_contains", arg: value },
      }
    case "contains":
      return {
        ok: true,
        backend: { kind: "body_contains", arg: value },
      }
    case "regex":
      return { ok: true, backend: { kind: "body_regex", arg: value } }
    case "wildcard":
      return { ok: true, backend: { kind: "body_wildcard", arg: value } }
    case "ne":
      return { ok: true, backend: { kind: "body_not_exact", arg: value } }
    default:
      return {
        ok: false,
        reason: `method ${method} is not meaningful for req_body`,
      }
  }
}

function translateMethod(method: string, value: string): TranslationResult {
  switch (method) {
    case "eq":
      return {
        ok: true,
        backend: { kind: "block_method", arg: value.toUpperCase() },
      }
    default:
      return {
        ok: false,
        reason: `method ${method} is not meaningful for http method`,
      }
  }
}

function translateJa4(method: string, value: string): TranslationResult {
  switch (method) {
    case "eq":
    case "contains":
      return { ok: true, backend: { kind: "tls_ja4", arg: value } }
    case "regex":
      // 后端 tls_ja4 matcher 为等值匹配；regex 透传将不会生效。
      return {
        ok: false,
        reason:
          "ja4 backend matcher is exact-match only; regex is not supported",
      }
    default:
      return {
        ok: false,
        reason: `method ${method} is not meaningful for ja4`,
      }
  }
}

/**
 * 在正则字面量中转义元字符。用于 ne / 反向匹配的回写正则。
 */
function escapeRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

/**
 * 按首个冒号切分 `name:value`，语义与后端 splitHeaderArg
 * （matcher.go 行 1090-1095）一致：冒号必须在下标 > 0 处，
 * 否则整串视为 name、value 为空。
 *
 * @returns [name, value]
 */
function splitFirstColon(arg: string): [string, string] {
  const i = arg.indexOf(":")
  if (i > 0) {
    return [arg.slice(0, i), arg.slice(i + 1)]
  }
  return [arg, ""]
}

function isValidGeoToken(value: string): boolean {
  // ISO 3166-1 alpha-2：2 个字母。后端接受 CSV 形式，但单 token 也合法。
  return /^[A-Za-z]{2}$/.test(value.trim())
}

/**
 * 形如 `{"op":"and","children":[{kind,arg}...]} 的 compound JSON 节点。
 * 与内部 `compoundCondition` 结构（matcher.go 行 1122-1135）字段对齐。
 * 仅使用本前端序列化路径支持的 op 子集：and / or / not。
 */
export interface CompoundNode {
  op?: string
  kind?: string
  arg?: string
  children?: CompoundNode[]
}

/**
 * 将一个 AND 组内的多条 ConditionRow 序列化为一个 and compound 节点。
 * 单行退化为纯 {kind, arg} 叶子（不带外层 op）。
 *
 * 当整张表只含一组 AND 且只有一行时，沿用原始形态保持向下兼容。
 *
 * 当某行需要 not 包装（wrapNot=true），返回的叶子自动升级为
 * {op:"not", children:[{kind,arg}]}；外层若只剩 1 个 not 叶子，
 * 上层会直接以该节点作为单 OR 子节点，避免出现 {and:[{not:...]}] 冗余嵌套。
 */
export interface PatternSerializationOptions {
  allowIP?: boolean
}

function shouldPreserveSource(
  row: ConditionRow,
  allowIP = false
): row is ConditionRow & { source: NonNullable<ConditionRow["source"]> } {
  const source = row.source
  if (!source) return false
  if (
    source.target !== row.target ||
    source.method !== row.method ||
    source.content !== row.content ||
    source.headerName !== row.headerName ||
    source.paramName !== row.paramName
  ) {
    return false
  }
  if (source.kind === "allow_ip" && !allowIP) return false
  if (source.kind === "block_ip" && allowIP) return false
  return true
}

export function rowsToCompoundNode(
  rows: ConditionRow[],
  options: PatternSerializationOptions = {}
): CompoundNode | null {
  if (rows.length === 0) return null
  const leaves: CompoundNode[] = []
  for (const row of rows) {
    const r = translateRow(row, {
      headerName: row.headerName,
      paramName: row.paramName,
      allowIP: options.allowIP,
    })
    if (!r.ok || !r.backend) {
      throw new Error(`cannot translate row: ${r.reason ?? "unknown"}`)
    }
    const backend = shouldPreserveSource(row, options.allowIP)
      ? { kind: row.source!.kind, arg: row.source!.arg }
      : r.backend
    const leaf: CompoundNode = { kind: backend.kind, arg: backend.arg }
    leaves.push(r.wrapNot ? { op: "not", children: [leaf] } : leaf)
  }
  if (leaves.length === 1) {
    return leaves[0]
  }
  return { op: "and", children: leaves }
}

/**
 * 将 AND-of-OR 条件组序列化为最终写入 pattern 字段的字符串。
 *
 * - 单组单行：直接产出 `{kind, arg}` 叶子（与后端约定一致）。
 * - 单组多行：产出 `{op: "and", children: [{kind, arg}...]}`。
 * - 多组多行：产出 `{op: "or", children: [{op:"and", children: [...]}, ...]}`。
 */
export function serializeGroupsToPattern(
  groups: ConditionRow[][],
  options: PatternSerializationOptions = {}
): string {
  const orChildren: CompoundNode[] = []
  for (const group of groups) {
    const node = rowsToCompoundNode(group, options)
    if (node) {
      orChildren.push(node)
    }
  }
  if (orChildren.length === 0) {
    return ""
  }
  if (groups.length === 1 && groups[0]?.length === 1) {
    const row = groups[0][0]
    if (
      shouldPreserveSource(row, options.allowIP) &&
      row.source.format === "dsl"
    ) {
      return `${row.source.kind}:${row.source.arg}`
    }
  }
  if (orChildren.length === 1) {
    return JSON.stringify(orChildren[0])
  }
  return JSON.stringify({ op: "or", children: orChildren })
}

/**
 * 将一个 {kind, arg} 叶子反推回 UI 行。无法精确还原时返回 null，
 * 调用方应给出兜底（默认 src_ip + eq + 原 arg）。
 */
export function backendToRow(leaf: {
  kind: string
  arg: string
}): ConditionRow | null {
  if (typeof leaf.kind !== "string" || typeof leaf.arg !== "string") {
    return null
  }
  switch (leaf.kind) {
    case "block_ip":
      return { target: "src_ip", method: "eq", content: leaf.arg }
    case "allow_ip":
      return { target: "src_ip", method: "eq", content: leaf.arg }
    case "geo_block":
      if (leaf.arg.includes(",")) return null
      return {
        target: "src_ip",
        method: "in_geo",
        content: leaf.arg,
      }
    case "block_path":
      return { target: "url_path", method: "prefix", content: leaf.arg }
    case "block_path_exact":
      return { target: "url_path", method: "eq", content: leaf.arg }
    case "block_path_regex":
      return { target: "url_path", method: "regex", content: leaf.arg }
    case "path_contains":
      return { target: "url_path", method: "contains", content: leaf.arg }
    case "path_wildcard":
      return { target: "url_path", method: "wildcard", content: leaf.arg }
    case "path_not_contains":
      return { target: "url_path", method: "ne", content: leaf.arg }
    case "path_not_exact":
      return { target: "url_path", method: "ne", content: leaf.arg }
    case "host":
      return { target: "host", method: "eq", content: leaf.arg }
    case "host_full":
      return { target: "host_full", method: "eq", content: leaf.arg }
    case "host_wildcard":
      return { target: "host", method: "wildcard", content: leaf.arg }
    case "host_regex":
      return { target: "host", method: "regex", content: leaf.arg }
    case "host_contains":
      return { target: "host", method: "contains", content: leaf.arg }
    case "host_not_contains":
      return { target: "host", method: "ne", content: leaf.arg }
    case "host_not_exact":
      return { target: "host", method: "ne", content: leaf.arg }
    case "full_url_contains":
      return { target: "url", method: "contains", content: leaf.arg }
    case "full_url_not_exact":
      return { target: "url", method: "ne", content: leaf.arg }
    case "full_url_wildcard":
      return { target: "url", method: "wildcard", content: leaf.arg }
    case "full_url_regex":
      return { target: "url", method: "regex", content: leaf.arg }
    case "block_header_exact":
    case "block_header_not_exact":
    case "block_header_prefix":
    case "block_header":
    case "block_header_regex":
    case "header_regex":
    case "header_wildcard": {
      // arg 形如 `Name:value`，与后端 splitHeaderArg（matcher.go 行 1090-1095）
      // 一致地按首个冒号切分。必须把 name 回填到 headerName，否则重新打开
      // 已保存的规则后再次提交会因 headerName 为空而抛错。
      const [name, value] = splitFirstColon(leaf.arg)
      return {
        target: "req_header",
        method:
          leaf.kind === "block_header_exact"
            ? "eq"
            : leaf.kind === "block_header_not_exact"
              ? "ne"
              : leaf.kind === "block_header"
                ? "contains"
                : leaf.kind === "block_header_prefix"
                ? "prefix"
                : leaf.kind === "header_wildcard"
                  ? "wildcard"
                  : "regex",
        content: value,
        headerName: name,
      }
    }
    case "block_query_contains":
    case "block_query_regex":
      return null
    case "query_param":
    case "query_param_not_exact":
    case "query_param_regex": {
      // arg 形如 `param:value`；query_param 走 splitHeaderArg，
      // query_param_regex 走 strings.Cut（matcher.go 行 989-1002），
      // 两者都按首个冒号切分。param 名回填到 paramName 才能重新提交。
      const [name, value] = splitFirstColon(leaf.arg)
      return {
        target: "get_param",
        method:
          leaf.kind === "query_param"
            ? "eq"
            : leaf.kind === "query_param_not_exact"
              ? "ne"
              : "regex",
        content: value,
        paramName: name,
      }
    }
    case "block_method":
      return { target: "method", method: "eq", content: leaf.arg }
    // 下面这些 kind 的 arg 不含 header 名（后端把名字写死在 matcher 里），
    // 回显时把固定名填进 headerName、arg 原样进 content，这样重新提交会
    // 翻译成语义等价的 block_header / header_regex，而不是因 headerName
    // 为空而抛错。
    case "block_content_type":
      return null
    case "block_user_agent":
      return {
        target: "req_header",
        method: "contains",
        content: leaf.arg,
        headerName: "user-agent",
      }
    case "block_user_agent_regex":
      return {
        target: "req_header",
        method: "regex",
        content: leaf.arg,
        headerName: "user-agent",
      }
    case "body_contains":
    case "block_body_contains":
      return { target: "req_body", method: "contains", content: leaf.arg }
    case "body_not_exact":
      return { target: "req_body", method: "ne", content: leaf.arg }
    case "body_regex":
    case "block_body_regex":
      return { target: "req_body", method: "regex", content: leaf.arg }
    case "body_wildcard":
      return { target: "req_body", method: "wildcard", content: leaf.arg }
    case "block_body_json_path":
    case "block_multipart":
      return null
    case "cookie_contains":
      return {
        target: "req_header",
        method: "contains",
        content: leaf.arg,
        headerName: "cookie",
      }
    case "referer_contains":
      return {
        target: "req_header",
        method: "contains",
        content: leaf.arg,
        headerName: "referer",
      }
    case "header_order_contains":
    case "header_order_regex":
      return null
    case "tls_ja4":
      return { target: "ja4", method: "eq", content: leaf.arg }
    default:
      return null
  }
}

function withBackendSource(
  row: ConditionRow | null,
  leaf: { kind: string; arg: string },
  format: "dsl" | "json"
): ConditionRow | null {
  if (!row) return null
  return {
    ...row,
    source: {
      kind: leaf.kind,
      arg: leaf.arg,
      format,
      target: row.target,
      method: row.method,
      content: row.content,
      headerName: row.headerName,
      paramName: row.paramName,
    },
  }
}

/**
 * 把 `{op:"not", children:[{kind,arg}]}` 反推回带「不」语义的 UI 行。
 *
 * 写路径只有两个 kind 会被 wrapNot 包裹（translateSrcIp 的
 * not_in_cidr / not_in_ip_group → block_ip，not_in_geo → geo_block），
 * 因此这里只需还原这两类；其余 not 节点无法精确还原，返回 null。
 */
function notLeafToRow(leaf: {
  kind: string
  arg: string
}): ConditionRow | null {
  switch (leaf.kind) {
    case "block_ip":
    case "allow_ip":
      return { target: "src_ip", method: "not_in_cidr", content: leaf.arg }
    case "geo_block":
      if (leaf.arg.includes(",")) return null
      return {
        target: "src_ip",
        method: "not_in_geo",
        content: leaf.arg,
      }
    case "full_url_contains":
      return { target: "url", method: "ne", content: leaf.arg }
    case "body_contains":
      return { target: "req_body", method: "ne", content: leaf.arg }
    case "query_param": {
      const [name, value] = splitFirstColon(leaf.arg)
      return {
        target: "get_param",
        method: "ne",
        content: value,
        paramName: name,
      }
    }
    case "block_header": {
      const [name, value] = splitFirstColon(leaf.arg)
      return {
        target: "req_header",
        method: "ne",
        content: value,
        headerName: name,
      }
    }
    default:
      return null
  }
}

/**
 * 把任意一个「行级」compound 节点反推回 UI 行。
 * 覆盖两种形态：裸叶子 `{kind,arg}` 与 not 包装 `{op:"not",children:[叶子]}`。
 * 后者若被忽略，保存过的 not_in_cidr / not_in_geo 规则在重新打开对话框时
 * 会整行丢失，再次保存即静默退化成正向匹配。
 */
function nodeToRow(node: CompoundNode): ConditionRow | null {
  if (node.kind) {
    return withBackendSource(
      backendToRow({ kind: node.kind, arg: node.arg ?? "" }),
      { kind: node.kind, arg: node.arg ?? "" },
      "json"
    )
  }
  if (node.op === "not") {
    const child = node.children?.[0]
    if (child?.kind) {
      return withBackendSource(
        notLeafToRow({ kind: child.kind, arg: child.arg ?? "" }),
        { kind: child.kind, arg: child.arg ?? "" },
        "json"
      )
    }
  }
  return null
}

function makeUneditableRow(rawPattern: string): ConditionRow {
  return {
    target: "",
    method: "",
    content: "",
    uneditable: true,
    rawPattern,
  }
}

/**
 * 校验并规范化后端 compound JSON 的形状。
 * 后端会对 op 做 TrimSpace + ToLower；前端必须使用同一规则，且不能让
 * malformed children/arg 在后续行映射或序列化阶段触发运行时异常。
 */
function normalizeCompoundNode(value: unknown): CompoundNode | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null
  }
  const record = value as Record<string, unknown>
  const hasKind = Object.prototype.hasOwnProperty.call(record, "kind")
  const hasOp = Object.prototype.hasOwnProperty.call(record, "op")
  const hasChildren = Object.prototype.hasOwnProperty.call(record, "children")
  if (hasKind && (hasOp || hasChildren)) return null
  if (typeof record.kind === "string") {
    if (typeof record.arg !== "string") return null
    return { kind: record.kind, arg: record.arg }
  }
  if (typeof record.op !== "string" || !Array.isArray(record.children)) {
    return null
  }
  const op = record.op.trim().toLowerCase()
  if (op !== "and" && op !== "or" && op !== "not") return null
  if (
    record.children.length === 0 ||
    (op === "not" && record.children.length !== 1)
  ) {
    return null
  }
  const children = record.children.map(normalizeCompoundNode)
  if (children.some((child): child is null => child === null)) return null
  return { op, children: children as CompoundNode[] }
}

/**
 * 把后端 pattern 字符串解析成 UI 行（保留原 OR/AND 嵌套结构）。
 * 对无法安全还原的复合节点保留不可编辑标记，禁止静默覆盖原规则。
 */
export function parsePatternToRows(pattern: string): ConditionRow[][] {
  if (!pattern || pattern.trim() === "") {
    return [[{ target: "src_ip", method: "eq", content: "" }]]
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(pattern)
  } catch {
    // 后端 ParsePattern 会对 pattern 先做 TrimSpace 再 splitFirstColon，
    // 前端 DSL fallback 必须使用同一规则，否则带前后空白的合法 DSL
    // （如 "  block_ip:10.0.0.1  "）会被误判为不可编辑 raw 行。
    const trimmed = pattern.trim()
    const [kind, arg] = splitFirstColon(trimmed)
    const row = withBackendSource(
      backendToRow({ kind, arg }),
      { kind, arg },
      "dsl"
    )
    if (row) {
      return [[row]]
    }
    return [[makeUneditableRow(pattern)]]
  }
  const node = normalizeCompoundNode(parsed)
  if (!node) {
    return [[makeUneditableRow(pattern)]]
  }
  const rows = parseCompoundRows(node)
  if (rows.length === 0) {
    return [[makeUneditableRow(pattern)]]
  }
  return rows
}

function parseCompoundRows(node: CompoundNode): ConditionRow[][] {
  if (!node) return []
  // 单叶子 / 单 not 叶子：serializeGroupsToPattern 在「单组单行」时的产出形态。
  const single = nodeToRow(node)
  if (single) {
    return [[single]]
  }
  if (node.op === "and" && node.children) {
    // 如果 and 组里有任何 child 无法映射回 UI 行，整棵子树都不可编辑，
    // 否则 collectAndRows 会静默丢掉该 child，保存后改变规则语义。
    const andRows = collectAndRows(node.children)
    return andRows.length === node.children.length ? [andRows] : []
  }
  if (node.op === "or" && node.children) {
    const out: ConditionRow[][] = []
    for (const child of node.children) {
      if (child.op === "and" && child.children) {
        const andRows = collectAndRows(child.children)
        if (andRows.length !== child.children.length) return []
        out.push(andRows)
      } else {
        const row = nodeToRow(child)
        if (!row) return []
        out.push([row])
      }
    }
    return out
  }
  return []
}

/** 把一个 and 组的 children 逐个反推为 UI 行，跳过无法还原的节点。 */
function collectAndRows(children: CompoundNode[]): ConditionRow[] {
  const rows: ConditionRow[] = []
  for (const child of children) {
    const row = nodeToRow(child)
    if (row) rows.push(row)
  }
  return rows
}
