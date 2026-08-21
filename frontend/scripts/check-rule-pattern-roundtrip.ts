import assert from "node:assert/strict"
import {
  parsePatternToRows,
  serializeGroupsToPattern,
  translateRow,
} from "../app/(dashboard)/rules/components/rule-pattern-mapper"

interface RoundTripCase {
  name: string
  pattern: string
  allowIP?: boolean
}

function normalizeCompoundNode(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return value
  }
  const node = value as Record<string, unknown>
  if (Array.isArray(node.children)) {
    const children = node.children.map(normalizeCompoundNode)
    const normalizedOp =
      typeof node.op === "string" ? node.op.trim().toLowerCase() : node.op
    if ((normalizedOp === "and" || normalizedOp === "or") && children.length === 1) {
      return children[0]
    }
    return { ...node, op: normalizedOp, children }
  }
  return node
}

/** 验证可编辑规则在打开并原样保存后保持后端语义。 */
function assertRoundTrip(testCase: RoundTripCase): void {
  const groups = parsePatternToRows(testCase.pattern)
  assert.equal(
    groups.some((group) => group.some((row) => row.uneditable)),
    false,
    `${testCase.name}: pattern unexpectedly became uneditable`
  )

  const serialized = serializeGroupsToPattern(groups, {
    allowIP: testCase.allowIP,
  })
  if (testCase.pattern.trimStart().startsWith("{")) {
    assert.deepEqual(
      JSON.parse(serialized),
      normalizeCompoundNode(JSON.parse(testCase.pattern)),
      `${testCase.name}: compound semantics changed`
    )
    return
  }
  assert.equal(serialized, testCase.pattern, `${testCase.name}: DSL changed`)
}

function assertUneditableRaw(pattern: string): void {
  const groups = parsePatternToRows(pattern)
  assert.equal(groups.length, 1, `${pattern}: must produce one readonly group`)
  assert.equal(
    groups[0]?.length,
    1,
    `${pattern}: must produce one readonly row`
  )
  assert.equal(groups[0]?.[0]?.uneditable, true, `${pattern}: must be readonly`)
  assert.equal(
    groups[0]?.[0]?.rawPattern,
    pattern,
    `${pattern}: readonly row must preserve the complete source pattern`
  )
}

const roundTripCases: RoundTripCase[] = [
  { name: "block IP DSL", pattern: "block_ip:10.0.0.0/8" },
  {
    name: "allow IP DSL",
    pattern: "allow_ip:192.0.2.1",
    allowIP: true,
  },
  {
    name: "single-country geographic block",
    pattern: "geo_block:CN",
  },
  {
    name: "legacy user-agent DSL",
    pattern: "block_user_agent:curl/8",
  },
  {
    name: "query value containing colon",
    pattern: "query_param:redirect:https://example.com/callback",
  },
  {
    name: "host full with wildcard and port",
    pattern: '{"kind":"host_full","arg":"*.example.com:8443"}',
  },
  {
    name: "eight-star wildcard",
    pattern: '{"kind":"path_wildcard","arg":"/a*b*c*d*e*f*g*h*"}',
  },
  {
    name: "header wildcard",
    pattern: '{"kind":"header_wildcard","arg":"User-Agent:Mozilla*Chrome*"}',
  },
  {
    name: "wildcard preserves boundary spaces",
    pattern: '{"kind":"path_wildcard","arg":" /admin/* "}',
  },
  {
    name: "JA4 source preservation",
    pattern: '{"kind":"tls_ja4","arg":"t13d1516h2_8daaf6152771_02713d6af862"}',
  },
  {
    name: "not-in CIDR",
    pattern: '{"op":"not","children":[{"kind":"block_ip","arg":"10.0.0.0/8"}]}',
  },
  {
    name: "unary OR",
    pattern: '{"op":"or","children":[{"kind":"block_path","arg":"/admin"}]}',
  },
  {
    name: "OR of AND groups",
    pattern:
      '{"op":"or","children":[{"op":"and","children":[{"kind":"path_contains","arg":"/admin"},{"kind":"host","arg":"example.com"}]},{"op":"and","children":[{"kind":"query_param_regex","arg":"id:^[0-9]+$"}]}]}',
  },
]

for (const testCase of roundTripCases) assertRoundTrip(testCase)

for (const pattern of [
  "block_query_contains:token=admin",
  "block_query_regex:(?i)union\\s+select",
  "header_order_contains:host,user-agent",
  "header_order_regex:^host,.*cookie$",
  "block_body_json_path:$.credentials.password",
  "block_multipart:filename=payload.php",
  "block_content_type:application/x-php",
  "tls_ja3:771,4865-4866-4867,0-11-10,29-23,0",
  "tls_ja3_hash:0123456789abcdef",
  "tls_version:TLS13",
  "tls_sni:checkout.example.com",
  "tls_alpn:h2",
  "tls_cipher_suite:TLS_AES_128_GCM_SHA256",
  "tls_cipher_suites:TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
  "geo_block:CN,US",
]) {
  assertUneditableRaw(pattern)
}

// 空白容错：前端解析与后端 ParsePattern 同样先 trim 整体再按首个冒号切分。
// 序列化后空白会被规范化，因此只验证语义不变（parse → serialize 等价于 trim 后原值）。
assertRoundTrip({
  name: "DSL with surrounding whitespace",
  pattern: "  block_ip:10.0.0.0/8  ".trim(),
})

// compound op 大小写与前后空白兼容：后端 ToLower + TrimSpace。
assertRoundTrip({
  name: "compound op uppercase + whitespace",
  pattern: '{ "op" : "AND" , "children" : [ { "kind" : "block_path" , "arg" : "/admin" } , { "kind" : "host" , "arg" : "example.com" } ] }',
})

// 历史 not_contains 叶子没有独立 UI 操作符；source 元数据必须阻止
// 回显后被重新序列化为 not_exact。
for (const pattern of [
  "path_not_contains:/private",
  "host_not_contains:internal.example",
]) {
  assertRoundTrip({
    name: `legacy ${pattern.split(":", 1)[0]} round-trip`,
    pattern,
  })
}

// 根节点类型错误：数组、数字、字符串都不是合法 compound。
for (const malformed of [
  "[]",
  "42",
  "\"block_ip:1.2.3.4\"",
  "null",
  "true",
]) {
  assertUneditableRaw(malformed)
}

// malformed JSON 必须降级为只读行，不能抛异常。
assertUneditableRaw('{"op":"and","children":[{"kind":"block_path","arg":"/admin"')

// kind 叶子和 compound 字段混用时，后端按 op 解释；前端必须拒绝编辑，
// 不能按 kind 优先丢弃 children。
assertUneditableRaw(
  '{"op":"and","kind":"block_path","arg":"/a","children":[{"kind":"block_path","arg":"/admin"}]}'
)

// 叶子节点 arg 不是字符串：不允许。
assertUneditableRaw('{"kind":"block_ip","arg":123}')

// not 操作子数不为 1：非法，降级只读。
assertUneditableRaw('{"op":"not","children":[{"kind":"block_path","arg":"/a"},{"kind":"block_path","arg":"/b"}]}')

// and 子节点存在无法映射的未知 kind：整组降级只读，不能部分丢条件。
assertUneditableRaw('{"op":"and","children":[{"kind":"block_path","arg":"/admin"},{"kind":"unknown_kind","arg":"x"}]}')

// or 下嵌套 and，其中一个 and 含未知 kind：整体降级只读。
assertUneditableRaw(
  '{"op":"or","children":[{"op":"and","children":[{"kind":"block_path","arg":"/a"},{"kind":"no_such_kind","arg":"x"}]},{"kind":"block_path","arg":"/b"}]}'
)

// Header 名含冒号：后端已有规则可以读取，但 UI 新建条件不能再生成这种
// 无法逆向分隔的参数，因此只验证 translateRow 拒绝，而不要求历史规则只读。
// 验证 UI 新建条件在 headerName / paramName 含冒号时不能提交。
{
  const headerColon = translateRow(
    {
      target: "req_header",
      method: "contains",
      content: "value",
      headerName: "X:Bad",
    },
    { headerName: "X:Bad" }
  )
  assert.equal(headerColon.ok, false, "headerName with colon must be rejected")
}

{
  const paramColon = translateRow(
    {
      target: "get_param",
      method: "contains",
      content: "value",
      paramName: "param:bad",
    },
    { paramName: "param:bad" }
  )
  assert.equal(paramColon.ok, false, "paramName with colon must be rejected")
}

// post_param / resp_body / http_req / http_resp 必须在 translateRow 阶段拒绝。
for (const target of ["post_param", "resp_body", "http_req", "http_resp"] as const) {
  const r = translateRow({
    target,
    method: "contains",
    content: "x",
  })
  assert.equal(r.ok, false, `${target} must be rejected by translateRow`)
}

const unsupportedPattern =
  '{"op":"if","if":{"kind":"host","arg":"example.com"},"then":{"kind":"block_path","arg":"/admin"}}'
const unsupportedRows = parsePatternToRows(unsupportedPattern)
assert.equal(unsupportedRows.length, 1)
assert.equal(unsupportedRows[0]?.length, 1)
assert.equal(unsupportedRows[0]?.[0]?.uneditable, true)
assert.equal(unsupportedRows[0]?.[0]?.rawPattern, unsupportedPattern)

console.log(
  `rule pattern round-trip check passed (${roundTripCases.length} cases)`
)
