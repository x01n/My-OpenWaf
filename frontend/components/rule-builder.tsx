"use client"

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react"
import {
  AlertCircle,
  CheckCircle2,
  Code,
  Eye,
  Plus,
  TestTube,
  Trash2,
} from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { CopyableBlock } from "@/components/log-presentation"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  testRulePattern,
  validateRulePattern,
  type RuleValidationResponse,
} from "@/lib/api"
import { cn } from "@/lib/utils"

const RULE_KINDS = [
  // Source IP
  {
    value: "block_ip",
    label: "封禁 IP/CIDR",
    placeholder: "192.168.1.0/24",
    group: "源 IP",
  },
  {
    value: "allow_ip",
    label: "放行 IP/CIDR",
    placeholder: "10.0.0.0/8",
    group: "源 IP",
  },
  {
    value: "geo_block",
    label: "地理位置封禁",
    placeholder: "CN,RU,KP",
    group: "源 IP",
  },
  // URL Path
  {
    value: "block_path",
    label: "路径前缀",
    placeholder: "/admin",
    group: "URL 路径",
  },
  {
    value: "block_path_exact",
    label: "路径精确",
    placeholder: "/.env",
    group: "URL 路径",
  },
  {
    value: "block_path_regex",
    label: "路径正则",
    placeholder: "(?i)/admin.*\\.php",
    group: "URL 路径",
  },
  {
    value: "full_url_contains",
    label: "完整 URL 包含",
    placeholder: "/admin?debug=",
    group: "URL 路径",
  },
  {
    value: "full_url_regex",
    label: "完整 URL 正则",
    placeholder: "(?i)/api/v[0-9]+/",
    group: "URL 路径",
  },
  // Query
  {
    value: "block_query_contains",
    label: "查询包含",
    placeholder: "union+select",
    group: "查询参数",
  },
  {
    value: "block_query_regex",
    label: "查询正则",
    placeholder: "(?i)union\\s+select",
    group: "查询参数",
  },
  {
    value: "query_param",
    label: "查询参数精确",
    placeholder: "id:1",
    group: "查询参数",
  },
  // Request Header
  {
    value: "block_header",
    label: "请求头包含",
    placeholder: "User-Agent:BadBot",
    group: "请求头",
  },
  {
    value: "block_header_regex",
    label: "请求头正则",
    placeholder: "User-Agent:(?i)bot|crawl",
    group: "请求头",
  },
  {
    value: "header_regex",
    label: "请求头值正则",
    placeholder: "X-Token:(?i)^test",
    group: "请求头",
  },
  {
    value: "block_user_agent",
    label: "User-Agent 包含",
    placeholder: "sqlmap",
    group: "请求头",
  },
  {
    value: "block_user_agent_regex",
    label: "User-Agent 正则",
    placeholder: "(?i)(sqlmap|nuclei)",
    group: "请求头",
  },
  {
    value: "host",
    label: "Host 精确匹配",
    placeholder: "admin.example.com",
    group: "请求头",
  },
  {
    value: "host_full",
    label: "Host 通配符",
    placeholder: "*.example.com",
    group: "请求头",
  },
  {
    value: "host_regex",
    label: "Host 正则表达式",
    placeholder: "(?i)(admin|api)\\.example\\.com",
    group: "请求头",
  },
  {
    value: "host_contains",
    label: "Host 包含",
    placeholder: "example.com",
    group: "请求头",
  },
  {
    value: "host_not_contains",
    label: "Host 不包含",
    placeholder: "internal",
    group: "请求头",
  },
  {
    value: "cookie_contains",
    label: "Cookie 包含",
    placeholder: "debug=true",
    group: "请求头",
  },
  {
    value: "referer_contains",
    label: "Referer 包含",
    placeholder: "evil.example",
    group: "请求头",
  },
  // Request Body
  {
    value: "body_contains",
    label: "请求 Body 包含",
    placeholder: "eval(",
    group: "请求 Body",
  },
  {
    value: "body_regex",
    label: "请求 Body 正则",
    placeholder: "(?i)<script",
    group: "请求 Body",
  },
  {
    value: "block_body_json_path",
    label: "JSON Path",
    placeholder: "$.user.role:(?i)admin",
    group: "请求 Body",
  },
  {
    value: "block_multipart",
    label: "上传文件名匹配",
    placeholder: "(?i)\\.(php|jsp|exe)$",
    group: "请求 Body",
  },
  // Protocol / Method
  {
    value: "block_method",
    label: "HTTP 方法",
    placeholder: "DELETE",
    group: "请求方法",
  },
  {
    value: "block_content_type",
    label: "Content-Type",
    placeholder: "application/xml",
    group: "请求方法",
  },
  {
    value: "tls_ja3_hash",
    label: "TLS JA3 Hash",
    placeholder: "27a5061c22108817120d1d3870cba0e0",
    group: "指纹匹配",
  },
  {
    value: "tls_ja4",
    label: "TLS JA4",
    placeholder: "t13d1516h2_8daaf6152771_e5627efa2ab1",
    group: "指纹匹配",
  },
  {
    value: "tls_version",
    label: "TLS 版本",
    placeholder: "TLS13",
    group: "指纹匹配",
  },
  {
    value: "tls_sni",
    label: "TLS SNI",
    placeholder: "login.example.com",
    group: "指纹匹配",
  },
  {
    value: "tls_alpn",
    label: "TLS ALPN",
    placeholder: "h2",
    group: "指纹匹配",
  },
  {
    value: "header_order_contains",
    label: "Header 顺序包含",
    placeholder: "host,user-agent,accept",
    group: "指纹匹配",
  },
  {
    value: "header_order_regex",
    label: "Header 顺序正则",
    placeholder: "(?i)user-agent.*accept",
    group: "指纹匹配",
  },
] as const

interface Condition {
  id: string
  kind: string
  arg: string
}

interface CompoundGroup {
  op: "and" | "or" | "not"
  children: Condition[]
}

interface RuleBuilderProps {
  value: string
  onChange: (pattern: string) => void
}

function conditionId(index: number) {
  return `condition-${index}`
}

function parsePattern(raw: string): {
  mode: "simple" | "compound"
  condition: Condition
  compound: CompoundGroup
} {
  const trimmed = raw.trim()
  const fallbackCondition = {
    id: conditionId(0),
    kind: "block_ip",
    arg: "",
  }
  const fallbackCompound = {
    op: "and" as const,
    children: [{ id: conditionId(0), kind: "block_ip", arg: "" }],
  }

  if (!trimmed) {
    return {
      mode: "simple",
      condition: fallbackCondition,
      compound: fallbackCompound,
    }
  }

  if (trimmed.startsWith("{")) {
    try {
      const obj = JSON.parse(trimmed) as {
        op?: "and" | "or" | "not"
        children?: Array<{ kind?: string; arg?: string }>
      }
      if (obj.op && Array.isArray(obj.children)) {
        return {
          mode: "compound",
          condition: fallbackCondition,
          compound: {
            op: obj.op,
            children: obj.children.length
              ? obj.children.map((child, index) => ({
                  id: conditionId(index),
                  kind: child.kind || "",
                  arg: child.arg || "",
                }))
              : fallbackCompound.children,
          },
        }
      }
    } catch {}
  }

  const colonIndex = trimmed.indexOf(":")
  if (colonIndex > 0) {
    const kind = trimmed.slice(0, colonIndex)
    const arg = trimmed.slice(colonIndex + 1)
    if (RULE_KINDS.some((item) => item.value === kind)) {
      return {
        mode: "simple",
        condition: { id: conditionId(0), kind, arg },
        compound: fallbackCompound,
      }
    }
  }

  return {
    mode: "simple",
    condition: { id: conditionId(0), kind: "", arg: trimmed },
    compound: fallbackCompound,
  }
}

function buildDSL(
  mode: "simple" | "compound",
  condition: Condition,
  compound: CompoundGroup
) {
  if (mode === "simple") {
    if (!condition.kind || !condition.arg) return ""
    return `${condition.kind}:${condition.arg}`
  }

  const validChildren = compound.children.filter(
    (child) => child.kind && child.arg
  )
  if (validChildren.length === 0) return ""
  if (validChildren.length === 1 && compound.op !== "not") {
    return `${validChildren[0].kind}:${validChildren[0].arg}`
  }

  return JSON.stringify({
    op: compound.op,
    children: validChildren.map((child) => ({
      kind: child.kind,
      arg: child.arg,
    })),
  })
}

export function RuleBuilder({ value, onChange }: RuleBuilderProps) {
  const idPrefix = useId()
  const parsedValue = useMemo(() => parsePattern(value), [value])
  const conditionIdRef = useRef(parsedValue.compound.children.length)
  const makeConditionId = useCallback(() => {
    const nextId = conditionIdRef.current
    conditionIdRef.current += 1
    return conditionId(nextId)
  }, [])
  const groupedKinds = useMemo(() => {
    const grouped = new Map<string, Array<(typeof RULE_KINDS)[number]>>()
    for (const item of RULE_KINDS) {
      if (!grouped.has(item.group)) {
        grouped.set(item.group, [])
      }
      grouped.get(item.group)?.push(item)
    }
    return Array.from(grouped.entries())
  }, [])

  const [mode, setMode] = useState<"simple" | "compound">(parsedValue.mode)
  const [condition, setCondition] = useState<Condition>(parsedValue.condition)
  const [compound, setCompound] = useState<CompoundGroup>(parsedValue.compound)
  const [advancedMode, setAdvancedMode] = useState(false)
  const [rawDSL, setRawDSL] = useState(value)
  const [testInput, setTestInput] = useState({
    path: "/admin",
    method: "GET",
    ip: "192.168.1.100",
    headers:
      "User-Agent: Mozilla/5.0\nX-OWAF-TLS-JA3-Hash: 27a5061c22108817120d1d3870cba0e0\nX-OWAF-TLS-JA4: t13d1516h2_8daaf6152771_e5627efa2ab1\nX-OWAF-TLS-Version: TLS13\nX-OWAF-TLS-SNI: login.example.com\nX-OWAF-TLS-ALPN: h2\nX-OWAF-Header-Order: host,user-agent,accept",
    query: "",
    body: "",
  })
  const [testResult, setTestResult] = useState<{
    match: boolean
    message: string
    kind?: string
    arg?: string
    error?: boolean
  } | null>(null)
  const [testOperationDetails, setTestOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const [validationResult, setValidationResult] =
    useState<RuleValidationResponse | null>(null)
  const [validationOperationDetails, setValidationOperationDetails] =
    useState<Record<string, unknown> | null>(null)
  const [validating, setValidating] = useState(false)

  useEffect(() => {
    return deferEffect(() => {
      conditionIdRef.current = parsedValue.compound.children.length
      setMode(parsedValue.mode)
      setCondition(parsedValue.condition)
      setCompound(parsedValue.compound)
      setRawDSL(value)
    })
  }, [parsedValue, value])

  useEffect(() => {
    if (!advancedMode) return
    return deferEffect(() => setRawDSL(buildDSL(mode, condition, compound)))
  }, [advancedMode, mode, condition, compound])

  function emit(
    nextMode: "simple" | "compound",
    nextCondition: Condition,
    nextCompound: CompoundGroup
  ) {
    const dsl = buildDSL(nextMode, nextCondition, nextCompound)
    setRawDSL(dsl)
    setValidationResult(null)
    setValidationOperationDetails(null)
    setTestResult(null)
    setTestOperationDetails(null)
    onChange(dsl)
  }

  function setSimpleKind(kind: string) {
    const next = { ...condition, kind }
    setCondition(next)
    emit("simple", next, compound)
  }

  function setSimpleArg(arg: string) {
    const next = { ...condition, arg }
    setCondition(next)
    emit("simple", next, compound)
  }

  function switchVisualMode(nextMode: "simple" | "compound") {
    setMode(nextMode)
    if (nextMode === "compound" && compound.children.length === 0) {
      const nextCompound = {
        op: "and" as const,
        children: [
          { id: makeConditionId(), kind: condition.kind, arg: condition.arg },
        ],
      }
      setCompound(nextCompound)
      emit(nextMode, condition, nextCompound)
      return
    }
    emit(nextMode, condition, compound)
  }

  function updateCompoundOp(op: "and" | "or" | "not") {
    const next = { ...compound, op }
    setCompound(next)
    emit("compound", condition, next)
  }

  function addChild() {
    const next = {
      ...compound,
      children: [
        ...compound.children,
        { id: makeConditionId(), kind: "block_ip", arg: "" },
      ],
    }
    setCompound(next)
    emit("compound", condition, next)
  }

  function removeChild(id: string) {
    const nextChildren = compound.children.filter((child) => child.id !== id)
    const next = {
      ...compound,
      children: nextChildren.length
        ? nextChildren
        : [{ id: makeConditionId(), kind: "block_ip", arg: "" }],
    }
    setCompound(next)
    emit("compound", condition, next)
  }

  function updateChild(id: string, field: "kind" | "arg", nextValue: string) {
    const next = {
      ...compound,
      children: compound.children.map((child) =>
        child.id === id ? { ...child, [field]: nextValue } : child
      ),
    }
    setCompound(next)
    emit("compound", condition, next)
  }

  function parseHeadersInput() {
    return Object.fromEntries(
      testInput.headers
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [key, ...rest] = line.split(":")
          return [key.trim(), rest.join(":").trim()]
        })
        .filter(([key]) => key)
    )
  }

  async function validateRule() {
    if (!rawDSL.trim()) {
      toast.error("规则不能为空")
      setValidationResult({
        valid: false,
        message: "规则不能为空",
      })
      return
    }
    setValidating(true)
    try {
      const data = await validateRulePattern(rawDSL)
      setValidationResult(data)
      setValidationOperationDetails({
        operation: "validate_rule_pattern",
        pattern: rawDSL,
        response: data,
      })
      if (data.valid) {
        toast.success(data.message || "规则语法正确")
      } else {
        toast.error(data.message || "规则验证失败")
      }
    } catch (error) {
      const response = {
        valid: false,
        message: error instanceof Error ? error.message : "验证失败",
      }
      setValidationResult(response)
      setValidationOperationDetails({
        operation: "validate_rule_pattern",
        pattern: rawDSL,
        response,
      })
      toast.error(error instanceof Error ? error.message : "验证失败")
    } finally {
      setValidating(false)
    }
  }

  async function testRule() {
    const dsl = rawDSL.trim()
    if (!dsl) {
      setTestResult({ match: false, message: "规则为空", error: true })
      setTestOperationDetails(null)
      return
    }

    const payload = {
      pattern: dsl,
      client_ip: testInput.ip,
      method: testInput.method,
      path: testInput.path,
      query: testInput.query,
      headers: parseHeadersInput(),
      body: testInput.body,
    }
    try {
      const data = await testRulePattern(payload)
      setTestResult({
        match: data.matched,
        kind: data.kind,
        arg: data.arg,
        message: data.matched ? "后端真实匹配命中" : "后端真实匹配未命中",
      })
      setTestOperationDetails({
        operation: "test_rule_pattern",
        payload,
        response: data,
      })
    } catch (error) {
      const response = {
        error: error instanceof Error ? error.message : "测试失败",
      }
      setTestResult({
        match: false,
        message: response.error,
        error: true,
      })
      setTestOperationDetails({
        operation: "test_rule_pattern",
        payload,
        response,
      })
    }
  }

  const simplePreview = buildDSL("simple", condition, compound)
  const compoundPreview = buildDSL("compound", condition, compound)
  const validationFeedback = validationResult ? (
    <Alert
      variant={validationResult.valid ? "default" : "destructive"}
      className={cn(
        validationResult.valid
          ? "border-chart-2/25 bg-chart-2/10"
          : "border-destructive/25 bg-destructive/10"
      )}
    >
      {validationResult.valid ? (
        <CheckCircle2 aria-hidden="true" />
      ) : (
        <AlertCircle aria-hidden="true" />
      )}
      <AlertTitle className="text-sm">
        {validationResult.valid ? "规则校验通过" : "规则校验未通过"}
      </AlertTitle>
      <AlertDescription
        className={cn(
          "flex flex-col gap-2 text-xs",
          validationResult.valid ? "text-foreground" : "text-destructive"
        )}
      >
        <span>{validationResult.message || "后端未返回说明"}</span>
        {validationResult.kind || validationResult.arg ? (
          <span className="break-all">
            kind: {validationResult.kind || "-"} / arg:{" "}
            {validationResult.arg || "-"}
          </span>
        ) : null}
        {validationResult.errors?.length ? (
          <ul className="ms-4 flex list-disc flex-col gap-1">
            {validationResult.errors.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        ) : null}
      </AlertDescription>
    </Alert>
  ) : null
  const testFeedback = testResult ? (
    <Alert
      variant={testResult.error ? "destructive" : "default"}
      className={cn(
        testResult.error
          ? "border-destructive/25 bg-destructive/10"
          : testResult.match
            ? "border-chart-2/25 bg-chart-2/10"
            : "border-chart-3/25 bg-chart-3/10"
      )}
    >
      {testResult.match ? (
        <CheckCircle2 aria-hidden="true" />
      ) : (
        <AlertCircle aria-hidden="true" />
      )}
      <AlertTitle className="text-sm">
        {testResult.error
          ? "测试失败"
          : testResult.match
            ? "测试命中"
            : "测试未命中"}
      </AlertTitle>
      <AlertDescription
        className={cn(
          "flex flex-col gap-2 text-xs",
          testResult.error ? "text-destructive" : "text-foreground"
        )}
      >
        <span>{testResult.message}</span>
        {testResult.kind || testResult.arg ? (
          <span className="break-all">
            kind: {testResult.kind || "-"} / arg: {testResult.arg || "-"}
          </span>
        ) : null}
      </AlertDescription>
    </Alert>
  ) : null

  return (
    <div className="flex flex-col gap-5 rounded-lg border border-border bg-muted/35 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-foreground">
            规则构建器
          </div>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            支持简单 DSL、复合 JSON 与快速测试，用于生成真实 pattern 字段。
          </p>
        </div>
        <Button
          type="button"
          variant={advancedMode ? "default" : "outline"}
          size="sm"
          className="rounded-md"
          onClick={() => setAdvancedMode((current) => !current)}
        >
          <Code data-icon="inline-start" />
          {advancedMode ? "可视化模式" : "高级模式"}
        </Button>
      </div>

      {advancedMode ? (
        <div className="flex flex-col gap-4">
          <Field>
            <FieldLabel htmlFor={`${idPrefix}-dsl`} className="text-xs">
              DSL 规则
            </FieldLabel>
            <Textarea
              id={`${idPrefix}-dsl`}
              value={rawDSL}
              onChange={(event) => {
                setRawDSL(event.target.value)
                setValidationResult(null)
                setTestResult(null)
                onChange(event.target.value)
              }}
              placeholder='{"op":"and","children":[{"kind":"block_ip","arg":"1.2.3.0/24"}]}'
              className="min-h-[160px] rounded-lg bg-background font-mono text-xs"
            />
          </Field>

          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="rounded-md"
              disabled={validating}
              onClick={validateRule}
            >
              {validating ? "验证中..." : "验证规则"}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="rounded-md"
              onClick={() => {
                const parsed = parsePattern(rawDSL)
                conditionIdRef.current = parsed.compound.children.length
                setMode(parsed.mode)
                setCondition(parsed.condition)
                setCompound(parsed.compound)
                setAdvancedMode(false)
              }}
            >
              切换到可视化
            </Button>
          </div>

          {validationFeedback}

          <Alert className="border-chart-3/25 bg-chart-3/10">
            <AlertDescription className="text-xs leading-6 text-foreground">
              简单规则格式为 <code>kind:arg</code>，复合规则格式为 JSON。示例：
              <code>block_ip:192.168.1.0/24</code>。
            </AlertDescription>
          </Alert>
        </div>
      ) : (
        <Tabs value="visual" className="w-full">
          <TabsList className="hidden">
            <TabsTrigger value="visual">可视化</TabsTrigger>
          </TabsList>
          <TabsContent value="visual" className="flex flex-col gap-5">
            <ToggleGroup
              type="single"
              value={mode}
              onValueChange={(nextMode) => {
                if (nextMode === "simple" || nextMode === "compound") {
                  switchVisualMode(nextMode)
                }
              }}
              variant="outline"
              size="sm"
              spacing={0}
            >
              <ToggleGroupItem value="simple">简单条件</ToggleGroupItem>
              <ToggleGroupItem value="compound">复合条件</ToggleGroupItem>
            </ToggleGroup>

            {mode === "simple" ? (
              <div className="flex flex-col gap-4">
                <FieldGroup className="grid gap-4 md:grid-cols-[180px_1fr]">
                  <Field>
                    <FieldLabel
                      htmlFor={`${idPrefix}-simple-kind`}
                      className="text-xs"
                    >
                      匹配类型
                    </FieldLabel>
                    <Select
                      value={condition.kind}
                      onValueChange={setSimpleKind}
                    >
                      <SelectTrigger
                        id={`${idPrefix}-simple-kind`}
                        className="w-full rounded-md bg-background"
                      >
                        <SelectValue placeholder="选择匹配类型" />
                      </SelectTrigger>
                      <SelectContent>
                        {groupedKinds.map(([group, items]) => (
                          <SelectGroup key={group}>
                            <SelectLabel>{group}</SelectLabel>
                            {items.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        ))}
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field>
                    <FieldLabel
                      htmlFor={`${idPrefix}-simple-arg`}
                      className="text-xs"
                    >
                      参数值
                    </FieldLabel>
                    <Input
                      id={`${idPrefix}-simple-arg`}
                      value={condition.arg}
                      onChange={(event) => setSimpleArg(event.target.value)}
                      placeholder={
                        RULE_KINDS.find((item) => item.value === condition.kind)
                          ?.placeholder || "输入匹配参数"
                      }
                      className="rounded-md bg-background"
                    />
                  </Field>
                </FieldGroup>

                <div className="rounded-lg border border-border bg-background px-4 py-3 text-xs leading-6 text-muted-foreground">
                  <div className="mb-1 flex items-center gap-2 font-medium text-foreground">
                    <Eye className="size-3.5" aria-hidden="true" />
                    DSL 预览
                  </div>
                  <code className="text-[11px] break-all">
                    {simplePreview || "未生成规则"}
                  </code>
                </div>
              </div>
            ) : (
              <div className="flex flex-col gap-4">
                <div className="flex flex-wrap items-center gap-3">
                  <Field
                    orientation="horizontal"
                    className="w-auto flex-row items-center gap-2"
                  >
                    <FieldLabel
                      htmlFor={`${idPrefix}-compound-op`}
                      className="text-xs"
                    >
                      逻辑运算
                    </FieldLabel>
                    <Select
                      value={compound.op}
                      onValueChange={(value) =>
                        updateCompoundOp(value as "and" | "or" | "not")
                      }
                    >
                      <SelectTrigger
                        id={`${idPrefix}-compound-op`}
                        className="w-[140px] rounded-md bg-background"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value="and">AND（且）</SelectItem>
                          <SelectItem value="or">OR（或）</SelectItem>
                          <SelectItem value="not">NOT（非）</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="rounded-md"
                    onClick={addChild}
                  >
                    <Plus data-icon="inline-start" />
                    添加条件
                  </Button>
                </div>

                <div className="flex flex-col gap-3">
                  {compound.children.map((child, index) => (
                    <div
                      key={child.id}
                      className="flex flex-col gap-2 rounded-lg border border-border bg-background p-4"
                    >
                      {index > 0 ? (
                        <div className="text-[11px] font-semibold tracking-[0.18em] text-muted-foreground uppercase">
                          {compound.op}
                        </div>
                      ) : null}
                      <div className="grid gap-3 md:grid-cols-[180px_1fr_auto]">
                        <Field>
                          <FieldLabel
                            htmlFor={`${idPrefix}-${child.id}-kind`}
                            className="sr-only"
                          >
                            匹配类型
                          </FieldLabel>
                          <Select
                            value={child.kind}
                            onValueChange={(nextValue) =>
                              updateChild(child.id, "kind", nextValue)
                            }
                          >
                            <SelectTrigger
                              id={`${idPrefix}-${child.id}-kind`}
                              className="w-full rounded-md bg-muted/35"
                            >
                              <SelectValue placeholder="匹配类型" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectGroup>
                                {RULE_KINDS.map((item) => (
                                  <SelectItem
                                    key={item.value}
                                    value={item.value}
                                  >
                                    {item.label}
                                  </SelectItem>
                                ))}
                              </SelectGroup>
                            </SelectContent>
                          </Select>
                        </Field>
                        <Field>
                          <FieldLabel
                            htmlFor={`${idPrefix}-${child.id}-arg`}
                            className="sr-only"
                          >
                            参数值
                          </FieldLabel>
                          <Input
                            id={`${idPrefix}-${child.id}-arg`}
                            value={child.arg}
                            onChange={(event) =>
                              updateChild(child.id, "arg", event.target.value)
                            }
                            placeholder={
                              RULE_KINDS.find(
                                (item) => item.value === child.kind
                              )?.placeholder || "输入参数"
                            }
                            className="rounded-md bg-muted/35"
                          />
                        </Field>
                        <Button
                          type="button"
                          variant="destructive"
                          size="icon-sm"
                          className="rounded-md"
                          aria-label="删除条件"
                          onClick={() => removeChild(child.id)}
                        >
                          <Trash2 data-icon="inline-start" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="rounded-lg border border-border bg-background px-4 py-3 text-xs leading-6 text-muted-foreground">
                  <div className="mb-1 flex items-center gap-2 font-medium text-foreground">
                    <Eye className="size-3.5" aria-hidden="true" />
                    DSL 预览
                  </div>
                  <code className="text-[11px] break-all">
                    {compoundPreview || "未生成规则"}
                  </code>
                </div>
              </div>
            )}

            <div className="flex flex-col gap-4 rounded-lg border border-border bg-background p-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
                <TestTube className="size-4" aria-hidden="true" />
                规则测试
              </div>
              <FieldGroup className="grid gap-3 md:grid-cols-2">
                <Field>
                  <FieldLabel
                    htmlFor={`${idPrefix}-test-path`}
                    className="sr-only"
                  >
                    请求路径
                  </FieldLabel>
                  <Input
                    id={`${idPrefix}-test-path`}
                    value={testInput.path}
                    onChange={(event) =>
                      setTestInput((current) => ({
                        ...current,
                        path: event.target.value,
                      }))
                    }
                    placeholder="路径，例如 /admin"
                    className="rounded-md bg-muted/35"
                  />
                </Field>
                <Field>
                  <FieldLabel
                    htmlFor={`${idPrefix}-test-method`}
                    className="sr-only"
                  >
                    请求方法
                  </FieldLabel>
                  <Input
                    id={`${idPrefix}-test-method`}
                    value={testInput.method}
                    onChange={(event) =>
                      setTestInput((current) => ({
                        ...current,
                        method: event.target.value,
                      }))
                    }
                    placeholder="方法，例如 GET"
                    className="rounded-md bg-muted/35"
                  />
                </Field>
                <Field>
                  <FieldLabel
                    htmlFor={`${idPrefix}-test-ip`}
                    className="sr-only"
                  >
                    客户端 IP
                  </FieldLabel>
                  <Input
                    id={`${idPrefix}-test-ip`}
                    value={testInput.ip}
                    onChange={(event) =>
                      setTestInput((current) => ({
                        ...current,
                        ip: event.target.value,
                      }))
                    }
                    placeholder="IP，例如 192.168.1.100"
                    className="rounded-md bg-muted/35"
                  />
                </Field>
                <Field>
                  <FieldLabel
                    htmlFor={`${idPrefix}-test-query`}
                    className="sr-only"
                  >
                    查询参数
                  </FieldLabel>
                  <Input
                    id={`${idPrefix}-test-query`}
                    value={testInput.query}
                    onChange={(event) =>
                      setTestInput((current) => ({
                        ...current,
                        query: event.target.value,
                      }))
                    }
                    placeholder="查询，例如 id=1"
                    className="rounded-md bg-muted/35"
                  />
                </Field>
                <Field className="md:col-span-2">
                  <FieldLabel
                    htmlFor={`${idPrefix}-test-headers`}
                    className="sr-only"
                  >
                    请求头
                  </FieldLabel>
                  <Textarea
                    id={`${idPrefix}-test-headers`}
                    value={testInput.headers}
                    onChange={(event) =>
                      setTestInput((current) => ({
                        ...current,
                        headers: event.target.value,
                      }))
                    }
                    placeholder="每行一个请求头，例如 User-Agent: Mozilla/5.0"
                    className="min-h-[96px] rounded-md bg-muted/35 font-mono text-xs"
                  />
                </Field>
                <Field className="md:col-span-2">
                  <FieldLabel
                    htmlFor={`${idPrefix}-test-body`}
                    className="sr-only"
                  >
                    请求 Body
                  </FieldLabel>
                  <Textarea
                    id={`${idPrefix}-test-body`}
                    value={testInput.body}
                    onChange={(event) =>
                      setTestInput((current) => ({
                        ...current,
                        body: event.target.value,
                      }))
                    }
                    placeholder="Body 内容"
                    className="min-h-[88px] rounded-md bg-muted/35"
                  />
                </Field>
              </FieldGroup>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                className="rounded-md"
                disabled={validating}
                onClick={validateRule}
              >
                {validating ? "验证中..." : "验证规则"}
              </Button>
              {validationFeedback}
              {validationOperationDetails ? (
                <CopyableBlock
                  label="规则校验响应体"
                  value={JSON.stringify(validationOperationDetails, null, 2)}
                  redact
                  defaultOpen={false}
                />
              ) : null}
              <Button
                type="button"
                variant="secondary"
                size="sm"
                className="rounded-md"
                onClick={testRule}
              >
                <TestTube data-icon="inline-start" />
                测试匹配
              </Button>
              {testFeedback}
              {testOperationDetails ? (
                <CopyableBlock
                  label="规则测试响应体"
                  value={JSON.stringify(testOperationDetails, null, 2)}
                  redact
                  defaultOpen={false}
                />
              ) : null}
            </div>
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}
