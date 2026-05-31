"use client"

import { useEffect, useMemo, useState } from "react"
import {
  AlertCircle,
  CheckCircle2,
  Code,
  Eye,
  Plus,
  TestTube,
  Trash2,
} from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { api } from "@/lib/api"

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

function newId() {
  return Math.random().toString(36).slice(2, 11)
}

function parsePattern(raw: string): {
  mode: "simple" | "compound"
  condition: Condition
  compound: CompoundGroup
} {
  const trimmed = raw.trim()
  const fallbackCondition = { id: newId(), kind: "block_ip", arg: "" }
  const fallbackCompound = {
    op: "and" as const,
    children: [{ id: newId(), kind: "block_ip", arg: "" }],
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
              ? obj.children.map((child) => ({
                  id: newId(),
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
        condition: { id: newId(), kind, arg },
        compound: fallbackCompound,
      }
    }
  }

  return {
    mode: "simple",
    condition: { id: newId(), kind: "", arg: trimmed },
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

  const [mode, setMode] = useState<"simple" | "compound">("simple")
  const [condition, setCondition] = useState<Condition>({
    id: newId(),
    kind: "block_ip",
    arg: "",
  })
  const [compound, setCompound] = useState<CompoundGroup>({
    op: "and",
    children: [{ id: newId(), kind: "block_ip", arg: "" }],
  })
  const [advancedMode, setAdvancedMode] = useState(false)
  const [rawDSL, setRawDSL] = useState(value)
  const [testInput, setTestInput] = useState({
    path: "/admin",
    method: "GET",
    ip: "192.168.1.100",
    headers: "User-Agent: Mozilla/5.0",
    query: "",
    body: "",
  })
  const [testResult, setTestResult] = useState<{
    match: boolean
    message: string
  } | null>(null)
  const [validating, setValidating] = useState(false)

  useEffect(() => {
    const parsed = parsePattern(value)
    setMode(parsed.mode)
    setCondition(parsed.condition)
    setCompound(parsed.compound)
    setRawDSL(value)
  }, [value])

  useEffect(() => {
    if (!advancedMode) return
    setRawDSL(buildDSL(mode, condition, compound))
  }, [advancedMode, mode, condition, compound])

  function emit(
    nextMode: "simple" | "compound",
    nextCondition: Condition,
    nextCompound: CompoundGroup
  ) {
    const dsl = buildDSL(nextMode, nextCondition, nextCompound)
    setRawDSL(dsl)
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
        children: [{ id: newId(), kind: condition.kind, arg: condition.arg }],
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
        { id: newId(), kind: "block_ip", arg: "" },
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
        : [{ id: newId(), kind: "block_ip", arg: "" }],
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

  async function validateRule() {
    if (!rawDSL.trim()) {
      toast.error("规则不能为空")
      return
    }
    setValidating(true)
    try {
      await api("/api/v1/rules/validate", {
        method: "POST",
        body: JSON.stringify({ pattern: rawDSL }),
      })
      toast.success("规则语法正确")
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "验证失败")
    } finally {
      setValidating(false)
    }
  }

  function testRule() {
    const dsl = rawDSL.trim()
    if (!dsl) {
      setTestResult({ match: false, message: "规则为空" })
      return
    }

    try {
      if (dsl.startsWith("{")) {
        setTestResult({
          match: false,
          message: "复合规则的精确测试依赖后端验证接口。",
        })
        return
      }

      const [kind, arg] = dsl.split(":", 2)
      let match = false
      let message = "无效规则"

      if (kind.includes("_ip")) {
        match = testInput.ip.includes(arg) || arg.includes(testInput.ip)
        message = match
          ? `IP ${testInput.ip} 匹配规则`
          : `IP ${testInput.ip} 不匹配`
      } else if (kind.includes("_path")) {
        if (kind.includes("_exact")) {
          match = testInput.path === arg
        } else if (kind.includes("_regex")) {
          match = new RegExp(arg).test(testInput.path)
        } else {
          match = testInput.path.startsWith(arg)
        }
        message = match
          ? `路径 ${testInput.path} 匹配规则`
          : `路径 ${testInput.path} 不匹配`
      } else if (kind.includes("_method")) {
        match = testInput.method.toUpperCase() === arg.toUpperCase()
        message = match
          ? `方法 ${testInput.method} 匹配规则`
          : `方法 ${testInput.method} 不匹配`
      } else if (kind.includes("_header")) {
        match = kind.includes("_regex")
          ? new RegExp(arg.split(":")[1] || arg).test(testInput.headers)
          : testInput.headers.toLowerCase().includes(arg.toLowerCase())
        message = match ? "请求头匹配规则" : "请求头不匹配"
      } else if (kind.includes("_query")) {
        match = kind.includes("_regex")
          ? new RegExp(arg).test(testInput.query)
          : testInput.query.includes(arg)
        message = match ? "查询参数匹配规则" : "查询参数不匹配"
      } else if (kind.includes("_body")) {
        match = kind.includes("_regex")
          ? new RegExp(arg).test(testInput.body)
          : testInput.body.includes(arg)
        message = match ? "Body 匹配规则" : "Body 不匹配"
      }

      setTestResult({ match, message })
    } catch (error) {
      setTestResult({
        match: false,
        message: error instanceof Error ? error.message : "测试失败",
      })
    }
  }

  const simplePreview = buildDSL("simple", condition, compound)
  const compoundPreview = buildDSL("compound", condition, compound)

  return (
    <div className="space-y-5 rounded-lg border border-slate-200 bg-slate-50/80 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-slate-900">规则构建器</div>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            支持简单 DSL、复合 JSON 与快速测试，用于生成真实 pattern 字段。
          </p>
        </div>
        <Button
          type="button"
          variant={advancedMode ? "default" : "outline"}
          size="sm"
          className={
            advancedMode
              ? "rounded-md bg-teal-500 text-white hover:bg-teal-600"
              : "rounded-md"
          }
          onClick={() => setAdvancedMode((current) => !current)}
        >
          <Code className="mr-1 h-3 w-3" />
          {advancedMode ? "可视化模式" : "高级模式"}
        </Button>
      </div>

      {advancedMode ? (
        <div className="space-y-4">
          <div className="space-y-2">
            <Label className="text-xs">DSL 规则</Label>
            <Textarea
              value={rawDSL}
              onChange={(event) => {
                setRawDSL(event.target.value)
                onChange(event.target.value)
              }}
              placeholder='{"op":"and","children":[{"kind":"block_ip","arg":"1.2.3.0/24"}]}'
              className="min-h-[160px] rounded-lg border-slate-200 bg-white font-mono text-xs"
            />
          </div>

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
                setMode(parsed.mode)
                setCondition(parsed.condition)
                setCompound(parsed.compound)
                setAdvancedMode(false)
              }}
            >
              切换到可视化
            </Button>
          </div>

          <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-xs leading-6 text-amber-900">
            简单规则格式为 <code>kind:arg</code>，复合规则格式为 JSON。示例：
            <code>block_ip:192.168.1.0/24</code>。
          </div>
        </div>
      ) : (
        <Tabs value="visual" className="w-full">
          <TabsList className="hidden">
            <TabsTrigger value="visual">可视化</TabsTrigger>
          </TabsList>
          <TabsContent value="visual" className="space-y-5">
            <div className="inline-flex rounded-full border border-slate-200 bg-white p-1">
              <button
                type="button"
                onClick={() => switchVisualMode("simple")}
                className={
                  mode === "simple"
                    ? "rounded-full bg-slate-950 px-4 py-2 text-xs font-medium text-white"
                    : "rounded-full px-4 py-2 text-xs font-medium text-slate-500"
                }
              >
                简单条件
              </button>
              <button
                type="button"
                onClick={() => switchVisualMode("compound")}
                className={
                  mode === "compound"
                    ? "rounded-full bg-slate-950 px-4 py-2 text-xs font-medium text-white"
                    : "rounded-full px-4 py-2 text-xs font-medium text-slate-500"
                }
              >
                复合条件
              </button>
            </div>

            {mode === "simple" ? (
              <div className="space-y-4">
                <div className="grid gap-4 md:grid-cols-[180px_1fr]">
                  <div className="space-y-2">
                    <Label className="text-xs">匹配类型</Label>
                    <Select
                      value={condition.kind}
                      onValueChange={setSimpleKind}
                    >
                      <SelectTrigger className="rounded-md border-slate-200 bg-white">
                        <SelectValue placeholder="选择匹配类型" />
                      </SelectTrigger>
                      <SelectContent>
                        {groupedKinds.map(([group, items]) => (
                          <div key={group}>
                            <div className="px-2 py-1.5 text-xs font-semibold text-slate-400">
                              {group}
                            </div>
                            {items.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </div>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs">参数值</Label>
                    <Input
                      value={condition.arg}
                      onChange={(event) => setSimpleArg(event.target.value)}
                      placeholder={
                        RULE_KINDS.find((item) => item.value === condition.kind)
                          ?.placeholder || "输入匹配参数"
                      }
                      className="rounded-md border-slate-200 bg-white"
                    />
                  </div>
                </div>

                <div className="rounded-lg border border-slate-200 bg-white px-4 py-3 text-xs leading-6 text-slate-600">
                  <div className="mb-1 flex items-center gap-2 font-medium text-slate-900">
                    <Eye className="h-3.5 w-3.5" /> DSL 预览
                  </div>
                  <code className="text-[11px] break-all">
                    {simplePreview || "未生成规则"}
                  </code>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                  <div className="flex items-center gap-2">
                    <Label className="text-xs">逻辑运算</Label>
                    <Select
                      value={compound.op}
                      onValueChange={(value) =>
                        updateCompoundOp(value as "and" | "or" | "not")
                      }
                    >
                      <SelectTrigger className="w-[140px] rounded-md border-slate-200 bg-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="and">AND（且）</SelectItem>
                        <SelectItem value="or">OR（或）</SelectItem>
                        <SelectItem value="not">NOT（非）</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="rounded-md"
                    onClick={addChild}
                  >
                    <Plus className="mr-1 h-3.5 w-3.5" /> 添加条件
                  </Button>
                </div>

                <div className="space-y-3">
                  {compound.children.map((child, index) => (
                    <div
                      key={child.id}
                      className="space-y-2 rounded-lg border border-slate-200 bg-white p-4"
                    >
                      {index > 0 ? (
                        <div className="text-[11px] font-semibold tracking-[0.18em] text-slate-400 uppercase">
                          {compound.op}
                        </div>
                      ) : null}
                      <div className="grid gap-3 md:grid-cols-[180px_1fr_auto]">
                        <Select
                          value={child.kind}
                          onValueChange={(nextValue) =>
                            updateChild(child.id, "kind", nextValue)
                          }
                        >
                          <SelectTrigger className="rounded-md border-slate-200 bg-slate-50">
                            <SelectValue placeholder="匹配类型" />
                          </SelectTrigger>
                          <SelectContent>
                            {RULE_KINDS.map((item) => (
                              <SelectItem key={item.value} value={item.value}>
                                {item.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Input
                          value={child.arg}
                          onChange={(event) =>
                            updateChild(child.id, "arg", event.target.value)
                          }
                          placeholder={
                            RULE_KINDS.find((item) => item.value === child.kind)
                              ?.placeholder || "输入参数"
                          }
                          className="rounded-md border-slate-200 bg-slate-50"
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon-sm"
                          className="rounded-md text-rose-600 hover:bg-rose-50 hover:text-rose-700"
                          onClick={() => removeChild(child.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="rounded-lg border border-slate-200 bg-white px-4 py-3 text-xs leading-6 text-slate-600">
                  <div className="mb-1 flex items-center gap-2 font-medium text-slate-900">
                    <Eye className="h-3.5 w-3.5" /> DSL 预览
                  </div>
                  <code className="text-[11px] break-all">
                    {compoundPreview || "未生成规则"}
                  </code>
                </div>
              </div>
            )}

            <div className="space-y-4 rounded-lg border border-slate-200 bg-white p-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <TestTube className="h-4 w-4" /> 规则测试
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <Input
                  value={testInput.path}
                  onChange={(event) =>
                    setTestInput((current) => ({
                      ...current,
                      path: event.target.value,
                    }))
                  }
                  placeholder="路径，例如 /admin"
                  className="rounded-md border-slate-200 bg-slate-50"
                />
                <Input
                  value={testInput.method}
                  onChange={(event) =>
                    setTestInput((current) => ({
                      ...current,
                      method: event.target.value,
                    }))
                  }
                  placeholder="方法，例如 GET"
                  className="rounded-md border-slate-200 bg-slate-50"
                />
                <Input
                  value={testInput.ip}
                  onChange={(event) =>
                    setTestInput((current) => ({
                      ...current,
                      ip: event.target.value,
                    }))
                  }
                  placeholder="IP，例如 192.168.1.100"
                  className="rounded-md border-slate-200 bg-slate-50"
                />
                <Input
                  value={testInput.query}
                  onChange={(event) =>
                    setTestInput((current) => ({
                      ...current,
                      query: event.target.value,
                    }))
                  }
                  placeholder="查询，例如 id=1"
                  className="rounded-md border-slate-200 bg-slate-50"
                />
                <Input
                  value={testInput.headers}
                  onChange={(event) =>
                    setTestInput((current) => ({
                      ...current,
                      headers: event.target.value,
                    }))
                  }
                  placeholder="请求头，例如 User-Agent: Mozilla/5.0"
                  className="rounded-md border-slate-200 bg-slate-50 md:col-span-2"
                />
                <Textarea
                  value={testInput.body}
                  onChange={(event) =>
                    setTestInput((current) => ({
                      ...current,
                      body: event.target.value,
                    }))
                  }
                  placeholder="Body 内容"
                  className="min-h-[88px] rounded-md border-slate-200 bg-slate-50 md:col-span-2"
                />
              </div>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                className="rounded-md"
                onClick={testRule}
              >
                <TestTube className="mr-1 h-3.5 w-3.5" /> 测试匹配
              </Button>
              {testResult ? (
                <div
                  className={
                    testResult.match
                      ? "flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs text-emerald-900"
                      : "flex items-center gap-2 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-xs text-rose-900"
                  }
                >
                  {testResult.match ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                  ) : (
                    <AlertCircle className="h-4 w-4 shrink-0" />
                  )}
                  <span>{testResult.message}</span>
                </div>
              ) : null}
            </div>
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}
