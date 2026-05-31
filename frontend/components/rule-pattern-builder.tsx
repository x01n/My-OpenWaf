"use client"

import { useState, useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Label } from "@/components/ui/label"
import { Card, CardContent } from "@/components/ui/card"
import { Plus, Trash2, Braces } from "lucide-react"

// All supported rule kinds with human-readable labels.
const RULE_KINDS = [
  {
    value: "block_ip",
    label: "封禁 IP / CIDR",
    placeholder: "192.168.1.0/24",
    group: "ACL",
  },
  {
    value: "allow_ip",
    label: "放行 IP / CIDR",
    placeholder: "10.0.0.0/8",
    group: "ACL",
  },
  {
    value: "block_path",
    label: "路径前缀匹配",
    placeholder: "/admin",
    group: "路径",
  },
  {
    value: "allow_path",
    label: "放行路径前缀",
    placeholder: "/health",
    group: "路径",
  },
  {
    value: "block_path_exact",
    label: "路径精确匹配",
    placeholder: "/.env",
    group: "路径",
  },
  {
    value: "block_path_regex",
    label: "路径正则匹配",
    placeholder: "(?i)/admin.*\\.php",
    group: "路径",
  },
  {
    value: "allow_path_regex",
    label: "放行路径正则",
    placeholder: "(?i)/api/public/.*",
    group: "路径",
  },
  {
    value: "block_query_contains",
    label: "查询参数包含",
    placeholder: "union+select",
    group: "查询",
  },
  {
    value: "block_query_regex",
    label: "查询参数正则",
    placeholder: "(?i)union\\s+select",
    group: "查询",
  },
  {
    value: "block_header",
    label: "请求头包含",
    placeholder: "User-Agent:BadBot",
    group: "请求头",
  },
  {
    value: "allow_header",
    label: "放行请求头",
    placeholder: "X-API-Key:secret",
    group: "请求头",
  },
  {
    value: "block_header_regex",
    label: "请求头正则",
    placeholder: "User-Agent:(?i)bot|crawl",
    group: "请求头",
  },
  {
    value: "block_method",
    label: "HTTP 方法",
    placeholder: "DELETE",
    group: "协议",
  },
  {
    value: "block_content_type",
    label: "Content-Type",
    placeholder: "application/xml",
    group: "协议",
  },
  {
    value: "block_body_contains",
    label: "Body包含",
    placeholder: "eval(",
    group: "Body",
  },
  {
    value: "block_body_regex",
    label: "Body正则",
    placeholder: "(?i)<script",
    group: "Body",
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

function newId() {
  return Math.random().toString(36).slice(2, 9)
}

interface RulePatternBuilderProps {
  value: string
  onChange: (pattern: string) => void
}

/**
 * Parses a DSL pattern string back into the visual builder state.
 */
function parsePattern(raw: string): {
  mode: "simple" | "compound"
  condition?: Condition
  compound?: CompoundGroup
} {
  const trimmed = raw.trim()
  if (!trimmed) {
    return {
      mode: "simple",
      condition: { id: newId(), kind: "block_ip", arg: "" },
    }
  }

  // Try JSON compound
  if (trimmed.startsWith("{")) {
    try {
      const obj = JSON.parse(trimmed)
      if (obj.op && obj.children) {
        const children = (obj.children as { kind: string; arg: string }[]).map(
          (c) => ({
            id: newId(),
            kind: c.kind || "",
            arg: c.arg || "",
          })
        )
        return { mode: "compound", compound: { op: obj.op, children } }
      }
    } catch {
      // Fall through to simple
    }
  }

  // Simple pattern: kind:arg
  const colonIdx = trimmed.indexOf(":")
  if (colonIdx > 0) {
    const kind = trimmed.slice(0, colonIdx)
    const arg = trimmed.slice(colonIdx + 1)
    if (RULE_KINDS.some((k) => k.value === kind)) {
      return { mode: "simple", condition: { id: newId(), kind, arg } }
    }
  }

  return { mode: "simple", condition: { id: newId(), kind: "", arg: trimmed } }
}

function buildDSL(
  mode: "simple" | "compound",
  condition: Condition,
  compound: CompoundGroup
): string {
  if (mode === "simple") {
    if (!condition.kind || !condition.arg) return ""
    return `${condition.kind}:${condition.arg}`
  }

  // Compound
  const validChildren = compound.children.filter((c) => c.kind && c.arg)
  if (validChildren.length === 0) return ""
  if (validChildren.length === 1 && compound.op !== "not") {
    return `${validChildren[0].kind}:${validChildren[0].arg}`
  }

  return JSON.stringify({
    op: compound.op,
    children: validChildren.map((c) => ({ kind: c.kind, arg: c.arg })),
  })
}

export function RulePatternBuilder({
  value,
  onChange,
}: RulePatternBuilderProps) {
  const parsed = parsePattern(value)
  const [mode, setMode] = useState<"simple" | "compound">(parsed.mode)
  const [condition, setCondition] = useState<Condition>(
    parsed.condition || { id: newId(), kind: "block_ip", arg: "" }
  )
  const [compound, setCompound] = useState<CompoundGroup>(
    parsed.compound || {
      op: "and",
      children: [{ id: newId(), kind: "block_ip", arg: "" }],
    }
  )

  const emitChange = useCallback(
    (m: "simple" | "compound", c: Condition, g: CompoundGroup) => {
      const dsl = buildDSL(m, c, g)
      onChange(dsl)
    },
    [onChange]
  )

  const handleSimpleKindChange = (kind: string) => {
    const next = { ...condition, kind }
    setCondition(next)
    emitChange("simple", next, compound)
  }

  const handleSimpleArgChange = (arg: string) => {
    const next = { ...condition, arg }
    setCondition(next)
    emitChange("simple", next, compound)
  }

  const toggleMode = () => {
    const nextMode = mode === "simple" ? "compound" : "simple"
    setMode(nextMode)
    if (nextMode === "compound" && compound.children.length === 0) {
      const g = {
        ...compound,
        children: [{ id: newId(), kind: condition.kind, arg: condition.arg }],
      }
      setCompound(g)
      emitChange(nextMode, condition, g)
    } else {
      emitChange(nextMode, condition, compound)
    }
  }

  const kindMeta = (kind: string) => RULE_KINDS.find((k) => k.value === kind)

  if (mode === "simple") {
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <div className="grid flex-1 grid-cols-[180px_1fr] gap-2">
            <Select
              value={condition.kind}
              onValueChange={handleSimpleKindChange}
            >
              <SelectTrigger>
                <SelectValue placeholder="匹配类型" />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(
                  RULE_KINDS.reduce(
                    (acc, k) => {
                      if (!acc[k.group]) acc[k.group] = []
                      acc[k.group].push(k)
                      return acc
                    },
                    {} as Record<string, (typeof RULE_KINDS)[number][]>
                  )
                ).map(([group, items]) => (
                  <div key={group}>
                    <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">
                      {group}
                    </div>
                    {items.map((k) => (
                      <SelectItem key={k.value} value={k.value}>
                        {k.label}
                      </SelectItem>
                    ))}
                  </div>
                ))}
              </SelectContent>
            </Select>
            <Input
              value={condition.arg}
              onChange={(e) => handleSimpleArgChange(e.target.value)}
              placeholder={kindMeta(condition.kind)?.placeholder || "参数值"}
            />
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={toggleMode}
            title="切换到组合条件"
          >
            <Braces className="h-4 w-4" />
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          DSL:{" "}
          <code className="rounded bg-muted px-1">
            {buildDSL("simple", condition, compound) || "..."}
          </code>
        </p>
      </div>
    )
  }

  // Compound mode
  const updateChild = (id: string, field: "kind" | "arg", val: string) => {
    const children = compound.children.map((c) =>
      c.id === id ? { ...c, [field]: val } : c
    )
    const g = { ...compound, children }
    setCompound(g)
    emitChange("compound", condition, g)
  }

  const addChild = () => {
    const children = [
      ...compound.children,
      { id: newId(), kind: "block_ip", arg: "" },
    ]
    const g = { ...compound, children }
    setCompound(g)
    emitChange("compound", condition, g)
  }

  const removeChild = (id: string) => {
    const children = compound.children.filter((c) => c.id !== id)
    const g = { ...compound, children }
    setCompound(g)
    emitChange("compound", condition, g)
  }

  const setOp = (op: "and" | "or" | "not") => {
    const g = { ...compound, op }
    setCompound(g)
    emitChange("compound", condition, g)
  }

  return (
    <Card className="border-dashed">
      <CardContent className="space-y-3 p-3">
        <div className="flex items-center gap-2">
          <Label className="text-xs font-medium">组合条件</Label>
          <Select
            value={compound.op}
            onValueChange={(v) => setOp(v as "and" | "or" | "not")}
          >
            <SelectTrigger className="h-7 w-24 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="and">AND (全部)</SelectItem>
              <SelectItem value="or">OR (任一)</SelectItem>
              <SelectItem value="not">NOT (取反)</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex-1" />
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={toggleMode}
            className="text-xs"
          >
            切换简单模式
          </Button>
        </div>

        {compound.children.map((child) => (
          <div key={child.id} className="flex items-center gap-2">
            <Select
              value={child.kind}
              onValueChange={(v) => updateChild(child.id, "kind", v)}
            >
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="匹配类型" />
              </SelectTrigger>
              <SelectContent>
                {RULE_KINDS.map((k) => (
                  <SelectItem key={k.value} value={k.value}>
                    {k.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              className="flex-1"
              value={child.arg}
              onChange={(e) => updateChild(child.id, "arg", e.target.value)}
              placeholder={kindMeta(child.kind)?.placeholder || "参数值"}
            />
            {compound.children.length > 1 && (
              <Button
                type="button"
                variant="ghost"
                size="icon"
                onClick={() => removeChild(child.id)}
              >
                <Trash2 className="h-4 w-4 text-destructive" />
              </Button>
            )}
          </div>
        ))}

        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={addChild}
          className="w-full"
        >
          <Plus className="mr-1 h-3 w-3" /> 添加条件
        </Button>

        <p className="text-xs text-muted-foreground">
          DSL:{" "}
          <code className="rounded bg-muted px-1 text-[10px] break-all">
            {buildDSL("compound", condition, compound) || "..."}
          </code>
        </p>
      </CardContent>
    </Card>
  )
}
