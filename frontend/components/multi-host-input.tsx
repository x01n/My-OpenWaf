"use client"

import { useState, type KeyboardEvent } from "react"
import { Globe, X } from "@/lib/icons"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

interface MultiHostInputProps {
  hosts: string[]
  onChange: (hosts: string[]) => void
  placeholder?: string
}

const HOST_PATTERN =
  /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/

function isValidHost(value: string): boolean {
  if (!value) return false
  if (value.length > 253) return false
  return HOST_PATTERN.test(value)
}

/**
 * MultiHostInput — 多域名标签输入组件。
 * 支持精确域名和泛域名（*.example.com），按 Enter / Tab / 逗号确认输入。
 */
export function MultiHostInput({
  hosts,
  onChange,
  placeholder,
}: MultiHostInputProps) {
  const [draft, setDraft] = useState("")
  const [error, setError] = useState("")

  function commit(raw: string) {
    const value = raw.trim().toLowerCase()
    if (!value) return
    if (!isValidHost(value)) {
      setError(`格式无效：${value}`)
      return
    }
    if (hosts.includes(value)) {
      setError("该域名已添加")
      return
    }
    setError("")
    onChange([...hosts, value])
    setDraft("")
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === "Tab" || e.key === ",") {
      e.preventDefault()
      commit(draft)
    }
    if (e.key === "Backspace" && draft === "" && hosts.length > 0) {
      onChange(hosts.slice(0, -1))
    }
  }

  function handlePaste(e: React.ClipboardEvent<HTMLInputElement>) {
    e.preventDefault()
    const text = e.clipboardData.getData("text")
    const parts = text.split(/[,\s\n]+/).filter(Boolean)
    const newHosts = [...hosts]
    for (const p of parts) {
      const v = p.trim().toLowerCase()
      if (v && isValidHost(v) && !newHosts.includes(v)) {
        newHosts.push(v)
      }
    }
    onChange(newHosts)
    setDraft("")
  }

  function remove(index: number) {
    onChange(hosts.filter((_, i) => i !== index))
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-input bg-background px-3 py-2 focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50">
        <Globe className="size-4 shrink-0 text-muted-foreground" />
        {hosts.map((h, i) => (
          <Badge key={h} variant="secondary" className="rounded-md font-medium">
            {h.startsWith("*.") && (
              <span className="text-[10px] text-muted-foreground">泛</span>
            )}
            {h}
            <Button
              type="button"
              variant="ghost"
              size="icon-xs"
              className="-me-1 rounded-full"
              aria-label={`移除域名 ${h}`}
              onClick={() => remove(i)}
            >
              <X data-icon="inline-start" />
            </Button>
          </Badge>
        ))}
        <Input
          value={draft}
          onChange={(e) => {
            setError("")
            const v = e.target.value
            if (v.endsWith(",")) {
              commit(v.slice(0, -1))
            } else {
              setDraft(v)
            }
          }}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          onBlur={() => {
            if (draft.trim()) commit(draft)
          }}
          placeholder={
            hosts.length === 0
              ? placeholder || "example.com 或 *.example.com"
              : "继续添加…"
          }
          className="min-w-[140px] flex-1 border-0 bg-transparent px-0 text-sm shadow-none focus-visible:ring-0"
        />
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}
      {hosts.length === 0 && (
        <p className="text-xs text-muted-foreground">
          按 Enter 或逗号确认。支持泛域名，如{" "}
          <code className="rounded bg-muted px-1">*.example.com</code>
        </p>
      )}
    </div>
  )
}
