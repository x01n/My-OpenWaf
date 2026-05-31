"use client"

import { useState, type KeyboardEvent } from "react"
import { Globe, X } from "lucide-react"
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
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-cyan-300 bg-white px-3 py-2 focus-within:ring-2 focus-within:ring-cyan-200">
        <Globe className="h-4 w-4 shrink-0 text-slate-400" />
        {hosts.map((h, i) => (
          <span
            key={h}
            className="inline-flex items-center gap-1 rounded-md border border-cyan-200 bg-cyan-50 px-2 py-0.5 text-sm font-medium text-cyan-700"
          >
            {h.startsWith("*.") && (
              <span className="text-xs text-cyan-400">泛</span>
            )}
            {h}
            <button
              type="button"
              onClick={() => remove(i)}
              className="ml-0.5 rounded-full p-0.5 text-cyan-400 transition-colors hover:bg-cyan-100 hover:text-cyan-600"
            >
              <X className="h-3 w-3" />
            </button>
          </span>
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
      {error && <p className="text-xs text-red-500">{error}</p>}
      {hosts.length === 0 && (
        <p className="text-xs text-slate-400">
          按 Enter 或逗号确认。支持泛域名，如{" "}
          <code className="rounded bg-slate-100 px-1">*.example.com</code>
        </p>
      )}
    </div>
  )
}
