"use client"

import { useState, type ReactNode } from "react"

export function redactSensitiveText(text?: string | number | null): string {
  if (text === undefined || text === null || text === "") return "-"
  return String(text)
    .replace(
      /((?:password|passwd|pwd|token|secret|session|api[_-]?key|apikey|authorization|cookie|csrf|xsrf)["'\s:=]+)([^&\s,"'}]+)/gi,
      "$1[redacted]"
    )
    .replace(/(Bearer\s+)[A-Za-z0-9._~+\/-]+=*/gi, "$1[redacted]")
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    if (!text || text === "-") return
    await navigator.clipboard.writeText(text)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1200)
  }

  return (
    <button
      type="button"
      className="rounded px-1.5 py-0.5 text-[10px] font-medium text-slate-400 hover:bg-slate-100 hover:text-slate-700"
      onClick={handleCopy}
    >
      {copied ? "已复制" : "复制"}
    </button>
  )
}

export function DetailField({
  label,
  value,
  mono = false,
  className = "",
  copyText,
}: {
  label: string
  value: ReactNode
  mono?: boolean
  className?: string
  copyText?: string
}) {
  return (
    <div
      className={`min-w-0 rounded-lg border border-slate-100 bg-slate-50 p-3 ${className}`}
    >
      <div className="flex items-center justify-between gap-2 text-[11px] font-medium tracking-wider text-slate-400 uppercase">
        <span>{label}</span>
        {copyText && <CopyButton text={copyText} />}
      </div>
      <div
        className={`mt-1 min-w-0 text-sm font-medium break-all text-slate-900 ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </div>
    </div>
  )
}

export function CopyableBlock({
  label,
  value,
  className = "",
  contentClassName = "max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-white p-2 text-xs text-slate-700",
  as = "pre",
  redact = false,
  defaultOpen = true,
}: {
  label: string
  value?: string | number | null
  className?: string
  contentClassName?: string
  as?: "pre" | "code" | "div"
  redact?: boolean
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  const rawText =
    value === undefined || value === null || value === "" ? "-" : String(value)
  const text = redact ? redactSensitiveText(rawText) : rawText
  const Content = as

  return (
    <div
      className={`rounded-lg border border-slate-100 bg-slate-50 p-3 ${className}`}
    >
      <div className="flex items-center justify-between gap-2 text-[11px] font-medium tracking-wider text-slate-400 uppercase">
        <button
          type="button"
          className="min-w-0 truncate text-left hover:text-slate-600"
          onClick={() => setOpen((value) => !value)}
        >
          {label} {open ? "▾" : "▸"}
        </button>
        <CopyButton text={text} />
      </div>
      {open && (
        <Content className={`mt-1 block ${contentClassName}`}>{text}</Content>
      )}
    </div>
  )
}

export function TruncatedCell({
  value,
  className = "",
  mono = false,
}: {
  value?: string | number | null
  className?: string
  mono?: boolean
}) {
  const text =
    value === undefined || value === null || value === "" ? "-" : String(value)
  return (
    <span
      className={`block min-w-0 truncate ${mono ? "font-mono" : ""} ${className}`}
      title={text}
    >
      {text}
    </span>
  )
}
