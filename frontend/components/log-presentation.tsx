"use client"

import { useState, type ReactNode } from "react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { getWAFActionMeta, type WAFActionValue } from "@/lib/console"
import { ChevronDown, ChevronRight } from "@/lib/icons"
import { cn } from "@/lib/utils"

type LogBadgeVariant = "outline" | "secondary" | "destructive"

const sensitiveLogKeyParts = [
  "authorization",
  "cookie",
  "token",
  "secret",
  "password",
  "passwd",
  "pwd",
  "session",
  "api-key",
  "api_key",
  "apikey",
  "auth-token",
  "auth_token",
  "csrf",
  "xsrf",
  "credential",
  "key",
]

const logWAFActionBadgeVariants: Record<WAFActionValue, LogBadgeVariant> = {
  allow: "outline",
  observe: "outline",
  redirect: "outline",
  rate_limit: "secondary",
  challenge: "secondary",
  captcha_challenge: "secondary",
  shield_challenge: "secondary",
  chain_challenge: "secondary",
  intercept: "destructive",
  drop: "destructive",
}

export function redactSensitiveText(text?: string | number | null): string {
  if (text === undefined || text === null || text === "") return "-"
  return String(text)
    .split(/\r?\n/)
    .map(redactSensitiveHeaderLine)
    .join("\n")
    .replace(
      /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|[\s\S])*?-----END [A-Z ]*PRIVATE KEY-----/gi,
      "[redacted-private-key]"
    )
    .replace(
      /(["']?(?:key_pem|private[_-]?key)["']?\s*:\s*["'])(?:\\.|[^"'\\])*(['"])/gi,
      "$1[redacted]$2"
    )
    .replace(
      /((?:password|passwd|pwd|token|secret|session|api[_-]?key|apikey|auth[_-]?token|key_pem|private[_-]?key|authorization|cookie|csrf|xsrf|credential|code|key)["'\s:=]+)([^&\s,"'}]+)/gi,
      "$1[redacted]"
    )
    .replace(/(Bearer\s+)[A-Za-z0-9._~+\/-]+=*/gi, "$1[redacted]")
}

function isSensitiveLogKey(key: string) {
  const lower = key.toLowerCase()
  return sensitiveLogKeyParts.some((part) => lower.includes(part))
}

function redactSensitiveHeaderLine(line: string) {
  const match = line.match(/^([^:\r\n]+):\s*(.*)$/)
  if (!match) return line
  const headerName = match[1].trim().toLowerCase()
  if (!isSensitiveLogKey(headerName)) return line
  return `${match[1]}: [redacted]`
}

export function WAFActionBadge({ action }: { action?: string | null }) {
  if (!action) return <span className="text-muted-foreground">-</span>

  const meta = getWAFActionMeta(action)
  return (
    <Badge
      variant={logWAFActionBadgeVariants[meta.value]}
      className="rounded-md text-xs"
    >
      {meta.shortLabel}
    </Badge>
  )
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
    <Button type="button" variant="ghost" size="xs" onClick={handleCopy}>
      {copied ? "已复制" : "复制"}
    </Button>
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
    <div className={cn("min-w-0 rounded-lg border bg-muted/35 p-3", className)}>
      <div className="flex items-center justify-between gap-2 text-[11px] font-medium tracking-wider text-muted-foreground uppercase">
        <span>{label}</span>
        {copyText && <CopyButton text={copyText} />}
      </div>
      <div
        className={cn(
          "mt-1 min-w-0 text-sm font-medium break-all text-foreground",
          mono && "font-mono text-xs"
        )}
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
  contentClassName = "max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-background p-2 text-xs text-foreground",
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
    <div className={cn("rounded-lg border bg-muted/35 p-3", className)}>
      <div className="flex items-center justify-between gap-2 text-[11px] font-medium tracking-wider text-muted-foreground uppercase">
        <Button
          type="button"
          variant="link"
          size="xs"
          className="min-w-0 justify-start truncate px-0 text-left text-[11px] tracking-wider uppercase"
          onClick={() => setOpen((value) => !value)}
        >
          {open ? (
            <ChevronDown data-icon="inline-start" />
          ) : (
            <ChevronRight data-icon="inline-start" />
          )}
          {label}
        </Button>
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
      className={cn("block min-w-0 truncate", mono && "font-mono", className)}
      title={text}
    >
      {text}
    </span>
  )
}
