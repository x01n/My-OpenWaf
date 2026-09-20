"use client"

import type { ReactNode } from "react"
import { ScrollArea } from "@/components/ui/scroll-area"

/** 报文区渲染字符上限，限制超大日志对布局与语法高亮的影响。 */
export const MAX_MESSAGE_CHARS = 16384

/** 敏感值统一占位符。 */
export const REDACTED = "[redacted]"

/**
 * 与后端日志脱敏规则保持一致的敏感字段片段。
 * 历史日志或旁路写入的数据也必须在前端展示前二次脱敏。
 */
const SENSITIVE_KEY_PARTS = [
  "authorization",
  "cookie",
  "token",
  "secret",
  "password",
  "passwd",
  "pwd",
  "session",
  "api-key",
  "apikey",
  "csrf",
  "credential",
  "key",
]

/** 单条 HTTP 头部。 */
export interface HeaderEntry {
  name: string
  value: string
  sensitive: boolean
}

/** 判断字段名称是否包含敏感片段。 */
export function isSensitiveFieldName(name: string): boolean {
  const lower = name.toLowerCase()
  return SENSITIVE_KEY_PARTS.some((part) => lower.includes(part))
}

/**
 * 解析后端持久化的 JSON 头部，兼容早期换行文本格式，并按 header_order 还原顺序。
 */
export function parseHeaderEntries(
  raw?: string,
  order?: string
): HeaderEntry[] {
  const text = (raw || "").trim()
  if (!text) return []

  if (text.startsWith("{")) {
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>
      const entries: HeaderEntry[] = []
      const consumed = new Set<string>()

      const push = (key: string) => {
        const value = parsed[key]
        const values = Array.isArray(value) ? value : [value]
        for (const item of values) {
          entries.push({
            name: key,
            value: item == null ? "" : String(item),
            sensitive: isSensitiveFieldName(key),
          })
        }
      }

      for (const rawName of (order || "").split(",")) {
        const name = rawName.trim()
        if (!name || consumed.has(name)) continue
        if (Object.prototype.hasOwnProperty.call(parsed, name)) {
          consumed.add(name)
          push(name)
        }
      }
      for (const key of Object.keys(parsed)) {
        if (consumed.has(key)) continue
        consumed.add(key)
        push(key)
      }
      return entries
    } catch {
      // 非法 JSON 继续按早期文本格式解析。
    }
  }

  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const idx = line.indexOf(":")
      const name = idx > 0 ? line.slice(0, idx) : line
      const value = idx > 0 ? line.slice(idx + 1).trim() : ""
      return { name, value, sensitive: isSensitiveFieldName(name) }
    })
}

/** 获取安全的头部展示值。 */
export function headerDisplayValue(entry: HeaderEntry): string {
  return entry.sensitive ? REDACTED : entry.value
}

/** 将查询参数中的敏感字段值替换为占位符。 */
export function redactQueryString(raw?: string): string {
  if (!raw) return ""
  const params = new URLSearchParams(raw)
  for (const key of Array.from(params.keys())) {
    if (!isSensitiveFieldName(key)) continue
    params.delete(key)
    params.append(key, REDACTED)
  }
  return params.toString()
}

/** 递归脱敏 JSON 请求体中的敏感字段。 */
function redactJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactJsonValue)
  if (!value || typeof value !== "object") return value

  const result: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value)) {
    result[key] = isSensitiveFieldName(key) ? REDACTED : redactJsonValue(item)
  }
  return result
}

/** 对无法按 JSON 或表单解析的文本执行保守的键值脱敏。 */
function redactTextAssignments(raw: string): string {
  const quoted = raw.replace(
    /(["'])([^"']+)\1\s*([:=])\s*(["'])(.*?)\4/g,
    (match, keyQuote, key, separator, valueQuote) =>
      isSensitiveFieldName(String(key))
        ? `${keyQuote}${key}${keyQuote}${separator}${valueQuote}${REDACTED}${valueQuote}`
        : match
  )

  return quoted.replace(
    /(^|[&\s])([^&\s=:{},]+)\s*=\s*([^&\r\n]*)/gm,
    (match, prefix, key) =>
      isSensitiveFieldName(String(key))
        ? `${prefix}${key}=${REDACTED}`
        : match
  )
}

/**
 * 按 Content-Type 脱敏请求体预览；解析失败时退回文本键值脱敏。
 */
export function redactBodyPreview(raw?: string, headersRaw?: string): string {
  if (!raw) return ""
  const contentType = parseHeaderEntries(headersRaw).find(
    (entry) => entry.name.toLowerCase() === "content-type"
  )?.value

  if (contentType?.toLowerCase().includes("application/x-www-form-urlencoded")) {
    const params = new URLSearchParams(raw)
    for (const key of Array.from(params.keys())) {
      if (!isSensitiveFieldName(key)) continue
      params.delete(key)
      params.append(key, REDACTED)
    }
    return params.toString()
  }

  if (
    contentType?.toLowerCase().includes("application/json") ||
    raw.trimStart().startsWith("{") ||
    raw.trimStart().startsWith("[")
  ) {
    try {
      return JSON.stringify(redactJsonValue(JSON.parse(raw)), null, 2)
    } catch {
      // 截断或非法 JSON 继续走文本脱敏，避免原值直出。
    }
  }

  return redactTextAssignments(raw)
}

/** 将非 ASCII 字符转换为可复制的转义形式。 */
export function applyEncoding(text: string, encoding: "utf8" | "ascii"): string {
  if (encoding !== "ascii") return text
  return text.replace(/[^\x00-\x7F]/g, (char) => {
    const codePoint = char.codePointAt(0) ?? 0
    if (codePoint <= 0xff) {
      return `\\x${codePoint.toString(16).padStart(2, "0")}`
    }
    return `\\u${codePoint.toString(16).padStart(4, "0")}`
  })
}

/** 截断超长报文并附加明确提示。 */
export function capMessage(text: string, truncatedLabel: string): string {
  if (text.length <= MAX_MESSAGE_CHARS) return text
  return `${text.slice(0, MAX_MESSAGE_CHARS)}\n... [${truncatedLabel}]`
}

/** 将后端协议 token 映射为 HTTP 报文协议标识。 */
export function wireProtocolLabel(token?: string): string {
  switch ((token || "").toLowerCase()) {
    case "http/1.0":
      return "HTTP/1.0"
    case "http/1.1":
      return "HTTP/1.1"
    case "h2":
    case "h2c":
      return "HTTP/2"
    case "h3":
      return "HTTP/3"
    default:
      return ""
  }
}

/** 按请求行、状态行、头部和正文的层级渲染 HTTP 报文。 */
export function renderHttpSyntax(raw: string): ReactNode {
  let inHeaders = true

  return raw.split(/\r?\n/).map((line, index) => {
    if (index === 0) {
      const responseParts = line.match(/^(HTTP\/\S+)\s+(\d{3})(.*)$/)
      if (responseParts) {
        return (
          <span key={index}>
            <span className="text-muted-foreground">{responseParts[1]}</span>{" "}
            <span className="font-semibold text-sky-700 dark:text-sky-300">
              {responseParts[2]}
            </span>
            <span className="text-foreground/70">{responseParts[3]}</span>
            {"\n"}
          </span>
        )
      }

      const requestParts = line.match(/^(\S+)\s(.*?)(?:\s(HTTP\/\S+))?$/)
      if (requestParts) {
        return (
          <span key={index}>
            <span className="font-semibold text-teal-700 dark:text-emerald-400">
              {requestParts[1]}
            </span>
            {requestParts[2] ? (
              <>
                {" "}
                <span className="text-sky-700 dark:text-sky-300">
                  {requestParts[2]}
                </span>
              </>
            ) : null}
            {requestParts[3] ? (
              <>
                {" "}
                <span className="text-muted-foreground">
                  {requestParts[3]}
                </span>
              </>
            ) : null}
            {"\n"}
          </span>
        )
      }
    }

    if (line === "") inHeaders = false
    const colonIndex = line.indexOf(":")
    if (inHeaders && colonIndex > 0 && !/^[\s\t]/.test(line)) {
      const name = line.slice(0, colonIndex)
      const value = line.slice(colonIndex + 1)
      return (
        <span key={index}>
          <span className="text-amber-700 dark:text-amber-400">{name}</span>
          <span className="text-muted-foreground">:</span>
          <span className="text-foreground/80">{value}</span>
          {"\n"}
        </span>
      )
    }

    return (
      <span key={index}>
        {line}
        {"\n"}
      </span>
    )
  })
}

/** 可滚动、可缩放且支持键盘聚焦的 HTTP 报文展示区。 */
export function MessageView({
  text,
  empty,
  fontScale,
  label,
}: {
  text: string
  empty: string
  fontScale: number
  label?: string
}) {
  if (!text) {
    return (
      <div className="flex h-[clamp(220px,42dvh,420px)] min-h-0 items-center justify-center rounded-lg border border-dashed bg-muted/20 px-6 text-center text-xs text-muted-foreground">
        {empty}
      </div>
    )
  }

  return (
    <ScrollArea
      className="h-[clamp(220px,42dvh,420px)] min-h-0 rounded-lg border bg-muted/30 outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 dark:bg-zinc-950/60"
      tabIndex={0}
      aria-label={label}
    >
      <pre
        className="p-4 font-mono leading-relaxed break-all whitespace-pre-wrap"
        style={{ fontSize: `${0.75 * fontScale}rem` }}
      >
        {renderHttpSyntax(text)}
      </pre>
    </ScrollArea>
  )
}
