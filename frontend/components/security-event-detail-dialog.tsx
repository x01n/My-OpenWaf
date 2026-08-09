"use client"

import { useMemo, useState } from "react"
import useSWR from "swr"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { format } from "date-fns"
import { zhCN } from "date-fns/locale"
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Collapsible, CollapsibleContent } from "@/components/ui/collapsible"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import {
  IconCopy,
  IconMinus,
  IconPlus,
  IconRefresh,
  IconShieldOff,
  IconLock,
  IconFingerprint,
  IconMessageReport,
  IconShieldLock,
} from "@tabler/icons-react"
import type { AccessLog, SecurityEvent, IPEntry } from "@/lib/types"
import { ipListApi, falsePositiveApi, requestTraceApi } from "@/lib/api"
import { countryFlag, countryName } from "@/lib/country-names"
import { categoryLabel } from "@/lib/attack-category"
import { IpHoverPreview } from "@/components/ip-hover-preview"
import { cn } from "@/lib/utils"

interface SecurityEventDetailDialogProps {
  event: SecurityEvent | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** 报文区渲染字符上限，超出部分截断展示，避免超大报文拖垮渲染 */
const MAX_MESSAGE_CHARS = 16384

/** 脱敏占位符，与后端 internal/dataplane/handler.go 保持一致 */
const REDACTED = "[redacted]"

/**
 * 敏感头部名称片段，与后端 isSensitiveLogKey
 * (internal/dataplane/handler.go) 的列表保持一致。
 * 后端写入时已脱敏，此处为前端二次防御：历史数据或非常规写入路径同样不泄露。
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

/**
 * 判断头部名称是否命中敏感片段。
 *
 * @param name 头部名称
 * @returns 命中任一敏感片段时返回 true
 */
function isSensitiveHeaderName(name: string): boolean {
  const lower = name.toLowerCase()
  return SENSITIVE_KEY_PARTS.some((part) => lower.includes(part))
}

/** 单条头部条目 */
interface HeaderEntry {
  name: string
  value: string
  sensitive: boolean
}

/**
 * 解析头部字段。
 *
 * 后端 requestHeadersJSON / responseHeadersJSON
 * (internal/dataplane/handler.go) 以 JSON 对象
 * `{"Name":["v1","v2"]}` 形式落库；早期数据可能为换行分隔文本，
 * 因此保留文本回退分支。
 *
 * @param raw 落库的头部字符串
 * @param order `header_order` 字段（逗号分隔），用于还原真实上报顺序
 * @returns 有序头部条目列表
 */
function parseHeaderEntries(raw?: string, order?: string): HeaderEntry[] {
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
            sensitive: isSensitiveHeaderName(key),
          })
        }
      }

      // header_order 与 headers 的 key 同源于 Hertz VisitAll 的 string(k)，可直接精确匹配
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
      // JSON 解析失败时按文本格式处理
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
      return { name, value, sensitive: isSensitiveHeaderName(name) }
    })
}

/**
 * 取头部展示值：敏感头部一律以占位符替换。
 */
function headerDisplayValue(entry: HeaderEntry): string {
  return entry.sensitive ? REDACTED : entry.value
}

/**
 * 按所选编码转换文本。ASCII 模式下将非 ASCII 字符转义为 \xHH / \uHHHH。
 */
function applyEncoding(text: string, encoding: "utf8" | "ascii"): string {
  if (encoding !== "ascii") return text
  return text.replace(/[^\x00-\x7F]/g, (ch) => {
    const cp = ch.codePointAt(0) ?? 0
    if (cp <= 0xff) return `\\x${cp.toString(16).padStart(2, "0")}`
    return `\\u${cp.toString(16).padStart(4, "0")}`
  })
}

/**
 * 截断超长报文并追加提示标记。
 */
function capMessage(text: string, truncatedLabel: string): string {
  if (text.length <= MAX_MESSAGE_CHARS) return text
  return `${text.slice(0, MAX_MESSAGE_CHARS)}\n... [${truncatedLabel}]`
}

/** 判断动作是否属于拦截/阻断类型 */
function isBlockAction(action: string): boolean {
  return action === "block" || action === "intercept" || action === "drop"
}

/** 判断动作是否属于挑战类型 */
function isChallengeAction(action: string): boolean {
  return (
    action === "challenge" ||
    action === "captcha_challenge" ||
    action === "shield_challenge" ||
    action === "chain_challenge"
  )
}

/** 动作对应的 Badge 样式类名 */
function getActionBadgeClass(action: string): string {
  if (isBlockAction(action))
    return "border-red-500/40 bg-red-500/15 text-red-600 dark:text-red-400"
  if (action === "observe" || action === "log_only")
    return "border-amber-500/40 bg-amber-500/15 text-amber-600 dark:text-amber-400"
  if (isChallengeAction(action))
    return "border-blue-500/40 bg-blue-500/15 text-blue-600 dark:text-blue-400"
  if (action === "allow")
    return "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
  return ""
}

/** 印章类型：拦截/挑战 -> deny；放行 -> allow；观察 -> observe */
function stampVariant(action: string): "deny" | "allow" | "observe" | null {
  if (isBlockAction(action) || isChallengeAction(action)) return "deny"
  if (action === "allow") return "allow"
  if (action === "observe" || action === "log_only") return "observe"
  return null
}

/**
 * 构建完整请求 URL。
 */
function buildFullUrl(ev: SecurityEvent): string {
  const scheme = ev.tls_version ? "https" : "http"
  const host = ev.host || "unknown"
  const path = ev.path || "/"
  const qs = ev.query_string ? `?${ev.query_string}` : ""
  return `${scheme}://${host}${path}${qs}`
}

/**
 * 将访问日志的 `http_protocol` 还原为报文中的协议标识。
 *
 * 后端 normalizeHTTPProtocol (internal/dataplane/handler.go) 把协议归一化为
 * ALPN 风格的 token，此处为其精确逆映射；无法确定对应关系的取值（例如回退到
 * X-Forwarded-Proto 的 `https`）返回空串，不做任何推测。
 *
 * @param token 访问日志中的 `http_protocol`
 * @returns 报文协议标识，未知时为空串
 */
function wireProtocolLabel(token?: string): string {
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

/**
 * 重建 HTTP 请求报文用于展示。
 *
 * @param ev 安全事件
 * @param protocol 协议标识，由 {@link wireProtocolLabel} 得出；未知时省略
 * @param encoding 展示编码
 * @param labels 截断提示文案
 */
function reconstructRequest(
  ev: SecurityEvent,
  protocol: string,
  encoding: "utf8" | "ascii",
  labels: { bodyTruncated: string; displayTruncated: string }
): string {
  const path = ev.path || "/"
  const qs = ev.query_string ? `?${ev.query_string}` : ""
  const requestLine = [ev.method, `${path}${qs}`, protocol]
    .filter(Boolean)
    .join(" ")
  const lines = [requestLine]

  const entries = parseHeaderEntries(ev.request_headers, ev.header_order)
  const hasHost = entries.some((e) => e.name.toLowerCase() === "host")
  if (!hasHost && ev.host) lines.push(`Host: ${ev.host}`)
  for (const entry of entries) {
    lines.push(`${entry.name}: ${headerDisplayValue(entry)}`)
  }

  let text = lines.join("\n")
  if (ev.request_body_preview) {
    text += `\n\n${ev.request_body_preview}`
    if (ev.request_body_truncated) text += `\n... [${labels.bodyTruncated}]`
  }
  return capMessage(applyEncoding(text, encoding), labels.displayTruncated)
}

/**
 * 重建 HTTP 响应报文用于展示。
 *
 * 响应头取自同 request_id 的访问日志（`response_headers`）。
 * 后端不落库响应体，因此仅能展示状态行与响应头。
 *
 * @returns 无任何可用响应数据时返回空字符串
 */
function reconstructResponse(
  ev: SecurityEvent,
  log: AccessLog | null,
  encoding: "utf8" | "ascii",
  displayTruncated: string
): string {
  const status = log?.status_code || ev.status_code
  const entries = parseHeaderEntries(log?.response_headers)
  if (!status && entries.length === 0) return ""

  const statusLine = [
    wireProtocolLabel(log?.http_protocol),
    status ? String(status) : "",
  ]
    .filter(Boolean)
    .join(" ")
  const lines = statusLine ? [statusLine] : []
  for (const entry of entries) {
    lines.push(`${entry.name}: ${headerDisplayValue(entry)}`)
  }
  return capMessage(applyEncoding(lines.join("\n"), encoding), displayTruncated)
}

/**
 * 生成 cURL 命令。敏感头部以占位符导出，避免凭据经剪贴板外泄。
 */
function buildCurlCommand(ev: SecurityEvent): string {
  const url = buildFullUrl(ev)
  let cmd = `curl -X ${ev.method} '${url}'`
  for (const entry of parseHeaderEntries(ev.request_headers, ev.header_order)) {
    if (entry.name.toLowerCase() === "host") continue
    const value = headerDisplayValue(entry).replace(/'/g, "'\\''")
    cmd += ` \\\n  -H '${entry.name}: ${value}'`
  }
  if (ev.request_body_preview) {
    const escaped = ev.request_body_preview.replace(/'/g, "'\\''")
    cmd += ` \\\n  --data '${escaped}'`
  }
  if (ev.tls_version) cmd += " \\\n  --insecure"
  return cmd
}

/**
 * HTTP 报文语法高亮渲染：首行方法/路径/协议着色，其余按 `名称: 值` 着色。
 */
function renderHttpSyntax(raw: string): React.ReactNode {
  return raw.split(/\r?\n/).map((line, i) => {
    if (i === 0) {
      const parts = line.match(/^(\S+)\s(.*?)(?:\s(HTTP\/\S+))?$/)
      if (parts) {
        return (
          <span key={i}>
            <span className="font-semibold text-teal-700 dark:text-emerald-400">
              {parts[1]}
            </span>
            {parts[2] ? (
              <>
                {" "}
                <span className="text-sky-700 dark:text-sky-300">
                  {parts[2]}
                </span>
              </>
            ) : null}
            {parts[3] ? (
              <>
                {" "}
                <span className="text-muted-foreground">{parts[3]}</span>
              </>
            ) : null}
            {"\n"}
          </span>
        )
      }
    }
    const colonIdx = line.indexOf(":")
    if (colonIdx > 0 && i > 0 && !/^[\s\t]/.test(line)) {
      const name = line.slice(0, colonIdx)
      const value = line.slice(colonIdx + 1)
      return (
        <span key={i}>
          <span className="text-amber-700 dark:text-amber-400">{name}</span>
          <span className="text-muted-foreground">:</span>
          <span className="text-foreground/80">{value}</span>
          {"\n"}
        </span>
      )
    }
    return (
      <span key={i}>
        {line}
        {"\n"}
      </span>
    )
  })
}

/**
 * 复制文本到剪贴板，成功/失败均以 toast 反馈。
 */
function copyToClipboard(text: string, successMsg: string, failMsg: string) {
  navigator.clipboard.writeText(text).then(
    () => toast.success(successMsg),
    () => toast.error(failMsg)
  )
}

/**
 * 印章角标：Deny / Allow / Observe，纯视觉装饰。
 */
function StampBadge({ variant }: { variant: "deny" | "allow" | "observe" }) {
  const cls =
    variant === "deny"
      ? "border-red-500/70 text-red-500/85"
      : variant === "allow"
        ? "border-emerald-500/70 text-emerald-500/85"
        : "border-amber-500/70 text-amber-500/85"
  const text =
    variant === "deny" ? "Deny" : variant === "allow" ? "Allow" : "Observe"
  return (
    <div
      className="pointer-events-none absolute top-1/2 right-5 -translate-y-1/2 -rotate-12 opacity-80 select-none"
      aria-hidden
    >
      <div className={cn("rounded-lg border-2 border-dashed p-1", cls)}>
        <div
          className={cn(
            "rounded-md border-2 px-3 py-0.5 font-mono text-base font-black tracking-[0.15em]",
            cls
          )}
        >
          {text}
        </div>
      </div>
    </div>
  )
}

/**
 * 详情行：左侧标签 + 右侧值，窄屏自动堆叠。
 */
function DetailRow({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="grid grid-cols-1 gap-0.5 py-1.5 sm:grid-cols-[128px_minmax(0,1fr)] sm:gap-3">
      <div className="text-xs text-muted-foreground sm:pt-0.5">{label}</div>
      <div className="min-w-0 text-sm">{children}</div>
    </div>
  )
}

/**
 * 报文展示区：等宽字体 + 语法高亮 + 响应式高度滚动。
 */
function MessageView({
  text,
  empty,
  fontScale,
}: {
  text: string
  empty: string
  fontScale: number
}) {
  const messageFontSize = `${0.75 * fontScale}rem`

  if (!text) {
    return (
      <div className="flex h-[clamp(220px,42dvh,420px)] min-h-0 items-center justify-center rounded-lg border border-dashed bg-muted/20 px-6 text-center text-xs text-muted-foreground">
        {empty}
      </div>
    )
  }
  return (
    <ScrollArea className="h-[clamp(220px,42dvh,420px)] min-h-0 rounded-lg border bg-muted/30 dark:bg-zinc-950/60">
      <pre
        className="p-4 font-mono leading-relaxed break-all whitespace-pre-wrap"
        style={{ fontSize: messageFontSize }}
      >
        {renderHttpSyntax(text)}
      </pre>
    </ScrollArea>
  )
}

/**
 * 安全事件详情弹窗。
 *
 * 顶部信息卡展示动作徽章、请求 URL、Deny 印章与关键字段；
 * 中部按 Tab 切换请求/响应报文（等宽高亮、可滚动、支持编码切换）；
 * 底部提供误报反馈、复制 cURL 与关闭操作。
 *
 * 敏感头部（Authorization / Cookie / Set-Cookie / API Key 等）在展示与
 * cURL 导出两条路径上均以占位符替换；超长报文按 {@link MAX_MESSAGE_CHARS} 截断。
 */
export function SecurityEventDetailDialog({
  event,
  open,
  onOpenChange,
}: SecurityEventDetailDialogProps) {
  const { t } = useTranslation()
  const [encoding, setEncoding] = useState<"utf8" | "ascii">("utf8")
  const [messageScale, setMessageScale] = useState(1)
  const [fingerprintOpen, setFingerprintOpen] = useState(false)
  const [banLoading, setBanLoading] = useState(false)
  const [fpDialogOpen, setFpDialogOpen] = useState(false)
  const [fpNote, setFpNote] = useState("")
  const [fpLoading, setFpLoading] = useState(false)

  const requestId = event?.request_id || ""

  // 同 request_id 的访问日志提供响应头与协议标识（安全事件模型本身不含这两项）
  const { data: trace, isLoading: traceLoading } = useSWR(
    open && requestId ? ["security-event-trace", requestId] : null,
    () => requestTraceApi.get(requestId),
    { revalidateOnFocus: false }
  )

  const actionLabelMap: Record<string, string> = useMemo(
    () => ({
      block: t("securityEvents.action.block"),
      intercept: t("securityEvents.action.intercept"),
      observe: t("securityEvents.action.observe"),
      challenge: t("securityEvents.action.challenge"),
      captcha_challenge: t("securityEvents.action.captcha_challenge"),
      shield_challenge: t("securityEvents.action.shield_challenge"),
      chain_challenge: t("securityEvents.action.chain_challenge"),
      allow: t("securityEvents.action.allow"),
      drop: t("securityEvents.action.drop"),
      log_only: t("securityEvents.action.log_only"),
    }),
    [t]
  )

  if (!event) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-4xl" />
      </Dialog>
    )
  }

  const ev = event
  const fullUrl = buildFullUrl(ev)
  const stamp = stampVariant(ev.action)
  const accessLog = trace?.access_logs?.[0] ?? null
  const hasFingerprint = Boolean(
    ev.tls_version ||
    ev.tls_sni ||
    ev.tls_ja3 ||
    ev.tls_ja3_hash ||
    ev.tls_ja4 ||
    ev.tls_alpn ||
    ev.tls_cipher_suites ||
    ev.tls_extensions ||
    ev.tls_curves ||
    ev.tls_point_formats ||
    ev.header_order
  )

  const truncateLabels = {
    bodyTruncated: t("securityEventDetail.bodyTruncated"),
    displayTruncated: t("securityEventDetail.displayTruncated"),
  }
  const requestText = reconstructRequest(
    ev,
    wireProtocolLabel(accessLog?.http_protocol),
    encoding,
    truncateLabels
  )
  const responseText = reconstructResponse(
    ev,
    accessLog,
    encoding,
    truncateLabels.displayTruncated
  )

  const attackTime = (() => {
    try {
      return format(new Date(ev.created_at), "yyyy-MM-dd HH:mm:ss", {
        locale: zhCN,
      })
    } catch {
      return ev.created_at
    }
  })()

  const copySuccess = t("common.copied")
  const copyFail = t("common.copyFailed")

  const handleAddToBlocklist = async () => {
    setBanLoading(true)
    try {
      const payload: Partial<IPEntry> = {
        value: ev.client_ip,
        kind: "blacklist",
        action: "intercept",
        note: t("securityEventDetail.blocklistNote", { id: ev.id }),
      }
      await ipListApi.create(payload)
      toast.success(t("securityEventDetail.addedToBlocklist"))
    } catch {
      toast.error(t("securityEventDetail.addBlocklistFailed"))
    } finally {
      setBanLoading(false)
    }
  }

  const handleSubmitFalsePositive = async () => {
    setFpLoading(true)
    try {
      await falsePositiveApi.create({
        security_event_id: ev.id,
        request_id: ev.request_id,
        rule_id_str: ev.rule_id_str || String(ev.rule_id ?? ""),
        category: ev.category,
        client_ip: ev.client_ip,
        host: ev.host,
        path: ev.path,
        match_desc: ev.match_desc || "",
        note: fpNote,
      })
      toast.success(t("falsePositives.submitSuccess"))
      setFpDialogOpen(false)
    } catch {
      toast.error(t("falsePositives.submitFailed"))
    } finally {
      setFpLoading(false)
    }
  }

  /** 指纹字段清单，仅渲染后端实际返回的项 */
  const fingerprintFields: Array<{ label: string; value?: string }> = [
    { label: "TLS Version", value: ev.tls_version },
    { label: "SNI", value: ev.tls_sni },
    { label: "ALPN", value: ev.tls_alpn },
    { label: "tls_ja4", value: ev.tls_ja4 },
    { label: "tls_ja3_hash", value: ev.tls_ja3_hash },
    { label: "tls_ja3", value: ev.tls_ja3 },
    { label: "Cipher Suites", value: ev.tls_cipher_suites },
    { label: "Extensions", value: ev.tls_extensions },
    { label: "Curves", value: ev.tls_curves },
    { label: "Point Formats", value: ev.tls_point_formats },
    { label: "Header Order", value: ev.header_order },
  ]

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-h-[calc(100dvh-1rem)] w-[calc(100%-1rem)] max-w-5xl overflow-x-hidden overflow-y-auto bg-muted/30 p-3 sm:max-h-[calc(100dvh-2rem)] sm:w-[calc(100%-2rem)] sm:p-5">
          <div className="sr-only">
            <DialogTitle>{t("securityEventDetail.dialogTitle")}</DialogTitle>
            <DialogDescription>{fullUrl}</DialogDescription>
          </div>

          {/* ====== 信息卡 ====== */}
          <div className="relative overflow-hidden rounded-xl border bg-background px-5 py-4 shadow-sm">
            <div className="flex items-start gap-2.5 pr-28">
              <Badge
                className={cn(
                  "mt-0.5 shrink-0 border px-2 py-0.5 text-xs font-semibold",
                  getActionBadgeClass(ev.action)
                )}
              >
                {actionLabelMap[ev.action] || ev.action}
              </Badge>
              <button
                type="button"
                className="min-w-0 text-left font-mono text-sm leading-relaxed break-all hover:text-primary"
                title={t("securityEventDetail.clickToCopyUrl")}
                onClick={() => copyToClipboard(fullUrl, copySuccess, copyFail)}
              >
                {fullUrl}
              </button>
            </div>
            {stamp && <StampBadge variant={stamp} />}

            <div className="mt-3.5 divide-y divide-border/40 pr-0 sm:pr-28">
              {/* 攻击者来源 */}
              <DetailRow label={t("securityEventDetail.attackSource")}>
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <IpHoverPreview
                    ip={ev.client_ip}
                    className="text-sm font-medium"
                  />
                  {ev.geo_country && (
                    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                      <span className="text-base leading-none">
                        {countryFlag(ev.geo_country)}
                      </span>
                      <span>{countryName(ev.geo_country)}</span>
                      {ev.geo_city && <span>/ {ev.geo_city}</span>}
                    </span>
                  )}
                  <Button
                    variant="link"
                    size="sm"
                    className="h-auto gap-1 p-0 text-xs"
                    disabled={banLoading}
                    onClick={handleAddToBlocklist}
                  >
                    <IconShieldLock className="h-3.5 w-3.5" />
                    {t("securityEventDetail.addToBlocklist")}
                  </Button>
                </div>
              </DetailRow>

              {/* JA4 指纹 */}
              <DetailRow label={t("securityEventDetail.ja4Fingerprint")}>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  {ev.tls_ja4 ? (
                    <button
                      type="button"
                      className="text-left font-mono text-xs break-all hover:text-primary"
                      title={t("securityEventDetail.clickToCopy")}
                      onClick={() =>
                        copyToClipboard(ev.tls_ja4 || "", copySuccess, copyFail)
                      }
                    >
                      {ev.tls_ja4}
                    </button>
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                  {hasFingerprint && (
                    <Button
                      variant="link"
                      size="sm"
                      className="h-auto gap-1 p-0 text-xs"
                      onClick={() => setFingerprintOpen((v) => !v)}
                    >
                      <IconFingerprint className="h-3.5 w-3.5" />
                      {t("securityEventDetail.viewFingerprintProfile")}
                    </Button>
                  )}
                </div>
              </DetailRow>

              {/* 攻击载荷 */}
              <DetailRow label={t("securityEventDetail.attackPayload")}>
                {ev.match_desc ? (
                  <code className="inline-block max-w-full rounded border border-red-500/20 bg-red-500/5 px-2 py-1 font-mono text-xs leading-relaxed break-all text-red-700 dark:text-red-300">
                    {ev.match_desc}
                  </code>
                ) : (
                  <span className="text-muted-foreground">-</span>
                )}
              </DetailRow>

              {/* 命中防护模块 */}
              <DetailRow label={t("securityEventDetail.hitModule")}>
                <div className="flex flex-wrap items-center gap-2">
                  <span>{categoryLabel(ev.category)}</span>
                  {ev.phase && (
                    <Badge
                      variant="secondary"
                      className="h-4 px-1.5 font-mono text-[10px] font-normal"
                    >
                      {ev.phase}
                    </Badge>
                  )}
                </div>
              </DetailRow>

              {/* 规则名称 */}
              <DetailRow label={t("securityEventDetail.ruleName")}>
                <span className="font-mono text-xs break-all">
                  {ev.rule_id_str || `#${ev.rule_id}`}
                </span>
              </DetailRow>

              {/* 请求方法 / 状态码 / 站点 */}
              <DetailRow label={t("securityEventDetail.methodStatus")}>
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge variant="outline" className="h-5 px-1.5 text-xs">
                    {ev.method}
                  </Badge>
                  {ev.status_code > 0 && (
                    <Badge
                      variant="outline"
                      className={cn(
                        "h-5 px-1.5 text-xs",
                        ev.status_code >= 400 &&
                          "border-red-500/40 text-red-600 dark:text-red-400"
                      )}
                    >
                      {ev.status_code}
                    </Badge>
                  )}
                  <Badge
                    variant="secondary"
                    className="h-5 px-1.5 text-[10px] font-normal"
                  >
                    site #{ev.site_id}
                  </Badge>
                </div>
              </DetailRow>

              {/* User-Agent */}
              {ev.user_agent && (
                <DetailRow label={t("securityEventDetail.userAgent")}>
                  <span className="block font-mono text-xs break-all text-foreground/80">
                    {ev.user_agent}
                  </span>
                </DetailRow>
              )}

              {/* 攻击时间 */}
              <DetailRow label={t("securityEventDetail.attackTime")}>
                <span>{attackTime}</span>
              </DetailRow>

              {/* 请求 ID */}
              <DetailRow label={t("securityEventDetail.requestId")}>
                <button
                  type="button"
                  className="text-left font-mono text-xs break-all text-foreground/70 hover:text-primary"
                  title={t("securityEventDetail.clickToCopy")}
                  onClick={() =>
                    copyToClipboard(ev.request_id, copySuccess, copyFail)
                  }
                >
                  {ev.request_id}
                </button>
              </DetailRow>
            </div>

            {/* 指纹画像折叠区 */}
            {hasFingerprint && (
              <Collapsible
                open={fingerprintOpen}
                onOpenChange={setFingerprintOpen}
              >
                <CollapsibleContent>
                  <div className="mt-3 rounded-lg border bg-muted/40 p-4">
                    <div className="mb-2 flex items-center gap-1.5 text-xs font-medium">
                      <IconLock className="h-3.5 w-3.5 text-emerald-500" />
                      {t("securityEventDetail.tlsInfo")}
                    </div>
                    <div className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
                      {fingerprintFields
                        .filter((f) => f.value)
                        .map((f) => (
                          <div key={f.label} className="min-w-0">
                            <span className="text-[11px] text-muted-foreground">
                              {f.label}
                            </span>
                            <p className="font-mono text-xs break-all">
                              {f.value}
                            </p>
                          </div>
                        ))}
                    </div>
                  </div>
                </CollapsibleContent>
              </Collapsible>
            )}

            <div className="pointer-events-none absolute -bottom-8 -left-6 opacity-[0.04]">
              <IconShieldOff className="h-40 w-40" strokeWidth={1} />
            </div>
          </div>

          {/* ====== 报文区 ====== */}
          <div className="mt-4 rounded-xl border bg-background px-5 py-4 shadow-sm">
            <Tabs defaultValue="request">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <TabsList>
                  <TabsTrigger value="request">
                    {t("securityEventDetail.requestMessage")}
                  </TabsTrigger>
                  <TabsTrigger value="response">
                    {t("securityEventDetail.responseMessage")}
                  </TabsTrigger>
                </TabsList>
                <div
                  className="flex flex-wrap items-center gap-1.5"
                  role="group"
                  aria-label="Message text size"
                >
                  <Button
                    type="button"
                    variant="outline"
                    size="icon-sm"
                    className="h-7 w-7"
                    aria-label="Decrease message text size"
                    title="Decrease message text size"
                    disabled={messageScale <= 0.8}
                    onClick={() =>
                      setMessageScale((value) =>
                        Math.max(0.8, Number((value - 0.1).toFixed(2)))
                      )
                    }
                  >
                    <IconMinus className="h-3.5 w-3.5" />
                  </Button>
                  <span
                    className="min-w-10 text-center font-mono text-[11px] text-muted-foreground"
                    aria-live="polite"
                  >
                    {Math.round(messageScale * 100)}%
                  </span>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon-sm"
                    className="h-7 w-7"
                    aria-label="Increase message text size"
                    title="Increase message text size"
                    disabled={messageScale >= 1.4}
                    onClick={() =>
                      setMessageScale((value) =>
                        Math.min(1.4, Number((value + 0.1).toFixed(2)))
                      )
                    }
                  >
                    <IconPlus className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    className="h-7 w-7"
                    aria-label="Reset message text size"
                    title="Reset message text size"
                    onClick={() => setMessageScale(1)}
                  >
                    <IconRefresh className="h-3.5 w-3.5" />
                  </Button>
                </div>
                <Select
                  value={encoding}
                  onValueChange={(v) => setEncoding(v as "utf8" | "ascii")}
                >
                  <SelectTrigger className="h-7 w-[110px] text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent align="end">
                    <SelectItem value="utf8">UTF-8</SelectItem>
                    <SelectItem value="ascii">ASCII</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <TabsContent value="request">
                <MessageView
                  text={requestText}
                  empty={t("securityEventDetail.noRequestData")}
                  fontScale={messageScale}
                />
              </TabsContent>

              <TabsContent value="response">
                <MessageView
                  text={responseText}
                  empty={
                    traceLoading
                      ? t("common.loading")
                      : t("securityEventDetail.noResponseData")
                  }
                  fontScale={messageScale}
                />
                {responseText && (
                  <p className="mt-2 text-[11px] text-muted-foreground">
                    {t("securityEventDetail.responseBodyNotStored")}
                  </p>
                )}
                {accessLog && (
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                    {accessLog.upstream && (
                      <span>
                        {t("securityEventDetail.upstream")}:{" "}
                        <span className="font-mono break-all">
                          {accessLog.upstream}
                        </span>
                      </span>
                    )}
                    {accessLog.cache_state && (
                      <span>
                        {t("securityEventDetail.cacheState")}:{" "}
                        <span className="font-mono">
                          {accessLog.cache_state}
                        </span>
                      </span>
                    )}
                    <span>
                      {t("securityEventDetail.upstreamLatency")}:{" "}
                      <span className="font-mono">
                        {accessLog.upstream_latency_ms} ms
                      </span>
                    </span>
                    <span>
                      {t("securityEventDetail.responseSize")}:{" "}
                      <span className="font-mono">
                        {accessLog.response_size} B
                      </span>
                    </span>
                  </div>
                )}
              </TabsContent>
            </Tabs>
            <p className="mt-2 text-[11px] text-muted-foreground">
              {t("securityEventDetail.redactionHint")}
            </p>
          </div>

          {/* ====== 底部操作栏 ====== */}
          <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-4">
              <Button
                variant="link"
                size="sm"
                className="h-auto gap-1 p-0 text-xs"
                onClick={() => {
                  setFpNote("")
                  setFpDialogOpen(true)
                }}
                disabled={fpLoading}
              >
                <IconMessageReport className="h-3.5 w-3.5" />
                {t("securityEventDetail.reportFalsePositive")}
              </Button>
              <Button
                variant="link"
                size="sm"
                className="h-auto gap-1 p-0 text-xs"
                onClick={() =>
                  copyToClipboard(buildCurlCommand(ev), copySuccess, copyFail)
                }
              >
                <IconCopy className="h-3.5 w-3.5" />
                {t("securityEventDetail.copyCurl")}
              </Button>
            </div>
            <Button size="sm" onClick={() => onOpenChange(false)}>
              {t("common.close")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* ====== 误报反馈提交对话框 ====== */}
      <Dialog open={fpDialogOpen} onOpenChange={setFpDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogTitle>{t("falsePositives.reportDialogTitle")}</DialogTitle>
          <DialogDescription>
            {t("falsePositives.reportDialogDesc")}
          </DialogDescription>
          <div className="space-y-3 pt-2">
            <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
              <div className="text-muted-foreground">
                {t("falsePositives.noteRuleId")}
              </div>
              <div className="mt-0.5 font-mono">
                {ev.rule_id_str || `#${ev.rule_id}`}{" "}
                <span className="text-muted-foreground">
                  ({categoryLabel(ev.category)})
                </span>
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium">
                {t("falsePositives.noteLabel")}
              </label>
              <Textarea
                rows={4}
                value={fpNote}
                onChange={(e) => setFpNote(e.target.value)}
                placeholder={t("falsePositives.notePlaceholder")}
                maxLength={2000}
              />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setFpDialogOpen(false)}
              disabled={fpLoading}
            >
              {t("common.cancel")}
            </Button>
            <Button
              size="sm"
              onClick={handleSubmitFalsePositive}
              disabled={fpLoading}
            >
              {fpLoading ? t("common.submitting") : t("falsePositives.submit")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
