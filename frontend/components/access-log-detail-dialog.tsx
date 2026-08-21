"use client"

import { useMemo, useState } from "react"
import { format } from "date-fns"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  IconChevronDown,
  IconClock,
  IconCopy,
  IconFingerprint,
  IconHash,
  IconMinus,
  IconPlus,
  IconRefresh,
  IconRoute,
  IconWorld,
} from "@tabler/icons-react"
import { ActionBadge } from "@/components/action-badge"
import {
  applyEncoding,
  capMessage,
  headerDisplayValue,
  MessageView,
  parseHeaderEntries,
  redactBodyPreview,
  redactQueryString,
  wireProtocolLabel,
} from "@/components/http-message-view"
import type { AccessLog } from "@/lib/types"
import { cn, formatBytes, formatLatencyMs } from "@/lib/utils"

interface AccessLogDetailDialogProps {
  log: AccessLog | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

type MessageTab = "request" | "response"
type MessageEncoding = "utf8" | "ascii"

/** 构造已脱敏的请求 URL。 */
function buildFullUrl(log: AccessLog): string {
  const scheme = log.tls_version ? "https" : "http"
  const host = log.host || "unknown"
  const path = log.path || "/"
  const safeQuery = redactQueryString(log.query_string)
  return `${scheme}://${host}${path}${safeQuery ? `?${safeQuery}` : ""}`
}

/** 重建访问日志中的请求报文。 */
function reconstructRequest(
  log: AccessLog,
  encoding: MessageEncoding,
  labels: { bodyTruncated: string; displayTruncated: string }
): string {
  const safeQuery = redactQueryString(log.query_string)
  const path = `${log.path || "/"}${safeQuery ? `?${safeQuery}` : ""}`
  const requestLine = [log.method, path, wireProtocolLabel(log.http_protocol)]
    .filter(Boolean)
    .join(" ")
  const entries = parseHeaderEntries(log.request_headers, log.header_order)
  const lines = [requestLine]

  if (!entries.some((entry) => entry.name.toLowerCase() === "host") && log.host) {
    lines.push(`Host: ${log.host}`)
  }
  for (const entry of entries) {
    lines.push(`${entry.name}: ${headerDisplayValue(entry)}`)
  }

  let text = lines.join("\n")
  if (log.request_body_preview) {
    text += `\n\n${redactBodyPreview(
      log.request_body_preview,
      log.request_headers
    )}`
    if (log.request_body_truncated) {
      text += `\n... [${labels.bodyTruncated}]`
    }
  }
  return capMessage(applyEncoding(text, encoding), labels.displayTruncated)
}

/** 重建访问日志中的响应状态行与响应头。 */
function reconstructResponse(
  log: AccessLog,
  encoding: MessageEncoding,
  displayTruncated: string
): string {
  const entries = parseHeaderEntries(log.response_headers)
  if (!log.status_code && entries.length === 0) return ""

  const statusLine = [
    wireProtocolLabel(log.http_protocol),
    log.status_code ? String(log.status_code) : "",
  ]
    .filter(Boolean)
    .join(" ")
  const lines = statusLine ? [statusLine] : []
  for (const entry of entries) {
    lines.push(`${entry.name}: ${headerDisplayValue(entry)}`)
  }
  return capMessage(
    applyEncoding(lines.join("\n"), encoding),
    displayTruncated
  )
}

/** 复制已脱敏文本并反馈结果。 */
function copyToClipboard(text: string, success: string, failed: string) {
  navigator.clipboard.writeText(text).then(
    () => toast.success(success),
    () => toast.error(failed)
  )
}

/** 状态码以区间语义着色，数值文本始终保留。 */
function statusBadgeClass(status: number): string {
  if (status >= 500) {
    return "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
  }
  if (status >= 400) {
    return "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
  }
  if (status >= 300) {
    return "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300"
  }
  if (status >= 200) {
    return "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
  }
  return ""
}

/** 详情标签与值的响应式布局。 */
function DetailItem({
  icon,
  label,
  value,
  mono,
}: {
  icon?: React.ReactNode
  label: string
  value: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="min-w-0 px-3 py-2.5 sm:px-4">
      <div className="flex items-center gap-1.5 text-[11px] font-medium tracking-wide text-muted-foreground uppercase">
        {icon}
        {label}
      </div>
      <div
        className={cn(
          "mt-1 min-w-0 text-sm break-all text-foreground",
          mono && "font-mono text-xs"
        )}
      >
        {value}
      </div>
    </div>
  )
}

/**
 * 访问日志详情：按需展示请求/响应报文、性能指标、上游与 TLS 指纹。
 * 所有头部、查询参数和请求体均在浏览器展示与复制前再次脱敏。
 */
export function AccessLogDetailDialog({
  log,
  open,
  onOpenChange,
}: AccessLogDetailDialogProps) {
  const { t, i18n } = useTranslation()
  const [activeTab, setActiveTab] = useState<MessageTab>("request")
  const [encoding, setEncoding] = useState<MessageEncoding>("utf8")
  const [messageScale, setMessageScale] = useState(1)

  const labels = useMemo(
    () => ({
      bodyTruncated: t("securityEventDetail.bodyTruncated"),
      displayTruncated: t("securityEventDetail.displayTruncated"),
    }),
    [t]
  )

  const requestText = useMemo(
    () => (log ? reconstructRequest(log, encoding, labels) : ""),
    [encoding, labels, log]
  )
  const responseText = useMemo(
    () =>
      log
        ? reconstructResponse(log, encoding, labels.displayTruncated)
        : "",
    [encoding, labels.displayTruncated, log]
  )

  if (!log) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-5xl">
          <span className="sr-only">
            <DialogTitle>{t("accessLogs.title")}</DialogTitle>
          </span>
        </DialogContent>
      </Dialog>
    )
  }

  const fullUrl = buildFullUrl(log)
  const copyText = activeTab === "request" ? requestText : responseText
  const requestSizeLabel = t("accessLogs.requestSize", {
    defaultValue: i18n.language.startsWith("zh") ? "请求大小" : "Request size",
  })
  const fingerprintFields = [
    { label: t("securityEventDetail.tlsVersion"), value: log.tls_version },
    { label: t("securityEventDetail.sni"), value: log.tls_sni },
    { label: t("securityEventDetail.alpn"), value: log.tls_alpn },
    { label: t("securityEventDetail.tlsJa4"), value: log.tls_ja4 },
    { label: t("securityEventDetail.tlsJa3Hash"), value: log.tls_ja3_hash },
    { label: t("securityEventDetail.tlsJa3"), value: log.tls_ja3 },
    { label: t("securityEventDetail.cipherSuites"), value: log.tls_cipher_suites },
    { label: t("securityEventDetail.extensions"), value: log.tls_extensions },
    { label: t("securityEventDetail.curves"), value: log.tls_curves },
    { label: t("securityEventDetail.pointFormats"), value: log.tls_point_formats },
    { label: t("securityEventDetail.headerOrder"), value: log.header_order },
  ].filter((field) => field.value)

  let occurredAt = log.created_at
  try {
    occurredAt = format(new Date(log.created_at), "yyyy-MM-dd HH:mm:ss")
  } catch {
    // 保留后端原始值，避免非法日期导致整个详情弹窗失败。
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100dvh-1rem)] w-[calc(100%-1rem)] max-w-5xl overflow-x-hidden overflow-y-auto p-0 sm:max-h-[calc(100dvh-2rem)] sm:w-[calc(100%-2rem)]">
        <div className="border-b bg-muted/20 px-4 py-4 sm:px-6">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Badge variant="outline" className="font-mono text-xs font-semibold">
              {log.method || "-"}
            </Badge>
            <Badge
              variant="outline"
              className={cn("font-mono text-xs", statusBadgeClass(log.status_code))}
            >
              {log.status_code || "-"}
            </Badge>
            <ActionBadge
              action={log.waf_action}
              className="h-6 px-2 text-xs"
            />
          </div>
          <DialogTitle className="mt-3 font-mono text-base leading-relaxed break-all sm:text-lg">
            {fullUrl}
          </DialogTitle>
          <DialogDescription className="mt-1 flex min-w-0 items-center gap-1.5 font-mono text-xs break-all">
            <IconHash className="h-3.5 w-3.5 shrink-0" />
            {log.request_id || `access-log-${log.id}`}
          </DialogDescription>
        </div>

        <div className="grid divide-y border-b sm:grid-cols-2 sm:divide-x sm:divide-y-0 lg:grid-cols-4">
          <DetailItem
            icon={<IconClock className="h-3.5 w-3.5" />}
            label={t("requestTrace.firstSeen")}
            value={occurredAt}
            mono
          />
          <DetailItem
            icon={<IconWorld className="h-3.5 w-3.5" />}
            label={t("requestTrace.clientIp")}
            value={log.client_ip || "-"}
            mono
          />
          <DetailItem
            icon={<IconRoute className="h-3.5 w-3.5" />}
            label={t("requestTrace.upstream")}
            value={log.upstream || "-"}
            mono
          />
          <DetailItem
            label={t("requestTrace.upstreamLatency")}
            value={formatLatencyMs(log.upstream_latency_ms)}
            mono
          />
        </div>

        <div className="px-4 py-4 sm:px-6">
          <Tabs
            value={activeTab}
            onValueChange={(value) => setActiveTab(value as MessageTab)}
          >
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div className="max-w-full overflow-x-auto">
                <TabsList className="w-max">
                  <TabsTrigger value="request">
                    {t("securityEventDetail.requestMessage")}
                    <span className="ml-1.5 font-mono text-[10px] text-muted-foreground">
                      {formatBytes(log.request_size)}
                    </span>
                  </TabsTrigger>
                  <TabsTrigger value="response">
                    {t("securityEventDetail.responseMessage")}
                    <span className="ml-1.5 font-mono text-[10px] text-muted-foreground">
                      {formatBytes(log.response_size)}
                    </span>
                  </TabsTrigger>
                </TabsList>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <div
                  className="flex items-center gap-1"
                  role="group"
                  aria-label={t("securityEventDetail.messageTextSize")}
                >
                  <Button
                    type="button"
                    variant="outline"
                    size="icon-sm"
                    className="h-7 w-7"
                    aria-label={t("securityEventDetail.decreaseMessageTextSize")}
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
                    aria-label={t("securityEventDetail.increaseMessageTextSize")}
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
                    aria-label={t("securityEventDetail.resetMessageTextSize")}
                    onClick={() => setMessageScale(1)}
                  >
                    <IconRefresh className="h-3.5 w-3.5" />
                  </Button>
                </div>
                <Select
                  value={encoding}
                  onValueChange={(value) =>
                    setEncoding(value as MessageEncoding)
                  }
                >
                  <SelectTrigger className="h-7 w-[104px] text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent align="end">
                    <SelectItem value="utf8">UTF-8</SelectItem>
                    <SelectItem value="ascii">ASCII</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 px-2 text-xs"
                  disabled={!copyText}
                  onClick={() =>
                    copyToClipboard(
                      copyText,
                      t("common.copied"),
                      t("common.copyFailed")
                    )
                  }
                >
                  <IconCopy className="h-3.5 w-3.5" />
                  {t("securityEventDetail.clickToCopy")}
                </Button>
              </div>
            </div>

            <TabsContent value="request" className="mt-0">
              <MessageView
                text={requestText}
                empty={t("securityEventDetail.noRequestData")}
                fontScale={messageScale}
                label={t("securityEventDetail.requestMessage")}
              />
            </TabsContent>
            <TabsContent value="response" className="mt-0">
              <MessageView
                text={responseText}
                empty={t("securityEventDetail.noResponseData")}
                fontScale={messageScale}
                label={t("securityEventDetail.responseMessage")}
              />
              <p className="mt-2 text-[11px] text-muted-foreground">
                {t("securityEventDetail.responseBodyNotStored")}
              </p>
            </TabsContent>
          </Tabs>

          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            <span>
              {requestSizeLabel}: {formatBytes(log.request_size)}
            </span>
            <span>
              {t("securityEventDetail.responseSize")}: {formatBytes(log.response_size)}
            </span>
            {log.cache_state && (
              <span>
                {t("securityEventDetail.cacheState")}: {log.cache_state}
              </span>
            )}
            {log.http_protocol && <span>
                {t("securityEventDetail.httpProtocol")}: {log.http_protocol}
              </span>}
            {log.upstream_http_protocol && (
              <span>
                {t("securityEventDetail.upstreamHttpProtocol")}: {log.upstream_http_protocol}
              </span>
            )}
          </div>
          <p className="mt-2 text-[11px] text-muted-foreground">
            {t("securityEventDetail.redactionHint")}
          </p>

          {fingerprintFields.length > 0 && (
            <Collapsible className="mt-4">
              <CollapsibleTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 w-full justify-between px-2 text-xs"
                >
                  <span className="flex items-center gap-1.5">
                    <IconFingerprint className="h-3.5 w-3.5" />
                    {t("securityEventDetail.viewFingerprintProfile")}
                  </span>
                  <IconChevronDown className="h-3.5 w-3.5 transition-transform motion-reduce:transition-none [[data-state=open]>&]:rotate-180" />
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent>
                <div className="mt-2 grid gap-x-6 gap-y-3 rounded-lg border bg-muted/20 p-4 sm:grid-cols-2">
                  {fingerprintFields.map((field) => (
                    <div key={field.label} className="min-w-0">
                      <span className="text-[11px] text-muted-foreground">
                        {field.label}
                      </span>
                      <p className="font-mono text-xs break-all">
                        {field.value}
                      </p>
                    </div>
                  ))}
                </div>
              </CollapsibleContent>
            </Collapsible>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
