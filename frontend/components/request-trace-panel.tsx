"use client"

import Link from "next/link"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { CopyableBlock, DetailField, WAFActionBadge } from "@/components/log-presentation"
import { ExternalLink, Route } from "@/lib/icons"
import { formatDate } from "@/lib/utils"
import type { AccessLog, RequestTrace, SecurityEvent } from "@/lib/api"

function tracePath(path?: string, query?: string) {
  if (!path) return "-"
  if (!query) return path
  return `${path}?${query}`
}

function accessLogTraceSummary(item: AccessLog) {
  return {
    id: item.id,
    created_at: item.created_at,
    site_id: item.site_id,
    request_id: item.request_id,
    client_ip: item.client_ip,
    host: item.host,
    path: item.path,
    query_string: item.query_string,
    method: item.method,
    status_code: item.status_code,
    waf_action: item.waf_action,
    cache_state: item.cache_state,
    upstream: item.upstream,
    upstream_latency_ms: item.upstream_latency_ms,
    response_size: item.response_size,
    request_size: item.request_size,
    http_protocol: item.http_protocol,
    tls_version: item.tls_version,
    tls_sni: item.tls_sni,
    tls_alpn: item.tls_alpn,
    tls_ja3_hash: item.tls_ja3_hash,
    tls_ja4: item.tls_ja4,
    header_order: item.header_order,
    request_headers: item.request_headers,
    request_body_preview: item.request_body_preview,
    request_body_truncated: item.request_body_truncated,
    response_headers: item.response_headers,
  }
}

function securityEventTraceSummary(item: SecurityEvent) {
  return {
    id: item.id,
    site_id: item.site_id,
    created_at: item.created_at,
    request_id: item.request_id,
    client_ip: item.client_ip,
    host: item.host,
    path: item.path,
    method: item.method,
    rule_id: item.rule_id,
    rule_id_str: item.rule_id_str,
    phase: item.phase,
    action: item.action,
    category: item.category,
    match_desc: item.match_desc,
    geo_country: item.geo_country,
    geo_city: item.geo_city,
    status_code: item.status_code,
    query_string: item.query_string,
    request_headers: item.request_headers,
    request_body_preview: item.request_body_preview,
    request_body_truncated: item.request_body_truncated,
    request_size: item.request_size,
    tls_version: item.tls_version,
    tls_sni: item.tls_sni,
    tls_alpn: item.tls_alpn,
    tls_ja3_hash: item.tls_ja3_hash,
    tls_ja4: item.tls_ja4,
    header_order: item.header_order,
  }
}

function requestTraceSummary(trace: RequestTrace) {
  return {
    request_id: trace.request_id,
    access_logs: trace.access_logs.map(accessLogTraceSummary),
    security_events: trace.security_events.map(securityEventTraceSummary),
  }
}

function TraceAccessLogItem({ item }: { item: AccessLog }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-background p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className="rounded-md">
          访问日志 #{item.id}
        </Badge>
        <Badge variant="secondary" className="rounded-md">
          {item.method || "-"} {item.status_code || "-"}
        </Badge>
        <WAFActionBadge action={item.waf_action} />
      </div>
      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        <DetailField label="时间" value={formatDate(item.created_at)} />
        <DetailField
          label="客户端 IP"
          value={item.client_ip || "-"}
          mono
          copyText={item.client_ip || undefined}
        />
        <DetailField
          label="Host"
          value={item.host || "-"}
          mono
          copyText={item.host || undefined}
        />
        <DetailField label="站点 ID" value={String(item.site_id)} mono />
      </div>
      <CopyableBlock
        label="访问路径"
        value={tracePath(item.path, item.query_string)}
        redact
        defaultOpen={false}
      />
    </div>
  )
}

function TraceSecurityEventItem({ item }: { item: SecurityEvent }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-background p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className="rounded-md">
          安全事件 #{item.id}
        </Badge>
        <Badge variant="secondary" className="rounded-md">
          {item.phase || "-"} / {item.category || "-"}
        </Badge>
        <WAFActionBadge action={item.action} />
      </div>
      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        <DetailField label="时间" value={formatDate(item.created_at)} />
        <DetailField
          label="客户端 IP"
          value={item.client_ip || "-"}
          mono
          copyText={item.client_ip || undefined}
        />
        <DetailField
          label="规则"
          value={item.rule_id_str || String(item.rule_id)}
          mono
          copyText={item.rule_id_str || String(item.rule_id)}
        />
        <DetailField label="状态码" value={String(item.status_code)} mono />
      </div>
      <CopyableBlock
        label="命中说明"
        value={item.match_desc || "-"}
        redact
        defaultOpen={false}
      />
    </div>
  )
}

export function RequestTracePanel({
  requestId,
  trace,
  loading,
  onLoad,
}: {
  requestId: string
  trace: RequestTrace | null
  loading: boolean
  onLoad: () => void
}) {
  const encodedRequestId = encodeURIComponent(requestId)

  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-muted/35 p-3 sm:col-span-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[11px] font-medium tracking-wider text-muted-foreground uppercase">
            请求追踪
          </div>
          <div className="mt-1 truncate font-mono text-xs text-foreground">
            {requestId || "-"}
          </div>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onLoad}
          disabled={!requestId || loading}
        >
          <Route data-icon="inline-start" />
          {loading ? "加载中" : "加载追踪"}
        </Button>
      </div>

      {trace && (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="rounded-md">
              访问日志 {trace.access_logs.length}
            </Badge>
            <Badge variant="outline" className="rounded-md">
              安全事件 {trace.security_events.length}
            </Badge>
            <Button asChild variant="outline" size="sm">
              <Link href={`/access-logs/?request_id=${encodedRequestId}`}>
                <ExternalLink data-icon="inline-start" />
                访问日志
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link href={`/security-events/?request_id=${encodedRequestId}`}>
                <ExternalLink data-icon="inline-start" />
                安全事件
              </Link>
            </Button>
          </div>

          <Separator />

          {trace.access_logs.length > 0 && (
            <div className="flex flex-col gap-2">
              {trace.access_logs.slice(0, 3).map((item) => (
                <TraceAccessLogItem key={item.id} item={item} />
              ))}
            </div>
          )}

          {trace.security_events.length > 0 && (
            <div className="flex flex-col gap-2">
              {trace.security_events.slice(0, 3).map((item) => (
                <TraceSecurityEventItem key={item.id} item={item} />
              ))}
            </div>
          )}

          <CopyableBlock
            label="完整追踪 JSON"
            value={JSON.stringify(requestTraceSummary(trace), null, 2)}
            redact
            defaultOpen={false}
          />
        </div>
      )}
    </div>
  )
}
