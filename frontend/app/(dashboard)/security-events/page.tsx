"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { useSearchParams } from "next/navigation"
import {
  AlertTriangle,
  Download,
  Eye,
  RefreshCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldBan,
} from "lucide-react"
import { toast } from "sonner"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Pagination } from "@/components/pagination"
import { DetailField, TruncatedCell } from "@/components/log-presentation"
import {
  getSecurityEventStats,
  getSecurityEvents,
  type SecurityEvent,
  type SecurityStats,
} from "@/lib/api"
import {
  getWAFActionMeta,
  wafActionOptions,
  phaseLabels,
  categoryLabels,
} from "@/lib/console"
import { formatDate } from "@/lib/utils"

const PAGE_SIZE = 20

function ActionBadge({ action }: { action: string }) {
  const meta = getWAFActionMeta(action)
  return (
    <Badge className={`rounded-md border text-xs ${meta.className}`}>
      {meta.shortLabel}
    </Badge>
  )
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return "-"
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function exportCSV(events: SecurityEvent[]) {
  const headers = [
    "ID",
    "时间",
    "Request ID",
    "IP",
    "Host",
    "方法",
    "路径",
    "动作",
    "阶段",
    "类别",
    "规则",
    "匹配说明",
  ]
  const rows = events.map((e) => [
    e.id,
    formatDate(e.created_at),
    e.request_id,
    e.client_ip,
    e.host,
    e.method,
    e.path,
    getWAFActionMeta(e.action).label,
    phaseLabels[e.phase] ?? e.phase,
    categoryLabels[e.category] ?? e.category,
    e.rule_id_str || e.rule_id,
    e.match_desc,
  ])
  const csv = [
    headers.join(","),
    ...rows.map((r) =>
      r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")
    ),
  ].join("\n")
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = `security-events-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function SecurityEventsPage() {
  const searchParams = useSearchParams()
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [stats, setStats] = useState<SecurityStats | null>(null)
  const [selected, setSelected] = useState<SecurityEvent | null>(null)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [idSearch, setIdSearch] = useState(() => searchParams.get("id") ?? "")
  const [requestIDSearch, setRequestIDSearch] = useState(
    () => searchParams.get("request_id") ?? ""
  )
  const [action, setAction] = useState(
    () => searchParams.get("action") ?? "all"
  )
  const [category, setCategory] = useState(
    () => searchParams.get("category") ?? "all"
  )
  const [clientIP, setClientIP] = useState(
    () => searchParams.get("client_ip") ?? ""
  )
  const [ruleIdStr, setRuleIdStr] = useState(
    () => searchParams.get("rule_id_str") ?? ""
  )
  const [hostSearch, setHostSearch] = useState(
    () => searchParams.get("host") ?? ""
  )
  const [pathSearch, setPathSearch] = useState(
    () => searchParams.get("path") ?? ""
  )
  const [sinceFilter, setSinceFilter] = useState("")
  const [untilFilter, setUntilFilter] = useState("")
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [eventRes, statsRes] = await Promise.all([
        getSecurityEvents({
          page,
          page_size: PAGE_SIZE,
          id: idSearch || undefined,
          request_id: requestIDSearch || undefined,
          action: action === "all" ? undefined : action,
          category: category === "all" ? undefined : category,
          client_ip: clientIP || undefined,
          rule_id_str: ruleIdStr || undefined,
          host: hostSearch || undefined,
          path: pathSearch || undefined,
          since: sinceFilter ? new Date(sinceFilter).toISOString() : undefined,
          until: untilFilter ? new Date(untilFilter).toISOString() : undefined,
        } as Record<string, unknown>),
        getSecurityEventStats(24),
      ])
      setEvents(eventRes.items ?? [])
      setTotal(eventRes.total ?? 0)
      setStats(statsRes)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败")
    } finally {
      setLoading(false)
    }
  }, [
    idSearch,
    requestIDSearch,
    action,
    category,
    clientIP,
    ruleIdStr,
    hostSearch,
    pathSearch,
    sinceFilter,
    untilFilter,
    page,
  ])

  function resetFilters() {
    setIdSearch("")
    setRequestIDSearch("")
    setAction("all")
    setCategory("all")
    setClientIP("")
    setRuleIdStr("")
    setHostSearch("")
    setPathSearch("")
    setSinceFilter("")
    setUntilFilter("")
    setPage(1)
  }

  useEffect(() => {
    load()
  }, [load])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  // derive stats
  const terminalEvents = useMemo(() => events.filter((evt) => getWAFActionMeta(evt.action).defaultStatus !== "—").length, [events])
  const challengeEvents = useMemo(
    () => events.filter((evt) => evt.action.includes("challenge")).length,
    [events]
  )
  const uniqueIPs = useMemo(
    () => new Set(events.map((evt) => evt.client_ip).filter(Boolean)).size,
    [events]
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">拦截日志</h1>
          <p className="mt-1 text-sm text-slate-500">
            检索拦截、验证、限速与观察事件，分析攻击来源和热点
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 rounded-lg"
            onClick={load}
          >
            <RefreshCcw className="h-3.5 w-3.5" /> 刷新
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 rounded-lg"
            onClick={() => exportCSV(events)}
            disabled={events.length === 0}
          >
            <Download className="h-3.5 w-3.5" /> 导出 CSV
          </Button>
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <Shield className="h-3.5 w-3.5 text-cyan-500" /> 总事件数
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {stats ? stats.total.toLocaleString() : "--"}
          </div>
          <div className="mt-1 text-xs text-slate-400">近 24 小时</div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <ShieldBan className="h-3.5 w-3.5 text-red-500" /> 终止事件
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {terminalEvents.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-slate-400">当前页统计</div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-500" /> 验证事件
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {challengeEvents.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-slate-400">当前页 challenge 动作</div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <ShieldAlert className="h-3.5 w-3.5 text-purple-500" /> 独立攻击IP
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {uniqueIPs}
          </div>
          <div className="mt-1 text-xs text-slate-400">当前页去重</div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="space-y-3 rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              value={idSearch}
              onChange={(e) => {
                setIdSearch(e.target.value)
                setPage(1)
              }}
              placeholder="拦截 ID"
              className="w-[120px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              value={requestIDSearch}
              onChange={(e) => {
                setRequestIDSearch(e.target.value)
                setPage(1)
              }}
              placeholder="Request ID"
              className="w-[180px] rounded-lg pl-8"
            />
          </div>
          <Select
            value={action}
            onValueChange={(v) => {
              setAction(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[140px] rounded-lg">
              <SelectValue placeholder="动作" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部动作</SelectItem>
              {wafActionOptions.map((item) => (
                <SelectItem key={item.value} value={item.value}>
                  {item.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            value={category}
            onValueChange={(v) => {
              setCategory(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-[160px] rounded-lg">
              <SelectValue placeholder="类别" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部类别</SelectItem>
              {Object.entries(categoryLabels).map(([key, label]) => (
                <SelectItem key={key} value={key}>
                  {label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <div className="relative">
            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              value={clientIP}
              onChange={(e) => {
                setClientIP(e.target.value)
                setPage(1)
              }}
              placeholder="搜索 IP"
              className="w-[160px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              value={hostSearch}
              onChange={(e) => {
                setHostSearch(e.target.value)
                setPage(1)
              }}
              placeholder="搜索 Host"
              className="w-[160px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              value={pathSearch}
              onChange={(e) => {
                setPathSearch(e.target.value)
                setPage(1)
              }}
              placeholder="搜索路径"
              className="w-[160px] rounded-lg pl-8"
            />
          </div>
          <div className="relative">
            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              value={ruleIdStr}
              onChange={(e) => {
                setRuleIdStr(e.target.value)
                setPage(1)
              }}
              placeholder="规则 ID"
              className="w-[140px] rounded-lg pl-8"
            />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-slate-500">
            开始时间
            <Input
              type="datetime-local"
              value={sinceFilter}
              onChange={(e) => {
                setSinceFilter(e.target.value)
                setPage(1)
              }}
              className="w-[190px] rounded-lg text-xs"
            />
          </label>
          <label className="flex items-center gap-1.5 text-xs text-slate-500">
            结束时间
            <Input
              type="datetime-local"
              value={untilFilter}
              onChange={(e) => {
                setUntilFilter(e.target.value)
                setPage(1)
              }}
              className="w-[190px] rounded-lg text-xs"
            />
          </label>
          <Button
            variant="ghost"
            size="sm"
            className="text-xs text-slate-500"
            onClick={resetFilters}
          >
            重置筛选
          </Button>
        </div>
      </div>

      {/* Events table */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        {loading ? (
          <div className="p-16 text-center text-sm text-slate-400">
            加载中...
          </div>
        ) : events.length === 0 ? (
          <div className="p-16 text-center text-sm text-slate-400">
            当前筛选条件下没有拦截日志
          </div>
        ) : (
          <>
            <div className="overflow-x-auto overscroll-x-contain">
              <table className="min-w-[1180px] table-fixed text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/80 text-left text-xs font-medium text-slate-500">
                    <th className="w-[150px] px-4 py-3">时间</th>
                    <th className="w-[90px] px-4 py-3">动作</th>
                    <th className="w-[130px] px-4 py-3">类别</th>
                    <th className="w-[80px] px-4 py-3">方法</th>
                    <th className="w-[160px] px-4 py-3">Host</th>
                    <th className="w-[90px] px-4 py-3">状态码</th>
                    <th className="w-[150px] px-4 py-3">源 IP</th>
                    <th className="w-[260px] px-4 py-3">请求路径</th>
                    <th className="w-[210px] px-4 py-3">匹配描述</th>
                    <th className="w-[80px] px-4 py-3 text-right">详情</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {events.map((evt) => (
                    <tr
                      key={evt.id}
                      className="transition-colors hover:bg-slate-50/50"
                    >
                      <td className="px-4 py-3 text-xs whitespace-nowrap text-slate-500">
                        {formatDate(evt.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <ActionBadge action={evt.action} />
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-700">
                        {categoryLabels[evt.category] ?? evt.category}
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-600">
                        {evt.method || "-"}
                      </td>
                      <td className="min-w-0 px-4 py-3 text-xs text-slate-600">
                        <TruncatedCell value={evt.host} />
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">
                        {evt.action === "drop" || evt.status_code === 0
                          ? "DROP"
                          : evt.status_code || "—"}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">
                        {evt.client_ip}
                      </td>
                      <td className="min-w-0 px-4 py-3 text-xs text-slate-600">
                        <TruncatedCell value={evt.path} mono />
                      </td>
                      <td className="min-w-0 px-4 py-3 text-xs text-slate-500">
                        <TruncatedCell value={evt.match_desc} />
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 rounded-md px-2 text-slate-600 hover:text-slate-900"
                          onClick={() => setSelected(evt)}
                        >
                          <Eye className="mr-1 h-3.5 w-3.5" /> 详情
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="border-t border-slate-100 p-3">
              <Pagination
                page={page}
                totalPages={totalPages}
                total={total}
                pageSize={PAGE_SIZE}
                onPageChange={setPage}
              />
            </div>
          </>
        )}
      </div>

      {/* Detail Dialog */}
      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-h-[86vh] max-w-3xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>事件详情</DialogTitle>
            <DialogDescription>完整的拦截日志信息</DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["Request ID", selected.request_id || "-", true],
                ["时间", formatDate(selected.created_at), false],
                ["客户端 IP", selected.client_ip, true],
                ["Host", selected.host || "-", true],
                ["方法", selected.method, true],
                ["阶段", phaseLabels[selected.phase] ?? selected.phase, false],
                [
                  "类别",
                  categoryLabels[selected.category] ?? selected.category,
                  false,
                ],
                ["动作", getWAFActionMeta(selected.action).label, false],
                [
                  "规则",
                  selected.rule_id_str || String(selected.rule_id),
                  true,
                ],
                ["状态码", String(selected.status_code), true],
                ["请求大小", formatBytes(selected.request_size ?? 0), true],
                ["国家", selected.geo_country || "-", false],
                ["城市", selected.geo_city || "-", false],
              ].map(([label, value, mono]) => (
                <DetailField
                  key={String(label)}
                  label={String(label)}
                  value={String(value)}
                  mono={Boolean(mono)}
                />
              ))}
              <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2">
                <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                  路径
                </div>
                <code className="mt-1 block text-xs break-all text-slate-700">
                  {selected.path}
                </code>
              </div>
              <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2">
                <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                  匹配描述
                </div>
                <div className="mt-1 text-sm text-slate-700">
                  {selected.match_desc || "-"}
                </div>
              </div>
              {selected.query_string && (
                <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2">
                  <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                    查询参数
                  </div>
                  <code className="mt-1 block text-xs break-all text-slate-700">
                    {selected.query_string}
                  </code>
                </div>
              )}
              <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2">
                <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                  Request Headers
                </div>
                <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-white p-2 text-xs text-slate-700">
                  {selected.request_headers || "-"}
                </pre>
              </div>
              <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2">
                <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                  Request Body Preview
                </div>
                <pre className="mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-white p-2 text-xs text-slate-700">
                  {selected.request_body_preview || "-"}
                </pre>
                {selected.request_body_truncated && (
                  <div className="mt-2 text-xs text-amber-600">请求体已截断显示</div>
                )}
              </div>
              <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2">
                <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                  User-Agent
                </div>
                <div className="mt-1 text-xs break-all text-slate-600">
                  {selected.user_agent || "-"}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
