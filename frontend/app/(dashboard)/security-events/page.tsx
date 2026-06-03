"use client"

import { useCallback, useEffect, useState } from "react"
import { useSearchParams } from "next/navigation"
import { Download, Eye, RefreshCcw, Search } from "lucide-react"
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
import {
  EmptyState,
  MetricCard,
  MetricGrid,
  PageIntro,
  Surface,
} from "@/components/console-shell"
import {
  CopyableBlock,
  DetailField,
  TruncatedCell,
} from "@/components/log-presentation"
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
    "源 IP",
    "Host",
    "方法",
    "路径",
    "动作",
    "阶段",
    "类别",
    "历史规则",
    "匹配描述",
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
      setEvents([])
      setTotal(0)
      setStats(null)
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

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Security Events"
        title="安全事件"
        description="检索拦截、验证、限速与观察事件，分析攻击来源和热点。"
        actions={
          <>
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
              <Download className="h-3.5 w-3.5" /> 导出当前页 CSV
            </Button>
          </>
        }
      />

      <MetricGrid>
        <MetricCard
          label="总事件数"
          value={stats ? stats.total.toLocaleString() : "--"}
          hint="近 24 小时"
        />
        <MetricCard
          label="终止事件"
          value={stats ? stats.intercepts.toLocaleString() : "--"}
          tone="danger"
          hint="近 24 小时"
        />
        <MetricCard
          label="验证事件"
          value={stats ? stats.challenges.toLocaleString() : "--"}
          tone="warning"
          hint="近 24 小时 challenge 动作"
        />
        <MetricCard
          label="独立请求"
          value={stats ? stats.requests.toLocaleString() : "--"}
          hint="近 24 小时去重 Request ID"
        />
      </MetricGrid>

      <Surface
        title="筛选条件"
        description="动作、类别、时间和请求字段会共同参与后端分页查询，导出仅包含当前页结果。"
      >
        <div className="space-y-3">
          <div className="relative">
            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input
              value={idSearch}
              onChange={(e) => {
                setIdSearch(e.target.value)
                setPage(1)
              }}
              placeholder="事件 ID"
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
              placeholder="搜索 Host（支持站点首个 Host 跳转）"
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
              placeholder="历史规则 ID"
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
      </Surface>

      {/* Events table */}
      <Surface
        title="安全事件列表"
        description={`当前筛选命中 ${total} 条，详情中的请求头和请求体按脱敏与截断策略展示。`}
      >
        {loading ? (
          <div className="p-16 text-center text-sm text-slate-400">
            加载中...
          </div>
        ) : events.length === 0 ? (
          <EmptyState
            title="当前筛选条件下本页没有安全事件"
            description="调整动作、类别、时间、Host、路径、源 IP 或历史规则 ID 后重新查看。"
          />
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
      </Surface>

      {/* Detail Dialog */}
      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-h-[86vh] max-w-3xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>事件详情</DialogTitle>
            <DialogDescription>
              完整的安全事件信息；规则字段为事件产生时记录的历史命中值，关联规则可能已被修改或删除。
            </DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["Request ID", selected.request_id || "-", true, true],
                ["时间", formatDate(selected.created_at), false, false],
                ["客户端 IP", selected.client_ip, true, true],
                ["Host", selected.host || "-", true, true],
                ["方法", selected.method, true, true],
                [
                  "阶段",
                  phaseLabels[selected.phase] ?? selected.phase,
                  false,
                  false,
                ],
                [
                  "类别",
                  categoryLabels[selected.category] ?? selected.category,
                  false,
                  false,
                ],
                ["动作", getWAFActionMeta(selected.action).label, false, false],
                [
                  "历史规则",
                  selected.rule_id_str || String(selected.rule_id),
                  true,
                  true,
                ],
                ["状态码", String(selected.status_code), true, true],
                [
                  "请求大小",
                  formatBytes(selected.request_size ?? 0),
                  true,
                  false,
                ],
                ["国家", selected.geo_country || "-", false, false],
                ["城市", selected.geo_city || "-", false, false],
              ].map(([label, value, mono, copyable]) => (
                <DetailField
                  key={String(label)}
                  label={String(label)}
                  value={String(value)}
                  mono={Boolean(mono)}
                  copyText={copyable ? String(value) : undefined}
                />
              ))}
              <CopyableBlock
                label="路径"
                value={selected.path}
                as="code"
                className="sm:col-span-2"
                contentClassName="max-h-32 overflow-auto text-xs break-all text-slate-700"
              />
              <CopyableBlock
                label="匹配描述"
                value={selected.match_desc || "-"}
                as="div"
                className="sm:col-span-2"
                contentClassName="text-sm break-all text-slate-700"
              />
              {selected.query_string && (
                <CopyableBlock
                  label="查询参数"
                  value={selected.query_string}
                  as="code"
                  className="sm:col-span-2"
                  contentClassName="max-h-32 overflow-auto text-xs break-all text-slate-700"
                />
              )}
              <CopyableBlock
                label="Request Headers"
                value={selected.request_headers || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2">
                <CopyableBlock
                  label="Request Body Preview"
                  value={selected.request_body_preview || "-"}
                  className="border-0 bg-transparent p-0"
                  contentClassName="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-white p-2 text-xs text-slate-700"
                  redact
                  defaultOpen={false}
                />
                {selected.request_body_truncated && (
                  <div className="mt-2 text-xs text-amber-600">
                    请求体已截断显示
                  </div>
                )}
              </div>
              <CopyableBlock
                label="User-Agent"
                value={selected.user_agent || "-"}
                as="div"
                className="sm:col-span-2"
                contentClassName="text-xs break-all text-slate-600"
              />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
