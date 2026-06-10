"use client"

import { useEffect, useMemo, useState } from "react"
import { Eye, RefreshCcw, Shield, Wifi } from "@/lib/icons"
import { deferEffect } from "@/lib/effects"
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  MetricCard,
  MetricGrid,
  PageIntro,
  Surface,
} from "@/components/console-shell"
import {
  CopyableBlock,
  DetailField,
  redactSensitiveText,
  WAFActionBadge,
} from "@/components/log-presentation"
import { RequestTracePanel } from "@/components/request-trace-panel"
import {
  getDashboardSummary,
  getRequestTrace,
  getSecurityEvent,
  getSecurityEvents,
  getSecurityEventStats,
  getUpstreamStatus,
  type DashboardSummary,
  type RequestTrace,
  type SecurityEvent,
  type SecurityStats,
  type UpstreamStatusItem,
} from "@/lib/api"
import { useAdminRealtime } from "@/lib/admin-realtime"
import { categoryLabels, getWAFActionMeta, phaseLabels } from "@/lib/console"
import { cn, formatBytes, formatDate } from "@/lib/utils"
import { toast } from "sonner"

const PIE_COLORS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
  "var(--muted-foreground)",
]

function fmt(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`
  return value.toLocaleString()
}

function tooltipNumber(value: unknown) {
  return typeof value === "number"
    ? value.toLocaleString()
    : String(value ?? "—")
}

type TabKey = "traffic" | "overview" | "threats"

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<TabKey>("traffic")
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [stats, setStats] = useState<SecurityStats | null>(null)
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [upstreams, setUpstreams] = useState<UpstreamStatusItem[]>([])
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)
  const [requestTrace, setRequestTrace] = useState<RequestTrace | null>(null)
  const [traceLoading, setTraceLoading] = useState(false)
  const [, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [livePoints, setLivePoints] = useState<
    Array<{ time: string; requests: number; qps: number; blocks: number }>
  >([])
  const realtime = useAdminRealtime()

  async function load({ initial = false } = {}) {
    if (initial) setLoading(true)
    setRefreshing(true)
    try {
      const [dashRes, statsRes, eventsRes, upstreamRes] = await Promise.all([
        getDashboardSummary(),
        getSecurityEventStats(24),
        getSecurityEvents({ page_size: 5 }),
        getUpstreamStatus().catch((error) => {
          toast.error(
            error instanceof Error ? error.message : "加载上游状态失败"
          )
          return { items: [], total: 0 }
        }),
      ])
      setSummary(dashRes)
      setStats(statsRes)
      setEvents(eventsRes.items ?? [])
      setUpstreams(upstreamRes.items ?? [])
      setLivePoints((prev) => {
        const now = new Date()
        const point = {
          time: now.toLocaleTimeString("zh-CN", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          requests: dashRes.requests_total,
          qps: Number(dashRes.qps_5s.toFixed(2)),
          blocks: dashRes.waf_blocks,
        }
        return [...prev, point].slice(-30)
      })
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "加载仪表盘数据失败")
    } finally {
      if (initial) setLoading(false)
      setRefreshing(false)
    }
  }

  async function openEventDetail(item: SecurityEvent) {
    setSelectedEvent(item)
    setRequestTrace(null)
    try {
      const detail = await getSecurityEvent(item.id)
      setSelectedEvent((current) =>
        current?.id === item.id ? detail : current
      )
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载事件详情失败")
    }
  }

  function closeEventDetail(open: boolean) {
    if (open) return
    setSelectedEvent(null)
    setRequestTrace(null)
  }

  async function loadEventRequestTrace() {
    if (!selectedEvent?.request_id) return
    setTraceLoading(true)
    try {
      setRequestTrace(await getRequestTrace(selectedEvent.request_id))
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载请求追踪失败")
    } finally {
      setTraceLoading(false)
    }
  }

  useEffect(() => {
    const cleanup = deferEffect(() => load({ initial: true }))
    const timer = setInterval(() => {
      if (document.visibilityState === "visible" && realtime.status !== "open")
        load()
    }, 15000)
    return () => {
      cleanup()
      clearInterval(timer)
    }
  }, [realtime.status])

  const effectiveSummary = realtime.dashboard ?? summary
  const effectiveUpstreams = realtime.upstreams?.items ?? upstreams
  const effectiveEvents = realtime.securityEvents?.items ?? events
  const effectiveLivePoints =
    realtime.dashboardPoints.length > 0 ? realtime.dashboardPoints : livePoints

  const liveTrendData = useMemo(() => {
    if (effectiveLivePoints.length > 0) {
      let prevRequests = effectiveLivePoints[0]?.requests ?? 0
      let prevBlocks = effectiveLivePoints[0]?.blocks ?? 0
      return effectiveLivePoints.map((point, index) => {
        const requests =
          index === 0 ? 0 : Math.max(0, point.requests - prevRequests)
        const blocks = index === 0 ? 0 : Math.max(0, point.blocks - prevBlocks)
        prevRequests = point.requests
        prevBlocks = point.blocks
        return { ...point, requests, blocks }
      })
    }
    return []
  }, [effectiveLivePoints])

  const blockTrendData = useMemo(() => {
    const liveBlocks = liveTrendData.filter((point) => point.blocks > 0)
    if (liveBlocks.length > 0) return liveTrendData
    return []
  }, [liveTrendData])

  const categoryData = useMemo(
    () => (stats?.categories ?? []).filter((c) => c.count > 0),
    [stats]
  )
  const unhealthyUpstreams = useMemo(
    () => effectiveUpstreams.filter((item) => !item.healthy),
    [effectiveUpstreams]
  )

  const tabs = [
    { key: "traffic" as const, label: "流量分析" },
    { key: "overview" as const, label: "安全态势" },
    { key: "threats" as const, label: "防护报告" },
  ]

  const actionLabel = (action: string) => {
    const map: Record<
      string,
      {
        text: string
        variant: "default" | "secondary" | "destructive" | "outline"
      }
    > = {
      intercept: {
        text: "拦截",
        variant: "destructive",
      },
      block: {
        text: "阻断",
        variant: "destructive",
      },
      observe: {
        text: "观察",
        variant: "secondary",
      },
      drop: {
        text: "丢弃",
        variant: "destructive",
      },
      challenge: {
        text: "质询",
        variant: "default",
      },
    }
    return (
      map[action] ?? {
        text: action,
        variant: "outline",
      }
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <PageIntro
        eyebrow="防护控制台"
        title="实时流量与威胁报告"
        description="按控制台运营视角组织指标、上游健康、实时 QPS 与安全事件，优先呈现可行动异常。"
        actions={
          <Button onClick={() => load()} disabled={refreshing} size="lg">
            <RefreshCcw
              data-icon="inline-start"
              className={cn(refreshing && "animate-spin")}
            />
            刷新数据
          </Button>
        }
      />

      {/* Tab bar */}
      <div className="flex items-center gap-2 rounded-lg border border-border bg-card p-1 shadow-sm">
        <ToggleGroup
          type="single"
          value={activeTab}
          onValueChange={(value) => {
            if (
              value === "traffic" ||
              value === "overview" ||
              value === "threats"
            ) {
              setActiveTab(value)
            }
          }}
          variant="outline"
          size="sm"
        >
          {tabs.map((tab) => (
            <ToggleGroupItem key={tab.key} value={tab.key}>
              {tab.label}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <div className="flex-1" />
        <Button
          onClick={() => load()}
          disabled={refreshing}
          variant="ghost"
          size="sm"
        >
          <RefreshCcw
            data-icon="inline-start"
            className={cn(refreshing && "animate-spin")}
          />
          刷新
        </Button>
      </div>

      <MetricGrid>
        {[
          {
            label: "总请求数",
            value: effectiveSummary ? fmt(effectiveSummary.requests_total) : "—",
            tone: "default" as const,
            hint: "累计访问请求",
          },
          {
            label: "2xx 响应数",
            value: effectiveSummary ? fmt(effectiveSummary.status_2xx) : "—",
            tone: "success" as const,
            hint: "上游成功响应",
          },
          {
            label: "独立访客 (UV)",
            value: effectiveSummary ? fmt(effectiveSummary.unique_ips) : "—",
            tone: "default" as const,
            hint: "按客户端 IP 聚合",
          },
          {
            label: "QPS (5s)",
            value: effectiveSummary ? effectiveSummary.qps_5s.toFixed(1) : "—",
            tone: "default" as const,
            hint: "最近 5 秒速率",
          },
          {
            label: "拦截次数",
            value: effectiveSummary ? fmt(effectiveSummary.waf_blocks) : "—",
            tone:
              effectiveSummary && effectiveSummary.waf_blocks > 0
                ? ("warning" as const)
                : ("default" as const),
            hint: "终止类 WAF 动作",
          },
          {
            label: "攻击 IP",
            value: effectiveSummary ? fmt(effectiveSummary.attack_ips) : "—",
            tone:
              effectiveSummary && effectiveSummary.attack_ips > 0
                ? ("danger" as const)
                : ("default" as const),
            hint: "命中攻击特征的 IP",
          },
        ].map((card) => (
          <MetricCard
            key={card.label}
            label={card.label}
            value={card.value}
            tone={card.tone}
            hint={card.hint}
          />
        ))}
      </MetricGrid>

      <MetricGrid>
        {[
          {
            label: "观察事件",
            value: effectiveSummary ? fmt(effectiveSummary.waf_observes) : "—",
            tone: "default" as const,
            hint: "非终止记录动作",
          },
          {
            label: "内置规则命中",
            value: effectiveSummary ? fmt(effectiveSummary.builtin_hits) : "—",
            tone: "warning" as const,
            hint: "内置规则触发次数",
          },
          {
            label: "Bot 评分 24h",
            value: effectiveSummary ? fmt(effectiveSummary.bot_total_24h) : "—",
            tone: "default" as const,
            hint: "最近 24 小时 Bot 评分",
          },
          {
            label: "高风险 Bot 24h",
            value: effectiveSummary
              ? fmt(effectiveSummary.bot_high_risk_24h)
              : "—",
            tone:
              effectiveSummary && effectiveSummary.bot_high_risk_24h > 0
                ? ("danger" as const)
                : ("default" as const),
            hint: "达到高风险阈值",
          },
          {
            label: "CVE 命中 24h",
            value: effectiveSummary ? fmt(effectiveSummary.cve_total_24h) : "—",
            tone:
              effectiveSummary && effectiveSummary.cve_total_24h > 0
                ? ("warning" as const)
                : ("default" as const),
            hint: "CVE 检测命中",
          },
          {
            label: "Drop 事件 24h",
            value: effectiveSummary ? fmt(effectiveSummary.drop_total_24h) : "—",
            tone:
              effectiveSummary && effectiveSummary.drop_total_24h > 0
                ? ("danger" as const)
                : ("default" as const),
            hint: "主动断连事件",
          },
        ].map((card) => (
          <MetricCard
            key={card.label}
            label={card.label}
            value={card.value}
            tone={card.tone}
            hint={card.hint}
          />
        ))}
      </MetricGrid>

      <MetricGrid>
        {[
          {
            label: "4xx 错误数",
            value: effectiveSummary
              ? fmt(effectiveSummary.errors_upstream_4xx)
              : "—",
            tone:
              effectiveSummary && effectiveSummary.errors_upstream_4xx > 0
                ? ("warning" as const)
                : ("default" as const),
            hint: "上游 4xx 响应",
          },
          {
            label: "4xx 错误率",
            value:
              effectiveSummary && effectiveSummary.requests_total > 0
                ? `${((effectiveSummary.errors_upstream_4xx / effectiveSummary.requests_total) * 100).toFixed(2)}%`
                : "0%",
            tone: "default" as const,
            hint: "基于当前摘要统计",
          },
          {
            label: "总拦截数",
            value: effectiveSummary ? fmt(effectiveSummary.waf_blocks) : "—",
            tone:
              effectiveSummary && effectiveSummary.waf_blocks > 0
                ? ("danger" as const)
                : ("default" as const),
            hint: "终止类 WAF 动作",
          },
          {
            label: "总拦截率",
            value:
              effectiveSummary && effectiveSummary.requests_total > 0
                ? `${((effectiveSummary.waf_blocks / effectiveSummary.requests_total) * 100).toFixed(2)}%`
                : "0%",
            tone: "default" as const,
            hint: "基于总请求计算",
          },
          {
            label: "5xx 错误数",
            value: effectiveSummary
              ? fmt(effectiveSummary.errors_upstream_5xx)
              : "—",
            tone:
              effectiveSummary && effectiveSummary.errors_upstream_5xx > 0
                ? ("danger" as const)
                : ("default" as const),
            hint: "上游 5xx 响应",
          },
          {
            label: "5xx 错误率",
            value:
              effectiveSummary && effectiveSummary.requests_total > 0
                ? `${((effectiveSummary.errors_upstream_5xx / effectiveSummary.requests_total) * 100).toFixed(2)}%`
                : "0%",
            tone: "default" as const,
            hint: "基于当前摘要统计",
          },
        ].map((card) => (
          <MetricCard
            key={card.label}
            label={card.label}
            value={card.value}
            tone={card.tone}
            hint={card.hint}
          />
        ))}
      </MetricGrid>

      <div className="grid gap-4 xl:grid-cols-3">
        <Surface title="CVE 命中分布">
          <div className="flex flex-col gap-2">
            {(effectiveSummary?.cve_by_type_24h ?? []).length === 0 ? (
              <div className="rounded-lg border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
                24 小时内暂无 CVE 命中
              </div>
            ) : (
              (effectiveSummary?.cve_by_type_24h ?? [])
                .slice(0, 5)
                .map((item) => (
                  <div
                    key={item.category}
                    className="flex items-center justify-between rounded-lg bg-muted/35 px-3 py-2 text-xs"
                  >
                    <span className="font-medium text-muted-foreground">
                      {item.category || "未分类"}
                    </span>
                    <span className="font-mono text-foreground">
                      {fmt(item.count)}
                    </span>
                  </div>
                ))
            )}
          </div>
        </Surface>
        <Surface title="Drop 来源">
          <div className="flex flex-col gap-2">
            {Object.entries(effectiveSummary?.drop_by_source_24h ?? {}).filter(
              ([, value]) => value > 0
            ).length === 0 ? (
              <div className="rounded-lg border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
                24 小时内暂无主动断连
              </div>
            ) : (
              Object.entries(effectiveSummary?.drop_by_source_24h ?? {})
                .filter(([, value]) => value > 0)
                .map(([source, value]) => (
                  <div
                    key={source}
                    className="flex items-center justify-between rounded-lg bg-muted/35 px-3 py-2 text-xs"
                  >
                    <span className="font-medium text-muted-foreground">
                      {source}
                    </span>
                    <span className="font-mono text-foreground">
                      {fmt(value)}
                    </span>
                  </div>
                ))
            )}
          </div>
        </Surface>
        <Surface title="Bot 风险概览">
          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="rounded-lg bg-muted/35 p-3">
              <div className="text-xs text-muted-foreground">评分</div>
              <div className="mt-1 font-mono text-lg font-bold text-foreground">
                {fmt(effectiveSummary?.bot_total_24h ?? 0)}
              </div>
            </div>
            <div className="rounded-lg bg-destructive/10 p-3">
              <div className="text-xs text-destructive">高风险</div>
              <div className="mt-1 font-mono text-lg font-bold text-destructive">
                {fmt(effectiveSummary?.bot_high_risk_24h ?? 0)}
              </div>
            </div>
            <div className="rounded-lg bg-secondary p-3">
              <div className="text-xs text-secondary-foreground/70">阻断</div>
              <div className="mt-1 font-mono text-lg font-bold text-secondary-foreground">
                {fmt(effectiveSummary?.bot_blocked_24h ?? 0)}
              </div>
            </div>
          </div>
        </Surface>
      </div>

      <Surface
        title="上游健康状态"
        description="主动探测与请求失败会共同更新状态，异常上游会被负载均衡跳过。"
        action={
          <Badge
            variant={unhealthyUpstreams.length ? "destructive" : "default"}
          >
            {effectiveUpstreams.length
              ? `${effectiveUpstreams.length - unhealthyUpstreams.length}/${effectiveUpstreams.length} 健康`
              : "暂无探测数据"}
          </Badge>
        }
      >
        {effectiveUpstreams.length > 0 && (
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {effectiveUpstreams.slice(0, 6).map((item) => (
              <div
                key={item.url}
                className="rounded-lg border border-border bg-muted/35 px-3 py-2"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-xs text-muted-foreground">
                    {item.url}
                  </span>
                  <Badge
                    variant={item.healthy ? "default" : "destructive"}
                    className="shrink-0"
                  >
                    {item.healthy ? "健康" : "异常"}
                  </Badge>
                </div>
                <div className="mt-1 text-[11px] text-muted-foreground">
                  失败 {item.fail_count} 次 ·{" "}
                  {item.checked_at ? formatDate(item.checked_at) : "未检查"}
                </div>
              </div>
            ))}
          </div>
        )}
      </Surface>

      {/* Charts area */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        {/* QPS & Timeline */}
        <div className="col-span-1 flex flex-col gap-4 xl:col-span-3">
          {/* Real-time QPS */}
          <Surface
            title="实时 QPS"
            action={
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Wifi className="size-3.5 text-primary" />
                <span>
                  {liveTrendData.length} 个采样点 ·{" "}
                  {realtime.status === "open" ? "实时通道" : "轮询兜底"}
                </span>
              </div>
            }
          >
            <div className="h-[180px]">
              {liveTrendData.length === 0 ? (
                <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-border text-sm text-muted-foreground">
                  暂无数据
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart
                    data={liveTrendData}
                    margin={{ top: 4, right: 8, left: -20, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="qpsGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop
                          offset="5%"
                          stopColor="var(--chart-1)"
                          stopOpacity={0.28}
                        />
                        <stop
                          offset="95%"
                          stopColor="var(--chart-1)"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="var(--border)"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="time"
                      tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
                      axisLine={false}
                      tickLine={false}
                      width={36}
                    />
                    <Tooltip
                      contentStyle={{
                        borderRadius: 8,
                        border: "1px solid var(--border)",
                        fontSize: 12,
                      }}
                      formatter={tooltipNumber}
                    />
                    <Area
                      type="monotone"
                      dataKey="qps"
                      stroke="var(--chart-1)"
                      strokeWidth={2}
                      fill="url(#qpsGrad)"
                      name="QPS"
                    />
                    <Area
                      type="monotone"
                      dataKey="requests"
                      stroke="var(--chart-2)"
                      strokeWidth={1.6}
                      fill="transparent"
                      name="新增请求"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </Surface>

          {/* Security events table */}
          <Surface
            title="最近安全事件"
            action={<Shield className="size-4 text-primary" />}
            className="p-0"
          >
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/45 text-xs text-muted-foreground">
                  <TableHead className="px-5 py-2.5">时间</TableHead>
                  <TableHead className="px-5 py-2.5">类型</TableHead>
                  <TableHead className="px-5 py-2.5">客户端 IP</TableHead>
                  <TableHead className="px-5 py-2.5">动作</TableHead>
                  <TableHead className="px-5 py-2.5">描述</TableHead>
                  <TableHead className="px-5 py-2.5 text-right">
                    详情
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {effectiveEvents.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      className="px-5 py-10 text-center text-muted-foreground"
                    >
                      暂无安全事件
                    </TableCell>
                  </TableRow>
                ) : (
                  effectiveEvents.map((ev) => {
                    const a = actionLabel(ev.action)
                    return (
                      <TableRow key={ev.id} className="hover:bg-muted/35">
                        <TableCell className="px-5 py-2.5 whitespace-nowrap text-muted-foreground">
                          {formatDate(ev.created_at)}
                        </TableCell>
                        <TableCell className="px-5 py-2.5">
                          <Badge variant="outline">{ev.category || "-"}</Badge>
                        </TableCell>
                        <TableCell className="px-5 py-2.5 font-mono text-[12px] text-muted-foreground">
                          {ev.client_ip}
                        </TableCell>
                        <TableCell className="px-5 py-2.5">
                          <Badge variant={a.variant}>{a.text}</Badge>
                        </TableCell>
                        <TableCell className="max-w-[280px] truncate px-5 py-2.5 text-muted-foreground">
                          {redactSensitiveText(ev.match_desc || ev.path)}
                        </TableCell>
                        <TableCell className="px-5 py-2.5 text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => openEventDetail(ev)}
                          >
                            <Eye data-icon="inline-start" />
                            详情
                          </Button>
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </Surface>
        </div>

        {/* Right sidebar charts */}
        <div className="flex flex-col gap-4">
          {/* Access trend */}
          <Surface
            title="访问情况"
            action={
              <span className="text-xs text-muted-foreground">
                峰值{" "}
                {liveTrendData.length > 0
                  ? fmt(Math.max(...liveTrendData.map((d) => d.requests)))
                  : "0"}
              </span>
            }
          >
            <div className="h-[120px]">
              {liveTrendData.length === 0 ? (
                <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                  暂无
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={120}>
                  <AreaChart
                    data={liveTrendData}
                    margin={{ top: 4, right: 4, left: -20, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="tealGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop
                          offset="5%"
                          stopColor="var(--chart-1)"
                          stopOpacity={0.2}
                        />
                        <stop
                          offset="95%"
                          stopColor="var(--chart-1)"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" hide />
                    <YAxis hide />
                    <Tooltip
                      contentStyle={{
                        borderRadius: 8,
                        border: "1px solid var(--border)",
                        fontSize: 12,
                      }}
                      formatter={tooltipNumber}
                    />
                    <Area
                      type="monotone"
                      dataKey="requests"
                      stroke="var(--chart-1)"
                      strokeWidth={1.5}
                      fill="url(#tealGrad)"
                      name="新增请求"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </Surface>

          {/* Block trend */}
          <Surface
            title="拦截情况"
            action={
              <span className="text-xs text-muted-foreground">
                峰值{" "}
                {blockTrendData.length > 0
                  ? fmt(Math.max(...blockTrendData.map((d) => d.blocks)))
                  : "0"}
              </span>
            }
          >
            <div className="h-[120px]">
              {blockTrendData.length === 0 ? (
                <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                  暂无
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={120}>
                  <AreaChart
                    data={blockTrendData}
                    margin={{ top: 4, right: 4, left: -20, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop
                          offset="5%"
                          stopColor="var(--destructive)"
                          stopOpacity={0.2}
                        />
                        <stop
                          offset="95%"
                          stopColor="var(--destructive)"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" hide />
                    <YAxis hide />
                    <Tooltip
                      contentStyle={{
                        borderRadius: 8,
                        border: "1px solid var(--border)",
                        fontSize: 12,
                      }}
                      formatter={tooltipNumber}
                    />
                    <Area
                      type="monotone"
                      dataKey="blocks"
                      stroke="var(--destructive)"
                      strokeWidth={1.5}
                      fill="url(#redGrad)"
                      name="新增拦截"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </Surface>

          {/* Category distribution */}
          <Surface title="攻击类型分布">
            {categoryData.length === 0 ? (
              <div className="flex h-[140px] items-center justify-center text-xs text-muted-foreground">
                暂无
              </div>
            ) : (
              <>
                <div className="flex justify-center">
                  <ResponsiveContainer width={140} height={140}>
                    <PieChart>
                      <Pie
                        data={categoryData}
                        dataKey="count"
                        nameKey="category"
                        innerRadius={38}
                        outerRadius={60}
                        paddingAngle={3}
                        strokeWidth={0}
                      >
                        {categoryData.map((_, i) => (
                          <Cell
                            key={i}
                            fill={PIE_COLORS[i % PIE_COLORS.length]}
                          />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="mt-2 flex flex-col gap-1.5">
                  {categoryData.slice(0, 5).map((c, i) => (
                    <div
                      key={c.category}
                      className="flex items-center justify-between text-[12px]"
                    >
                      <div className="flex items-center gap-1.5">
                        <span
                          className="size-2 rounded-full"
                          style={{
                            backgroundColor: PIE_COLORS[i % PIE_COLORS.length],
                          }}
                        />
                        <span className="text-muted-foreground">
                          {c.category}
                        </span>
                      </div>
                      <span className="font-medium text-foreground">
                        {fmt(c.count)}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </Surface>
        </div>
      </div>

      <Dialog open={!!selectedEvent} onOpenChange={closeEventDetail}>
        <DialogContent className="max-h-[86vh] max-w-3xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>最近安全事件详情</DialogTitle>
            <DialogDescription>
              来自安全事件详情接口；请求头、请求体和用户输入字段按脱敏策略展示。
            </DialogDescription>
          </DialogHeader>
          {selectedEvent && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["Request ID", selectedEvent.request_id || "-", true, true],
                ["时间", formatDate(selectedEvent.created_at), false, false],
                ["客户端 IP", selectedEvent.client_ip, true, true],
                ["Host", selectedEvent.host || "-", true, true],
                ["方法", selectedEvent.method, true, true],
                [
                  "阶段",
                  phaseLabels[selectedEvent.phase] ?? selectedEvent.phase,
                  false,
                  false,
                ],
                [
                  "类别",
                  categoryLabels[selectedEvent.category] ??
                    selectedEvent.category,
                  false,
                  false,
                ],
                [
                  "动作",
                  getWAFActionMeta(selectedEvent.action).label,
                  false,
                  false,
                ],
                [
                  "历史规则",
                  selectedEvent.rule_id_str || String(selectedEvent.rule_id),
                  true,
                  true,
                ],
                ["状态码", String(selectedEvent.status_code), true, true],
                ["TLS 版本", selectedEvent.tls_version || "-", true, true],
                ["TLS SNI", selectedEvent.tls_sni || "-", true, true],
                ["TLS ALPN", selectedEvent.tls_alpn || "-", true, true],
                ["JA3 Hash", selectedEvent.tls_ja3_hash || "-", true, true],
                ["JA4", selectedEvent.tls_ja4 || "-", true, true],
                ["Header Order", selectedEvent.header_order || "-", true, true],
                [
                  "请求大小",
                  formatBytes(selectedEvent.request_size ?? 0),
                  true,
                  false,
                ],
                ["国家", selectedEvent.geo_country || "-", false, false],
                ["城市", selectedEvent.geo_city || "-", false, false],
              ].map(([label, value, mono, copyable]) => (
                <DetailField
                  key={String(label)}
                  label={String(label)}
                  value={String(value)}
                  mono={Boolean(mono)}
                  copyText={copyable ? String(value) : undefined}
                />
              ))}
              <DetailField
                label="WAF 动作"
                value={<WAFActionBadge action={selectedEvent.action} />}
              />
              <RequestTracePanel
                requestId={selectedEvent.request_id}
                trace={requestTrace}
                loading={traceLoading}
                onLoad={loadEventRequestTrace}
              />
              <CopyableBlock
                label="路径"
                value={selectedEvent.path}
                as="code"
                className="sm:col-span-2"
                contentClassName="max-h-32 overflow-auto text-xs break-all text-foreground"
                redact
              />
              <CopyableBlock
                label="匹配描述"
                value={selectedEvent.match_desc || "-"}
                as="div"
                className="sm:col-span-2"
                contentClassName="text-sm break-all text-foreground"
                redact
              />
              {selectedEvent.query_string && (
                <CopyableBlock
                  label="查询参数"
                  value={selectedEvent.query_string}
                  as="code"
                  className="sm:col-span-2"
                  contentClassName="max-h-32 overflow-auto text-xs break-all text-foreground"
                  redact
                />
              )}
              <CopyableBlock
                label="Request Headers"
                value={selectedEvent.request_headers || "-"}
                className="sm:col-span-2"
                redact
                defaultOpen={false}
              />
              <div className="rounded-lg border bg-muted/35 p-3 sm:col-span-2">
                <CopyableBlock
                  label="Request Body Preview"
                  value={selectedEvent.request_body_preview || "-"}
                  className="border-0 bg-transparent p-0"
                  contentClassName="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-background p-2 text-xs text-foreground"
                  redact
                  defaultOpen={false}
                />
                {selectedEvent.request_body_truncated && (
                  <div className="mt-2 text-xs text-muted-foreground">
                    请求体已截断显示
                  </div>
                )}
              </div>
              <CopyableBlock
                label="JA3"
                value={selectedEvent.tls_ja3 || "-"}
                as="code"
                className="sm:col-span-2"
                contentClassName="max-h-32 overflow-auto text-xs break-all text-foreground"
              />
              <CopyableBlock
                label="User-Agent"
                value={selectedEvent.user_agent || "-"}
                as="div"
                className="sm:col-span-2"
                contentClassName="text-xs break-all text-muted-foreground"
                redact
              />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
