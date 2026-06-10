"use client"

import { useCallback, useEffect, useId, useState } from "react"
import Link from "next/link"
import { useSearchParams } from "next/navigation"
import { AlertTriangle, ExternalLink, Save, RotateCcw, Eye } from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Pagination } from "@/components/pagination"
import {
  CopyableBlock,
  DetailField,
  redactSensitiveText,
} from "@/components/log-presentation"
import {
  EmptyState,
  InlineMeta,
  MetricCard,
  MetricGrid,
  PageIntro,
  Surface,
  statusToneClass,
} from "@/components/console-shell"
import {
  getDropEvents,
  getDropPolicy,
  getDropStats,
  getConfigAppliedReloadFailureDetails,
  isConfigAppliedReloadFailureError,
  updateDropPolicy,
  type DropEvent,
  type DropPolicy,
  type DropStats,
} from "@/lib/api"
import { formatDate } from "@/lib/utils"

const PAGE_SIZE = 20
const DROP_SOURCES = ["all", "bot", "cve", "rule", "ip_reputation"] as const

function pageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

function dropSourceFromSearchParams(searchParams: URLSearchParams) {
  const source = searchParams.get("source") ?? "all"
  return DROP_SOURCES.includes(source as (typeof DROP_SOURCES)[number])
    ? source
    : "all"
}

function dateTimeLocalFromSearchParams(
  searchParams: URLSearchParams,
  key: string
) {
  const value = searchParams.get(key)
  if (!value) return ""
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ""
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate()
  )}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function relatedEventHref(
  pathname: "/access-logs/" | "/security-events/",
  event: DropEvent
) {
  const params = new URLSearchParams()
  if (event.client_ip) params.set("client_ip", event.client_ip)
  if (event.host) params.set("host", event.host)
  if (event.path) params.set("path", event.path)
  const query = params.toString()
  return query ? `${pathname}?${query}` : pathname
}

function buildDropPolicyPatch(
  current: DropPolicy,
  baseline: DropPolicy
): Partial<DropPolicy> {
  const patch: Partial<DropPolicy> = {}
  if (current.enabled !== baseline.enabled) {
    patch.enabled = current.enabled
  }
  if (current.bot_score_threshold !== baseline.bot_score_threshold) {
    patch.bot_score_threshold = current.bot_score_threshold
  }
  if (current.cve_auto_drop_critical !== baseline.cve_auto_drop_critical) {
    patch.cve_auto_drop_critical = current.cve_auto_drop_critical
  }
  if (current.cve_auto_drop_high !== baseline.cve_auto_drop_high) {
    patch.cve_auto_drop_high = current.cve_auto_drop_high
  }
  return patch
}

export default function DropPolicyPage() {
  const searchParams = useSearchParams()
  const dropPolicyEnabledId = useId()
  const botScoreThresholdId = useId()
  const cveCriticalDropId = useId()
  const cveHighDropId = useId()
  const [policy, setPolicy] = useState<DropPolicy | null>(null)
  const [baselinePolicy, setBaselinePolicy] = useState<DropPolicy | null>(null)
  const [stats, setStats] = useState<DropStats | null>(null)
  const [events, setEvents] = useState<DropEvent[]>([])
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [total, setTotal] = useState(0)
  const [ip, setIP] = useState(() => searchParams.get("ip") ?? "")
  const [source, setSource] = useState(() =>
    dropSourceFromSearchParams(searchParams)
  )
  const [startTimeFilter, setStartTimeFilter] = useState(() =>
    dateTimeLocalFromSearchParams(searchParams, "start_time")
  )
  const [endTimeFilter, setEndTimeFilter] = useState(() =>
    dateTimeLocalFromSearchParams(searchParams, "end_time")
  )
  const [saving, setSaving] = useState(false)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<DropEvent | null>(null)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [dropPolicy, dropStats, dropEvents] = await Promise.all([
        getDropPolicy(),
        getDropStats(),
        getDropEvents({
          page,
          page_size: PAGE_SIZE,
          ip: ip || undefined,
          source: source === "all" ? undefined : source,
          start_time: startTimeFilter
            ? new Date(startTimeFilter).toISOString()
            : undefined,
          end_time: endTimeFilter
            ? new Date(endTimeFilter).toISOString()
            : undefined,
        }),
      ])
      setPolicy(dropPolicy)
      setBaselinePolicy(dropPolicy)
      setStats(dropStats)
      setEvents(dropEvents.items ?? [])
      setTotal(dropEvents.total ?? 0)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载阻断策略失败")
      setEvents([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [endTimeFilter, ip, page, source, startTimeFilter])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  async function save() {
    if (!policy) return
    let submittedPayload: Partial<DropPolicy> | null = null
    setSaving(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      const latest = await getDropPolicy()
      const patch = buildDropPolicyPatch(policy, baselinePolicy ?? latest)
      if (Object.keys(patch).length === 0) {
        setPolicy(latest)
        setBaselinePolicy(latest)
        setOperationDetails({
          operation: "noop",
          payload: null,
          response: latest,
        })
        toast.success("阻断策略已是最新")
        return
      }
      submittedPayload = patch
      const response = await updateDropPolicy(patch)
      setPolicy(response)
      setBaselinePolicy(response)
      setOperationDetails({
        operation: "update",
        payload: patch,
        response,
      })
      toast.success("阻断策略已保存")
    } catch (error) {
      if (isConfigAppliedReloadFailureError(error)) {
        const details =
          getConfigAppliedReloadFailureDetails<Record<string, unknown>>(error)
        if (details) {
          setReloadFailureDetails(details)
          setOperationDetails({
            operation: "update",
            payload: submittedPayload,
            response: details,
          })
        }
        const latest = await getDropPolicy()
        setPolicy(latest)
        setBaselinePolicy(latest)
      }
      toast.error(error instanceof Error ? error.message : "保存阻断策略失败")
    } finally {
      setSaving(false)
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Connection Drop"
        title="阻断策略"
        description="控制主动断连策略——当 Bot 评分或 CVE 检测触发时自动阻断恶意连接，查看最近的阻断事件。"
        actions={
          <Button onClick={save} disabled={saving}>
            <Save data-icon="inline-start" />
            {saving ? "保存中..." : "保存配置"}
          </Button>
        }
      />

      {reloadFailureDetails ? (
        <Alert className="gap-3">
          <AlertTriangle />
          <AlertTitle>配置已保存但运行时重载失败</AlertTitle>
          <AlertDescription>
            后端已返回阻断策略响应体；请核对 item 或 error 字段。
          </AlertDescription>
          <CopyableBlock
            label="reload 失败响应体"
            value={JSON.stringify(reloadFailureDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {operationDetails ? (
        <Alert className="gap-3">
          <Save />
          <AlertTitle>最近阻断策略操作响应</AlertTitle>
          <AlertDescription>
            后端已返回阻断策略操作响应体；请核对 operation、payload 与
            response 字段；operation 为 noop 时表示后端最新策略与本地表单一致。
          </AlertDescription>
          <CopyableBlock
            label="阻断策略操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {/* 统计区域 */}
      {stats && (
        <MetricGrid>
          <MetricCard
            label="24h 总阻断"
            value={stats.total_24h.toLocaleString()}
            tone={stats.total_24h > 0 ? "danger" : "default"}
          />
          <MetricCard
            label="24h Bot 阻断"
            value={stats.by_bot.toLocaleString()}
            hint="来自 Bot 检测引擎"
          />
          <MetricCard
            label="24h CVE 阻断"
            value={stats.by_cve.toLocaleString()}
            hint="来自 CVE 漏洞检测"
          />
          <MetricCard
            label="24h 规则 + IP 信誉"
            value={(stats.by_rule + stats.by_ip_reputation).toLocaleString()}
            hint={`规则: ${stats.by_rule} / IP信誉: ${stats.by_ip_reputation}`}
          />
        </MetricGrid>
      )}

      {/* 策略配置 */}
      {policy ? (
        <div className="grid gap-6 xl:grid-cols-2">
          <Surface title="策略配置" description="调整自动阻断策略的触发条件。">
            <FieldGroup className="grid gap-5">
              <Field
                orientation="horizontal"
                className="rounded-xl border bg-muted/35 px-4 py-3"
              >
                <FieldContent>
                  <FieldLabel htmlFor={dropPolicyEnabledId}>
                    启用全局阻断策略
                  </FieldLabel>
                  <FieldDescription>
                    开启后根据评分和规则自动阻断恶意连接
                  </FieldDescription>
                </FieldContent>
                <Switch
                  id={dropPolicyEnabledId}
                  checked={policy.enabled}
                  onCheckedChange={(v) => setPolicy({ ...policy, enabled: v })}
                />
              </Field>

              <Field>
                <FieldLabel htmlFor={botScoreThresholdId}>
                  Bot 自动阻断阈值
                </FieldLabel>
                <Input
                  id={botScoreThresholdId}
                  type="number"
                  value={policy.bot_score_threshold}
                  onChange={(e) =>
                    setPolicy({
                      ...policy,
                      bot_score_threshold: Number(e.target.value),
                    })
                  }
                  className="rounded-lg"
                />
                <FieldDescription>
                  Bot 页保存分数阈值时会同步到这里；该值是运行时自动断连阈值。
                </FieldDescription>
              </Field>

              <Field
                orientation="horizontal"
                className="rounded-xl border bg-muted/35 px-4 py-3"
              >
                <FieldContent>
                  <FieldLabel htmlFor={cveCriticalDropId}>
                    Critical CVE 自动断连
                  </FieldLabel>
                  <FieldDescription>
                    与全局防护页保持同步；检测到 Critical 级别 CVE
                    攻击时自动阻断
                  </FieldDescription>
                </FieldContent>
                <Switch
                  id={cveCriticalDropId}
                  checked={policy.cve_auto_drop_critical}
                  onCheckedChange={(v) =>
                    setPolicy({ ...policy, cve_auto_drop_critical: v })
                  }
                />
              </Field>

              <Field
                orientation="horizontal"
                className="rounded-xl border bg-muted/35 px-4 py-3"
              >
                <FieldContent>
                  <FieldLabel htmlFor={cveHighDropId}>
                    High CVE 自动断连
                  </FieldLabel>
                  <FieldDescription>
                    与全局防护页保持同步；检测到 High 级别 CVE 攻击时自动阻断
                  </FieldDescription>
                </FieldContent>
                <Switch
                  id={cveHighDropId}
                  checked={policy.cve_auto_drop_high}
                  onCheckedChange={(v) =>
                    setPolicy({ ...policy, cve_auto_drop_high: v })
                  }
                />
              </Field>
            </FieldGroup>
          </Surface>

          <Surface
            title="策略状态"
            description="当前阻断策略各项开关的运行状态。"
          >
            <div className="grid gap-3 md:grid-cols-2">
              <InlineMeta
                label="全局策略"
                value={
                  <span
                    className={
                      policy.enabled
                        ? "text-foreground"
                        : "text-muted-foreground"
                    }
                  >
                    {policy.enabled ? "● 已启用" : "○ 已关闭"}
                  </span>
                }
              />
              <InlineMeta
                label="Bot 阈值"
                value={String(policy.bot_score_threshold)}
              />
              <InlineMeta
                label="Critical CVE"
                value={
                  <span
                    className={
                      policy.cve_auto_drop_critical
                        ? "text-foreground"
                        : "text-muted-foreground"
                    }
                  >
                    {policy.cve_auto_drop_critical ? "● 自动断连" : "○ 关闭"}
                  </span>
                }
              />
              <InlineMeta
                label="High CVE"
                value={
                  <span
                    className={
                      policy.cve_auto_drop_high
                        ? "text-foreground"
                        : "text-muted-foreground"
                    }
                  >
                    {policy.cve_auto_drop_high ? "● 自动断连" : "○ 关闭"}
                  </span>
                }
              />
            </div>
          </Surface>
        </div>
      ) : (
        <Surface className="min-h-[280px]">
          <Skeleton className="h-[220px] rounded-lg" />
        </Surface>
      )}

      {/* 阻断事件表格 */}
      <Surface
        title="阻断事件"
        description="最近的主动断连记录；筛选条件只影响当前列表页。"
      >
        <div className="mb-4 flex flex-wrap gap-3">
          <Input
            value={ip}
            onChange={(e) => {
              setIP(e.target.value)
              setPage(1)
            }}
            placeholder="按客户端 IP 筛选"
            className="w-48 rounded-lg"
          />
          <Select
            value={source}
            onValueChange={(value) => {
              setSource(value)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-36 rounded-lg">
              <SelectValue placeholder="来源" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">全部来源</SelectItem>
                <SelectItem value="bot">Bot</SelectItem>
                <SelectItem value="cve">CVE</SelectItem>
                <SelectItem value="rule">规则</SelectItem>
                <SelectItem value="ip_reputation">IP 信誉</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Input
            type="datetime-local"
            value={startTimeFilter}
            onChange={(e) => {
              setStartTimeFilter(e.target.value)
              setPage(1)
            }}
            aria-label="阻断事件开始时间"
            className="w-[190px] rounded-lg"
          />
          <Input
            type="datetime-local"
            value={endTimeFilter}
            onChange={(e) => {
              setEndTimeFilter(e.target.value)
              setPage(1)
            }}
            aria-label="阻断事件结束时间"
            className="w-[190px] rounded-lg"
          />
          <Button
            variant="outline"
            className="rounded-lg"
            onClick={() => {
              setIP("")
              setSource("all")
              setStartTimeFilter("")
              setEndTimeFilter("")
              setPage(1)
            }}
          >
            <RotateCcw data-icon="inline-start" />
            重置
          </Button>
        </div>

        {loading ? (
          <EmptyState
            title="阻断事件加载中"
            description="正在读取主动断连记录和筛选结果。"
          />
        ) : events.length === 0 ? (
          <EmptyState
            title="暂无阻断事件"
            description="当前筛选条件下本页没有主动断连事件。"
          />
        ) : (
          <div className="flex flex-col gap-4">
            <div className="overflow-hidden rounded-xl border">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/45 text-xs tracking-wider text-muted-foreground uppercase hover:bg-muted/45">
                    <TableHead>时间</TableHead>
                    <TableHead>客户端 IP</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>路径</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead>历史规则 ID</TableHead>
                    <TableHead>详情</TableHead>
                    <TableHead className="w-16 text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell className="text-xs whitespace-nowrap text-muted-foreground">
                        {formatDate(item.created_at)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {item.client_ip}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {item.host || "-"}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate font-mono text-xs text-muted-foreground">
                        {redactSensitiveText(item.path)}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`console-badge ${statusToneClass(item.source)}`}
                        >
                          {item.source}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {item.rule_id || "-"}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                        {redactSensitiveText(item.detail)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setSelected(item)}
                        >
                          <Eye data-icon="inline-start" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <Pagination
              page={page}
              totalPages={totalPages}
              total={total}
              pageSize={PAGE_SIZE}
              onPageChange={setPage}
            />
          </div>
        )}
      </Surface>

      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-h-[80vh] max-w-2xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>阻断事件详情</DialogTitle>
            <DialogDescription>
              来自后端 drop_events 的原始字段。
            </DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["时间", formatDate(selected.created_at), false],
                [
                  "站点 ID",
                  selected.site_id ? String(selected.site_id) : "-",
                  true,
                ],
                ["客户端 IP", selected.client_ip || "-", true],
                ["来源", selected.source || "-", true],
                ["历史规则 ID", selected.rule_id || "-", true],
                ["Host", selected.host || "-", true],
              ].map(([label, value, copyable]) => (
                <DetailField
                  key={String(label)}
                  label={String(label)}
                  value={String(value)}
                  copyText={copyable ? String(value) : undefined}
                />
              ))}
              <CopyableBlock
                label="路径"
                value={selected.path || "-"}
                as="code"
                className="sm:col-span-2"
                contentClassName="max-h-32 overflow-auto text-xs break-all text-foreground"
                redact
              />
              <CopyableBlock
                label="详情"
                value={selected.detail || "-"}
                className="sm:col-span-2"
                redact
              />
              <Alert className="sm:col-span-2">
                <AlertTitle>相关日志</AlertTitle>
                <AlertDescription>
                  按当前阻断事件的客户端 IP、Host 和路径检索访问日志或安全事件。
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button asChild variant="outline" size="sm">
                      <Link href={relatedEventHref("/access-logs/", selected)}>
                        <ExternalLink data-icon="inline-start" />
                        访问日志
                      </Link>
                    </Button>
                    <Button asChild variant="outline" size="sm">
                      <Link
                        href={relatedEventHref(
                          "/security-events/",
                          selected
                        )}
                      >
                        <ExternalLink data-icon="inline-start" />
                        安全事件
                      </Link>
                    </Button>
                  </div>
                </AlertDescription>
              </Alert>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
