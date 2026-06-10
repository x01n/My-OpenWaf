"use client"

import { useCallback, useEffect, useId, useState } from "react"
import { useSearchParams } from "next/navigation"
import { AlertTriangle, Eye, Save, RotateCcw, ShieldAlert } from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Pagination } from "@/components/pagination"
import { RequestTracePanel } from "@/components/request-trace-panel"
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
  getBotScores,
  getBotSettings,
  getBotStats,
  getRequestTrace,
  getConfigAppliedReloadFailureDetails,
  isConfigAppliedReloadFailureError,
  updateBotSettings,
  type BotScoreLog,
  type BotScoreStats,
  type BotSettings,
  type RequestTrace,
} from "@/lib/api"
import { formatDate } from "@/lib/utils"

const PAGE_SIZE = 20

function pageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
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

function sameList<T>(left: T[], right: T[]) {
  return (
    left.length === right.length &&
    left.every((item, index) => item === right[index])
  )
}

function buildBotSettingsPatch(
  current: BotSettings,
  baseline: BotSettings
): Partial<BotSettings> {
  const patch: Partial<BotSettings> = {}
  if (current.enabled !== baseline.enabled) {
    patch.enabled = current.enabled
  }
  if (current.score_threshold !== baseline.score_threshold) {
    patch.score_threshold = current.score_threshold
  }
  if (!sameList(current.high_risk_countries, baseline.high_risk_countries)) {
    patch.high_risk_countries = current.high_risk_countries
  }
  if (!sameList(current.datacenter_asns, baseline.datacenter_asns)) {
    patch.datacenter_asns = current.datacenter_asns
  }
  if (!sameList(current.vpn_proxy_asns, baseline.vpn_proxy_asns)) {
    patch.vpn_proxy_asns = current.vpn_proxy_asns
  }
  if (current.geoip_db_path !== baseline.geoip_db_path) {
    patch.geoip_db_path = current.geoip_db_path
  }
  return patch
}

export default function BotProtectionPage() {
  const searchParams = useSearchParams()
  const botEnabledId = useId()
  const botScoreThresholdId = useId()
  const geoipDbPathId = useId()
  const countryInputId = useId()
  const datacenterAsnInputId = useId()
  const vpnAsnInputId = useId()
  const [settings, setSettings] = useState<BotSettings | null>(null)
  const [baselineSettings, setBaselineSettings] = useState<BotSettings | null>(
    null
  )
  const [stats, setStats] = useState<BotScoreStats | null>(null)
  const [logs, setLogs] = useState<BotScoreLog[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [ip, setIP] = useState(() => searchParams.get("ip") ?? "")
  const [minScore, setMinScore] = useState(
    () => searchParams.get("min_score") ?? ""
  )
  const [maxScore, setMaxScore] = useState(
    () => searchParams.get("max_score") ?? ""
  )
  const [hostFilter, setHostFilter] = useState(
    () => searchParams.get("host") ?? ""
  )
  const [pathFilter, setPathFilter] = useState(
    () => searchParams.get("path") ?? ""
  )
  const [userAgentFilter, setUserAgentFilter] = useState(
    () => searchParams.get("user_agent") ?? ""
  )
  const [requestIDFilter, setRequestIDFilter] = useState(
    () => searchParams.get("request_id") ?? ""
  )
  const [ja3HashFilter, setJA3HashFilter] = useState(
    () => searchParams.get("ja3_hash") ?? ""
  )
  const [ja4Filter, setJA4Filter] = useState(
    () => searchParams.get("ja4") ?? ""
  )
  const [tlsSNIFilter, setTLSSNIFilter] = useState(
    () => searchParams.get("tls_sni") ?? ""
  )
  const [startTimeFilter, setStartTimeFilter] = useState(() =>
    dateTimeLocalFromSearchParams(searchParams, "start_time")
  )
  const [endTimeFilter, setEndTimeFilter] = useState(() =>
    dateTimeLocalFromSearchParams(searchParams, "end_time")
  )
  const [highRiskOnly, setHighRiskOnly] = useState(
    () => searchParams.get("high_risk") === "true"
  )
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<BotScoreLog | null>(null)
  const [requestTrace, setRequestTrace] = useState<RequestTrace | null>(null)
  const [traceLoading, setTraceLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [reloadFailureDetails, setReloadFailureDetails] =
    useState<Record<string, unknown> | null>(null)
  const [operationDetails, setOperationDetails] =
    useState<Record<string, unknown> | null>(null)

  // country tag input
  const [countryInput, setCountryInput] = useState("")
  // ASN tag input
  const [datacenterAsnInput, setDatacenterAsnInput] = useState("")
  const [vpnAsnInput, setVpnAsnInput] = useState("")

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [botSettings, botStats, scoreLogs] = await Promise.all([
        getBotSettings(),
        getBotStats(),
        getBotScores({
          page,
          page_size: PAGE_SIZE,
          ip: ip || undefined,
          min_score: minScore ? Number(minScore) : undefined,
          max_score: maxScore ? Number(maxScore) : undefined,
          host: hostFilter || undefined,
          path: pathFilter || undefined,
          user_agent: userAgentFilter || undefined,
          request_id: requestIDFilter || undefined,
          ja3_hash: ja3HashFilter || undefined,
          ja4: ja4Filter || undefined,
          tls_sni: tlsSNIFilter || undefined,
          high_risk: highRiskOnly || undefined,
          start_time: startTimeFilter
            ? new Date(startTimeFilter).toISOString()
            : undefined,
          end_time: endTimeFilter
            ? new Date(endTimeFilter).toISOString()
            : undefined,
        }),
      ])
      setSettings(botSettings)
      setBaselineSettings(botSettings)
      setStats(botStats)
      setLogs(scoreLogs.items ?? [])
      setTotal(scoreLogs.total ?? 0)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载 Bot 数据失败")
      setStats(null)
      setLogs([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [
    ip,
    minScore,
    maxScore,
    hostFilter,
    pathFilter,
    userAgentFilter,
    requestIDFilter,
    ja3HashFilter,
    ja4Filter,
    tlsSNIFilter,
    startTimeFilter,
    endTimeFilter,
    highRiskOnly,
    page,
  ])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  function openDetail(item: BotScoreLog) {
    setSelected(item)
    setRequestTrace(null)
    setTraceLoading(false)
  }

  function closeDetail(open: boolean) {
    if (open) return
    setSelected(null)
    setRequestTrace(null)
    setTraceLoading(false)
  }

  async function loadRequestTrace() {
    if (!selected?.request_id) return
    setTraceLoading(true)
    try {
      setRequestTrace(await getRequestTrace(selected.request_id))
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载请求追踪失败")
    } finally {
      setTraceLoading(false)
    }
  }

  async function save() {
    if (!settings) return
    let submittedPayload: Partial<BotSettings> | null = null
    setSaving(true)
    setReloadFailureDetails(null)
    setOperationDetails(null)
    try {
      const latest = await getBotSettings()
      const patch = buildBotSettingsPatch(settings, baselineSettings ?? latest)
      if (Object.keys(patch).length === 0) {
        setSettings(latest)
        setBaselineSettings(latest)
        setOperationDetails({
          operation: "noop",
          payload: null,
          response: latest,
        })
        toast.success("Bot 配置已是最新")
        return
      }
      submittedPayload = patch
      const response = await updateBotSettings(patch)
      setSettings(response)
      setBaselineSettings(response)
      setOperationDetails({
        operation: "update",
        payload: patch,
        response,
      })
      toast.success("Bot 配置已保存")
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
        const latest = await getBotSettings()
        setSettings(latest)
        setBaselineSettings(latest)
      }
      toast.error(error instanceof Error ? error.message : "保存 Bot 配置失败")
    } finally {
      setSaving(false)
    }
  }

  function addCountry() {
    if (!settings || !countryInput.trim()) return
    const code = countryInput.trim().toUpperCase()
    if (settings.high_risk_countries.includes(code)) {
      setCountryInput("")
      return
    }
    setSettings({
      ...settings,
      high_risk_countries: [...settings.high_risk_countries, code],
    })
    setCountryInput("")
  }

  function removeCountry(code: string) {
    if (!settings) return
    setSettings({
      ...settings,
      high_risk_countries: settings.high_risk_countries.filter(
        (c) => c !== code
      ),
    })
  }

  function addAsn(type: "datacenter" | "vpn") {
    if (!settings) return
    const input = type === "datacenter" ? datacenterAsnInput : vpnAsnInput
    const num = Number(input.trim())
    if (!num || Number.isNaN(num)) return
    const key = type === "datacenter" ? "datacenter_asns" : "vpn_proxy_asns"
    if (settings[key].includes(num)) {
      if (type === "datacenter") setDatacenterAsnInput("")
      else setVpnAsnInput("")
      return
    }
    setSettings({ ...settings, [key]: [...settings[key], num] })
    if (type === "datacenter") setDatacenterAsnInput("")
    else setVpnAsnInput("")
  }

  function removeAsn(type: "datacenter" | "vpn", asn: number) {
    if (!settings) return
    const key = type === "datacenter" ? "datacenter_asns" : "vpn_proxy_asns"
    setSettings({ ...settings, [key]: settings[key].filter((a) => a !== asn) })
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Bot Detection"
        title="Bot 防护"
        description="配置 Bot 检测引擎的全局开关、评分阈值、高风险国家和 ASN 列表，查看评分日志。"
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
            后端已返回 Bot 配置响应体；请核对 item 或 error 字段。
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
          <ShieldAlert />
          <AlertTitle>最近 Bot 配置操作响应</AlertTitle>
          <AlertDescription>
            后端已返回 Bot 配置操作响应体；请核对 operation、payload 与
            response 字段；operation 为 noop 时表示后端最新配置与本地表单一致。
          </AlertDescription>
          <CopyableBlock
            label="Bot 配置操作响应体"
            value={JSON.stringify(operationDetails, null, 2)}
            className="col-span-full"
            redact
            defaultOpen={false}
          />
        </Alert>
      ) : null}

      {settings ? (
        <div className="grid gap-6 xl:grid-cols-2">
          {/* 全局开关和阈值 */}
          <Surface
            title="基本配置"
            description="Bot 检测的全局开关和评分阈值。"
          >
            <FieldGroup className="grid gap-5">
              <Field
                orientation="horizontal"
                className="rounded-xl border bg-muted/35 px-4 py-3"
              >
                <FieldContent>
                  <FieldLabel htmlFor={botEnabledId}>启用 Bot 检测</FieldLabel>
                  <FieldDescription>
                    开启后对所有请求进行 Bot 评分
                  </FieldDescription>
                </FieldContent>
                <Switch
                  id={botEnabledId}
                  checked={settings.enabled}
                  onCheckedChange={(v) =>
                    setSettings({ ...settings, enabled: v })
                  }
                />
              </Field>

              <Field>
                <FieldLabel htmlFor={botScoreThresholdId}>
                  Bot 分数阈值
                </FieldLabel>
                <Input
                  id={botScoreThresholdId}
                  type="number"
                  value={settings.score_threshold}
                  onChange={(e) =>
                    setSettings({
                      ...settings,
                      score_threshold: Number(e.target.value),
                    })
                  }
                  className="rounded-md"
                  placeholder="评分达到此值判定为 Bot"
                />
                <FieldDescription>
                  评分 ≥ 阈值的请求将被判定为 Bot，并同步为 Drop
                  页的自动断连阈值
                </FieldDescription>
              </Field>

              <Field>
                <FieldLabel htmlFor={geoipDbPathId}>
                  GeoIP 数据库路径
                </FieldLabel>
                <Input
                  id={geoipDbPathId}
                  value={settings.geoip_db_path}
                  onChange={(e) =>
                    setSettings({ ...settings, geoip_db_path: e.target.value })
                  }
                  className="rounded-md"
                  placeholder="/path/to/GeoLite2-Country.mmdb"
                />
              </Field>
            </FieldGroup>
          </Surface>

          {/* 配置摘要 */}
          <Surface title="配置摘要" description="当前 Bot 防护策略概览。">
            <div className="grid gap-3 md:grid-cols-2">
              <InlineMeta
                label="运行状态"
                value={
                  <span
                    className={
                      settings.enabled
                        ? "text-foreground"
                        : "text-muted-foreground"
                    }
                  >
                    {settings.enabled ? "● 已启用" : "○ 已关闭"}
                  </span>
                }
              />
              <InlineMeta
                label="分数阈值"
                value={String(settings.score_threshold)}
              />
              <InlineMeta
                label="高风险国家数"
                value={String(settings.high_risk_countries.length)}
              />
              <InlineMeta
                label="数据中心 ASN 数"
                value={String(settings.datacenter_asns.length)}
              />
              <InlineMeta
                label="VPN/代理 ASN 数"
                value={String(settings.vpn_proxy_asns.length)}
              />
              <InlineMeta
                label="GeoIP 路径"
                value={settings.geoip_db_path || "未设置"}
              />
            </div>
          </Surface>

          {/* 风险国家 */}
          <Surface
            title="高风险国家"
            description="来自这些国家的请求将获得更高的 Bot 评分。"
          >
            <FieldGroup className="flex flex-col gap-3">
              <Field>
                <FieldLabel htmlFor={countryInputId}>国家代码</FieldLabel>
                <div className="flex gap-2">
                  <Input
                    id={countryInputId}
                    value={countryInput}
                    onChange={(e) => setCountryInput(e.target.value)}
                    placeholder="输入国家代码（如 CN, RU）"
                    className="rounded-md"
                    onKeyDown={(e) =>
                      e.key === "Enter" && (e.preventDefault(), addCountry())
                    }
                  />
                  <Button
                    variant="outline"
                    className="shrink-0 rounded-md"
                    onClick={addCountry}
                  >
                    添加
                  </Button>
                </div>
              </Field>
              <div className="flex min-h-[40px] flex-wrap gap-2">
                {settings.high_risk_countries.length === 0 ? (
                  <span className="text-sm text-muted-foreground">
                    暂无高风险国家
                  </span>
                ) : (
                  settings.high_risk_countries.map((code) => (
                    <Badge
                      key={code}
                      variant="secondary"
                      className="cursor-pointer"
                      onClick={() => removeCountry(code)}
                    >
                      {code} ×
                    </Badge>
                  ))
                )}
              </div>
            </FieldGroup>
          </Surface>

          {/* ASN 配置 */}
          <Surface
            title="ASN 配置"
            description="数据中心和 VPN/代理的 ASN 列表。"
          >
            <FieldGroup className="flex flex-col gap-5">
              <Field>
                <FieldLabel htmlFor={datacenterAsnInputId}>
                  数据中心 ASN
                </FieldLabel>
                <div className="flex gap-2">
                  <Input
                    id={datacenterAsnInputId}
                    value={datacenterAsnInput}
                    onChange={(e) => setDatacenterAsnInput(e.target.value)}
                    placeholder="输入 ASN 号码"
                    type="number"
                    className="rounded-md"
                    onKeyDown={(e) =>
                      e.key === "Enter" &&
                      (e.preventDefault(), addAsn("datacenter"))
                    }
                  />
                  <Button
                    variant="outline"
                    className="shrink-0 rounded-md"
                    onClick={() => addAsn("datacenter")}
                  >
                    添加
                  </Button>
                </div>
                <div className="flex min-h-[32px] flex-wrap gap-2">
                  {settings.datacenter_asns.map((asn) => (
                    <Badge
                      key={asn}
                      variant="outline"
                      className="cursor-pointer"
                      onClick={() => removeAsn("datacenter", asn)}
                    >
                      AS{asn} ×
                    </Badge>
                  ))}
                </div>
              </Field>

              <Field>
                <FieldLabel htmlFor={vpnAsnInputId}>VPN/代理 ASN</FieldLabel>
                <div className="flex gap-2">
                  <Input
                    id={vpnAsnInputId}
                    value={vpnAsnInput}
                    onChange={(e) => setVpnAsnInput(e.target.value)}
                    placeholder="输入 ASN 号码"
                    type="number"
                    className="rounded-md"
                    onKeyDown={(e) =>
                      e.key === "Enter" && (e.preventDefault(), addAsn("vpn"))
                    }
                  />
                  <Button
                    variant="outline"
                    className="shrink-0 rounded-md"
                    onClick={() => addAsn("vpn")}
                  >
                    添加
                  </Button>
                </div>
                <div className="flex min-h-[32px] flex-wrap gap-2">
                  {settings.vpn_proxy_asns.map((asn) => (
                    <Badge
                      key={asn}
                      variant="outline"
                      className="cursor-pointer"
                      onClick={() => removeAsn("vpn", asn)}
                    >
                      AS{asn} ×
                    </Badge>
                  ))}
                </div>
              </Field>
            </FieldGroup>
          </Surface>
        </div>
      ) : (
        <div className="grid gap-6 xl:grid-cols-2">
          {[1, 2, 3, 4].map((i) => (
            <Surface key={i} className="min-h-[200px]">
              <Skeleton className="h-[160px] rounded-lg" />
            </Surface>
          ))}
        </div>
      )}

      <MetricGrid>
        <MetricCard
          label="24 小时评分"
          value={stats ? stats.total_24h.toLocaleString() : "—"}
          hint="来自后端 Bot 评分表 24 小时聚合。"
        />
        <MetricCard
          label="24 小时拦截"
          value={stats ? stats.blocked_24h.toLocaleString() : "—"}
          hint="后端按 action 为 block / drop 聚合。"
          tone={stats && stats.blocked_24h > 0 ? "danger" : "default"}
        />
        <MetricCard
          label="24 小时高风险"
          value={stats ? stats.high_risk_24h.toLocaleString() : "—"}
          hint="后端按 is_high_risk 聚合。"
          tone={stats && stats.high_risk_24h > 0 ? "warning" : "default"}
        />
        <MetricCard
          label="24 小时平均分"
          value={stats ? stats.avg_score_24h.toFixed(1) : "—"}
          hint="后端返回 avg_score_24h。"
          tone={
            stats && stats.avg_score_24h >= (settings?.score_threshold ?? 60)
              ? "danger"
              : "default"
          }
        />
      </MetricGrid>

      {/* 评分日志表格 */}
      <Surface title="评分日志" description="Bot 检测引擎记录的评分事件。">
        <div className="mb-4 flex flex-wrap gap-3">
          <Input
            value={ip}
            onChange={(e) => {
              setIP(e.target.value)
              setPage(1)
            }}
            placeholder="按 IP 筛选"
            className="w-48 rounded-md"
          />
          <Input
            value={minScore}
            onChange={(e) => {
              setMinScore(e.target.value)
              setPage(1)
            }}
            placeholder="最低分"
            type="number"
            className="w-32 rounded-md"
          />
          <Input
            value={maxScore}
            onChange={(e) => {
              setMaxScore(e.target.value)
              setPage(1)
            }}
            placeholder="最高分"
            type="number"
            className="w-32 rounded-md"
          />
          <Input
            value={ja3HashFilter}
            onChange={(e) => {
              setJA3HashFilter(e.target.value)
              setPage(1)
            }}
            placeholder="按 JA3 Hash 筛选"
            className="w-64 rounded-md"
          />
          <Input
            value={ja4Filter}
            onChange={(e) => {
              setJA4Filter(e.target.value)
              setPage(1)
            }}
            placeholder="按 JA4 筛选"
            className="w-64 rounded-md"
          />
          <Input
            value={tlsSNIFilter}
            onChange={(e) => {
              setTLSSNIFilter(e.target.value)
              setPage(1)
            }}
            placeholder="按 TLS SNI 筛选"
            className="w-56 rounded-md"
          />
          <Input
            value={hostFilter}
            onChange={(e) => {
              setHostFilter(e.target.value)
              setPage(1)
            }}
            placeholder="按 Host 筛选"
            className="w-48 rounded-md"
          />
          <Input
            value={pathFilter}
            onChange={(e) => {
              setPathFilter(e.target.value)
              setPage(1)
            }}
            placeholder="按路径筛选"
            className="w-48 rounded-md"
          />
          <Input
            value={userAgentFilter}
            onChange={(e) => {
              setUserAgentFilter(e.target.value)
              setPage(1)
            }}
            placeholder="按 User-Agent 筛选"
            className="w-56 rounded-md"
          />
          <Input
            value={requestIDFilter}
            onChange={(e) => {
              setRequestIDFilter(e.target.value)
              setPage(1)
            }}
            placeholder="Request ID"
            className="w-56 rounded-md"
          />
          <Input
            type="datetime-local"
            value={startTimeFilter}
            onChange={(e) => {
              setStartTimeFilter(e.target.value)
              setPage(1)
            }}
            aria-label="Bot 评分开始时间"
            className="w-[190px] rounded-md"
          />
          <Input
            type="datetime-local"
            value={endTimeFilter}
            onChange={(e) => {
              setEndTimeFilter(e.target.value)
              setPage(1)
            }}
            aria-label="Bot 评分结束时间"
            className="w-[190px] rounded-md"
          />
          <Button
            type="button"
            variant={highRiskOnly ? "default" : "outline"}
            className="rounded-md"
            onClick={() => {
              setHighRiskOnly((value) => !value)
              setPage(1)
            }}
          >
            <ShieldAlert data-icon="inline-start" />
            仅高风险
          </Button>
          <Button
            variant="outline"
            className="rounded-md"
            onClick={() => {
              setIP("")
              setMinScore("")
              setMaxScore("")
              setJA3HashFilter("")
              setJA4Filter("")
              setTLSSNIFilter("")
              setHostFilter("")
              setPathFilter("")
              setUserAgentFilter("")
              setRequestIDFilter("")
              setStartTimeFilter("")
              setEndTimeFilter("")
              setHighRiskOnly(false)
              setPage(1)
            }}
          >
            <RotateCcw data-icon="inline-start" />
            重置
          </Button>
        </div>

        {loading ? (
          <EmptyState
            title="Bot 评分日志加载中"
            description="正在读取 Bot 评分事件和筛选结果。"
          />
        ) : logs.length === 0 ? (
          <EmptyState
            title="暂无 Bot 评分日志"
            description="当 Bot 检测引擎记录评分事件后，这里会展示客户端 IP、分数与执行动作。"
          />
        ) : (
          <div className="flex flex-col gap-4">
            <div className="overflow-hidden rounded-xl border">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/45 text-xs tracking-wider text-muted-foreground uppercase hover:bg-muted/45">
                    <TableHead>客户端 IP</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>路径</TableHead>
                    <TableHead className="text-center">总分</TableHead>
                    <TableHead className="text-center">GeoIP</TableHead>
                    <TableHead className="text-center">指纹</TableHead>
                    <TableHead className="text-center">行为</TableHead>
                    <TableHead>动作</TableHead>
                    <TableHead>时间</TableHead>
                    <TableHead className="w-16 text-right">详情</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell className="font-mono text-xs">
                        {item.client_ip}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {item.host || "-"}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate font-mono text-xs text-muted-foreground">
                        {redactSensitiveText(item.path)}
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge
                          variant={
                            item.total_score >=
                            (settings?.score_threshold ?? 60)
                              ? "destructive"
                              : "secondary"
                          }
                          className="font-mono"
                        >
                          {item.total_score}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-center text-xs text-muted-foreground">
                        {item.geoip_score}
                      </TableCell>
                      <TableCell className="text-center text-xs text-muted-foreground">
                        {item.fingerprint_score}
                      </TableCell>
                      <TableCell className="text-center text-xs text-muted-foreground">
                        {item.behavior_score}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`console-badge ${statusToneClass(item.action)}`}
                        >
                          {item.action}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs whitespace-nowrap text-muted-foreground">
                        {formatDate(item.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => openDetail(item)}
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

      <Dialog open={!!selected} onOpenChange={closeDetail}>
        <DialogContent className="max-h-[86vh] max-w-3xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>Bot 评分详情</DialogTitle>
            <DialogDescription>
              查看本次评分的请求、指纹、分项分数和后端分析详情。
            </DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["Request ID", selected.request_id || "-"],
                ["站点 ID", selected.site_id ? String(selected.site_id) : "-"],
                ["客户端 IP", selected.client_ip],
                ["Host", selected.host || "-"],
                ["总分", String(selected.total_score)],
                ["GeoIP 分", String(selected.geoip_score)],
                ["指纹分", String(selected.fingerprint_score)],
                ["行为分", String(selected.behavior_score)],
                ["IP 信誉分", String(selected.ip_rep_score)],
                ["高风险", selected.is_high_risk ? "是" : "否"],
                ["动作", selected.action || "-"],
                ["时间", formatDate(selected.created_at)],
              ].map(([label, value]) => (
                <DetailField key={label} label={label} value={value} />
              ))}
              <RequestTracePanel
                requestId={selected.request_id || ""}
                trace={requestTrace}
                loading={traceLoading}
                onLoad={loadRequestTrace}
              />
              {(
                [
                  ["路径", selected.path || "-", true],
                  ["User-Agent", selected.user_agent || "-", true],
                  ["JA3 Hash", selected.tls_ja3_hash || "-", false],
                  ["JA4", selected.tls_ja4 || "-", false],
                  ["TLS 版本", selected.tls_version || "-", false],
                  ["TLS SNI", selected.tls_sni || "-", false],
                  ["ALPN", selected.tls_alpn || "-", false],
                  ["Header Order", selected.header_order || "-", false],
                ] as Array<[string, string, boolean]>
              ).map(([label, value, redact]) => (
                <CopyableBlock
                  key={label}
                  label={label}
                  value={value}
                  as="code"
                  className="sm:col-span-2"
                  contentClassName="text-xs break-all text-foreground"
                  redact={redact}
                />
              ))}
              <CopyableBlock
                label="Details"
                value={selected.details || "-"}
                className="sm:col-span-2"
                contentClassName="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-background p-2 text-xs text-foreground"
                redact
              />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
