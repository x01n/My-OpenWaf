"use client"

import { useCallback, useEffect, useState } from "react"
import { Eye, Save, RotateCcw, ShieldAlert } from "lucide-react"
import { toast } from "sonner"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Pagination } from "@/components/pagination"
import {
  EmptyState,
  InlineMeta,
  PageIntro,
  Surface,
  statusToneClass,
} from "@/components/console-shell"
import {
  getBotScores,
  getBotSettings,
  updateBotSettings,
  type BotScoreLog,
  type BotSettings,
} from "@/lib/api"
import { formatDate } from "@/lib/utils"

const PAGE_SIZE = 20

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
  const [settings, setSettings] = useState<BotSettings | null>(null)
  const [baselineSettings, setBaselineSettings] = useState<BotSettings | null>(
    null
  )
  const [logs, setLogs] = useState<BotScoreLog[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [ip, setIP] = useState("")
  const [minScore, setMinScore] = useState("")
  const [hostFilter, setHostFilter] = useState("")
  const [pathFilter, setPathFilter] = useState("")
  const [requestIDFilter, setRequestIDFilter] = useState("")
  const [fingerprintQuery, setFingerprintQuery] = useState("")
  const [highRiskOnly, setHighRiskOnly] = useState(false)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<BotScoreLog | null>(null)
  const [saving, setSaving] = useState(false)

  // country tag input
  const [countryInput, setCountryInput] = useState("")
  // ASN tag input
  const [datacenterAsnInput, setDatacenterAsnInput] = useState("")
  const [vpnAsnInput, setVpnAsnInput] = useState("")

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [botSettings, scoreLogs] = await Promise.all([
        getBotSettings(),
        getBotScores({
          page,
          page_size: PAGE_SIZE,
          ip: ip || undefined,
          min_score: minScore ? Number(minScore) : undefined,
          host: hostFilter || undefined,
          path: pathFilter || undefined,
          request_id: requestIDFilter || undefined,
          ja3_hash: fingerprintQuery || undefined,
          ja4: fingerprintQuery || undefined,
          high_risk: highRiskOnly || undefined,
        }),
      ])
      setSettings(botSettings)
      setBaselineSettings(botSettings)
      setLogs(scoreLogs.items ?? [])
      setTotal(scoreLogs.total ?? 0)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载 Bot 数据失败")
      setLogs([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [
    ip,
    minScore,
    hostFilter,
    pathFilter,
    requestIDFilter,
    fingerprintQuery,
    highRiskOnly,
    page,
  ])

  useEffect(() => {
    load()
  }, [load])

  async function save() {
    if (!settings) return
    setSaving(true)
    try {
      const latest = await getBotSettings()
      const patch = buildBotSettingsPatch(settings, baselineSettings ?? latest)
      if (Object.keys(patch).length === 0) {
        setSettings(latest)
        setBaselineSettings(latest)
        toast.success("Bot 配置已是最新")
        return
      }
      const response = await updateBotSettings(patch)
      setSettings(response)
      setBaselineSettings(response)
      toast.success("Bot 配置已保存")
    } catch (error) {
      toast.error(String(error))
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
    <div className="space-y-6">
      <PageIntro
        eyebrow="Bot Detection"
        title="Bot 防护"
        description="配置 Bot 检测引擎的全局开关、评分阈值、高风险国家和 ASN 列表，查看评分日志。"
        actions={
          <Button onClick={save} disabled={saving} className="gap-2">
            <Save className="h-4 w-4" />
            {saving ? "保存中..." : "保存配置"}
          </Button>
        }
      />

      {settings ? (
        <div className="grid gap-6 xl:grid-cols-2">
          {/* 全局开关和阈值 */}
          <Surface
            title="基本配置"
            description="Bot 检测的全局开关和评分阈值。"
          >
            <div className="grid gap-5">
              <div className="flex items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-3">
                <div>
                  <div className="text-sm font-medium text-slate-900">
                    启用 Bot 检测
                  </div>
                  <div className="text-xs text-slate-500">
                    开启后对所有请求进行 Bot 评分
                  </div>
                </div>
                <Switch
                  checked={settings.enabled}
                  onCheckedChange={(v) =>
                    setSettings({ ...settings, enabled: v })
                  }
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700">
                  Bot 分数阈值
                </label>
                <Input
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
                <p className="text-xs text-slate-400">
                  评分 ≥ 阈值的请求将被判定为 Bot，并同步为 Drop
                  页的自动断连阈值
                </p>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700">
                  GeoIP 数据库路径
                </label>
                <Input
                  value={settings.geoip_db_path}
                  onChange={(e) =>
                    setSettings({ ...settings, geoip_db_path: e.target.value })
                  }
                  className="rounded-md"
                  placeholder="/path/to/GeoLite2-Country.mmdb"
                />
              </div>
            </div>
          </Surface>

          {/* 配置摘要 */}
          <Surface title="配置摘要" description="当前 Bot 防护策略概览。">
            <div className="grid gap-3 md:grid-cols-2">
              <InlineMeta
                label="运行状态"
                value={
                  <span
                    className={
                      settings.enabled ? "text-emerald-600" : "text-slate-400"
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
            <div className="space-y-3">
              <div className="flex gap-2">
                <Input
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
              <div className="flex min-h-[40px] flex-wrap gap-2">
                {settings.high_risk_countries.length === 0 ? (
                  <span className="text-sm text-slate-400">暂无高风险国家</span>
                ) : (
                  settings.high_risk_countries.map((code) => (
                    <Badge
                      key={code}
                      variant="secondary"
                      className="cursor-pointer gap-1 px-3 py-1 text-xs hover:bg-rose-100 hover:text-rose-700"
                      onClick={() => removeCountry(code)}
                    >
                      {code} ×
                    </Badge>
                  ))
                )}
              </div>
            </div>
          </Surface>

          {/* ASN 配置 */}
          <Surface
            title="ASN 配置"
            description="数据中心和 VPN/代理的 ASN 列表。"
          >
            <div className="space-y-5">
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700">
                  数据中心 ASN
                </label>
                <div className="flex gap-2">
                  <Input
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
                      className="cursor-pointer gap-1 px-3 py-1 text-xs hover:bg-rose-100 hover:text-rose-700"
                      onClick={() => removeAsn("datacenter", asn)}
                    >
                      AS{asn} ×
                    </Badge>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700">
                  VPN/代理 ASN
                </label>
                <div className="flex gap-2">
                  <Input
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
                      className="cursor-pointer gap-1 px-3 py-1 text-xs hover:bg-rose-100 hover:text-rose-700"
                      onClick={() => removeAsn("vpn", asn)}
                    >
                      AS{asn} ×
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </Surface>
        </div>
      ) : (
        <div className="grid gap-6 xl:grid-cols-2">
          {[1, 2, 3, 4].map((i) => (
            <Surface key={i} className="min-h-[200px] animate-pulse">
              <div className="h-full" />
            </Surface>
          ))}
        </div>
      )}

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
            value={fingerprintQuery}
            onChange={(e) => {
              setFingerprintQuery(e.target.value)
              setPage(1)
            }}
            placeholder="JA3 Hash 或 JA4"
            className="w-64 rounded-md"
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
            value={requestIDFilter}
            onChange={(e) => {
              setRequestIDFilter(e.target.value)
              setPage(1)
            }}
            placeholder="Request ID"
            className="w-56 rounded-md"
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
            <ShieldAlert className="mr-2 h-4 w-4" />
            仅高风险
          </Button>
          <Button
            variant="outline"
            className="rounded-md"
            onClick={() => {
              setIP("")
              setMinScore("")
              setFingerprintQuery("")
              setHostFilter("")
              setPathFilter("")
              setRequestIDFilter("")
              setHighRiskOnly(false)
              setPage(1)
            }}
          >
            <RotateCcw className="mr-2 h-4 w-4" />
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
          <div className="space-y-4">
            <div className="overflow-hidden rounded-xl border border-slate-200/80">
              <Table>
                <TableHeader>
                  <TableRow className="bg-slate-50 text-xs tracking-wider text-slate-500 uppercase">
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
                    <TableRow key={item.id} className="hover:bg-slate-50">
                      <TableCell className="font-mono text-xs">
                        {item.client_ip}
                      </TableCell>
                      <TableCell className="text-sm text-slate-600">
                        {item.host || "-"}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate font-mono text-xs text-slate-500">
                        {item.path}
                      </TableCell>
                      <TableCell className="text-center">
                        <span
                          className={`inline-flex items-center justify-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                            item.total_score >=
                            (settings?.score_threshold ?? 60)
                              ? "bg-rose-50 text-rose-700"
                              : "bg-slate-100 text-slate-600"
                          }`}
                        >
                          {item.total_score}
                        </span>
                      </TableCell>
                      <TableCell className="text-center text-xs text-slate-500">
                        {item.geoip_score}
                      </TableCell>
                      <TableCell className="text-center text-xs text-slate-500">
                        {item.fingerprint_score}
                      </TableCell>
                      <TableCell className="text-center text-xs text-slate-500">
                        {item.behavior_score}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`console-badge ${statusToneClass(item.action)}`}
                        >
                          {item.action}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs whitespace-nowrap text-slate-500">
                        {formatDate(item.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-8 w-8"
                          onClick={() => setSelected(item)}
                        >
                          <Eye className="h-4 w-4" />
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
                <div
                  key={label}
                  className="rounded-lg border border-slate-100 bg-slate-50 p-3"
                >
                  <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                    {label}
                  </div>
                  <div className="mt-1 text-sm break-all text-slate-700">
                    {value}
                  </div>
                </div>
              ))}
              {[
                ["路径", selected.path || "-"],
                ["User-Agent", selected.user_agent || "-"],
                ["JA3 Hash", selected.tls_ja3_hash || "-"],
                ["JA4", selected.tls_ja4 || "-"],
                ["TLS 版本", selected.tls_version || "-"],
                ["ALPN", selected.tls_alpn || "-"],
                ["Header Order", selected.header_order || "-"],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2"
                >
                  <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                    {label}
                  </div>
                  <code className="mt-1 block text-xs break-all text-slate-700">
                    {value}
                  </code>
                </div>
              ))}
              <div className="rounded-lg border border-slate-100 bg-slate-50 p-3 sm:col-span-2">
                <div className="text-[11px] font-medium tracking-wider text-slate-400 uppercase">
                  Details
                </div>
                <pre className="mt-1 max-h-64 overflow-auto rounded bg-white p-2 text-xs break-all whitespace-pre-wrap text-slate-700">
                  {selected.details || "-"}
                </pre>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
