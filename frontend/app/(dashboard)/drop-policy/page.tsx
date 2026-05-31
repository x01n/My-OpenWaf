"use client"

import { useCallback, useEffect, useState } from "react"
import { Save, RotateCcw } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
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
  updateDropPolicy,
  type DropEvent,
  type DropPolicy,
  type DropStats,
} from "@/lib/api"
import { formatDate } from "@/lib/utils"

const PAGE_SIZE = 20

export default function DropPolicyPage() {
  const [policy, setPolicy] = useState<DropPolicy | null>(null)
  const [stats, setStats] = useState<DropStats | null>(null)
  const [events, setEvents] = useState<DropEvent[]>([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [ip, setIP] = useState("")
  const [source, setSource] = useState("all")
  const [saving, setSaving] = useState(false)
  const [loading, setLoading] = useState(true)

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
        }),
      ])
      setPolicy(dropPolicy)
      setStats(dropStats)
      setEvents(dropEvents.items ?? [])
      setTotal(dropEvents.total ?? 0)
    } finally {
      setLoading(false)
    }
  }, [ip, page, source])

  useEffect(() => {
    load()
  }, [load])

  async function save() {
    if (!policy) return
    setSaving(true)
    try {
      const response = await updateDropPolicy(policy)
      setPolicy(response)
      toast.success("阻断策略已保存")
    } catch (error) {
      toast.error(String(error))
    } finally {
      setSaving(false)
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Connection Drop"
        title="阻断策略"
        description="控制主动断连策略——当 Bot 评分或 CVE 检测触发时自动阻断恶意连接，查看最近的阻断事件。"
        actions={
          <Button onClick={save} disabled={saving} className="gap-2">
            <Save className="h-4 w-4" />
            {saving ? "保存中..." : "保存配置"}
          </Button>
        }
      />

      {/* 统计区域 */}
      {stats && (
        <MetricGrid>
          <MetricCard
            label="24h 总阻断"
            value={stats.total_24h.toLocaleString()}
            tone={stats.total_24h > 0 ? "danger" : "default"}
          />
          <MetricCard
            label="Bot 阻断"
            value={stats.by_bot.toLocaleString()}
            hint="来自 Bot 检测引擎"
          />
          <MetricCard
            label="CVE 阻断"
            value={stats.by_cve.toLocaleString()}
            hint="来自 CVE 漏洞检测"
          />
          <MetricCard
            label="规则 + IP 信誉"
            value={(stats.by_rule + stats.by_ip_reputation).toLocaleString()}
            hint={`规则: ${stats.by_rule} / IP信誉: ${stats.by_ip_reputation}`}
          />
        </MetricGrid>
      )}

      {/* 策略配置 */}
      {policy ? (
        <div className="grid gap-6 xl:grid-cols-2">
          <Surface title="策略配置" description="调整自动阻断策略的触发条件。">
            <div className="grid gap-5">
              <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
                <div>
                  <div className="text-sm font-medium text-slate-900">
                    启用全局阻断策略
                  </div>
                  <div className="text-xs text-slate-500">
                    开启后根据评分和规则自动阻断恶意连接
                  </div>
                </div>
                <Switch
                  checked={policy.enabled}
                  onCheckedChange={(v) => setPolicy({ ...policy, enabled: v })}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700">
                  Bot 自动阻断阈值
                </label>
                <Input
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
                <p className="text-xs text-slate-400">
                  Bot 评分 ≥ 此阈值时自动断开连接
                </p>
              </div>

              <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
                <div>
                  <div className="text-sm font-medium text-slate-900">
                    Critical CVE 自动断连
                  </div>
                  <div className="text-xs text-slate-500">
                    检测到 Critical 级别 CVE 攻击时自动阻断
                  </div>
                </div>
                <Switch
                  checked={policy.cve_auto_drop_critical}
                  onCheckedChange={(v) =>
                    setPolicy({ ...policy, cve_auto_drop_critical: v })
                  }
                />
              </div>

              <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
                <div>
                  <div className="text-sm font-medium text-slate-900">
                    High CVE 自动断连
                  </div>
                  <div className="text-xs text-slate-500">
                    检测到 High 级别 CVE 攻击时自动阻断
                  </div>
                </div>
                <Switch
                  checked={policy.cve_auto_drop_high}
                  onCheckedChange={(v) =>
                    setPolicy({ ...policy, cve_auto_drop_high: v })
                  }
                />
              </div>
            </div>
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
                      policy.enabled ? "text-emerald-600" : "text-slate-400"
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
                        ? "text-emerald-600"
                        : "text-slate-400"
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
                        ? "text-emerald-600"
                        : "text-slate-400"
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
        <Surface className="min-h-[280px] animate-pulse">
          <div className="h-full" />
        </Surface>
      )}

      {/* 阻断事件表格 */}
      <Surface title="阻断事件" description="最近的主动断连记录。">
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
          <select
            value={source}
            onChange={(e) => {
              setSource(e.target.value)
              setPage(1)
            }}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-900"
          >
            <option value="all">全部来源</option>
            <option value="bot">Bot</option>
            <option value="cve">CVE</option>
            <option value="rule">规则</option>
            <option value="ip_reputation">IP 信誉</option>
          </select>
          <Button
            variant="outline"
            className="rounded-lg"
            onClick={() => {
              setIP("")
              setSource("all")
              setPage(1)
            }}
          >
            <RotateCcw className="mr-2 h-4 w-4" />
            重置
          </Button>
        </div>

        {loading ? (
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">
            加载中...
          </div>
        ) : events.length === 0 ? (
          <EmptyState
            title="暂无阻断事件"
            description="没有符合筛选条件的主动断连事件。"
          />
        ) : (
          <div className="space-y-4">
            <div className="overflow-hidden rounded-lg border border-slate-200">
              <Table>
                <TableHeader>
                  <TableRow className="bg-slate-50 text-xs tracking-wider text-slate-500 uppercase">
                    <TableHead>时间</TableHead>
                    <TableHead>客户端 IP</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>路径</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead>规则 ID</TableHead>
                    <TableHead>详情</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.map((item) => (
                    <TableRow key={item.id} className="hover:bg-slate-50">
                      <TableCell className="text-xs whitespace-nowrap text-slate-500">
                        {formatDate(item.created_at)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {item.client_ip}
                      </TableCell>
                      <TableCell className="text-sm text-slate-600">
                        {item.host || "-"}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate font-mono text-xs text-slate-500">
                        {item.path}
                      </TableCell>
                      <TableCell>
                        <span
                          className={`console-badge ${statusToneClass(item.source)}`}
                        >
                          {item.source}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-500">
                        {item.rule_id || "-"}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-xs text-slate-500">
                        {item.detail || "-"}
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
    </div>
  )
}
