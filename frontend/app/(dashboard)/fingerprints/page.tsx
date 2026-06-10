"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { useSearchParams } from "next/navigation"
import { ExternalLink, Eye, RefreshCcw, Search } from "@/lib/icons"
import { toast } from "sonner"
import { deferEffect } from "@/lib/effects"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
import {
  EmptyState,
  MetricCard,
  MetricGrid,
  PageIntro,
  Surface,
} from "@/components/console-shell"
import { Pagination } from "@/components/pagination"
import {
  DetailField,
  redactSensitiveText,
  TruncatedCell,
} from "@/components/log-presentation"
import { getFingerprints, type FingerprintSummary } from "@/lib/api"
import { useAdminRealtime } from "@/lib/admin-realtime"
import { formatDate } from "@/lib/utils"

const PAGE_SIZE = 20

function pageFromSearchParams(searchParams: URLSearchParams) {
  const value = Number(searchParams.get("page") ?? "1")
  return Number.isInteger(value) && value > 0 ? value : 1
}

function fingerprintKey(item: FingerprintSummary, idx: number) {
  return `${item.tls_ja3_hash || "no-ja3"}:${item.tls_ja4 || "no-ja4"}:${idx}`
}

function botScoreFilterHref(item: FingerprintSummary) {
  const params = new URLSearchParams()
  if (item.tls_ja3_hash) params.set("ja3_hash", item.tls_ja3_hash)
  if (item.tls_ja4) params.set("ja4", item.tls_ja4)
  if (item.tls_sni) params.set("tls_sni", item.tls_sni)
  const query = params.toString()
  return query ? `/bot-protection/?${query}` : "/bot-protection/"
}

export default function FingerprintsPage() {
  const searchParams = useSearchParams()
  const realtime = useAdminRealtime()
  const [items, setItems] = useState<FingerprintSummary[]>([])
  const [page, setPage] = useState(() => pageFromSearchParams(searchParams))
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState("")
  const [selected, setSelected] = useState<FingerprintSummary | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await getFingerprints({ page, page_size: PAGE_SIZE })
      setItems(res.items ?? [])
      setTotal(res.total ?? 0)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载指纹失败")
      setItems([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    return deferEffect(load)
  }, [load])

  const realtimeFingerprints =
    page === 1 && !query.trim() ? realtime.fingerprints : null
  const visibleItems = realtimeFingerprints?.items ?? items
  const visibleTotal = realtimeFingerprints?.total ?? total
  const visibleLoading = loading && !realtimeFingerprints

  const filteredItems = useMemo(() => {
    const keyword = query.trim().toLowerCase()
    if (!keyword) return visibleItems
    return visibleItems.filter((item) =>
      [
        item.tls_ja3_hash,
        item.tls_ja4,
        item.tls_version,
        item.tls_alpn,
        item.tls_sni,
      ].some((value) => (value || "").toLowerCase().includes(keyword))
    )
  }, [visibleItems, query])

  const totalPages = Math.max(1, Math.ceil(visibleTotal / PAGE_SIZE))
  const highRiskFingerprints = visibleItems.filter(
    (item) => (item.high_risk_count ?? 0) > 0
  ).length
  const avgBotScore = visibleItems.length
    ? Math.round(
        visibleItems.reduce(
          (sum, item) => sum + (item.avg_bot_score ?? 0),
          0
        ) / visibleItems.length
      )
    : 0

  return (
    <div className="flex flex-col gap-6">
      <PageIntro
        eyebrow="Client Fingerprints"
        title="客户端指纹"
        description="按 JA3 Hash / JA4 聚合 TLS 客户端指纹，用于排查异常客户端、自动化工具和协议兼容问题。"
        actions={
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 rounded-lg"
            onClick={load}
          >
            <RefreshCcw data-icon="inline-start" />
            刷新
          </Button>
        }
      />

      <MetricGrid>
        <MetricCard
          label="聚合指纹"
          value={visibleTotal.toLocaleString()}
          hint={
            realtimeFingerprints ? "实时快照聚合总数" : "后端返回的聚合总数"
          }
        />
        <MetricCard
          label="当前页高风险"
          value={highRiskFingerprints.toLocaleString()}
          hint="当前页有高风险 Bot 样本"
          tone={highRiskFingerprints > 0 ? "danger" : "default"}
        />
        <MetricCard
          label="当前页平均 Bot 分"
          value={avgBotScore.toLocaleString()}
          hint="当前页指纹关联评分均值"
          tone={
            avgBotScore >= 80
              ? "danger"
              : avgBotScore >= 50
                ? "warning"
                : "success"
          }
        />
      </MetricGrid>

      <Surface
        title="TLS 指纹聚合"
        description="展示最近访问日志中采集到的 TLS 指纹、协议参数和最后出现时间；搜索仅筛选当前页数据。"
      >
        <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="relative max-w-xl flex-1">
            <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="当前页筛选 JA3 Hash、JA4、SNI、ALPN、TLS 版本"
              className="rounded-lg pl-9"
            />
          </div>
          <Button asChild variant="outline" size="sm" className="rounded-lg">
            <Link href="/access-logs/">查看请求样本</Link>
          </Button>
        </div>

        {visibleLoading ? (
          <EmptyState
            title="指纹数据加载中"
            description="正在读取最近访问日志聚合出的 TLS 指纹。"
          />
        ) : filteredItems.length === 0 ? (
          <EmptyState
            title="暂无匹配指纹"
            description="请调整当前页筛选条件、切换分页，或等待 HTTPS 请求进入数据面并写入访问日志。"
          />
        ) : (
          <div className="flex flex-col gap-4">
            <div className="rounded-lg border">
              <Table className="min-w-[1040px] table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[230px] px-4">JA3 Hash</TableHead>
                    <TableHead className="w-[260px] px-4">JA4</TableHead>
                    <TableHead className="w-[90px] px-4">TLS</TableHead>
                    <TableHead className="w-[220px] px-4">SNI</TableHead>
                    <TableHead className="w-[100px] px-4 text-right">
                      Bot 均分
                    </TableHead>
                    <TableHead className="w-[100px] px-4 text-right">
                      高风险
                    </TableHead>
                    <TableHead className="w-[90px] px-4 text-right">
                      次数
                    </TableHead>
                    <TableHead className="w-[160px] px-4">最后出现</TableHead>
                    <TableHead className="w-[90px] px-4 text-right">
                      详情
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredItems.map((item, idx) => (
                    <TableRow key={fingerprintKey(item, idx)}>
                      <TableCell className="min-w-0 px-4 text-xs">
                        <TruncatedCell value={item.tls_ja3_hash} mono />
                      </TableCell>
                      <TableCell className="min-w-0 px-4 text-xs">
                        <TruncatedCell value={item.tls_ja4} mono />
                      </TableCell>
                      <TableCell className="px-4 text-xs text-muted-foreground">
                        {item.tls_version || "-"}
                      </TableCell>
                      <TableCell className="min-w-0 px-4 text-xs">
                        <TruncatedCell value={item.tls_sni} />
                      </TableCell>
                      <TableCell className="px-4 text-right font-mono text-xs">
                        {Math.round(item.avg_bot_score ?? 0)}
                      </TableCell>
                      <TableCell className="px-4 text-right font-mono text-xs">
                        {item.high_risk_count ?? 0}
                      </TableCell>
                      <TableCell className="px-4 text-right font-mono text-xs">
                        {item.count}
                      </TableCell>
                      <TableCell className="px-4 text-xs whitespace-nowrap text-muted-foreground">
                        {formatDate(item.last_seen)}
                      </TableCell>
                      <TableCell className="px-4 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="rounded-md px-2"
                          onClick={() => setSelected(item)}
                        >
                          <Eye data-icon="inline-start" />
                          详情
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="flex flex-col gap-3 text-xs text-muted-foreground">
              <span>
                共 {visibleTotal} 条聚合记录，当前页匹配 {filteredItems.length} 条
                {realtimeFingerprints ? " · 实时快照第一页" : ""}
              </span>
              <Pagination
                page={page}
                totalPages={totalPages}
                total={visibleTotal}
                pageSize={PAGE_SIZE}
                onPageChange={setPage}
              />
            </div>
          </div>
        )}
      </Surface>

      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-h-[80vh] max-w-2xl overflow-y-auto rounded-xl">
          <DialogHeader>
            <DialogTitle>指纹详情</DialogTitle>
            <DialogDescription>
              聚合自访问日志的 TLS 客户端指纹字段。
            </DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              <DetailField
                label="JA3 Hash"
                value={selected.tls_ja3_hash || "-"}
                mono
              />
              <DetailField label="JA4" value={selected.tls_ja4 || "-"} mono />
              <DetailField
                label="TLS 版本"
                value={selected.tls_version || "-"}
                mono
              />
              <DetailField label="ALPN" value={selected.tls_alpn || "-"} mono />
              <DetailField label="SNI" value={selected.tls_sni || "-"} mono />
              <DetailField
                label="平均 Bot 分"
                value={Math.round(selected.avg_bot_score ?? 0).toLocaleString()}
                mono
              />
              <DetailField
                label="高风险样本"
                value={(selected.high_risk_count ?? 0).toLocaleString()}
                mono
              />
              <DetailField
                label="出现次数"
                value={selected.count.toLocaleString()}
                mono
              />
              <DetailField
                label="最后出现"
                value={formatDate(selected.last_seen)}
              />
              <DetailField
                label="最近客户端 IP"
                value={selected.last_client_ip || "-"}
                mono
              />
              <DetailField
                className="sm:col-span-2"
                label="最近 User-Agent"
                value={redactSensitiveText(selected.last_user_agent)}
                mono
              />
              <DetailField
                className="sm:col-span-2"
                label="最近 Header Order"
                value={selected.last_header_order || "-"}
                mono
              />
              <Alert className="sm:col-span-2">
                <AlertTitle>样本追踪</AlertTitle>
                <AlertDescription>
                  指纹聚合来自访问日志；可按当前 JA3 Hash、JA4 和 TLS SNI
                  跳转到 Bot 评分日志。
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button asChild variant="outline" size="sm">
                      <Link href={botScoreFilterHref(selected)}>
                        <ExternalLink data-icon="inline-start" />
                        查看 Bot 日志
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
