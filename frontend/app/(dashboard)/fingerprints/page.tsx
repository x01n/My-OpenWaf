"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { Eye, Fingerprint, RefreshCcw, Search, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState, PageIntro, Surface } from "@/components/console-shell"
import { DetailField, TruncatedCell } from "@/components/log-presentation"
import { getFingerprints, type FingerprintSummary } from "@/lib/api"
import { formatDate } from "@/lib/utils"

const PAGE_SIZE = 20

function fingerprintKey(item: FingerprintSummary, idx: number) {
  return `${item.tls_ja3_hash || "no-ja3"}:${item.tls_ja4 || "no-ja4"}:${idx}`
}

export default function FingerprintsPage() {
  const [items, setItems] = useState<FingerprintSummary[]>([])
  const [page, setPage] = useState(1)
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
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    load()
  }, [load])

  const filteredItems = useMemo(() => {
    const keyword = query.trim().toLowerCase()
    if (!keyword) return items
    return items.filter((item) =>
      [
        item.tls_ja3_hash,
        item.tls_ja4,
        item.tls_version,
        item.tls_alpn,
        item.tls_sni,
      ].some((value) => (value || "").toLowerCase().includes(keyword))
    )
  }, [items, query])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const uniqueSNI = new Set(items.map((item) => item.tls_sni).filter(Boolean))
    .size
  const h2Count = items.filter((item) =>
    (item.tls_alpn || "").includes("h2")
  ).length

  return (
    <div className="space-y-6">
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
            <RefreshCcw className="h-3.5 w-3.5" /> 刷新
          </Button>
        }
      />

      <div className="grid gap-4 md:grid-cols-3">
        <Surface title="聚合指纹" description="当前页统计">
          <div className="flex items-end justify-between">
            <div className="text-3xl font-semibold text-slate-950">
              {total.toLocaleString()}
            </div>
            <Fingerprint className="h-7 w-7 text-cyan-500" />
          </div>
        </Surface>
        <Surface title="SNI 覆盖" description="当前页去重域名">
          <div className="flex items-end justify-between">
            <div className="text-3xl font-semibold text-slate-950">
              {uniqueSNI}
            </div>
            <ShieldCheck className="h-7 w-7 text-emerald-500" />
          </div>
        </Surface>
        <Surface title="HTTP/2 指纹" description="ALPN 包含 h2">
          <div className="flex items-end justify-between">
            <div className="text-3xl font-semibold text-slate-950">
              {h2Count}
            </div>
            <Badge className="border-cyan-200 bg-cyan-50 text-cyan-700">
              h2
            </Badge>
          </div>
        </Surface>
      </div>

      <Surface
        title="TLS 指纹聚合"
        description="展示最近访问日志中采集到的 TLS 指纹、协议参数和最后出现时间。"
      >
        <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="relative max-w-xl flex-1">
            <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="搜索 JA3 Hash、JA4、SNI、ALPN、TLS 版本"
              className="rounded-lg pl-9"
            />
          </div>
          <Button asChild variant="outline" size="sm" className="rounded-lg">
            <Link href="/access-logs/">查看请求样本</Link>
          </Button>
        </div>

        {loading ? (
          <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">
            加载中...
          </div>
        ) : filteredItems.length === 0 ? (
          <EmptyState
            title="暂无匹配指纹"
            description="请调整搜索条件，或等待 HTTPS 请求进入数据面并写入访问日志。"
          />
        ) : (
          <div className="space-y-4">
            <div className="overflow-x-auto overscroll-x-contain rounded-lg border border-slate-200">
              <table className="min-w-[1040px] table-fixed text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/80 text-left text-xs font-medium text-slate-500">
                    <th className="w-[230px] px-4 py-3">JA3 Hash</th>
                    <th className="w-[260px] px-4 py-3">JA4</th>
                    <th className="w-[90px] px-4 py-3">TLS</th>
                    <th className="w-[220px] px-4 py-3">SNI</th>
                    <th className="w-[120px] px-4 py-3">ALPN</th>
                    <th className="w-[90px] px-4 py-3 text-right">次数</th>
                    <th className="w-[160px] px-4 py-3">最后出现</th>
                    <th className="w-[90px] px-4 py-3 text-right">详情</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {filteredItems.map((item, idx) => (
                    <tr
                      key={fingerprintKey(item, idx)}
                      className="hover:bg-slate-50/70"
                    >
                      <td className="min-w-0 px-4 py-3 text-xs">
                        <TruncatedCell value={item.tls_ja3_hash} mono />
                      </td>
                      <td className="min-w-0 px-4 py-3 text-xs">
                        <TruncatedCell value={item.tls_ja4} mono />
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-600">
                        {item.tls_version || "-"}
                      </td>
                      <td className="min-w-0 px-4 py-3 text-xs">
                        <TruncatedCell value={item.tls_sni} />
                      </td>
                      <td className="min-w-0 px-4 py-3 text-xs">
                        <TruncatedCell value={item.tls_alpn} mono />
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-xs">
                        {item.count}
                      </td>
                      <td className="px-4 py-3 text-xs whitespace-nowrap text-slate-500">
                        {formatDate(item.last_seen)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 rounded-md px-2"
                          onClick={() => setSelected(item)}
                        >
                          <Eye className="mr-1 h-3.5 w-3.5" /> 详情
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex flex-col gap-3 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
              <span>
                共 {total} 条聚合记录，当前页匹配 {filteredItems.length} 条
              </span>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  上一页
                </Button>
                <span>
                  {page} / {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                >
                  下一页
                </Button>
              </div>
            </div>
          </div>
        )}
      </Surface>

      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-w-2xl rounded-xl">
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
                label="出现次数"
                value={selected.count.toLocaleString()}
                mono
              />
              <DetailField
                className="sm:col-span-2"
                label="最后出现"
                value={formatDate(selected.last_seen)}
              />
              <div className="rounded-lg border border-cyan-100 bg-cyan-50 p-3 text-xs leading-5 text-cyan-800 sm:col-span-2">
                可以到请求日志按 Host、时间范围或 Request ID
                继续追踪样本；如果需要按 JA3/JA4 直接筛选，请补充后端查询参数。
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
