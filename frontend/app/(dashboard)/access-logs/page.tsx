"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Download, RefreshCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, InlineMeta, PageIntro, Surface, statusToneClass } from "@/components/console-shell";
import { Pagination } from "@/components/pagination";
import { getAccessLogs, type AccessLog } from "@/lib/api";
import { formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

function exportCSV(items: AccessLog[]) {
  const headers = ["ID", "时间", "Request ID", "站点", "IP", "方法", "路径", "状态", "WAF", "缓存", "上游"];
  const rows = items.map((item) => [
    item.id,
    formatDate(item.created_at),
    item.request_id,
    item.host,
    item.client_ip,
    item.method,
    item.path,
    item.status_code,
    item.waf_action,
    item.cache_state,
    item.upstream,
  ]);
  const csv = [headers.join(","), ...rows.map((row) => row.map((value) => `"${String(value ?? "").replace(/"/g, '""')}"`).join(","))].join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `access-logs-${new Date().toISOString().slice(0, 10)}.csv`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default function AccessLogsPage() {
  const [items, setItems] = useState<AccessLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [host, setHost] = useState("");
  const [clientIP, setClientIP] = useState("");
  const [cacheState, setCacheState] = useState("all");
  const [wafAction, setWafAction] = useState("all");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await getAccessLogs({
        page,
        page_size: PAGE_SIZE,
        host: host || undefined,
        client_ip: clientIP || undefined,
        cache_state: cacheState === "all" ? undefined : cacheState,
        waf_action: wafAction === "all" ? undefined : wafAction,
      });
      setItems(response.items ?? []);
      setTotal(response.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [page, host, clientIP, cacheState, wafAction]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const stats = useMemo(() => {
    const hits = items.filter((item) => item.cache_state === "hit").length;
    const misses = items.filter((item) => item.cache_state === "miss").length;
    const blocked = items.filter((item) => item.waf_action !== "none" && item.waf_action !== "observe").length;
    return { hits, misses, blocked };
  }, [items]);

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Request Audit"
        title="访问日志"
        description="基于 /api/v1/access-logs 查看请求结果、缓存命中与上游访问情况，用于排障、审计与缓存验证。"
        actions={
          <>
            <Button variant="secondary" className="rounded-2xl bg-white text-slate-950 hover:bg-slate-100" onClick={load}>
              <RefreshCcw className="mr-2 h-4 w-4" /> 刷新
            </Button>
            <Button variant="secondary" className="rounded-2xl bg-white text-slate-950 hover:bg-slate-100" onClick={() => exportCSV(items)} disabled={items.length === 0}>
              <Download className="mr-2 h-4 w-4" /> 导出 CSV
            </Button>
          </>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <Surface title="当前页统计" description="快速确认缓存与阻断效果。">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <InlineMeta label="记录数" value={items.length.toLocaleString()} />
            <InlineMeta label="缓存命中" value={stats.hits.toLocaleString()} />
            <InlineMeta label="缓存回源" value={stats.misses.toLocaleString()} />
            <InlineMeta label="终端动作" value={stats.blocked.toLocaleString()} />
          </div>
        </Surface>

        <Surface title="筛选条件" description="按 Host、IP、缓存状态与 WAF 动作过滤。">
          <div className="grid gap-3 md:grid-cols-2">
            <Input value={host} onChange={(event) => { setHost(event.target.value); setPage(1); }} placeholder="按 Host 筛选" className="rounded-xl" />
            <Input value={clientIP} onChange={(event) => { setClientIP(event.target.value); setPage(1); }} placeholder="按客户端 IP 筛选" className="rounded-xl" />
            <Select value={cacheState} onValueChange={(value) => { setCacheState(value); setPage(1); }}>
              <SelectTrigger className="rounded-xl"><SelectValue placeholder="缓存状态" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部缓存状态</SelectItem>
                <SelectItem value="hit">命中</SelectItem>
                <SelectItem value="miss">回源</SelectItem>
                <SelectItem value="bypass">绕过</SelectItem>
              </SelectContent>
            </Select>
            <Select value={wafAction} onValueChange={(value) => { setWafAction(value); setPage(1); }}>
              <SelectTrigger className="rounded-xl"><SelectValue placeholder="WAF 动作" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部动作</SelectItem>
                <SelectItem value="none">放行</SelectItem>
                <SelectItem value="observe">观察</SelectItem>
                <SelectItem value="intercept">拦截</SelectItem>
                <SelectItem value="drop">丢弃</SelectItem>
                <SelectItem value="challenge">挑战</SelectItem>
                <SelectItem value="redirect">重定向</SelectItem>
                <SelectItem value="maintenance">维护</SelectItem>
                <SelectItem value="challenge_passed">挑战通过</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </Surface>
      </div>

      <Surface title="日志列表" description="包含缓存状态、WAF 结果与上游目标。">
        {loading ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : items.length === 0 ? (
          <EmptyState title="没有访问日志" description="当前筛选条件下暂无记录，请稍后重试或调整筛选。" />
        ) : (
          <div className="space-y-4">
            <div className="overflow-hidden rounded-[24px] border border-slate-200">
              <table className="min-w-full divide-y divide-slate-200 bg-white text-sm">
                <thead className="bg-slate-50 text-left text-xs uppercase tracking-[0.16em] text-slate-500">
                  <tr>
                    <th className="px-4 py-3">时间</th>
                    <th className="px-4 py-3">Host</th>
                    <th className="px-4 py-3">方法</th>
                    <th className="px-4 py-3">路径</th>
                    <th className="px-4 py-3">状态</th>
                    <th className="px-4 py-3">WAF</th>
                    <th className="px-4 py-3">缓存</th>
                    <th className="px-4 py-3">上游</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {items.map((item) => (
                    <tr key={item.id} className="transition-colors hover:bg-slate-50">
                      <td className="px-4 py-3 text-xs text-slate-500">{formatDate(item.created_at)}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">{item.host}</td>
                      <td className="px-4 py-3 text-xs text-slate-700">{item.method}</td>
                      <td className="max-w-[340px] truncate px-4 py-3 font-mono text-xs text-slate-700">{item.path}</td>
                      <td className="px-4 py-3 text-xs text-slate-700">{item.status_code}</td>
                      <td className="px-4 py-3"><span className={`console-badge ${statusToneClass(item.waf_action)}`}>{item.waf_action}</span></td>
                      <td className="px-4 py-3"><span className={`console-badge ${statusToneClass(item.cache_state)}`}>{item.cache_state}</span></td>
                      <td className="max-w-[260px] truncate px-4 py-3 font-mono text-xs text-slate-500">{item.upstream || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} totalPages={totalPages} total={total} pageSize={PAGE_SIZE} onPageChange={setPage} />
          </div>
        )}
      </Surface>
    </div>
  );
}
