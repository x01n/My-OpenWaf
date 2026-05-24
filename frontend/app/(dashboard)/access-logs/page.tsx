"use client";

import { useCallback, useEffect, useState } from "react";
import { Download, Eye, RefreshCcw, Search } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Pagination } from "@/components/pagination";
import { getAccessLogs, type AccessLog } from "@/lib/api";
import { getWAFActionMeta, wafActionOptions } from "@/lib/console";
import { formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

function StatusBadge({ code }: { code: number }) {
  let cls = "border-slate-200 bg-slate-50 text-slate-600";
  if (code >= 200 && code < 300)
    cls = "border-emerald-200 bg-emerald-50 text-emerald-700";
  else if (code >= 300 && code < 400)
    cls = "border-blue-200 bg-blue-50 text-blue-700";
  else if (code >= 400 && code < 500)
    cls = "border-amber-200 bg-amber-50 text-amber-700";
  else if (code >= 500) cls = "border-red-200 bg-red-50 text-red-700";

  return <Badge className={`${cls} hover:${cls} font-mono`}>{code}</Badge>;
}

function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET: "border-cyan-200 bg-cyan-50 text-cyan-700",
    POST: "border-indigo-200 bg-indigo-50 text-indigo-700",
    PUT: "border-amber-200 bg-amber-50 text-amber-700",
    DELETE: "border-red-200 bg-red-50 text-red-700",
    PATCH: "border-purple-200 bg-purple-50 text-purple-700",
  };
  const cls = colors[method] ?? "border-slate-200 bg-slate-50 text-slate-600";
  return <Badge className={`${cls} hover:${cls} font-mono text-[11px]`}>{method}</Badge>;
}

function ActionBadge({ action }: { action: string }) {
  if (!action) return <span className="text-slate-400">-</span>;
  const meta = getWAFActionMeta(action);
  return <Badge className={`rounded-md border text-xs ${meta.className}`}>{meta.shortLabel}</Badge>;
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return "-";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatLatency(ms: number): string {
  if (!ms || ms === 0) return "-";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function exportCSV(items: AccessLog[]) {
  const headers = [
    "ID", "时间", "Request ID", "Host", "IP", "方法", "路径", "查询参数",
    "状态码", "WAF动作", "缓存状态", "上游", "上游耗时(ms)", "响应大小", "User-Agent",
  ];
  const rows = items.map((i) => [
    i.id, formatDate(i.created_at), i.request_id, i.host,
    i.client_ip, i.method, i.path, i.query_string,
    i.status_code, i.waf_action, i.cache_state, i.upstream,
    i.upstream_latency_ms, i.response_size, i.user_agent,
  ]);
  const csv = [
    headers.join(","),
    ...rows.map((r) => r.map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`).join(",")),
  ].join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `access-logs-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AccessLogsPage() {
  const [items, setItems] = useState<AccessLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<AccessLog | null>(null);

  // Filters
  const [pathSearch, setPathSearch] = useState("");
  const [hostSearch, setHostSearch] = useState("");
  const [clientIP, setClientIP] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [methodFilter, setMethodFilter] = useState("all");
  const [wafActionFilter, setWafActionFilter] = useState("all");
  const [cacheFilter, setCacheFilter] = useState("all");
  const [sinceFilter, setSinceFilter] = useState("");
  const [untilFilter, setUntilFilter] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, unknown> = {
        page,
        page_size: PAGE_SIZE,
      };
      if (pathSearch) params.path = pathSearch;
      if (hostSearch) params.host = hostSearch;
      if (clientIP) params.client_ip = clientIP;
      if (statusFilter !== "all") params.status_group = statusFilter;
      if (methodFilter !== "all") params.method = methodFilter;
      if (wafActionFilter !== "all") params.waf_action = wafActionFilter;
      if (cacheFilter !== "all") params.cache_state = cacheFilter;
      if (sinceFilter) params.since = new Date(sinceFilter).toISOString();
      if (untilFilter) params.until = new Date(untilFilter).toISOString();
      const res = await getAccessLogs(params as Parameters<typeof getAccessLogs>[0]);
      setItems(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [page, pathSearch, hostSearch, clientIP, statusFilter, methodFilter, wafActionFilter, cacheFilter, sinceFilter, untilFilter]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  function resetFilters() {
    setPathSearch(""); setHostSearch(""); setClientIP("");
    setStatusFilter("all"); setMethodFilter("all");
    setWafActionFilter("all"); setCacheFilter("all");
    setSinceFilter(""); setUntilFilter(""); setPage(1);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">访问日志</h1>
          <p className="mt-1 text-sm text-slate-500">
            查看请求结果、状态码、上游响应耗时与 WAF 动作，用于排障与审计
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="gap-1.5 rounded-lg" onClick={load}>
            <RefreshCcw className="h-3.5 w-3.5" /> 刷新
          </Button>
          <Button variant="outline" size="sm" className="gap-1.5 rounded-lg" onClick={() => exportCSV(items)} disabled={items.length === 0}>
            <Download className="h-3.5 w-3.5" /> 导出 CSV
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="space-y-3 rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input value={pathSearch} onChange={(e) => { setPathSearch(e.target.value); setPage(1); }} placeholder="搜索路径" className="w-[180px] rounded-lg pl-8" />
          </div>
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input value={hostSearch} onChange={(e) => { setHostSearch(e.target.value); setPage(1); }} placeholder="搜索 Host" className="w-[160px] rounded-lg pl-8" />
          </div>
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input value={clientIP} onChange={(e) => { setClientIP(e.target.value); setPage(1); }} placeholder="搜索源 IP" className="w-[160px] rounded-lg pl-8" />
          </div>
          <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setPage(1); }}>
            <SelectTrigger className="w-[130px] rounded-lg"><SelectValue placeholder="状态码" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部状态码</SelectItem>
              <SelectItem value="2xx">2xx 成功</SelectItem>
              <SelectItem value="3xx">3xx 重定向</SelectItem>
              <SelectItem value="4xx">4xx 客户端错误</SelectItem>
              <SelectItem value="5xx">5xx 服务端错误</SelectItem>
            </SelectContent>
          </Select>
          <Select value={methodFilter} onValueChange={(v) => { setMethodFilter(v); setPage(1); }}>
            <SelectTrigger className="w-[110px] rounded-lg"><SelectValue placeholder="方法" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部方法</SelectItem>
              {HTTP_METHODS.map((m) => (<SelectItem key={m} value={m}>{m}</SelectItem>))}
            </SelectContent>
          </Select>
          <Select value={wafActionFilter} onValueChange={(v) => { setWafActionFilter(v); setPage(1); }}>
            <SelectTrigger className="w-[130px] rounded-lg"><SelectValue placeholder="WAF 动作" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部 WAF</SelectItem>
              {wafActionOptions.map((item) => (<SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>))}
            </SelectContent>
          </Select>
          <Select value={cacheFilter} onValueChange={(v) => { setCacheFilter(v); setPage(1); }}>
            <SelectTrigger className="w-[120px] rounded-lg"><SelectValue placeholder="缓存" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部缓存</SelectItem>
              <SelectItem value="HIT">命中</SelectItem>
              <SelectItem value="MISS">未命中</SelectItem>
              <SelectItem value="BYPASS">跳过</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-slate-500">
            开始时间
            <Input type="datetime-local" value={sinceFilter} onChange={(e) => { setSinceFilter(e.target.value); setPage(1); }} className="w-[190px] rounded-lg text-xs" />
          </label>
          <label className="flex items-center gap-1.5 text-xs text-slate-500">
            结束时间
            <Input type="datetime-local" value={untilFilter} onChange={(e) => { setUntilFilter(e.target.value); setPage(1); }} className="w-[190px] rounded-lg text-xs" />
          </label>
          <Button variant="ghost" size="sm" className="text-xs text-slate-500" onClick={resetFilters}>重置筛选</Button>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        {loading ? (
          <div className="p-16 text-center text-sm text-slate-400">加载中...</div>
        ) : items.length === 0 ? (
          <div className="p-16 text-center text-sm text-slate-400">
            当前筛选条件下暂无访问日志
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/80 text-left text-xs font-medium text-slate-500">
                    <th className="px-4 py-3">时间</th>
                    <th className="px-4 py-3">方法</th>
                    <th className="px-4 py-3">Host</th>
                    <th className="px-4 py-3">路径</th>
                    <th className="px-4 py-3">状态码</th>
                    <th className="px-4 py-3">源 IP</th>
                    <th className="px-4 py-3">WAF</th>
                    <th className="px-4 py-3">上游耗时</th>
                    <th className="px-4 py-3">响应大小</th>
                    <th className="px-4 py-3 text-right">详情</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {items.map((item) => (
                    <tr key={item.id} className="transition-colors hover:bg-slate-50/50">
                      <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                        {formatDate(item.created_at)}
                      </td>
                      <td className="px-4 py-3"><MethodBadge method={item.method} /></td>
                      <td className="max-w-[140px] truncate px-4 py-3 text-xs text-slate-600" title={item.host}>
                        {item.host || "-"}
                      </td>
                      <td className="max-w-[240px] truncate px-4 py-3 font-mono text-xs text-slate-600" title={item.path}>
                        {item.path}
                      </td>
                      <td className="px-4 py-3"><StatusBadge code={item.status_code} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">{item.client_ip}</td>
                      <td className="px-4 py-3"><ActionBadge action={item.waf_action} /></td>
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-500">
                        {formatLatency(item.upstream_latency_ms)}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-slate-500">
                        {formatBytes(item.response_size)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button variant="ghost" size="sm" className="h-7 rounded-md px-2 text-slate-600 hover:text-slate-900" onClick={() => setSelected(item)}>
                          <Eye className="mr-1 h-3.5 w-3.5" /> 详情
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="border-t border-slate-100 p-3">
              <Pagination page={page} totalPages={totalPages} total={total} pageSize={PAGE_SIZE} onPageChange={setPage} />
            </div>
          </>
        )}
      </div>

      {/* Detail Dialog */}
      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-w-2xl rounded-xl">
          <DialogHeader>
            <DialogTitle>请求详情</DialogTitle>
            <DialogDescription>完整的访问日志信息</DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              {([
                ["Request ID", selected.request_id || "-"],
                ["时间", formatDate(selected.created_at)],
                ["客户端 IP", selected.client_ip],
                ["Host", selected.host || "-"],
                ["方法", selected.method],
                ["状态码", String(selected.status_code)],
                ["WAF 动作", selected.waf_action ? getWAFActionMeta(selected.waf_action).label : "-"],
                ["缓存状态", selected.cache_state || "-"],
                ["上游服务器", selected.upstream || "-"],
                ["上游耗时", formatLatency(selected.upstream_latency_ms)],
                ["响应大小", formatBytes(selected.response_size)],
                ["站点 ID", String(selected.site_id)],
              ] as [string, string][]).map(([label, value]) => (
                <div key={label} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">{label}</div>
                  <div className="mt-1 text-sm font-medium text-slate-900">{value}</div>
                </div>
              ))}
              <div className="sm:col-span-2 rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">路径</div>
                <code className="mt-1 block break-all text-xs text-slate-700">{selected.path}</code>
              </div>
              {selected.query_string && (
                <div className="sm:col-span-2 rounded-lg border border-slate-100 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">查询参数</div>
                  <code className="mt-1 block break-all text-xs text-slate-700">{selected.query_string}</code>
                </div>
              )}
              <div className="sm:col-span-2 rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">User-Agent</div>
                <div className="mt-1 break-all text-xs text-slate-600">{selected.user_agent || "-"}</div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
