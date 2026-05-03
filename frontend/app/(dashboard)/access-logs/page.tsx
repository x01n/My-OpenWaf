"use client";

import { useCallback, useEffect, useState } from "react";
import { Download, RefreshCcw, Search } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Pagination } from "@/components/pagination";
import { getAccessLogs, type AccessLog } from "@/lib/api";
import { formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

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

function exportCSV(items: AccessLog[]) {
  const headers = [
    "ID", "时间", "Request ID", "站点", "IP", "方法", "路径",
    "状态", "WAF", "缓存", "上游",
  ];
  const rows = items.map((i) => [
    i.id, formatDate(i.created_at), i.request_id, i.host,
    i.client_ip, i.method, i.path, i.status_code,
    i.waf_action, i.cache_state, i.upstream,
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
  const [pathSearch, setPathSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [clientIP, setClientIP] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, unknown> = {
        page,
        page_size: PAGE_SIZE,
      };
      if (pathSearch) params.path = pathSearch;
      if (clientIP) params.client_ip = clientIP;
      // status filter: 2xx, 3xx, 4xx, 5xx
      // API doesn't have status_code filter directly, but pass it
      if (statusFilter !== "all") {
        params.status_group = statusFilter;
      }
      const res = await getAccessLogs(params as Parameters<typeof getAccessLogs>[0]);
      setItems(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [page, pathSearch, statusFilter, clientIP]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">访问日志</h1>
          <p className="mt-1 text-sm text-slate-500">
            查看请求结果、状态码与上游响应，用于排障与审计
          </p>
        </div>
        <div className="flex items-center gap-2">
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
            onClick={() => exportCSV(items)}
            disabled={items.length === 0}
          >
            <Download className="h-3.5 w-3.5" /> 导出 CSV
          </Button>
        </div>
      </div>

      {/* Search / Filter bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
          <Input
            value={pathSearch}
            onChange={(e) => { setPathSearch(e.target.value); setPage(1); }}
            placeholder="搜索路径"
            className="w-[200px] rounded-lg pl-8"
          />
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
          <Input
            value={clientIP}
            onChange={(e) => { setClientIP(e.target.value); setPage(1); }}
            placeholder="搜索源 IP"
            className="w-[180px] rounded-lg pl-8"
          />
        </div>
        <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setPage(1); }}>
          <SelectTrigger className="w-[140px] rounded-lg">
            <SelectValue placeholder="状态码" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态码</SelectItem>
            <SelectItem value="2xx">2xx 成功</SelectItem>
            <SelectItem value="3xx">3xx 重定向</SelectItem>
            <SelectItem value="4xx">4xx 客户端错误</SelectItem>
            <SelectItem value="5xx">5xx 服务端错误</SelectItem>
          </SelectContent>
        </Select>
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
                    <th className="px-4 py-3">路径</th>
                    <th className="px-4 py-3">状态码</th>
                    <th className="px-4 py-3">源 IP</th>
                    <th className="px-4 py-3">WAF</th>
                    <th className="px-4 py-3">上游</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {items.map((item) => (
                    <tr
                      key={item.id}
                      className="transition-colors hover:bg-slate-50/50"
                    >
                      <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                        {formatDate(item.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <MethodBadge method={item.method} />
                      </td>
                      <td className="max-w-[300px] truncate px-4 py-3 font-mono text-xs text-slate-600">
                        {item.path}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge code={item.status_code} />
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">
                        {item.client_ip}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">
                        {item.waf_action || "-"}
                      </td>
                      <td className="max-w-[200px] truncate px-4 py-3 font-mono text-xs text-slate-400">
                        {item.upstream || "-"}
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
      </div>
    </div>
  );
}
