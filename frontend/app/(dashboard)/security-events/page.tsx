"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Download,
  Eye,
  RefreshCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldBan,
} from "lucide-react";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Pagination } from "@/components/pagination";
import {
  getSecurityEventStats,
  getSecurityEvents,
  type SecurityEvent,
  type SecurityStats,
} from "@/lib/api";
import { getWAFActionMeta, wafActionOptions } from "@/lib/console";
import { formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

function ActionBadge({ action }: { action: string }) {
  const meta = getWAFActionMeta(action);
  return <Badge className={`rounded-md border text-xs ${meta.className}`}>{meta.shortLabel}</Badge>;
}

function exportCSV(events: SecurityEvent[]) {
  const headers = [
    "ID", "时间", "Request ID", "IP", "Host", "方法", "路径",
    "动作", "阶段", "类别", "规则", "匹配说明",
  ];
  const rows = events.map((e) => [
    e.id, formatDate(e.created_at), e.request_id, e.client_ip,
    e.host, e.method, e.path, e.action, e.phase, e.category,
    e.rule_id_str || e.rule_id, e.match_desc,
  ]);
  const csv = [
    headers.join(","),
    ...rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")),
  ].join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `security-events-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function SecurityEventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [stats, setStats] = useState<SecurityStats | null>(null);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [action, setAction] = useState("all");
  const [category, setCategory] = useState("all");
  const [clientIP, setClientIP] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [eventRes, statsRes] = await Promise.all([
        getSecurityEvents({
          page,
          page_size: PAGE_SIZE,
          action: action === "all" ? undefined : action,
          category: category === "all" ? undefined : category,
          client_ip: clientIP || undefined,
        }),
        getSecurityEventStats(24),
      ]);
      setEvents(eventRes.items ?? []);
      setTotal(eventRes.total ?? 0);
      setStats(statsRes);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [action, category, clientIP, page]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  // derive stats
  const terminalEvents = useMemo(
    () => stats?.categories?.reduce((s, c) => s + c.count, 0) ?? 0,
    [stats]
  );
  const uniqueIPs = useMemo(
    () => stats?.top_ips?.length ?? 0,
    [stats]
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">安全事件</h1>
          <p className="mt-1 text-sm text-slate-500">
            检索拦截与观察事件，分析攻击来源和热点
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
            onClick={() => exportCSV(events)}
            disabled={events.length === 0}
          >
            <Download className="h-3.5 w-3.5" /> 导出 CSV
          </Button>
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <Shield className="h-3.5 w-3.5 text-cyan-500" /> 总事件数
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {stats ? stats.total.toLocaleString() : "--"}
          </div>
          <div className="mt-1 text-xs text-slate-400">近 24 小时</div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <ShieldBan className="h-3.5 w-3.5 text-red-500" /> 终止事件
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {terminalEvents.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-slate-400">按类别汇总</div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-500" /> 今日质询
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {stats?.categories?.find((c) => c.category === "challenge")?.count ?? 0}
          </div>
          <div className="mt-1 text-xs text-slate-400">challenge events</div>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <ShieldAlert className="h-3.5 w-3.5 text-purple-500" /> 独立攻击IP
          </div>
          <div className="mt-2 text-2xl font-semibold text-slate-900">
            {uniqueIPs}
          </div>
          <div className="mt-1 text-xs text-slate-400">去重统计</div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
        <Select value={action} onValueChange={(v) => { setAction(v); setPage(1); }}>
          <SelectTrigger className="w-[140px] rounded-lg">
            <SelectValue placeholder="动作" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部动作</SelectItem>
            {wafActionOptions.map((item) => (
              <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={category} onValueChange={(v) => { setCategory(v); setPage(1); }}>
          <SelectTrigger className="w-[140px] rounded-lg">
            <SelectValue placeholder="类别" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部类别</SelectItem>
            <SelectItem value="sqli">SQL 注入</SelectItem>
            <SelectItem value="xss">XSS</SelectItem>
            <SelectItem value="path_traversal">路径遍历</SelectItem>
            <SelectItem value="webshell">WebShell</SelectItem>
            <SelectItem value="cmd_injection">命令注入</SelectItem>
            <SelectItem value="ssrf">SSRF</SelectItem>
            <SelectItem value="xxe">XXE</SelectItem>
            <SelectItem value="bot_malicious">恶意 Bot</SelectItem>
            <SelectItem value="rate_limit">速率限制</SelectItem>
          </SelectContent>
        </Select>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
          <Input
            value={clientIP}
            onChange={(e) => { setClientIP(e.target.value); setPage(1); }}
            placeholder="搜索 IP"
            className="w-[180px] rounded-lg pl-8"
          />
        </div>
      </div>

      {/* Events table */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        {loading ? (
          <div className="p-16 text-center text-sm text-slate-400">加载中...</div>
        ) : events.length === 0 ? (
          <div className="p-16 text-center text-sm text-slate-400">
            当前筛选条件下没有安全事件
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/80 text-left text-xs font-medium text-slate-500">
                    <th className="px-4 py-3">时间</th>
                    <th className="px-4 py-3">动作</th>
                    <th className="px-4 py-3">类别</th>
                    <th className="px-4 py-3">状态码</th>
                    <th className="px-4 py-3">源 IP</th>
                    <th className="px-4 py-3">请求路径</th>
                    <th className="px-4 py-3">匹配描述</th>
                    <th className="px-4 py-3 text-right">详情</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {events.map((evt) => (
                    <tr
                      key={evt.id}
                      className="transition-colors hover:bg-slate-50/50"
                    >
                      <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                        {formatDate(evt.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <ActionBadge action={evt.action} />
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-700">
                        {evt.category}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">
                        {evt.action === "drop" || evt.status_code === 0 ? "DROP" : evt.status_code || "—"}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">
                        {evt.client_ip}
                      </td>
                      <td className="max-w-[240px] truncate px-4 py-3 font-mono text-xs text-slate-600">
                        {evt.path}
                      </td>
                      <td className="max-w-[200px] truncate px-4 py-3 text-xs text-slate-500">
                        {evt.match_desc || "-"}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 rounded-md px-2 text-slate-600 hover:text-slate-900"
                          onClick={() => setSelected(evt)}
                        >
                          <Eye className="mr-1 h-3.5 w-3.5" /> 详情
                        </Button>
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

      {/* Detail Dialog */}
      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-w-2xl rounded-xl">
          <DialogHeader>
            <DialogTitle>事件详情</DialogTitle>
            <DialogDescription>完整的安全事件信息</DialogDescription>
          </DialogHeader>
          {selected && (
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["Request ID", selected.request_id || "-"],
                ["时间", formatDate(selected.created_at)],
                ["客户端 IP", selected.client_ip],
                ["Host", selected.host || "-"],
                ["方法", selected.method],
                ["阶段", selected.phase],
                ["类别", selected.category],
                ["动作", selected.action],
                ["规则", selected.rule_id_str || String(selected.rule_id)],
                ["状态码", String(selected.status_code)],
                ["国家", selected.geo_country || "-"],
                ["城市", selected.geo_city || "-"],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                    {label}
                  </div>
                  <div className="mt-1 text-sm font-medium text-slate-900">{value}</div>
                </div>
              ))}
              <div className="sm:col-span-2 rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">路径</div>
                <code className="mt-1 block break-all text-xs text-slate-700">{selected.path}</code>
              </div>
              <div className="sm:col-span-2 rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400">匹配描述</div>
                <div className="mt-1 text-sm text-slate-700">{selected.match_desc || "-"}</div>
              </div>
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
