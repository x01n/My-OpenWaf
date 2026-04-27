"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Download, RefreshCcw } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { EmptyState, InlineMeta, PageIntro, Surface, statusToneClass } from "@/components/console-shell";
import { Pagination } from "@/components/pagination";
import {
  getSecurityEventStats,
  getSecurityEvents,
  type SecurityEvent,
  type SecurityStats,
} from "@/lib/api";
import { formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

function exportCSV(events: SecurityEvent[]) {
  const headers = ["ID", "时间", "Request ID", "IP", "Host", "方法", "路径", "动作", "阶段", "类别", "规则", "匹配说明"];
  const rows = events.map((event) => [
    event.id,
    formatDate(event.created_at),
    event.request_id,
    event.client_ip,
    event.host,
    event.method,
    event.path,
    event.action,
    event.phase,
    event.category,
    event.rule_id_str || event.rule_id,
    event.match_desc,
  ]);
  const csv = [headers.join(","), ...rows.map((row) => row.map((item) => `"${String(item).replace(/"/g, '""')}"`).join(","))].join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `security-events-${new Date().toISOString().slice(0, 10)}.csv`;
  anchor.click();
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
      const [eventResponse, statsResponse] = await Promise.all([
        getSecurityEvents({
          page,
          page_size: PAGE_SIZE,
          action: action === "all" ? undefined : action,
          category: category === "all" ? undefined : category,
          client_ip: clientIP || undefined,
        }),
        getSecurityEventStats(24),
      ]);
      setEvents(eventResponse.items ?? []);
      setTotal(eventResponse.total ?? 0);
      setStats(statsResponse);
    } finally {
      setLoading(false);
    }
  }, [action, category, clientIP, page]);

  useEffect(() => {
    load();
  }, [load]);

  const topCategories = useMemo(() => stats?.categories?.slice(0, 5) ?? [], [stats]);
  const topIPs = useMemo(() => stats?.top_ips?.slice(0, 5) ?? [], [stats]);
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Event Analytics"
        title="安全事件"
        description="检索当前系统记录的拦截与观察事件，按动作、类别、IP 和规则聚合查看热点来源与攻击面。"
        actions={
          <>
            <Button variant="secondary" className="rounded-2xl bg-white text-slate-950 hover:bg-slate-100" onClick={load}>
              <RefreshCcw className="mr-2 h-4 w-4" /> 刷新
            </Button>
            <Button variant="secondary" className="rounded-2xl bg-white text-slate-950 hover:bg-slate-100" onClick={() => exportCSV(events)} disabled={events.length === 0}>
              <Download className="mr-2 h-4 w-4" /> 导出 CSV
            </Button>
          </>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <Surface title="24 小时统计" description="来自 /api/v1/security-events/stats 的聚合数据。">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <InlineMeta label="事件总数" value={stats ? stats.total.toLocaleString() : "--"} />
            <InlineMeta label="统计窗口" value={stats ? `${stats.hours} 小时` : "--"} />
            <InlineMeta label="Top 类别数" value={topCategories.length ? topCategories[0].count : "--"} />
            <InlineMeta label="Top 攻击 IP" value={topIPs.length ? topIPs[0].client_ip : "--"} />
          </div>
        </Surface>

        <Surface title="筛选条件" description="按动作、类别和客户端 IP 缩小结果范围。">
          <div className="grid gap-3 md:grid-cols-3">
            <Select value={action} onValueChange={(value) => { setAction(value); setPage(1); }}>
              <SelectTrigger className="rounded-xl"><SelectValue placeholder="动作" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部动作</SelectItem>
                <SelectItem value="intercept">拦截</SelectItem>
                <SelectItem value="observe">观察</SelectItem>
              </SelectContent>
            </Select>
            <Select value={category} onValueChange={(value) => { setCategory(value); setPage(1); }}>
              <SelectTrigger className="rounded-xl"><SelectValue placeholder="类别" /></SelectTrigger>
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
            <Input
              value={clientIP}
              onChange={(event) => { setClientIP(event.target.value); setPage(1); }}
              placeholder="按客户端 IP 筛选"
              className="rounded-xl"
            />
          </div>
        </Surface>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Surface title="类别分布" description="帮助识别近期最常见的攻击类型。">
          <div className="space-y-3">
            {topCategories.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">暂无聚合类别数据。</div>
            ) : (
              topCategories.map((item) => (
                <div key={item.category} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                  <span className="font-medium text-slate-800">{item.category}</span>
                  <span className="text-slate-950">{item.count}</span>
                </div>
              ))
            )}
          </div>
        </Surface>

        <Surface title="热点来源 IP" description="最近 24 小时内触发事件最多的客户端 IP。">
          <div className="space-y-3">
            {topIPs.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">暂无热点来源数据。</div>
            ) : (
              topIPs.map((item) => (
                <div key={item.client_ip} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                  <span className="font-mono text-slate-700">{item.client_ip}</span>
                  <span className="text-slate-950">{item.count}</span>
                </div>
              ))
            )}
          </div>
        </Surface>
      </div>

      <Surface title="事件列表" description="点击行可查看请求标识、规则和详细命中说明。">
        {loading ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : events.length === 0 ? (
          <EmptyState title="没有匹配事件" description="当前筛选条件下没有安全事件，可以放宽筛选条件后重试。" />
        ) : (
          <div className="space-y-4">
            <div className="overflow-hidden rounded-[24px] border border-slate-200">
              <table className="min-w-full divide-y divide-slate-200 bg-white text-sm">
                <thead className="bg-slate-50 text-left text-xs uppercase tracking-[0.16em] text-slate-500">
                  <tr>
                    <th className="px-4 py-3">时间</th>
                    <th className="px-4 py-3">IP</th>
                    <th className="px-4 py-3">方法</th>
                    <th className="px-4 py-3">路径</th>
                    <th className="px-4 py-3">动作</th>
                    <th className="px-4 py-3">类别</th>
                    <th className="px-4 py-3">规则</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {events.map((event) => (
                    <tr key={event.id} className="cursor-pointer transition-colors hover:bg-slate-50" onClick={() => setSelected(event)}>
                      <td className="px-4 py-3 text-xs text-slate-500">{formatDate(event.created_at)}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">{event.client_ip}</td>
                      <td className="px-4 py-3 text-xs text-slate-700">{event.method}</td>
                      <td className="max-w-[320px] truncate px-4 py-3 font-mono text-xs text-slate-700">{event.path}</td>
                      <td className="px-4 py-3"><span className={`console-badge ${statusToneClass(event.action)}`}>{event.action}</span></td>
                      <td className="px-4 py-3 text-xs text-slate-700">{event.category}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-700">{event.rule_id_str || event.rule_id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} totalPages={totalPages} total={total} pageSize={PAGE_SIZE} onPageChange={setPage} />
          </div>
        )}
      </Surface>

      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-w-2xl rounded-[28px]">
          <DialogHeader>
            <DialogTitle>事件详情</DialogTitle>
            <DialogDescription>查看请求标识、规则与详细命中说明。</DialogDescription>
          </DialogHeader>
          {selected ? (
            <div className="grid gap-3 md:grid-cols-2">
              <InlineMeta label="Request ID" value={selected.request_id || "-"} />
              <InlineMeta label="时间" value={formatDate(selected.created_at)} />
              <InlineMeta label="客户端 IP" value={selected.client_ip} />
              <InlineMeta label="Host" value={selected.host || "-"} />
              <InlineMeta label="方法" value={selected.method} />
              <InlineMeta label="阶段" value={selected.phase} />
              <InlineMeta label="类别" value={selected.category} />
              <InlineMeta label="动作" value={selected.action} />
              <InlineMeta label="规则" value={selected.rule_id_str || String(selected.rule_id)} />
              <InlineMeta label="状态码" value={String(selected.status_code)} />
              <div className="md:col-span-2">
                <InlineMeta label="路径" value={<code className="text-xs">{selected.path}</code>} />
              </div>
              <div className="md:col-span-2">
                <InlineMeta label="匹配描述" value={selected.match_desc || "-"} />
              </div>
              <div className="md:col-span-2">
                <InlineMeta label="User-Agent" value={selected.user_agent || "-"} />
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
