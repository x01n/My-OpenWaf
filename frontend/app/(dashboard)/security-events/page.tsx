"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { api } from "@/lib/api";
import { RefreshCw, Download } from "lucide-react";
import { Pagination } from "@/components/pagination";

interface SecurityEvent {
  id: number;
  created_at: string;
  request_id: string;
  client_ip: string;
  host: string;
  path: string;
  method: string;
  user_agent: string;
  rule_id: number;
  rule_id_str: string;
  phase: string;
  action: string;
  category: string;
  match_desc: string;
  geo_country: string;
  geo_city: string;
  status_code: number;
}

interface StatsData {
  total: number;
  hours: number;
  categories: { category: string; count: number }[] | null;
  top_ips: { client_ip: string; count: number }[] | null;
  top_paths: { path: string; count: number }[] | null;
  top_rules: { rule_id_str: string; count: number }[] | null;
}

export default function SecurityEventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<StatsData | null>(null);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);

  // Filters
  const [filterAction, setFilterAction] = useState("");
  const [filterCategory, setFilterCategory] = useState("");
  const [filterIP, setFilterIP] = useState("");
  const [debouncedIP, setDebouncedIP] = useState("");

  // Debounce IP filter
  const ipDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    ipDebounceRef.current = setTimeout(() => {
      setDebouncedIP(filterIP);
      setPage(1);
    }, 300);
    return () => { if (ipDebounceRef.current) clearTimeout(ipDebounceRef.current); };
  }, [filterIP]);

  const pageSize = 20;

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
      });
      if (filterAction) params.set("action", filterAction);
      if (filterCategory) params.set("category", filterCategory);
      if (debouncedIP) params.set("client_ip", debouncedIP);

      const data = await api<{ items: SecurityEvent[]; total: number }>(
        `/api/v1/security-events?${params}`,
      );
      setEvents(data.items || []);
      setTotal(data.total);
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [page, filterAction, filterCategory, debouncedIP]);

  const loadStats = useCallback(async () => {
    try {
      const data = await api<StatsData>("/api/v1/security-events/stats?hours=24");
      setStats(data);
    } catch {
      // non-critical
    }
  }, []);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  useEffect(() => {
    loadStats();
    const id = setInterval(loadStats, 30000);
    return () => clearInterval(id);
  }, [loadStats]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-800">安全事件</h1>
          <p className="text-gray-500 text-sm">
            WAF 拦截与观察事件记录
          </p>
        </div>
        <div className="flex gap-2">
          <button
            className="inline-flex items-center px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white text-gray-700 hover:border-cyan-400 hover:text-cyan-600 transition-colors disabled:opacity-50"
            onClick={() => exportCSV(events)}
            disabled={events.length === 0}
          >
            <Download className="mr-1 h-3.5 w-3.5" />
            导出 CSV
          </button>
          <button
            className="inline-flex items-center px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white text-gray-700 hover:border-cyan-400 hover:text-cyan-600 transition-colors disabled:opacity-50"
            onClick={() => {
              loadEvents();
              loadStats();
            }}
            disabled={loading}
          >
            <RefreshCw
              className={`mr-1 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`}
            />
            刷新
          </button>
        </div>
      </div>

      {/* Stats cards */}
      {stats && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="text-gray-500 text-xs mb-2">24h 事件总数</div>
            <div className="text-gray-900 text-2xl font-bold tabular-nums">
              {stats.total.toLocaleString()}
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="text-gray-500 text-xs mb-2">攻击类型分布</div>
            <div className="flex flex-wrap gap-1">
              {(stats.categories || []).slice(0, 5).map((c) => (
                <span key={c.category} className="inline-flex items-center border border-gray-200 rounded px-2 py-0.5 text-xs text-gray-600">
                  {c.category}: {c.count}
                </span>
              ))}
              {(!stats.categories || stats.categories.length === 0) && (
                <span className="text-xs text-gray-400">暂无数据</span>
              )}
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="text-gray-500 text-xs mb-2">Top 攻击来源 IP</div>
            <div className="space-y-1 text-xs">
              {(stats.top_ips || []).slice(0, 3).map((ip) => (
                <div key={ip.client_ip} className="flex justify-between">
                  <span className="font-mono text-gray-700">{ip.client_ip}</span>
                  <span className="text-gray-400">{ip.count}</span>
                </div>
              ))}
              {(!stats.top_ips || stats.top_ips.length === 0) && (
                <span className="text-gray-400">暂无数据</span>
              )}
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="text-gray-500 text-xs mb-2">Top 触发规则</div>
            <div className="space-y-1 text-xs">
              {(stats.top_rules || []).slice(0, 3).map((r) => (
                <div key={r.rule_id_str} className="flex justify-between">
                  <span className="font-mono text-gray-700">{r.rule_id_str}</span>
                  <span className="text-gray-400">{r.count}</span>
                </div>
              ))}
              {(!stats.top_rules || stats.top_rules.length === 0) && (
                <span className="text-gray-400">暂无数据</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select
          value={filterAction}
          onValueChange={(v) => {
            setFilterAction(v === "all" ? "" : v);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[140px] h-8 text-sm">
            <SelectValue placeholder="动作" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部动作</SelectItem>
            <SelectItem value="intercept">拦截</SelectItem>
            <SelectItem value="observe">观察</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={filterCategory}
          onValueChange={(v) => {
            setFilterCategory(v === "all" ? "" : v);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-[160px] h-8 text-sm">
            <SelectValue placeholder="类别" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部类别</SelectItem>
            <SelectItem value="sqli">SQL 注入</SelectItem>
            <SelectItem value="xss">XSS</SelectItem>
            <SelectItem value="path_traversal">路径遍历</SelectItem>
            <SelectItem value="webshell">Webshell</SelectItem>
            <SelectItem value="revshell">反弹 Shell</SelectItem>
            <SelectItem value="ssrf">SSRF</SelectItem>
            <SelectItem value="cmd_injection">命令注入</SelectItem>
            <SelectItem value="xxe">XXE</SelectItem>
            <SelectItem value="ldap_injection">LDAP 注入</SelectItem>
            <SelectItem value="nosql_injection">NoSQL 注入</SelectItem>
            <SelectItem value="template_injection">模板注入</SelectItem>
            <SelectItem value="file_upload">文件上传</SelectItem>
            <SelectItem value="protocol_violation">协议违规</SelectItem>
            <SelectItem value="bot_malicious">恶意 Bot</SelectItem>
            <SelectItem value="bot_suspicious">可疑 Bot</SelectItem>
            <SelectItem value="rate_limit">速率限制</SelectItem>
          </SelectContent>
        </Select>
        <Input
          placeholder="按 IP 筛选"
          className="w-[180px] h-8 text-sm"
          value={filterIP}
          onChange={(e) => {
            setFilterIP(e.target.value);
          }}
        />
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Events table */}
      <div className="rounded-lg border border-gray-200 overflow-hidden bg-white">
        <Table>
          <TableHeader>
            <TableRow className="bg-gray-50 hover:bg-gray-50">
              <TableHead className="w-[160px] text-gray-600 font-medium text-xs">时间</TableHead>
              <TableHead className="text-gray-600 font-medium text-xs">IP</TableHead>
              <TableHead className="text-gray-600 font-medium text-xs">方法</TableHead>
              <TableHead className="text-gray-600 font-medium text-xs">路径</TableHead>
              <TableHead className="text-gray-600 font-medium text-xs">动作</TableHead>
              <TableHead className="text-gray-600 font-medium text-xs">类别</TableHead>
              <TableHead className="text-gray-600 font-medium text-xs">规则</TableHead>
              <TableHead className="text-gray-600 font-medium text-xs">阶段</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {events.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="text-center text-gray-400 py-8">
                  暂无安全事件
                </TableCell>
              </TableRow>
            )}
            {events.map((ev) => (
              <TableRow
                key={ev.id}
                className="cursor-pointer hover:bg-gray-50"
                onClick={() => setSelected(ev)}
              >
                <TableCell className="text-xs font-mono">
                  {new Date(ev.created_at).toLocaleString("zh-CN")}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {ev.client_ip}
                </TableCell>
                <TableCell>
                  <span className="bg-gray-100 text-gray-600 rounded px-1.5 py-0.5 text-xs font-mono">
                    {ev.method}
                  </span>
                </TableCell>
                <TableCell className="max-w-[200px] truncate text-xs font-mono">
                  {ev.path}
                </TableCell>
                <TableCell>
                  {ev.action === "intercept" ? (
                    <span className="bg-red-50 text-red-600 border border-red-200 rounded px-2 py-0.5 text-xs">
                      拦截
                    </span>
                  ) : (
                    <span className="bg-amber-50 text-amber-600 border border-amber-200 rounded px-2 py-0.5 text-xs">
                      观察
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-xs">{ev.category}</TableCell>
                <TableCell className="text-xs font-mono">
                  {ev.rule_id_str || ev.rule_id}
                </TableCell>
                <TableCell className="text-xs">{ev.phase}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      <Pagination
        page={page}
        totalPages={totalPages}
        total={total}
        pageSize={pageSize}
        onPageChange={setPage}
      />

      {/* Detail dialog */}
      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>事件详情</DialogTitle>
          </DialogHeader>
          {selected && (
            <div className="space-y-3 text-sm">
              <Row label="Request ID" value={selected.request_id} mono />
              <Row label="时间" value={new Date(selected.created_at).toLocaleString("zh-CN")} />
              <Row label="客户端 IP" value={selected.client_ip} mono />
              <Row label="Host" value={selected.host} />
              <Row label="方法" value={selected.method} />
              <Row label="路径" value={selected.path} mono />
              <Row label="User-Agent" value={selected.user_agent} />
              <Row label="动作" value={selected.action} />
              <Row label="阶段" value={selected.phase} />
              <Row label="类别" value={selected.category} />
              <Row label="规则 ID" value={selected.rule_id_str || String(selected.rule_id)} mono />
              <Row label="匹配描述" value={selected.match_desc} />
              {selected.geo_country && (
                <Row label="地理位置" value={`${selected.geo_country} ${selected.geo_city || ""}`} />
              )}
              <Row label="状态码" value={String(selected.status_code)} />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function exportCSV(events: SecurityEvent[]) {
  const headers = [
    "ID", "时间", "Request ID", "IP", "Host", "方法", "路径",
    "动作", "阶段", "类别", "规则", "匹配描述", "User-Agent",
  ];
  const rows = events.map((e) => [
    e.id,
    new Date(e.created_at).toLocaleString("zh-CN"),
    e.request_id,
    e.client_ip,
    e.host,
    e.method,
    `"${e.path.replace(/"/g, '""')}"`,
    e.action,
    e.phase,
    e.category,
    e.rule_id_str || e.rule_id,
    `"${(e.match_desc || "").replace(/"/g, '""')}"`,
    `"${(e.user_agent || "").replace(/"/g, '""')}"`,
  ]);

  const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `security-events-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex gap-3">
      <span className="w-28 shrink-0 text-gray-500">{label}</span>
      <span className={`break-all ${mono ? "font-mono text-xs" : ""}`}>
        {value || "-"}
      </span>
    </div>
  );
}
