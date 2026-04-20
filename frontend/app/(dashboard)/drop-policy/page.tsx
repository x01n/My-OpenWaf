"use client";

import { useCallback, useEffect, useState } from "react";
import {
  getDropPolicy,
  updateDropPolicy,
  getDropStats,
  getDropEvents,
  type DropPolicy,
  type DropStats,
  type DropEvent,
  type DropEventQuery,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { Loader2, ChevronLeft, ChevronRight, ShieldOff, Bot, Bug, FileWarning, Globe } from "lucide-react";

const PAGE_SIZE = 20;

function formatDate(s: string) {
  if (!s) return "-";
  return new Date(s).toLocaleString("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmt(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return n.toLocaleString();
}

export default function DropPolicyPage() {
  // Policy
  const [policy, setPolicy] = useState<DropPolicy | null>(null);
  const [policyLoading, setPolicyLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Stats
  const [stats, setStats] = useState<DropStats | null>(null);

  // Events
  const [events, setEvents] = useState<DropEvent[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [filters, setFilters] = useState<DropEventQuery>({});

  useEffect(() => {
    getDropPolicy()
      .then(setPolicy)
      .catch(() => toast.error("加载阻断策略失败"))
      .finally(() => setPolicyLoading(false));
    getDropStats()
      .then(setStats)
      .catch(() => {});
  }, []);

  const loadEvents = useCallback(async () => {
    setEventsLoading(true);
    try {
      const res = await getDropEvents({ ...filters, page, page_size: PAGE_SIZE });
      setEvents(res.items ?? []);
      setEventsTotal(res.total ?? 0);
    } catch {
      setEvents([]);
    } finally {
      setEventsLoading(false);
    }
  }, [page, filters]);

  useEffect(() => { loadEvents(); }, [loadEvents]);

  async function savePolicy() {
    if (!policy) return;
    setSaving(true);
    try {
      await updateDropPolicy(policy);
      toast.success("阻断策略已保存");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  const totalPages = Math.max(1, Math.ceil(eventsTotal / PAGE_SIZE));

  const SOURCE_OPTIONS = [
    { value: "bot", label: "Bot检测" },
    { value: "cve", label: "CVE规则" },
    { value: "rule", label: "自定义规则" },
    { value: "ip_rep", label: "IP信誉" },
  ];

  const statCards = stats
    ? [
        { label: "总阻断数", value: stats.total_dropped, icon: ShieldOff, color: "text-rose-500" },
        { label: "Bot阻断", value: stats.dropped_by_bot, icon: Bot, color: "text-orange-500" },
        { label: "CVE阻断", value: stats.dropped_by_cve, icon: Bug, color: "text-amber-500" },
        { label: "规则阻断", value: stats.dropped_by_rule, icon: FileWarning, color: "text-blue-500" },
        { label: "IP信誉阻断", value: stats.dropped_by_ip_rep, icon: Globe, color: "text-purple-500" },
      ]
    : [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-gray-800">阻断策略</h1>
        <p className="text-gray-500 text-sm mt-0.5">配置全局阻断策略，查看阻断统计和事件</p>
      </div>

      {/* Policy Config */}
      {policyLoading ? (
        <div className="bg-white border border-gray-200 rounded-lg p-6 text-center text-gray-400">加载中...</div>
      ) : policy ? (
        <div className="bg-white border border-gray-200 rounded-lg p-6 space-y-5">
          <h2 className="text-sm font-medium text-gray-700">策略配置</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 max-w-2xl">
            <div className="flex items-center justify-between">
              <div>
                <Label className="text-sm font-medium">全局开关</Label>
                <p className="text-xs text-gray-400">启用后将执行阻断策略</p>
              </div>
              <Switch
                checked={policy.enabled}
                onCheckedChange={(v) => setPolicy({ ...policy, enabled: v })}
              />
            </div>
            <div className="space-y-2">
              <Label className="text-sm">Bot分数阈值 ({policy.bot_score_threshold})</Label>
              <input
                type="range"
                min={0}
                max={100}
                value={policy.bot_score_threshold}
                onChange={(e) => setPolicy({ ...policy, bot_score_threshold: Number(e.target.value) })}
                className="w-full accent-teal-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label className="text-sm font-medium">CVE Critical 自动Drop</Label>
                <p className="text-xs text-gray-400">Critical级别CVE匹配自动阻断</p>
              </div>
              <Switch
                checked={policy.cve_auto_drop_critical}
                onCheckedChange={(v) => setPolicy({ ...policy, cve_auto_drop_critical: v })}
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label className="text-sm font-medium">CVE High 自动Drop</Label>
                <p className="text-xs text-gray-400">High级别CVE匹配自动阻断</p>
              </div>
              <Switch
                checked={policy.cve_auto_drop_high}
                onCheckedChange={(v) => setPolicy({ ...policy, cve_auto_drop_high: v })}
              />
            </div>
          </div>
          <Button onClick={savePolicy} disabled={saving} className="bg-teal-500 hover:bg-teal-600 text-white">
            {saving && <Loader2 className="mr-1 h-4 w-4 animate-spin" />}
            保存策略
          </Button>
        </div>
      ) : null}

      {/* Stats Cards */}
      {statCards.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {statCards.map((s) => (
            <div key={s.label} className="bg-white border border-gray-200 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <s.icon className={`h-4 w-4 ${s.color}`} />
                <span className="text-xs text-gray-500">{s.label}</span>
              </div>
              <div className={`text-2xl font-bold ${s.color} tabular-nums`}>{fmt(s.value)}</div>
            </div>
          ))}
        </div>
      )}

      {/* Events Section */}
      <div className="space-y-3">
        <h2 className="text-sm font-medium text-gray-700">阻断事件</h2>

        {/* Filters */}
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label className="text-xs text-gray-500">IP</Label>
            <Input
              className="w-[160px] h-8 text-sm"
              placeholder="筛选IP"
              value={filters.ip ?? ""}
              onChange={(e) => { setFilters({ ...filters, ip: e.target.value }); setPage(1); }}
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs text-gray-500">来源</Label>
            <Select value={filters.source ?? "all"} onValueChange={(v) => { setFilters({ ...filters, source: v === "all" ? undefined : v }); setPage(1); }}>
              <SelectTrigger className="w-[120px] h-8 text-sm"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部</SelectItem>
                {SOURCE_OPTIONS.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <Button size="sm" variant="outline" onClick={() => { setFilters({}); setPage(1); }}>
            重置
          </Button>
        </div>

        {/* Table */}
        <div className="rounded-lg border border-gray-200 overflow-hidden bg-white">
          <Table>
            <TableHeader>
              <TableRow className="bg-gray-50">
                <TableHead className="text-gray-600 font-medium">IP</TableHead>
                <TableHead className="text-gray-600 font-medium w-[90px]">来源</TableHead>
                <TableHead className="text-gray-600 font-medium w-[120px]">规则ID</TableHead>
                <TableHead className="text-gray-600 font-medium">详情</TableHead>
                <TableHead className="text-gray-600 font-medium w-[120px]">域名</TableHead>
                <TableHead className="text-gray-600 font-medium">路径</TableHead>
                <TableHead className="text-gray-600 font-medium w-[150px]">时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {eventsLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-32 text-center text-gray-400">加载中...</TableCell>
                </TableRow>
              ) : events.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-32 text-center text-gray-400">暂无数据</TableCell>
                </TableRow>
              ) : (
                events.map((ev) => (
                  <TableRow key={ev.id} className="hover:bg-gray-50">
                    <TableCell className="font-mono text-xs">{ev.client_ip}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{ev.source}</Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono text-gray-600">{ev.rule_id}</TableCell>
                    <TableCell className="text-sm text-gray-600 truncate max-w-[200px]">{ev.detail}</TableCell>
                    <TableCell className="text-sm text-gray-600 truncate">{ev.host}</TableCell>
                    <TableCell className="text-sm text-gray-600 truncate max-w-[160px]">{ev.path}</TableCell>
                    <TableCell className="text-sm text-gray-500">{formatDate(ev.created_at)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        {eventsTotal > PAGE_SIZE && (
          <div className="flex items-center justify-between text-sm text-gray-500">
            <span>{PAGE_SIZE} 条每页，共 {eventsTotal} 条</span>
            <div className="flex items-center gap-1">
              <Button variant="outline" size="icon" className="h-7 w-7" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="px-2">{page} / {totalPages}</span>
              <Button variant="outline" size="icon" className="h-7 w-7" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
