"use client";

import { useCallback, useEffect, useState } from "react";
import { Ban, Bot, Bug, Globe } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Pagination } from "@/components/pagination";
import { EmptyState, InlineMeta, PageIntro, Surface, statusToneClass } from "@/components/console-shell";
import { getDropEvents, getDropPolicy, getDropStats, updateDropPolicy, type DropEvent, type DropPolicy, type DropStats } from "@/lib/api";
import { formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

export default function DropPolicyPage() {
  const [policy, setPolicy] = useState<DropPolicy | null>(null);
  const [stats, setStats] = useState<DropStats | null>(null);
  const [events, setEvents] = useState<DropEvent[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [ip, setIP] = useState("");
  const [source, setSource] = useState("all");
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [dropPolicy, dropStats, dropEvents] = await Promise.all([
        getDropPolicy(),
        getDropStats(),
        getDropEvents({ page, page_size: PAGE_SIZE, ip: ip || undefined, source: source === "all" ? undefined : source }),
      ]);
      setPolicy(dropPolicy);
      setStats(dropStats);
      setEvents(dropEvents.items ?? []);
      setTotal(dropEvents.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [ip, page, source]);

  useEffect(() => {
    load();
  }, [load]);

  async function save() {
    if (!policy) return;
    setSaving(true);
    try {
      const response = await updateDropPolicy(policy);
      setPolicy(response);
      toast.success("阻断策略已保存");
    } catch (error) {
      toast.error(String(error));
    } finally {
      setSaving(false);
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Connection Drop"
        title="阻断策略"
        description="控制主动断连策略，并查看最近 24 小时的阻断来源分布与事件列表。"
        actions={<Button onClick={save} disabled={saving}>{saving ? "保存中..." : "保存配置"}</Button>}
      />

      {policy ? (
        <div className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
          <Surface title="策略配置" description="直接映射 /api/v1/drop-policy/update。">
            <div className="grid gap-4">
              <ToggleRow label="启用全局阻断策略" checked={policy.enabled} onChange={(value) => setPolicy({ ...policy, enabled: value })} />
              <NumberRow label="Bot 自动阻断阈值" value={policy.bot_score_threshold} onChange={(value) => setPolicy({ ...policy, bot_score_threshold: value })} />
              <ToggleRow label="Critical CVE 自动断连" checked={policy.cve_auto_drop_critical} onChange={(value) => setPolicy({ ...policy, cve_auto_drop_critical: value })} />
              <ToggleRow label="High CVE 自动断连" checked={policy.cve_auto_drop_high} onChange={(value) => setPolicy({ ...policy, cve_auto_drop_high: value })} />
            </div>
          </Surface>

          <Surface title="24 小时阻断汇总" description="来自 /api/v1/drop-stats。">
            <div className="grid gap-3 md:grid-cols-2">
              <InlineMeta label="总阻断数" value={stats ? stats.total_24h.toLocaleString() : "--"} />
              <InlineMeta label="Bot" value={stats ? stats.by_bot.toLocaleString() : "--"} />
              <InlineMeta label="CVE" value={stats ? stats.by_cve.toLocaleString() : "--"} />
              <InlineMeta label="规则" value={stats ? stats.by_rule.toLocaleString() : "--"} />
              <InlineMeta label="IP 信誉" value={stats ? stats.by_ip_reputation.toLocaleString() : "--"} />
            </div>
          </Surface>
        </div>
      ) : (
        <Surface className="min-h-[280px] animate-pulse"><div className="h-full" /></Surface>
      )}

      <Surface title="阻断事件" description="按客户端 IP 和来源过滤最新主动断连记录。">
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <Input value={ip} onChange={(event) => { setIP(event.target.value); setPage(1); }} placeholder="按客户端 IP 筛选" className="rounded-xl" />
          <select value={source} onChange={(event) => { setSource(event.target.value); setPage(1); }} className="h-10 rounded-xl border border-slate-200 bg-white px-3 text-sm text-slate-900">
            <option value="all">全部来源</option>
            <option value="bot">Bot</option>
            <option value="cve">CVE</option>
            <option value="rule">规则</option>
            <option value="ip_reputation">IP 信誉</option>
          </select>
          <Button variant="outline" className="rounded-xl" onClick={() => { setIP(""); setSource("all"); setPage(1); }}>重置筛选</Button>
        </div>

        {loading ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : events.length === 0 ? (
          <EmptyState title="暂无阻断事件" description="没有符合筛选条件的主动断连事件。" />
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {events.map((item) => (
                <div key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
                      <Ban className="h-4 w-4 text-rose-700" />
                      {item.client_ip}
                    </div>
                    <span className={`console-badge ${statusToneClass(item.source)}`}>{item.source}</span>
                  </div>
                  <div className="space-y-2 text-sm text-slate-600">
                    <div className="flex items-center gap-2"><Globe className="h-4 w-4 text-slate-400" /> {item.host || "-"}</div>
                    <div className="flex items-center gap-2"><Bot className="h-4 w-4 text-slate-400" /> 规则 {item.rule_id || "-"}</div>
                    <div className="flex items-center gap-2"><Bug className="h-4 w-4 text-slate-400" /> {item.detail}</div>
                    <div className="font-mono text-xs text-slate-500">{item.path}</div>
                    <div className="text-xs text-slate-500">{formatDate(item.created_at)}</div>
                  </div>
                </div>
              ))}
            </div>
            <Pagination page={page} totalPages={totalPages} total={total} pageSize={PAGE_SIZE} onPageChange={setPage} />
          </div>
        )}
      </Surface>
    </div>
  );
}

function ToggleRow({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
      <span className="text-sm font-medium text-slate-900">{label}</span>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="h-4 w-4" />
    </div>
  );
}

function NumberRow({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <label className="space-y-2 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm">
      <span className="font-medium text-slate-900">{label}</span>
      <input type="number" value={value} onChange={(event) => onChange(Number(event.target.value))} className="h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-slate-900" />
    </label>
  );
}
