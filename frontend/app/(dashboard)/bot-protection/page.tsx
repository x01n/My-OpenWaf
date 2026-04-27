"use client";

import { useCallback, useEffect, useState } from "react";
import { Bot, Globe2, Radar } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Pagination } from "@/components/pagination";
import { EmptyState, InlineMeta, PageIntro, Surface, statusToneClass } from "@/components/console-shell";
import { getBotScores, getBotSettings, updateBotSettings, type BotScoreLog, type BotSettings } from "@/lib/api";
import { formatDate } from "@/lib/utils";

const PAGE_SIZE = 20;

function normalizeSettings(settings: BotSettings): BotSettings {
  return {
    ...settings,
    high_risk_countries: settings.high_risk_countries ?? [],
    datacenter_asns: settings.datacenter_asns ?? [],
    vpn_proxy_asns: settings.vpn_proxy_asns ?? [],
    geoip_db_path: settings.geoip_db_path ?? "",
  };
}

export default function BotProtectionPage() {
  const [settings, setSettings] = useState<BotSettings | null>(null);
  const [logs, setLogs] = useState<BotScoreLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [ip, setIP] = useState("");
  const [minScore, setMinScore] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [botSettings, scoreLogs] = await Promise.all([
        getBotSettings(),
        getBotScores({ page, page_size: PAGE_SIZE, ip: ip || undefined, min_score: minScore ? Number(minScore) : undefined }),
      ]);
      setSettings(normalizeSettings(botSettings));
      setLogs(scoreLogs.items ?? []);
      setTotal(scoreLogs.total ?? 0);
    } finally {
      setLoading(false);
    }
  }, [ip, minScore, page]);

  useEffect(() => {
    load();
  }, [load]);

  async function save() {
    if (!settings) return;
    setSaving(true);
    try {
      const response = await updateBotSettings(settings);
      setSettings(normalizeSettings(response));
      toast.success("Bot 配置已保存");
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
        eyebrow="Bot Detection"
        title="Bot 防护"
        description="配置 GeoIP、ASN、风险国家与 Bot 评分阈值，并查看后端实际采集的评分日志。"
        actions={<Button onClick={save} disabled={saving}>{saving ? "保存中..." : "保存配置"}</Button>}
      />

      {settings ? (
        <div className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
          <Surface title="Bot 配置" description="直接映射 /api/v1/bot-settings。">
            <div className="grid gap-4">
              <ToggleRow label="启用 Bot 检测" checked={settings.enabled} onChange={(value) => setSettings({ ...settings, enabled: value })} />
              <NumberRow label="分数阈值" value={settings.score_threshold} onChange={(value) => setSettings({ ...settings, score_threshold: value })} />
              <TextListRow label="高风险国家" value={settings.high_risk_countries.join(", ")} onChange={(value) => setSettings({ ...settings, high_risk_countries: splitCSV(value) })} />
              <TextListRow label="数据中心 ASN" value={settings.datacenter_asns.join(", ")} onChange={(value) => setSettings({ ...settings, datacenter_asns: splitCSV(value).map(Number).filter((item) => !Number.isNaN(item)) })} />
              <TextListRow label="VPN/代理 ASN" value={settings.vpn_proxy_asns.join(", ")} onChange={(value) => setSettings({ ...settings, vpn_proxy_asns: splitCSV(value).map(Number).filter((item) => !Number.isNaN(item)) })} />
              <TextListRow label="GeoIP 数据库路径" value={settings.geoip_db_path} onChange={(value) => setSettings({ ...settings, geoip_db_path: value })} />
            </div>
          </Surface>

          <Surface title="配置摘要" description="快速查看当前策略的关键状态。">
            <div className="grid gap-3 md:grid-cols-2">
              <InlineMeta label="运行状态" value={settings.enabled ? "已启用" : "已关闭"} />
              <InlineMeta label="阈值" value={String(settings.score_threshold)} />
              <InlineMeta label="高风险国家数" value={String(settings.high_risk_countries.length)} />
              <InlineMeta label="数据中心 ASN 数" value={String(settings.datacenter_asns.length)} />
            </div>
          </Surface>
        </div>
      ) : (
        <Surface className="min-h-[280px] animate-pulse"><div className="h-full" /></Surface>
      )}

      <Surface title="评分日志" description="来自 /api/v1/bot-scores，可按 IP 与最低分过滤。">
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <Input value={ip} onChange={(event) => { setIP(event.target.value); setPage(1); }} placeholder="按 IP 筛选" className="rounded-xl" />
          <Input value={minScore} onChange={(event) => { setMinScore(event.target.value); setPage(1); }} placeholder="最低分" type="number" className="rounded-xl" />
          <Button variant="outline" className="rounded-xl" onClick={() => { setIP(""); setMinScore(""); setPage(1); }}>重置筛选</Button>
        </div>

        {loading ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : logs.length === 0 ? (
          <EmptyState title="暂无 Bot 评分日志" description="当 Bot 检测引擎记录评分事件后，这里会展示客户端、路径、分数与执行动作。" />
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {logs.map((item) => (
                <div key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
                      <Bot className="h-4 w-4 text-cyan-700" />
                      {item.client_ip}
                    </div>
                    <span className={`console-badge ${statusToneClass(item.action)}`}>{item.action}</span>
                  </div>
                  <div className="space-y-2 text-sm text-slate-600">
                    <div className="flex items-center gap-2"><Globe2 className="h-4 w-4 text-slate-400" /> {item.host || "-"}</div>
                    <div className="flex items-center gap-2"><Radar className="h-4 w-4 text-slate-400" /> 总分 {item.total_score}</div>
                    <div className="font-mono text-xs text-slate-500">{item.path}</div>
                    <div className="text-xs text-slate-500">GeoIP {item.geoip_score} · 指纹 {item.fingerprint_score} · 行为 {item.behavior_score}</div>
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

function splitCSV(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
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

function TextListRow({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="space-y-2 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm">
      <span className="font-medium text-slate-900">{label}</span>
      <input value={value} onChange={(event) => onChange(event.target.value)} className="h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-slate-900" />
    </label>
  );
}
