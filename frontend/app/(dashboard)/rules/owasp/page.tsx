"use client";

import { useCallback, useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { MetricCard, MetricGrid, PageIntro, Surface, EmptyState } from "@/components/console-shell";
import { owaspModuleOptions } from "@/lib/console";
import {
  getOWASPRules, getOWASPRuleStats, updateOWASPRule, batchUpdateOWASPRules,
  getSensitivityConfig, updateSensitivityConfig,
  type OWASPRule, type OWASPRuleStats, type SensitivityConfig,
} from "@/lib/rules-api";

const sensitivityLevels = ["off", "low", "medium", "high", "very_high"] as const;
const levelLabel: Record<string, string> = { off: "关闭", low: "低", medium: "中", high: "高", very_high: "极高" };

export default function OWASPRuleManagementPage() {
  const [rules, setRules] = useState<OWASPRule[]>([]);
  const [grouped, setGrouped] = useState<Record<string, OWASPRule[]>>({});
  const [stats, setStats] = useState<OWASPRuleStats | null>(null);
  const [sensitivity, setSensitivity] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [savingSens, setSavingSens] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [rulesRes, statsRes] = await Promise.all([getOWASPRules(), getOWASPRuleStats()]);
      setRules(rulesRes.items ?? []);
      setGrouped(rulesRes.grouped ?? {});
      setStats(statsRes);
    } catch (e) { toast.error(String(e)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    getSensitivityConfig(1).then((c) => setSensitivity(c.category_sensitivity ?? {})).catch(() => {});
  }, []);

  async function handleToggle(id: string, enabled: boolean) {
    try { await updateOWASPRule(id, { enabled }); load(); } catch (e) { toast.error(String(e)); }
  }

  async function batchToggleCategory(category: string, enabled: boolean) {
    const ids = (grouped[category] ?? []).map((r) => r.id);
    if (ids.length === 0) return;
    try {
      await batchUpdateOWASPRules(ids.map((id) => ({ id, enabled })));
      toast.success(`已${enabled ? "启用" : "禁用"}类别 ${category} 的 ${ids.length} 条规则`);
      load();
    } catch (e) { toast.error(String(e)); }
  }

  async function batchToggleSelected(enabled: boolean) {
    if (selected.size === 0) return;
    try {
      await batchUpdateOWASPRules([...selected].map((id) => ({ id, enabled })));
      toast.success(`已${enabled ? "启用" : "禁用"} ${selected.size} 条规则`);
      setSelected(new Set());
      load();
    } catch (e) { toast.error(String(e)); }
  }

  async function saveSensitivity() {
    setSavingSens(true);
    try {
      await updateSensitivityConfig(1, { category_sensitivity: sensitivity });
      toast.success("敏感度配置已保存");
    } catch (e) { toast.error(String(e)); }
    finally { setSavingSens(false); }
  }

  function toggleSelect(id: string) {
    setSelected((prev) => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });
  }

  const categories = Object.keys(grouped).sort();

  return (
    <div className="space-y-6">
      <PageIntro eyebrow="OWASP Rule Management" title="OWASP 规则管理" description="按类别管理 OWASP 检测规则，配置敏感度矩阵，支持批量启用/禁用操作。" />

      {stats && (
        <MetricGrid>
          <MetricCard label="规则总数" value={stats.total} />
          <MetricCard label="已启用" value={stats.enabled_count} tone="success" />
          <MetricCard label="已禁用" value={stats.disabled_count} />
          <MetricCard label="类别数" value={Object.keys(stats.by_category ?? {}).length} />
        </MetricGrid>
      )}

      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList>
          <TabsTrigger value="rules">规则列表</TabsTrigger>
          <TabsTrigger value="sensitivity">敏感度矩阵</TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="space-y-4">
          {selected.size > 0 && (
            <div className="flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-2">
              <span className="text-sm text-slate-600">已选 {selected.size} 条</span>
              <Button size="sm" variant="outline" className="rounded-xl" onClick={() => batchToggleSelected(true)}>批量启用</Button>
              <Button size="sm" variant="outline" className="rounded-xl" onClick={() => batchToggleSelected(false)}>批量禁用</Button>
            </div>
          )}

          {loading ? (
            <Surface><div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div></Surface>
          ) : categories.length === 0 ? (
            <Surface><EmptyState title="暂无 OWASP 规则" description="引擎未注册任何 OWASP 规则。" /></Surface>
          ) : (
            categories.map((cat) => (
              <Surface key={cat} title={cat} description={`${grouped[cat].length} 条规则`} action={
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" className="rounded-xl" onClick={() => batchToggleCategory(cat, true)}>全部启用</Button>
                  <Button size="sm" variant="outline" className="rounded-xl" onClick={() => batchToggleCategory(cat, false)}>全部禁用</Button>
                </div>
              }>
                <div className="overflow-x-auto rounded-xl border border-slate-200">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-10"><Checkbox checked={grouped[cat].every((r) => selected.has(r.id))} onCheckedChange={(v) => { const ids = grouped[cat].map((r) => r.id); setSelected((prev) => { const s = new Set(prev); ids.forEach((id) => v ? s.add(id) : s.delete(id)); return s; }); }} /></TableHead>
                        <TableHead>规则 ID</TableHead>
                        <TableHead>名称</TableHead>
                        <TableHead>描述</TableHead>
                        <TableHead>启用</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {grouped[cat].map((rule) => (
                        <TableRow key={rule.id}>
                          <TableCell><Checkbox checked={selected.has(rule.id)} onCheckedChange={() => toggleSelect(rule.id)} /></TableCell>
                          <TableCell><Badge variant="outline" className="rounded-lg font-mono text-xs">{rule.id}</Badge></TableCell>
                          <TableCell className="font-medium text-slate-900">{rule.name}</TableCell>
                          <TableCell className="text-sm text-slate-500 max-w-[300px] truncate">{rule.description}</TableCell>
                          <TableCell><Switch checked={rule.enabled} onCheckedChange={(v) => handleToggle(rule.id, v)} /></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </Surface>
            ))
          )}
        </TabsContent>

        <TabsContent value="sensitivity">
          <Surface title="敏感度矩阵" description="为每个 OWASP 类别配置检测敏感度级别。" action={
            <Button onClick={saveSensitivity} disabled={savingSens}>{savingSens ? "保存中..." : "保存配置"}</Button>
          }>
            <div className="overflow-x-auto rounded-xl border border-slate-200">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="min-w-[160px]">类别</TableHead>
                    {sensitivityLevels.map((l) => <TableHead key={l} className="text-center">{levelLabel[l]}</TableHead>)}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {owaspModuleOptions.map((mod) => (
                    <TableRow key={mod.key}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <ShieldCheck className="h-4 w-4 text-cyan-700" />
                          <span className="font-medium text-slate-900">{mod.label}</span>
                        </div>
                      </TableCell>
                      {sensitivityLevels.map((level) => (
                        <TableCell key={level} className="text-center">
                          <input type="radio" name={`sens-${mod.key}`} checked={(sensitivity[mod.key] ?? "off") === level} onChange={() => setSensitivity({ ...sensitivity, [mod.key]: level })} className="h-4 w-4 accent-cyan-600" />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Surface>
        </TabsContent>
      </Tabs>
    </div>
  );
}