"use client";

import { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageIntro, Surface, EmptyState } from "@/components/console-shell";
import { owaspModuleOptions } from "@/lib/console";
import {
  getOWASPRules, getOWASPRuleStats, updateOWASPRule, batchUpdateOWASPRules,
  getSensitivityConfig, updateSensitivityConfig,
  type OWASPRule, type OWASPRuleStats,
} from "@/lib/rules-api";

const sensitivityLevels = ["off", "low", "medium", "high", "very_high", "strict"] as const;
const levelLabel: Record<string, string> = { off: "关闭", low: "低", medium: "中", high: "高", very_high: "极高", strict: "严格" };

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-lg border bg-white p-5 shadow-sm">
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );
}

export default function OWASPRuleManagementPage() {
  const [grouped, setGrouped] = useState<Record<string, OWASPRule[]>>({});
  const [stats, setStats] = useState<OWASPRuleStats | null>(null);
  const [sensitivity, setSensitivity] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [savingSens, setSavingSens] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [rulesRes, statsRes] = await Promise.all([getOWASPRules(), getOWASPRuleStats()]);
      const items = rulesRes.items ?? [];
      const groupedRules = rulesRes.grouped ?? items.reduce<Record<string, OWASPRule[]>>((acc, rule) => {
        const category = rule.category || "uncategorized";
        acc[category] = [...(acc[category] ?? []), rule];
        return acc;
      }, {});
      setGrouped(groupedRules);
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
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleCollapse(cat: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  }

  const categories = Object.keys(grouped).sort();

  return (
    <div className="space-y-6">
      <PageIntro eyebrow="OWASP Rule Management" title="OWASP 规则管理" description="按类别管理 OWASP 检测规则，配置敏感度矩阵，支持批量启用/禁用操作。" />

      {stats && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="规则总数" value={stats.total} color="text-slate-900" />
          <StatCard label="已启用" value={stats.enabled_count} color="text-emerald-600" />
          <StatCard label="已禁用" value={stats.disabled_count} color="text-slate-500" />
          <StatCard label="类别数" value={Object.keys(stats.by_category ?? {}).length} color="text-cyan-600" />
        </div>
      )}

      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList>
          <TabsTrigger value="rules">规则列表</TabsTrigger>
          <TabsTrigger value="sensitivity">敏感度矩阵</TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="space-y-4">
          {selected.size > 0 && (
            <div className="flex items-center gap-3 rounded-lg border border-slate-200 bg-slate-50 px-4 py-2">
              <span className="text-sm text-slate-600">已选 {selected.size} 条</span>
              <Button size="sm" variant="outline" className="rounded-md" onClick={() => batchToggleSelected(true)}>批量启用</Button>
              <Button size="sm" variant="outline" className="rounded-md" onClick={() => batchToggleSelected(false)}>批量禁用</Button>
            </div>
          )}

          {loading ? (
            <Surface><div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div></Surface>
          ) : categories.length === 0 ? (
            <Surface><EmptyState title="暂无 OWASP 规则" description="引擎未注册任何 OWASP 规则。" /></Surface>
          ) : (
            categories.map((cat) => {
              const isCollapsed = collapsed.has(cat);
              return (
                <div key={cat} className="rounded-lg border border-slate-200 bg-white shadow-sm overflow-hidden">
                  <div
                    className="flex items-center justify-between px-5 py-3 cursor-pointer hover:bg-slate-50 transition-colors"
                    onClick={() => toggleCollapse(cat)}
                  >
                    <div className="flex items-center gap-2">
                      {isCollapsed ? <ChevronRight className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
                      <span className="font-semibold text-slate-900">{cat}</span>
                      <Badge variant="outline" className="rounded-md text-xs">{grouped[cat].length} 条</Badge>
                    </div>
                    <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
                      <Button size="sm" variant="outline" className="rounded-md h-7 text-xs" onClick={() => batchToggleCategory(cat, true)}>全部启用</Button>
                      <Button size="sm" variant="outline" className="rounded-md h-7 text-xs" onClick={() => batchToggleCategory(cat, false)}>全部禁用</Button>
                    </div>
                  </div>
                  {!isCollapsed && (
                    <div className="border-t border-slate-200">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-10">
                              <Checkbox
                                checked={grouped[cat].every((r) => selected.has(r.id))}
                                onCheckedChange={(v) => {
                                  const ids = grouped[cat].map((r) => r.id);
                                  setSelected((prev) => {
                                    const s = new Set(prev);
                                    ids.forEach((id) => v ? s.add(id) : s.delete(id));
                                    return s;
                                  });
                                }}
                              />
                            </TableHead>
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
                              <TableCell><Badge variant="outline" className="rounded-md font-mono text-xs">{rule.id}</Badge></TableCell>
                              <TableCell className="font-medium text-slate-900">{rule.name}</TableCell>
                              <TableCell className="text-sm text-slate-500 max-w-[300px] truncate">{rule.description}</TableCell>
                              <TableCell><Switch checked={rule.enabled} onCheckedChange={(v) => handleToggle(rule.id, v)} /></TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </TabsContent>

        <TabsContent value="sensitivity">
          <Surface title="敏感度矩阵" description="为每个 OWASP 类别配置检测敏感度级别（18 类别 × 6 级别）。" action={
            <Button onClick={saveSensitivity} disabled={savingSens} className="rounded-md bg-cyan-600 hover:bg-cyan-700">
              {savingSens ? "保存中..." : "保存配置"}
            </Button>
          }>
            <div className="overflow-x-auto rounded-lg border border-slate-200">
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
                          <ShieldCheck className="h-4 w-4 text-cyan-600" />
                          <span className="font-medium text-slate-900">{mod.label}</span>
                        </div>
                      </TableCell>
                      {sensitivityLevels.map((level) => (
                        <TableCell key={level} className="text-center">
                          <input
                            type="radio"
                            name={`sens-${mod.key}`}
                            checked={(sensitivity[mod.key] ?? "off") === level}
                            onChange={() => setSensitivity({ ...sensitivity, [mod.key]: level })}
                            className="h-4 w-4 accent-cyan-600"
                          />
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
