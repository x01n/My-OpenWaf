"use client";

import { useEffect, useState } from "react";
import { Radar, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { EmptyState, InlineMeta, PageIntro, Surface } from "@/components/console-shell";
import { getProtectionSettings, updateProtectionSettings, type ProtectionSettings } from "@/lib/api";

interface CCRule {
  name: string;
  conditions: Array<{ target: string; operator: string; value: string }>;
  window: number;
  threshold: number;
  action: string;
  duration: number;
}

const emptyRule: CCRule = {
  name: "",
  conditions: [{ target: "url_path", operator: "equals", value: "" }],
  window: 60,
  threshold: 100,
  action: "captcha",
  duration: 5,
};

export default function CCProtectionPage() {
  const [settings, setSettings] = useState<ProtectionSettings | null>(null);
  const [rules, setRules] = useState<CCRule[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [draft, setDraft] = useState<CCRule>(emptyRule);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getProtectionSettings().then((data) => {
      setSettings(data);
      setRules(Array.isArray(data.cc_rules) ? (data.cc_rules as CCRule[]) : []);
    }).catch((error) => toast.error(String(error)));
  }, []);

  async function persist(nextRules: CCRule[], nextSettings?: ProtectionSettings) {
    const payload = {
      ...(nextSettings || settings),
      cc_rules: nextRules,
    } as ProtectionSettings;
    const result = await updateProtectionSettings(payload);
    setSettings(result);
    setRules(Array.isArray(result.cc_rules) ? (result.cc_rules as CCRule[]) : []);
  }

  async function saveRule() {
    if (!settings) return;
    setSaving(true);
    try {
      const nextRules = [...rules, draft];
      await persist(nextRules);
      toast.success("CC 规则已保存");
      setDialogOpen(false);
      setDraft(emptyRule);
    } catch (error) {
      toast.error(String(error));
    } finally {
      setSaving(false);
    }
  }

  if (!settings) {
    return <Surface className="min-h-[320px] animate-pulse"><div className="h-full" /></Surface>;
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Traffic Pressure Control"
        title="CC 防护"
        description="管理等待室、全局 CC 自定义开关和基于 protection-settings 存储的 cc_rules 数组。"
        actions={<Button onClick={() => setDialogOpen(true)}>新增规则</Button>}
      />

      <div className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
        <Surface title="全局控制" description="全部写入 protection-settings。">
          <div className="grid gap-4">
            <ToggleRow label="启用等待室" checked={settings.waiting_room_enabled || false} onChange={async (value) => { const next = { ...settings, waiting_room_enabled: value }; setSettings(next); await persist(rules, next); }} />
            <ToggleRow label="使用自定义 CC 规则" checked={settings.cc_use_custom || false} onChange={async (value) => { const next = { ...settings, cc_use_custom: value }; setSettings(next); await persist(rules, next); }} />
            <InlineMeta label="请求限流" value={settings.request_ratelimit_enabled ? `${settings.request_ratelimit_max}/${settings.request_ratelimit_window}s` : "关闭"} />
            <InlineMeta label="自动封禁" value={settings.auto_ban_enabled ? `${settings.auto_ban_threshold}/${settings.auto_ban_window}s` : "关闭"} />
          </div>
        </Surface>

        <Surface title="当前规则概览" description="cc_rules 目前仅在 protection-settings 中以 JSON 数组形式存储。">
          {rules.length === 0 ? (
            <EmptyState title="还没有 CC 自定义规则" description="新增规则后，可基于 URL、Header、IP 或 Method 定义频率阈值与动作。" />
          ) : (
            <div className="space-y-3">
              {rules.map((rule, index) => (
                <div key={`${rule.name}-${index}`} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="mb-2 flex items-center gap-2 text-sm font-medium text-slate-900">
                    <Radar className="h-4 w-4 text-cyan-700" />
                    {rule.name || `规则 ${index + 1}`}
                  </div>
                  <div className="text-sm text-slate-600">{rule.window}s 内触发 {rule.threshold} 次 → {rule.action} {rule.duration} 分钟</div>
                  <div className="mt-2 text-xs text-slate-500">条件数：{rule.conditions.length}</div>
                  <div className="mt-3 flex justify-end">
                    <Button variant="ghost" size="sm" className="text-rose-600" onClick={async () => { const next = rules.filter((_, current) => current !== index); await persist(next); toast.success("规则已删除"); }}>删除</Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Surface>
      </div>

      <Surface title="接口说明" description="避免制造不存在的后端资源。">
        <div className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-4 text-sm leading-6 text-amber-900">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <p>当前 CC 规则并不是独立资源接口，而是 protection-settings 里的 cc_rules JSON 数组。新版页面已改为按真实存储模型编辑。</p>
        </div>
      </Surface>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl rounded-[28px]">
          <DialogHeader>
            <DialogTitle>新增 CC 规则</DialogTitle>
            <DialogDescription>新增的规则会保存到 protection-settings.cc_rules。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 md:grid-cols-2">
            <Input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="规则名称" className="rounded-xl" />
            <Input value={String(draft.window)} onChange={(event) => setDraft({ ...draft, window: Number(event.target.value) })} placeholder="时间窗口（秒）" type="number" className="rounded-xl" />
            <Input value={String(draft.threshold)} onChange={(event) => setDraft({ ...draft, threshold: Number(event.target.value) })} placeholder="触发阈值" type="number" className="rounded-xl" />
            <Input value={draft.action} onChange={(event) => setDraft({ ...draft, action: event.target.value })} placeholder="动作：captcha / block" className="rounded-xl" />
            <Input value={String(draft.duration)} onChange={(event) => setDraft({ ...draft, duration: Number(event.target.value) })} placeholder="持续时间（分钟）" type="number" className="rounded-xl" />
            <Input value={draft.conditions[0]?.target || ""} onChange={(event) => setDraft({ ...draft, conditions: [{ ...draft.conditions[0], target: event.target.value }] })} placeholder="条件目标" className="rounded-xl" />
            <Input value={draft.conditions[0]?.operator || ""} onChange={(event) => setDraft({ ...draft, conditions: [{ ...draft.conditions[0], operator: event.target.value }] })} placeholder="条件操作符" className="rounded-xl" />
            <Input value={draft.conditions[0]?.value || ""} onChange={(event) => setDraft({ ...draft, conditions: [{ ...draft.conditions[0], value: event.target.value }] })} placeholder="条件值" className="rounded-xl md:col-span-2" />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>取消</Button>
            <Button onClick={saveRule} disabled={saving}>{saving ? "保存中..." : "保存规则"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ToggleRow({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void | Promise<void> }) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
      <span className="text-sm font-medium text-slate-900">{label}</span>
      <input type="checkbox" checked={checked} onChange={(event) => void onChange(event.target.checked)} className="h-4 w-4" />
    </div>
  );
}
