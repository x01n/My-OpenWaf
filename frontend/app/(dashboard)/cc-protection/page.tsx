"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Clock, Shield, Zap, Lock, Plus, Pencil, Trash2, Info,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  getProtectionSettings, updateProtectionSettings, type ProtectionSettings,
} from "@/lib/api";
import { getWAFActionMeta, terminalWAFActionOptions } from "@/lib/console";
import { cn } from "@/lib/utils";

/* ───── types ───── */
interface CCCondition {
  target: string;
  operator: string;
  value: string;
}
interface CCRule {
  name: string;
  enabled?: boolean;
  conditions: CCCondition[];
  window: number;
  threshold: number;
  action: string;
  duration: number;
  captcha?: boolean;
}

const emptyCondition: CCCondition = { target: "url_path", operator: "equals", value: "" };
const emptyRule: CCRule = {
  name: "", enabled: true,
  conditions: [{ ...emptyCondition }],
  window: 60, threshold: 100, action: "challenge", duration: 5, captcha: false,
};

const targetOptions = [
  { value: "url_path", label: "URL 路径" },
  { value: "header", label: "请求头" },
  { value: "method", label: "请求方法" },
];
const operatorOptions = [
  { value: "equals", label: "等于" },
  { value: "contains", label: "包含" },
  { value: "prefix", label: "前缀关键字" },
];

/* ───── main ───── */
export default function CCProtectionPage() {
  const [settings, setSettings] = useState<ProtectionSettings | null>(null);
  const [rules, setRules] = useState<CCRule[]>([]);
  const [saving, setSaving] = useState(false);

  // module dialogs
  const [waitingRoomOpen, setWaitingRoomOpen] = useState(false);
  const [rateLimitOpen, setRateLimitOpen] = useState(false);
  const [bruteForceOpen, setBruteForceOpen] = useState(false);

  // rule dialog
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false);
  const [editIndex, setEditIndex] = useState<number | null>(null);
  const [draft, setDraft] = useState<CCRule>({ ...emptyRule });

  const load = useCallback(() => {
    getProtectionSettings()
      .then((data) => {
        setSettings(data);
        setRules(Array.isArray(data.cc_rules) ? (data.cc_rules as CCRule[]) : []);
      })
      .catch((err) => toast.error(String(err)));
  }, []);

  useEffect(() => { load(); }, [load]);

  async function persist(nextRules?: CCRule[], nextSettings?: ProtectionSettings) {
    const payload = {
      ...(nextSettings || settings),
      cc_rules: nextRules ?? rules,
    } as ProtectionSettings;
    setSaving(true);
    try {
      const result = await updateProtectionSettings(payload);
      setSettings(result);
      setRules(Array.isArray(result.cc_rules) ? (result.cc_rules as CCRule[]) : []);
      return result;
    } finally {
      setSaving(false);
    }
  }

  /* ── module card helpers ── */
  async function toggleWaitingRoom(val: boolean) {
    if (!settings) return;
    const next = { ...settings, waiting_room_enabled: val };
    setSettings(next);
    await persist(rules, next);
    toast.success(val ? "等待室草案已启用" : "等待室草案已关闭");
  }

  async function toggleRateLimit(val: boolean) {
    if (!settings) return;
    const next = { ...settings, request_ratelimit_enabled: val };
    setSettings(next);
    await persist(rules, next);
    toast.success(val ? "频率限制已启用" : "频率限制已关闭");
  }

  async function toggleBruteForce(val: boolean) {
    if (!settings) return;
    const next = { ...settings, auto_ban_enabled: val };
    setSettings(next);
    await persist(rules, next);
    toast.success(val ? "暴力防护已启用" : "暴力防护已关闭");
  }

  /* ── rule CRUD ── */
  function openAddRule() {
    setEditIndex(null);
    setDraft({ ...emptyRule, conditions: [{ ...emptyCondition }] });
    setRuleDialogOpen(true);
  }
  function openEditRule(idx: number) {
    setEditIndex(idx);
    setDraft({ ...rules[idx], conditions: rules[idx].conditions.map((c) => ({ ...c })) });
    setRuleDialogOpen(true);
  }
  async function saveRule() {
    if (!draft.name.trim()) { toast.error("请输入规则名称"); return; }
    const nextRules = [...rules];
    if (editIndex !== null) {
      nextRules[editIndex] = draft;
    } else {
      nextRules.push(draft);
    }
    try {
      await persist(nextRules);
      toast.success(editIndex !== null ? "规则已更新" : "规则已添加");
      setRuleDialogOpen(false);
    } catch (err) {
      toast.error(String(err));
    }
  }
  async function deleteRule(idx: number) {
    const next = rules.filter((_, i) => i !== idx);
    try {
      await persist(next);
      toast.success("规则已删除");
    } catch (err) {
      toast.error(String(err));
    }
  }
  async function toggleRule(idx: number) {
    const next = [...rules];
    next[idx] = { ...next[idx], enabled: !next[idx].enabled };
    try {
      await persist(next);
    } catch (err) {
      toast.error(String(err));
    }
  }

  /* ── condition helpers ── */
  function updateCondition(ci: number, patch: Partial<CCCondition>) {
    setDraft((d) => ({
      ...d,
      conditions: d.conditions.map((c, i) => (i === ci ? { ...c, ...patch } : c)),
    }));
  }
  function addCondition() {
    setDraft((d) => ({ ...d, conditions: [...d.conditions, { ...emptyCondition }] }));
  }
  function removeCondition(ci: number) {
    setDraft((d) => ({ ...d, conditions: d.conditions.filter((_, i) => i !== ci) }));
  }

  /* ── save module config ── */
  async function saveWaitingRoom() {
    if (!settings) return;
    try { await persist(rules); toast.success("等待室草案已保存"); setWaitingRoomOpen(false); } catch (err) { toast.error(String(err)); }
  }
  async function saveRateLimit() {
    if (!settings) return;
    try { await persist(rules); toast.success("频率限制配置已保存"); setRateLimitOpen(false); } catch (err) { toast.error(String(err)); }
  }
  async function saveBruteForce() {
    if (!settings) return;
    try { await persist(rules); toast.success("暴力防护配置已保存"); setBruteForceOpen(false); } catch (err) { toast.error(String(err)); }
  }

  if (!settings) {
    return (
      <div className="space-y-6 p-6">
        <div className="h-24 animate-pulse rounded-lg bg-slate-100" />
        <div className="h-64 animate-pulse rounded-lg bg-slate-100" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">CC 防护</h1>
          <p className="mt-1 text-sm text-slate-500">管理等待室、频率限制、暴力防护及自定义 CC 规则</p>
        </div>
      </div>

      {/* 3 Module Cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {/* Waiting Room */}
        <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-100 text-slate-600">
                <Clock className="h-4 w-4" />
              </div>
              <span className="text-sm font-semibold text-slate-900">等待室</span>
            </div>
            <Switch checked={settings.waiting_room_enabled || false} onCheckedChange={toggleWaitingRoom} />
          </div>
          <p className="mb-4 text-xs text-slate-500">当前仅保存等待室草案开关，数据面尚未接入排队削峰执行链路。</p>
          <Button variant="outline" size="sm" className="w-full rounded-md border-slate-200 text-slate-700 hover:bg-slate-50" onClick={() => setWaitingRoomOpen(true)}>
            配置
          </Button>
        </div>

        {/* Rate Limit */}
        <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-100 text-slate-600">
                <Zap className="h-4 w-4" />
              </div>
              <span className="text-sm font-semibold text-slate-900">频率限制</span>
            </div>
            <Switch checked={settings.request_ratelimit_enabled} onCheckedChange={toggleRateLimit} />
          </div>
          <p className="mb-1 text-xs text-slate-500">
            {settings.request_ratelimit_enabled
              ? `${settings.request_ratelimit_max} 次 / ${settings.request_ratelimit_window}s · 动作: ${settings.request_ratelimit_action}`
              : "未启用频率限制"}
          </p>
          <p className="mb-3 text-xs text-slate-400">严格限制每个 IP 的访问频率，阻止超限的 IP</p>
          <Button variant="outline" size="sm" className="w-full rounded-md border-slate-200 text-slate-700 hover:bg-slate-50" onClick={() => setRateLimitOpen(true)}>
            配置
          </Button>
        </div>

        {/* Brute Force */}
        <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-100 text-slate-600">
                <Lock className="h-4 w-4" />
              </div>
              <span className="text-sm font-semibold text-slate-900">暴力防护</span>
            </div>
            <Switch checked={settings.auto_ban_enabled} onCheckedChange={toggleBruteForce} />
          </div>
          <p className="mb-4 text-xs text-slate-500">
            {settings.auto_ban_enabled
              ? `阈值 ${settings.auto_ban_threshold} / ${settings.auto_ban_window}s · 封禁 ${settings.auto_ban_duration}s`
              : "未启用暴力防护"}
          </p>
          <Button variant="outline" size="sm" className="w-full rounded-md border-slate-200 text-slate-700 hover:bg-slate-50" onClick={() => setBruteForceOpen(true)}>
            配置
          </Button>
        </div>
      </div>

      {/* Custom Rules Table */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900">自定义规则</h2>
            <p className="mt-0.5 text-xs text-slate-500">基于 URL、Header、Method 定义频率阈值与动作</p>
          </div>
          <Button onClick={openAddRule} className="rounded-md bg-slate-950 text-white hover:bg-slate-800" size="sm">
            <Plus className="mr-1.5 h-3.5 w-3.5" /> 添加规则
          </Button>
        </div>

        {rules.length === 0 ? (
          <div className="flex min-h-[200px] flex-col items-center justify-center p-8 text-center">
            <Shield className="mb-3 h-10 w-10 text-slate-300" />
            <p className="text-sm font-medium text-slate-600">还没有自定义规则</p>
            <p className="mt-1 text-xs text-slate-400">点击「添加规则」创建第一条 CC 自定义规则</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/80">
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-600">状态</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600">名称</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600">匹配条件</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600">持续时间</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-600">动作</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold text-slate-600">操作</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, idx) => (
                  <tr key={`${rule.name}-${idx}`} className="border-b border-slate-50 hover:bg-slate-50/50">
                    <td className="px-5 py-3">
                      <Switch checked={rule.enabled !== false} onCheckedChange={() => toggleRule(idx)} size="sm" />
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-800">{rule.name || `规则 ${idx + 1}`}</td>
                    <td className="px-4 py-3 text-slate-600">
                      {rule.conditions.map((c, ci) => (
                        <span key={ci} className="mr-1 inline-block rounded bg-slate-100 px-1.5 py-0.5 text-xs">
                          {targetOptions.find((t) => t.value === c.target)?.label || c.target}{" "}
                          {operatorOptions.find((o) => o.value === c.operator)?.label || c.operator}{" "}
                          {c.value || "…"}
                        </span>
                      ))}
                    </td>
                    <td className="px-4 py-3 text-slate-600">
                      {rule.window}s / {rule.threshold}次 → {rule.duration}分钟
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn("inline-flex rounded-md border px-2 py-0.5 text-xs font-medium", getWAFActionMeta(rule.action).className)}>
                        {getWAFActionMeta(rule.action).shortLabel}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => openEditRule(idx)} className="rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600">
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button onClick={() => deleteRule(idx)} className="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-600">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ══════ Waiting Room Dialog ══════ */}
      <Dialog open={waitingRoomOpen} onOpenChange={setWaitingRoomOpen}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>等待室配置</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              当前后端仅保存 <code>waiting_room_enabled</code> 草案开关，尚未看到数据面排队/削峰执行链路消费这些参数。
            </div>
            <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
              等待室容量、等待时间和刷新间隔保留为后续接线方向，本轮不提供可编辑参数，避免误认为保存后已生效。
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setWaitingRoomOpen(false)}>取消</Button>
            <Button className="bg-slate-950 text-white hover:bg-slate-800" onClick={saveWaitingRoom}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ══════ Rate Limit Dialog ══════ */}
      <Dialog open={rateLimitOpen} onOpenChange={setRateLimitOpen}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>频率限制配置</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <label className="block text-sm">
              <span className="font-medium text-slate-700">请求次数阈值</span>
              <Input type="number" className="mt-1 rounded-md" value={settings.request_ratelimit_max}
                onChange={(e) => setSettings({ ...settings, request_ratelimit_max: Number(e.target.value) })} />
            </label>
            <label className="block text-sm">
              <span className="font-medium text-slate-700">时间窗口（秒）</span>
              <Input type="number" className="mt-1 rounded-md" value={settings.request_ratelimit_window}
                onChange={(e) => setSettings({ ...settings, request_ratelimit_window: Number(e.target.value) })} />
            </label>
            <label className="block text-sm">
              <span className="font-medium text-slate-700">超限动作</span>
              <Select value={settings.request_ratelimit_action} onValueChange={(v) => setSettings({ ...settings, request_ratelimit_action: v })}>
                <SelectTrigger className="mt-1 rounded-md"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="captcha">人机验证 (Challenge)</SelectItem>
                  <SelectItem value="intercept">拦截 (Intercept)</SelectItem>
                  <SelectItem value="block">封禁 (Block)</SelectItem>
                </SelectContent>
              </Select>
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRateLimitOpen(false)}>取消</Button>
            <Button className="bg-slate-950 text-white hover:bg-slate-800" onClick={saveRateLimit}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ══════ Brute Force Dialog ══════ */}
      <Dialog open={bruteForceOpen} onOpenChange={setBruteForceOpen}>
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>暴力防护配置</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <label className="block text-sm">
              <span className="font-medium text-slate-700">失败次数阈值</span>
              <Input type="number" className="mt-1 rounded-md" value={settings.auto_ban_threshold}
                onChange={(e) => setSettings({ ...settings, auto_ban_threshold: Number(e.target.value) })} />
            </label>
            <label className="block text-sm">
              <span className="font-medium text-slate-700">检测窗口（秒）</span>
              <Input type="number" className="mt-1 rounded-md" value={settings.auto_ban_window}
                onChange={(e) => setSettings({ ...settings, auto_ban_window: Number(e.target.value) })} />
            </label>
            <label className="block text-sm">
              <span className="font-medium text-slate-700">封禁时长（秒）</span>
              <Input type="number" className="mt-1 rounded-md" value={settings.auto_ban_duration}
                onChange={(e) => setSettings({ ...settings, auto_ban_duration: Number(e.target.value) })} />
            </label>
            <label className="block text-sm">
              <span className="font-medium text-slate-700">关联字段</span>
              <Select defaultValue="ip">
                <SelectTrigger className="mt-1 rounded-md"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="ip">IP 地址</SelectItem>
                  <SelectItem value="account">账号</SelectItem>
                  <SelectItem value="ip_account">IP + 账号</SelectItem>
                </SelectContent>
              </Select>
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBruteForceOpen(false)}>取消</Button>
            <Button className="bg-slate-950 text-white hover:bg-slate-800" onClick={saveBruteForce}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ══════ Add / Edit Rule Dialog ══════ */}
      <Dialog open={ruleDialogOpen} onOpenChange={setRuleDialogOpen}>
        <DialogContent className="max-w-2xl rounded-lg">
          <DialogHeader>
            <DialogTitle>{editIndex !== null ? "编辑规则" : "添加规则"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {/* Name */}
            <label className="block text-sm">
              <span className="font-medium text-slate-700">名称 <span className="text-rose-500">*</span></span>
              <Input className="mt-1 rounded-md" placeholder="规则名称"
                value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </label>

            {/* Conditions */}
            <div className="rounded-lg border border-slate-200 bg-slate-50/50 p-4">
              {draft.conditions.map((cond, ci) => (
                <div key={ci} className="mb-3 flex items-start gap-2">
                  <div className="grid flex-1 grid-cols-3 gap-2">
                    <div>
                      <span className="mb-1 block text-xs font-medium text-slate-500">匹配目标</span>
                      <Select value={cond.target} onValueChange={(v) => updateCondition(ci, { target: v })}>
                        <SelectTrigger className="rounded-md bg-white"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {targetOptions.map((t) => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <span className="mb-1 block text-xs font-medium text-slate-500">匹配方式 <span className="text-rose-500">*</span></span>
                      <Select value={cond.operator} onValueChange={(v) => updateCondition(ci, { operator: v })}>
                        <SelectTrigger className="rounded-md bg-white"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {operatorOptions.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <span className="mb-1 block text-xs font-medium text-slate-500">匹配内容 <span className="text-rose-500">*</span></span>
                      <Input className="rounded-md bg-white" placeholder="例如: /index.html"
                        value={cond.value} onChange={(e) => updateCondition(ci, { value: e.target.value })} />
                    </div>
                  </div>
                  {draft.conditions.length > 1 && (
                    <button onClick={() => removeCondition(ci)} className="mt-6 rounded p-1 text-slate-400 hover:bg-slate-200 hover:text-slate-600">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>
              ))}
              <button onClick={addCondition} className="mt-1 rounded-md border border-dashed border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50">
                + 添加一个 AND 条件
              </button>
            </div>

            {/* Params */}
            <div className="grid grid-cols-4 gap-3">
              <label className="block text-sm">
                <span className="font-medium text-slate-700">经过时间 <span className="text-rose-500">*</span></span>
                <div className="mt-1 flex items-center gap-1">
                  <Input type="number" className="rounded-md" value={draft.window}
                    onChange={(e) => setDraft({ ...draft, window: Number(e.target.value) })} />
                  <span className="text-xs text-slate-500">秒</span>
                </div>
              </label>
              <label className="block text-sm">
                <span className="font-medium text-slate-700">请求次数达到 <span className="text-rose-500">*</span></span>
                <div className="mt-1 flex items-center gap-1">
                  <Input type="number" className="rounded-md" value={draft.threshold}
                    onChange={(e) => setDraft({ ...draft, threshold: Number(e.target.value) })} />
                  <span className="text-xs text-slate-500">次</span>
                </div>
              </label>
              <label className="block text-sm">
                <span className="font-medium text-slate-700">限制结果</span>
                <Select value={draft.action} onValueChange={(v) => setDraft({ ...draft, action: v })}>
                  <SelectTrigger className="mt-1 rounded-md"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {terminalWAFActionOptions.map((a) => <SelectItem key={a.value} value={a.value}>{a.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </label>
              <label className="block text-sm">
                <span className="font-medium text-slate-700">人机验证 <span className="text-rose-500">*</span></span>
                <div className="mt-1 flex items-center gap-1">
                  <Input type="number" className="rounded-md" value={draft.duration}
                    onChange={(e) => setDraft({ ...draft, duration: Number(e.target.value) })} />
                  <span className="text-xs text-slate-500">分钟</span>
                </div>
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRuleDialogOpen(false)}>取消</Button>
            <Button className="bg-slate-950 text-white hover:bg-slate-800" onClick={saveRule} disabled={saving}>
              {saving ? "保存中..." : "确定"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
