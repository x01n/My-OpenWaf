"use client";

import { useEffect, useMemo, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { PageIntro, InlineMeta, Surface } from "@/components/console-shell";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { owaspModuleOptions } from "@/lib/console";
import { getProtectionSettings, updateProtectionSettings, type ProtectionSettings } from "@/lib/api";

const moduleModes = [
  { value: "off", label: "关闭" },
  { value: "observe", label: "观察" },
  { value: "mid", label: "平衡" },
  { value: "high", label: "严格" },
] as const;

export default function ProtectionPage() {
  const [settings, setSettings] = useState<ProtectionSettings | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getProtectionSettings().then(setSettings).catch((error) => toast.error(String(error)));
  }, []);

  const enabledCount = useMemo(() => {
    if (!settings?.owasp_modules) return 0;
    return Object.values(settings.owasp_modules).filter((value) => value !== "off").length;
  }, [settings]);

  async function save() {
    if (!settings) return;
    setSaving(true);
    try {
      const result = await updateProtectionSettings(settings);
      setSettings(result);
      toast.success("防护配置已保存");
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
        eyebrow="Global Protection"
        title="攻击防护"
        description="配置全局 OWASP、请求限流、错误限流、维护模式和登录安全策略。所有设置都直接写入 /api/v1/protection-settings。"
        actions={<Button onClick={save} disabled={saving}>{saving ? "保存中..." : "保存配置"}</Button>}
      />

      <div className="grid gap-6 xl:grid-cols-3">
        <Surface title="全局状态" description="当前防护基础开关。" className="xl:col-span-1">
          <div className="grid gap-3">
            <InlineMeta label="OWASP" value={settings.builtin_owasp_enabled ? "已启用" : "已关闭"} />
            <InlineMeta label="请求限流" value={settings.request_ratelimit_enabled ? `${settings.request_ratelimit_max}/${settings.request_ratelimit_window}s` : "关闭"} />
            <InlineMeta label="错误限流" value={settings.error_ratelimit_enabled ? `${settings.error_ratelimit_max}/${settings.error_ratelimit_window}s` : "关闭"} />
            <InlineMeta label="维护模式" value={settings.maintenance_global_enabled ? `开启 · ${settings.maintenance_global_status}` : "关闭"} />
          </div>
        </Surface>

        <Surface title="基础开关" description="最常用的全局防护开关。" className="xl:col-span-2">
          <div className="grid gap-3 md:grid-cols-2">
            <ToggleItem label="启用 OWASP 引擎" checked={settings.builtin_owasp_enabled} onChange={(value) => setSettings({ ...settings, builtin_owasp_enabled: value })} />
            <ToggleItem label="请求限流" checked={settings.request_ratelimit_enabled} onChange={(value) => setSettings({ ...settings, request_ratelimit_enabled: value })} />
            <ToggleItem label="错误限流" checked={settings.error_ratelimit_enabled} onChange={(value) => setSettings({ ...settings, error_ratelimit_enabled: value })} />
            <ToggleItem label="维护模式" checked={settings.maintenance_global_enabled} onChange={(value) => setSettings({ ...settings, maintenance_global_enabled: value })} />
            <ToggleItem label="Bot 检测入口" checked={settings.bot_detection_enabled} onChange={(value) => setSettings({ ...settings, bot_detection_enabled: value })} />
            <ToggleItem label="自动封禁" checked={settings.auto_ban_enabled} onChange={(value) => setSettings({ ...settings, auto_ban_enabled: value })} />
          </div>
        </Surface>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Surface title="限流与维护参数" description="用于控制吞吐、错误熔断和维护响应。">
          <div className="grid gap-4 md:grid-cols-2">
            <NumberField label="请求窗口（秒）" value={settings.request_ratelimit_window} onChange={(value) => setSettings({ ...settings, request_ratelimit_window: value })} />
            <NumberField label="请求上限" value={settings.request_ratelimit_max} onChange={(value) => setSettings({ ...settings, request_ratelimit_max: value })} />
            <NumberField label="错误窗口（秒）" value={settings.error_ratelimit_window} onChange={(value) => setSettings({ ...settings, error_ratelimit_window: value })} />
            <NumberField label="错误上限" value={settings.error_ratelimit_max} onChange={(value) => setSettings({ ...settings, error_ratelimit_max: value })} />
            <NumberField label="自动封禁阈值" value={settings.auto_ban_threshold} onChange={(value) => setSettings({ ...settings, auto_ban_threshold: value })} />
            <NumberField label="自动封禁时长（秒）" value={settings.auto_ban_duration} onChange={(value) => setSettings({ ...settings, auto_ban_duration: value })} />
            <NumberField label="维护状态码" value={settings.maintenance_global_status} onChange={(value) => setSettings({ ...settings, maintenance_global_status: value })} />
            <NumberField label="密码最短长度" value={settings.login_min_password_length} onChange={(value) => setSettings({ ...settings, login_min_password_length: value })} />
          </div>
        </Surface>

        <Surface title="命中动作" description="后端真实支持的全局动作配置。">
          <div className="grid gap-4 md:grid-cols-2">
            <SelectField label="OWASP 命中动作" value={settings.builtin_owasp_on_hit} options={["intercept", "observe"]} onChange={(value) => setSettings({ ...settings, builtin_owasp_on_hit: value })} />
            <SelectField label="OWASP 敏感度" value={settings.builtin_owasp_sensitivity} options={["low", "mid", "high"]} onChange={(value) => setSettings({ ...settings, builtin_owasp_sensitivity: value })} />
            <SelectField label="请求限流动作" value={settings.request_ratelimit_action} options={["intercept", "observe"]} onChange={(value) => setSettings({ ...settings, request_ratelimit_action: value })} />
            <SelectField label="错误限流动作" value={settings.error_ratelimit_action} options={["intercept", "observe"]} onChange={(value) => setSettings({ ...settings, error_ratelimit_action: value })} />
            <SelectField label="CVE 动作" value={settings.cve_action} options={["intercept", "observe"]} onChange={(value) => setSettings({ ...settings, cve_action: value })} />
          </div>
        </Surface>
      </div>

      <Surface title="OWASP 模块矩阵" description={`当前已启用 ${enabledCount} 个模块；键名已与后端引擎分类常量对齐。`}>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {owaspModuleOptions.map((module) => (
            <div key={module.key} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-900">
                <ShieldAlert className="h-4 w-4 text-cyan-700" />
                {module.label}
              </div>
              <Select
                value={settings.owasp_modules?.[module.key] || "off"}
                onValueChange={(value) =>
                  setSettings({
                    ...settings,
                    owasp_modules: {
                      ...(settings.owasp_modules || {}),
                      [module.key]: value,
                    },
                  })
                }
              >
                <SelectTrigger className="rounded-xl"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {moduleModes.map((item) => (
                    <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ))}
        </div>
      </Surface>
    </div>
  );
}

function ToggleItem({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
      <span className="text-sm font-medium text-slate-900">{label}</span>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <label className="space-y-2 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm">
      <span className="font-medium text-slate-900">{label}</span>
      <input className="h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-slate-900" type="number" value={value} onChange={(event) => onChange(Number(event.target.value))} />
    </label>
  );
}

function SelectField({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <div className="space-y-2 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm">
      <div className="font-medium text-slate-900">{label}</div>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger className="rounded-xl"><SelectValue /></SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option} value={option}>{option}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
