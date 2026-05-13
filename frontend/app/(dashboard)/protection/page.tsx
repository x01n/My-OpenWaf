"use client";

import { useEffect, useMemo, useState } from "react";
import { ShieldAlert, ShieldCheck, Eye, Wrench, Zap, Save } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { PageIntro, Surface } from "@/components/console-shell";
import { getProtectionSettings, updateProtectionSettings, type ProtectionSettings } from "@/lib/api";
import { getWAFActionMeta, terminalWAFActionOptions } from "@/lib/console";
import { cn } from "@/lib/utils";

const protectionModes = [
  { id: "protection", label: "防护模式", desc: "标准防护，拦截已知攻击", icon: ShieldCheck, sensitivity: "mid" },
  { id: "observe", label: "观察模式", desc: "仅记录不拦截，用于调试", icon: Eye, sensitivity: "low" },
  { id: "maintenance", label: "维护模式", desc: "暂停防护，返回维护页面", icon: Wrench, sensitivity: "off" },
  { id: "strict", label: "高强度模式", desc: "最严格检测，可能误报", icon: Zap, sensitivity: "strict" },
] as const;

const sensitivityLevels = [
  { value: "off", label: "无" },
  { value: "low", label: "低" },
  { value: "mid", label: "中" },
  { value: "high", label: "高" },
  { value: "very_high", label: "极高" },
  { value: "strict", label: "严格" },
] as const;

const categories = [
  { key: "sqli", label: "SQL 注入" },
  { key: "xss", label: "XSS 跨站脚本" },
  { key: "cmd_injection", label: "命令注入" },
  { key: "ssrf", label: "SSRF 服务端请求伪造" },
  { key: "xxe", label: "XXE 外部实体" },
  { key: "ldap_injection", label: "LDAP 注入" },
  { key: "nosql_injection", label: "NoSQL 注入" },
  { key: "template_injection", label: "模板注入 (SSTI)" },
  { key: "jndi_injection", label: "JNDI 注入" },
  { key: "crlf_injection", label: "CRLF 注入" },
  { key: "expression_language", label: "EL 表达式" },
  { key: "deserialization", label: "反序列化" },
  { key: "graphql_injection", label: "GraphQL" },
  { key: "webshell", label: "Webshell" },
  { key: "revshell", label: "反向 Shell" },
  { key: "path_traversal", label: "路径遍历" },
] as const;

function deriveMode(settings: ProtectionSettings): string {
  if (settings.maintenance_global_enabled) return "maintenance";
  if (settings.builtin_owasp_on_hit === "observe") return "observe";
  if (settings.builtin_owasp_sensitivity === "high" || settings.builtin_owasp_sensitivity === "strict") return "strict";
  return "protection";
}

export default function ProtectionPage() {
  const [settings, setSettings] = useState<ProtectionSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [activeMode, setActiveMode] = useState("protection");

  useEffect(() => {
    getProtectionSettings()
      .then((data) => {
        setSettings(data);
        setActiveMode(deriveMode(data));
      })
      .catch((err) => toast.error(String(err)));
  }, []);

  const modules = useMemo(() => {
    if (!settings?.owasp_modules) return {} as Record<string, string>;
    return settings.owasp_modules;
  }, [settings]);

  function setModuleSensitivity(key: string, value: string) {
    if (!settings) return;
    setSettings({
      ...settings,
      owasp_modules: { ...modules, [key]: value },
    });
  }

  function applyMode(modeId: string) {
    if (!settings) return;
    setActiveMode(modeId);
    const mode = protectionModes.find((m) => m.id === modeId);
    if (!mode) return;

    const next = { ...settings };
    switch (modeId) {
      case "protection":
        next.builtin_owasp_enabled = true;
        next.builtin_owasp_on_hit = "intercept";
        next.builtin_owasp_sensitivity = "mid";
        next.maintenance_global_enabled = false;
        break;
      case "observe":
        next.builtin_owasp_enabled = true;
        next.builtin_owasp_on_hit = "observe";
        next.builtin_owasp_sensitivity = "mid";
        next.maintenance_global_enabled = false;
        break;
      case "maintenance":
        next.maintenance_global_enabled = true;
        break;
      case "strict":
        next.builtin_owasp_enabled = true;
        next.builtin_owasp_on_hit = "intercept";
        next.builtin_owasp_sensitivity = "high";
        next.maintenance_global_enabled = false;
        break;
    }
    setSettings(next);
  }

  async function save() {
    if (!settings) return;
    setSaving(true);
    try {
      const result = await updateProtectionSettings(settings);
      setSettings(result);
      toast.success("防护配置已保存");
    } catch (err) {
      toast.error(String(err));
    } finally {
      setSaving(false);
    }
  }

  if (!settings) {
    return (
      <div className="space-y-6 p-6">
        <div className="h-24 animate-pulse rounded-lg bg-slate-100" />
        <div className="h-96 animate-pulse rounded-lg bg-slate-100" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Protection Policy"
        title="攻击防护"
        description="配置全局防护模式、动作状态码、黑白名单优先级、挑战策略和检测类别敏感度。"
        actions={
          <Button
            onClick={save}
            disabled={saving}
            className="rounded-md bg-slate-950 px-6 text-white hover:bg-slate-800"
          >
            <Save className="mr-2 h-4 w-4" />
            {saving ? "保存中..." : "保存配置"}
          </Button>
        }
      />

      <Surface title="策略执行顺序" description="数据面按优先级短路执行，规则级动作可覆盖全局默认动作。">
        <div className="grid gap-3 md:grid-cols-4">
          {[
            ["01", "白名单", "最高优先级，命中后跳过后续检测", "border-emerald-200 bg-emerald-50 text-emerald-700"],
            ["02", "黑名单", "在基础检测前拦截、限速或阻断", "border-rose-200 bg-rose-50 text-rose-700"],
            ["03", "基础检测", "OWASP/CVE、Bot、限速、签名和自定义规则", "border-cyan-200 bg-cyan-50 text-cyan-700"],
            ["04", "后续动作", "验证码、5s盾、链式验证或阶梯升级", "border-violet-200 bg-violet-50 text-violet-700"],
          ].map(([idx, title, desc, tone]) => (
            <div key={idx} className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
              <Badge className={cn("rounded-md border text-[11px]", tone)}>{idx}</Badge>
              <div className="mt-3 text-sm font-semibold text-slate-900">{title}</div>
              <p className="mt-1 text-xs leading-5 text-slate-500">{desc}</p>
            </div>
          ))}
        </div>
      </Surface>

      {/* Mode Selection Cards */}
      <div>
        <h2 className="mb-3 text-sm font-medium text-slate-700">防护模式</h2>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {protectionModes.map((mode) => {
            const Icon = mode.icon;
            const isActive = activeMode === mode.id;
            return (
              <button
                key={mode.id}
                onClick={() => applyMode(mode.id)}
                className={cn(
                  "flex flex-col items-start gap-2 rounded-lg border-2 bg-white p-4 text-left shadow-sm transition-all hover:shadow-md",
                  isActive
                    ? "border-cyan-500 bg-cyan-50/30 ring-1 ring-cyan-500/20"
                    : "border-slate-200 hover:border-slate-300"
                )}
              >
                <div
                  className={cn(
                    "flex h-9 w-9 items-center justify-center rounded-lg",
                    isActive ? "bg-slate-100 text-slate-700" : "bg-slate-100 text-slate-500"
                  )}
                >
                  <Icon className="h-5 w-5" />
                </div>
                <div>
                  <div className={cn("text-sm font-semibold", isActive ? "text-cyan-700" : "text-slate-900")}>
                    {mode.label}
                  </div>
                  <div className="mt-0.5 text-xs text-slate-500">{mode.desc}</div>
                </div>
                {isActive && (
                  <div className="mt-auto self-end">
                    <span className="inline-flex items-center rounded-full bg-cyan-100 px-2 py-0.5 text-[10px] font-medium text-cyan-700">
                      当前
                    </span>
                  </div>
                )}
              </button>
            );
          })}
        </div>
      </div>

      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 px-5 py-4">
          <h2 className="text-base font-semibold text-slate-900">全局动作策略</h2>
          <p className="mt-1 text-xs text-slate-500">
            统一控制 OWASP、CVE、请求限速、错误限速和自动封禁的命中动作；规则级动作会覆盖这里的默认值。
          </p>
        </div>
        <div className="grid gap-4 p-5 lg:grid-cols-2 xl:grid-cols-5">
          {[
            ["builtin_owasp_on_hit", "OWASP 命中"],
            ["cve_action", "CVE 命中"],
            ["request_ratelimit_action", "请求限速"],
            ["error_ratelimit_action", "错误限速"],
            ["auto_ban_action", "自动封禁"],
          ].map(([field, label]) => {
            const value = String((settings as unknown as Record<string, unknown>)[field] ?? (field.includes("ratelimit") ? "rate_limit" : "intercept"));
            const meta = getWAFActionMeta(value);
            return (
              <div key={field} className="rounded-lg border border-slate-200 bg-slate-50/60 p-3">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-600">{label}</span>
                  <span className={cn("rounded-md border px-2 py-0.5 text-[10px] font-medium", meta.className)}>{meta.defaultStatus}</span>
                </div>
                <Select
                  value={value}
                  onValueChange={(v) => setSettings({ ...settings, [field]: v } as ProtectionSettings)}
                >
                  <SelectTrigger className="h-8 rounded-md bg-white text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {terminalWAFActionOptions.map((item) => (
                      <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="mt-2 min-h-8 text-[11px] leading-4 text-slate-500">{meta.description}</p>
              </div>
            );
          })}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
        <Surface title="高危资源耗尽与 CVE 自动阻断" description="Critical/High CVE 可自动升级为 Drop；规则级动作优先于自动阻断。">
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              ["cve_auto_drop_critical", "Critical 自动阻断", "命中 Critical CVE 且规则未单独配置动作时返回 RST"],
              ["cve_auto_drop_high", "High 自动阻断", "命中 High CVE 且规则未单独配置动作时返回 RST"],
            ].map(([field, label, desc]) => {
              const checked = Boolean((settings as unknown as Record<string, unknown>)[field]);
              return (
                <div key={field} className="rounded-lg border border-slate-200 bg-slate-50/60 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold text-slate-900">{label}</div>
                      <p className="mt-1 text-xs leading-5 text-slate-500">{desc}</p>
                    </div>
                    <Switch checked={checked} onCheckedChange={(v) => setSettings({ ...settings, [field]: v } as ProtectionSettings)} />
                  </div>
                </div>
              );
            })}
          </div>
        </Surface>

        <Surface title="人机验证与后续动作" description="配置验证码、5s盾、混合验证和命中后的阶梯升级。">
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              ["captcha_enabled", "验证码", "captcha_challenge"],
              ["shield_enabled", "5s 盾", "shield_challenge"],
              ["chain_enabled", "混合验证", "chain_challenge"],
              ["escalation_enabled", "后续动作升级", "challenge → rate_limit → drop"],
            ].map(([field, label, hint]) => {
              const checked = Boolean((settings as unknown as Record<string, unknown>)[field]);
              return (
                <div key={field} className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50/60 px-4 py-3">
                  <div>
                    <div className="text-sm font-semibold text-slate-900">{label}</div>
                    <div className="text-[11px] font-mono text-slate-500">{hint}</div>
                  </div>
                  <Switch checked={checked} onCheckedChange={(v) => setSettings({ ...settings, [field]: v } as ProtectionSettings)} />
                </div>
              );
            })}
          </div>
        </Surface>
      </div>

      {/* Sensitivity Matrix Table */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 px-5 py-4">
          <h2 className="text-base font-semibold text-slate-900">检测类别敏感度矩阵</h2>
          <p className="mt-1 text-xs text-slate-500">
            为每个检测类别设置敏感度级别，级别越高检测越严格但可能增加误报
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50/80">
                <th className="px-5 py-3 text-left text-xs font-semibold text-slate-600 uppercase tracking-wider">
                  类别名称
                </th>
                {sensitivityLevels.map((level) => (
                  <th
                    key={level.value}
                    className="px-3 py-3 text-center text-xs font-semibold text-slate-600 uppercase tracking-wider"
                  >
                    {level.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {categories.map((cat, idx) => {
                const currentValue = modules[cat.key] || "off";
                return (
                  <tr
                    key={cat.key}
                    className={cn(
                      "border-b border-slate-50 transition-colors hover:bg-slate-50/50",
                      idx % 2 === 0 ? "bg-white" : "bg-slate-50/30"
                    )}
                  >
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="h-3.5 w-3.5 text-slate-400" />
                        <span className="font-medium text-slate-800">{cat.label}</span>
                      </div>
                    </td>
                    {sensitivityLevels.map((level) => {
                      const isSelected = currentValue === level.value;
                      return (
                        <td key={level.value} className="px-3 py-3 text-center">
                          <button
                            onClick={() => setModuleSensitivity(cat.key, level.value)}
                            className={cn(
                              "inline-flex h-5 w-5 items-center justify-center rounded-full border-2 transition-all",
                              isSelected
                                ? "border-slate-900 bg-slate-900 shadow-sm"
                                : "border-slate-300 bg-white hover:border-cyan-300"
                            )}
                          >
                            {isSelected && (
                              <span className="block h-2 w-2 rounded-full bg-white" />
                            )}
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom Save */}
      <div className="flex justify-end pb-4">
        <Button
          onClick={save}
          disabled={saving}
          className="rounded-md bg-slate-950 px-8 py-2 text-white hover:bg-slate-800"
        >
          <Save className="mr-2 h-4 w-4" />
          {saving ? "保存中..." : "保存配置"}
        </Button>
      </div>
    </div>
  );
}
