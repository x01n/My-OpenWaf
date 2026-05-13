"use client";

import { useEffect, useState } from "react";
import { Globe, Lock, Network, Save, Server, Shield, Zap } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { InlineMeta, PageIntro, Surface } from "@/components/console-shell";
import {
  getDashboardSummary,
  getProtectionSettings,
  getSystemSettings,
  updateProtectionSettings,
  updateSystemSetting,
  createSystemSetting,
  type DashboardSummary,
  type ProtectionSettings,
  type SystemSetting,
} from "@/lib/api";

// Helper: get value from system settings
function getSettingValue(settings: SystemSetting[], key: string, fallback = ""): string {
  const found = settings.find((s) => s.key === key);
  return found?.value ?? fallback;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days} 天 ${hours} 小时 ${mins} 分`;
  if (hours > 0) return `${hours} 小时 ${mins} 分`;
  return `${mins} 分钟`;
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<SystemSetting[]>([]);
  const [protection, setProtection] = useState<ProtectionSettings | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Network config state
  const [xffMode, setXffMode] = useState("X-Forwarded-For");
  const [trustedCidr, setTrustedCidr] = useState("");

  // Protocol state
  const [ipv6Enabled, setIpv6Enabled] = useState(false);
  const [http2Enabled, setHttp2Enabled] = useState(false);
  const [hstsEnabled, setHstsEnabled] = useState(false);
  const [brotliEnabled, setBrotliEnabled] = useState(false);

  // Security state (from protection settings)
  const [maxAttempts, setMaxAttempts] = useState(5);
  const [lockoutMinutes, setLockoutMinutes] = useState(15);
  const [minPasswordLen, setMinPasswordLen] = useState(8);

  async function load() {
    setLoading(true);
    try {
      const [systemSettings, protectionSettings, dash] = await Promise.all([
        getSystemSettings(),
        getProtectionSettings(),
        getDashboardSummary().catch(() => null),
      ]);
      setSettings(systemSettings);
      setProtection(protectionSettings);
      setSummary(dash);

      // Populate network settings
      setXffMode(getSettingValue(systemSettings, "xff_mode", "X-Forwarded-For"));
      setTrustedCidr(getSettingValue(systemSettings, "trusted_cidr", ""));

      // Populate protocol settings
      setIpv6Enabled(getSettingValue(systemSettings, "ipv6_enabled") === "true");
      setHttp2Enabled(getSettingValue(systemSettings, "http2_enabled") === "true");
      setHstsEnabled(getSettingValue(systemSettings, "hsts_enabled") === "true");
      setBrotliEnabled(getSettingValue(systemSettings, "brotli_enabled") === "true");

      // Populate security settings
      setMaxAttempts(protectionSettings.login_max_attempts ?? 5);
      setLockoutMinutes(protectionSettings.login_lockout_minutes ?? 15);
      setMinPasswordLen(protectionSettings.login_min_password_length ?? 8);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleSave() {
    setSaving(true);
    try {
      // Save system settings (key/value pairs)
      const settingPairs: [string, string][] = [
        ["xff_mode", xffMode],
        ["trusted_cidr", trustedCidr],
        ["ipv6_enabled", String(ipv6Enabled)],
        ["http2_enabled", String(http2Enabled)],
        ["hsts_enabled", String(hstsEnabled)],
        ["brotli_enabled", String(brotliEnabled)],
      ];

      for (const [key, value] of settingPairs) {
        const exists = settings.find((s) => s.key === key);
        if (exists) {
          await updateSystemSetting(key, value);
        } else {
          await createSystemSetting({ key, value });
        }
      }

      // Save protection settings (login security)
      if (protection) {
        await updateProtectionSettings({
          ...protection,
          login_max_attempts: maxAttempts,
          login_lockout_minutes: lockoutMinutes,
          login_min_password_length: minPasswordLen,
        });
      }

      toast.success("系统设置已保存");
      await load(); // Reload to sync state
    } catch (error) {
      toast.error(String(error));
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <PageIntro eyebrow="Platform Settings" title="系统设置" description="加载中..." />
        <Surface className="min-h-[400px] animate-pulse"><div className="h-full" /></Surface>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Platform Settings"
        title="系统设置"
        description="配置网络、协议、安全策略等系统级参数，所有修改保存后立即生效。"
        actions={
          <Button onClick={handleSave} disabled={saving} className="gap-2">
            <Save className="h-4 w-4" />
            {saving ? "保存中..." : "保存设置"}
          </Button>
        }
      />

      <div className="grid gap-6 xl:grid-cols-2">
        {/* 网络配置 */}
        <Surface title="网络配置" description="客户端 IP 获取方式和信任代理设置。">
          <div className="grid gap-5">
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                <Globe className="h-4 w-4 text-slate-600" />
                客户端 IP 获取方式
              </label>
              <Select value={xffMode} onValueChange={setXffMode}>
                <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="X-Forwarded-For">X-Forwarded-For</SelectItem>
                  <SelectItem value="X-Real-IP">X-Real-IP</SelectItem>
                  <SelectItem value="RemoteAddr">RemoteAddr (直连)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-slate-400">反向代理架构下应选择 X-Forwarded-For 或 X-Real-IP</p>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                <Network className="h-4 w-4 text-slate-600" />
                信任代理 CIDR 列表
              </label>
              <Input
                value={trustedCidr}
                onChange={(e) => setTrustedCidr(e.target.value)}
                className="rounded-md"
                placeholder="例如：10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
              />
              <p className="text-xs text-slate-400">多个 CIDR 用逗号分隔，仅从受信代理的请求中提取客户端 IP</p>
            </div>
          </div>
        </Surface>

        {/* 协议支持 */}
        <Surface title="协议支持" description="控制服务端支持的网络协议和压缩特性。">
          <div className="grid gap-4">
            <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
              <div>
                <div className="text-sm font-medium text-slate-900 flex items-center gap-2">
                  <Zap className="h-4 w-4 text-slate-600" /> IPv6 支持
                </div>
                <div className="text-xs text-slate-500">允许通过 IPv6 地址访问</div>
              </div>
              <Switch checked={ipv6Enabled} onCheckedChange={setIpv6Enabled} />
            </div>

            <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
              <div>
                <div className="text-sm font-medium text-slate-900 flex items-center gap-2">
                  <Zap className="h-4 w-4 text-slate-600" /> HTTP/2
                </div>
                <div className="text-xs text-slate-500">启用 HTTP/2 协议以提升传输效率</div>
              </div>
              <Switch checked={http2Enabled} onCheckedChange={setHttp2Enabled} />
            </div>

            <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
              <div>
                <div className="text-sm font-medium text-slate-900 flex items-center gap-2">
                  <Lock className="h-4 w-4 text-slate-600" /> HTTPS HSTS
                </div>
                <div className="text-xs text-slate-500">启用严格传输安全（Strict-Transport-Security）</div>
              </div>
              <Switch checked={hstsEnabled} onCheckedChange={setHstsEnabled} />
            </div>

            <div className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
              <div>
                <div className="text-sm font-medium text-slate-900 flex items-center gap-2">
                  <Zap className="h-4 w-4 text-slate-600" /> Brotli 压缩
                </div>
                <div className="text-xs text-slate-500">启用 Brotli 压缩以减小传输体积</div>
              </div>
              <Switch checked={brotliEnabled} onCheckedChange={setBrotliEnabled} />
            </div>
          </div>
        </Surface>

        {/* 安全设置 */}
        <Surface title="安全设置" description="登录安全策略和会话超时配置。">
          <div className="grid gap-5">
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                <Shield className="h-4 w-4 text-slate-600" />
                最小密码长度
              </label>
              <Input
                type="number"
                value={minPasswordLen}
                onChange={(e) => setMinPasswordLen(Number(e.target.value))}
                className="rounded-md"
                min={6}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                <Shield className="h-4 w-4 text-slate-600" />
                最大登录失败次数
              </label>
              <Input
                type="number"
                value={maxAttempts}
                onChange={(e) => setMaxAttempts(Number(e.target.value))}
                className="rounded-md"
                min={1}
              />
              <p className="text-xs text-slate-400">超过此次数后账户将被临时锁定</p>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                <Lock className="h-4 w-4 text-slate-600" />
                锁定时长（分钟）
              </label>
              <Input
                type="number"
                value={lockoutMinutes}
                onChange={(e) => setLockoutMinutes(Number(e.target.value))}
                className="rounded-md"
                min={1}
              />
              <p className="text-xs text-slate-400">账户被锁定后的自动解锁等待时间</p>
            </div>
          </div>
        </Surface>

        {/* 系统信息 */}
        <Surface title="系统信息" description="当前运行实例的只读信息。">
          <div className="grid gap-3 md:grid-cols-2">
            <InlineMeta label="版本号" value={
              <span className="flex items-center gap-2">
                <Server className="h-3.5 w-3.5 text-slate-600" />
                {getSettingValue(settings, "version", "未知")}
              </span>
            } />
            <InlineMeta label="运行时间" value={summary ? formatUptime(summary.uptime_sec) : "未知"} />
            <InlineMeta label="系统设置数" value={String(settings.length)} />
            <InlineMeta label="数据面版本" value={
              <span className="font-mono text-xs">{String(summary?.revision ?? "N/A")}</span>
            } />
          </div>
        </Surface>
      </div>
    </div>
  );
}
