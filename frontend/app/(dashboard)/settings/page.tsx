"use client";

import { useEffect, useState } from "react";
import { Lock, Shield, Settings2 } from "lucide-react";
import { PageIntro, InlineMeta, Surface } from "@/components/console-shell";
import { getAPIKeys, getProtectionSettings, getSystemSettings, type APIKey, type ProtectionSettings, type SystemSetting } from "@/lib/api";
import { formatDate } from "@/lib/utils";

export default function SettingsPage() {
  const [settings, setSettings] = useState<SystemSetting[]>([]);
  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [protection, setProtection] = useState<ProtectionSettings | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const [systemSettings, keys, protectionSettings] = await Promise.all([
        getSystemSettings(),
        getAPIKeys(),
        getProtectionSettings(),
      ]);
      setSettings(systemSettings);
      setApiKeys(keys.items || []);
      setProtection(protectionSettings);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Platform Settings"
        title="系统设置"
        description="查看系统级 key/value 设置、登录安全策略和自动化访问令牌。该页面聚焦后端真实存在的系统资源。"
      />

      <div className="grid gap-6 xl:grid-cols-2">
        <Surface title="登录安全策略" description="读取自 protection-settings 中的登录限制字段。">
          <div className="grid gap-3 md:grid-cols-3">
            <InlineMeta label="最小密码长度" value={protection ? String(protection.login_min_password_length) : "--"} />
            <InlineMeta label="失败次数上限" value={protection ? String(protection.login_max_attempts) : "--"} />
            <InlineMeta label="锁定时长（分钟）" value={protection ? String(protection.login_lockout_minutes) : "--"} />
          </div>
        </Surface>

        <Surface title="系统配置数量" description="来自 /api/v1/settings 的存储项。">
          <div className="grid gap-3 md:grid-cols-3">
            <InlineMeta label="设置总数" value={String(settings.length)} />
            <InlineMeta label="API 密钥数" value={String(apiKeys.length)} />
            <InlineMeta label="证书策略状态" value={protection?.maintenance_global_enabled ? "维护开启" : "维护关闭"} />
          </div>
        </Surface>
      </div>

      <Surface title="系统设置项" description="仅展示后端真实存储的 key/value 记录。">
        {loading ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">加载中...</div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {settings.map((item) => (
              <div key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <div className="mb-2 flex items-center gap-2 text-sm font-medium text-slate-900">
                  <Settings2 className="h-4 w-4 text-cyan-700" />
                  {item.key}
                </div>
                <div className="font-mono text-xs text-slate-600 break-all">{item.value}</div>
              </div>
            ))}
          </div>
        )}
      </Surface>

      <Surface title="API 密钥速览" description="当前已有 Bearer Token 的摘要信息。">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {apiKeys.map((item) => (
            <div key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-medium text-slate-900">
                <Lock className="h-4 w-4 text-cyan-700" />
                {item.name}
              </div>
              <div className="text-xs text-slate-500">创建于 {formatDate(item.created_at)}</div>
              <div className="text-xs text-slate-500">最近使用 {item.last_used_at ? formatDate(item.last_used_at) : "从未使用"}</div>
            </div>
          ))}
        </div>
      </Surface>

      <Surface title="运维提示" description="当前页面不做伪造写操作入口，避免误导。">
        <div className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-4 text-sm leading-6 text-amber-900">
          <Shield className="mt-0.5 h-4 w-4 shrink-0" />
          <p>
            旧版前端把证书、拦截页面、日志保留等杂项混在同一页中，但其中不少并没有独立后端接口。新版页面只展示系统真实存在的资源，证书和 API 密钥已分别拆分到专属页面。
          </p>
        </div>
      </Surface>
    </div>
  );
}
