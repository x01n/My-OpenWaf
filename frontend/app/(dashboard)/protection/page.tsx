"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { api } from "@/lib/api";
import { toast } from "sonner";

interface ProtectionConfig {
  request_ratelimit_enabled: boolean;
  request_ratelimit_window: number;
  request_ratelimit_max: number;
  request_ratelimit_action: string;
  error_ratelimit_enabled: boolean;
  error_ratelimit_window: number;
  error_ratelimit_max: number;
  error_ratelimit_action: string;
  error_ratelimit_count_4xx: boolean;
  error_ratelimit_count_5xx: boolean;
  error_ratelimit_count_block: boolean;
  builtin_owasp_enabled: boolean;
  builtin_owasp_sensitivity: string;
  builtin_owasp_on_hit: string;
  maintenance_global_enabled: boolean;
  maintenance_global_html: string;
  maintenance_global_status: number;
  bot_detection_enabled: boolean;
  auto_ban_enabled: boolean;
  auto_ban_threshold: number;
  auto_ban_window: number;
  auto_ban_duration: number;
}

export default function ProtectionPage() {
  const [cfg, setCfg] = useState<ProtectionConfig | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api<ProtectionConfig>("/api/v1/protection-settings").then(setCfg).catch(() => {});
  }, []);

  function update<K extends keyof ProtectionConfig>(key: K, value: ProtectionConfig[K]) {
    setCfg((prev) => prev ? { ...prev, [key]: value } : prev);
  }

  async function handleSave() {
    if (!cfg) return;
    setSaving(true);
    try {
      await api("/api/v1/protection-settings", { method: "POST", body: JSON.stringify(cfg) });
      toast.success("已保存，配置重载后生效");
    } catch {
      toast.error("保存失败");
    } finally {
      setSaving(false);
    }
  }

  if (!cfg) return <p className="text-sm text-muted-foreground">加载中…</p>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">防护设置</h1>
        <p className="text-sm text-muted-foreground">
          配置请求/错误限流、内置 OWASP 命中动作（拦截/观察）、以及维护模式。限流与错误拦截默认关闭；维护模式请谨慎开启。
        </p>
      </div>

      {/* A: Request Rate Limit */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">启用请求限流</CardTitle>
              <CardDescription>开启后，按客户端 IP 与 Host 在设定时间窗口内限制最大请求次数。</CardDescription>
            </div>
            <Switch checked={cfg.request_ratelimit_enabled} onCheckedChange={(v) => update("request_ratelimit_enabled", v)} />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <Label>统计窗口（秒）</Label>
              <Input type="number" min={1} value={cfg.request_ratelimit_window} onChange={(e) => update("request_ratelimit_window", +e.target.value)} disabled={!cfg.request_ratelimit_enabled} />
            </div>
            <div className="space-y-1">
              <Label>窗口内最大请求数</Label>
              <Input type="number" min={1} value={cfg.request_ratelimit_max} onChange={(e) => update("request_ratelimit_max", +e.target.value)} disabled={!cfg.request_ratelimit_enabled} />
            </div>
          </div>
          <div className="space-y-1">
            <Label>超限动作</Label>
            <Select value={cfg.request_ratelimit_action} onValueChange={(v) => update("request_ratelimit_action", v)} disabled={!cfg.request_ratelimit_enabled}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="intercept">拦截（返回 429，不转发上游）</SelectItem>
                <SelectItem value="observe">观察（仅记日志，仍转发上游）</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <p className="text-xs text-muted-foreground">当前版本为全局配置，对所有数据面站点生效。</p>
        </CardContent>
      </Card>

      {/* B: Error Rate Limit */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">启用错误响应限流</CardTitle>
              <CardDescription>开启后，同一客户端在窗口内产生过多错误类响应时，短期内不再转发上游。</CardDescription>
            </div>
            <Switch checked={cfg.error_ratelimit_enabled} onCheckedChange={(v) => update("error_ratelimit_enabled", v)} />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <Label>统计窗口（秒）</Label>
              <Input type="number" min={1} value={cfg.error_ratelimit_window} onChange={(e) => update("error_ratelimit_window", +e.target.value)} disabled={!cfg.error_ratelimit_enabled} />
            </div>
            <div className="space-y-1">
              <Label>窗口内最大错误次数</Label>
              <Input type="number" min={1} value={cfg.error_ratelimit_max} onChange={(e) => update("error_ratelimit_max", +e.target.value)} disabled={!cfg.error_ratelimit_enabled} />
            </div>
          </div>
          <div className="space-y-2">
            <Label>计入错误的响应类型</Label>
            <div className="flex flex-wrap gap-4 text-sm">
              <label className="flex items-center gap-1.5">
                <Switch checked={cfg.error_ratelimit_count_4xx} onCheckedChange={(v) => update("error_ratelimit_count_4xx", v)} disabled={!cfg.error_ratelimit_enabled} />
                上游 4xx
              </label>
              <label className="flex items-center gap-1.5">
                <Switch checked={cfg.error_ratelimit_count_5xx} onCheckedChange={(v) => update("error_ratelimit_count_5xx", v)} disabled={!cfg.error_ratelimit_enabled} />
                上游 5xx
              </label>
              <label className="flex items-center gap-1.5">
                <Switch checked={cfg.error_ratelimit_count_block} onCheckedChange={(v) => update("error_ratelimit_count_block", v)} disabled={!cfg.error_ratelimit_enabled} />
                WAF 拦截响应
              </label>
            </div>
          </div>
          <div className="space-y-1">
            <Label>超限动作</Label>
            <Select value={cfg.error_ratelimit_action} onValueChange={(v) => update("error_ratelimit_action", v)} disabled={!cfg.error_ratelimit_enabled}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="intercept">拦截</SelectItem>
                <SelectItem value="observe">观察</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* C: OWASP */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">启用内置 OWASP 默认防护</CardTitle>
              <CardDescription>对 SQL 注入、Webshell、反弹 shell 等做多信号模糊检测（含 URL/编码归一化）。非完整 CRS。</CardDescription>
            </div>
            <Switch checked={cfg.builtin_owasp_enabled} onCheckedChange={(v) => update("builtin_owasp_enabled", v)} />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <Label>敏感度</Label>
              <Select value={cfg.builtin_owasp_sensitivity} onValueChange={(v) => update("builtin_owasp_sensitivity", v)} disabled={!cfg.builtin_owasp_enabled}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">低（仅高置信）</SelectItem>
                  <SelectItem value="mid">中（平衡）</SelectItem>
                  <SelectItem value="high">高（更易命中，误报可能增加）</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>命中动作</Label>
              <Select value={cfg.builtin_owasp_on_hit} onValueChange={(v) => update("builtin_owasp_on_hit", v)} disabled={!cfg.builtin_owasp_enabled}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="intercept">拦截（阻断，不转发上游）</SelectItem>
                  <SelectItem value="observe">观察（仅写安全日志，正常响应）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">内置类别含 SQL 注入、Webshell、反弹 shell、XSS、路径穿越等；日志中带分类 ID。</p>
        </CardContent>
      </Card>

      {/* D: Bot Detection */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">Bot 检测</CardTitle>
              <CardDescription>启用后，结合 User-Agent 签名和请求指纹评分识别恶意 Bot，高分直接拦截。</CardDescription>
            </div>
            <Switch checked={cfg.bot_detection_enabled} onCheckedChange={(v) => update("bot_detection_enabled", v)} />
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">
            检测覆盖已知安全工具（sqlmap/nikto/burp 等）+ 请求指纹分析（缺少 Accept/Language/Encoding 等浏览器标准头）。
            恶意评分 ≥80 拦截，50-79 观察记录。
          </p>
        </CardContent>
      </Card>

      {/* E: Auto-ban */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">IP 自动封禁</CardTitle>
              <CardDescription>当同一 IP 在时间窗口内触发安全规则达到阈值时，自动临时封禁。</CardDescription>
            </div>
            <Switch checked={cfg.auto_ban_enabled} onCheckedChange={(v) => update("auto_ban_enabled", v)} />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-1">
              <Label>触发阈值（次）</Label>
              <Input type="number" min={1} value={cfg.auto_ban_threshold} onChange={(e) => update("auto_ban_threshold", +e.target.value)} disabled={!cfg.auto_ban_enabled} />
            </div>
            <div className="space-y-1">
              <Label>统计窗口（秒）</Label>
              <Input type="number" min={1} value={cfg.auto_ban_window} onChange={(e) => update("auto_ban_window", +e.target.value)} disabled={!cfg.auto_ban_enabled} />
            </div>
            <div className="space-y-1">
              <Label>封禁时长（秒）</Label>
              <Input type="number" min={1} value={cfg.auto_ban_duration} onChange={(e) => update("auto_ban_duration", +e.target.value)} disabled={!cfg.auto_ban_enabled} />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">默认：60 秒内触发 10 次规则命中 → 自动封禁 1 小时。</p>
        </CardContent>
      </Card>

      {/* F: Maintenance */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">维护模式</CardTitle>
              <CardDescription>开启后，全部请求均返回下方维护页，不转发上游。WebSocket 不升级；SSE 返回维护内容。</CardDescription>
            </div>
            <Switch checked={cfg.maintenance_global_enabled} onCheckedChange={(v) => update("maintenance_global_enabled", v)} />
          </div>
        </CardHeader>
        {cfg.maintenance_global_enabled && (
          <CardContent className="space-y-4">
            <Alert>
              <AlertDescription>维护模式影响全部流量，请确认后再保存。</AlertDescription>
            </Alert>
            <div className="space-y-1">
              <Label>维护页内容（HTML）</Label>
              <Textarea rows={6} value={cfg.maintenance_global_html} onChange={(e) => update("maintenance_global_html", e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>HTTP 状态码</Label>
              <Select value={String(cfg.maintenance_global_status)} onValueChange={(v) => update("maintenance_global_status", +v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="503">503 Service Unavailable</SelectItem>
                  <SelectItem value="200">200 OK（仅展示页）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        )}
      </Card>

      <Separator />

      <div className="flex justify-end gap-2">
        <Button onClick={handleSave} disabled={saving}>
          {saving ? "保存中…" : "保存设置"}
        </Button>
      </div>
    </div>
  );
}
