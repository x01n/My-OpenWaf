"use client";

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Clock,
  Copy,
  Database,
  Download,
  Globe,
  KeyRound,
  Lock,
  Network,
  Plus,
  RefreshCcw,
  Save,
  Search,
  Server,
  Shield,
  ShieldCheck,
  Trash2,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { InlineMeta, PageIntro, Surface } from "@/components/console-shell";
import { Pagination } from "@/components/pagination";
import {
  createAPIKey,
  createSystemSetting,
  getAPIKeys,
  getAccessLogs,
  getDashboardSummary,
  getProtectionSettings,
  getSecurityEvents,
  getSystemSettings,
  removeAPIKey,
  updateProtectionSettings,
  updateSystemSetting,
  type APIKey,
  type AccessLog,
  type DashboardSummary,
  type ProtectionSettings,
  type SecurityEvent,
  type SystemSetting,
} from "@/lib/api";
import { formatDate } from "@/lib/utils";

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function getSettingValue(
  settings: SystemSetting[],
  key: string,
  fallback = "",
): string {
  return settings.find((s) => s.key === key)?.value ?? fallback;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days} 天 ${hours} 小时 ${mins} 分`;
  if (hours > 0) return `${hours} 小时 ${mins} 分`;
  return `${mins} 分钟`;
}

function maskToken(token?: string): string {
  if (!token) return "••••••••••••••••";
  if (token.length <= 8)
    return "••••" + token.slice(-4);
  return token.slice(0, 4) + "••••••••" + token.slice(-4);
}

const RETENTION_OPTIONS = [
  { value: "0", label: "不清理" },
  { value: "1", label: "1 天" },
  { value: "3", label: "3 天" },
  { value: "7", label: "7 天" },
  { value: "15", label: "15 天" },
  { value: "30", label: "30 天" },
] as const;

const CUSTOM_HTML_CODES = [
  { code: "403", label: "403 Forbidden", color: "border-rose-200 bg-rose-50 text-rose-700" },
  { code: "429", label: "429 Too Many Requests", color: "border-amber-200 bg-amber-50 text-amber-700" },
  { code: "404", label: "404 Not Found", color: "border-orange-200 bg-orange-50 text-orange-700" },
  { code: "502", label: "502 Bad Gateway", color: "border-purple-200 bg-purple-50 text-purple-700" },
  { code: "504", label: "504 Gateway Timeout", color: "border-slate-200 bg-slate-100 text-slate-700" },
] as const;

const LOG_PAGE_SIZE = 15;

/* ------------------------------------------------------------------ */
/*  Main Component                                                     */
/* ------------------------------------------------------------------ */

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("protection");

  /* Shared data */
  const [settings, setSettings] = useState<SystemSetting[]>([]);
  const [protection, setProtection] = useState<ProtectionSettings | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  /* ---- Protection Config tab state ---- */
  const [savingProtection, setSavingProtection] = useState(false);

  // Data cleanup retention
  const [secEventRetention, setSecEventRetention] = useState("30");
  const [accessLogRetention, setAccessLogRetention] = useState("30");
  const [statsRetention, setStatsRetention] = useState("0");

  // Block page customization
  const [blockPageType, setBlockPageType] = useState("default");
  const [blockPageText, setBlockPageText] = useState("");
  const [activeCustomCode, setActiveCustomCode] = useState("403");
  const [customHtmlMap, setCustomHtmlMap] = useState<Record<string, string>>({});

  // Detection engine mode
  const [engineMode, setEngineMode] = useState("multi");

  // Network config
  const [xffMode, setXffMode] = useState("X-Forwarded-For");
  const [trustedCidr, setTrustedCidr] = useState("");

  // Protocol state
  const [ipv6Enabled, setIpv6Enabled] = useState(false);
  const [http2Enabled, setHttp2Enabled] = useState(false);
  const [hstsEnabled, setHstsEnabled] = useState(false);
  const [brotliEnabled, setBrotliEnabled] = useState(false);

  /* ---- Console Management tab state ---- */
  const [savingConsole, setSavingConsole] = useState(false);

  // Login security (from protection settings)
  const [maxAttempts, setMaxAttempts] = useState(5);
  const [lockoutMinutes, setLockoutMinutes] = useState(15);
  const [minPasswordLen, setMinPasswordLen] = useState(8);
  const [sessionTimeout, setSessionTimeout] = useState(60);
  const [accessIpWhitelist, setAccessIpWhitelist] = useState("");

  // API keys
  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(false);
  const [apiKeyDialogOpen, setApiKeyDialogOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<APIKey | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Admin console certificate
  const [adminCertMode, setAdminCertMode] = useState("self_signed");

  /* ---- System Logs tab state ---- */
  const [logType, setLogType] = useState<"security" | "access">("security");
  const [secEvents, setSecEvents] = useState<SecurityEvent[]>([]);
  const [accessLogs, setAccessLogs] = useState<AccessLog[]>([]);
  const [logPage, setLogPage] = useState(1);
  const [logTotal, setLogTotal] = useState(0);
  const [logLoading, setLogLoading] = useState(false);
  const [logSearch, setLogSearch] = useState("");

  /* ---------------------------------------------------------------- */
  /*  Data loading                                                     */
  /* ---------------------------------------------------------------- */

  async function loadSettings() {
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

      // Populate protection config
      setSecEventRetention(
        getSettingValue(systemSettings, "security_event_retention_days", "30"),
      );
      setAccessLogRetention(
        getSettingValue(systemSettings, "access_log_retention_days", "30"),
      );
      setStatsRetention(
        getSettingValue(systemSettings, "stats_retention_days", "0"),
      );
      setBlockPageType(
        getSettingValue(systemSettings, "block_page_type", "default"),
      );
      setBlockPageText(
        getSettingValue(systemSettings, "block_page_text", ""),
      );
      setEngineMode(
        getSettingValue(systemSettings, "engine_mode", "multi"),
      );

      // Load custom HTML per code
      const htmlMap: Record<string, string> = {};
      for (const item of CUSTOM_HTML_CODES) {
        htmlMap[item.code] = getSettingValue(
          systemSettings,
          `custom_html_${item.code}`,
          "",
        );
      }
      setCustomHtmlMap(htmlMap);

      // Network config
      setXffMode(
        getSettingValue(systemSettings, "xff_mode", "X-Forwarded-For"),
      );
      setTrustedCidr(getSettingValue(systemSettings, "trusted_cidr", ""));

      // Protocol
      setIpv6Enabled(
        getSettingValue(systemSettings, "ipv6_enabled") === "true",
      );
      setHttp2Enabled(
        getSettingValue(systemSettings, "http2_enabled") === "true",
      );
      setHstsEnabled(
        getSettingValue(systemSettings, "hsts_enabled") === "true",
      );
      setBrotliEnabled(
        getSettingValue(systemSettings, "brotli_enabled") === "true",
      );

      // Login security
      setMaxAttempts(protectionSettings.login_max_attempts ?? 5);
      setLockoutMinutes(protectionSettings.login_lockout_minutes ?? 15);
      setMinPasswordLen(protectionSettings.login_min_password_length ?? 8);
      setSessionTimeout(
        Number(
          getSettingValue(systemSettings, "session_timeout_minutes", "60"),
        ),
      );
      setAccessIpWhitelist(
        getSettingValue(systemSettings, "access_ip_whitelist", ""),
      );

      // Admin cert
      setAdminCertMode(
        getSettingValue(systemSettings, "admin_cert_mode", "self_signed"),
      );
    } finally {
      setLoading(false);
    }
  }

  function loadApiKeys() {
    setApiKeysLoading(true);
    getAPIKeys()
      .then((data) => setApiKeys(data.items || []))
      .catch((e) => toast.error(String(e)))
      .finally(() => setApiKeysLoading(false));
  }

  const loadLogs = useCallback(async () => {
    setLogLoading(true);
    try {
      if (logType === "security") {
        const res = await getSecurityEvents({
          page: logPage,
          page_size: LOG_PAGE_SIZE,
          client_ip: logSearch || undefined,
        });
        setSecEvents(res.items ?? []);
        setLogTotal(res.total ?? 0);
      } else {
        const res = await getAccessLogs({
          page: logPage,
          page_size: LOG_PAGE_SIZE,
          client_ip: logSearch || undefined,
        });
        setAccessLogs(res.items ?? []);
        setLogTotal(res.total ?? 0);
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载日志失败");
    } finally {
      setLogLoading(false);
    }
  }, [logType, logPage, logSearch]);

  useEffect(() => {
    loadSettings();
  }, []);

  useEffect(() => {
    if (activeTab === "console") loadApiKeys();
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === "logs") loadLogs();
  }, [activeTab, loadLogs]);

  /* ---------------------------------------------------------------- */
  /*  Save handlers                                                    */
  /* ---------------------------------------------------------------- */

  async function saveSetting(key: string, value: string) {
    const exists = settings.find((s) => s.key === key);
    if (exists) {
      await updateSystemSetting(key, value);
    } else {
      await createSystemSetting({ key, value });
    }
  }

  async function handleSaveProtection() {
    setSavingProtection(true);
    try {
      // System settings
      const pairs: [string, string][] = [
        ["security_event_retention_days", secEventRetention],
        ["access_log_retention_days", accessLogRetention],
        ["stats_retention_days", statsRetention],
        ["block_page_type", blockPageType],
        ["block_page_text", blockPageText],
        ["engine_mode", engineMode],
        ["xff_mode", xffMode],
        ["trusted_cidr", trustedCidr],
        ["ipv6_enabled", String(ipv6Enabled)],
        ["http2_enabled", String(http2Enabled)],
        ["hsts_enabled", String(hstsEnabled)],
        ["brotli_enabled", String(brotliEnabled)],
      ];

      // Custom HTML per status code
      for (const item of CUSTOM_HTML_CODES) {
        pairs.push([
          `custom_html_${item.code}`,
          customHtmlMap[item.code] ?? "",
        ]);
      }

      for (const [key, value] of pairs) {
        await saveSetting(key, value);
      }

      toast.success("防护配置已保存");
      await loadSettings();
    } catch (error) {
      toast.error(String(error));
    } finally {
      setSavingProtection(false);
    }
  }

  async function handleSaveConsole() {
    setSavingConsole(true);
    try {
      // Save login security to protection settings
      if (protection) {
        await updateProtectionSettings({
          ...protection,
          login_max_attempts: maxAttempts,
          login_lockout_minutes: lockoutMinutes,
          login_min_password_length: minPasswordLen,
        });
      }

      // Save other console settings
      const pairs: [string, string][] = [
        ["session_timeout_minutes", String(sessionTimeout)],
        ["access_ip_whitelist", accessIpWhitelist],
        ["admin_cert_mode", adminCertMode],
      ];

      for (const [key, value] of pairs) {
        await saveSetting(key, value);
      }

      toast.success("控制台设置已保存");
      await loadSettings();
    } catch (error) {
      toast.error(String(error));
    } finally {
      setSavingConsole(false);
    }
  }

  /* ---------------------------------------------------------------- */
  /*  API Key handlers                                                 */
  /* ---------------------------------------------------------------- */

  async function handleCreateKey() {
    if (!newKeyName.trim()) {
      toast.error("请输入密钥名称");
      return;
    }
    setCreating(true);
    try {
      const response = await createAPIKey(newKeyName);
      setCreatedToken(response.token || null);
      setNewKeyName("");
      toast.success("密钥已创建，请立即复制明文 Token。");
      loadApiKeys();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setCreating(false);
    }
  }

  async function handleDeleteKey() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await removeAPIKey(deleteTarget.id);
      toast.success("API 密钥已删除");
      setDeleteTarget(null);
      loadApiKeys();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setDeleting(false);
    }
  }

  /* ---------------------------------------------------------------- */
  /*  Log export                                                       */
  /* ---------------------------------------------------------------- */

  function exportLogCSV() {
    if (logType === "security") {
      const headers = [
        "ID",
        "时间",
        "IP",
        "Host",
        "方法",
        "路径",
        "动作",
        "类别",
        "匹配说明",
      ];
      const rows = secEvents.map((e) => [
        e.id,
        formatDate(e.created_at),
        e.client_ip,
        e.host,
        e.method,
        e.path,
        e.action,
        e.category,
        e.match_desc,
      ]);
      const csv = [
        headers.join(","),
        ...rows.map((r) =>
          r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","),
        ),
      ].join("\n");
      downloadCSV(csv, "security-events");
    } else {
      const headers = [
        "ID",
        "时间",
        "IP",
        "方法",
        "路径",
        "状态码",
        "WAF",
        "上游",
      ];
      const rows = accessLogs.map((i) => [
        i.id,
        formatDate(i.created_at),
        i.client_ip,
        i.method,
        i.path,
        i.status_code,
        i.waf_action,
        i.upstream,
      ]);
      const csv = [
        headers.join(","),
        ...rows.map((r) =>
          r.map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`).join(","),
        ),
      ].join("\n");
      downloadCSV(csv, "access-logs");
    }
  }

  function downloadCSV(csv: string, name: string) {
    const blob = new Blob(["﻿" + csv], {
      type: "text/csv;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name}-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  /* ---------------------------------------------------------------- */
  /*  Loading state                                                    */
  /* ---------------------------------------------------------------- */

  if (loading) {
    return (
      <div className="space-y-6">
        <PageIntro
          eyebrow="Platform Settings"
          title="系统设置"
          description="加载中..."
        />
        <Surface className="min-h-[400px] animate-pulse">
          <div className="h-full" />
        </Surface>
      </div>
    );
  }

  const logTotalPages = Math.max(1, Math.ceil(logTotal / LOG_PAGE_SIZE));

  /* ---------------------------------------------------------------- */
  /*  Render                                                           */
  /* ---------------------------------------------------------------- */

  return (
    <div className="space-y-6">
      <PageIntro
        eyebrow="Platform Settings"
        title="通用设置"
        description="配置防护策略、控制台管理和日志查看，所有修改保存后立即生效。"
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList variant="line" className="mb-2 border-b border-slate-200 pb-px">
          <TabsTrigger value="protection" className="gap-1.5 px-4 py-2 text-sm">
            <Shield className="h-4 w-4" />
            防护配置
          </TabsTrigger>
          <TabsTrigger value="console" className="gap-1.5 px-4 py-2 text-sm">
            <Server className="h-4 w-4" />
            控制台管理
          </TabsTrigger>
          <TabsTrigger value="logs" className="gap-1.5 px-4 py-2 text-sm">
            <Database className="h-4 w-4" />
            系统日志
          </TabsTrigger>
        </TabsList>

        {/* ============================================================ */}
        {/*  TAB 1: 防护配置                                              */}
        {/* ============================================================ */}
        <TabsContent value="protection">
          <div className="space-y-6">
            {/* Data Cleanup */}
            <Surface
              title="数据清理"
              description="配置安全事件、访问日志和统计数据的自动清理周期，超过保留天数的数据将被自动删除。"
            >
              <div className="grid gap-6 lg:grid-cols-3">
                {/* Security events retention */}
                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-teal-600" />
                    安全事件保留
                  </label>
                  <RadioGroup
                    value={secEventRetention}
                    onValueChange={setSecEventRetention}
                    className="flex flex-wrap gap-2"
                  >
                    {RETENTION_OPTIONS.map((opt) => (
                      <label
                        key={opt.value}
                        className={`flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors ${
                          secEventRetention === opt.value
                            ? "border-teal-300 bg-teal-50 text-teal-700"
                            : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
                        }`}
                      >
                        <RadioGroupItem value={opt.value} className="sr-only" />
                        {opt.label}
                      </label>
                    ))}
                  </RadioGroup>
                </div>

                {/* Access log retention */}
                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                    <Clock className="h-4 w-4 text-teal-600" />
                    访问日志保留
                  </label>
                  <RadioGroup
                    value={accessLogRetention}
                    onValueChange={setAccessLogRetention}
                    className="flex flex-wrap gap-2"
                  >
                    {RETENTION_OPTIONS.map((opt) => (
                      <label
                        key={opt.value}
                        className={`flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors ${
                          accessLogRetention === opt.value
                            ? "border-teal-300 bg-teal-50 text-teal-700"
                            : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
                        }`}
                      >
                        <RadioGroupItem value={opt.value} className="sr-only" />
                        {opt.label}
                      </label>
                    ))}
                  </RadioGroup>
                </div>

                {/* Stats retention */}
                <div className="space-y-3">
                  <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                    <Database className="h-4 w-4 text-teal-600" />
                    统计报表保留
                  </label>
                  <RadioGroup
                    value={statsRetention}
                    onValueChange={setStatsRetention}
                    className="flex flex-wrap gap-2"
                  >
                    {RETENTION_OPTIONS.map((opt) => (
                      <label
                        key={opt.value}
                        className={`flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors ${
                          statsRetention === opt.value
                            ? "border-teal-300 bg-teal-50 text-teal-700"
                            : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
                        }`}
                      >
                        <RadioGroupItem value={opt.value} className="sr-only" />
                        {opt.label}
                      </label>
                    ))}
                  </RadioGroup>
                </div>
              </div>
            </Surface>

            {/* Block Page Customization */}
            <Surface
              title="拦截页面"
              description="配置 WAF 拦截时向客户端返回的页面内容和样式。"
            >
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-slate-700">
                    页面类型
                  </label>
                  <Select value={blockPageType} onValueChange={setBlockPageType}>
                    <SelectTrigger className="w-[260px] rounded-md">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="default">默认拦截页面</SelectItem>
                      <SelectItem value="text">纯文本</SelectItem>
                      <SelectItem value="custom">自定义 HTML</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {blockPageType === "text" && (
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700">
                      拦截文本内容
                    </label>
                    <Textarea
                      value={blockPageText}
                      onChange={(e) => setBlockPageText(e.target.value)}
                      rows={4}
                      className="rounded-md"
                      placeholder="例如：Access Denied - Your request has been blocked."
                    />
                  </div>
                )}

                {blockPageType === "custom" && (
                  <div className="space-y-3">
                    <label className="text-sm font-medium text-slate-700">
                      自定义 HTML（按状态码配置）
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {CUSTOM_HTML_CODES.map((item) => (
                        <button
                          key={item.code}
                          type="button"
                          onClick={() => setActiveCustomCode(item.code)}
                          className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                            activeCustomCode === item.code
                              ? item.color
                              : "border-slate-200 bg-white text-slate-500 hover:border-slate-300"
                          }`}
                        >
                          {item.label}
                        </button>
                      ))}
                    </div>
                    <Textarea
                      value={customHtmlMap[activeCustomCode] ?? ""}
                      onChange={(e) =>
                        setCustomHtmlMap((prev) => ({
                          ...prev,
                          [activeCustomCode]: e.target.value,
                        }))
                      }
                      rows={10}
                      className="rounded-md font-mono text-xs"
                      placeholder={`输入 ${activeCustomCode} 状态码的自定义 HTML...`}
                    />
                    <div className="flex items-start gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
                      <span>
                        支持 Go template 变量：{"{{.StatusCode}}"}{"  "}
                        {"{{.Message}}"}{"  "}{"{{.ClientIP}}"}{"  "}
                        {"{{.RequestID}}"}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </Surface>

            {/* Detection Engine Mode */}
            <Surface
              title="检测引擎性能配置"
              description="配置 WAF 检测引擎的运行模式，影响检测吞吐量和资源占用。"
            >
              <div className="space-y-3">
                <RadioGroup
                  value={engineMode}
                  onValueChange={setEngineMode}
                  className="grid gap-3 sm:grid-cols-2"
                >
                  <label
                    className={`flex cursor-pointer items-start gap-3 rounded-lg border p-4 transition-colors ${
                      engineMode === "single"
                        ? "border-teal-300 bg-teal-50"
                        : "border-slate-200 bg-white hover:border-slate-300"
                    }`}
                  >
                    <RadioGroupItem value="single" className="mt-0.5" />
                    <div>
                      <div className="text-sm font-medium text-slate-900">
                        单线程模式
                      </div>
                      <div className="mt-1 text-xs text-slate-500">
                        适合低配置环境，资源消耗低，检测按顺序执行。
                      </div>
                    </div>
                  </label>
                  <label
                    className={`flex cursor-pointer items-start gap-3 rounded-lg border p-4 transition-colors ${
                      engineMode === "multi"
                        ? "border-teal-300 bg-teal-50"
                        : "border-slate-200 bg-white hover:border-slate-300"
                    }`}
                  >
                    <RadioGroupItem value="multi" className="mt-0.5" />
                    <div>
                      <div className="text-sm font-medium text-slate-900">
                        多线程模式
                      </div>
                      <div className="mt-1 text-xs text-slate-500">
                        推荐。OWASP 与 CVE 检测并行执行，吞吐量更高。
                      </div>
                    </div>
                  </label>
                </RadioGroup>
              </div>
            </Surface>

            {/* Network & Protocol */}
            <div className="grid gap-6 xl:grid-cols-2">
              <Surface
                title="网络配置"
                description="客户端 IP 获取方式和信任代理设置。"
              >
                <div className="grid gap-5">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                      <Globe className="h-4 w-4 text-slate-600" />
                      客户端 IP 获取方式
                    </label>
                    <Select value={xffMode} onValueChange={setXffMode}>
                      <SelectTrigger className="rounded-md">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="X-Forwarded-For">
                          X-Forwarded-For
                        </SelectItem>
                        <SelectItem value="X-Real-IP">X-Real-IP</SelectItem>
                        <SelectItem value="RemoteAddr">
                          RemoteAddr (直连)
                        </SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-slate-400">
                      反向代理架构下应选择 X-Forwarded-For 或 X-Real-IP
                    </p>
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
                    <p className="text-xs text-slate-400">
                      多个 CIDR 用逗号分隔，仅从受信代理的请求中提取客户端 IP
                    </p>
                  </div>
                </div>
              </Surface>

              <Surface
                title="协议支持"
                description="控制服务端支持的网络协议和压缩特性。"
              >
                <div className="grid gap-4">
                  {[
                    {
                      label: "IPv6 支持",
                      desc: "允许通过 IPv6 地址访问",
                      icon: Zap,
                      checked: ipv6Enabled,
                      onChange: setIpv6Enabled,
                    },
                    {
                      label: "HTTP/2",
                      desc: "启用 HTTP/2 协议以提升传输效率",
                      icon: Zap,
                      checked: http2Enabled,
                      onChange: setHttp2Enabled,
                    },
                    {
                      label: "HTTPS HSTS",
                      desc: "启用严格传输安全（Strict-Transport-Security）",
                      icon: Lock,
                      checked: hstsEnabled,
                      onChange: setHstsEnabled,
                    },
                    {
                      label: "Brotli 压缩",
                      desc: "启用 Brotli 压缩以减小传输体积",
                      icon: Zap,
                      checked: brotliEnabled,
                      onChange: setBrotliEnabled,
                    },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3"
                    >
                      <div>
                        <div className="text-sm font-medium text-slate-900 flex items-center gap-2">
                          <item.icon className="h-4 w-4 text-slate-600" />{" "}
                          {item.label}
                        </div>
                        <div className="text-xs text-slate-500">{item.desc}</div>
                      </div>
                      <Switch
                        checked={item.checked}
                        onCheckedChange={item.onChange}
                      />
                    </div>
                  ))}
                </div>
              </Surface>
            </div>

            {/* System info (readonly) */}
            <Surface
              title="系统信息"
              description="当前运行实例的只读信息。"
            >
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                <InlineMeta
                  label="版本号"
                  value={
                    <span className="flex items-center gap-2">
                      <Server className="h-3.5 w-3.5 text-slate-600" />
                      {getSettingValue(settings, "version", "未知")}
                    </span>
                  }
                />
                <InlineMeta
                  label="运行时间"
                  value={
                    summary ? formatUptime(summary.uptime_sec) : "未知"
                  }
                />
                <InlineMeta
                  label="系统设置数"
                  value={String(settings.length)}
                />
                <InlineMeta
                  label="数据面版本"
                  value={
                    <span className="font-mono text-xs">
                      {String(summary?.revision ?? "N/A")}
                    </span>
                  }
                />
              </div>
            </Surface>

            {/* Save button */}
            <div className="flex justify-end">
              <Button
                onClick={handleSaveProtection}
                disabled={savingProtection}
                className="gap-2 rounded-md bg-teal-600 text-white hover:bg-teal-500"
              >
                <Save className="h-4 w-4" />
                {savingProtection ? "保存中..." : "保存防护配置"}
              </Button>
            </div>
          </div>
        </TabsContent>

        {/* ============================================================ */}
        {/*  TAB 2: 控制台管理                                            */}
        {/* ============================================================ */}
        <TabsContent value="console">
          <div className="space-y-6">
            {/* Login Security */}
            <Surface
              title="登录安全设置"
              description="配置管理控制台的密码策略、登录锁定、会话超时和访问白名单。"
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="space-y-5">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                      <Shield className="h-4 w-4 text-teal-600" />
                      最小密码长度
                    </label>
                    <Input
                      type="number"
                      value={minPasswordLen}
                      onChange={(e) =>
                        setMinPasswordLen(Number(e.target.value))
                      }
                      className="rounded-md"
                      min={6}
                      max={128}
                    />
                    <p className="text-xs text-slate-400">
                      管理员密码的最小字符数要求
                    </p>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                      <Shield className="h-4 w-4 text-teal-600" />
                      最大登录失败次数
                    </label>
                    <Input
                      type="number"
                      value={maxAttempts}
                      onChange={(e) =>
                        setMaxAttempts(Number(e.target.value))
                      }
                      className="rounded-md"
                      min={1}
                      max={100}
                    />
                    <p className="text-xs text-slate-400">
                      超过此次数后账户将被临时锁定
                    </p>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                      <Lock className="h-4 w-4 text-teal-600" />
                      锁定时长（分钟）
                    </label>
                    <Input
                      type="number"
                      value={lockoutMinutes}
                      onChange={(e) =>
                        setLockoutMinutes(Number(e.target.value))
                      }
                      className="rounded-md"
                      min={1}
                      max={1440}
                    />
                    <p className="text-xs text-slate-400">
                      账户被锁定后的自动解锁等待时间
                    </p>
                  </div>
                </div>

                <div className="space-y-5">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                      <Clock className="h-4 w-4 text-teal-600" />
                      会话超时时间（分钟）
                    </label>
                    <Input
                      type="number"
                      value={sessionTimeout}
                      onChange={(e) =>
                        setSessionTimeout(Number(e.target.value))
                      }
                      className="rounded-md"
                      min={5}
                      max={10080}
                    />
                    <p className="text-xs text-slate-400">
                      登录会话无操作后自动失效的时间
                    </p>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 flex items-center gap-2">
                      <Network className="h-4 w-4 text-teal-600" />
                      控制台访问 IP 白名单
                    </label>
                    <Textarea
                      value={accessIpWhitelist}
                      onChange={(e) =>
                        setAccessIpWhitelist(e.target.value)
                      }
                      rows={3}
                      className="rounded-md"
                      placeholder="每行一个 IP 或 CIDR，留空表示不限制"
                    />
                    <p className="text-xs text-slate-400">
                      限制仅允许特定 IP 访问管理控制台，留空则不限制
                    </p>
                  </div>
                </div>
              </div>
            </Surface>

            {/* API Keys */}
            <Surface
              title="API 令牌"
              description="为自动化任务、CI/CD 或运维脚本生成 Bearer Token。创建后仅返回一次明文 Token。"
              action={
                <Button
                  className="gap-2 rounded-md bg-teal-500 text-white hover:bg-teal-600"
                  onClick={() => {
                    setApiKeyDialogOpen(true);
                    setCreatedToken(null);
                    setNewKeyName("");
                  }}
                >
                  <Plus className="h-4 w-4" /> 创建密钥
                </Button>
              }
            >
              {apiKeysLoading ? (
                <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">
                  加载中...
                </div>
              ) : apiKeys.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center text-sm text-slate-500">
                  还没有 API 密钥。创建后可用于自动化访问管理 API。
                </div>
              ) : (
                <div className="overflow-hidden rounded-lg border border-slate-200">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-slate-50 text-xs uppercase tracking-wider text-slate-500">
                        <TableHead className="w-16">ID</TableHead>
                        <TableHead>名称</TableHead>
                        <TableHead>密钥</TableHead>
                        <TableHead>创建时间</TableHead>
                        <TableHead>最近使用</TableHead>
                        <TableHead className="w-20 text-right">
                          操作
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {apiKeys.map((item) => (
                        <TableRow key={item.id} className="hover:bg-slate-50">
                          <TableCell className="font-mono text-xs text-slate-500">
                            {item.id}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <KeyRound className="h-4 w-4 text-slate-600" />
                              <span className="font-medium text-slate-900">
                                {item.name}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <code className="rounded-lg bg-slate-100 px-2 py-1 text-xs font-mono text-slate-500">
                              {maskToken(item.token)}
                            </code>
                          </TableCell>
                          <TableCell className="text-xs text-slate-500 whitespace-nowrap">
                            {formatDate(item.created_at)}
                          </TableCell>
                          <TableCell className="text-xs text-slate-500 whitespace-nowrap">
                            {item.last_used_at
                              ? formatDate(item.last_used_at)
                              : "从未使用"}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center justify-end">
                              <Button
                                variant="ghost"
                                size="icon-sm"
                                className="rounded-lg text-rose-600 hover:bg-rose-50 hover:text-rose-700"
                                onClick={() => setDeleteTarget(item)}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </Surface>

            {/* Admin Certificate Mode */}
            <Surface
              title="控制台证书"
              description="控制管理控制台 HTTPS 的证书来源。如需管理具体证书，请前往「证书管理」页面。"
            >
              <RadioGroup
                value={adminCertMode}
                onValueChange={setAdminCertMode}
                className="grid gap-3 sm:grid-cols-3"
              >
                <label
                  className={`flex cursor-pointer items-start gap-3 rounded-lg border p-4 transition-colors ${
                    adminCertMode === "self_signed"
                      ? "border-teal-300 bg-teal-50"
                      : "border-slate-200 bg-white hover:border-slate-300"
                  }`}
                >
                  <RadioGroupItem value="self_signed" className="mt-0.5" />
                  <div>
                    <div className="text-sm font-medium text-slate-900">
                      自签名证书
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      系统自动生成，适合内网使用
                    </div>
                  </div>
                </label>
                <label
                  className={`flex cursor-pointer items-start gap-3 rounded-lg border p-4 transition-colors ${
                    adminCertMode === "custom"
                      ? "border-teal-300 bg-teal-50"
                      : "border-slate-200 bg-white hover:border-slate-300"
                  }`}
                >
                  <RadioGroupItem value="custom" className="mt-0.5" />
                  <div>
                    <div className="text-sm font-medium text-slate-900">
                      自定义证书
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      使用「证书管理」中上传的证书
                    </div>
                  </div>
                </label>
                <label
                  className={`flex cursor-pointer items-start gap-3 rounded-lg border p-4 transition-colors ${
                    adminCertMode === "none"
                      ? "border-teal-300 bg-teal-50"
                      : "border-slate-200 bg-white hover:border-slate-300"
                  }`}
                >
                  <RadioGroupItem value="none" className="mt-0.5" />
                  <div>
                    <div className="text-sm font-medium text-slate-900">
                      不启用 HTTPS
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      仅 HTTP 访问控制台（不推荐）
                    </div>
                  </div>
                </label>
              </RadioGroup>
              <div className="mt-4 flex items-start gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
                <span>
                  管理和上传 TLS 证书请前往{" "}
                  <a
                    href="/certificates/"
                    className="font-medium text-teal-600 underline underline-offset-2 hover:text-teal-700"
                  >
                    证书管理
                  </a>{" "}
                  页面。
                </span>
              </div>
            </Surface>

            {/* Save button */}
            <div className="flex justify-end">
              <Button
                onClick={handleSaveConsole}
                disabled={savingConsole}
                className="gap-2 rounded-md bg-teal-600 text-white hover:bg-teal-500"
              >
                <Save className="h-4 w-4" />
                {savingConsole ? "保存中..." : "保存控制台设置"}
              </Button>
            </div>
          </div>
        </TabsContent>

        {/* ============================================================ */}
        {/*  TAB 3: 系统日志                                              */}
        {/* ============================================================ */}
        <TabsContent value="logs">
          <div className="space-y-4">
            {/* Controls */}
            <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
              <Select
                value={logType}
                onValueChange={(v) => {
                  setLogType(v as "security" | "access");
                  setLogPage(1);
                }}
              >
                <SelectTrigger className="w-[160px] rounded-lg">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="security">安全事件</SelectItem>
                  <SelectItem value="access">访问日志</SelectItem>
                </SelectContent>
              </Select>
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                <Input
                  value={logSearch}
                  onChange={(e) => {
                    setLogSearch(e.target.value);
                    setLogPage(1);
                  }}
                  placeholder="搜索 IP"
                  className="w-[180px] rounded-lg pl-8"
                />
              </div>
              <div className="ml-auto flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 rounded-lg"
                  onClick={loadLogs}
                >
                  <RefreshCcw className="h-3.5 w-3.5" /> 刷新
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 rounded-lg"
                  onClick={exportLogCSV}
                  disabled={
                    (logType === "security" && secEvents.length === 0) ||
                    (logType === "access" && accessLogs.length === 0)
                  }
                >
                  <Download className="h-3.5 w-3.5" /> 导出 CSV
                </Button>
              </div>
            </div>

            {/* Log table */}
            <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
              {logLoading ? (
                <div className="p-16 text-center text-sm text-slate-400">
                  加载中...
                </div>
              ) : logType === "security" ? (
                secEvents.length === 0 ? (
                  <div className="p-16 text-center text-sm text-slate-400">
                    暂无安全事件日志
                  </div>
                ) : (
                  <>
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-slate-100 bg-slate-50/80 text-left text-xs font-medium text-slate-500">
                            <th className="px-4 py-3">时间</th>
                            <th className="px-4 py-3">动作</th>
                            <th className="px-4 py-3">类别</th>
                            <th className="px-4 py-3">源 IP</th>
                            <th className="px-4 py-3">Host</th>
                            <th className="px-4 py-3">路径</th>
                            <th className="px-4 py-3">匹配描述</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-50">
                          {secEvents.map((evt) => (
                            <tr
                              key={evt.id}
                              className="transition-colors hover:bg-slate-50/50"
                            >
                              <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                                {formatDate(evt.created_at)}
                              </td>
                              <td className="px-4 py-3">
                                <Badge
                                  className={`rounded-md border text-xs ${
                                    evt.action === "intercept" || evt.action === "block"
                                      ? "border-rose-200 bg-rose-50 text-rose-700"
                                      : evt.action === "drop"
                                        ? "border-slate-300 bg-slate-100 text-slate-800"
                                        : evt.action === "observe"
                                          ? "border-slate-200 bg-slate-50 text-slate-600"
                                          : "border-amber-200 bg-amber-50 text-amber-700"
                                  }`}
                                >
                                  {evt.action}
                                </Badge>
                              </td>
                              <td className="px-4 py-3 text-xs text-slate-700">
                                {evt.category}
                              </td>
                              <td className="px-4 py-3 font-mono text-xs text-slate-700">
                                {evt.client_ip}
                              </td>
                              <td className="px-4 py-3 text-xs text-slate-600">
                                {evt.host || "-"}
                              </td>
                              <td className="max-w-[200px] truncate px-4 py-3 font-mono text-xs text-slate-600">
                                {evt.path}
                              </td>
                              <td className="max-w-[180px] truncate px-4 py-3 text-xs text-slate-500">
                                {evt.match_desc || "-"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="border-t border-slate-100 p-3">
                      <Pagination
                        page={logPage}
                        totalPages={logTotalPages}
                        total={logTotal}
                        pageSize={LOG_PAGE_SIZE}
                        onPageChange={setLogPage}
                      />
                    </div>
                  </>
                )
              ) : accessLogs.length === 0 ? (
                <div className="p-16 text-center text-sm text-slate-400">
                  暂无访问日志
                </div>
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-slate-100 bg-slate-50/80 text-left text-xs font-medium text-slate-500">
                          <th className="px-4 py-3">时间</th>
                          <th className="px-4 py-3">方法</th>
                          <th className="px-4 py-3">路径</th>
                          <th className="px-4 py-3">状态码</th>
                          <th className="px-4 py-3">源 IP</th>
                          <th className="px-4 py-3">WAF</th>
                          <th className="px-4 py-3">上游</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-50">
                        {accessLogs.map((item) => (
                          <tr
                            key={item.id}
                            className="transition-colors hover:bg-slate-50/50"
                          >
                            <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                              {formatDate(item.created_at)}
                            </td>
                            <td className="px-4 py-3">
                              <Badge
                                className={`rounded-md border font-mono text-[11px] ${
                                  item.method === "GET"
                                    ? "border-cyan-200 bg-cyan-50 text-cyan-700"
                                    : item.method === "POST"
                                      ? "border-indigo-200 bg-indigo-50 text-indigo-700"
                                      : "border-slate-200 bg-slate-50 text-slate-600"
                                }`}
                              >
                                {item.method}
                              </Badge>
                            </td>
                            <td className="max-w-[240px] truncate px-4 py-3 font-mono text-xs text-slate-600">
                              {item.path}
                            </td>
                            <td className="px-4 py-3">
                              <Badge
                                className={`rounded-md border font-mono text-xs ${
                                  item.status_code >= 500
                                    ? "border-red-200 bg-red-50 text-red-700"
                                    : item.status_code >= 400
                                      ? "border-amber-200 bg-amber-50 text-amber-700"
                                      : item.status_code >= 200 &&
                                          item.status_code < 300
                                        ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                                        : "border-slate-200 bg-slate-50 text-slate-600"
                                }`}
                              >
                                {item.status_code}
                              </Badge>
                            </td>
                            <td className="px-4 py-3 font-mono text-xs text-slate-700">
                              {item.client_ip}
                            </td>
                            <td className="px-4 py-3 text-xs text-slate-500">
                              {item.waf_action || "-"}
                            </td>
                            <td className="max-w-[160px] truncate px-4 py-3 font-mono text-xs text-slate-400">
                              {item.upstream || "-"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="border-t border-slate-100 p-3">
                    <Pagination
                      page={logPage}
                      totalPages={logTotalPages}
                      total={logTotal}
                      pageSize={LOG_PAGE_SIZE}
                      onPageChange={setLogPage}
                    />
                  </div>
                </>
              )}
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {/* ============================================================ */}
      {/*  Dialogs                                                      */}
      {/* ============================================================ */}

      {/* Create API Key Dialog */}
      <Dialog open={apiKeyDialogOpen} onOpenChange={setApiKeyDialogOpen}>
        <DialogContent className="max-w-lg rounded-lg">
          <DialogHeader>
            <DialogTitle>
              {createdToken ? "令牌已创建" : "创建 API 密钥"}
            </DialogTitle>
            <DialogDescription>
              {createdToken
                ? "请立即复制返回的明文 Token。"
                : "创建后仅会返回一次明文 Token。"}
            </DialogDescription>
          </DialogHeader>
          {createdToken ? (
            <div className="space-y-4">
              <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>
                  请立即复制此 Token，关闭后将无法再次查看明文。
                </span>
              </div>
              <div className="flex gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3">
                <code className="flex-1 break-all text-xs text-slate-700">
                  {createdToken}
                </code>
                <Button
                  variant="outline"
                  size="icon-sm"
                  className="shrink-0 rounded-lg"
                  onClick={() => {
                    navigator.clipboard.writeText(createdToken);
                    toast.success("已复制到剪贴板");
                  }}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <Label htmlFor="api-key-name">密钥名称</Label>
              <Input
                id="api-key-name"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="例如：CI Deploy / Terraform / Alert Sync"
                className="rounded-lg"
                onKeyDown={(e) => e.key === "Enter" && handleCreateKey()}
              />
            </div>
          )}
          <DialogFooter>
            {createdToken ? (
              <Button onClick={() => setApiKeyDialogOpen(false)}>
                完成
              </Button>
            ) : (
              <>
                <Button
                  variant="outline"
                  onClick={() => setApiKeyDialogOpen(false)}
                >
                  取消
                </Button>
                <Button onClick={handleCreateKey} disabled={creating}>
                  {creating ? "创建中..." : "创建"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete API Key Dialog */}
      <Dialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <DialogContent className="max-w-md rounded-lg">
          <DialogHeader>
            <DialogTitle>确认删除 API 密钥</DialogTitle>
            <DialogDescription>
              删除后该密钥将立即失效，相关自动化任务需要改用新的 Token。
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-4 py-4 text-sm leading-6 text-rose-900">
            目标密钥：{deleteTarget?.name || "-"}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              取消
            </Button>
            <Button
              className="bg-rose-600 hover:bg-rose-500"
              disabled={deleting}
              onClick={handleDeleteKey}
            >
              {deleting ? "删除中..." : "删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
