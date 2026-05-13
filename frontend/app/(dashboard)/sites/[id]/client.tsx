"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  Bot,
  Globe,
  Loader2,
  Plus,
  Save,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SiteListenersPanel } from "@/components/site-listeners-panel";
import {
  getCertificates,
  getSite,
  startSite,
  stopSite,
  updateSite,
  type Certificate,
  type Site,
} from "@/lib/api";
import { getWAFActionMeta, terminalWAFActionOptions } from "@/lib/console";
import { findInvalidSiteUpstream, parseSiteUpstreams, serializeSiteUpstreams } from "@/lib/site-upstreams";
import { formatDate } from "@/lib/utils";
import { toast } from "sonner";

function extractSiteId(candidate: string | undefined) {
  if (!candidate) return "";
  const last = candidate.split("/").filter(Boolean).at(-1) ?? "";
  return /^\d+$/.test(last) ? last : "";
}

type TabKey = "basic" | "listeners" | "upstream" | "advanced";

export default function SiteDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const siteId = useMemo(() => {
    const rawId = params.id as string | undefined;
    const queryId = searchParams.get("id") || undefined;
    return (
      extractSiteId(queryId) ||
      extractSiteId(rawId) ||
      extractSiteId(pathname) ||
      (typeof window !== "undefined" ? extractSiteId(window.location.pathname) : "") ||
      "_"
    );
  }, [params.id, pathname, searchParams]);

  const [site, setSite] = useState<Site | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [tab, setTab] = useState<TabKey>("basic");

  // Editable form state
  const [host, setHost] = useState("");
  const [bind, setBind] = useState("");
  const [network, setNetwork] = useState("tcp");
  const [tlsEnabled, setTlsEnabled] = useState(false);
  const [certId, setCertId] = useState<number | null>(null);
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [upstreams, setUpstreams] = useState<string[]>([]);
  const [xffMode, setXFFMode] = useState("strip_all_and_set_remote");
  const [trustedCIDR, setTrustedCIDR] = useState("");
  const [preserveOriginalHost, setPreserveOriginalHost] = useState(false);
  const [upstreamTLSSkipVerify, setUpstreamTLSSkipVerify] = useState(false);
  const [upstreamTLSServerName, setUpstreamTLSServerName] = useState("");
  const [cacheEnabled, setCacheEnabled] = useState(false);
  const [cacheDefaultTTL, setCacheDefaultTTL] = useState(0);
  const [cacheRules, setCacheRules] = useState<Array<{ type: string; value: string; ttl: number }>>([]);
  const [owaspAction, setOwaspAction] = useState("intercept");
  const [cveAction, setCveAction] = useState("intercept");
  const [rateLimitAction, setRateLimitAction] = useState("rate_limit");

  // Advanced
  const [blockHtml, setBlockHtml] = useState("");
  const [blockStatus, setBlockStatus] = useState(403);
  const [maintenanceEnabled, setMaintenanceEnabled] = useState(false);
  const [maintenanceHtml, setMaintenanceHtml] = useState("");
  const [maintenanceStatus, setMaintenanceStatus] = useState(503);
  const [maxBodyBytes, setMaxBodyBytes] = useState(0);
  const [antiReplayEnabled, setAntiReplayEnabled] = useState(false);
  const [antiReplayTTL, setAntiReplayTTL] = useState(300);
  const [antiReplayAction, setAntiReplayAction] = useState("shield_challenge");

  const load = useCallback(async () => {
    if (siteId === "_") {
      setSite(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const s = await getSite(siteId);
      setSite(s);
      // Populate form
      setHost(s.host);
      setBind(s.bind);
      setNetwork(s.network);
      setTlsEnabled(s.tls_enabled);
      setCertId(s.cert_id ?? null);
      setUpstreams(parseSiteUpstreams(s.upstream_urls));
      setXFFMode(s.xff_mode || "strip_all_and_set_remote");
      setTrustedCIDR(s.trusted_cidr || "");
      setPreserveOriginalHost(Boolean(s.preserve_original_host));
      setUpstreamTLSSkipVerify(Boolean(s.upstream_tls_skip_verify));
      setUpstreamTLSServerName(s.upstream_tls_server_name || "");
      setCacheEnabled(Boolean(s.cache_enabled));
      setCacheDefaultTTL(s.cache_default_ttl || 0);
      if (Array.isArray(s.cache_rules)) {
        setCacheRules(s.cache_rules.map((rule) => ({ type: rule.type || "prefix", value: rule.value || rule.path || "", ttl: rule.ttl || 0 })));
      } else if (typeof s.cache_rules === "string" && s.cache_rules.trim()) {
        try {
          const parsed = JSON.parse(s.cache_rules) as Array<{ type?: string; value?: string; path?: string; ttl?: number }>;
          setCacheRules(parsed.map((rule) => ({ type: rule.type || "prefix", value: rule.value || rule.path || "", ttl: rule.ttl || 0 })));
        } catch { setCacheRules([]); }
      } else {
        setCacheRules([]);
      }
      setOwaspAction(s.owasp_action || "intercept");
      setCveAction(s.cve_action || "intercept");
      setRateLimitAction(s.rate_limit_action || "rate_limit");
      setBlockHtml(s.block_html || "");
      setBlockStatus(s.block_status || 403);
      setMaintenanceEnabled(s.maintenance_enabled);
      setMaintenanceHtml(s.maintenance_html || "");
      setMaintenanceStatus(s.maintenance_status || 503);
      setMaxBodyBytes(s.max_body_bytes || 0);
      setAntiReplayEnabled(Boolean(s.anti_replay_enabled));
      setAntiReplayTTL(s.anti_replay_ttl || 300);
      setAntiReplayAction(s.anti_replay_action || "shield_challenge");
    } catch (err) {
      toast.error(String(err));
      setSite(null);
    } finally {
      setLoading(false);
    }
  }, [siteId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    getCertificates()
      .then((data) => setCertificates(data.items || []))
      .catch(() => setCertificates([]));
  }, []);

  async function handleSave() {
    if (!site) return;
    const normalizedUpstreams = upstreams.map((item) => item.trim()).filter(Boolean);
    if (normalizedUpstreams.length === 0) {
      toast.error("至少需要配置一个上游地址");
      return;
    }
    const invalidUpstream = findInvalidSiteUpstream(normalizedUpstreams);
    if (invalidUpstream) {
      toast.error(`上游地址格式无效：${invalidUpstream}`);
      return;
    }
    if (tlsEnabled && !certId) {
      toast.error("启用 HTTPS 时请选择证书");
      return;
    }
    setSaving(true);
    try {
      await updateSite(site.id, {
        host,
        bind,
        network,
        tls_enabled: tlsEnabled,
        cert_id: tlsEnabled ? certId : null,
        upstream_urls: serializeSiteUpstreams(normalizedUpstreams),
        xff_mode: xffMode,
        trusted_cidr: trustedCIDR,
        preserve_original_host: preserveOriginalHost,
        upstream_tls_skip_verify: upstreamTLSSkipVerify,
        upstream_tls_server_name: upstreamTLSServerName,
        cache_enabled: cacheEnabled,
        cache_default_ttl: cacheDefaultTTL,
        cache_rules: JSON.stringify(cacheRules.filter((rule) => rule.value.trim() && rule.ttl > 0)),
        owasp_action: owaspAction,
        cve_action: cveAction,
        rate_limit_action: rateLimitAction,
        block_html: blockHtml,
        block_status: blockStatus,
        maintenance_enabled: maintenanceEnabled,
        maintenance_html: maintenanceHtml,
        maintenance_status: maintenanceStatus,
        max_body_bytes: maxBodyBytes,
        anti_replay_enabled: antiReplayEnabled,
        anti_replay_ttl: antiReplayTTL,
        anti_replay_action: antiReplayAction,
      });
      toast.success("站点配置已保存");
      load();
    } catch (err) {
      toast.error(String(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleToggle() {
    if (!site) return;
    try {
      if (site.enabled) {
        await stopSite(site.id);
      } else {
        await startSite(site.id);
      }
      toast.success(site.enabled ? "站点已停用" : "站点已启用");
      load();
    } catch (err) {
      toast.error(String(err));
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-slate-500" />
      </div>
    );
  }

  if (!site) {
    return (
      <div className="flex min-h-[400px] flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 bg-white">
        <Globe className="mb-4 h-12 w-12 text-slate-300" />
        <h3 className="text-lg font-semibold text-slate-700">站点不存在</h3>
        <p className="mt-2 text-sm text-slate-500">该站点可能已被删除或无权访问</p>
        <Button
          className="mt-4 rounded-md bg-slate-950 text-white hover:bg-slate-800"
          onClick={() => router.push("/sites/")}
        >
          返回应用列表
        </Button>
      </div>
    );
  }

  const tabs: { key: TabKey; label: string }[] = [
    { key: "basic", label: "基本配置" },
    { key: "listeners", label: "监听管理" },
    { key: "upstream", label: "上游管理" },
    { key: "advanced", label: "高级配置" },
  ];

  const quickLinks = [
    {
      label: "CC 防护",
      desc: "管理 CC 防护规则与等待室",
      icon: Zap,
      href: "/cc-protection/",
      color: "bg-amber-50 text-amber-600",
    },
    {
      label: "Bot 防护",
      desc: "调整 Bot 阈值与评分策略",
      icon: Bot,
      href: "/bot-protection/",
      color: "bg-purple-50 text-purple-600",
    },
    {
      label: "攻击防护",
      desc: "配置 OWASP 与限流策略",
      icon: ShieldAlert,
      href: "/protection/",
      color: "bg-red-50 text-red-600",
    },
    {
      label: "安全策略",
      desc: "验证码、5秒盾与防重放",
      icon: ShieldCheck,
      href: "/security/",
      color: "bg-slate-100 text-slate-600",
    },
  ];

  return (
    <div className="space-y-6">
      {/* Back */}
      <Button
        variant="ghost"
        className="rounded-md text-slate-500 hover:text-slate-900"
        onClick={() => router.push("/sites/")}
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        返回应用列表
      </Button>

      {/* Site Header */}
      <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-slate-100">
              <Globe className="h-6 w-6 text-slate-600" />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-xl font-bold text-slate-900">{site.host}</h1>
                <span
                  className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                    site.enabled
                      ? "bg-emerald-50 text-emerald-700"
                      : "bg-slate-100 text-slate-500"
                  }`}
                >
                  {site.enabled ? "运行中" : "已停止"}
                </span>
              </div>
              <p className="mt-1 text-sm text-slate-500">
                {site.tls_enabled ? "HTTPS" : "HTTP"} · 监听{" "}
                <span className="font-mono">{site.bind}</span> · 网络 {site.network} · 创建于{" "}
                {formatDate(site.created_at)}
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" className="rounded-md" onClick={handleToggle}>
              {site.enabled ? "停用站点" : "启用站点"}
            </Button>
            <Button variant="outline" className="rounded-md" onClick={load}>
              刷新
            </Button>
          </div>
        </div>
      </div>

      {/* Quick Entry Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {quickLinks.map((q) => (
          <button
            key={q.label}
            onClick={() => router.push(q.href)}
            className="group rounded-lg border border-slate-200 bg-white p-5 text-left shadow-sm transition-all hover:border-slate-300 hover:shadow-md"
          >
            <div className={`mb-3 flex h-10 w-10 items-center justify-center rounded-lg ${q.color}`}>
              <q.icon className="h-5 w-5" />
            </div>
            <h3 className="text-sm font-semibold text-slate-900 group-hover:text-slate-600">
              {q.label}
            </h3>
            <p className="mt-1 text-xs text-slate-500">{q.desc}</p>
          </button>
        ))}
      </div>

      {/* Tabs */}
      <div className="rounded-lg border border-slate-200 bg-white shadow-sm">
        <div className="flex border-b border-slate-200">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-6 py-3 text-sm font-medium transition-colors ${
                tab === t.key
                  ? "border-b-2 border-slate-950 text-slate-950"
                  : "text-slate-500 hover:text-slate-700"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* Basic Config Tab */}
          {tab === "basic" && (
            <div className="space-y-5">
              <div className="grid gap-5 md:grid-cols-2">
                <FieldGroup label="域名 / Host">
                  <Input
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                    placeholder="example.com"
                    className="rounded-md"
                  />
                </FieldGroup>
                <FieldGroup label="监听地址">
                  <Input
                    value={bind}
                    onChange={(e) => setBind(e.target.value)}
                    placeholder=":80"
                    className="rounded-md"
                  />
                </FieldGroup>
                <FieldGroup label="网络协议">
                  <select
                    value={network}
                    onChange={(e) => setNetwork(e.target.value)}
                    className="h-10 w-full rounded-md border border-slate-200 bg-white px-3 text-sm"
                  >
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                  </select>
                </FieldGroup>
                <FieldGroup label="接入协议">
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setTlsEnabled(false);
                        setCertId(null);
                        setBind(":80");
                      }}
                      className={`flex-1 rounded-md border px-4 py-2 text-sm font-medium ${
                        !tlsEnabled
                          ? "border-slate-950 bg-slate-100 text-slate-950"
                          : "border-slate-200 text-slate-600"
                      }`}
                    >
                      HTTP
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setTlsEnabled(true);
                        setBind(":443");
                      }}
                      className={`flex-1 rounded-md border px-4 py-2 text-sm font-medium ${
                        tlsEnabled
                          ? "border-slate-950 bg-slate-100 text-slate-950"
                          : "border-slate-200 text-slate-600"
                      }`}
                    >
                      HTTPS
                    </button>
                  </div>
                </FieldGroup>
                {tlsEnabled && (
                  <FieldGroup label="TLS 证书">
                    <Select value={certId ? String(certId) : ""} onValueChange={(value) => setCertId(value ? Number(value) : null)}>
                      <SelectTrigger className="rounded-md">
                        <SelectValue placeholder={certificates.length ? "选择证书" : "当前没有可用证书"} />
                      </SelectTrigger>
                      <SelectContent>
                        {certificates.map((cert) => (
                          <SelectItem key={cert.id} value={String(cert.id)}>{cert.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </FieldGroup>
                )}
                <FieldGroup label="客户端 IP 解析">
                  <Select value={xffMode} onValueChange={setXFFMode}>
                    <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="strip_all_and_set_remote">忽略 X-Forwarded-For，使用直连 IP</SelectItem>
                      <SelectItem value="trust_outer_waf_cidr_then_take_leftmost">信任外层 WAF CIDR 后取最左 IP</SelectItem>
                    </SelectContent>
                  </Select>
                </FieldGroup>
                <FieldGroup label="可信代理 CIDR">
                  <Input
                    value={trustedCIDR}
                    onChange={(e) => setTrustedCIDR(e.target.value)}
                    placeholder="10.0.0.0/8, 192.168.0.0/16"
                    className="rounded-md font-mono"
                  />
                </FieldGroup>
                <label className="flex items-center justify-between rounded-md border border-slate-200 bg-slate-50 px-4 py-3 md:col-span-2">
                  <div>
                    <div className="text-sm font-medium text-slate-900">保留原始 Host</div>
                    <div className="mt-0.5 text-xs text-slate-500">转发到上游时使用客户端请求 Host，并写入 X-Forwarded-Host。</div>
                  </div>
                  <ToggleSwitch checked={preserveOriginalHost} onChange={setPreserveOriginalHost} />
                </label>
              </div>
            </div>
          )}

          {/* Listeners Tab */}
          {tab === "listeners" && (
            <SiteListenersPanel siteId={site.id} onChanged={load} />
          )}

          {/* Upstream Tab */}
          {tab === "upstream" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">上游地址列表</h3>
                  <p className="text-xs text-slate-500">请求将被转发到以下上游服务器</p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="rounded-md"
                  onClick={() => setUpstreams([...upstreams, "http://127.0.0.1:8080"])}
                >
                  <Plus className="mr-1.5 h-3.5 w-3.5" />
                  添加上游
                </Button>
              </div>
              <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                多上游按轮询转发；安全请求在连接失败时会尝试下一个 upstream，避免重复提交非幂等请求。
              </div>
              <div className="grid gap-4 rounded-md border border-slate-200 bg-slate-50 p-4 md:grid-cols-2">
                <label className="flex items-center justify-between rounded-md border border-slate-200 bg-white px-4 py-3">
                  <div>
                    <div className="text-sm font-medium text-slate-900">跳过上游 TLS 校验</div>
                    <div className="mt-0.5 text-xs text-slate-500">仅用于自签名或测试上游。</div>
                  </div>
                  <ToggleSwitch checked={upstreamTLSSkipVerify} onChange={setUpstreamTLSSkipVerify} />
                </label>
                <FieldGroup label="上游 TLS Server Name">
                  <Input
                    value={upstreamTLSServerName}
                    onChange={(e) => setUpstreamTLSServerName(e.target.value)}
                    placeholder="origin.example.com"
                    className="rounded-md font-mono"
                  />
                </FieldGroup>
              </div>
              <div className="space-y-3">
                {upstreams.length === 0 ? (
                  <div className="rounded-md border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-center text-sm text-slate-400">
                    暂无上游地址，请点击上方按钮添加
                  </div>
                ) : (
                  upstreams.map((u, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 p-2"
                    >
                      <Input
                        value={u}
                        onChange={(e) => {
                          const next = [...upstreams];
                          next[i] = e.target.value;
                          setUpstreams(next);
                        }}
                        placeholder="http://127.0.0.1:8080"
                        className="border-0 bg-transparent font-mono text-sm shadow-none focus-visible:ring-0"
                      />
                      {upstreams.length > 1 && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 shrink-0 rounded-md text-red-500 hover:bg-red-50 hover:text-red-600"
                          onClick={() => setUpstreams(upstreams.filter((_, idx) => idx !== i))}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Advanced Tab */}
          {tab === "advanced" && (
            <div className="space-y-6">
              <div className="rounded-md border border-slate-200 p-5">
                <h3 className="text-sm font-semibold text-slate-900">站点级动作覆盖</h3>
                <p className="mb-4 text-xs text-slate-500">覆盖全局 OWASP/CVE/限速默认动作；规则级 action 优先级更高。</p>
                <div className="grid gap-4 md:grid-cols-3">
                  {[
                    ["OWASP", owaspAction, setOwaspAction],
                    ["CVE", cveAction, setCveAction],
                    ["请求限速", rateLimitAction, setRateLimitAction],
                  ].map(([label, value, setter]) => {
                    const meta = getWAFActionMeta(value as string);
                    return (
                      <FieldGroup key={label as string} label={label as string}>
                        <Select value={value as string} onValueChange={(v) => (setter as (next: string) => void)(v)}>
                          <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            {terminalWAFActionOptions.map((item) => (
                              <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <p className="text-[11px] text-slate-500">默认状态：{meta.defaultStatus}，{meta.description}</p>
                      </FieldGroup>
                    );
                  })}
                </div>
              </div>

              <div className="rounded-md border border-slate-200 p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">资源缓存规则</h3>
                    <p className="text-xs text-slate-500">仅缓存 GET 200、无 Set-Cookie、响应体非空的安全响应。</p>
                  </div>
                  <ToggleSwitch checked={cacheEnabled} onChange={setCacheEnabled} />
                </div>
                {cacheEnabled && (
                  <div className="mt-4 space-y-3">
                    <div className="max-w-xs">
                      <FieldGroup label="默认 TTL（秒）">
                        <Input type="number" min={0} value={cacheDefaultTTL} onChange={(e) => setCacheDefaultTTL(Number(e.target.value))} className="rounded-md" />
                      </FieldGroup>
                    </div>
                    {cacheRules.map((rule, idx) => (
                      <div key={idx} className="grid gap-2 rounded-md border border-slate-200 bg-slate-50 p-2 md:grid-cols-[140px_1fr_120px_40px]">
                        <Select value={rule.type} onValueChange={(v) => setCacheRules(cacheRules.map((item, i) => i === idx ? { ...item, type: v } : item))}>
                          <SelectTrigger className="rounded-md bg-white"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="suffix">后缀</SelectItem>
                            <SelectItem value="prefix">前缀</SelectItem>
                            <SelectItem value="exact">精确</SelectItem>
                          </SelectContent>
                        </Select>
                        <Input value={rule.value} onChange={(e) => setCacheRules(cacheRules.map((item, i) => i === idx ? { ...item, value: e.target.value } : item))} placeholder={rule.type === "suffix" ? ".js" : "/assets/"} className="rounded-md bg-white font-mono text-xs" />
                        <Input type="number" min={1} value={rule.ttl} onChange={(e) => setCacheRules(cacheRules.map((item, i) => i === idx ? { ...item, ttl: Number(e.target.value) } : item))} className="rounded-md bg-white" />
                        <Button variant="ghost" size="icon" className="h-9 w-9 text-rose-500" onClick={() => setCacheRules(cacheRules.filter((_, i) => i !== idx))}><Trash2 className="h-4 w-4" /></Button>
                      </div>
                    ))}
                    <Button variant="outline" size="sm" className="rounded-md" onClick={() => setCacheRules([...cacheRules, { type: "suffix", value: ".js", ttl: 3600 }])}>添加缓存规则</Button>
                  </div>
                )}
              </div>

              {/* Maintenance */}
              <div className="rounded-md border border-slate-200 p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">维护模式</h3>
                    <p className="text-xs text-slate-500">开启后将返回维护页面，所有流量不转发</p>
                  </div>
                  <ToggleSwitch
                    checked={maintenanceEnabled}
                    onChange={setMaintenanceEnabled}
                  />
                </div>
                {maintenanceEnabled && (
                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <FieldGroup label="维护状态码">
                      <Input
                        type="number"
                        value={maintenanceStatus}
                        onChange={(e) => setMaintenanceStatus(Number(e.target.value))}
                        className="rounded-md"
                      />
                    </FieldGroup>
                    <FieldGroup label="维护页面 HTML">
                      <textarea
                        value={maintenanceHtml}
                        onChange={(e) => setMaintenanceHtml(e.target.value)}
                        rows={3}
                        placeholder="<h1>维护中</h1>"
                        className="w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-sm"
                      />
                    </FieldGroup>
                  </div>
                )}
              </div>

              {/* Block settings */}
              <div className="rounded-md border border-slate-200 p-5">
                <h3 className="text-sm font-semibold text-slate-900">自定义拦截页面</h3>
                <p className="mb-4 text-xs text-slate-500">
                  当请求被 WAF 拦截时展示的页面内容
                </p>
                <div className="grid gap-4 md:grid-cols-2">
                  <FieldGroup label="拦截状态码">
                    <Input
                      type="number"
                      value={blockStatus}
                      onChange={(e) => setBlockStatus(Number(e.target.value))}
                      className="rounded-md"
                    />
                  </FieldGroup>
                  <FieldGroup label="拦截页面 HTML">
                    <textarea
                      value={blockHtml}
                      onChange={(e) => setBlockHtml(e.target.value)}
                      rows={3}
                      placeholder="<h1>Access Denied</h1>"
                      className="w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-sm"
                    />
                  </FieldGroup>
                </div>
              </div>

              {/* Max body */}
              <div className="rounded-md border border-slate-200 p-5">
                <h3 className="text-sm font-semibold text-slate-900">请求体限制</h3>
                <p className="mb-4 text-xs text-slate-500">限制最大请求体大小（字节），0 表示不限制</p>
                <div className="max-w-xs">
                  <Input
                    type="number"
                    value={maxBodyBytes}
                    onChange={(e) => setMaxBodyBytes(Number(e.target.value))}
                    className="rounded-md"
                    placeholder="0"
                  />
                </div>
              </div>

              {/* Anti replay */}
              <div className="rounded-md border border-slate-200 p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900">防重放保护</h3>
                    <p className="text-xs text-slate-500">基于 Nonce 校验拦截重复提交请求</p>
                  </div>
                  <ToggleSwitch checked={antiReplayEnabled} onChange={setAntiReplayEnabled} />
                </div>
                {antiReplayEnabled && (
                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <FieldGroup label="Nonce TTL（秒）">
                      <Input
                        type="number"
                        min={10}
                        max={86400}
                        value={antiReplayTTL}
                        onChange={(e) => setAntiReplayTTL(Number(e.target.value))}
                        className="rounded-md"
                      />
                    </FieldGroup>
                    <FieldGroup label="命中动作">
                      <Select value={antiReplayAction} onValueChange={setAntiReplayAction}>
                        <SelectTrigger className="rounded-md"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {terminalWAFActionOptions.map((item) => (
                            <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </FieldGroup>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Save Button */}
        <div className="flex justify-end border-t border-slate-200 px-6 py-4">
          <Button
            onClick={handleSave}
            disabled={saving}
            className="rounded-md bg-slate-950 text-white hover:bg-slate-800"
          >
            {saving ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Save className="mr-2 h-4 w-4" />
            )}
            {saving ? "保存中..." : "保存配置"}
          </Button>
        </div>
      </div>
    </div>
  );
}

function FieldGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="text-sm font-medium text-slate-700">{label}</label>
      {children}
    </div>
  );
}

function ToggleSwitch({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
        checked ? "bg-slate-950" : "bg-slate-200"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
          checked ? "translate-x-6" : "translate-x-1"
        }`}
      />
    </button>
  );
}
