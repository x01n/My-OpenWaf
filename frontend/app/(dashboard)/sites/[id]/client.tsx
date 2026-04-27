"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, usePathname, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Bot,
  Fingerprint,
  ListFilter,
  ShieldAlert,
  ShieldCheck,
  TimerReset,
  Waypoints,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState, InlineMeta, PageIntro, Surface, statusToneClass } from "@/components/console-shell";
import { AttackHeatmap } from "@/components/charts/attack-heatmap";
import { Pagination } from "@/components/pagination";
import {
  getSite,
  getSiteAccessLogs,
  getSiteDropEvents,
  getSiteDropStats,
  getSiteRules,
  getSiteSecurityEvents,
  getSiteSecurityStats,
  getSiteSecurityTimeline,
  type AccessLog,
  type DropEvent,
  type DropStats,
  type Rule,
  type SecurityEvent,
  type Site,
  type SiteSecurityStats,
  type TimelineBucket,
} from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { toast } from "sonner";

const PAGE_SIZE = 10;
const DETAIL_PAGE_SIZE = 6;

function parseUpstreams(raw: string) {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as string[];
  } catch {}
  return raw ? raw.split(",").map((item) => item.trim()).filter(Boolean) : [];
}

function parseCacheRules(value: Site["cache_rules"]) {
  if (!value) return [] as Array<{ path: string; ttl: number }>;
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function extractSiteId(candidate: string | undefined) {
  if (!candidate) return "";
  const last = candidate.split("/").filter(Boolean).at(-1) ?? "";
  return /^\d+$/.test(last) ? last : "";
}

export default function SiteDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const siteId = useMemo(() => {
    const rawId = params.id as string | undefined;
    return (
      extractSiteId(rawId) ||
      extractSiteId(pathname) ||
      (typeof window !== "undefined" ? extractSiteId(window.location.pathname) : "") ||
      "_"
    );
  }, [params.id, pathname]);

  const [site, setSite] = useState<Site | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [securityStats, setSecurityStats] = useState<SiteSecurityStats | null>(null);
  const [timeline, setTimeline] = useState<TimelineBucket[]>([]);
  const [dropStats, setDropStats] = useState<DropStats | null>(null);

  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [securityTotal, setSecurityTotal] = useState(0);
  const [securityPage, setSecurityPage] = useState(1);
  const [securityAction, setSecurityAction] = useState("all");
  const [securityPath, setSecurityPath] = useState("");

  const [accessLogs, setAccessLogs] = useState<AccessLog[]>([]);
  const [accessTotal, setAccessTotal] = useState(0);
  const [accessPage, setAccessPage] = useState(1);
  const [accessPath, setAccessPath] = useState("");
  const [accessCacheState, setAccessCacheState] = useState("all");

  const [dropEvents, setDropEvents] = useState<DropEvent[]>([]);
  const [dropTotal, setDropTotal] = useState(0);
  const [dropPage, setDropPage] = useState(1);
  const [dropClientIP, setDropClientIP] = useState("");
  const [dropSource, setDropSource] = useState("all");

  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (siteId === "_") {
      setSite(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const [
        siteResponse,
        ruleResponse,
        securityStatResponse,
        timelineResponse,
        dropStatResponse,
        securityEventResponse,
        accessLogResponse,
        dropEventResponse,
      ] = await Promise.all([
        getSite(siteId),
        getSiteRules(siteId),
        getSiteSecurityStats(siteId, 24),
        getSiteSecurityTimeline(siteId, 24),
        getSiteDropStats(siteId),
        getSiteSecurityEvents(siteId, {
          page: securityPage,
          page_size: DETAIL_PAGE_SIZE,
          action: securityAction === "all" ? undefined : securityAction,
          path: securityPath || undefined,
        }),
        getSiteAccessLogs(siteId, {
          page: accessPage,
          page_size: DETAIL_PAGE_SIZE,
          path: accessPath || undefined,
          cache_state: accessCacheState === "all" ? undefined : accessCacheState,
        }),
        getSiteDropEvents(siteId, {
          page: dropPage,
          page_size: DETAIL_PAGE_SIZE,
          client_ip: dropClientIP || undefined,
          source: dropSource === "all" ? undefined : dropSource,
        }),
      ]);

      setSite(siteResponse);
      setRules(ruleResponse.items ?? []);
      setSecurityStats(securityStatResponse);
      setTimeline(timelineResponse.buckets ?? []);
      setDropStats(dropStatResponse);

      setSecurityEvents(securityEventResponse.items ?? []);
      setSecurityTotal(securityEventResponse.total ?? 0);

      setAccessLogs(accessLogResponse.items ?? []);
      setAccessTotal(accessLogResponse.total ?? 0);

      setDropEvents(dropEventResponse.items ?? []);
      setDropTotal(dropEventResponse.total ?? 0);
    } catch (error) {
      toast.error(String(error));
      setSite(null);
    } finally {
      setLoading(false);
    }
  }, [siteId, securityPage, securityAction, securityPath, accessPage, accessPath, accessCacheState, dropPage, dropClientIP, dropSource]);

  useEffect(() => {
    load();
  }, [load]);

  const upstreams = useMemo(() => (site ? parseUpstreams(site.upstream_urls) : []), [site]);
  const cacheRules = useMemo(() => parseCacheRules(site?.cache_rules), [site?.cache_rules]);
  const timelineData = useMemo(
    () => timeline.map((item) => ({ hour: item.bucket.includes(" ") ? item.bucket.split(" ").at(-1) || item.bucket : item.bucket, count: item.count })),
    [timeline],
  );

  if (loading) {
    return (
      <Surface className="min-h-[420px] animate-pulse">
        <div className="h-full" />
      </Surface>
    );
  }

  if (!site) {
    return (
      <EmptyState
        title="站点详情加载失败"
        description="该站点可能不存在，或当前会话没有访问权限。请返回列表页重新选择。"
        action={<Button onClick={() => router.push("/sites/")}>返回应用列表</Button>}
      />
    );
  }

  const mode = site.maintenance_enabled ? "maintenance" : site.attack_protection_level === "observe" ? "observe" : "protect";
  const securityTotalPages = Math.max(1, Math.ceil(securityTotal / DETAIL_PAGE_SIZE));
  const accessTotalPages = Math.max(1, Math.ceil(accessTotal / DETAIL_PAGE_SIZE));
  const dropTotalPages = Math.max(1, Math.ceil(dropTotal / DETAIL_PAGE_SIZE));

  return (
    <div className="space-y-6">
      <Button variant="ghost" className="w-fit rounded-2xl text-slate-600 hover:bg-slate-100 hover:text-slate-950" onClick={() => router.push("/sites/")}>
        <ArrowLeft className="mr-2 h-4 w-4" /> 返回应用列表
      </Button>

      <PageIntro
        eyebrow="Site Runtime"
        title={site.host}
        description="站点详情页对齐真实 Site、站点级规则、安全事件、访问日志、缓存状态与主动阻断情况。"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" className="rounded-xl" onClick={load}>刷新详情</Button>
            <div className={`console-badge ${statusToneClass(site.enabled ? "running" : "stopped")}`}>
              {site.enabled ? "运行中" : "已停用"}
            </div>
          </div>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[1.3fr_0.9fr]">
        <Surface title="接入与转发" description="展示站点基础信息、TLS 绑定和上游转发目标。">
          <div className="space-y-5">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              <InlineMeta label="监听地址" value={site.bind} />
              <InlineMeta label="协议" value={site.tls_enabled ? "HTTPS" : "HTTP"} />
              <InlineMeta label="网络" value={site.network} />
              <InlineMeta label="证书 ID" value={site.cert_id ? `#${site.cert_id}` : "未绑定"} />
              <InlineMeta label="XFF 模式" value={site.xff_mode || "默认"} />
              <InlineMeta label="保留原始 Host" value={site.preserve_original_host ? "是" : "否"} />
            </div>
            <div className="space-y-3 rounded-[22px] border border-slate-200 bg-slate-50/80 p-4">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
                <Waypoints className="h-4 w-4 text-cyan-700" />
                上游服务器
              </div>
              <div className="space-y-2">
                {upstreams.length === 0 ? (
                  <div className="text-sm text-slate-500">未配置上游地址</div>
                ) : (
                  upstreams.map((upstream, index) => (
                    <div key={index} className="rounded-2xl border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-slate-700">
                      {upstream}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </Surface>

        <Surface title="保护状态" description="站点级防护配置与全局继承关系。">
          <div className="space-y-3">
            <StatusItem icon={ShieldCheck} label="防护模式" value={mode === "maintenance" ? "维护模式" : mode === "observe" ? "观察模式" : "防护模式"} status={mode} />
            <StatusItem icon={Bot} label="Bot 防护" value={site.bot_protection_enabled ? `开启 · ${site.bot_protection_level || "default"}` : "关闭"} status={site.bot_protection_enabled ? "success" : "default"} />
            <StatusItem icon={ShieldAlert} label="OWASP 覆盖" value={site.owasp_enabled == null ? "继承全局" : site.owasp_enabled ? `启用 · ${site.owasp_sensitivity || "mid"}` : "站点禁用"} status={site.owasp_enabled ? "success" : site.owasp_enabled === false ? "warning" : "default"} />
            <StatusItem icon={TimerReset} label="速率限制" value={site.rate_limit_enabled == null ? "继承全局" : site.rate_limit_enabled ? `${site.rate_limit_max || 0}/${site.rate_limit_window || 0}s` : "站点禁用"} status={site.rate_limit_enabled ? "warning" : "default"} />
            <StatusItem icon={Fingerprint} label="维护状态" value={site.maintenance_enabled ? `已开启 · HTTP ${site.maintenance_status || 503}` : "关闭"} status={site.maintenance_enabled ? "error" : "default"} />
          </div>
        </Surface>
      </div>

      <div className="grid gap-6 xl:grid-cols-4">
        <Surface title="24 小时安全统计" description="站点级事件聚合。">
          <div className="grid gap-3">
            <InlineMeta label="事件总数" value={securityStats?.total?.toLocaleString() ?? "0"} />
            <InlineMeta label="终端动作" value={securityStats?.intercepts?.toLocaleString() ?? "0"} />
            <InlineMeta label="观察命中" value={securityStats?.observes?.toLocaleString() ?? "0"} />
            <InlineMeta label="涉及请求" value={securityStats?.requests?.toLocaleString() ?? "0"} />
          </div>
        </Surface>
        <Surface title="主动阻断统计" description="drop 维度聚合。">
          <div className="grid gap-3">
            <InlineMeta label="24h 总数" value={dropStats?.total_24h?.toLocaleString() ?? "0"} />
            <InlineMeta label="Bot" value={dropStats?.by_bot?.toLocaleString() ?? "0"} />
            <InlineMeta label="CVE" value={dropStats?.by_cve?.toLocaleString() ?? "0"} />
            <InlineMeta label="黑名单" value={dropStats?.by_ip_reputation?.toLocaleString() ?? "0"} />
          </div>
        </Surface>
        <Surface title="缓存配置" description="站点目录树缓存。">
          <div className="grid gap-3">
            <InlineMeta label="缓存开关" value={site.cache_enabled ? "启用" : "关闭"} />
            <InlineMeta label="默认 TTL" value={site.cache_default_ttl ? `${site.cache_default_ttl}s` : "未配置"} />
            <InlineMeta label="规则数" value={cacheRules.length.toLocaleString()} />
            <InlineMeta label="时间线桶" value={timeline.length.toLocaleString()} />
          </div>
        </Surface>
        <Surface title="记录信息" description="站点基础审计信息。">
          <div className="grid gap-3">
            <InlineMeta label="站点 ID" value={`#${site.id}`} />
            <InlineMeta label="策略 ID" value={site.policy_id ? `#${site.policy_id}` : "未绑定"} />
            <InlineMeta label="创建时间" value={formatDate(site.created_at)} />
            <InlineMeta label="更新时间" value={formatDate(site.updated_at)} />
          </div>
        </Surface>
      </div>

      <Surface title="24 小时攻击时间线" description="按小时查看站点安全事件峰值。">
        {timelineData.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">24 小时内暂无安全事件时间线数据。</div>
        ) : (
          <AttackHeatmap data={timelineData} height={280} />
        )}
      </Surface>

      <div className="grid gap-6 xl:grid-cols-2">
        <Surface title="缓存规则" description="按路径前缀进行目录树缓存匹配。">
          <div className="space-y-3">
            {cacheRules.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">当前站点未配置目录树缓存规则。</div>
            ) : (
              cacheRules.map((rule) => (
                <div key={`${rule.path}-${rule.ttl}`} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm">
                  <span className="font-mono text-slate-700">{rule.path}</span>
                  <span className="text-slate-950">{rule.ttl}s</span>
                </div>
              ))
            )}
          </div>
        </Surface>

        <Surface
          title="站点规则"
          description="当前站点绑定策略中的规则。"
          action={<Button variant="outline" className="rounded-xl" onClick={() => router.push("/rules/")}>查看全局规则</Button>}
        >
          <div className="space-y-3">
            {rules.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">当前站点未绑定自定义规则。</div>
            ) : (
              rules.slice(0, 10).map((rule) => (
                <div key={rule.id} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium text-slate-900">{rule.name || `Rule #${rule.id}`}</div>
                      <div className="text-xs text-slate-500">{rule.phase} · priority {rule.priority}</div>
                    </div>
                    <div className={`console-badge ${statusToneClass(rule.enabled ? "running" : "stopped")}`}>{rule.action}</div>
                  </div>
                  <div className="mt-2 font-mono text-xs text-slate-600">{rule.pattern}</div>
                </div>
              ))
            )}
          </div>
        </Surface>
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <Surface
          title="最近安全事件"
          description="站点级拦截与观察事件。"
          action={<Button variant="outline" className="rounded-xl" onClick={() => router.push("/security-events/")}>查看全局事件</Button>}
        >
          <div className="mb-4 grid gap-3">
            <div className="grid gap-3 md:grid-cols-[1fr_180px_auto]">
              <Input value={securityPath} onChange={(event) => { setSecurityPath(event.target.value); setSecurityPage(1); }} placeholder="按路径筛选安全事件" className="rounded-xl" />
              <select value={securityAction} onChange={(event) => { setSecurityAction(event.target.value); setSecurityPage(1); }} className="h-10 rounded-xl border border-slate-200 bg-white px-3 text-sm text-slate-900">
                <option value="all">全部动作</option>
                <option value="intercept">拦截</option>
                <option value="observe">观察</option>
                <option value="drop">丢弃</option>
                <option value="challenge">挑战</option>
                <option value="redirect">重定向</option>
              </select>
              <Button variant="outline" className="rounded-xl" onClick={() => { setSecurityPath(""); setSecurityAction("all"); setSecurityPage(1); }}>
                <ListFilter className="mr-2 h-4 w-4" /> 重置
              </Button>
            </div>
          </div>
          {securityEvents.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">暂无事件。</div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-3">
                {securityEvents.map((event) => (
                  <div key={event.id} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-xs text-slate-500">{formatDate(event.created_at)}</div>
                      <div className={`console-badge ${statusToneClass(event.action)}`}>{event.action}</div>
                    </div>
                    <div className="mt-2 font-mono text-xs text-slate-700">{event.path}</div>
                    <div className="mt-2 text-xs text-slate-500">{event.rule_id_str || event.rule_id} · {event.category}</div>
                  </div>
                ))}
              </div>
              <Pagination page={securityPage} totalPages={securityTotalPages} total={securityTotal} pageSize={DETAIL_PAGE_SIZE} onPageChange={setSecurityPage} />
            </div>
          )}
        </Surface>

        <Surface
          title="最近访问日志"
          description="可观察缓存命中与回源。"
          action={<Button variant="outline" className="rounded-xl" onClick={() => router.push("/access-logs/")}>查看全局日志</Button>}
        >
          <div className="mb-4 grid gap-3">
            <div className="grid gap-3 md:grid-cols-[1fr_180px_auto]">
              <Input value={accessPath} onChange={(event) => { setAccessPath(event.target.value); setAccessPage(1); }} placeholder="按路径筛选访问日志" className="rounded-xl" />
              <select value={accessCacheState} onChange={(event) => { setAccessCacheState(event.target.value); setAccessPage(1); }} className="h-10 rounded-xl border border-slate-200 bg-white px-3 text-sm text-slate-900">
                <option value="all">全部缓存状态</option>
                <option value="hit">命中</option>
                <option value="miss">回源</option>
                <option value="bypass">绕过</option>
              </select>
              <Button variant="outline" className="rounded-xl" onClick={() => { setAccessPath(""); setAccessCacheState("all"); setAccessPage(1); }}>
                <ListFilter className="mr-2 h-4 w-4" /> 重置
              </Button>
            </div>
          </div>
          {accessLogs.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">暂无访问日志。</div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-3">
                {accessLogs.map((item) => (
                  <div key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-xs text-slate-500">{formatDate(item.created_at)}</div>
                      <div className="flex items-center gap-2">
                        <span className={`console-badge ${statusToneClass(item.waf_action)}`}>{item.waf_action}</span>
                        <span className={`console-badge ${statusToneClass(item.cache_state)}`}>{item.cache_state}</span>
                      </div>
                    </div>
                    <div className="mt-2 font-mono text-xs text-slate-700">{item.path}</div>
                    <div className="mt-2 text-xs text-slate-500">{item.method} · {item.status_code} · {item.upstream || "-"}</div>
                  </div>
                ))}
              </div>
              <Pagination page={accessPage} totalPages={accessTotalPages} total={accessTotal} pageSize={DETAIL_PAGE_SIZE} onPageChange={setAccessPage} />
            </div>
          )}
        </Surface>

        <Surface
          title="最近主动阻断"
          description="按站点维度展示 drop 事件。"
          action={<Button variant="outline" className="rounded-xl" onClick={() => router.push("/drop-policy/")}>查看全局阻断</Button>}
        >
          <div className="mb-4 grid gap-3">
            <div className="grid gap-3 md:grid-cols-[1fr_180px_auto]">
              <Input value={dropClientIP} onChange={(event) => { setDropClientIP(event.target.value); setDropPage(1); }} placeholder="按客户端 IP 筛选 drop" className="rounded-xl" />
              <select value={dropSource} onChange={(event) => { setDropSource(event.target.value); setDropPage(1); }} className="h-10 rounded-xl border border-slate-200 bg-white px-3 text-sm text-slate-900">
                <option value="all">全部来源</option>
                <option value="bot">Bot</option>
                <option value="cve">CVE</option>
                <option value="rule">规则</option>
                <option value="ip_reputation">IP 信誉</option>
              </select>
              <Button variant="outline" className="rounded-xl" onClick={() => { setDropClientIP(""); setDropSource("all"); setDropPage(1); }}>
                <ListFilter className="mr-2 h-4 w-4" /> 重置
              </Button>
            </div>
          </div>
          {dropEvents.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">暂无主动阻断事件。</div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-3">
                {dropEvents.map((item) => (
                  <div key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-xs text-slate-500">{formatDate(item.created_at)}</div>
                      <div className={`console-badge ${statusToneClass("drop")}`}>{item.source}</div>
                    </div>
                    <div className="mt-2 font-mono text-xs text-slate-700">{item.path}</div>
                    <div className="mt-2 text-xs text-slate-500">{item.client_ip} · {item.rule_id || "-"}</div>
                  </div>
                ))}
              </div>
              <Pagination page={dropPage} totalPages={dropTotalPages} total={dropTotal} pageSize={DETAIL_PAGE_SIZE} onPageChange={setDropPage} />
            </div>
          )}
        </Surface>
      </div>

      <Surface title="站点运行参数" description="对齐 Site 模型的关键容量、TLS 与维护控制字段。">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <InlineMeta label="最大 Body" value={site.max_body_bytes ? `${site.max_body_bytes} bytes` : "默认"} />
          <InlineMeta label="TLS 最低版本" value={site.min_tls_version || "TLS12"} />
          <InlineMeta label="TLS 最高版本" value={site.max_tls_version || "TLS13"} />
          <InlineMeta label="上游证书校验" value={site.upstream_tls_skip_verify ? "跳过校验" : "严格校验"} />
          <InlineMeta label="维护状态码" value={String(site.maintenance_status || 503)} />
          <InlineMeta label="拦截状态码" value={String(site.block_status || 403)} />
          <InlineMeta label="可信 CIDR" value={site.trusted_cidr || "未配置"} />
          <InlineMeta label="Listener ID" value={String(site.listener_id || 0)} />
        </div>
      </Surface>
    </div>
  );
}

function StatusItem({
  icon: Icon,
  label,
  value,
  status,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  status: string;
}) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-3">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-900 text-white">
          <Icon className="h-4 w-4" />
        </div>
        <div>
          <div className="text-sm font-medium text-slate-900">{label}</div>
          <div className="text-xs text-slate-500">站点级当前生效配置</div>
        </div>
      </div>
      <div className={`console-badge ${statusToneClass(status)}`}>{value}</div>
    </div>
  );
}
