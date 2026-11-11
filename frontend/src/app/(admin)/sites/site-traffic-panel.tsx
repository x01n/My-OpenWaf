"use client";

/**
 * 站点「站点流量」面板：站点级访问日志 + 连接丢弃事件可观测性。
 *
 * 数据来源（internal/admin/router.go L189-192）：
 * - GET /sites/:id/access-logs/stats?hours=24 → SiteAccessLogStats
 * - GET /sites/:id/access-logs → { items, total, page }
 * - GET /sites/:id/drop-stats → DropStatsSummary
 * - GET /sites/:id/drop-events → { items, total, page }
 * 日志详情因列表投影不含大字段，按 id 二次拉取 GET /access-logs/:id。
 */

import { useCallback, useEffect, useState } from "react";
import { Button, Input, ScrollShadow, Tabs, useOverlayState } from "@heroui/react";
import { RefreshCw } from "lucide-react";
import { apiGet } from "@/lib/api/client";
import { useApi, useDebounced, useList } from "@/lib/hooks/use-api";
import type {
  SiteAccessLog,
  SiteAccessLogStats,
  SiteDropEvent,
  SiteDropStats,
} from "@/lib/types/site-traffic";
import {
  CardSkeleton,
  ErrorState,
  Pager,
  SearchInput,
  SimpleSelect,
  StatCard,
  StatusChip,
  TableSkeleton,
  Toolbar,
  type StatusTone,
} from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import { formatDateTime, truncate } from "@/lib/utils/format";
import { useI18n, useNumberFormat, type MessageKey, type TranslateFn } from "@/i18n";

/* ---------- 常量 ---------- */

const PAGE_SIZE = 20;

type MethodFilter =
  | "all"
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD"
  | "OPTIONS";

/** waf_action 取值来自 internal/core/action/action.go 常量集与 dataplane 写入点。 */
const ACTION_META: Record<string, { labelKey: MessageKey; tone: StatusTone }> = {
  allow: { labelKey: "action.allow", tone: "success" },
  none: { labelKey: "siteDetail.traffic.action.none", tone: "neutral" },
  observe: { labelKey: "action.observe", tone: "info" },
  tag: { labelKey: "siteDetail.traffic.action.tag", tone: "info" },
  log_only: { labelKey: "siteDetail.traffic.action.logOnly", tone: "info" },
  intercept: { labelKey: "action.intercept", tone: "danger" },
  block: { labelKey: "action.intercept", tone: "danger" },
  drop: { labelKey: "action.drop", tone: "danger" },
  rate_limit: { labelKey: "action.rateLimit", tone: "danger" },
  challenge: { labelKey: "action.challenge", tone: "warning" },
  captcha_challenge: { labelKey: "action.captchaChallenge", tone: "warning" },
  shield_challenge: { labelKey: "action.shieldChallenge", tone: "warning" },
  chain_challenge: { labelKey: "action.chainChallenge", tone: "warning" },
  challenge_passed: { labelKey: "siteDetail.traffic.action.challengePassed", tone: "success" },
  redirect: { labelKey: "action.redirect", tone: "info" },
  basic_auth: { labelKey: "siteDetail.traffic.action.basicAuth", tone: "warning" },
  maintenance: { labelKey: "siteDetail.traffic.action.maintenance", tone: "warning" },
  js_plugin_fail_closed: { labelKey: "siteDetail.traffic.action.pluginFailClosed", tone: "danger" },
};

/** WAF 动作筛选项（值与 ACTION_META 对齐，all 为全部）。 */
const WAF_ACTION_FILTERS = [
  "intercept",
  "observe",
  "drop",
  "challenge",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
  "rate_limit",
  "redirect",
  "allow",
  "none",
] as const;

/** cache_state 取值：hit / miss / stale / bypass（internal/dataplane/handler.go L1076-1153）。 */
const CACHE_STATE_META: Record<string, { labelKey: MessageKey; tone: StatusTone }> = {
  hit: { labelKey: "siteDetail.traffic.cache.hit", tone: "success" },
  miss: { labelKey: "siteDetail.traffic.cache.miss", tone: "warning" },
  stale: { labelKey: "siteDetail.traffic.cache.stale", tone: "warning" },
  bypass: { labelKey: "siteDetail.traffic.cache.bypass", tone: "neutral" },
};

/** 丢弃来源语言包键与语义色：bot/cve/rule/ip_reputation。 */
const DROP_SOURCE_META: Record<string, { labelKey: MessageKey; tone: StatusTone }> = {
  bot: { labelKey: "siteDetail.traffic.dropSource.bot", tone: "warning" },
  cve: { labelKey: "siteDetail.traffic.dropSource.cve", tone: "danger" },
  rule: { labelKey: "siteDetail.traffic.dropSource.rule", tone: "info" },
  ip_reputation: { labelKey: "siteDetail.traffic.dropSource.ipReputation", tone: "neutral" },
};

const DROP_SOURCE_FILTERS = ["bot", "cve", "rule", "ip_reputation"] as const;

/* ---------- 工具 ---------- */

function statusTextClass(code: number): string {
  return code >= 500 ? "text-danger" : code >= 400 ? "text-warning" : "text-success";
}

function ActionChip({ action }: { action: string }) {
  const { t } = useI18n();
  const meta = ACTION_META[action];
  return (
    <StatusChip tone={meta?.tone ?? "neutral"}>
      {meta ? t(meta.labelKey) : action || "-"}
    </StatusChip>
  );
}

function CacheStateChip({ state }: { state: string }) {
  const { t } = useI18n();
  const meta = CACHE_STATE_META[state];
  return (
    <StatusChip tone={meta?.tone ?? "neutral"}>
      {meta ? t(meta.labelKey) : state || "-"}
    </StatusChip>
  );
}

function DropSourceChip({ source }: { source: string }) {
  const { t } = useI18n();
  const meta = DROP_SOURCE_META[source];
  return (
    <StatusChip tone={meta?.tone ?? "neutral"}>
      {meta ? t(meta.labelKey) : source || "-"}
    </StatusChip>
  );
}

/* ---------- 日志详情字段分组 ---------- */

type FieldKind = "text" | "time" | "bool" | "count" | "pre";

type FieldSpec = {
  labelKey: MessageKey;
  key: keyof SiteAccessLog;
  kind?: FieldKind;
};

/** 基础信息分组。 */
const BASE_FIELDS: FieldSpec[] = [
  { labelKey: "siteDetail.field.id", key: "id", kind: "count" },
  { labelKey: "common.time", key: "created_at", kind: "time" },
  { labelKey: "siteDetail.traffic.field.siteId", key: "site_id", kind: "count" },
  { labelKey: "common.requestId", key: "request_id" },
  { labelKey: "common.clientIp", key: "client_ip" },
  { labelKey: "common.host", key: "host" },
  { labelKey: "common.path", key: "path" },
  { labelKey: "siteDetail.traffic.field.queryString", key: "query_string" },
  { labelKey: "common.method", key: "method" },
  { labelKey: "common.statusCode", key: "status_code", kind: "count" },
  { labelKey: "siteDetail.traffic.field.wafAction", key: "waf_action", kind: "text" },
  { labelKey: "siteDetail.traffic.field.cacheState", key: "cache_state", kind: "text" },
  { labelKey: "siteDetail.traffic.field.upstream", key: "upstream" },
  { labelKey: "siteDetail.recorded.field.userAgent", key: "user_agent" },
  { labelKey: "siteDetail.traffic.field.httpProtocol", key: "http_protocol" },
  { labelKey: "siteDetail.traffic.field.upstreamProtocol", key: "upstream_http_protocol" },
  { labelKey: "siteDetail.traffic.field.upstreamLatency", key: "upstream_latency_ms", kind: "count" },
  { labelKey: "siteDetail.traffic.field.responseSize", key: "response_size", kind: "count" },
];

/** TLS 指纹分组。 */
const TLS_FIELDS: FieldSpec[] = [
  { labelKey: "siteDetail.traffic.field.tlsVersion", key: "tls_version" },
  { labelKey: "siteDetail.traffic.field.tlsSni", key: "tls_sni" },
  { labelKey: "siteDetail.traffic.field.tlsAlpn", key: "tls_alpn" },
  { labelKey: "siteDetail.traffic.field.ja3", key: "tls_ja3", kind: "pre" },
  { labelKey: "siteDetail.traffic.field.ja3Hash", key: "tls_ja3_hash" },
  { labelKey: "siteDetail.traffic.field.ja4", key: "tls_ja4" },
  { labelKey: "siteDetail.traffic.field.cipherSuites", key: "tls_cipher_suites", kind: "pre" },
  { labelKey: "siteDetail.traffic.field.extensions", key: "tls_extensions", kind: "pre" },
  { labelKey: "siteDetail.traffic.field.curves", key: "tls_curves", kind: "pre" },
  { labelKey: "siteDetail.traffic.field.pointFormats", key: "tls_point_formats" },
  { labelKey: "siteDetail.traffic.field.headerOrder", key: "header_order", kind: "pre" },
  { labelKey: "siteDetail.traffic.field.zeroRtt", key: "zero_rtt", kind: "bool" },
];

/** 访客融合分组。 */
const FUSION_FIELDS: FieldSpec[] = [
  { labelKey: "siteDetail.traffic.field.fusionClass", key: "visitor_fusion_class" },
  { labelKey: "siteDetail.traffic.field.fusionScore", key: "visitor_fusion_score", kind: "count" },
  {
    labelKey: "siteDetail.traffic.field.fusionClientFamily",
    key: "visitor_fusion_client_family",
  },
  { labelKey: "siteDetail.traffic.field.fusionUaClaim", key: "visitor_fusion_ua_claim" },
  { labelKey: "siteDetail.traffic.field.fusionConsistency", key: "visitor_fusion_consistency" },
  {
    labelKey: "siteDetail.traffic.field.fusionEvidence",
    key: "visitor_fusion_evidence_sufficient",
    kind: "bool",
  },
  { labelKey: "siteDetail.traffic.field.fusionReasons", key: "visitor_fusion_reasons", kind: "pre" },
];

/** 请求响应分组。 */
const PAYLOAD_FIELDS: FieldSpec[] = [
  { labelKey: "siteDetail.traffic.field.requestHeaders", key: "request_headers", kind: "pre" },
  {
    labelKey: "siteDetail.traffic.field.requestBodyPreview",
    key: "request_body_preview",
    kind: "pre",
  },
  {
    labelKey: "siteDetail.traffic.field.requestBodyTruncated",
    key: "request_body_truncated",
    kind: "bool",
  },
  { labelKey: "siteDetail.traffic.field.requestSize", key: "request_size", kind: "count" },
  { labelKey: "siteDetail.traffic.field.responseHeaders", key: "response_headers", kind: "pre" },
];

function fieldValue(
  row: SiteAccessLog,
  spec: FieldSpec,
  t: TranslateFn,
  fmt: (n: number | undefined) => string,
): string {
  const raw = row[spec.key];
  if (spec.kind === "time") return formatDateTime(raw as string);
  if (spec.kind === "bool") {
    return raw ? t("siteDetail.traffic.bool.yes") : t("siteDetail.traffic.bool.no");
  }
  if (spec.kind === "count") return fmt(raw as number);
  return "";
}

/** 字段行渲染：时间/布尔/数字已格式化，长文本走滚动 pre。 */
function DetailField({ row, spec }: { row: SiteAccessLog; spec: FieldSpec }) {
  const { t } = useI18n();
  const fmt = useNumberFormat();
  const label = t(spec.labelKey);

  if (spec.kind === "time" || spec.kind === "bool" || spec.kind === "count") {
    const value = fieldValue(row, spec, t, fmt);
    return <DetailRow label={label}>{value || "-"}</DetailRow>;
  }
  const raw = row[spec.key];
  const text = typeof raw === "string" ? raw : raw ? String(raw) : "";
  if (!text) return <DetailRow label={label}>-</DetailRow>;
  if (spec.kind === "pre") {
    return (
      <DetailRow label={label}>
        <ScrollShadow className="max-h-48">
          <pre className="text-xs break-all whitespace-pre-wrap">{text}</pre>
        </ScrollShadow>
      </DetailRow>
    );
  }
  return <DetailRow label={label}>{text}</DetailRow>;
}

function FieldGroup({
  title,
  row,
  fields,
}: {
  title: string;
  row: SiteAccessLog;
  fields: FieldSpec[];
}) {
  return (
    <div>
      <div className="text-muted mb-1 text-sm font-medium">{title}</div>
      <div className="bg-surface rounded-xl border border-separator px-4">
        {fields.map((spec) => (
          <DetailField key={spec.key} row={row} spec={spec} />
        ))}
      </div>
    </div>
  );
}

/* ---------- 主面板 ---------- */

export function SiteTrafficPanel({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const fmt = useNumberFormat();

  /* 访问日志筛选 */
  const [qInput, setQInput] = useState("");
  const q = useDebounced(qInput, 350);
  const [method, setMethod] = useState<MethodFilter>("all");
  const [wafAction, setWafAction] = useState("all");

  const logs = useList<SiteAccessLog>(`/sites/${siteId}/access-logs`, {
    q: q || undefined,
    method: method === "all" ? undefined : method,
    waf_action: wafAction === "all" ? undefined : wafAction,
  });

  /* 丢弃事件筛选 */
  const [clientIpInput, setClientIpInput] = useState("");
  const clientIp = useDebounced(clientIpInput, 350);
  const [source, setSource] = useState("all");

  const drops = useList<SiteDropEvent>(`/sites/${siteId}/drop-events`, {
    client_ip: clientIp || undefined,
    source: source === "all" ? undefined : source,
  });

  /* 防抖筛选变化后回到第一页，避免停留在越界页码 */
  useEffect(() => {
    logs.setPage(1);
  }, [q, method, wafAction, logs.setPage]);
  useEffect(() => {
    drops.setPage(1);
  }, [clientIp, source, drops.setPage]);

  /* 统计 */
  const stats = useApi<SiteAccessLogStats>(
    useCallback(
      () => apiGet<SiteAccessLogStats>(`/sites/${siteId}/access-logs/stats`, { hours: 24 }),
      [siteId],
    ),
    [siteId],
  );
  const dropStats = useApi<SiteDropStats>(
    useCallback(() => apiGet<SiteDropStats>(`/sites/${siteId}/drop-stats`), [siteId]),
    [siteId],
  );

  /* 日志详情：列表投影不含大字段，按 id 拉取完整行 */
  const [detail, setDetail] = useState<SiteAccessLog | null>(null);
  const detailState = useOverlayState();
  const detailFull = useApi<SiteAccessLog>(
    useCallback(() => apiGet<SiteAccessLog>(`/access-logs/${detail!.id}`), [detail?.id]),
    [detail?.id],
    { enabled: detail !== null },
  );
  const detailData =
    detailFull.data && detailFull.data.id === detail?.id ? detailFull.data : detail;

  function openDetail(row: SiteAccessLog) {
    setDetail(row);
    detailState.open();
  }

  function reloadAll() {
    void stats.reload();
    void dropStats.reload();
    void logs.reload();
    void drops.reload();
  }

  const methodOptions: { key: MethodFilter; label: string }[] = [
    { key: "all", label: t("logs.method.all") },
    { key: "GET", label: "GET" },
    { key: "POST", label: "POST" },
    { key: "PUT", label: "PUT" },
    { key: "PATCH", label: "PATCH" },
    { key: "DELETE", label: "DELETE" },
    { key: "HEAD", label: "HEAD" },
    { key: "OPTIONS", label: "OPTIONS" },
  ];

  const wafActionOptions = [
    { key: "all", label: t("siteDetail.traffic.wafActionAll") },
    ...WAF_ACTION_FILTERS.map((key) => ({
      key,
      label: t(ACTION_META[key].labelKey),
    })),
  ];

  const dropSourceOptions = [
    { key: "all", label: t("siteDetail.traffic.dropSourceAll") },
    ...DROP_SOURCE_FILTERS.map((key) => ({
      key,
      label: t(DROP_SOURCE_META[key].labelKey),
    })),
  ];

  const logColumns: DataTableColumn<SiteAccessLog>[] = [
    {
      header: t("logs.col.time"),
      render: (row) => (
        <span className="text-xs whitespace-nowrap">{formatDateTime(row.created_at)}</span>
      ),
    },
    {
      header: t("logs.col.clientIp"),
      render: (row) => <span className="font-mono text-xs">{row.client_ip || "-"}</span>,
    },
    { header: t("logs.col.method"), render: (row) => <span className="text-xs">{row.method}</span> },
    {
      header: t("logs.col.path"),
      className: "max-w-56",
      render: (row) => {
        const full = row.query_string ? `${row.path}?${row.query_string}` : row.path;
        return (
          <span className="block truncate font-mono text-xs" title={full}>
            {truncate(full || "-", 48)}
          </span>
        );
      },
    },
    {
      header: t("logs.col.statusCode"),
      render: (row) => (
        <span className={`tabular text-sm font-medium ${statusTextClass(row.status_code)}`}>
          {row.status_code}
        </span>
      ),
    },
    { header: "WAF", render: (row) => <ActionChip action={row.waf_action} /> },
    { header: t("siteDetail.traffic.col.cache"), render: (row) => <CacheStateChip state={row.cache_state} /> },
    {
      header: t("siteDetail.traffic.col.latency"),
      render: (row) => <span className="tabular text-xs">{row.upstream_latency_ms}</span>,
    },
    {
      header: t("common.actions"),
      render: (row) => (
        <Button size="sm" variant="outline" onPress={() => openDetail(row)}>
          {t("common.detail")}
        </Button>
      ),
    },
  ];

  const dropColumns: DataTableColumn<SiteDropEvent>[] = [
    {
      header: t("logs.col.time"),
      render: (row) => (
        <span className="text-xs whitespace-nowrap">{formatDateTime(row.created_at)}</span>
      ),
    },
    {
      header: t("logs.col.clientIp"),
      render: (row) => <span className="font-mono text-xs">{row.client_ip || "-"}</span>,
    },
    {
      header: t("siteDetail.traffic.col.source"),
      render: (row) => <DropSourceChip source={row.source} />,
    },
    {
      header: t("siteDetail.traffic.col.ruleId"),
      render: (row) => <span className="font-mono text-xs">{row.rule_id || "-"}</span>,
    },
    {
      header: t("common.host"),
      render: (row) => <span className="block max-w-40 truncate text-xs">{row.host || "-"}</span>,
    },
    {
      header: t("common.path"),
      className: "max-w-56",
      render: (row) => (
        <span className="block truncate font-mono text-xs" title={row.path}>
          {truncate(row.path || "-", 48)}
        </span>
      ),
    },
    {
      header: t("siteDetail.traffic.col.detail"),
      className: "max-w-56",
      render: (row) => (
        <span className="text-muted block truncate text-xs" title={row.detail}>
          {truncate(row.detail || "-", 48)}
        </span>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-4 py-2">
      {/* 请求统计（24 小时） */}
      <section>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-muted text-sm font-medium">{t("siteDetail.traffic.stats.requests")}</h3>
          <Button size="sm" variant="ghost" onPress={reloadAll}>
            <RefreshCw className="size-3.5" /> {t("common.refresh")}
          </Button>
        </div>
        {stats.error ? (
          <ErrorState message={stats.error} onRetry={stats.reload} />
        ) : stats.loading && !stats.data ? (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <CardSkeleton key={i} height="h-24" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4">
            <StatCard label={t("siteDetail.traffic.stats.total")} value={fmt(stats.data?.requests)} />
            <StatCard
              label={t("siteDetail.traffic.stats.intercepts")}
              value={fmt(stats.data?.intercepts)}
              tone="danger"
            />
            <StatCard
              label={t("siteDetail.traffic.stats.observes")}
              value={fmt(stats.data?.observes)}
              tone="warning"
            />
            <StatCard
              label={t("siteDetail.traffic.stats.cacheHits")}
              value={fmt(stats.data?.cache_hits)}
              tone="success"
            />
            <StatCard
              label={t("siteDetail.traffic.stats.cacheMisses")}
              value={fmt(stats.data?.cache_misses)}
            />
            <StatCard
              label={t("siteDetail.traffic.stats.cacheBypasses")}
              value={fmt(stats.data?.cache_bypasses)}
            />
            <StatCard
              label={t("siteDetail.traffic.stats.cacheStales")}
              value={fmt(stats.data?.cache_stales)}
              tone="warning"
            />
          </div>
        )}
      </section>

      {/* 丢弃统计（24 小时） */}
      <section>
        <h3 className="text-muted mb-2 text-sm font-medium">{t("siteDetail.traffic.drop.title")}</h3>
        {dropStats.error ? (
          <ErrorState message={dropStats.error} onRetry={dropStats.reload} />
        ) : dropStats.loading && !dropStats.data ? (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <CardSkeleton key={i} height="h-24" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            <StatCard
              label={t("siteDetail.traffic.drop.total")}
              value={fmt(dropStats.data?.total_24h)}
              tone="danger"
            />
            <StatCard
              label={t("siteDetail.traffic.drop.bot")}
              value={fmt(dropStats.data?.by_bot)}
              tone="warning"
            />
            <StatCard
              label={t("siteDetail.traffic.drop.cve")}
              value={fmt(dropStats.data?.by_cve)}
              tone="danger"
            />
            <StatCard
              label={t("siteDetail.traffic.drop.rule")}
              value={fmt(dropStats.data?.by_rule)}
              tone="info"
            />
            <StatCard
              label={t("siteDetail.traffic.drop.ipReputation")}
              value={fmt(dropStats.data?.by_ip_reputation)}
            />
          </div>
        )}
      </section>

      {/* 明细列表 */}
      <Tabs aria-label={t("siteDetail.traffic.tabs.aria")}>
        <Tabs.List aria-label={t("siteDetail.traffic.tabs.navAria")}>
          <Tabs.Tab id="logs">{t("siteDetail.traffic.tab.logs")}</Tabs.Tab>
          <Tabs.Tab id="drops">{t("siteDetail.traffic.tab.drops")}</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel id="logs">
          <div className="flex flex-col gap-2">
            <Toolbar>
              <SearchInput
                value={qInput}
                onChange={setQInput}
                placeholder={t("logs.search")}
              />
              <SimpleSelect
                value={method}
                onChange={setMethod}
                options={methodOptions}
                label={t("siteDetail.traffic.methodFilter")}
              />
              <SimpleSelect<string>
                value={wafAction}
                onChange={setWafAction}
                options={wafActionOptions}
                label={t("siteDetail.traffic.wafActionFilter")}
                className="w-44"
              />
            </Toolbar>
            {logs.error ? (
              <ErrorState message={logs.error} onRetry={logs.reload} />
            ) : logs.loading && logs.items.length === 0 ? (
              <TableSkeleton rows={6} />
            ) : (
              <DataTable
                ariaLabel={t("logs.listAria")}
                columns={logColumns}
                rows={logs.items}
                emptyMessage={t("logs.empty")}
              />
            )}
            <Pager
              page={logs.page}
              pageSize={logs.pageSize}
              total={logs.total}
              onPageChange={logs.setPage}
            />
          </div>
        </Tabs.Panel>

        <Tabs.Panel id="drops">
          <div className="flex flex-col gap-2">
            <Toolbar>
              <Input
                className="w-44"
                aria-label={t("siteDetail.recorded.clientIpFilter")}
                placeholder={t("common.clientIp")}
                value={clientIpInput}
                onChange={(e) => setClientIpInput(e.target.value)}
              />
              <SimpleSelect<string>
                value={source}
                onChange={setSource}
                options={dropSourceOptions}
                label={t("siteDetail.traffic.sourceFilter")}
                className="w-40"
              />
            </Toolbar>
            {drops.error ? (
              <ErrorState message={drops.error} onRetry={drops.reload} />
            ) : drops.loading && drops.items.length === 0 ? (
              <TableSkeleton rows={6} />
            ) : (
              <DataTable
                ariaLabel={t("siteDetail.traffic.drop.listAria")}
                columns={dropColumns}
                rows={drops.items}
                emptyMessage={t("siteDetail.traffic.drop.empty")}
              />
            )}
            <Pager
              page={drops.page}
              pageSize={drops.pageSize}
              total={drops.total}
              onPageChange={drops.setPage}
            />
          </div>
        </Tabs.Panel>
      </Tabs>

      {/* 访问日志详情 */}
      <DetailDrawer
        state={detailState}
        title={
          detail
            ? t("siteDetail.traffic.detail.title", { id: detail.id })
            : t("siteDetail.traffic.detail.fallback")
        }
        description={detail ? `${detail.method} ${detail.host}${detail.path}` : undefined}
        width="w-[640px]"
      >
        {detailFull.loading && !detailFull.data ? (
          <TableSkeleton rows={6} />
        ) : detailFull.error ? (
          <ErrorState message={detailFull.error} onRetry={detailFull.reload} />
        ) : detailData ? (
          <div className="flex flex-col gap-3">
            <FieldGroup
              title={t("siteDetail.traffic.detail.base")}
              row={detailData}
              fields={BASE_FIELDS}
            />
            <FieldGroup
              title={t("siteDetail.traffic.detail.tls")}
              row={detailData}
              fields={TLS_FIELDS}
            />
            <FieldGroup
              title={t("siteDetail.traffic.detail.fusion")}
              row={detailData}
              fields={FUSION_FIELDS}
            />
            <FieldGroup
              title={t("siteDetail.traffic.detail.payload")}
              row={detailData}
              fields={PAYLOAD_FIELDS}
            />
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
