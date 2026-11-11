"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  Input,
  Modal,
  ScrollShadow,
  Table,
  Tabs,
  TextArea,
  useOverlayState,
} from "@heroui/react";
import { Activity, ChevronDown, ChevronUp, Flag, RefreshCw, Route, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api/client";
import { useApi, useDebounced, useList } from "@/lib/hooks/use-api";
import type {
  FalsePositive,
  RequestTrace,
  SecurityEvent,
  SecurityEventRequest,
  SecurityEventStats,
  TimelineBucket,
} from "@/lib/types/event";
import {
  CardSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
  Pager,
  SearchInput,
  SimpleSelect,
  StatCard,
  StatusChip,
  TableSkeleton,
  Toolbar,
  type StatusTone,
} from "@/components/ui/primitives";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import { DataTable } from "@/components/ui/data-table";
import { formatDateTime, truncate } from "@/lib/utils/format";
import { showError, showSuccess } from "@/components/ui/toast-host";
import { useI18n, useNumberFormat, type MessageKey } from "@/i18n";
import { ActiveFilterBar, type ActiveFilter } from "@/components/ui/active-filter-bar";

/* ---------- 常量与选项 ---------- */

type ActionFilter = "all" | "block" | "drop" | "captcha" | "challenge" | "observe" | "allow";

const ACTION_FILTER_KEYS: Record<ActionFilter, MessageKey> = {
  all: "action.filterAll",
  block: "action.block",
  drop: "action.drop",
  captcha: "action.captcha",
  challenge: "action.challenge",
  observe: "action.observe",
  allow: "action.allow",
};

const ACTION_FILTERS: ActionFilter[] = ["all", "block", "drop", "captcha", "challenge", "observe", "allow"];

/** WAF action → 展示标签与语义色 */
const ACTION_META: Record<string, { labelKey: MessageKey; tone: StatusTone }> = {
  block: { labelKey: "action.block", tone: "danger" },
  drop: { labelKey: "action.drop", tone: "danger" },
  captcha: { labelKey: "action.captcha", tone: "warning" },
  challenge: { labelKey: "action.challenge", tone: "warning" },
  observe: { labelKey: "action.observe", tone: "info" },
  allow: { labelKey: "action.allow", tone: "success" },
};

type CategoryFilter = "all" | "cve" | "sqli" | "xss" | "protocol" | "bot" | "scanner" | "other";

const CATEGORY_KEYS: Record<CategoryFilter, MessageKey> = {
  all: "events.category.all",
  cve: "events.category.cve",
  sqli: "events.category.sqli",
  xss: "events.category.xss",
  protocol: "events.category.protocol",
  bot: "events.category.bot",
  scanner: "events.category.scanner",
  other: "events.category.other",
};

const CATEGORIES: CategoryFilter[] = ["all", "cve", "sqli", "xss", "protocol", "bot", "scanner", "other"];

type FpStatus = "pending" | "confirmed" | "rejected";

const FP_STATUS_KEYS: Record<FpStatus, MessageKey> = {
  pending: "events.fp.status.pending",
  confirmed: "events.fp.status.confirmed",
  rejected: "events.fp.status.rejected",
};

const FP_STATUSES: FpStatus[] = ["pending", "confirmed", "rejected"];

const FP_STATUS_TONE: Record<FpStatus, StatusTone> = {
  pending: "warning",
  confirmed: "success",
  rejected: "neutral",
};

/* ---------- 工具 ---------- */

/** datetime-local 值 → RFC3339（UTC）；空或无效返回 undefined（不作为查询条件） */
function toIso(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** 聚合 TOP 榜卡片：类别 / 来源 IP / 目标路径 / 命中规则 */
function TopListCard({
  title,
  items,
}: {
  title: string;
  items: { label: string; count: number }[];
}) {
  const { t } = useI18n();
  const formatNumber = useNumberFormat();
  return (
    <div className="bg-surface rounded-xl border border-separator p-3">
      <div className="text-muted mb-2 text-xs font-medium">{title}</div>
      {items.length === 0 ? (
        <div className="text-muted text-xs">{t("common.empty")}</div>
      ) : (
        <div className="flex flex-col gap-1">
          {items.slice(0, 5).map((it, i) => (
            <div key={`${it.label}-${i}`} className="flex items-center justify-between gap-2 text-xs">
              <span className="min-w-0 flex-1 truncate font-mono" title={it.label}>
                {it.label || "-"}
              </span>
              <span className="text-muted tabular shrink-0">{formatNumber(it.count)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function wafActionTone(action: string): StatusTone {
  return ACTION_META[action]?.tone ?? "neutral";
}

function ActionChip({ action }: { action: string }) {
  const { t } = useI18n();
  const meta = ACTION_META[action];
  return <StatusChip tone={meta?.tone ?? "neutral"}>{meta ? t(meta.labelKey) : action}</StatusChip>;
}

/** 详情字段值渲染：对象 → 滚动 pre；其余原样展示 */
function DetailValue({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted">-</span>;
  }
  if (typeof value === "object") {
    return (
      <ScrollShadow className="max-h-48">
        <pre className="text-xs break-all whitespace-pre-wrap">{JSON.stringify(value, null, 2)}</pre>
      </ScrollShadow>
    );
  }
  return <span className="break-all">{String(value)}</span>;
}

/** 详情字段行：时间类字段（*_at）本地化展示 */
function DetailField({ label, value }: { label: string; value: unknown }) {
  const isTime = typeof value === "string" && value !== "" && /_at$/.test(label);
  return (
    <DetailRow label={label}>
      {isTime ? formatDateTime(value as string) : <DetailValue value={value} />}
    </DetailRow>
  );
}

/* ---------- 24 小时事件时间线（纯 CSS 条形图） ---------- */

function TimelineBars({ buckets }: { buckets: TimelineBucket[] }) {
  const { t } = useI18n();
  if (!buckets || buckets.length === 0) {
    return <div className="text-muted py-6 text-center text-sm">{t("events.timeline.empty")}</div>;
  }
  const max = Math.max(...buckets.map((b) => b.count ?? 0), 1);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex h-32 items-end gap-1">
        {buckets.map((b, i) => (
          <div
            key={i}
            className="group relative flex h-full flex-1 items-end"
            title={t("events.timeline.tooltip", {
              time: formatDateTime(b.bucket),
              count: b.count ?? 0,
            })}
          >
            <div
              className="bg-accent w-full rounded-t transition-all group-hover:opacity-80"
              style={{ height: `${Math.max(2, ((b.count ?? 0) / max) * 100)}%` }}
            />
          </div>
        ))}
      </div>
      <div className="text-muted flex items-center justify-between text-xs">
        <span>{formatDateTime(buckets[0]?.bucket)}</span>
        <span>{t("events.timeline.peak", { count: max })}</span>
        <span>{formatDateTime(buckets[buckets.length - 1]?.bucket)}</span>
      </div>
    </div>
  );
}

/* ---------- 误报反馈面板 ---------- */

function FalsePositivesPanel() {
  const { t } = useI18n();
  const [savingId, setSavingId] = useState<number | null>(null);
  const { data, loading, error, reload } = useApi<FalsePositive[]>(
    useCallback(async () => {
      const d = await api.get<{ items?: FalsePositive[] } | FalsePositive[]>("/false-positives");
      return Array.isArray(d) ? d : (d.items ?? []);
    }, []),
  );
  const items = data ?? [];

  /** 更新误报处理状态 */
  async function updateStatus(id: number, status: FpStatus) {
    setSavingId(id);
    try {
      await api.post(`/false-positives/${id}/status`, { status });
      showSuccess(t("events.fp.statusUpdated"));
      void reload();
    } catch (e) {
      showError(t("events.fp.updateFailed"), e instanceof Error ? e.message : String(e));
    } finally {
      setSavingId(null);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && items.length === 0 ? (
        <div className="bg-surface rounded-xl border border-separator p-4">
          <TableSkeleton rows={6} />
        </div>
      ) : (
        <div className="bg-surface overflow-x-auto rounded-xl border border-separator">
          <Table>
            <Table.Content aria-label={t("events.fp.listTitle")}>
            <Table.Header>
              <Table.Column isRowHeader>{t("events.fp.col.id")}</Table.Column>
              <Table.Column>{t("events.fp.col.eventId")}</Table.Column>
              <Table.Column>{t("events.fp.col.note")}</Table.Column>
              <Table.Column>{t("events.fp.col.status")}</Table.Column>
              <Table.Column>{t("events.fp.col.createdAt")}</Table.Column>
              <Table.Column>{t("events.fp.col.updatedAt")}</Table.Column>
              <Table.Column>{t("events.fp.col.updateStatus")}</Table.Column>
            </Table.Header>
            <Table.Body items={items} renderEmptyState={() => <EmptyState message={t("events.fp.empty")} />}>
              {(row) => (
                <Table.Row id={`fp-${row.id}`}>
                  <Table.Cell>
                    <span className="tabular text-xs">{row.id}</span>
                  </Table.Cell>
                  <Table.Cell>
                    <span className="tabular text-xs">{row.security_event_id}</span>
                  </Table.Cell>
                  <Table.Cell>
                    <span className="block max-w-[280px] truncate text-xs" title={row.note}>
                      {truncate(row.note, 40)}
                    </span>
                  </Table.Cell>
                  <Table.Cell>
                    <StatusChip tone={FP_STATUS_TONE[row.status] ?? "neutral"}>
                      {FP_STATUS_KEYS[row.status] ? t(FP_STATUS_KEYS[row.status]) : row.status}
                    </StatusChip>
                  </Table.Cell>
                  <Table.Cell>
                    <span className="text-xs whitespace-nowrap">{formatDateTime(row.created_at)}</span>
                  </Table.Cell>
                  <Table.Cell>
                    <span className="text-xs whitespace-nowrap">{formatDateTime(row.updated_at)}</span>
                  </Table.Cell>
                  <Table.Cell>
                    <SimpleSelect
                      className="w-32"
                      value={row.status}
                      onChange={(v) => {
                        if (v !== row.status) void updateStatus(row.id, v);
                      }}
                      options={FP_STATUSES.map((s) => ({ key: s, label: t(FP_STATUS_KEYS[s]) }))}
                      label={t("events.fp.col.updateStatus")}
                    />
                  </Table.Cell>
                </Table.Row>
              )}
            </Table.Body>
            </Table.Content>
          </Table>
        </div>
      )}
    </div>
  );
}

/* ---------- 主页面 ---------- */

/** 高级筛选输入（与后端 securityEventFilterFromQuery 的参数一一对应） */
type AdvancedFilters = {
  requestId: string;
  phase: string;
  host: string;
  path: string;
  queryString: string;
  ruleIdStr: string;
  tlsVersion: string;
  tlsSni: string;
  tlsAlpn: string;
  tlsJa3: string;
  tlsJa4: string;
  headerOrder: string;
};

const EMPTY_ADVANCED_FILTERS: AdvancedFilters = {
  requestId: "",
  phase: "",
  host: "",
  path: "",
  queryString: "",
  ruleIdStr: "",
  tlsVersion: "",
  tlsSni: "",
  tlsAlpn: "",
  tlsJa3: "",
  tlsJa4: "",
  headerOrder: "",
};

/** 把高级筛选输入转成查询参数；空值字段省略 */
function advancedQuery(f: AdvancedFilters): Record<string, string | undefined> {
  return {
    request_id: f.requestId.trim() || undefined,
    phase: f.phase.trim() || undefined,
    host: f.host.trim() || undefined,
    path: f.path.trim() || undefined,
    query_string: f.queryString.trim() || undefined,
    rule_id_str: f.ruleIdStr.trim() || undefined,
    tls_version: f.tlsVersion.trim() || undefined,
    tls_sni: f.tlsSni.trim() || undefined,
    tls_alpn: f.tlsAlpn.trim() || undefined,
    tls_ja3_hash: f.tlsJa3.trim() || undefined,
    tls_ja4: f.tlsJa4.trim() || undefined,
    header_order: f.headerOrder.trim() || undefined,
  };
}

/** 高级筛选折叠面板：事件列表与请求聚合共用同一份筛选状态 */
function AdvancedFiltersPanel({
  open,
  filters,
  onChange,
}: {
  open: boolean;
  filters: AdvancedFilters;
  onChange: (patch: Partial<AdvancedFilters>) => void;
}) {
  const { t } = useI18n();
  if (!open) return null;
  const fields: { key: keyof AdvancedFilters; label: string; placeholder: string }[] = [
    { key: "requestId", label: t("common.requestId"), placeholder: "request_id" },
    { key: "phase", label: t("events.filter.phase"), placeholder: t("events.placeholder.phase") },
    { key: "host", label: t("common.host"), placeholder: t("logs.placeholder.host") },
    { key: "path", label: t("common.path"), placeholder: t("logs.placeholder.path") },
    { key: "queryString", label: t("events.filter.query"), placeholder: "query_string" },
    { key: "ruleIdStr", label: t("events.filter.ruleId"), placeholder: t("events.placeholder.ruleId") },
    { key: "tlsVersion", label: t("events.filter.tlsVersion"), placeholder: t("logs.placeholder.tlsVersion") },
    { key: "tlsSni", label: "TLS SNI", placeholder: "tls_sni" },
    { key: "tlsAlpn", label: "TLS ALPN", placeholder: t("logs.placeholder.tlsAlpn") },
    { key: "tlsJa3", label: "JA3", placeholder: "tls_ja3_hash" },
    { key: "tlsJa4", label: "JA4", placeholder: "tls_ja4" },
    { key: "headerOrder", label: t("events.filter.headerOrder"), placeholder: "header_order" },
  ];
  return (
    <div className="bg-surface mb-3 grid gap-2 rounded-xl border border-separator p-3 md:grid-cols-3 xl:grid-cols-4">
      {fields.map((f) => (
        <Input
          key={f.key}
          aria-label={`${f.label} ${t("common.filter")}`}
          placeholder={f.placeholder}
          value={filters[f.key]}
          onChange={(e) => onChange({ [f.key]: e.target.value })}
        />
      ))}
    </div>
  );
}

export default function SecurityEventsClient() {
  const { t } = useI18n();
  const formatNumber = useNumberFormat();
  /* 列表筛选状态 */
  const [qInput, setQInput] = useState("");
  const q = useDebounced(qInput, 350);
  const [action, setAction] = useState<ActionFilter>("all");
  const [category, setCategory] = useState<CategoryFilter>("all");
  const [clientIp, setClientIp] = useState("");
  const [sinceInput, setSinceInput] = useState("");
  const [untilInput, setUntilInput] = useState("");

  /* 高级筛选：事件列表与请求聚合共用 */
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [filters, setFilters] = useState<AdvancedFilters>(EMPTY_ADVANCED_FILTERS);
  const setFilter = useCallback(
    (patch: Partial<AdvancedFilters>) => setFilters((prev) => ({ ...prev, ...patch })),
    [],
  );
  const debouncedAdvanced = useDebounced(advancedQuery(filters), 350);

  const list = useList<SecurityEvent>("/security-events", {
    q: q || undefined,
    action: action === "all" ? undefined : action,
    category: category === "all" ? undefined : category,
    client_ip: clientIp || undefined,
    since: toIso(sinceInput),
    until: toIso(untilInput),
    ...debouncedAdvanced,
  });

  /* 请求级聚合视图：按 request_id 去重，total 为请求数 */
  const requests = useList<SecurityEventRequest>("/security-events/requests", {
    q: q || undefined,
    action: action === "all" ? undefined : action,
    category: category === "all" ? undefined : category,
    client_ip: clientIp || undefined,
    since: toIso(sinceInput),
    until: toIso(untilInput),
    ...debouncedAdvanced,
  });

  /* 防抖筛选变化后回到第一页，避免停留在越界页码 */
  useEffect(() => {
    list.setPage(1);
    requests.setPage(1);
  }, [
    q,
    action,
    category,
    clientIp,
    sinceInput,
    untilInput,
    debouncedAdvanced,
    list.setPage,
    requests.setPage,
  ]);

  /* 统计与时间线 */
  const {
    data: stats,
    loading: statsLoading,
    reload: reloadStats,
  } = useApi<SecurityEventStats>(useCallback(() => api.get<SecurityEventStats>("/security-events/stats"), []));
  const {
    data: timeline,
    loading: timelineLoading,
    reload: reloadTimeline,
  } = useApi<{ buckets?: TimelineBucket[] }>(
    useCallback(
      () => api.get<{ buckets?: TimelineBucket[] }>("/security-events/timeline", { hours: 24 }),
      [],
    ),
  );

  /* 事件详情抽屉 */
  const [detail, setDetail] = useState<SecurityEvent | null>(null);
  const [fpNote, setFpNote] = useState("");
  const [fpSaving, setFpSaving] = useState(false);
  const detailState = useOverlayState();
  const {
    data: detailFull,
    loading: detailLoading,
    error: detailError,
    reload: reloadDetail,
  } = useApi<SecurityEvent>(
    useCallback(() => api.get<SecurityEvent>(`/security-events/${detail!.id}`), [detail?.id]),
    [detail?.id],
    { enabled: detail !== null },
  );
  const detailData = detailFull ?? detail;
  const detailEntries = detailData ? Object.entries(detailData) : [];

  /* 请求追踪弹窗 */
  const [traceId, setTraceId] = useState("");
  const [traceInput, setTraceInput] = useState("");
  const traceState = useOverlayState();
  const {
    data: trace,
    loading: traceLoading,
    error: traceError,
    reload: traceReload,
  } = useApi<RequestTrace>(
    useCallback(() => api.get<RequestTrace>(`/request/${traceId}`), [traceId]),
    [traceId],
    { enabled: traceId !== "" },
  );

  function openDetail(ev: SecurityEvent) {
    setDetail(ev);
    setFpNote("");
    detailState.open();
  }

  function openTrace(id: string) {
    setTraceId(id);
    traceState.open();
  }

  /** 在事件详情内提交误报 */
  async function submitFalsePositive() {
    if (!detail || !fpNote.trim()) return;
    setFpSaving(true);
    try {
      await api.post("/false-positives", { security_event_id: detail.id, note: fpNote.trim() });
      showSuccess(t("events.fp.submitted"));
      setFpNote("");
    } catch (e) {
      showError(t("events.fp.failed"), e instanceof Error ? e.message : String(e));
    } finally {
      setFpSaving(false);
    }
  }

  function refreshAll() {
    void list.reload();
    void requests.reload();
    void reloadStats();
    void reloadTimeline();
  }

  /**
   * 已激活筛选条件清单（Cloudflare 风格可见 chips）。
   * 合并简单筛选 + 高级筛选；只在有值时展示短标签。
   * 枚举筛选使用当前本地化标签（与下拉一致）。
   */
  const activeFilters = useMemo<ActiveFilter[]>(() => {
    const items: ActiveFilter[] = [];
    const add = (key: string, label: string, value: string) => {
      if (value && value.trim() !== "") {
        items.push({ key, label, value: value.trim() });
      }
    };

    add("q", t("events.cond.q"), q.trim());
    if (action !== "all") {
      add("action", t("events.cond.action"), t(ACTION_FILTER_KEYS[action]));
    }
    if (category !== "all") {
      add("category", t("events.cond.category"), t(CATEGORY_KEYS[category]));
    }
    add("clientIp", t("events.cond.clientIp"), clientIp.trim());
    add("since", t("events.cond.since"), sinceInput);
    add("until", t("events.cond.until"), untilInput);

    // 高级筛选（与后端 securityEventFilterFromQuery 字段对应）
    add("requestId", t("events.cond.requestId"), filters.requestId.trim());
    add("phase", t("events.cond.phase"), filters.phase.trim());
    add("host", t("events.cond.host"), filters.host.trim());
    add("path", t("events.cond.path"), filters.path.trim());
    add("queryString", t("events.cond.query"), filters.queryString.trim());
    add("ruleIdStr", t("events.cond.ruleId"), filters.ruleIdStr.trim());
    add("tlsVersion", t("events.cond.tlsVersion"), filters.tlsVersion.trim());
    add("tlsSni", t("events.cond.tlsSni"), filters.tlsSni.trim());
    add("tlsAlpn", t("events.cond.tlsAlpn"), filters.tlsAlpn.trim());
    add("tlsJa3", t("events.cond.ja3"), filters.tlsJa3.trim());
    add("tlsJa4", t("events.cond.ja4"), filters.tlsJa4.trim());
    add("headerOrder", t("events.cond.headerOrder"), filters.headerOrder.trim());

    return items;
  }, [
    t,
    q,
    action,
    category,
    clientIp,
    sinceInput,
    untilInput,
    filters,
  ]);

  /** 单个筛选的清除器表：键与 activeFilters 的 key 一一对应。 */
  const FILTER_RESETTERS: Record<string, () => void> = {
    q: () => setQInput(""),
    action: () => setAction("all"),
    category: () => setCategory("all"),
    clientIp: () => setClientIp(""),
    since: () => setSinceInput(""),
    until: () => setUntilInput(""),
    // 高级
    requestId: () => setFilter({ requestId: "" }),
    phase: () => setFilter({ phase: "" }),
    host: () => setFilter({ host: "" }),
    path: () => setFilter({ path: "" }),
    queryString: () => setFilter({ queryString: "" }),
    ruleIdStr: () => setFilter({ ruleIdStr: "" }),
    tlsVersion: () => setFilter({ tlsVersion: "" }),
    tlsSni: () => setFilter({ tlsSni: "" }),
    tlsAlpn: () => setFilter({ tlsAlpn: "" }),
    tlsJa3: () => setFilter({ tlsJa3: "" }),
    tlsJa4: () => setFilter({ tlsJa4: "" }),
    headerOrder: () => setFilter({ headerOrder: "" }),
  };

  function clearFilter(key: string) {
    FILTER_RESETTERS[key]?.();
  }

  /** 一键清除全部筛选；高级面板开关独立，不随清除变化。 */
  function clearAllFilters() {
    Object.values(FILTER_RESETTERS).forEach((reset) => reset());
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t("events.title")}
        description={t("events.description")}
        actions={
          <Button size="sm" variant="ghost" onPress={refreshAll}>
            <RefreshCw className="size-3.5" /> {t("common.refresh")}
          </Button>
        }
      />

      <Tabs aria-label={t("events.title")}>
        <Tabs.List aria-label={t("events.title")}>
          <Tabs.Tab id="events">
            <span className="flex items-center gap-1.5">
              <ShieldAlert className="size-4" /> {t("events.tab.events")}
            </span>
          </Tabs.Tab>
          <Tabs.Tab id="requests">
            <span className="flex items-center gap-1.5">
              <Route className="size-4" /> {t("events.tab.requests")}
            </span>
          </Tabs.Tab>
          <Tabs.Tab id="fp">
            <span className="flex items-center gap-1.5">
              <Flag className="size-4" /> {t("events.tab.fp")}
            </span>
          </Tabs.Tab>
        </Tabs.List>

        {/* 事件列表面板 */}
        <Tabs.Panel id="events">
          <div className="flex flex-col gap-4">
            {/* 统计条：真实聚合计数 + TOP 排行 */}
            {statsLoading && !stats ? (
              <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
                {Array.from({ length: 5 }).map((_, i) => (
                  <CardSkeleton key={i} height="h-24" />
                ))}
              </div>
            ) : stats ? (
              <div className="flex flex-col gap-4">
                <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
                  <StatCard label={t("events.stats.total")} value={formatNumber(stats.total)} />
                  <StatCard label={t("events.stats.intercepts")} value={formatNumber(stats.intercepts)} tone="danger" />
                  <StatCard label={t("events.stats.observes")} value={formatNumber(stats.observes)} tone="warning" />
                  <StatCard label={t("events.stats.challenges")} value={formatNumber(stats.challenges)} tone="info" />
                  <StatCard label={t("events.stats.requests")} value={formatNumber(stats.requests)} />
                </div>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
                  <TopListCard
                    title={t("events.top.categories")}
                    items={(stats.categories ?? []).map((c) => ({ label: c.category, count: c.count }))}
                  />
                  <TopListCard
                    title={t("events.top.ips")}
                    items={(stats.top_ips ?? []).map((i) => ({ label: i.client_ip, count: i.count }))}
                  />
                  <TopListCard
                    title={t("events.top.paths")}
                    items={(stats.top_paths ?? []).map((p) => ({ label: p.path, count: p.count }))}
                  />
                  <TopListCard
                    title={t("events.top.rules")}
                    items={(stats.top_rules ?? []).map((r) => ({ label: r.rule_id_str, count: r.count }))}
                  />
                </div>
              </div>
            ) : (
              <div className="text-muted py-2 text-center text-sm">{t("events.noStats")}</div>
            )}

            {/* 24 小时时间线 */}
            <section>
              <h2 className="text-muted mb-2 flex items-center gap-1.5 text-sm font-medium">
                <Activity className="size-4" /> {t("events.timeline.title")}
              </h2>
              <div className="bg-surface rounded-xl border border-separator p-4">
                {timelineLoading && !timeline ? (
                  <TableSkeleton rows={3} />
                ) : (
                  <TimelineBars buckets={timeline?.buckets ?? []} />
                )}
              </div>
            </section>

            {/* 工具栏 */}
            <Toolbar>
              <SearchInput value={qInput} onChange={setQInput} placeholder={t("events.search")} />
              <SimpleSelect
                value={action}
                onChange={setAction}
                options={ACTION_FILTERS.map((a) => ({ key: a, label: t(ACTION_FILTER_KEYS[a]) }))}
                label={t("events.filter.action")}
              />
              <SimpleSelect
                value={category}
                onChange={setCategory}
                options={CATEGORIES.map((c) => ({ key: c, label: t(CATEGORY_KEYS[c]) }))}
                label={t("events.filter.category")}
              />
              <Input
                className="w-40"
                aria-label={t("events.filter.clientIp")}
                placeholder={t("common.clientIp")}
                value={clientIp}
                onChange={(e) => setClientIp(e.target.value)}
              />
              <Button
                size="sm"
                variant="ghost"
                onPress={() => setAdvancedOpen((v) => !v)}
              >
                {advancedOpen ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
                {t("events.filter.advanced")}
              </Button>
            </Toolbar>
            <AdvancedFiltersPanel open={advancedOpen} filters={filters} onChange={setFilter} />

            <ActiveFilterBar
              filters={activeFilters}
              onClear={clearFilter}
              onClearAll={clearAllFilters}
            />

            {/* 事件列表 */}
            {list.error ? (
              <ErrorState message={list.error} onRetry={list.reload} />
            ) : list.loading && list.items.length === 0 ? (
              <div className="bg-surface rounded-xl border border-separator p-4">
                <TableSkeleton rows={8} />
              </div>
            ) : (
              <div className="bg-surface overflow-x-auto rounded-xl border border-separator">
                <Table>
                  <Table.Content aria-label={t("events.title")}>
                  <Table.Header>
                    <Table.Column isRowHeader>{t("events.col.time")}</Table.Column>
                    <Table.Column>{t("events.col.clientIp")}</Table.Column>
                    <Table.Column>{t("events.col.host")}</Table.Column>
                    <Table.Column>{t("events.col.request")}</Table.Column>
                    <Table.Column>{t("events.col.action")}</Table.Column>
                    <Table.Column>{t("events.col.category")}</Table.Column>
                    <Table.Column>{t("events.col.rule")}</Table.Column>
                    <Table.Column>{t("events.col.actions")}</Table.Column>
                  </Table.Header>
                  <Table.Body
                    items={list.items}
                    renderEmptyState={() => <EmptyState message={t("events.empty")} />}
                  >
                    {(row) => (
                      <Table.Row id={`se-${row.id}`}>
                        <Table.Cell>
                          <span className="text-xs whitespace-nowrap">{formatDateTime(row.created_at)}</span>
                        </Table.Cell>
                        <Table.Cell>
                          <span className="font-mono text-xs">{row.client_ip}</span>
                        </Table.Cell>
                        <Table.Cell>
                          <span className="text-xs">{row.host}</span>
                        </Table.Cell>
                        <Table.Cell>
                          <span
                            className="block max-w-[240px] truncate font-mono text-xs"
                            title={`${row.method} ${row.host}${row.path}`}
                          >
                            {row.method} {truncate(row.path, 28)}
                          </span>
                        </Table.Cell>
                        <Table.Cell>
                          <ActionChip action={row.action} />
                        </Table.Cell>
                        <Table.Cell>
                          <span className="text-xs">{row.category}</span>
                        </Table.Cell>
                        <Table.Cell>
                          <span className="font-mono text-xs">{row.rule_id}</span>
                        </Table.Cell>
                        <Table.Cell>
                          <Button size="sm" variant="outline" onPress={() => openDetail(row)}>
                            {t("common.detail")}
                          </Button>
                        </Table.Cell>
                      </Table.Row>
                    )}
                  </Table.Body>
                  </Table.Content>
                </Table>
              </div>
            )}
            <Pager page={list.page} pageSize={list.pageSize} total={list.total} onPageChange={list.setPage} />
          </div>
        </Tabs.Panel>

        {/* 请求聚合面板：按 request_id 去重，一行代表一次请求 */}
        <Tabs.Panel id="requests">
          <div className="flex flex-col gap-4">
            <Toolbar>
              <SearchInput value={qInput} onChange={setQInput} placeholder={t("events.search")} />
              <SimpleSelect
                value={action}
                onChange={setAction}
                options={ACTION_FILTERS.map((a) => ({ key: a, label: t(ACTION_FILTER_KEYS[a]) }))}
                label={t("events.filter.action")}
              />
              <SimpleSelect
                value={category}
                onChange={setCategory}
                options={CATEGORIES.map((c) => ({ key: c, label: t(CATEGORY_KEYS[c]) }))}
                label={t("events.filter.category")}
              />
              <Input
                className="w-40"
                aria-label={t("events.filter.clientIp")}
                placeholder={t("common.clientIp")}
                value={clientIp}
                onChange={(e) => setClientIp(e.target.value)}
              />
              <Input
                className="w-56"
                type="datetime-local"
                aria-label={t("common.startTime")}
                value={sinceInput}
                onChange={(e) => setSinceInput(e.target.value)}
              />
              <Input
                className="w-56"
                type="datetime-local"
                aria-label={t("common.endTime")}
                value={untilInput}
                onChange={(e) => setUntilInput(e.target.value)}
              />
            </Toolbar>
 
            <ActiveFilterBar
              filters={activeFilters}
              onClear={clearFilter}
              onClearAll={clearAllFilters}
            />
 
            {requests.error ? (
              <ErrorState message={requests.error} onRetry={requests.reload} />
            ) : requests.loading && requests.items.length === 0 ? (
              <div className="bg-surface rounded-xl border border-separator p-4">
                <TableSkeleton rows={8} />
              </div>
            ) : (
              <DataTable<SecurityEventRequest & { id: string }>
                ariaLabel={t("events.tab.requests")}
                columns={[
                  {
                    header: t("events.requests.col.requestId"),
                    render: (row) => (
                      <span className="block max-w-[280px] truncate font-mono text-xs" title={row.request_id}>
                        {row.request_id}
                      </span>
                    ),
                  },
                  {
                    header: t("events.requests.col.eventCount"),
                    render: (row) => <span className="tabular text-sm font-medium">{row.event_count}</span>,
                  },
                  {
                    header: t("events.requests.col.lastSeen"),
                    render: (row) => (
                      <span className="text-xs whitespace-nowrap">{formatDateTime(row.last_seen)}</span>
                    ),
                  },
                  {
                    header: t("events.requests.col.actions"),
                    render: (row) => (
                      <Button
                        size="sm"
                        variant="outline"
                        onPress={() => {
                          setTraceInput(row.request_id);
                          openTrace(row.request_id);
                        }}
                      >
                        {t("events.requests.trace")}
                      </Button>
                    ),
                  },
                ]}
                rows={requests.items.map((r) => ({ ...r, id: r.request_id }))}
                emptyMessage={t("events.requests.empty")}
              />
            )}
            <Pager
              page={requests.page}
              pageSize={requests.pageSize}
              total={requests.total}
              onPageChange={requests.setPage}
            />
          </div>
        </Tabs.Panel>

        {/* 误报反馈面板 */}
        <Tabs.Panel id="fp">
          <FalsePositivesPanel />
        </Tabs.Panel>
      </Tabs>

      {/* 事件详情抽屉 */}
      <DetailDrawer
        state={detailState}
        title={detail ? t("events.detail.title", { id: detail.id }) : t("events.detail.fallback")}
        description={detail ? `${detail.method} ${detail.host}${detail.path}` : undefined}
        width="w-[640px]"
        footer={
          <Button
            size="sm"
            variant="outline"
            isDisabled={!detailData?.request_id}
            onPress={() => {
              if (detailData?.request_id) openTrace(String(detailData.request_id));
            }}
          >
            <Route className="size-3.5" /> {t("events.trace.request")}
          </Button>
        }
      >
        {detailLoading && !detailFull ? (
          <TableSkeleton rows={6} />
        ) : detailError ? (
          <ErrorState message={detailError} onRetry={reloadDetail} />
        ) : detailData ? (
          <div className="flex flex-col gap-4">
            <div>
              {detailEntries.map(([key, value]) => (
                <DetailField key={key} label={key} value={value} />
              ))}
            </div>
            {/* 误报提交 */}
            <div className="bg-surface rounded-xl border border-separator p-3">
              <div className="mb-2 text-sm font-medium">{t("events.fp.formTitle")}</div>
              <TextArea
                aria-label={t("events.fp.col.note")}
                placeholder={t("events.fp.placeholder")}
                value={fpNote}
                onChange={(e) => setFpNote(e.target.value)}
                className="mb-2"
              />
              <div className="flex justify-end">
                <Button
                  size="sm"
                  variant="primary"
                  isPending={fpSaving}
                  isDisabled={!fpNote.trim()}
                  onPress={submitFalsePositive}
                >
                  {t("events.fp.submit")}
                </Button>
              </div>
            </div>
          </div>
        ) : null}
      </DetailDrawer>

      {/* 请求追踪弹窗 */}
      <Modal state={traceState}>
        <Modal.Backdrop>
          <Modal.Container size="lg">
            <Modal.Dialog>
              <Modal.Header>
                <Modal.Heading>
                  {t("events.trace.title")}
                  {traceId ? ` · ${traceId}` : ""}
                </Modal.Heading>
                <Modal.CloseTrigger />
              </Modal.Header>
              <Modal.Body>
                {traceId === "" ? null : traceLoading && !trace ? (
                  <TableSkeleton rows={6} />
                ) : traceError ? (
                  <ErrorState message={traceError} onRetry={traceReload} />
                ) : trace ? (
                  <div className="flex flex-col gap-4">
                    {/* 访问日志 */}
                    <section>
                      <h3 className="text-muted mb-2 text-sm font-medium">
                        {t("events.trace.accessLogs", { count: trace.access_logs?.length ?? 0 })}
                      </h3>
                      <div className="flex flex-col gap-1.5">
                        {(trace.access_logs ?? []).map((log) => (
                          <div
                            key={log.id}
                            className="bg-surface flex items-center gap-2 rounded-lg border border-separator px-3 py-1.5 text-xs"
                          >
                            <span className="text-muted whitespace-nowrap">{formatDateTime(log.created_at)}</span>
                            <span className="font-mono">{log.method}</span>
                            <span className="text-muted">{log.host}</span>
                            <span className="min-w-0 flex-1 truncate font-mono">
                              {log.path}
                              {log.query_string ? `?${log.query_string}` : ""}
                            </span>
                            <span
                              className={`tabular font-medium ${
                                log.status_code >= 500
                                  ? "text-danger"
                                  : log.status_code >= 400
                                    ? "text-warning"
                                    : "text-success"
                              }`}
                            >
                              {log.status_code}
                            </span>
                            <StatusChip tone={wafActionTone(log.waf_action)}>{log.waf_action}</StatusChip>
                          </div>
                        ))}
                        {(trace.access_logs ?? []).length === 0 && <EmptyState message={t("events.trace.emptyLogs")} />}
                      </div>
                    </section>
                    {/* 安全事件 */}
                    <section>
                      <h3 className="text-muted mb-2 text-sm font-medium">
                        {t("events.trace.securityEvents", { count: trace.security_events?.length ?? 0 })}
                      </h3>
                      <div className="flex flex-col gap-1.5">
                        {(trace.security_events ?? []).map((ev) => (
                          <div
                            key={ev.id}
                            className="bg-surface flex items-center gap-2 rounded-lg border border-separator px-3 py-1.5 text-xs"
                          >
                            <span className="text-muted whitespace-nowrap">{formatDateTime(ev.created_at)}</span>
                            <ActionChip action={ev.action} />
                            <span>{ev.category}</span>
                            <span className="font-mono">{ev.rule_id}</span>
                            <span className="min-w-0 flex-1 truncate">{ev.host}{ev.path}</span>
                          </div>
                        ))}
                        {(trace.security_events ?? []).length === 0 && <EmptyState message={t("events.trace.emptyEvents")} />}
                      </div>
                    </section>
                    {/* Bot 评分（结构未知，宽松 JSON 展示） */}
                    <section>
                      <h3 className="text-muted mb-2 text-sm font-medium">{t("events.trace.botScores")}</h3>
                      {(trace.bot_scores ?? []).length === 0 ? (
                        <EmptyState message={t("events.trace.emptyBotScores")} />
                      ) : (
                        <ScrollShadow className="max-h-48">
                          <pre className="text-xs break-all whitespace-pre-wrap">
                            {JSON.stringify(trace.bot_scores, null, 2)}
                          </pre>
                        </ScrollShadow>
                      )}
                    </section>
                  </div>
                ) : null}
              </Modal.Body>
              <Modal.Footer>
                <Button size="sm" variant="ghost" onPress={traceState.close}>
                  {t("common.close")}
                </Button>
              </Modal.Footer>
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>
    </div>
  );
}
