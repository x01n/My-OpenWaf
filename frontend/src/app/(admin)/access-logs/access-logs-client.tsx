"use client";

import { useCallback, useMemo, useState } from "react";
import { Button, Input, ScrollShadow, Table, Tabs, useOverlayState } from "@heroui/react";
import { ChevronDown, ChevronUp, Fingerprint, Globe, RefreshCw } from "lucide-react";
import { api } from "@/lib/api/client";
import { useApi, useDebounced, useList } from "@/lib/hooks/use-api";
import type { AccessLog } from "@/lib/types/event";
import {
  EmptyState,
  ErrorState,
  PageHeader,
  Pager,
  SearchInput,
  SimpleSelect,
  StatusChip,
  TableSkeleton,
  Toolbar,
  type StatusTone,
} from "@/components/ui/primitives";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import { ActiveFilterBar, type ActiveFilter } from "@/components/ui/active-filter-bar";
import { formatDateTime, toIso, truncate } from "@/lib/utils/format";
import { useI18n, type MessageKey } from "@/i18n";

/* ---------- 常量与选项 ---------- */

type MethodFilter = "all" | "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS";

const METHODS: MethodFilter[] = ["all", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"];

type StatusGroupFilter = "all" | "2xx" | "3xx" | "4xx" | "5xx";

const STATUS_GROUP_KEYS: Record<StatusGroupFilter, MessageKey> = {
  all: "logs.status.all",
  "2xx": "logs.status.2xx",
  "3xx": "logs.status.3xx",
  "4xx": "logs.status.4xx",
  "5xx": "logs.status.5xx",
};

const STATUS_GROUPS: StatusGroupFilter[] = ["all", "2xx", "3xx", "4xx", "5xx"];

/** WAF action → 展示标签与语义色 */
const ACTION_META: Record<string, { labelKey: MessageKey; tone: StatusTone }> = {
  block: { labelKey: "action.block", tone: "danger" },
  drop: { labelKey: "action.drop", tone: "danger" },
  captcha: { labelKey: "action.captcha", tone: "warning" },
  challenge: { labelKey: "action.challenge", tone: "warning" },
  observe: { labelKey: "action.observe", tone: "info" },
  allow: { labelKey: "action.allow", tone: "success" },
};

/* ---------- 工具 ---------- */

function wafActionTone(action: string): StatusTone {
  return ACTION_META[action]?.tone ?? "neutral";
}

/** 状态码语义色：≥500 danger / ≥400 warning / 其他 success */
function statusTone(code: number): StatusTone {
  return code >= 500 ? "danger" : code >= 400 ? "warning" : "success";
}

function statusTextClass(code: number): string {
  return code >= 500 ? "text-danger" : code >= 400 ? "text-warning" : "text-success";
}

function ActionChip({ action }: { action: string }) {
  const { t } = useI18n();
  const meta = ACTION_META[action];
  return <StatusChip tone={meta?.tone ?? "neutral"}>{meta ? t(meta.labelKey) : action}</StatusChip>;
}

/** TLS 指纹相关字段判定（宽松匹配键名） */
function isTlsKey(key: string): boolean {
  return /tls|ja3|ja4|fingerprint/i.test(key);
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

/** 详情字段行：时间类字段（*_at / last_seen）本地化展示 */
function DetailField({ label, value }: { label: string; value: unknown }) {
  const isTime = typeof value === "string" && value !== "" && /(_at|last_seen)$/.test(label);
  return (
    <DetailRow label={label}>
      {isTime ? formatDateTime(value as string) : <DetailValue value={value} />}
    </DetailRow>
  );
}

/* ---------- TLS 指纹面板（字段从响应推断，宽松渲染） ---------- */

type FingerprintRow = Record<string, unknown>;

/** 列名含时间语义时本地化展示 */
function renderFpCell(row: FingerprintRow, col: string): string {
  const v = row[col];
  if (v === null || v === undefined || v === "") return "-";
  if (typeof v === "object") return truncate(JSON.stringify(v), 40);
  if (typeof v === "string" && /(_at|last_seen|^time$)/.test(col)) return formatDateTime(v);
  return truncate(String(v), 48);
}

function FingerprintsPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<{ items?: FingerprintRow[] } | FingerprintRow[]>(
    useCallback(() => api.get<{ items?: FingerprintRow[] } | FingerprintRow[]>("/fingerprints"), []),
  );
  const rows = data ? (Array.isArray(data) ? data : (data.items ?? [])) : [];
  const columns = rows.length > 0 ? Object.keys(rows[0]) : [];

  return (
    <div className="flex flex-col gap-3">
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading && rows.length === 0 ? (
        <div className="bg-surface rounded-xl border border-separator p-4">
          <TableSkeleton rows={6} />
        </div>
      ) : (
        <div className="bg-surface overflow-x-auto rounded-xl border border-separator">
          <Table>
            <Table.Content aria-label={t("logs.tls.listAria")}>
            <Table.Header>
              {columns.map((col, i) => (
                <Table.Column key={col} isRowHeader={i === 0}>{col}</Table.Column>
              ))}
            </Table.Header>
            <Table.Body renderEmptyState={() => <EmptyState message={t("logs.tls.empty")} />}>
              {rows.map((row, i) => (
                <Table.Row key={i} id={`fp-${i}`}>
                  {columns.map((col) => (
                    <Table.Cell key={col}>
                      <span
                        className={`text-xs ${typeof row[col] === "number" ? "tabular" : ""}`}
                        title={typeof row[col] === "string" ? (row[col] as string) : undefined}
                      >
                        {renderFpCell(row, col)}
                      </span>
                    </Table.Cell>
                  ))}
                </Table.Row>
              ))}
            </Table.Body>
            </Table.Content>
          </Table>
        </div>
      )}
    </div>
  );
}

/* ---------- 主页面 ---------- */

export default function AccessLogsClient() {
  const { t } = useI18n();
  /* 列表筛选状态 */
  const [qInput, setQInput] = useState("");
  const q = useDebounced(qInput, 350);
  const [method, setMethod] = useState<MethodFilter>("all");
  const [statusGroup, setStatusGroup] = useState<StatusGroupFilter>("all");
  const [clientIp, setClientIp] = useState("");

  /* 高级筛选状态：覆盖后端 AccessLogFilter 的其余字段 */
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [requestId, setRequestId] = useState("");
  const [host, setHost] = useState("");
  const [path, setPath] = useState("");
  const [queryString, setQueryString] = useState("");
  const [wafAction, setWafAction] = useState("");
  const [cacheState, setCacheState] = useState("");
  const [tlsVersion, setTlsVersion] = useState("");
  const [tlsSni, setTlsSni] = useState("");
  const [tlsAlpn, setTlsAlpn] = useState("");
  const [tlsJa3, setTlsJa3] = useState("");
  const [tlsJa4, setTlsJa4] = useState("");
  const [sinceInput, setSinceInput] = useState("");
  const [untilInput, setUntilInput] = useState("");

  const advanced = useMemo(
    () => ({
      request_id: requestId.trim() || undefined,
      host: host.trim() || undefined,
      path: path.trim() || undefined,
      query_string: queryString.trim() || undefined,
      waf_action: wafAction.trim() || undefined,
      cache_state: cacheState.trim() || undefined,
      tls_version: tlsVersion.trim() || undefined,
      tls_sni: tlsSni.trim() || undefined,
      tls_alpn: tlsAlpn.trim() || undefined,
      tls_ja3_hash: tlsJa3.trim() || undefined,
      tls_ja4: tlsJa4.trim() || undefined,
      since: toIso(sinceInput),
      until: toIso(untilInput),
    }),
    [
      requestId,
      host,
      path,
      queryString,
      wafAction,
      cacheState,
      tlsVersion,
      tlsSni,
      tlsAlpn,
      tlsJa3,
      tlsJa4,
      sinceInput,
      untilInput,
    ],
  );
  const debouncedAdvanced = useDebounced(advanced, 350);

  const list = useList<AccessLog>("/access-logs", {
    q: q || undefined,
    method: method === "all" ? undefined : method,
    status_group: statusGroup === "all" ? undefined : statusGroup,
    client_ip: clientIp || undefined,
    ...debouncedAdvanced,
  });

  /* 日志详情抽屉 */
  const [detail, setDetail] = useState<AccessLog | null>(null);
  const detailState = useOverlayState();
  const {
    data: detailFull,
    loading: detailLoading,
    error: detailError,
    reload: reloadDetail,
  } = useApi<AccessLog>(
    useCallback(() => api.get<AccessLog>(`/access-logs/${detail!.id}`), [detail?.id]),
    [detail?.id],
    { enabled: detail !== null },
  );
  const detailData = detailFull ?? detail;
  const entries = detailData ? Object.entries(detailData) : [];
  const normalEntries = entries.filter(([key]) => !isTlsKey(key));
  const tlsEntries = entries.filter(([key]) => isTlsKey(key));

  function openDetail(log: AccessLog) {
    setDetail(log);
    detailState.open();
  }

  /**
   * 已激活筛选条件清单。
   *
   * 只在筛选真正生效时列出条目：`q` 用防抖后的值判定，避免用户输入过程中
   * 条件条闪烁；枚举项取当前语言的标签，与下拉框显示保持一致。
   */
  const activeFilters = useMemo<ActiveFilter[]>(() => {
    const items: ActiveFilter[] = [];
    const add = (key: string, label: string, value: string) => {
      if (value) items.push({ key, label, value });
    };

    add("q", t("logs.cond.q"), q.trim());
    if (method !== "all") add("method", t("logs.cond.method"), method);
    if (statusGroup !== "all") {
      add("statusGroup", t("logs.cond.status"), t(STATUS_GROUP_KEYS[statusGroup]));
    }
    add("clientIp", t("logs.cond.clientIp"), clientIp.trim());
    add("requestId", t("logs.cond.requestId"), requestId.trim());
    add("host", t("logs.cond.host"), host.trim());
    add("path", t("logs.cond.path"), path.trim());
    add("queryString", t("logs.cond.query"), queryString.trim());
    add("wafAction", t("logs.cond.wafAction"), wafAction.trim());
    add("cacheState", t("logs.cond.cacheState"), cacheState.trim());
    add("tlsVersion", t("logs.cond.tlsVersion"), tlsVersion.trim());
    add("tlsSni", t("logs.cond.tlsSni"), tlsSni.trim());
    add("tlsAlpn", t("logs.cond.tlsAlpn"), tlsAlpn.trim());
    add("tlsJa3", t("logs.cond.ja3"), tlsJa3.trim());
    add("tlsJa4", t("logs.cond.ja4"), tlsJa4.trim());
    add("since", t("logs.cond.since"), sinceInput);
    add("until", t("logs.cond.until"), untilInput);
    return items;
  }, [
    t,
    q,
    method,
    statusGroup,
    clientIp,
    requestId,
    host,
    path,
    queryString,
    wafAction,
    cacheState,
    tlsVersion,
    tlsSni,
    tlsAlpn,
    tlsJa3,
    tlsJa4,
    sinceInput,
    untilInput,
  ]);

  /** 单个筛选的清除器表：键与 activeFilters 的 key 一一对应。 */
  const FILTER_RESETTERS: Record<string, () => void> = {
    q: () => setQInput(""),
    method: () => setMethod("all"),
    statusGroup: () => setStatusGroup("all"),
    clientIp: () => setClientIp(""),
    requestId: () => setRequestId(""),
    host: () => setHost(""),
    path: () => setPath(""),
    queryString: () => setQueryString(""),
    wafAction: () => setWafAction(""),
    cacheState: () => setCacheState(""),
    tlsVersion: () => setTlsVersion(""),
    tlsSni: () => setTlsSni(""),
    tlsAlpn: () => setTlsAlpn(""),
    tlsJa3: () => setTlsJa3(""),
    tlsJa4: () => setTlsJa4(""),
    since: () => setSinceInput(""),
    until: () => setUntilInput(""),
  };

  function clearFilter(key: string) {
    FILTER_RESETTERS[key]?.();
  }

  /** 一键清除全部筛选；关闭高级面板与筛选条件是否可见无关，故不改 advancedOpen。 */
  function clearAllFilters() {
    Object.values(FILTER_RESETTERS).forEach((reset) => reset());
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t("logs.title")}
        description={t("logs.description")}
        actions={
          <Button size="sm" variant="ghost" onPress={list.reload}>
            <RefreshCw className="size-3.5" /> {t("common.refresh")}
          </Button>
        }
      />

      <Tabs aria-label={t("logs.title")}>
        <Tabs.List aria-label={t("logs.title")}>
          <Tabs.Tab id="logs">
            <span className="flex items-center gap-1.5">
              <Globe className="size-4" /> {t("logs.tab.logs")}
            </span>
          </Tabs.Tab>
          <Tabs.Tab id="tls">
            <span className="flex items-center gap-1.5">
              <Fingerprint className="size-4" /> {t("logs.tab.tls")}
            </span>
          </Tabs.Tab>
        </Tabs.List>

        {/* 访问日志面板 */}
        <Tabs.Panel id="logs">
          <div className="flex flex-col gap-4">
            <Toolbar>
              <SearchInput value={qInput} onChange={setQInput} placeholder={t("logs.search")} />
              <SimpleSelect
                value={method}
                onChange={setMethod}
                options={METHODS.map((m) => ({ key: m, label: m === "all" ? t("logs.method.all") : m }))}
                label={t("logs.filter.method")}
              />
              <SimpleSelect
                value={statusGroup}
                onChange={setStatusGroup}
                options={STATUS_GROUPS.map((g) => ({ key: g, label: t(STATUS_GROUP_KEYS[g]) }))}
                label={t("logs.filter.statusGroup")}
              />
              <Input
                className="w-40"
                aria-label={t("logs.filter.clientIp")}
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
                {t("logs.filter.advanced")}
              </Button>
            </Toolbar>

            {advancedOpen ? (
              <div className="bg-surface mb-3 grid gap-2 rounded-xl border border-separator p-3 md:grid-cols-3 xl:grid-cols-4">
                <Input
                  aria-label={t("logs.filter.requestId")}
                  placeholder={t("common.requestId")}
                  value={requestId}
                  onChange={(e) => setRequestId(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.host")}
                  placeholder={t("logs.placeholder.host")}
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.path")}
                  placeholder={t("logs.placeholder.path")}
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.query")}
                  placeholder="query_string"
                  value={queryString}
                  onChange={(e) => setQueryString(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.wafAction")}
                  placeholder={t("logs.placeholder.wafAction")}
                  value={wafAction}
                  onChange={(e) => setWafAction(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.cacheState")}
                  placeholder={t("logs.placeholder.cacheState")}
                  value={cacheState}
                  onChange={(e) => setCacheState(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.tlsVersion")}
                  placeholder={t("logs.placeholder.tlsVersion")}
                  value={tlsVersion}
                  onChange={(e) => setTlsVersion(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.tlsSni")}
                  placeholder="tls_sni"
                  value={tlsSni}
                  onChange={(e) => setTlsSni(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.tlsAlpn")}
                  placeholder={t("logs.placeholder.tlsAlpn")}
                  value={tlsAlpn}
                  onChange={(e) => setTlsAlpn(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.ja3")}
                  placeholder="tls_ja3_hash"
                  value={tlsJa3}
                  onChange={(e) => setTlsJa3(e.target.value)}
                />
                <Input
                  aria-label={t("logs.filter.ja4")}
                  placeholder="tls_ja4"
                  value={tlsJa4}
                  onChange={(e) => setTlsJa4(e.target.value)}
                />
                <Input
                  type="datetime-local"
                  aria-label={t("common.startTime")}
                  value={sinceInput}
                  onChange={(e) => setSinceInput(e.target.value)}
                />
                <Input
                  type="datetime-local"
                  aria-label={t("common.endTime")}
                  value={untilInput}
                  onChange={(e) => setUntilInput(e.target.value)}
                />
              </div>
            ) : null}

            <ActiveFilterBar
              filters={activeFilters}
              onClear={clearFilter}
              onClearAll={clearAllFilters}
            />

            {list.error ? (
              <ErrorState message={list.error} onRetry={list.reload} />
            ) : list.loading && list.items.length === 0 ? (
              <div className="bg-surface rounded-xl border border-separator p-4">
                <TableSkeleton rows={8} />
              </div>
            ) : (
              <div className="bg-surface overflow-x-auto rounded-xl border border-separator">
                <Table>
                  <Table.Content aria-label={t("logs.listAria")}>
                  <Table.Header>
                    <Table.Column isRowHeader>{t("logs.col.time")}</Table.Column>
                    <Table.Column>{t("logs.col.clientIp")}</Table.Column>
                    <Table.Column>{t("logs.col.method")}</Table.Column>
                    <Table.Column>{t("logs.col.host")}</Table.Column>
                    <Table.Column>{t("logs.col.path")}</Table.Column>
                    <Table.Column>{t("logs.col.statusCode")}</Table.Column>
                    <Table.Column>{t("logs.col.waf")}</Table.Column>
                    <Table.Column>{t("logs.col.ua")}</Table.Column>
                    <Table.Column>{t("logs.col.actions")}</Table.Column>
                  </Table.Header>
                  <Table.Body
                    items={list.items}
                    renderEmptyState={() => <EmptyState message={t("logs.empty")} />}
                  >
                    {(row) => (
                      <Table.Row id={`al-${row.id}`}>
                        <Table.Cell>
                          <span className="text-xs whitespace-nowrap">{formatDateTime(row.created_at)}</span>
                        </Table.Cell>
                        <Table.Cell>
                          <span className="font-mono text-xs">{row.client_ip}</span>
                        </Table.Cell>
                        <Table.Cell>
                          <StatusChip tone={statusTone(row.status_code)}>{row.method}</StatusChip>
                        </Table.Cell>
                        <Table.Cell>
                          <span className="text-xs">{row.host}</span>
                        </Table.Cell>
                        <Table.Cell>
                          <span
                            className="block max-w-[240px] truncate font-mono text-xs"
                            title={row.path + (row.query_string ? `?${row.query_string}` : "")}
                          >
                            {truncate(row.path + (row.query_string ? `?${row.query_string}` : ""), 36)}
                          </span>
                        </Table.Cell>
                        <Table.Cell>
                          <span className={`tabular text-sm font-medium ${statusTextClass(row.status_code)}`}>
                            {row.status_code}
                          </span>
                        </Table.Cell>
                        <Table.Cell>
                          <ActionChip action={row.waf_action} />
                        </Table.Cell>
                        <Table.Cell>
                          <span className="block max-w-[180px] truncate text-xs" title={row.user_agent}>
                            {truncate(row.user_agent || "-", 32)}
                          </span>
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

        {/* TLS 指纹面板 */}
        <Tabs.Panel id="tls">
          <FingerprintsPanel />
        </Tabs.Panel>
      </Tabs>

      {/* 日志详情抽屉 */}
      <DetailDrawer
        state={detailState}
        title={detail ? t("logs.detail.title", { id: detail.id }) : t("logs.detail.fallback")}
        description={detail ? `${detail.method} ${detail.host}${detail.path}` : undefined}
        width="w-[640px]"
      >
        {detailLoading && !detailFull ? (
          <TableSkeleton rows={6} />
        ) : detailError ? (
          <ErrorState message={detailError} onRetry={reloadDetail} />
        ) : detailData ? (
          <div className="flex flex-col gap-3">
            <div>
              {normalEntries.map(([key, value]) => (
                <DetailField key={key} label={key} value={value} />
              ))}
            </div>
            {tlsEntries.length > 0 && (
              <div>
                <div className="text-muted mb-1 text-sm font-medium">{t("logs.detail.tls")}</div>
                {tlsEntries.map(([key, value]) => (
                  <DetailField key={key} label={key} value={value} />
                ))}
              </div>
            )}
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
