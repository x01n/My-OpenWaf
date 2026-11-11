"use client";

/**
 * JS 插件管理：运行时状态、列表、新建/编辑、校验、试运行、运行统计、启停与删除。
 *
 * 后端契约（internal/admin/system/jsplugin）：
 * - 列表 GET /js-plugins → { items: (JSPlugin & {compile_error?})[], total }
 * - 运行时 GET /js-plugins/runtime → jsPluginRuntimeStatus（enabled 为 int 计数）
 * - 校验 POST /js-plugins/validate {stage, source, timeout_ms?} → {valid, error?}
 * - 试运行 POST /js-plugins/dry-run {stage, source, timeout_ms, sample_request|sample_response}
 *   → {result, execution_time_ms, error?}（runtime 未装配时 503）
 * - 统计 GET /js-plugins/stats → { items: (PluginStatsItem & {last_error?...})[], total }
 * - 启停 POST /js-plugins/:id/toggle（无 body = 翻转）；删除 POST /js-plugins/:id/delete
 * - site_id 三态：显式 null = 全局，数字 = 站点级
 */

import { useCallback, useMemo, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input, Tabs } from "@heroui/react";
import { Plus, RefreshCw, Pencil, Play } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n, type MessageKey } from "@/i18n";
import type { Site } from "@/lib/types/site";
import type { JSPlugin, PluginStatsItem } from "@/lib/types/system";
import {
  PageHeader,
  StatusChip,
  type StatusTone,
  Toolbar,
  SearchInput,
  ErrorState,
  SimpleSelect,
} from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { ActiveFilterBar, type ActiveFilter } from "@/components/ui/active-filter-bar";
import { CodeEditor } from "../shared/code-editor";

/** 列表行：JSPlugin + 快照编译诊断 */
type JsPluginRow = JSPlugin & { compile_error?: string };

type ValidateResult = { valid?: boolean; error?: string };

/** 运行时状态（jsPluginRuntimeStatus；enabled/compiled/compile_errors 为计数） */
type JsRuntimeStatus = {
  backend: string;
  available: boolean;
  engine_ready: boolean;
  enabled: number;
  compiled: number;
  compile_errors: number;
  request_supported: boolean;
  response_supported: boolean;
};

/** dry-run 响应（错误时 result 为 null；runtime 未装配时 503） */
type JsDryRunResult = {
  result?: unknown;
  execution_time_ms?: number;
  error?: string;
};

/** 统计行：附加最近一次故障诊断 */
type JsStatsItem = PluginStatsItem & {
  last_error?: string;
  last_error_stage?: string;
  last_error_at?: string;
  last_error_count?: number;
};

type JsStage = "request" | "response";

/** 阶段选项；labelKey 在渲染处经 t() 展开 */
const STAGE_OPTIONS: { key: JsStage; labelKey: MessageKey }[] = [
  { key: "request", labelKey: "jsPlugins.stage.request" },
  { key: "response", labelKey: "jsPlugins.stage.response" },
];

/** 失败模式选项；labelKey 在渲染处经 t() 展开 */
const FAILURE_MODE_OPTIONS: { key: "fail_open" | "fail_closed"; labelKey: MessageKey }[] = [
  { key: "fail_open", labelKey: "jsPlugins.failureMode.failOpen" },
  { key: "fail_closed", labelKey: "jsPlugins.failureMode.failClosed" },
];

/** 把「每行 Key: Value」文本解析为 headers 对象；空行与无冒号行跳过 */
function parseHeaders(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key) headers[key] = value;
  }
  return headers;
}

function RuntimeStatusBar() {
  const { t } = useI18n();
  const runtime = useApi<JsRuntimeStatus>(() => apiGet("/js-plugins/runtime"));

  if (runtime.error) {
    return <ErrorState message={runtime.error} onRetry={runtime.reload} />;
  }
  if (!runtime.data) {
    return <div className="bg-surface rounded-xl border border-separator p-4 text-sm">{t("common.loading")}</div>;
  }
  const r = runtime.data;
  const items: { label: string; value: string; tone: StatusTone }[] = [
    { label: t("jsPlugins.runtime.backend"), value: r.backend, tone: "info" },
    {
      label: t("jsPlugins.runtime.available"),
      value: r.available ? t("jsPlugins.runtime.availableOk") : t("jsPlugins.runtime.availableBad"),
      tone: r.available ? "success" : "danger",
    },
    {
      label: t("jsPlugins.runtime.engine"),
      value: r.engine_ready ? t("jsPlugins.runtime.engineOk") : t("jsPlugins.runtime.engineBad"),
      tone: r.engine_ready ? "success" : "warning",
    },
    { label: t("jsPlugins.runtime.enabledScripts"), value: String(r.enabled), tone: "neutral" },
    { label: t("jsPlugins.runtime.compiled"), value: String(r.compiled), tone: "neutral" },
    {
      label: t("jsPlugins.runtime.compileErrors"),
      value: String(r.compile_errors),
      tone: r.compile_errors > 0 ? "danger" : "success",
    },
    {
      label: t("jsPlugins.runtime.requestStage"),
      value: r.request_supported ? t("jsPlugins.runtime.supported") : t("jsPlugins.runtime.unsupported"),
      tone: r.request_supported ? "success" : "warning",
    },
    {
      label: t("jsPlugins.runtime.responseStage"),
      value: r.response_supported ? t("jsPlugins.runtime.supported") : t("jsPlugins.runtime.unsupported"),
      tone: r.response_supported ? "success" : "warning",
    },
  ];
  return (
    <div className="bg-surface flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border border-separator p-3">
      {items.map((it) => (
        <div key={it.label} className="flex items-center gap-1.5 text-sm">
          <span className="text-muted">{it.label}</span>
          <StatusChip tone={it.tone}>{it.value}</StatusChip>
        </div>
      ))}
    </div>
  );
}

function JsPluginsClient() {
  const { t } = useI18n();
  const list = useApi<ListResponse<JsPluginRow>>(() => apiGet("/js-plugins"));
  const stats = useApi<ListResponse<JsStatsItem>>(() => apiGet("/js-plugins/stats"));
  const sites = useApi<ListResponse<Site>>(() => apiGet("/sites", { page: 1, page_size: 100 }));
  const [search, setSearch] = useState("");

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<JsPluginRow | null>(null);
  const formState = useOverlayState();

  const [dryRunSource, setDryRunSource] = useState<string | null>(null);
  const dryRunState = useOverlayState();

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return list.data?.items ?? [];
    return (list.data?.items ?? []).filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.description ?? "").toLowerCase().includes(q),
    );
  }, [list.data, search]);

  /**
   * 已激活筛选条件清单（Cloudflare 风格可见 chips）。
   * 仅前端搜索 q。
   */
  const activeFilters = useMemo<ActiveFilter[]>(() => {
    const items: ActiveFilter[] = [];
    const add = (key: string, label: string, value: string) => {
      if (value && value.trim() !== "") {
        items.push({ key, label, value: value.trim() });
      }
    };
    add("q", t("jsPlugins.cond.q"), search.trim());
    return items;
  }, [t, search]);

  /** 单个筛选的清除器表 */
  const FILTER_RESETTERS: Record<string, () => void> = {
    q: () => setSearch(""),
  };

  function clearFilter(key: string) {
    FILTER_RESETTERS[key]?.();
  }

  function clearAllFilters() {
    Object.values(FILTER_RESETTERS).forEach((reset) => reset());
  }

  const openCreate = useCallback(() => {
    setEditing(null);
    setFormOpen(true);
    formState.open();
  }, [formState]);

  const openEdit = useCallback(
    (row: JsPluginRow) => {
      setEditing(row);
      setFormOpen(true);
      formState.open();
    },
    [formState],
  );

  const openDryRun = useCallback(
    (row: JsPluginRow) => {
      setDryRunSource(row.source);
      dryRunState.open();
    },
    [dryRunState],
  );

  const columns = useMemo<DataTableColumn<JsPluginRow>[]>(
    () => [
      {
        header: t("jsPlugins.col.name"),
        render: (row) => (
          <div className="flex flex-col gap-1">
            <span className="font-medium">{row.name}</span>
            {row.compile_error && (
              <StatusChip tone="danger">
                <span title={row.compile_error}>{t("jsPlugins.col.compileFailed")}</span>
              </StatusChip>
            )}
          </div>
        ),
      },
      {
        header: t("jsPlugins.col.stage"),
        render: (row) =>
          row.stage === "request" ? (
            <StatusChip tone="info">request</StatusChip>
          ) : (
            <StatusChip tone="warning">response</StatusChip>
          ),
      },
      {
        header: t("jsPlugins.col.failureMode"),
        render: (row) =>
          row.failure_mode === "fail_open" ? (
            <StatusChip tone="success">fail_open</StatusChip>
          ) : (
            <StatusChip tone="danger">fail_closed</StatusChip>
          ),
      },
      { header: t("jsPlugins.col.priority"), className: "tabular", render: (row) => row.priority },
      {
        header: t("jsPlugins.col.status"),
        render: (row) => (
          <StatusChip tone={row.enabled ? "success" : "neutral"}>
            {row.enabled ? t("jsPlugins.col.enabled") : t("jsPlugins.col.disabled")}
          </StatusChip>
        ),
      },
      {
        header: t("jsPlugins.col.timeout"),
        className: "tabular",
        render: (row) => (row.timeout_ms > 0 ? `${row.timeout_ms} ms` : t("jsPlugins.col.timeoutDefault")),
      },
      {
        header: t("jsPlugins.col.site"),
        render: (row) => (row.site_id ? `#${row.site_id}` : t("jsPlugins.col.global")),
      },
      {
        header: t("jsPlugins.col.description"),
        className: "max-w-48",
        render: (row) => (
          <span className="text-muted line-clamp-1 break-all">{row.description || "-"}</span>
        ),
      },
      {
        header: t("common.actions"),
        render: (row) => (
          <div className="flex items-center gap-1.5">
            <Button size="sm" variant="ghost" onPress={() => openDryRun(row)}>
              <Play className="size-3.5" /> {t("jsPlugins.action.dryRun")}
            </Button>
            <Button size="sm" variant="outline" onPress={() => openEdit(row)}>
              <Pencil className="size-3.5" /> {t("common.edit")}
            </Button>
            <Button
              size="sm"
              variant={row.enabled ? "outline" : "primary"}
              onPress={() =>
                void apiPost(`/js-plugins/${row.id}/toggle`).then(
                  () => {
                    showSuccess(row.enabled ? t("jsPlugins.toast.disabled") : t("jsPlugins.toast.enabled"));
                    void list.reload();
                  },
                  (err) =>
                    showError(t("common.operationFailed"), err instanceof ApiError ? err.message : undefined),
                )
              }
            >
              {row.enabled ? t("jsPlugins.action.disable") : t("jsPlugins.action.enable")}
            </Button>
            <ConfirmButton
              confirmText={t("jsPlugins.action.deleteConfirm", { name: row.name })}
              successText={t("jsPlugins.action.deleted")}
              onConfirm={async () => {
                await apiPost(`/js-plugins/${row.id}/delete`);
                void list.reload();
              }}
            >
              {t("common.delete")}
            </ConfirmButton>
          </div>
        ),
      },
    ],
    [openEdit, openDryRun, list, t],
  );

  const statsColumns = useMemo<DataTableColumn<JsStatsItem>[]>(
    () => [
      { header: t("jsPlugins.col.name"), render: (row) => <span className="font-medium">{row.name}</span> },
      {
        header: t("jsPlugins.col.stage"),
        render: (row) =>
          row.stage === "request" ? (
            <StatusChip tone="info">request</StatusChip>
          ) : (
            <StatusChip tone="warning">response</StatusChip>
          ),
      },
      { header: t("jsPlugins.col.runs"), className: "tabular", render: (row) => row.runs },
      {
        header: t("jsPlugins.col.failures"),
        className: "tabular",
        render: (row) =>
          row.failures > 0 ? (
            <span className="text-danger tabular">{row.failures}</span>
          ) : (
            <span className="tabular">0</span>
          ),
      },
      {
        header: t("jsPlugins.col.timeout"),
        className: "tabular",
        render: (row) =>
          row.timeouts > 0 ? (
            <span className="text-warning tabular">{row.timeouts}</span>
          ) : (
            <span className="tabular">0</span>
          ),
      },
      { header: t("jsPlugins.col.avgMs"), className: "tabular", render: (row) => `${row.avg_ms.toFixed(2)} ms` },
      {
        header: t("jsPlugins.col.lastError"),
        className: "max-w-56",
        render: (row) =>
          row.last_error ? (
            <span className="text-danger line-clamp-1 break-all" title={row.last_error}>
              {row.last_error}
            </span>
          ) : (
            "-"
          ),
      },
    ],
    [t],
  );

  return (
    <div>
      <PageHeader
        title={t("jsPlugins.title")}
        description={t("jsPlugins.description")}
        actions={
          <>
            <Button size="sm" variant="ghost" onPress={() => void list.reload()}>
              <RefreshCw className="size-3.5" /> {t("common.refresh")}
            </Button>
            <Button size="sm" variant="primary" onPress={openCreate}>
              <Plus className="size-3.5" /> {t("jsPlugins.create")}
            </Button>
          </>
        }
      />

      <RuntimeStatusBar />

      <Tabs aria-label={t("jsPlugins.tab.viewAria")}>
        <Tabs.List aria-label={t("jsPlugins.tab.navAria")}>
          <Tabs.Tab id="list">{t("jsPlugins.tab.list")}</Tabs.Tab>
          <Tabs.Tab id="stats">{t("jsPlugins.tab.stats")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel id="list">
          <Toolbar>
            <SearchInput value={search} onChange={setSearch} placeholder={t("jsPlugins.searchPlaceholder")} />
          </Toolbar>

          <ActiveFilterBar
            filters={activeFilters}
            onClear={clearFilter}
            onClearAll={clearAllFilters}
          />

          {list.error ? (
            <ErrorState message={list.error} onRetry={list.reload} />
          ) : (
            <DataTable
              ariaLabel={t("jsPlugins.listAria")}
              columns={columns}
              rows={filtered}
              loading={list.loading}
              emptyMessage={t("jsPlugins.empty")}
            />
          )}
        </Tabs.Panel>
        <Tabs.Panel id="stats">
          {stats.error ? (
            <ErrorState message={stats.error} onRetry={stats.reload} />
          ) : (
            <DataTable
              ariaLabel={t("jsPlugins.statsAria")}
              columns={statsColumns}
              rows={stats.data?.items}
              loading={stats.loading}
              emptyMessage={t("jsPlugins.statsEmpty")}
            />
          )}
        </Tabs.Panel>
      </Tabs>

      {formOpen ? (
        <JsPluginFormModal
          key={editing ? `js-edit-${editing.id}` : "js-create"}
          state={formState}
          editing={editing}
          sites={sites.data?.items ?? []}
          onSaved={() => {
            void list.reload();
            void stats.reload();
            setFormOpen(false);
          }}
        />
      ) : null}

      {dryRunSource !== null ? (
        <JsDryRunModal
          key={`js-dryrun-${dryRunSource.slice(0, 40)}-${dryRunSource.length}`}
          state={dryRunState}
          initialSource={dryRunSource}
        />
      ) : null}
    </div>
  );
}

/**
 * 新建/编辑 JS 插件弹窗。
 *
 * 后端校验（internal/admin/system/jsplugin）：
 * - name ≤128 字符；description ≤512 字符；timeout_ms ∈ [0, 1000]，0 = 用默认超时
 * - stage 必须是 request/response；failure_mode 必须是 fail_open/fail_closed
 */
function JsPluginFormModal({
  state,
  editing,
  sites,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  editing: JsPluginRow | null;
  sites: Site[];
  onSaved: () => void;
}) {
  const [name, setName] = useState(editing?.name ?? "");
  const [stage, setStage] = useState<JsStage>(editing?.stage ?? "request");
  const [failureMode, setFailureMode] = useState<"fail_open" | "fail_closed">(
    editing?.failure_mode ?? "fail_open",
  );
  const [priority, setPriority] = useState(String(editing?.priority ?? 100));
  const [timeoutMs, setTimeoutMs] = useState(String(editing?.timeout_ms ?? 0));
  const [siteId, setSiteId] = useState(editing?.site_id ? String(editing.site_id) : "global");
  const [description, setDescription] = useState(editing?.description ?? "");
  const [source, setSource] = useState(editing?.source ?? "");
  const [saving, setSaving] = useState(false);
  const [validateMsg, setValidateMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [validating, setValidating] = useState(false);
  const { t } = useI18n();

  async function handleValidate() {
    setValidating(true);
    setValidateMsg(null);
    try {
      const res = await apiPost<ValidateResult>("/js-plugins/validate", {
        stage,
        source,
        timeout_ms: Number(timeoutMs) || 0,
      });
      if (res.valid) {
        setValidateMsg({ ok: true, text: t("jsPlugins.validate.passed") });
      } else {
        setValidateMsg({ ok: false, text: res.error ?? t("jsPlugins.validate.failed") });
      }
    } catch (err) {
      setValidateMsg({
        ok: false,
        text: err instanceof ApiError ? err.message : t("jsPlugins.validate.requestFailed"),
      });
    } finally {
      setValidating(false);
    }
  }

  async function handleSave() {
    if (!name.trim() || !source.trim()) {
      showError(t("jsPlugins.form.incompleteTitle"), t("jsPlugins.form.incompleteDesc"));
      return;
    }
    setSaving(true);
    const payload = {
      name: name.trim(),
      stage,
      source,
      failure_mode: failureMode,
      priority: Number(priority) || 0,
      timeout_ms: Number(timeoutMs) || 0,
      description: description.trim(),
      site_id: siteId === "global" ? null : Number(siteId),
    };
    try {
      if (editing) {
        await apiPost(`/js-plugins/${editing.id}/update`, payload);
      } else {
        await apiPost("/js-plugins", payload);
      }
      showSuccess(editing ? t("jsPlugins.form.updated") : t("jsPlugins.form.created"));
      onSaved();
      state.close();
    } catch (err) {
      showError(t("jsPlugins.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal state={state}>
      <Modal.Backdrop>
        <Modal.Container size="lg">
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Heading>
                {editing ? t("jsPlugins.form.editTitle") : t("jsPlugins.form.createTitle")}
              </Modal.Heading>
              <Modal.CloseTrigger aria-label={t("common.close")} />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <div className="flex gap-3">
                <TextField aria-label={t("jsPlugins.form.name")} isRequired className="flex-1">
                  <Input
                    placeholder={t("jsPlugins.form.namePlaceholder")}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </TextField>
                <SimpleSelect
                  value={stage}
                  onChange={setStage}
                  label={t("jsPlugins.form.stage")}
                  className="w-56"
                  options={STAGE_OPTIONS.map((o) => ({ key: o.key, label: t(o.labelKey) }))}
                />
                <SimpleSelect
                  value={failureMode}
                  onChange={setFailureMode}
                  label={t("jsPlugins.form.failureMode")}
                  className="w-56"
                  options={FAILURE_MODE_OPTIONS.map((o) => ({ key: o.key, label: t(o.labelKey) }))}
                />
              </div>
              <div className="flex gap-3">
                <TextField aria-label={t("jsPlugins.form.priority")} className="flex-1">
                  <Input
                    type="number"
                    placeholder={t("jsPlugins.form.priorityPlaceholder")}
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                  />
                </TextField>
                <TextField aria-label={t("jsPlugins.form.timeoutMs")} className="flex-1">
                  <Input
                    type="number"
                    placeholder={t("jsPlugins.form.timeoutMsPlaceholder")}
                    value={timeoutMs}
                    onChange={(e) => setTimeoutMs(e.target.value)}
                  />
                </TextField>
                <SimpleSelect
                  value={siteId}
                  onChange={setSiteId}
                  label={t("jsPlugins.form.site")}
                  className="w-64"
                  options={[
                    { key: "global", label: t("jsPlugins.form.siteGlobal") },
                    ...sites.map((s) => ({
                      key: String(s.id),
                      label: s.name ? `${s.name}（${s.host}）` : s.host,
                    })),
                  ]}
                />
              </div>
              <TextField aria-label={t("jsPlugins.form.description")}>
                <Input
                  placeholder={t("jsPlugins.form.descriptionPlaceholder")}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </TextField>
              <div>
                <div className="mb-1.5 text-sm">{t("jsPlugins.form.sourceLabel")}</div>
                <CodeEditor
                  ariaLabel={t("jsPlugins.form.sourceAria")}
                  value={source}
                  onChange={setSource}
                  placeholder={t("jsPlugins.form.sourcePlaceholder")}
                />
              </div>
              {validateMsg && (
                <div className={`text-sm ${validateMsg.ok ? "text-success" : "text-danger"}`}>
                  {validateMsg.text}
                </div>
              )}
            </Modal.Body>
            <Modal.Footer>
              <Button variant="ghost" onPress={state.close}>
                {t("common.cancel")}
              </Button>
              <Button
                variant="outline"
                isPending={validating}
                isDisabled={!source.trim()}
                onPress={() => void handleValidate()}
              >
                {t("jsPlugins.validate.action")}
              </Button>
              <Button variant="primary" isPending={saving} onPress={() => void handleSave()}>
                {t("common.save")}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}

/**
 * JS 插件试运行弹窗。
 *
 * 请求结构精确对应 DryRunJSPlugin（internal/admin/system/jsplugin）：
 * - request 阶段发 sample_request：method/path/raw_query/host/client_ip/user_agent/
 *   content_type/body/headers/query_params（键名逐字取自 jsplugin.RequestSnapshot json tag）
 * - response 阶段发 sample_response：status/path/content_type/body/method/raw_query/
 *   client_ip/headers/request_headers（键名逐字取自 jsplugin.ResponseSnapshot json tag）
 * - 非目标类型的样例字段服务端会静默跳过
 *
 * 响应：{result, execution_time_ms, error?}。
 */
function JsDryRunModal({
  state,
  initialSource,
}: {
  state: ReturnType<typeof useOverlayState>;
  initialSource: string;
}) {
  const [source, setSource] = useState(initialSource);
  const [stage, setStage] = useState<JsStage>("request");
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/");
  const [rawQuery, setRawQuery] = useState("");
  const [host, setHost] = useState("example.com");
  const [clientIp, setClientIp] = useState("203.0.113.9");
  const [userAgent, setUserAgent] = useState("Mozilla/5.0");
  const [contentType, setContentType] = useState("");
  const [status, setStatus] = useState("200");
  const [headersText, setHeadersText] = useState("");
  const [body, setBody] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<JsDryRunResult | null>(null);
  const { t } = useI18n();

  async function handleRun() {
    setRunning(true);
    setResult(null);
    const common = {
      method: method.trim() || "GET",
      path: path.trim() || "/",
      raw_query: rawQuery,
      host,
      client_ip: clientIp,
      content_type: contentType,
      body,
    };
    const payload =
      stage === "request"
        ? {
            stage,
            source,
            timeout_ms: 0,
            sample_request: {
              ...common,
              user_agent: userAgent,
              headers: parseHeaders(headersText),
              query_params: parseHeaders(rawQuery.replaceAll("&", "\n")),
            },
          }
        : {
            stage,
            source,
            timeout_ms: 0,
            sample_response: {
              ...common,
              status: Number(status) || 200,
              headers: parseHeaders(headersText),
            },
          };
    try {
      const res = await apiPost<JsDryRunResult>("/js-plugins/dry-run", payload);
      setResult(res);
    } catch (err) {
      setResult({ error: err instanceof ApiError ? err.message : t("jsPlugins.dryRun.requestFailed") });
    } finally {
      setRunning(false);
    }
  }

  const resultJson = useMemo(
    () => (result?.result === undefined || result?.result === null ? null : JSON.stringify(result.result, null, 2)),
    [result],
  );

  return (
    <Modal state={state}>
      <Modal.Backdrop>
        <Modal.Container size="lg">
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Heading>{t("jsPlugins.dryRun.title")}</Modal.Heading>
              <Modal.CloseTrigger aria-label={t("common.close")} />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <div>
                <div className="mb-1.5 text-sm">{t("jsPlugins.dryRun.sourceLabel")}</div>
                <CodeEditor
                  ariaLabel={t("jsPlugins.dryRun.sourceAria")}
                  value={source}
                  onChange={setSource}
                  minHeight="10rem"
                  maxHeight="16rem"
                />
              </div>
              <div className="flex gap-3">
                <SimpleSelect
                  value={stage}
                  onChange={setStage}
                  label={t("jsPlugins.dryRun.stage")}
                  className="w-56"
                  options={STAGE_OPTIONS.map((o) => ({ key: o.key, label: t(o.labelKey) }))}
                />
                <TextField aria-label={t("jsPlugins.dryRun.method")} className="flex-1">
                  <Input placeholder="GET" value={method} onChange={(e) => setMethod(e.target.value)} />
                </TextField>
                <TextField aria-label={t("common.path")} className="flex-1">
                  <Input placeholder="/" value={path} onChange={(e) => setPath(e.target.value)} />
                </TextField>
                {stage === "response" && (
                  <TextField aria-label={t("jsPlugins.dryRun.statusCode")} className="w-28">
                    <Input type="number" placeholder="200" value={status} onChange={(e) => setStatus(e.target.value)} />
                  </TextField>
                )}
              </div>
              <div className="flex gap-3">
                {stage === "request" && (
                  <TextField aria-label="User-Agent" className="flex-1">
                    <Input placeholder="Mozilla/5.0" value={userAgent} onChange={(e) => setUserAgent(e.target.value)} />
                  </TextField>
                )}
                <TextField aria-label={t("jsPlugins.dryRun.rawQuery")} className="flex-1">
                  <Input
                    placeholder={t("jsPlugins.dryRun.rawQueryPlaceholder")}
                    value={rawQuery}
                    onChange={(e) => setRawQuery(e.target.value)}
                  />
                </TextField>
                <TextField aria-label="Host" className="flex-1">
                  <Input placeholder="example.com" value={host} onChange={(e) => setHost(e.target.value)} />
                </TextField>
                <TextField aria-label={t("common.clientIp")} className="flex-1">
                  <Input placeholder="203.0.113.9" value={clientIp} onChange={(e) => setClientIp(e.target.value)} />
                </TextField>
              </div>
              <div className="flex gap-3">
                <TextField aria-label="Content-Type" className="flex-1">
                  <Input
                    placeholder={t("jsPlugins.dryRun.contentTypePlaceholder")}
                    value={contentType}
                    onChange={(e) => setContentType(e.target.value)}
                  />
                </TextField>
                <TextField aria-label={t("jsPlugins.dryRun.headers")} className="flex-[2]">
                  <Input
                    placeholder={t("jsPlugins.dryRun.headersPlaceholder")}
                    value={headersText}
                    onChange={(e) => setHeadersText(e.target.value)}
                  />
                </TextField>
              </div>
              <TextField aria-label={t("jsPlugins.dryRun.body")}>
                <Input
                  placeholder={
                    stage === "response"
                      ? t("jsPlugins.dryRun.responseBodyPlaceholder")
                      : t("jsPlugins.dryRun.bodyPlaceholder")
                  }
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
              </TextField>

              {result && (
                <div className="rounded-lg border border-separator p-3 text-sm">
                  {result.error ? (
                    <div className="text-danger">{result.error}</div>
                  ) : resultJson ? (
                    <div className="flex flex-col gap-2">
                      <div className="text-muted">
                        {t("jsPlugins.dryRun.successWithPlan", {
                          ms: (result.execution_time_ms ?? 0).toFixed(2),
                        })}
                      </div>
                      <CodeEditor ariaLabel={t("jsPlugins.dryRun.planAria")} value={resultJson} readOnly maxHeight="16rem" />
                    </div>
                  ) : (
                    <div className="text-muted">
                      {t("jsPlugins.dryRun.successNoChanges", {
                        ms: (result.execution_time_ms ?? 0).toFixed(2),
                      })}
                    </div>
                  )}
                </div>
              )}
            </Modal.Body>
            <Modal.Footer>
              <Button variant="ghost" onPress={state.close}>
                {t("common.close")}
              </Button>
              <Button variant="primary" isPending={running} isDisabled={!source.trim()} onPress={() => void handleRun()}>
                {t("jsPlugins.dryRun.run")}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}

export default JsPluginsClient;
