"use client";

/**
 * Lua 插件管理：列表、新建/编辑、校验、试运行、运行统计、启停与删除。
 *
 * 后端契约（internal/admin/system/luaplugin + internal/waf/luaplugin）：
 * - 列表 GET /lua-plugins → { items: (LuaPlugin & {compile_error?})[], total }
 * - 创建 POST /lua-plugins；更新 POST /lua-plugins/:id/update（204）
 * - 校验 POST /lua-plugins/validate {stage, source} → {valid, error?}
 * - 试运行 POST /lua-plugins/dry-run → DryRunBatchResult（decision 键为 Go 默认 PascalCase）
 * - 统计 GET /lua-plugins/stats → { items: PluginStatsItem[], total }
 * - 启停 POST /lua-plugins/:id/toggle（无 body = 翻转）；删除 POST /lua-plugins/:id/delete
 * - site_id 为三态（json.RawMessage）：显式 null = 全局，数字 = 站点级
 */

import { useCallback, useMemo, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input, Tabs } from "@heroui/react";
import { Plus, RefreshCw, Pencil, Play } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { useI18n, type MessageKey } from "@/i18n";
import type { Site } from "@/lib/types/site";
import type { LuaPlugin, LuaPluginStatsResponse, PluginStatsItem } from "@/lib/types/system";
import {
  PageHeader,
  StatusChip,
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

/** 列表行：LuaPlugin + 快照编译诊断 */
type LuaPluginRow = LuaPlugin & { compile_error?: string };

type ValidateResult = { valid?: boolean; error?: string };

/** dry-run 判定结果；后端 Decision 无 json tag，序列化为 Go 默认 PascalCase 键 */
type LuaDecision = {
  Action?: string;
  Message?: string;
  RedirectTo?: string;
  StatusCode?: number;
  [key: string]: unknown;
};

type LuaDryRunResult = {
  compile_error?: string;
  runtime_error?: string;
  decision?: LuaDecision;
  elapsed_ms?: number;
  iterations?: number;
  kv_available?: boolean;
  error?: string;
};

/** 阶段选项；labelKey 在渲染处经 t() 展开 */
const STAGE_OPTIONS: { key: "pre" | "post"; labelKey: MessageKey }[] = [
  { key: "pre", labelKey: "luaPlugins.stage.pre" },
  { key: "post", labelKey: "luaPlugins.stage.post" },
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

function LuaPluginsClient() {
  const { t } = useI18n();
  const list = useApi<ListResponse<LuaPluginRow>>(() => apiGet("/lua-plugins"));
  const stats = useApi<LuaPluginStatsResponse>(() => apiGet("/lua-plugins/stats"));
  const sites = useApi<ListResponse<Site>>(() => apiGet("/sites", { page: 1, page_size: 100 }));
  const [search, setSearch] = useState("");

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<LuaPluginRow | null>(null);
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
    add("q", t("luaPlugins.cond.q"), search.trim());
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
    (row: LuaPluginRow) => {
      setEditing(row);
      setFormOpen(true);
      formState.open();
    },
    [formState],
  );

  const openDryRun = useCallback(
    (row: LuaPluginRow) => {
      setDryRunSource(row.source);
      dryRunState.open();
    },
    [dryRunState],
  );

  const columns = useMemo<DataTableColumn<LuaPluginRow>[]>(
    () => [
      {
        header: t("luaPlugins.col.name"),
        render: (row) => (
          <div className="flex flex-col gap-1">
            <span className="font-medium">{row.name}</span>
            {row.compile_error && (
              <StatusChip tone="danger">
                <span title={row.compile_error}>{t("luaPlugins.col.compileFailed")}</span>
              </StatusChip>
            )}
          </div>
        ),
      },
      {
        header: t("luaPlugins.col.stage"),
        render: (row) =>
          row.stage === "pre" ? (
            <StatusChip tone="info">{t("luaPlugins.col.stagePre")}</StatusChip>
          ) : (
            <StatusChip tone="warning">{t("luaPlugins.col.stagePost")}</StatusChip>
          ),
      },
      { header: t("luaPlugins.col.priority"), className: "tabular", render: (row) => row.priority },
      {
        header: t("luaPlugins.col.status"),
        render: (row) => (
          <StatusChip tone={row.enabled ? "success" : "neutral"}>
            {row.enabled ? t("luaPlugins.col.enabled") : t("luaPlugins.col.disabled")}
          </StatusChip>
        ),
      },
      {
        header: t("luaPlugins.col.timeout"),
        className: "tabular",
        render: (row) => (row.timeout_ms > 0 ? `${row.timeout_ms} ms` : t("luaPlugins.col.timeoutDefault")),
      },
      {
        header: t("luaPlugins.col.site"),
        render: (row) => (row.site_id ? `#${row.site_id}` : t("luaPlugins.col.global")),
      },
      {
        header: t("luaPlugins.col.description"),
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
              <Play className="size-3.5" /> {t("luaPlugins.action.dryRun")}
            </Button>
            <Button size="sm" variant="outline" onPress={() => openEdit(row)}>
              <Pencil className="size-3.5" /> {t("common.edit")}
            </Button>
            <Button
              size="sm"
              variant={row.enabled ? "outline" : "primary"}
              onPress={() =>
                void apiPost(`/lua-plugins/${row.id}/toggle`).then(
                  () => {
                    showSuccess(row.enabled ? t("luaPlugins.toast.disabled") : t("luaPlugins.toast.enabled"));
                    void list.reload();
                  },
                  (err) =>
                    showError(t("common.operationFailed"), err instanceof ApiError ? err.message : undefined),
                )
              }
            >
              {row.enabled ? t("luaPlugins.action.disable") : t("luaPlugins.action.enable")}
            </Button>
            <ConfirmButton
              confirmText={t("luaPlugins.action.deleteConfirm", { name: row.name })}
              successText={t("luaPlugins.action.deleted")}
              onConfirm={async () => {
                await apiPost(`/lua-plugins/${row.id}/delete`);
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

  const statsColumns = useMemo<DataTableColumn<PluginStatsItem>[]>(
    () => [
      { header: t("luaPlugins.col.name"), render: (row) => <span className="font-medium">{row.name}</span> },
      {
        header: t("luaPlugins.col.stage"),
        render: (row) =>
          row.stage === "pre" ? (
            <StatusChip tone="info">pre</StatusChip>
          ) : (
            <StatusChip tone="warning">post</StatusChip>
          ),
      },
      { header: t("luaPlugins.col.runs"), className: "tabular", render: (row) => row.runs },
      {
        header: t("luaPlugins.col.failures"),
        className: "tabular",
        render: (row) =>
          row.failures > 0 ? (
            <span className="text-danger tabular">{row.failures}</span>
          ) : (
            <span className="tabular">0</span>
          ),
      },
      {
        header: t("luaPlugins.col.timeout"),
        className: "tabular",
        render: (row) =>
          row.timeouts > 0 ? (
            <span className="text-warning tabular">{row.timeouts}</span>
          ) : (
            <span className="tabular">0</span>
          ),
      },
      { header: t("luaPlugins.col.avgMs"), className: "tabular", render: (row) => `${row.avg_ms.toFixed(2)} ms` },
    ],
    [t],
  );

  return (
    <div>
      <PageHeader
        title={t("luaPlugins.title")}
        description={t("luaPlugins.description")}
        actions={
          <>
            <Button size="sm" variant="ghost" onPress={() => void list.reload()}>
              <RefreshCw className="size-3.5" /> {t("common.refresh")}
            </Button>
            <Button size="sm" variant="primary" onPress={openCreate}>
              <Plus className="size-3.5" /> {t("luaPlugins.create")}
            </Button>
          </>
        }
      />

      <Tabs aria-label={t("luaPlugins.tab.viewAria")}>
        <Tabs.List aria-label={t("luaPlugins.tab.navAria")}>
          <Tabs.Tab id="list">{t("luaPlugins.tab.list")}</Tabs.Tab>
          <Tabs.Tab id="stats">{t("luaPlugins.tab.stats")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel id="list">
          <Toolbar>
            <SearchInput value={search} onChange={setSearch} placeholder={t("luaPlugins.searchPlaceholder")} />
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
              ariaLabel={t("luaPlugins.listAria")}
              columns={columns}
              rows={filtered}
              loading={list.loading}
              emptyMessage={t("luaPlugins.empty")}
            />
          )}
        </Tabs.Panel>
        <Tabs.Panel id="stats">
          {/* Redis 未启用时 Evaluate 静默 fail-open，脚本不执行且 runs 不增——必须显式告知用户 */}
          {stats.data?.kv_executable === false ? (
            <div className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
              {t("luaPlugins.redisWarning")}
            </div>
          ) : null}
          {stats.error ? (
            <ErrorState message={stats.error} onRetry={stats.reload} />
          ) : (
            <DataTable
              ariaLabel={t("luaPlugins.statsAria")}
              columns={statsColumns}
              rows={stats.data?.items}
              loading={stats.loading}
              emptyMessage={t("luaPlugins.statsEmpty")}
            />
          )}
        </Tabs.Panel>
      </Tabs>

      {formOpen ? (
        <LuaPluginFormModal
          key={editing ? `lua-edit-${editing.id}` : "lua-create"}
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
        <LuaDryRunModal
          key={`lua-dryrun-${dryRunSource.slice(0, 40)}-${dryRunSource.length}`}
          state={dryRunState}
          initialSource={dryRunSource}
        />
      ) : null}
    </div>
  );
}

/**
 * 新建/编辑 Lua 插件弹窗。
 *
 * 后端校验（internal/admin/system/luaplugin）：
 * - name ≤128 字符；description ≤512 字符；timeout_ms ∈ [0, 1000]，0 = 用默认超时
 * - source 必须包含 handle；stage 必须是 pre/post
 */
function LuaPluginFormModal({
  state,
  editing,
  sites,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  editing: LuaPluginRow | null;
  sites: Site[];
  onSaved: () => void;
}) {
  const [name, setName] = useState(editing?.name ?? "");
  const [stage, setStage] = useState<"pre" | "post">(editing?.stage ?? "pre");
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
      const res = await apiPost<ValidateResult>("/lua-plugins/validate", { stage, source });
      if (res.valid) {
        setValidateMsg({ ok: true, text: t("luaPlugins.validate.passed") });
      } else {
        setValidateMsg({ ok: false, text: res.error ?? t("luaPlugins.validate.failed") });
      }
    } catch (err) {
      setValidateMsg({
        ok: false,
        text: err instanceof ApiError ? err.message : t("luaPlugins.validate.requestFailed"),
      });
    } finally {
      setValidating(false);
    }
  }

  async function handleSave() {
    if (!name.trim() || !source.trim()) {
      showError(t("luaPlugins.form.incompleteTitle"), t("luaPlugins.form.incompleteDesc"));
      return;
    }
    setSaving(true);
    const payload = {
      name: name.trim(),
      stage,
      source,
      priority: Number(priority) || 0,
      timeout_ms: Number(timeoutMs) || 0,
      description: description.trim(),
      site_id: siteId === "global" ? null : Number(siteId),
    };
    try {
      if (editing) {
        await apiPost(`/lua-plugins/${editing.id}/update`, payload);
      } else {
        await apiPost("/lua-plugins", payload);
      }
      showSuccess(editing ? t("luaPlugins.form.updated") : t("luaPlugins.form.created"));
      onSaved();
      state.close();
    } catch (err) {
      showError(t("luaPlugins.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
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
                {editing ? t("luaPlugins.form.editTitle") : t("luaPlugins.form.createTitle")}
              </Modal.Heading>
              <Modal.CloseTrigger aria-label={t("common.close")} />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <div className="flex gap-3">
                <TextField aria-label={t("luaPlugins.form.name")} isRequired className="flex-1">
                  <Input
                    placeholder={t("luaPlugins.form.namePlaceholder")}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </TextField>
                <SimpleSelect
                  value={stage}
                  onChange={setStage}
                  label={t("luaPlugins.form.stage")}
                  className="w-48"
                  options={STAGE_OPTIONS.map((o) => ({ key: o.key, label: t(o.labelKey) }))}
                />
              </div>
              <div className="flex gap-3">
                <TextField aria-label={t("luaPlugins.form.priority")} className="flex-1">
                  <Input
                    type="number"
                    placeholder={t("luaPlugins.form.priorityPlaceholder")}
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                  />
                </TextField>
                <TextField aria-label={t("luaPlugins.form.timeoutMs")} className="flex-1">
                  <Input
                    type="number"
                    placeholder={t("luaPlugins.form.timeoutMsPlaceholder")}
                    value={timeoutMs}
                    onChange={(e) => setTimeoutMs(e.target.value)}
                  />
                </TextField>
                <SimpleSelect
                  value={siteId}
                  onChange={setSiteId}
                  label={t("luaPlugins.form.site")}
                  className="w-64"
                  options={[
                    { key: "global", label: t("luaPlugins.form.siteGlobal") },
                    ...sites.map((s) => ({
                      key: String(s.id),
                      label: s.name ? `${s.name}（${s.host}）` : s.host,
                    })),
                  ]}
                />
              </div>
              <TextField aria-label={t("luaPlugins.form.description")}>
                <Input
                  placeholder={t("luaPlugins.form.descriptionPlaceholder")}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </TextField>
              <div>
                <div className="mb-1.5 text-sm">{t("luaPlugins.form.sourceLabel")}</div>
                <CodeEditor
                  ariaLabel={t("luaPlugins.form.sourceAria")}
                  value={source}
                  onChange={setSource}
                  placeholder={t("luaPlugins.form.sourcePlaceholder")}
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
                {t("luaPlugins.validate.action")}
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
 * Lua 插件试运行弹窗。
 *
 * 请求结构精确对应 luaDryRunRequest（internal/admin/system/luaplugin）：
 * - request.headers 为 map[string]string；query 为不带 ? 的原始查询串
 * - site_id、tls_*、phase、action 由服务端补默认值，不在前端表单展开（YAGNI）
 *
 * 响应为 DryRunBatchResult；decision 内键为 Go 默认 PascalCase（无 json tag）。
 */
function LuaDryRunModal({
  state,
  initialSource,
}: {
  state: ReturnType<typeof useOverlayState>;
  initialSource: string;
}) {
  const [source, setSource] = useState(initialSource);
  const [stage, setStage] = useState<"pre" | "post">("pre");
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/");
  const [query, setQuery] = useState("");
  const [host, setHost] = useState("example.com");
  const [clientIp, setClientIp] = useState("203.0.113.9");
  const [userAgent, setUserAgent] = useState("Mozilla/5.0");
  const [headersText, setHeadersText] = useState("");
  const [body, setBody] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<LuaDryRunResult | null>(null);
  const { t } = useI18n();

  async function handleRun() {
    setRunning(true);
    setResult(null);
    try {
      const res = await apiPost<LuaDryRunResult>("/lua-plugins/dry-run", {
        stage,
        source,
        timeout_ms: 0,
        iterations: 1,
        request: {
          client_ip: clientIp,
          method: method.trim() || "GET",
          path: path.trim() || "/",
          query,
          host,
          user_agent: userAgent,
          headers: parseHeaders(headersText),
          body,
        },
      });
      setResult(res);
    } catch (err) {
      setResult({ error: err instanceof ApiError ? err.message : t("luaPlugins.dryRun.requestFailed") });
    } finally {
      setRunning(false);
    }
  }

  const decision = result?.decision;

  return (
    <Modal state={state}>
      <Modal.Backdrop>
        <Modal.Container size="lg">
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Heading>{t("luaPlugins.dryRun.title")}</Modal.Heading>
              <Modal.CloseTrigger aria-label={t("common.close")} />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <div>
                <div className="mb-1.5 text-sm">{t("luaPlugins.dryRun.sourceLabel")}</div>
                <CodeEditor
                  ariaLabel={t("luaPlugins.dryRun.sourceAria")}
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
                  label={t("luaPlugins.dryRun.stage")}
                  className="w-48"
                  options={STAGE_OPTIONS.map((o) => ({ key: o.key, label: t(o.labelKey) }))}
                />
                <TextField aria-label={t("luaPlugins.dryRun.method")} className="flex-1">
                  <Input placeholder="GET" value={method} onChange={(e) => setMethod(e.target.value)} />
                </TextField>
                <TextField aria-label={t("common.path")} className="flex-1">
                  <Input placeholder="/" value={path} onChange={(e) => setPath(e.target.value)} />
                </TextField>
                <TextField aria-label={t("luaPlugins.dryRun.query")} className="flex-1">
                  <Input
                    placeholder={t("luaPlugins.dryRun.queryPlaceholder")}
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                  />
                </TextField>
              </div>
              <div className="flex gap-3">
                <TextField aria-label="Host" className="flex-1">
                  <Input placeholder="example.com" value={host} onChange={(e) => setHost(e.target.value)} />
                </TextField>
                <TextField aria-label={t("common.clientIp")} className="flex-1">
                  <Input placeholder="203.0.113.9" value={clientIp} onChange={(e) => setClientIp(e.target.value)} />
                </TextField>
                <TextField aria-label="User-Agent" className="flex-1">
                  <Input placeholder="Mozilla/5.0" value={userAgent} onChange={(e) => setUserAgent(e.target.value)} />
                </TextField>
              </div>
              <TextField aria-label={t("luaPlugins.dryRun.headers")}>
                <Input
                  placeholder={t("luaPlugins.dryRun.headersPlaceholder")}
                  value={headersText}
                  onChange={(e) => setHeadersText(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("luaPlugins.dryRun.body")}>
                <Input
                  placeholder={t("luaPlugins.dryRun.bodyPlaceholder")}
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                />
              </TextField>

              {result && (
                <div className="rounded-lg border border-separator p-3 text-sm">
                  {result.error ? (
                    <div className="text-danger">{result.error}</div>
                  ) : result.compile_error ? (
                    <div className="text-danger">
                      {t("luaPlugins.dryRun.compileFailed", { error: result.compile_error })}
                    </div>
                  ) : result.runtime_error ? (
                    <div className="text-danger">
                      {t("luaPlugins.dryRun.runtimeError", { error: result.runtime_error })}
                    </div>
                  ) : (
                    <div className="flex flex-col gap-1.5">
                      <div>
                        {t("luaPlugins.dryRun.decision")}
                        {decision?.Action ? (
                          <span className="text-warning font-medium"> {decision.Action}</span>
                        ) : (
                          <span className="text-muted"> {t("luaPlugins.dryRun.noDecision")}</span>
                        )}
                      </div>
                      {decision?.Message && (
                        <div className="text-muted">
                          {t("luaPlugins.dryRun.message", { message: decision.Message })}
                        </div>
                      )}
                      {decision?.RedirectTo && (
                        <div className="text-muted">
                          {t("luaPlugins.dryRun.redirectTo", { url: decision.RedirectTo })}
                        </div>
                      )}
                      {decision?.StatusCode ? (
                        <div className="text-muted">
                          {t("luaPlugins.dryRun.statusCode", { code: decision.StatusCode })}
                        </div>
                      ) : null}
                      <div className="text-muted">
                        {t("luaPlugins.dryRun.elapsed", { ms: (result.elapsed_ms ?? 0).toFixed(2) })}
                        {result.kv_available
                          ? t("luaPlugins.dryRun.kvAvailable")
                          : t("luaPlugins.dryRun.kvUnavailable")}
                      </div>
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
                {t("luaPlugins.dryRun.run")}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}

export default LuaPluginsClient;
