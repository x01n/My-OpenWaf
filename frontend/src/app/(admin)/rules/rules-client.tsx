"use client";

import { useCallback, useMemo, useState } from "react";
import { useOverlayState, Button, TextField, Input, Chip, TextArea } from "@heroui/react";
import { Plus, Upload, Download, FlaskConical, BookOpen } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useApi, useDebounced, useList } from "@/lib/hooks/use-api";
import type {
  Policy,
  Rule,
  RulePhase,
  RuleTemplate,
  RuleTestRequest,
  RuleTestResult,
  RuleValidateResult,
} from "@/lib/types/rule";
import { formatDateTime, truncate } from "@/lib/utils/format";
import {
  PageHeader,
  Toolbar,
  SimpleSelect,
  SearchInput,
  Pager,
  ErrorState,
  ToggleSwitch,
} from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { FormDialog } from "@/components/ui/dialogs";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { useI18n, type MessageKey } from "@/i18n";
import { ActiveFilterBar, type ActiveFilter } from "@/components/ui/active-filter-bar";

/* ---------- 常量契约（internal/store/policy.go、internal/core/action） ---------- */

type PhaseFilter = "" | RulePhase;

const PHASE_KEYS: Record<RulePhase, MessageKey> = {
  acl: "rules.phase.acl",
  signature: "rules.phase.signature",
  custom: "rules.phase.custom",
};

const PHASE_CHIP_COLOR: Record<RulePhase, "default" | "accent" | "warning"> = {
  acl: "default",
  signature: "accent",
  custom: "warning",
};

/** 动作取值来自 internal/core/action.Type（block/log_only 已被后端归一化，不再提供） */
const ACTION_OPTIONS: { key: string; labelKey: MessageKey }[] = [
  { key: "intercept", labelKey: "action.option.intercept" },
  { key: "drop", labelKey: "action.option.drop" },
  { key: "challenge", labelKey: "action.option.challenge" },
  { key: "captcha_challenge", labelKey: "action.option.captchaChallenge" },
  { key: "shield_challenge", labelKey: "action.option.shieldChallenge" },
  { key: "chain_challenge", labelKey: "action.option.chainChallenge" },
  { key: "redirect", labelKey: "action.option.redirect" },
  { key: "rate_limit", labelKey: "action.option.rateLimit" },
  { key: "observe", labelKey: "action.option.observe" },
  { key: "allow", labelKey: "action.option.allow" },
];

/** 列表短标签：与表单下拉的完整语义文案分离。 */
const ACTION_LABEL_KEYS: Record<string, MessageKey> = {
  intercept: "action.intercept",
  block: "action.block",
  drop: "action.drop",
  challenge: "action.challenge",
  captcha_challenge: "action.captchaChallenge",
  shield_challenge: "action.shieldChallenge",
  chain_challenge: "action.chainChallenge",
  redirect: "action.redirect",
  rate_limit: "action.rateLimit",
  observe: "action.observe",
  allow: "action.allow",
};

/** 动作语义配色：拦截/丢弃=danger、挑战系/限流=warning、放行/观察=success、重定向=info(accent) */
function actionTone(action: string): "danger" | "warning" | "success" | "accent" | "default" {
  switch (action) {
    case "intercept":
    case "block":
    case "drop":
      return "danger";
    case "challenge":
    case "captcha_challenge":
    case "shield_challenge":
    case "chain_challenge":
    case "rate_limit":
      return "warning";
    case "allow":
    case "observe":
      return "success";
    case "redirect":
      return "accent";
    default:
      return "default";
  }
}

/** 挑战系动作：需要展示验证码 / 频次条件字段 */
const CHALLENGE_ACTIONS = new Set([
  "challenge",
  "captcha_challenge",
  "shield_challenge",
  "chain_challenge",
]);

/* ---------- 表单状态 ---------- */

type RuleFormState = {
  name: string;
  policy_id: number;
  phase: RulePhase;
  pattern: string;
  action: string;
  priority: number;
  enabled: boolean;
  status_code: number;
  redirect_to: string;
  captcha_type: string;
  window_seconds: number;
  request_count: number;
  captcha_minutes: number;
};

const EMPTY_FORM: RuleFormState = {
  name: "",
  policy_id: 0,
  phase: "acl",
  pattern: "",
  action: "intercept",
  priority: 100,
  enabled: true,
  status_code: 0,
  redirect_to: "",
  captcha_type: "",
  window_seconds: 0,
  request_count: 0,
  captcha_minutes: 0,
};

const EMPTY_TEST: RuleTestRequest = {
  pattern: "",
  client_ip: "",
  path: "",
  query: "",
  headers: "",
  method: "",
  body: "",
};

function toInt(v: string): number {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

/* ---------- 主组件 ---------- */

function RulesClient() {
  const { t } = useI18n();
  const [qInput, setQInput] = useState("");
  const q = useDebounced(qInput, 350);
  const [phaseFilter, setPhaseFilter] = useState<PhaseFilter>("");
  const [editing, setEditing] = useState<Rule | null>(null);
  const [form, setForm] = useState<RuleFormState>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const formState = useOverlayState();
  const testState = useOverlayState();
  const templatesState = useOverlayState();
  const importState = useOverlayState();

  const { items, total, page, pageSize, setPage, loading, error, reload } = useList<Rule>("/rules", {
    q: q || undefined,
  });

  const policies = useApi<ListResponse<Policy>>(
    useCallback(() => apiGet<ListResponse<Policy>>("/policies", { page: 1, page_size: 200 }), []),
  );

  const templates = useApi<{ templates: RuleTemplate[]; total: number }>(
    useCallback(() => apiGet<{ templates: RuleTemplate[]; total: number }>("/rules/templates"), []),
    [],
    { enabled: false },
  );

  /** phase 后端列表接口不支持筛选，对当前页做前端过滤 */
  const filtered = useMemo(() => {
    if (!phaseFilter) return items;
    return items.filter((it) => it.phase === phaseFilter);
  }, [items, phaseFilter]);

  /**
   * 已激活筛选条件清单（Cloudflare 风格可见 chips）。
   * phase + q；只在有值时展示短标签。
   */
  const activeFilters = useMemo<ActiveFilter[]>(() => {
    const items: ActiveFilter[] = [];
    const add = (key: string, label: string, value: string) => {
      if (value && value.trim() !== "") {
        items.push({ key, label, value: value.trim() });
      }
    };

    if (phaseFilter) {
      const phaseLabel = PHASE_KEYS[phaseFilter as RulePhase]
        ? t(PHASE_KEYS[phaseFilter as RulePhase])
        : phaseFilter;
      add("phase", t("rules.cond.phase"), phaseLabel);
    }
    add("q", t("rules.cond.q"), q.trim());

    return items;
  }, [t, phaseFilter, q]);

  /** 单个筛选的清除器表 */
  const FILTER_RESETTERS: Record<string, () => void> = {
    phase: () => setPhaseFilter(""),
    q: () => setQInput(""),
  };

  function clearFilter(key: string) {
    FILTER_RESETTERS[key]?.();
  }

  function clearAllFilters() {
    Object.values(FILTER_RESETTERS).forEach((reset) => reset());
  }

  const policyName = useCallback(
    (id: number) => policies.data?.items.find((p) => p.id === id)?.name ?? t("rules.policyFallback", { id }),
    [policies.data, t],
  );

  const columns: DataTableColumn<Rule>[] = [
    {
      header: t("rules.col.name"),
      render: (it) => (
        <div>
          <div className="text-sm font-medium">{it.name || "-"}</div>
          <div className="text-muted text-xs">{policyName(it.policy_id)}</div>
        </div>
      ),
    },
    {
      header: t("rules.col.phase"),
      render: (it) => (
        <Chip size="sm" variant="soft" color={PHASE_CHIP_COLOR[it.phase] ?? "default"}>
          {PHASE_KEYS[it.phase] ? t(PHASE_KEYS[it.phase]) : it.phase}
        </Chip>
      ),
    },
    {
      header: t("rules.col.pattern"),
      className: "w-[320px]",
      render: (it) => (
        <span className="block max-w-[320px] truncate font-mono text-xs" title={it.pattern}>
          {truncate(it.pattern, 60)}
        </span>
      ),
    },
    {
      header: t("rules.col.action"),
      render: (it) => (
        <Chip size="sm" variant="soft" color={actionTone(it.action)}>
          {ACTION_LABEL_KEYS[it.action] ? t(ACTION_LABEL_KEYS[it.action]) : it.action}
        </Chip>
      ),
    },
    {
      header: t("rules.col.priority"),
      render: (it) => <span className="tabular text-sm">{it.priority}</span>,
    },
    {
      header: t("rules.col.status"),
      render: (it) =>
        it.enabled ? (
          <Chip size="sm" variant="soft" color="success">
            {t("common.enabled")}
          </Chip>
        ) : (
          <Chip size="sm" variant="soft" color="default">
            {t("common.disabled")}
          </Chip>
        ),
    },
    {
      header: t("rules.col.updatedAt"),
      render: (it) => <span className="text-muted text-xs">{formatDateTime(it.updated_at)}</span>,
    },
    {
      header: t("rules.col.actions"),
      render: (it) => (
        <div className="flex items-center gap-1.5">
          <Button
            size="sm"
            variant="outline"
            onPress={() => {
              setEditing(it);
              setForm({
                name: it.name,
                policy_id: it.policy_id,
                phase: it.phase,
                pattern: it.pattern,
                action: it.action,
                priority: it.priority,
                enabled: it.enabled,
                status_code: it.status_code ?? 0,
                redirect_to: it.redirect_to ?? "",
                captcha_type: it.captcha_type ?? "",
                window_seconds: it.window_seconds ?? 0,
                request_count: it.request_count ?? 0,
                captcha_minutes: it.captcha_minutes ?? 0,
              });
              formState.open();
            }}
          >
            {t("common.edit")}
          </Button>
          <ConfirmButton
            confirmText={t("rules.deleteConfirm", { name: it.name || `#${it.id}` })}
            successText={t("rules.deleted")}
            onConfirm={async () => {
              await apiPost(`/rules/${it.id}/delete`);
              reload();
            }}
          >
            {t("common.delete")}
          </ConfirmButton>
        </div>
      ),
    },
  ];

  function openCreate() {
    setEditing(null);
    setForm(EMPTY_FORM);
    formState.open();
  }

  /** 用模板填充新建表单（模板库 / 测试弹窗共用） */
  function applyTemplate(tpl: RuleTemplate) {
    setEditing(null);
    setForm({
      ...EMPTY_FORM,
      pattern: tpl.pattern,
      phase: (tpl.phase as RulePhase) || "custom",
      action: tpl.action || "intercept",
      name: tpl.name,
    });
    templatesState.close();
    formState.open();
  }

  async function handleSave() {
    if (!form.name.trim()) {
      showError(t("rules.saveFailed"), t("rules.error.name"));
      return;
    }
    if (form.policy_id <= 0) {
      showError(t("rules.saveFailed"), t("rules.error.policy"));
      return;
    }
    if (!form.pattern.trim()) {
      showError(t("rules.saveFailed"), t("rules.error.pattern"));
      return;
    }
    if (form.action === "allow" && form.phase !== "acl") {
      showError(t("rules.saveFailed"), t("rules.error.allowPhase"));
      return;
    }
    if (form.action === "redirect" && !form.redirect_to.trim()) {
      showError(t("rules.saveFailed"), t("rules.error.redirect"));
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        policy_id: form.policy_id,
        phase: form.phase,
        pattern: form.pattern.trim(),
        action: form.action,
        priority: toInt(String(form.priority)),
        enabled: form.enabled,
        status_code: toInt(String(form.status_code)),
        redirect_to: form.redirect_to.trim(),
        captcha_type: form.captcha_type.trim(),
        window_seconds: toInt(String(form.window_seconds)),
        request_count: toInt(String(form.request_count)),
        captcha_minutes: toInt(String(form.captcha_minutes)),
      };
      if (editing) {
        await apiPost(`/rules/${editing.id}/update`, payload);
      } else {
        await apiPost("/rules", payload);
      }
      showSuccess(t("rules.saved"));
      formState.close();
      reload();
    } catch (err) {
      showError(t("rules.saveFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  async function handleExport() {
    try {
      const data = await apiGet<{ rules: Rule[] }>("/rules/export");
      const rules = data.rules ?? [];
      const blob = new Blob([JSON.stringify(rules, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `waf-rules-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showSuccess(t("rules.export.done", { count: rules.length }));
    } catch (err) {
      showError(t("rules.export.failed"), err instanceof ApiError ? err.message : undefined);
    }
  }

  /* ---------- 导入 ---------- */

  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);

  async function handleImportFile(file: File) {
    try {
      setImportText(await file.text());
    } catch {
      showError(t("rules.import.readFailed"));
    }
  }

  async function handleImport() {
    let rules: unknown[];
    try {
      const parsed = JSON.parse(importText) as unknown;
      const arr = Array.isArray(parsed) ? parsed : (parsed as { rules?: unknown[] })?.rules;
      if (!Array.isArray(arr) || arr.length === 0) {
        throw new Error(t("rules.import.missingArray"));
      }
      rules = arr;
    } catch (e) {
      showError(t("rules.import.failed"), e instanceof Error ? e.message : t("rules.import.parseFailed"));
      return;
    }
    setImporting(true);
    try {
      const res = await apiPost<{ imported: number; total: number }>("/rules/import", { rules });
      showSuccess(t("rules.import.done", { imported: res.imported, total: res.total }));
      importState.close();
      setImportText("");
      reload();
    } catch (err) {
      showError(t("rules.import.failed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setImporting(false);
    }
  }

  /* ---------- 规则测试 ---------- */

  const [testForm, setTestForm] = useState<RuleTestRequest>(EMPTY_TEST);
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);
  const [validateResult, setValidateResult] = useState<RuleValidateResult | null>(null);
  const [testRunning, setTestRunning] = useState(false);

  function openTest() {
    setTestForm((f) => (f.pattern ? f : { ...f, pattern: form.pattern }));
    setTestResult(null);
    setValidateResult(null);
    testState.open();
    void templates.reload();
  }

  async function handleTest() {
    if (!testForm.pattern.trim()) {
      showError(t("rules.test.failed"), t("rules.error.pattern"));
      return;
    }
    setTestRunning(true);
    setTestResult(null);
    setValidateResult(null);
    try {
      setTestResult(
        await apiPost<RuleTestResult>("/rules/test", {
          ...testForm,
          pattern: testForm.pattern.trim(),
        }),
      );
    } catch (err) {
      showError(t("rules.test.failed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setTestRunning(false);
    }
  }

  async function handleValidate() {
    if (!testForm.pattern.trim()) {
      showError(t("rules.test.validateFailed"), t("rules.error.pattern"));
      return;
    }
    setTestRunning(true);
    setTestResult(null);
    setValidateResult(null);
    try {
      setValidateResult(
        await apiPost<RuleValidateResult>("/rules/validate", { pattern: testForm.pattern.trim() }),
      );
    } catch (err) {
      showError(t("rules.test.validateFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setTestRunning(false);
    }
  }

  const templateItems = templates.data?.templates ?? [];
  const [selectedTemplate, setSelectedTemplate] = useState("");

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t("rules.title")}
        description={t("rules.description")}
        actions={
          <>
            <Button variant="ghost" onPress={openTest}>
              <FlaskConical className="size-4" /> {t("rules.test")}
            </Button>
            <Button
              variant="outline"
              onPress={() => {
                templatesState.open();
                void templates.reload();
              }}
            >
              <BookOpen className="size-4" /> {t("rules.templates")}
            </Button>
            <Button variant="outline" onPress={handleExport}>
              <Download className="size-4" /> {t("rules.export")}
            </Button>
            <Button variant="outline" onPress={importState.open}>
              <Upload className="size-4" /> {t("rules.import")}
            </Button>
            <Button variant="primary" onPress={openCreate}>
              <Plus className="size-4" /> {t("rules.create")}
            </Button>
          </>
        }
      />

      <Toolbar>
        <SimpleSelect<PhaseFilter>
          value={phaseFilter}
          onChange={setPhaseFilter}
          label={t("rules.filter.phase")}
          options={[
            { key: "", label: t("rules.phase.all") },
            { key: "acl", label: t("rules.phase.acl") },
            { key: "signature", label: t("rules.phase.signature") },
            { key: "custom", label: t("rules.phase.custom") },
          ]}
        />
        <SearchInput value={qInput} onChange={setQInput} placeholder={t("rules.search")} />
      </Toolbar>

      <ActiveFilterBar
        filters={activeFilters}
        onClear={clearFilter}
        onClearAll={clearAllFilters}
      />

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : (
        <DataTable
          ariaLabel={t("rules.title")}
          columns={columns}
          rows={filtered}
          loading={loading}
          emptyMessage={t("rules.empty")}
        />
      )}
      <Pager page={page} pageSize={pageSize} total={total} onPageChange={setPage} />

      {/* 新建 / 编辑弹窗 */}
      <FormDialog
        state={formState}
        title={editing ? t("rules.form.edit", { id: editing.id }) : t("rules.form.create")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onPress={formState.close}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" isPending={saving} onPress={handleSave}>
              {t("common.save")}
            </Button>
          </>
        }
      >
        <TextField aria-label={t("rules.form.name")} isRequired>
          <Input
            placeholder={t("rules.form.namePlaceholder")}
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          />
        </TextField>
        <SimpleSelect<string>
          value={form.policy_id > 0 ? String(form.policy_id) : ""}
          onChange={(key) => setForm((f) => ({ ...f, policy_id: toInt(key) }))}
          label={t("rules.form.policy")}
          className="w-full"
          options={[
            { key: "", label: t("rules.form.policyPlaceholder") },
            ...(policies.data?.items ?? []).map((p) => ({ key: String(p.id), label: p.name })),
          ]}
        />
        <div className="grid grid-cols-2 gap-3">
          <SimpleSelect<RulePhase>
            value={form.phase}
            onChange={(phase) =>
              setForm((f) => ({
                ...f,
                phase,
                action: f.action === "allow" && phase !== "acl" ? "intercept" : f.action,
              }))
            }
            label={t("rules.form.phase")}
            className="w-full"
            options={[
              { key: "acl", label: t("rules.phase.aclFull") },
              { key: "signature", label: t("rules.phase.signatureFull") },
              { key: "custom", label: t("rules.phase.customFull") },
            ]}
          />
          <SimpleSelect<string>
            value={form.action}
            onChange={(action) => setForm((f) => ({ ...f, action }))}
            label={t("rules.form.action")}
            className="w-full"
            options={ACTION_OPTIONS.map((o) => ({ key: o.key, label: t(o.labelKey) }))}
          />
        </div>
        <TextArea
          aria-label={t("rules.form.pattern")}
          placeholder={t("rules.form.patternPlaceholder")}
          value={form.pattern}
          onChange={(e) => setForm((f) => ({ ...f, pattern: e.target.value }))}
          className="min-h-[96px] font-mono text-xs"
        />
        <div className="grid grid-cols-2 gap-3">
          <TextField aria-label={t("rules.form.priority")}>
            <Input
              type="number"
              placeholder={t("rules.form.priorityPlaceholder")}
              value={String(form.priority)}
              onChange={(e) => setForm((f) => ({ ...f, priority: toInt(e.target.value) }))}
            />
          </TextField>
          <div className="flex items-center">
            <ToggleSwitch
              isSelected={form.enabled}
              onChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
            >
              {t("rules.form.enabled")}
            </ToggleSwitch>
          </div>
        </div>

        {form.action === "redirect" && (
          <div className="bg-warning-soft grid grid-cols-2 gap-3 rounded-xl p-3">
            <TextField aria-label={t("common.statusCode")}>
              <Input
                type="number"
                placeholder={t("rules.form.redirectStatus")}
                value={String(form.status_code)}
                onChange={(e) => setForm((f) => ({ ...f, status_code: toInt(e.target.value) }))}
              />
            </TextField>
            <TextField aria-label={t("action.option.redirect")}>
              <Input
                placeholder={t("rules.form.redirectTo")}
                value={form.redirect_to}
                onChange={(e) => setForm((f) => ({ ...f, redirect_to: e.target.value }))}
              />
            </TextField>
          </div>
        )}

        {CHALLENGE_ACTIONS.has(form.action) && (
          <div className="bg-warning-soft grid grid-cols-2 gap-3 rounded-xl p-3">
            <TextField aria-label={t("action.captcha")}>
              <Input
                placeholder={t("rules.form.captchaType")}
                value={form.captcha_type}
                onChange={(e) => setForm((f) => ({ ...f, captcha_type: e.target.value }))}
              />
            </TextField>
            <TextField aria-label={t("rules.form.captchaMinutes")}>
              <Input
                type="number"
                placeholder={t("rules.form.captchaMinutes")}
                value={String(form.captcha_minutes)}
                onChange={(e) => setForm((f) => ({ ...f, captcha_minutes: toInt(e.target.value) }))}
              />
            </TextField>
            <TextField aria-label={t("rules.form.windowSeconds")}>
              <Input
                type="number"
                placeholder={t("rules.form.windowSeconds")}
                value={String(form.window_seconds)}
                onChange={(e) => setForm((f) => ({ ...f, window_seconds: toInt(e.target.value) }))}
              />
            </TextField>
            <TextField aria-label={t("rules.form.requestCount")}>
              <Input
                type="number"
                placeholder={t("rules.form.requestCount")}
                value={String(form.request_count)}
                onChange={(e) => setForm((f) => ({ ...f, request_count: toInt(e.target.value) }))}
              />
            </TextField>
          </div>
        )}
      </FormDialog>

      {/* 模板库弹窗 */}
      <FormDialog
        state={templatesState}
        title={t("rules.template.title")}
        description={t("rules.template.description")}
        size="lg"
      >
        {templates.loading ? (
          <div className="text-muted py-4 text-center text-sm">{t("rules.template.loading")}</div>
        ) : templateItems.length === 0 ? (
          <div className="text-muted py-4 text-center text-sm">{t("rules.template.empty")}</div>
        ) : (
          <div className="flex max-h-[60vh] flex-col gap-2 overflow-y-auto">
            {templateItems.map((tpl) => (
              <div key={`${tpl.category}-${tpl.name}`} className="border-separator border-b pb-2 last:border-0">
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-sm font-medium">
                      {tpl.name}
                      <Chip size="sm" variant="tertiary" className="ml-2">
                        {tpl.category}
                      </Chip>
                    </div>
                    <div className="text-muted mt-0.5 text-xs">{tpl.description}</div>
                    <div className="mt-1 truncate font-mono text-xs" title={tpl.pattern}>
                      {tpl.pattern}
                    </div>
                  </div>
                  <Button size="sm" variant="outline" onPress={() => applyTemplate(tpl)}>
                    {t("rules.template.use")}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </FormDialog>

      {/* 导入弹窗 */}
      <FormDialog
        state={importState}
        title={t("rules.import.title")}
        description={t("rules.import.description")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onPress={importState.close}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" isPending={importing} isDisabled={!importText.trim()} onPress={handleImport}>
              {t("rules.import.start")}
            </Button>
          </>
        }
      >
        <label className="text-muted flex items-center gap-2 text-sm">
          <input
            type="file"
            accept=".json,application/json"
            className="text-xs"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleImportFile(file);
              e.target.value = "";
            }}
          />
          {t("rules.import.choose")}
        </label>
        <TextArea
          aria-label={t("rules.import.title")}
          placeholder='[{"name":"...","policy_id":1,"phase":"acl","pattern":"block_ip:1.2.3.4","action":"intercept","priority":100,"enabled":true}]'
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          className="min-h-[200px] font-mono text-xs"
        />
      </FormDialog>

      {/* 规则测试弹窗 */}
      <FormDialog
        state={testState}
        title={t("rules.test.title")}
        description={t("rules.test.description")}
        size="lg"
        footer={
          <>
            <Button variant="ghost" onPress={testState.close}>
              {t("common.close")}
            </Button>
            <Button variant="outline" isPending={testRunning} onPress={handleValidate}>
              {t("rules.test.validate")}
            </Button>
            <Button variant="primary" isPending={testRunning} onPress={handleTest}>
              {t("rules.test.run")}
            </Button>
          </>
        }
      >
        {templateItems.length > 0 && (
          <SimpleSelect<string>
            value={selectedTemplate}
            onChange={(name) => {
              setSelectedTemplate(name);
              const tpl = templateItems.find((t) => t.name === name);
              if (tpl) setTestForm((f) => ({ ...f, pattern: tpl.pattern }));
            }}
            label={t("rules.test.template")}
            className="w-full"
            options={[
              { key: "", label: t("rules.test.templatePlaceholder") },
              ...templateItems.map((tpl) => ({
                key: tpl.name,
                label: t("rules.test.templateOption", { name: tpl.name, category: tpl.category }),
              })),
            ]}
          />
        )}
        <TextArea
          aria-label={t("rules.form.pattern")}
          placeholder={t("rules.form.namePlaceholder")}
          value={testForm.pattern}
          onChange={(e) => setTestForm((f) => ({ ...f, pattern: e.target.value }))}
          className="min-h-[80px] font-mono text-xs"
        />
        <div className="grid grid-cols-2 gap-3">
          <TextField aria-label={t("rules.test.clientIp")}>
            <Input
              placeholder={t("rules.test.clientIp")}
              value={testForm.client_ip ?? ""}
              onChange={(e) => setTestForm((f) => ({ ...f, client_ip: e.target.value }))}
            />
          </TextField>
          <TextField aria-label={t("common.method")}>
            <Input
              placeholder={t("rules.test.method")}
              value={testForm.method ?? ""}
              onChange={(e) => setTestForm((f) => ({ ...f, method: e.target.value }))}
            />
          </TextField>
          <TextField aria-label={t("common.path")}>
            <Input
              placeholder={t("rules.test.path")}
              value={testForm.path ?? ""}
              onChange={(e) => setTestForm((f) => ({ ...f, path: e.target.value }))}
            />
          </TextField>
          <TextField aria-label={t("rules.test.query")}>
            <Input
              placeholder={t("rules.test.query")}
              value={testForm.query ?? ""}
              onChange={(e) => setTestForm((f) => ({ ...f, query: e.target.value }))}
            />
          </TextField>
        </div>
        <TextArea
          aria-label={t("rules.test.headers")}
          placeholder={t("rules.test.headers")}
          value={testForm.headers ?? ""}
          onChange={(e) => setTestForm((f) => ({ ...f, headers: e.target.value }))}
          className="min-h-[60px] font-mono text-xs"
        />
        <TextArea
          aria-label={t("rules.test.body")}
          placeholder={t("rules.test.body")}
          value={testForm.body ?? ""}
          onChange={(e) => setTestForm((f) => ({ ...f, body: e.target.value }))}
          className="min-h-[60px] font-mono text-xs"
        />

        {validateResult && (
          <div className="border-separator rounded-xl border p-3 text-sm">
            <Chip size="sm" variant="soft" color={validateResult.valid ? "success" : "danger"}>
              {validateResult.valid ? t("rules.test.valid") : t("rules.test.invalid")}
            </Chip>
            {validateResult.message && (
              <div className="text-muted mt-1.5 text-xs">{validateResult.message}</div>
            )}
          </div>
        )}
        {testResult && (
          <div className="border-separator rounded-xl border p-3 text-sm">
            <Chip size="sm" variant="soft" color={testResult.matched ? "success" : "default"}>
              {testResult.matched ? t("rules.test.matched") : t("rules.test.unmatched")}
            </Chip>
            <div className="text-muted mt-1.5 text-xs">
              {t("rules.test.kind")}：<span className="font-mono">{testResult.kind}</span>
              {testResult.arg && (
                <>
                  {" · "}
                  {t("rules.test.arg")}：<span className="font-mono">{testResult.arg}</span>
                </>
              )}
            </div>
          </div>
        )}
      </FormDialog>
    </div>
  );
}

export default RulesClient;
