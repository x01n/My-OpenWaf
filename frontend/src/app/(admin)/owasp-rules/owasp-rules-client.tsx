"use client";

/**
 * OWASP 规则页面客户端。
 *
 * 数据来源（internal/admin/router.go）：
 * - GET  /api/v1/owasp-rules、/api/v1/owasp-rules/stats（router.go:224-225）
 * - GET  /api/v1/policies/:policyId/owasp-rules、…/stats（router.go:226-227）
 * - POST /api/v1/policies/:policyId/owasp-rules/:id|reset|batch（router.go:326-328）
 * - POST /api/v1/owasp-rules/batch（批量与全量重置，policy_id 由请求体指定）
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, Checkbox, Chip, useOverlayState } from "@heroui/react";
import { RefreshCw, RotateCcw, ListChecks } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useApi, useDebounced, useList } from "@/lib/hooks/use-api";
import type { Policy } from "@/lib/types/rule";
import type { OWASPRule, OWASPRuleStats } from "@/lib/types/owasp";
import { useI18n } from "@/i18n";
import { PageHeader, Toolbar, SimpleSelect, SearchInput, Pager, ErrorState, StatCard, StatusChip } from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { OWASPRuleDrawer } from "./owasp-rule-drawer";
import { OWASPBatchDialog } from "./owasp-batch-dialog";
import { ActiveFilterBar, type ActiveFilter } from "@/components/ui/active-filter-bar";
import {
  ACTION_LABELS,
  OWASP_CATEGORY_LABELS,
  OWASP_CATEGORY_OPTIONS,
  localizeOptions,
  SENSITIVITY_LABELS,
  translateLabel,
} from "@/lib/utils/rule-constants";

const PAGE_SIZE = 50;

function OWASPRulesClient() {
  const { t } = useI18n();

  /* ---------- 策略与过滤 ---------- */
  const [policyId, setPolicyId] = useState(0);
  const [category, setCategory] = useState("");
  const [page, setPage] = useState(1);
  const [qInput, setQInput] = useState("");
  const q = useDebounced(qInput, 350);

  /* ---------- 选中与弹层 ---------- */
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [drawerRule, setDrawerRule] = useState<OWASPRule | null>(null);

  const drawerState = useOverlayState();
  const batchState = useOverlayState();

  const policies = useApi<ListResponse<Policy>>(
    useCallback(() => apiGet<ListResponse<Policy>>("/policies", { page: 1, page_size: 200 }), []),
  );

  /** 默认策略来自 policies.is_default（internal/store/policy.go），缺省取首个 */
  useEffect(() => {
    if (policyId !== 0 || !policies.data?.items.length) return;
    const list = policies.data.items;
    const preferred = list.find((p) => p.is_default) ?? list[0];
    setPolicyId(preferred.id);
  }, [policyId, policies.data]);

  const listPath = policyId > 0 ? `/policies/${policyId}/owasp-rules` : "/owasp-rules";
  const statsPath = policyId > 0 ? `/policies/${policyId}/owasp-rules/stats` : "/owasp-rules/stats";

  const list = useList<OWASPRule>(
    listPath,
    {
      category: category || undefined,
      q: q || undefined,
      include_grouped: "false",
    },
    PAGE_SIZE,
  );

  const stats = useApi<OWASPRuleStats>(
    useCallback(() => apiGet<OWASPRuleStats>(statsPath), [statsPath]),
    [statsPath],
    { enabled: true },
  );

  const items = list.items;

  const refreshAll = () => {
    void list.reload();
    void stats.reload();
  };

  /* ---------- 选择 ---------- */
  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const allSelected = items.length > 0 && items.every((it) => selected.has(it.id));

  /* ---------- 类别选项（来自真实聚合，全量口径） ---------- */
  const categoryOptions = useMemo(() => {
    const byCategory = stats.data?.by_category ?? {};
    const keys = Object.keys(byCategory).sort((a, b) => (byCategory[b] ?? 0) - (byCategory[a] ?? 0));
    if (keys.length === 0) return localizeOptions(OWASP_CATEGORY_OPTIONS, t);
    return [
      { key: "", label: t("owaspRules.filter.allCategories") },
      ...keys.map((key) => ({
        key,
        label: t("owaspRules.categoryWithCount", {
          name: translateLabel(t, OWASP_CATEGORY_LABELS, key),
          count: byCategory[key],
        }),
      })),
    ];
  }, [stats.data, t]);

  const categoryEntries = Object.entries(stats.data?.by_category ?? {}).sort(
    (a, b) => b[1] - a[1],
  );

  /**
   * 已激活筛选条件清单（Cloudflare 风格可见 chips）。
   * policy + category + q；只在有值时展示短标签。
   */
  const activeFilters = useMemo<ActiveFilter[]>(() => {
    const items: ActiveFilter[] = [];
    const add = (key: string, label: string, value: string) => {
      if (value && value.trim() !== "") {
        items.push({ key, label, value: value.trim() });
      }
    };

    // 策略：0 表示默认策略
    if (policyId > 0) {
      const p = policies.data?.items.find((pp) => pp.id === policyId);
      const val = p?.name || t("owaspRules.filter.policyFallback", { id: policyId });
      add("policy", t("owaspRules.cond.policy"), val);
    } else if (policies.data?.items.length) {
      // 显式展示“默认策略”
      add("policy", t("owaspRules.cond.policy"), t("owaspRules.defaultPolicy"));
    }

    if (category) {
      const val = translateLabel(t, OWASP_CATEGORY_LABELS, category) || category;
      add("category", t("owaspRules.cond.category"), val);
    }

    add("q", t("owaspRules.cond.q"), q.trim());

    return items;
  }, [t, policyId, category, q, policies.data]);

  /** 单个筛选的清除器表 */
  const FILTER_RESETTERS: Record<string, () => void> = {
    policy: () => {
      setPolicyId(0);
      setPage(1);
    },
    category: () => {
      setCategory("");
      setPage(1);
    },
    q: () => {
      setQInput("");
      setPage(1);
    },
  };

  function clearFilter(key: string) {
    FILTER_RESETTERS[key]?.();
  }

  function clearAllFilters() {
    Object.values(FILTER_RESETTERS).forEach((reset) => reset());
  }

  /* ---------- 表格 ---------- */
  const columns: DataTableColumn<OWASPRule>[] = [
    {
      header: t("owaspRules.col.select"),
      className: "w-10",
      render: (it) => (
        <Checkbox
          aria-label={t("owaspRules.selectAria", { name: it.name })}
          isSelected={selected.has(it.id)}
          onChange={() => toggleSelect(it.id)}
        >
          <Checkbox.Content>
            <Checkbox.Control>
              <Checkbox.Indicator />
            </Checkbox.Control>
          </Checkbox.Content>
        </Checkbox>
      ),
    },
    {
      header: t("owaspRules.col.rule"),
      className: "min-w-[240px]",
      render: (it) => (
        <div>
          <div className="text-sm font-medium">{it.name || "-"}</div>
          <div className="text-muted font-mono text-xs break-all">{it.id}</div>
        </div>
      ),
    },
    {
      header: t("owaspRules.col.category"),
      className: "min-w-[132px] whitespace-nowrap",
      render: (it) => (
        <Chip size="sm" variant="soft">
          {translateLabel(t, OWASP_CATEGORY_LABELS, it.category)}
        </Chip>
      ),
    },
    {
      header: t("owaspRules.col.score"),
      className: "min-w-[64px] whitespace-nowrap",
      render: (it) => <span className="tabular text-sm">{it.score}</span>,
    },
    {
      header: t("owaspRules.col.status"),
      className: "min-w-[88px] whitespace-nowrap",
      render: (it) => (
        <div className="flex flex-wrap items-center gap-1.5">
          <StatusChip tone={it.enabled ? "success" : "neutral"}>
            {it.enabled ? t("common.enabled") : t("common.disabled")}
          </StatusChip>
          {it.overridden && <StatusChip tone="info">{t("owaspRules.overridden")}</StatusChip>}
        </div>
      ),
    },
    {
      header: t("owaspRules.col.action"),
      className: "min-w-[88px] whitespace-nowrap",
      render: (it) => (
        <span className="text-sm">{translateLabel(t, ACTION_LABELS, it.action)}</span>
      ),
    },
    {
      header: t("owaspRules.col.sensitivity"),
      className: "min-w-[92px] whitespace-nowrap",
      render: (it) => (
        <span className="text-muted text-xs">
          {it.sensitivity
            ? (translateLabel(t, SENSITIVITY_LABELS, it.sensitivity))
            : (it.default_sensitivity || "-")}
        </span>
      ),
    },
    {
      header: t("owaspRules.col.whitelist"),
      className: "min-w-[96px] whitespace-nowrap",
      render: (it) => (
        <span className="text-muted tabular text-xs">
          {(it.whitelist ?? []).length > 0
            ? t("owaspRules.whitelistCount", { count: it.whitelist?.length ?? 0 })
            : "-"}
        </span>
      ),
    },
    {
      header: t("common.actions"),
      className: "min-w-[200px] whitespace-nowrap",
      render: (it) => (
        <div className="flex flex-nowrap items-center gap-1.5">
          <Button
            size="sm"
            variant="outline"
            onPress={() => {
              setDrawerRule(it);
              drawerState.open();
            }}
          >
            {t("owaspRules.configure")}
          </Button>
          <ConfirmButton
            title={t("owaspRules.resetTitle")}
            confirmText={t("owaspRules.resetConfirm", { name: it.name })}
            successText={t("owaspRules.resetSuccess")}
            isDisabled={!it.overridden}
            onConfirm={async () => {
              await apiPost(`/policies/${policyId}/owasp-rules/${it.id}/reset`);
              refreshAll();
            }}
          >
            {t("owaspRules.reset")}
          </ConfirmButton>
        </div>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t("owaspRules.title")}
        description={t("owaspRules.description")}
        actions={
          <Button
            size="sm"
            variant="ghost"
            onPress={() => {
              void list.reload();
              void stats.reload();
            }}
          >
            <RefreshCw className="size-3.5" /> {t("common.refresh")}
          </Button>
        }
      />

      {/* 统计条 */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label={t("owaspRules.stats.total")} value={stats.data?.total ?? 0} />
        <StatCard label={t("owaspRules.stats.enabled")} value={stats.data?.enabled_count ?? 0} tone="success" />
        <StatCard label={t("owaspRules.stats.disabled")} value={stats.data?.disabled_count ?? 0} />
        <StatCard
          label={t("owaspRules.stats.policy")}
          value={policyId > 0 ? `#${policyId}` : t("owaspRules.defaultPolicy")}
        />
      </div>

      {/* 类别分布 */}
      <div className="bg-surface rounded-xl border border-separator p-4">
        <div className="text-muted mb-2 text-xs">{t("owaspRules.categoryDistribution")}</div>
        {stats.error ? (
          <div className="text-danger text-sm">{stats.error}</div>
        ) : categoryEntries.length === 0 ? (
          <div className="text-muted text-sm">{t("common.empty")}</div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {categoryEntries.map(([key, count]) => (
              <div key={key}>
                <div className="mb-1 flex items-center justify-between text-xs">
                  <span>{translateLabel(t, OWASP_CATEGORY_LABELS, key)}</span>
                  <span className="tabular text-muted">{count}</span>
                </div>
                <div className="bg-default h-2 w-full overflow-hidden rounded-full">
                  <div
                    className="bg-accent h-full rounded-full"
                    style={{
                      width: `${stats.data && stats.data.total > 0 ? Math.max(2, (count / stats.data.total) * 100) : 0}%`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 工具栏 */}
      <Toolbar>
        <SimpleSelect<string>
          value={policyId > 0 ? String(policyId) : ""}
          onChange={(key) => {
            setPolicyId(Number(key) || 0);
            setPage(1);
            setSelected(new Set());
          }}
          label={t("owaspRules.filter.policy")}
          className="w-48"
          options={[
            {
              key: "",
              label: policies.loading ? t("common.loading") : t("owaspRules.defaultPolicy"),
            },
            ...(policies.data?.items ?? []).map((p) => ({
              key: String(p.id),
              label: `${p.name || t("owaspRules.filter.policyFallback", { id: p.id })}${
                p.is_default ? t("owaspRules.filter.defaultSuffix") : ""
              }`,
            })),
          ]}
        />
        <SimpleSelect<string>
          value={category}
          onChange={(key) => {
            setCategory(key);
            setPage(1);
          }}
          label={t("owaspRules.filter.category")}
          className="w-48"
          options={categoryOptions}
        />
        <SearchInput
          value={qInput}
          onChange={(v) => {
            setQInput(v);
            setPage(1);
          }}
          placeholder={t("owaspRules.filter.search")}
        />
      </Toolbar>

      <ActiveFilterBar
        filters={activeFilters}
        onClear={clearFilter}
        onClearAll={clearAllFilters}
      />

      {/* 批量操作 */}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant="ghost"
          isDisabled={items.length === 0}
          onPress={() => {
            setSelected((prev) => {
              if (allSelected) return new Set();
              const next = new Set(prev);
              for (const it of items) next.add(it.id);
              return next;
            });
          }}
        >
          <ListChecks className="size-3.5" />{" "}
          {allSelected ? t("owaspRules.batch.deselectAll") : t("owaspRules.batch.selectAll")}
        </Button>
        <Button
          size="sm"
          variant="outline"
          isDisabled={selected.size === 0}
          onPress={batchState.open}
        >
          {t("owaspRules.batch.open", { count: selected.size })}
        </Button>
        <ConfirmButton
          title={t("owaspRules.restoreDefaults")}
          confirmText={t("owaspRules.restoreConfirm", {
            id: policyId > 0 ? `#${policyId}` : t("owaspRules.defaultPolicy"),
          })}
          successText={t("owaspRules.restoreSuccess")}
          isDisabled={policyId <= 0}
          onConfirm={async () => {
            const res = await apiPost<{ updated: number }>("/owasp-rules/batch", {
              policy_id: policyId,
              reset_all: true,
            });
            setSelected(new Set());
            refreshAll();
            showSuccess(t("owaspRules.cleared", { count: res.updated ?? 0 }));
          }}
        >
          <RotateCcw className="size-3.5" /> {t("owaspRules.restoreDefaults")}
        </ConfirmButton>
        <span className="text-muted text-xs">{t("owaspRules.hint")}</span>
      </div>

      {list.error ? (
        <ErrorState message={list.error} onRetry={list.reload} />
      ) : (
        <DataTable
          ariaLabel={t("owaspRules.listAria")}
          columns={columns}
          rows={items}
          loading={list.loading}
          emptyMessage={t("owaspRules.empty")}
        />
      )}
      <Pager page={page} pageSize={PAGE_SIZE} total={list.total} onPageChange={setPage} />

      <OWASPRuleDrawer
        state={drawerState}
        rule={drawerRule}
        policyId={policyId}
        onSaved={() => {
          setSelected(new Set());
          refreshAll();
        }}
      />

      <OWASPBatchDialog
        state={batchState}
        policyId={policyId}
        ids={items.filter((it) => selected.has(it.id)).map((it) => it.catalog_id)}
        onDone={() => {
          setSelected(new Set());
          refreshAll();
        }}
      />
    </div>
  );
}

export default OWASPRulesClient;
