"use client";

/**
 * 站点生效规则面板（只读）：展示该站点关联策略下的自定义规则。
 *
 * 后端契约（internal/admin/rule/rule.go ListSiteRules）：
 * GET /sites/:id/rules → { items: Rule[], total, policy_id, inherited }
 * inherited=true 表示站点未绑定策略，展示默认策略的规则。
 */

import { useCallback } from "react";
import { apiGet } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import type { Rule } from "@/lib/types/rule";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { StatusChip } from "@/components/ui/primitives";
import { useI18n } from "@/i18n";

type SiteRulesResponse = {
  items: Rule[];
  total: number;
  policy_id: number;
  inherited: boolean;
};

export function SiteRulesPanel({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const { data, loading, error } = useApi(
    useCallback(() => apiGet<SiteRulesResponse>(`/sites/${siteId}/rules`), [siteId]),
  );
  const items = data?.items ?? [];

  const phaseLabel = (phase: string): string => {
    if (phase === "acl") return t("rules.phase.acl");
    if (phase === "signature") return t("rules.phase.signature");
    if (phase === "custom") return t("rules.phase.custom");
    return phase;
  };

  const columns: DataTableColumn<Rule>[] = [
    { header: t("rules.col.name"), render: (r) => <span className="font-medium">{r.name}</span> },
    {
      header: t("rules.col.phase"),
      render: (r) => phaseLabel(r.phase),
    },
    {
      header: t("siteDetail.siteRules.col.match"),
      className: "max-w-44",
      render: (r) => <span className="text-muted break-all">{r.pattern}</span>,
    },
    { header: t("rules.col.action"), render: (r) => r.action },
    {
      header: t("rules.col.priority"),
      render: (r) => <span className="tabular">{r.priority}</span>,
    },
    {
      header: t("siteDetail.listeners.status"),
      render: (r) => (
        <StatusChip tone={r.enabled ? "success" : "neutral"}>
          {r.enabled ? t("common.enabled") : t("common.disabled")}
        </StatusChip>
      ),
    },
  ];

  if (error) {
    return <div className="text-danger py-4 text-center text-sm">{error}</div>;
  }

  return (
    <div className="flex flex-col gap-2 py-2">
      {data ? (
        <div className="text-muted text-xs">
          {t("siteDetail.siteRules.policy", { id: data.policy_id })}
          {data.inherited
            ? t("siteDetail.siteRules.inherited")
            : t("siteDetail.siteRules.bound")}{" "}
          · {t("siteDetail.siteRules.total", { count: data.total })}
        </div>
      ) : null}
      <DataTable
        ariaLabel={t("siteDetail.siteRules.listAria")}
        columns={columns}
        rows={items.length > 0 ? items : undefined}
        loading={loading}
        emptyMessage={t("siteDetail.siteRules.empty")}
      />
    </div>
  );
}
