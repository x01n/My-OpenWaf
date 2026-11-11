"use client";

/**
 * Bot 评分记录面板：GET /bot-scores 分页列表 + 按 id 展开评分明细。
 *
 * 后端契约（internal/admin/protect/bot/bot.go GetBotScores）：
 * - 查询参数：ip / host / path / user_agent / request_id / ja3_hash / ja4 / tls_sni /
 *   high_risk(true|false) / min_score / max_score / start_time / end_time / page / page_size
 * - 响应：{ items: BotScoreLog[], total }
 * 列表项结构见 internal/store/events.go BotScoreLog。
 */

import { useCallback, useMemo, useState } from "react";
import { Button, Input, ScrollShadow, useOverlayState } from "@heroui/react";
import { apiGet } from "@/lib/api/client";
import { useDebounced, useList } from "@/lib/hooks/use-api";
import { useI18n } from "@/i18n";
import { localizeOptions } from "@/i18n/localized-options";
import type { BotScoreLog } from "@/lib/types/protection";
import {
  ErrorState,
  Pager,
  SearchInput,
  SimpleSelect,
  StatusChip,
  TableSkeleton,
  Toolbar,
} from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import { formatDateTime, truncate } from "@/lib/utils/format";
import { ActiveFilterBar, type ActiveFilter } from "@/components/ui/active-filter-bar";
import { HIGH_RISK_OPTIONS, SCORE_PARTS } from "./protection-model";

export function BotScoresPanel() {
  const { t } = useI18n();
  const [ipInput, setIpInput] = useState("");
  const ip = useDebounced(ipInput, 350);
  const [hostInput, setHostInput] = useState("");
  const host = useDebounced(hostInput, 350);
  const [highRisk, setHighRisk] = useState("all");
  const [minScoreInput, setMinScoreInput] = useState("");
  const minScore = useDebounced(minScoreInput, 350);

  const list = useList<BotScoreLog>("/bot-scores", {
    ip: ip || undefined,
    host: host || undefined,
    high_risk: highRisk === "all" ? undefined : highRisk,
    min_score: minScore.trim() === "" ? undefined : Number(minScore),
  });

  /**
   * 已激活筛选条件清单（Cloudflare 风格可见 chips）。
   */
  const activeFilters = useMemo<ActiveFilter[]>(() => {
    const items: ActiveFilter[] = [];
    const add = (key: string, label: string, value: string) => {
      if (value && value.trim() !== "") {
        items.push({ key, label, value: value.trim() });
      }
    };

    add("ip", t("protection.botScores.cond.ip"), ip.trim());
    add("host", t("protection.botScores.cond.host"), host.trim());

    if (highRisk !== "all") {
      const opt = HIGH_RISK_OPTIONS.find((o) => o.key === highRisk);
      const val = opt?.labelKey ? t(opt.labelKey) : highRisk;
      add("risk", t("protection.botScores.cond.risk"), val);
    }

    if (minScore.trim() !== "") {
      add("minScore", t("protection.botScores.cond.minScore"), minScore.trim());
    }

    return items;
  }, [t, ip, host, highRisk, minScore]);

  /** 单个筛选的清除器表 */
  const FILTER_RESETTERS: Record<string, () => void> = {
    ip: () => setIpInput(""),
    host: () => setHostInput(""),
    risk: () => setHighRisk("all"),
    minScore: () => setMinScoreInput(""),
  };

  function clearFilter(key: string) {
    FILTER_RESETTERS[key]?.();
  }

  function clearAllFilters() {
    Object.values(FILTER_RESETTERS).forEach((reset) => reset());
  }

  const [detail, setDetail] = useState<BotScoreLog | null>(null);
  const detailState = useOverlayState();

  function openDetail(row: BotScoreLog) {
    setDetail(row);
    detailState.open();
  }

  const columns: DataTableColumn<BotScoreLog>[] = [
    {
      header: t("protection.botScores.col.time"),
      render: (row) => (
        <span className="text-xs whitespace-nowrap">{formatDateTime(row.created_at)}</span>
      ),
    },
    {
      header: t("protection.botScores.col.clientIp"),
      render: (row) => <span className="font-mono text-xs">{row.client_ip || "-"}</span>,
    },
    {
      header: t("protection.botScores.col.host"),
      render: (row) => <span className="block max-w-40 truncate text-xs">{row.host || "-"}</span>,
    },
    {
      header: t("protection.botScores.col.path"),
      className: "max-w-56",
      render: (row) => (
        <span className="block truncate font-mono text-xs" title={row.path}>
          {truncate(row.path || "-", 40)}
        </span>
      ),
    },
    {
      header: t("protection.botScores.col.totalScore"),
      render: (row) => (
        <span className={`tabular text-sm font-semibold ${row.total_score >= 60 ? "text-danger" : ""}`}>
          {row.total_score}
        </span>
      ),
    },
    {
      header: t("protection.botScores.col.risk"),
      render: (row) => (
        <StatusChip tone={row.is_high_risk ? "danger" : "neutral"}>
          {row.is_high_risk
            ? t("protection.botScores.risk.high")
            : t("protection.botScores.risk.normal")}
        </StatusChip>
      ),
    },
    { header: t("protection.botScores.col.action"), render: (row) => <span className="text-xs">{row.action || "-"}</span> },
    {
      header: t("common.actions"),
      render: (row) => (
        <Button size="sm" variant="outline" onPress={() => openDetail(row)}>
          {t("common.detail")}
        </Button>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-3 py-2">
      <Toolbar>
        <SearchInput value={ipInput} onChange={setIpInput} placeholder={t("protection.botScores.searchIp")} />
        <SearchInput value={hostInput} onChange={setHostInput} placeholder={t("protection.botScores.col.host")} />
        <SimpleSelect<string>
          value={highRisk}
          onChange={setHighRisk}
          options={localizeOptions(HIGH_RISK_OPTIONS, t)}
          label={t("protection.botScores.filter.risk")}
          className="w-36"
        />
        <Input
          className="w-32"
          type="number"
          min={0}
          max={100}
          placeholder={t("protection.botScores.filter.minScore")}
          aria-label={t("protection.botScores.filter.minScore")}
          value={minScoreInput}
          onChange={(e) => setMinScoreInput(e.target.value)}
        />
      </Toolbar>

      <ActiveFilterBar
        filters={activeFilters}
        onClear={clearFilter}
        onClearAll={clearAllFilters}
      />

      {list.error ? (
        <ErrorState message={list.error} onRetry={list.reload} />
      ) : list.loading && list.items.length === 0 ? (
        <TableSkeleton rows={8} />
      ) : (
        <DataTable
          ariaLabel={t("protection.botScores.listAria")}
          columns={columns}
          rows={list.items}
          emptyMessage={t("protection.botScores.empty")}
        />
      )}
      <Pager
        page={list.page}
        pageSize={list.pageSize}
        total={list.total}
        onPageChange={list.setPage}
      />

      <DetailDrawer
        state={detailState}
        title={
          detail
            ? t("protection.botScores.detail.title", { id: detail.id })
            : t("protection.botScores.detail.fallbackTitle")
        }
        description={detail ? `${detail.host}${detail.path}` : undefined}
        width="w-[640px]"
      >
        {detail ? (
          <div className="flex flex-col gap-3">
            <div className="bg-surface rounded-xl border border-separator px-4 py-2">
              <DetailRow label={t("protection.botScores.detail.id")}>
                <span className="tabular">{detail.id}</span>
              </DetailRow>
              <DetailRow label={t("protection.botScores.detail.time")}>{formatDateTime(detail.created_at)}</DetailRow>
              <DetailRow label={t("protection.botScores.detail.siteId")}>
                <span className="tabular">{detail.site_id}</span>
              </DetailRow>
              <DetailRow label={t("protection.botScores.detail.requestId")}>{detail.request_id || "-"}</DetailRow>
              <DetailRow label={t("protection.botScores.detail.clientIp")}>{detail.client_ip || "-"}</DetailRow>
              <DetailRow label={t("protection.botScores.detail.host")}>{detail.host || "-"}</DetailRow>
              <DetailRow label={t("protection.botScores.detail.path")}>
                <span className="break-all">{detail.path || "-"}</span>
              </DetailRow>
              <DetailRow label={t("protection.botScores.detail.action")}>{detail.action || "-"}</DetailRow>
              <DetailRow label={t("protection.botScores.detail.highRisk")}>
                {detail.is_high_risk
                  ? t("protection.botScores.detail.yes")
                  : t("protection.botScores.detail.no")}
              </DetailRow>
              <DetailRow label={t("protection.botScores.detail.dangerous")}>
                {detail.dangerous
                  ? t("protection.botScores.detail.yes")
                  : t("protection.botScores.detail.no")}
              </DetailRow>
            </div>

            <div>
              <div className="text-muted mb-1 text-sm font-medium">
                {t("protection.botScores.parts.title")}
              </div>
              <div className="bg-surface rounded-xl border border-separator px-4">
                {SCORE_PARTS.map((part) => (
                  <DetailRow key={part.key} label={t(part.labelKey)}>
                    <span className="tabular">{detail[part.key] as number}</span>
                  </DetailRow>
                ))}
              </div>
            </div>

            <div>
              <div className="text-muted mb-1 text-sm font-medium">
                {t("protection.botScores.features.title")}
              </div>
              <div className="bg-surface rounded-xl border border-separator px-4 py-2">
                <DetailRow label={t("protection.botScores.features.userAgent")}>
                  <span className="break-all">{detail.user_agent || "-"}</span>
                </DetailRow>
                <DetailRow label={t("protection.botScores.features.tlsVersion")}>{detail.tls_version || "-"}</DetailRow>
                <DetailRow label={t("protection.botScores.features.sni")}>{detail.tls_sni || "-"}</DetailRow>
                <DetailRow label={t("protection.botScores.features.alpn")}>{detail.tls_alpn || "-"}</DetailRow>
                <DetailRow label={t("protection.botScores.features.ja3")}>{detail.tls_ja3_hash || "-"}</DetailRow>
                <DetailRow label={t("protection.botScores.features.ja4")}>{detail.tls_ja4 || "-"}</DetailRow>
                <DetailRow label={t("protection.botScores.features.headerOrder")}>
                  <ScrollShadow className="max-h-32">
                    <pre className="text-xs break-all whitespace-pre-wrap">
                      {detail.header_order || "-"}
                    </pre>
                  </ScrollShadow>
                </DetailRow>
              </div>
            </div>

            {detail.danger_reasons ? (
              <div>
                <div className="text-muted mb-1 text-sm font-medium">
                  {t("protection.botScores.dangerReasons")}
                </div>
                <div className="bg-surface rounded-xl border border-separator px-4 py-2">
                  <span className="break-all text-sm">{detail.danger_reasons}</span>
                </div>
              </div>
            ) : null}

            {detail.details ? (
              <div>
                <div className="text-muted mb-1 text-sm font-medium">
                  {t("protection.botScores.details")}
                </div>
                <ScrollShadow className="bg-surface max-h-60 rounded-xl border border-separator p-3">
                  <pre className="text-xs break-all whitespace-pre-wrap">{detail.details}</pre>
                </ScrollShadow>
              </div>
            ) : null}
          </div>
        ) : null}
      </DetailDrawer>
    </div>
  );
}
