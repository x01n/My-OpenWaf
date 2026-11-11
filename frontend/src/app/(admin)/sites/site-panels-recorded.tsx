"use client";

/**
 * 站点详情「录制资源」面板：站点命中资源的去重列表与全字段详情。
 *
 * 后端契约：
 * - GET  /sites/:id/recorded-resources（分页 page_size=50）
 * - POST /sites/:id/recorded-resources/clear
 */

import { useState } from "react";
import { useOverlayState, Button, Input, Chip, ScrollShadow } from "@heroui/react";
import { apiPost } from "@/lib/api/client";
import { useList } from "@/lib/hooks/use-api";
import type { RecordedResource } from "@/lib/types/access";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { DetailDrawer, DetailRow } from "@/components/ui/detail-drawer";
import { Pager, SearchInput, SimpleSelect, Toolbar } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils/format";
import { useI18n } from "@/i18n";

/** 按 HTTP 方法返回 Chip 配色。 */
function methodColor(method: string): "default" | "accent" | "success" {
  if (method === "GET") return "accent";
  if (method === "POST") return "success";
  return "default";
}

export function RecordedResourcesPanel({ siteId }: { siteId: number }) {
  const { t } = useI18n();
  const [q, setQ] = useState("");
  const [method, setMethod] = useState("all");
  const [host, setHost] = useState("");
  const [clientIp, setClientIp] = useState("");

  const list = useList<RecordedResource>(
    `/sites/${siteId}/recorded-resources`,
    {
      q: q || undefined,
      method: method === "all" ? undefined : method,
      host: host || undefined,
      client_ip: clientIp || undefined,
    },
    50,
  );

  const [detail, setDetail] = useState<RecordedResource | null>(null);
  const detailState = useOverlayState();

  function openDetail(row: RecordedResource) {
    setDetail(row);
    detailState.open();
  }

  const columns: DataTableColumn<RecordedResource>[] = [
    {
      header: t("common.method"),
      render: (row) => (
        <Chip size="sm" variant="soft" color={methodColor(row.method)}>
          {row.method || "-"}
        </Chip>
      ),
    },
    {
      header: t("common.host"),
      render: (row) => <span className="break-all text-xs">{row.host || "-"}</span>,
    },
    {
      header: t("common.path"),
      className: "max-w-56",
      render: (row) => {
        const full = row.query_string ? `${row.path}?${row.query_string}` : row.path;
        return (
          <span className="text-muted block truncate font-mono text-xs" title={full}>
            {full || "-"}
          </span>
        );
      },
    },
    {
      header: t("common.statusCode"),
      render: (row) => <span className="tabular">{row.status_code || "-"}</span>,
    },
    {
      header: t("common.clientIp"),
      render: (row) => <span className="font-mono tabular text-xs">{row.client_ip || "-"}</span>,
    },
    { header: "TLS", render: (row) => row.tls_version || "-" },
    {
      header: t("siteDetail.recorded.col.hits"),
      render: (row) => <span className="tabular">{row.hit_count}</span>,
    },
    {
      header: t("siteDetail.recorded.col.lastSeen"),
      render: (row) => <span className="tabular">{formatDateTime(row.last_seen)}</span>,
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

  return (
    <div className="flex flex-col gap-2 py-2">
      <Toolbar>
        <SearchInput value={q} onChange={setQ} placeholder={t("siteDetail.recorded.search")} />
        <SimpleSelect
          value={method}
          onChange={setMethod}
          options={[
            { key: "all", label: t("logs.method.all") },
            { key: "GET", label: "GET" },
            { key: "POST", label: "POST" },
            { key: "PUT", label: "PUT" },
            { key: "DELETE", label: "DELETE" },
            { key: "HEAD", label: "HEAD" },
            { key: "OPTIONS", label: "OPTIONS" },
          ]}
        />
        <Input
          className="w-44"
          aria-label={t("siteDetail.recorded.hostFilter")}
          placeholder={t("siteDetail.recorded.hostFilter")}
          value={host}
          onChange={(e) => setHost(e.target.value)}
        />
        <Input
          className="w-44"
          aria-label={t("siteDetail.recorded.clientIpFilter")}
          placeholder={t("siteDetail.recorded.clientIpFilter")}
          value={clientIp}
          onChange={(e) => setClientIp(e.target.value)}
        />
        <ConfirmButton
          variant="ghost"
          title={t("siteDetail.recorded.clear")}
          confirmText={t("siteDetail.recorded.clearConfirm")}
          successText={t("siteDetail.recorded.cleared")}
          onConfirm={async () => {
            await apiPost(`/sites/${siteId}/recorded-resources/clear`);
            void list.reload();
          }}
        >
          {t("siteDetail.recorded.clear")}
        </ConfirmButton>
      </Toolbar>

      <DataTable
        ariaLabel={t("siteDetail.recorded.listAria")}
        columns={columns}
        rows={list.items.length > 0 ? list.items : undefined}
        loading={list.loading}
        emptyMessage={t("siteDetail.recorded.empty")}
      />
      <Pager
        page={list.page}
        pageSize={list.pageSize}
        total={list.total}
        onPageChange={list.setPage}
      />

      <RecordedResourceDetail state={detailState} row={detail} />
    </div>
  );
}

/** 录制资源详情抽屉（全字段只读展示）。 */
function RecordedResourceDetail({
  state,
  row,
}: {
  state: ReturnType<typeof useOverlayState>;
  row: RecordedResource | null;
}) {
  const { t } = useI18n();
  return (
    <DetailDrawer state={state} title={t("siteDetail.recorded.detailTitle")} width="w-[560px]">
      {row ? (
        <div className="bg-surface rounded-xl border border-separator px-4 py-1">
          <DetailRow label={t("siteDetail.field.id")}>
            <span className="tabular">{row.id}</span>
          </DetailRow>
          <DetailRow label={t("common.method")}>{row.method || "-"}</DetailRow>
          <DetailRow label={t("common.host")}>{row.host || "-"}</DetailRow>
          <DetailRow label={t("common.path")}>
            <span className="break-all">{row.path || "-"}</span>
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.queryString")}>
            <span className="break-all">{row.query_string || "-"}</span>
          </DetailRow>
          <DetailRow label={t("common.clientIp")}>{row.client_ip || "-"}</DetailRow>
          <DetailRow label={t("common.statusCode")}>
            <span className="tabular">{row.status_code || "-"}</span>
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.contentType")}>
            {row.content_type || "-"}
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.tlsVersion")}>
            {row.tls_version || "-"}
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.tlsSni")}>{row.tls_sni || "-"}</DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.tlsAlpn")}>{row.tls_alpn || "-"}</DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.ja3")}>
            <span className="break-all">{row.ja3_hash || "-"}</span>
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.ja4")}>
            <span className="break-all">{row.ja4 || "-"}</span>
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.userAgent")}>
            <span className="break-all">{row.user_agent || "-"}</span>
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.matchedRules")}>
            <span className="break-all">{row.matched_rule_ids || "-"}</span>
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.primaryRule")}>
            <span className="tabular">{row.primary_rule_id || "-"}</span>
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.firstSeen")}>
            {formatDateTime(row.first_seen)}
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.col.lastSeen")}>
            {formatDateTime(row.last_seen)}
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.col.hits")}>
            <span className="tabular">{row.hit_count}</span>
          </DetailRow>
          <DetailRow label={t("siteDetail.recorded.field.bodySnippet")}>
            {row.request_body_snippet ? (
              <ScrollShadow className="max-h-48">
                <pre className="text-xs break-all whitespace-pre-wrap">
                  {row.request_body_snippet}
                </pre>
              </ScrollShadow>
            ) : (
              "-"
            )}
          </DetailRow>
          <DetailRow label={t("siteDetail.field.createdAt")}>
            {formatDateTime(row.created_at)}
          </DetailRow>
          <DetailRow label={t("siteDetail.field.updatedAt")}>
            {formatDateTime(row.updated_at)}
          </DetailRow>
        </div>
      ) : null}
    </DetailDrawer>
  );
}
