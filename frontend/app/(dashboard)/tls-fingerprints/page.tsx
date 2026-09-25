"use client"

import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { PageHeader } from "@/components/page-header"
import { DataTable } from "@/components/data-table"
import { TablePagination } from "@/components/table-pagination"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { IconEye, IconFingerprint } from "@tabler/icons-react"
import { useFingerprints } from "@/hooks/use-api"
import { formatDate } from "@/lib/utils"
import type { TLSFingerprintSummary } from "@/lib/types"

const PAGE_SIZE = 20

/** 页面行模型：与 TLSFingerprintSummary 一致（后端 GET /fingerprints 返回）。 */
type FingerprintItem = TLSFingerprintSummary

/** 主指纹标识：优先 JA4（规则 DSL 中可编辑的 kind），回退 JA3 摘要。 */
function primaryFingerprint(row: FingerprintItem): string {
  return row.tls_ja4 || row.tls_ja3_hash || "-"
}

/** 详情弹窗内的一行「标签：值」，长值可折行不撑破容器。 */
function DetailRow({ label, value }: { label: string; value?: string }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-xs leading-5">
        {value || "-"}
      </dd>
    </div>
  )
}

/**
 * TLS 指纹列表页：按客户端指纹聚合的访问摘要，
 * 数据来自 GET /fingerprints（分页），列表仅展示高频摘要字段，
 * 完整字段在行详情弹窗内查看。
 */
export default function TLSFingerprintsPage() {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const [detailRow, setDetailRow] = useState<FingerprintItem | null>(null)

  const params = useMemo(
    () => ({ page, page_size: PAGE_SIZE }),
    [page]
  )
  const { data, isLoading, error } = useFingerprints(params)
  const items = data?.items || []
  const total = data?.total || 0

  const columns = [
    {
      key: "fingerprint",
      title: t("tlsFingerprints.columns.fingerprint"),
      render: (row: FingerprintItem) => (
        <span
          className="block max-w-[280px] truncate font-mono text-xs"
          title={primaryFingerprint(row)}
        >
          {primaryFingerprint(row)}
        </span>
      ),
    },
    {
      key: "version",
      title: t("tlsFingerprints.columns.version"),
      width: "110px",
      render: (row: FingerprintItem) =>
        row.tls_version ? (
          <Badge variant="outline" className="font-mono text-xs">
            {row.tls_version}
          </Badge>
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      key: "alpn",
      title: t("tlsFingerprints.columns.alpn"),
      width: "90px",
      render: (row: FingerprintItem) =>
        row.tls_alpn ? (
          <Badge variant="secondary" className="font-mono text-xs">
            {row.tls_alpn}
          </Badge>
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      key: "cipher_suites",
      title: t("tlsFingerprints.columns.cipherSuites"),
      render: (row: FingerprintItem) => (
        <span
          className="block max-w-[240px] truncate font-mono text-xs text-muted-foreground"
          title={row.tls_cipher_suites || ""}
        >
          {row.tls_cipher_suites || "-"}
        </span>
      ),
    },
    {
      key: "count",
      title: t("tlsFingerprints.columns.count"),
      width: "100px",
      render: (row: FingerprintItem) => (
        <span className="font-mono text-sm">
          {(row.count ?? 0).toLocaleString()}
        </span>
      ),
    },
    {
      key: "high_risk_count",
      title: t("tlsFingerprints.columns.highRiskCount"),
      width: "110px",
      render: (row: FingerprintItem) =>
        (row.high_risk_count ?? 0) > 0 ? (
          <Badge variant="destructive" className="font-mono text-xs">
            {row.high_risk_count?.toLocaleString()}
          </Badge>
        ) : (
          <span className="text-muted-foreground">0</span>
        ),
    },
    {
      key: "avg_bot_score",
      title: t("tlsFingerprints.columns.avgBotScore"),
      width: "120px",
      render: (row: FingerprintItem) => (
        <span className="font-mono text-sm">
          {typeof row.avg_bot_score === "number"
            ? row.avg_bot_score.toFixed(1)
            : "-"}
        </span>
      ),
    },
    {
      key: "last_seen",
      title: t("tlsFingerprints.columns.lastSeen"),
      width: "160px",
      render: (row: FingerprintItem) => (
        <span className="text-xs text-muted-foreground">
          {formatDate(row.last_seen)}
        </span>
      ),
    },
    {
      key: "action",
      title: t("common.action"),
      width: "80px",
      render: (row: FingerprintItem) => (
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setDetailRow(row)}
          title={t("tlsFingerprints.detailTitle")}
        >
          <IconEye className="h-4 w-4" />
        </Button>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title={t("tlsFingerprints.title")}
        description={t("tlsFingerprints.description")}
        icon={<IconFingerprint className="h-6 w-6 text-primary" />}
      />
      {error && (
        <Alert variant="destructive">
          <AlertTitle>{t("error.pageLoadFailed")}</AlertTitle>
          <AlertDescription>
            {(error as Error)?.message || t("error.unexpectedError")}
          </AlertDescription>
        </Alert>
      )}
      <DataTable<FingerprintItem>
        columns={columns}
        data={items}
        loading={isLoading}
        rowKey={(row) => primaryFingerprint(row)}
        emptyText={t("tlsFingerprints.empty")}
      />
      <TablePagination
        page={page}
        pageSize={PAGE_SIZE}
        total={total}
        onPageChange={setPage}
      />

      <Dialog open={detailRow !== null} onOpenChange={(open) => !open && setDetailRow(null)}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>{t("tlsFingerprints.detailTitle")}</DialogTitle>
          </DialogHeader>
          {detailRow && (
            <dl className="space-y-2">
              <DetailRow
                label={t("tlsFingerprints.detail.ja4")}
                value={detailRow.tls_ja4}
              />
              <DetailRow
                label={t("tlsFingerprints.detail.sni")}
                value={detailRow.tls_sni}
              />
              <DetailRow
                label={t("tlsFingerprints.detail.ja3Hash")}
                value={detailRow.tls_ja3_hash}
              />
              <DetailRow
                label={t("tlsFingerprints.detail.extensions")}
                value={detailRow.tls_extensions}
              />
              <DetailRow
                label={t("tlsFingerprints.detail.curves")}
                value={detailRow.tls_curves}
              />
              <DetailRow
                label={t("tlsFingerprints.detail.pointFormats")}
                value={detailRow.tls_point_formats}
              />
              <DetailRow
                label={t("tlsFingerprints.detail.userAgent")}
                value={detailRow.last_user_agent}
              />
              <DetailRow
                label={t("tlsFingerprints.detail.clientIP")}
                value={detailRow.last_client_ip}
              />
              <DetailRow
                label={t("tlsFingerprints.detail.headerOrder")}
                value={detailRow.last_header_order}
              />
            </dl>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}