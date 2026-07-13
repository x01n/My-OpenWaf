"use client";

/**
 * 误报反馈管理页面。
 *
 * 列出管理员通过安全事件详情提交的误报反馈记录，
 * 支持按审查状态筛选、翻页、更改状态（确认 / 拒绝）以及删除（仅 admin）。
 */

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { format } from "date-fns";
import { zhCN } from "date-fns/locale";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
  PaginationEllipsis,
} from "@/components/ui/pagination";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import {
  IconAlertHexagon,
  IconCheck,
  IconX,
  IconTrash,
  IconChevronDown,
} from "@tabler/icons-react";
import {
  useFalsePositives,
  useFalsePositiveStatusUpdate,
  useFalsePositiveDelete,
} from "@/hooks/use-api";
import { useAuth } from "@/hooks/use-auth";
import type { FalsePositiveReport } from "@/lib/types";
import { categoryLabel } from "@/lib/attack-category";

type StatusValue = "" | "pending" | "confirmed" | "rejected";

/**
 * 根据状态返回 Badge 的样式与文案 key。
 */
function statusBadgeClass(status: string): string {
  switch (status) {
    case "confirmed":
      return "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400";
    case "rejected":
      return "border-zinc-500/40 bg-zinc-500/15 text-zinc-600 dark:text-zinc-400";
    case "pending":
    default:
      return "border-amber-500/40 bg-amber-500/15 text-amber-600 dark:text-amber-400";
  }
}

/**
 * 格式化后端时间字符串，失败时返回原值。
 */
function formatTime(value: string): string {
  try {
    return format(new Date(value), "yyyy-MM-dd HH:mm:ss", { locale: zhCN });
  } catch {
    return value;
  }
}

export default function FalsePositivesPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [page, setPage] = useState(1);
  const pageSize = 20;
  const [status, setStatus] = useState<StatusValue>("");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<FalsePositiveReport | null>(null);

  const { data, isLoading } = useFalsePositives({
    page,
    page_size: pageSize,
    status: status || undefined,
  });

  const updateStatus = useFalsePositiveStatusUpdate();
  const deleteFp = useFalsePositiveDelete();

  const items: FalsePositiveReport[] = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / pageSize) || 1;

  const statusLabelMap = useMemo<Record<string, string>>(
    () => ({
      pending: t("falsePositives.status.pending", { defaultValue: "待审查" }),
      confirmed: t("falsePositives.status.confirmed", { defaultValue: "已确认" }),
      rejected: t("falsePositives.status.rejected", { defaultValue: "已拒绝" }),
    }),
    [t],
  );

  const handleUpdateStatus = async (row: FalsePositiveReport, next: string) => {
    if (row.status === next) return;
    try {
      await updateStatus.execute({ id: row.id, status: next });
      toast.success(t("common.updateSuccess"));
    } catch {
      toast.error(t("common.updateFailed"));
    }
  };

  const handleDelete = (row: FalsePositiveReport) => {
    setPendingDelete(row);
    setConfirmOpen(true);
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    try {
      await deleteFp.execute(pendingDelete.id);
      toast.success(t("common.deleteSuccess"));
      setConfirmOpen(false);
      setPendingDelete(null);
    } catch {
      toast.error(t("common.deleteFailed"));
    }
  };

  const columns = [
    {
      key: "created_at",
      title: t("falsePositives.reportedAt", { defaultValue: "提交时间" }),
      width: "170px",
      render: (row: FalsePositiveReport) => (
        <span className="font-mono text-xs">{formatTime(row.created_at)}</span>
      ),
    },
    {
      key: "submitted_by",
      title: t("falsePositives.submittedBy", { defaultValue: "提交者" }),
      width: "120px",
      render: (row: FalsePositiveReport) => (
        <span className="text-xs">
          {row.submitted_by || <span className="text-muted-foreground">-</span>}
        </span>
      ),
    },
    {
      key: "rule_id_str",
      title: t("falsePositives.ruleId", { defaultValue: "命中规则" }),
      width: "160px",
      render: (row: FalsePositiveReport) => (
        <span className="font-mono text-xs">{row.rule_id_str || "-"}</span>
      ),
    },
    {
      key: "category",
      title: t("falsePositives.category", { defaultValue: "类别" }),
      width: "120px",
      render: (row: FalsePositiveReport) => (
        <span className="text-xs">{categoryLabel(row.category)}</span>
      ),
    },
    {
      key: "client_ip",
      title: t("falsePositives.clientIp", { defaultValue: "客户端 IP" }),
      width: "130px",
      render: (row: FalsePositiveReport) => (
        <span className="font-mono text-xs">{row.client_ip}</span>
      ),
    },
    {
      key: "host",
      title: t("falsePositives.host", { defaultValue: "主机" }),
      width: "160px",
      render: (row: FalsePositiveReport) => (
        <span className="break-all font-mono text-xs">{row.host}</span>
      ),
    },
    {
      key: "path",
      title: t("falsePositives.path", { defaultValue: "路径" }),
      render: (row: FalsePositiveReport) => (
        <span className="break-all font-mono text-xs">{row.path}</span>
      ),
    },
    {
      key: "note",
      title: t("falsePositives.note", { defaultValue: "备注" }),
      width: "180px",
      render: (row: FalsePositiveReport) => (
        <span className="line-clamp-1 text-xs" title={row.note}>
          {row.note || <span className="text-muted-foreground">-</span>}
        </span>
      ),
    },
    {
      key: "status",
      title: t("falsePositives.statusColumn", { defaultValue: "状态" }),
      width: "100px",
      render: (row: FalsePositiveReport) => (
        <Badge className={`border px-2 py-0.5 text-xs ${statusBadgeClass(row.status)}`}>
          {statusLabelMap[row.status] || row.status}
        </Badge>
      ),
    },
    {
      key: "actions",
      title: t("common.actions"),
      width: "220px",
      render: (row: FalsePositiveReport) => (
        <div className="flex flex-wrap items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 gap-1 px-2 text-xs"
            onClick={() => setExpandedId(expandedId === row.id ? null : row.id)}
          >
            <IconChevronDown
              className={`h-3.5 w-3.5 transition-transform ${expandedId === row.id ? "rotate-180" : ""}`}
            />
            {t("falsePositives.expand", { defaultValue: "详情" })}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 gap-1 px-2 text-xs text-emerald-600 hover:text-emerald-700"
            disabled={row.status === "confirmed" || updateStatus.loading}
            onClick={() => handleUpdateStatus(row, "confirmed")}
          >
            <IconCheck className="h-3.5 w-3.5" />
            {t("falsePositives.actions.confirm", { defaultValue: "确认" })}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 gap-1 px-2 text-xs text-zinc-600 hover:text-zinc-800"
            disabled={row.status === "rejected" || updateStatus.loading}
            onClick={() => handleUpdateStatus(row, "rejected")}
          >
            <IconX className="h-3.5 w-3.5" />
            {t("falsePositives.actions.reject", { defaultValue: "拒绝" })}
          </Button>
          {isAdmin && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-xs text-destructive hover:text-destructive"
              disabled={deleteFp.loading}
              onClick={() => handleDelete(row)}
            >
              <IconTrash className="h-3.5 w-3.5" />
              {t("falsePositives.actions.delete", { defaultValue: "删除" })}
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <IconAlertHexagon className="h-6 w-6 text-primary" />
        <h1 className="text-xl font-semibold">
          {t("falsePositives.title", { defaultValue: "误报反馈" })}
        </h1>
        <Badge variant="secondary" className="h-5 px-2 text-xs">
          {t("common.total", { count: total })}
        </Badge>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="text-base">
              {t("falsePositives.list", { defaultValue: "反馈列表" })}
            </CardTitle>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">
                {t("falsePositives.filterStatus", { defaultValue: "状态筛选" })}
              </span>
              <Select
                value={status || "all"}
                onValueChange={(v) => {
                  setStatus(v === "all" ? "" : (v as StatusValue));
                  setPage(1);
                }}
              >
                <SelectTrigger className="h-8 w-[140px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent align="end">
                  <SelectItem value="all">{t("common.all")}</SelectItem>
                  <SelectItem value="pending">{statusLabelMap.pending}</SelectItem>
                  <SelectItem value="confirmed">{statusLabelMap.confirmed}</SelectItem>
                  <SelectItem value="rejected">{statusLabelMap.rejected}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <DataTable<FalsePositiveReport>
            columns={columns}
            data={items}
            loading={isLoading}
            rowKey={(row) => row.id}
            emptyText={t("falsePositives.empty", { defaultValue: "暂无误报反馈" })}
          />

          {expandedId != null && (() => {
            const row = items.find((i) => i.id === expandedId);
            if (!row) return null;
            return (
              <div className="rounded-md border bg-muted/20 p-4">
                <div className="mb-2 text-xs font-medium text-muted-foreground">
                  {t("falsePositives.matchDesc", { defaultValue: "命中详情" })} #{row.id}
                </div>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-foreground/80">
                  {row.match_desc || t("common.empty")}
                </pre>
                {row.note && (
                  <div className="mt-3 border-t pt-3">
                    <div className="mb-1 text-xs font-medium text-muted-foreground">
                      {t("falsePositives.note", { defaultValue: "备注" })}
                    </div>
                    <div className="text-xs">{row.note}</div>
                  </div>
                )}
              </div>
            );
          })()}

          {totalPages > 1 && (
            <Pagination>
              <PaginationContent>
                <PaginationItem>
                  <PaginationPrevious
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    className={page <= 1 ? "pointer-events-none opacity-50" : ""}
                  />
                </PaginationItem>
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  const pageNum = i + 1;
                  return (
                    <PaginationItem key={pageNum}>
                      <PaginationLink isActive={page === pageNum} onClick={() => setPage(pageNum)}>
                        {pageNum}
                      </PaginationLink>
                    </PaginationItem>
                  );
                })}
                {totalPages > 5 && (
                  <PaginationItem>
                    <PaginationEllipsis />
                  </PaginationItem>
                )}
                <PaginationItem>
                  <PaginationNext
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    className={page >= totalPages ? "pointer-events-none opacity-50" : ""}
                  />
                </PaginationItem>
              </PaginationContent>
            </Pagination>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={t("falsePositives.confirmDeleteTitle", { defaultValue: "删除反馈记录" })}
        description={t("falsePositives.confirmDeleteDesc", {
          defaultValue: "删除后无法恢复，是否继续？",
        })}
        loading={deleteFp.loading}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
