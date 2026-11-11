"use client";

/**
 * 登录会话面板：
 * - GET /auth/sessions?all=true（admin 可看全部；非 admin 后端自动退化为本人会话）
 * - 强制下线 POST /auth/sessions/force-logout {jti}
 */

import { useCallback } from "react";
import { apiGet, apiPost } from "@/lib/api/client";
import { useApi } from "@/lib/hooks/use-api";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { CardSkeleton, ErrorState, Toolbar } from "@/components/ui/primitives";
import { formatDateTime, truncate } from "@/lib/utils/format";
import { useI18n } from "@/i18n";
import type { SessionInfo } from "@/lib/types/system";

type Rows = SessionInfo & { id: string | number };

export function SessionsPanel() {
  const { t } = useI18n();
  const { data, loading, error, reload } = useApi<{ sessions: SessionInfo[] }>(
    useCallback(() => apiGet<{ sessions: SessionInfo[] }>("/auth/sessions", { all: true }), []),
  );

  const rows: Rows[] = (data?.sessions ?? []).map((s) => ({ ...s, id: s.jti }));

  const columns: DataTableColumn<Rows>[] = [
    { header: t("admin.sessions.col.username"), render: (r) => <span className="font-medium">{r.username || "-"}</span> },
    { header: t("admin.sessions.col.ip"), render: (r) => <span className="tabular text-xs">{r.ip || "-"}</span> },
    {
      header: t("admin.sessions.col.device"),
      className: "max-w-[320px]",
      render: (r) => (
        <span className="text-muted block text-xs leading-5" title={r.user_agent}>
          {r.device_info || truncate(r.user_agent || "-", 80)}
        </span>
      ),
    },
    {
      header: t("admin.sessions.col.loginAt"),
      render: (r) => <span className="tabular text-muted text-xs">{formatDateTime(r.login_at)}</span>,
    },
    {
      header: t("admin.sessions.col.lastActiveAt"),
      render: (r) => (
        <span className="tabular text-muted text-xs">{formatDateTime(r.last_active_at)}</span>
      ),
    },
    {
      header: t("admin.sessions.col.expiresAt"),
      render: (r) => <span className="tabular text-muted text-xs">{formatDateTime(r.expires_at)}</span>,
    },
    {
      header: t("common.actions"),
      className: "w-28",
      render: (r) => (
        <ConfirmButton
          confirmText={t("admin.sessions.revokeConfirm", { name: r.username })}
          title={t("admin.sessions.revoke")}
          successText={t("admin.sessions.revoked")}
          onConfirm={async () => {
            await apiPost("/auth/sessions/force-logout", { jti: r.jti });
            void reload();
          }}
        >
          {t("admin.sessions.revoke")}
        </ConfirmButton>
      ),
    },
  ];

  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (loading && !data) return <CardSkeleton height="h-56" />;

  return (
    <div className="bg-surface rounded-xl border border-separator p-4">
      <Toolbar>
        <span className="text-muted text-xs">{t("admin.sessions.activeCount", { count: rows.length })}</span>
      </Toolbar>
      <DataTable
        ariaLabel={t("admin.sessions.listAria")}
        columns={columns}
        rows={rows}
        loading={loading}
        emptyMessage={t("admin.sessions.empty")}
      />
    </div>
  );
}
