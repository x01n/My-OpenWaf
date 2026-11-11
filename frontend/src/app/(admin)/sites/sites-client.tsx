"use client";

/**
 * 站点管理：列表、新建/编辑弹窗、启停与详情抽屉入口。
 *
 * 后端契约（internal/admin/router.go）：
 * - 列表 GET /sites → { items: SiteListItem[], total }
 * - 创建 POST /sites；更新 POST /sites/:id/update；删除 POST /sites/:id/delete（204）
 * - 启停 POST /sites/:id/start | /sites/:id/stop → { status, message }
 */

import { useCallback, useMemo, useState } from "react";
import { useOverlayState, Button, Modal, TextField, Input, Label } from "@heroui/react";
import { Plus, RefreshCw, Eye, Pencil, Play, Square } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useApi, useList } from "@/lib/hooks/use-api";
import type { Certificate } from "@/lib/types/site";
import type { SiteActionResponse, SiteListItem } from "@/lib/types/site-admin";
import { formatDateTime } from "@/lib/utils/format";
import {
  PageHeader,
  StatusChip,
  Toolbar,
  SearchInput,
  Pager,
  ErrorState,
  SimpleSelect,
  ToggleSwitch,
} from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { useI18n, type MessageKey } from "@/i18n";
import { ActiveFilterBar, type ActiveFilter } from "@/components/ui/active-filter-bar";
import { SiteDetailDrawer } from "./site-detail-drawer";

function SitesClient() {
  const { t } = useI18n();
  const list = useList<SiteListItem>("/sites");
  const [search, setSearch] = useState("");
  const [togglingId, setTogglingId] = useState<number | null>(null);

  // 证书下拉选项来源
  const certs = useList<Certificate>("/certificates", {}, 100);

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<SiteListItem | null>(null);
  const formState = useOverlayState();

  const [detailSite, setDetailSite] = useState<SiteListItem | null>(null);
  const detailState = useOverlayState();

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return list.items;
    return list.items.filter(
      (s) =>
        s.host.toLowerCase().includes(q) ||
        (s.listener_summary ?? "").toLowerCase().includes(q) ||
        (s.tls_summary ?? "").toLowerCase().includes(q),
    );
  }, [list.items, search]);

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
    add("q", t("sites.cond.q"), search.trim());
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
    (row: SiteListItem) => {
      setEditing(row);
      setFormOpen(true);
      formState.open();
    },
    [formState],
  );

  const openDetail = useCallback(
    (row: SiteListItem) => {
      setDetailSite(row);
      detailState.open();
    },
    [detailState],
  );

  const handleToggle = useCallback(
    async (row: SiteListItem) => {
      setTogglingId(row.id);
      const action = row.enabled ? "stop" : "start";
      try {
        await apiPost<SiteActionResponse>(`/sites/${row.id}/${action}`);
        showSuccess(row.enabled ? t("sites.toggle.stopped") : t("sites.toggle.started"));
        void list.reload();
      } catch (err) {
        showError(t("sites.operationFailed"), err instanceof ApiError ? err.message : undefined);
      } finally {
        setTogglingId(null);
      }
    },
    [list, t],
  );

  const columns = useMemo<DataTableColumn<SiteListItem>[]>(
    () => [
      {
        header: t("sites.col.host"),
        render: (row) => <span className="font-medium">{row.host}</span>,
      },
      {
        header: t("sites.col.status"),
        render: (row) => (
          <StatusChip tone={row.enabled ? "success" : "neutral"}>
            {row.enabled ? t("sites.status.running") : t("sites.status.stopped")}
          </StatusChip>
        ),
      },
      { header: t("sites.col.tls"), render: (row) => row.tls_summary ?? "-" },
      {
        header: t("sites.col.listener"),
        className: "max-w-48",
        render: (row) => <span className="text-muted break-all">{row.listener_summary || "-"}</span>,
      },
      {
        header: t("sites.col.createdAt"),
        render: (row) => <span className="tabular">{formatDateTime(row.created_at)}</span>,
      },
      {
        header: t("common.actions"),
        render: (row) => (
          <div className="flex items-center gap-1.5">
            <Button size="sm" variant="ghost" onPress={() => openDetail(row)}>
              <Eye className="size-3.5" /> {t("common.detail")}
            </Button>
            <Button
              size="sm"
              variant={row.enabled ? "outline" : "primary"}
              isPending={togglingId === row.id}
              onPress={() => void handleToggle(row)}
            >
              {row.enabled ? <Square className="size-3.5" /> : <Play className="size-3.5" />}
              {row.enabled ? t("sites.action.stop") : t("sites.action.start")}
            </Button>
            <Button size="sm" variant="outline" onPress={() => openEdit(row)}>
              <Pencil className="size-3.5" /> {t("common.edit")}
            </Button>
            <ConfirmButton
              confirmText={t("sites.deleteConfirm", { host: row.host })}
              successText={t("sites.deleted")}
              onConfirm={async () => {
                await apiPost(`/sites/${row.id}/delete`);
                if (detailSite?.id === row.id) detailState.close();
                void list.reload();
              }}
            >
              {t("common.delete")}
            </ConfirmButton>
          </div>
        ),
      },
    ],
    [openDetail, openEdit, handleToggle, togglingId, list, detailSite, detailState, t],
  );

  return (
    <div>
      <PageHeader
        title={t("sites.title")}
        description={t("sites.description")}
        actions={
          <>
            <Button size="sm" variant="ghost" onPress={() => void list.reload()}>
              <RefreshCw className="size-3.5" /> {t("common.refresh")}
            </Button>
            <Button size="sm" variant="primary" onPress={openCreate}>
              <Plus className="size-3.5" /> {t("sites.create")}
            </Button>
          </>
        }
      />

      <Toolbar>
        <SearchInput value={search} onChange={setSearch} placeholder={t("sites.search")} />
      </Toolbar>

      <ActiveFilterBar
        filters={activeFilters}
        onClear={clearFilter}
        onClearAll={clearAllFilters}
      />

      {list.error ? (
        <ErrorState message={list.error} onRetry={list.reload} />
      ) : (
        <>
          <DataTable
            ariaLabel={t("sites.title")}
            columns={columns}
            rows={filtered}
            loading={list.loading}
            emptyMessage={t("sites.empty")}
          />
          <Pager
            page={list.page}
            pageSize={list.pageSize}
            total={list.total}
            onPageChange={list.setPage}
          />
        </>
      )}

      {formOpen ? (
        <SiteFormModal
          key={editing ? `site-edit-${editing.id}` : "site-create"}
          state={formState}
          editing={editing}
          certs={certs.items}
          onSaved={() => {
            void list.reload();
            setFormOpen(false);
          }}
        />
      ) : null}

      <SiteDetailDrawer
        state={detailState}
        site={detailSite}
        certs={certs.items}
        onChanged={() => void list.reload()}
      />
    </div>
  );
}

/**
 * 计算证书域名与站点 Host 的匹配分。
 *
 * Host 与证书 domain 均支持逗号分隔多值；证书 domain 支持 `*.example.com` 通配符。
 * 返回匹配分：3=精确匹配，2=通配符匹配，1=同主域后缀匹配，0=不匹配。
 */
export function certMatchScore(siteHosts: string, certDomain: string): number {
  const hosts = siteHosts.split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
  const domains = certDomain.split(",").map((d) => d.trim().toLowerCase()).filter(Boolean);
  let best = 0;
  for (const h of hosts) {
    const host = h.replace(/\.\d+(:\d+)?$/, "").replace(/:\d+$/, ""); // 去端口/IP 后缀
    for (const d of domains) {
      if (d === host || d === "*." + host) return 3;
      if (d.startsWith("*.")) {
        const suffix = d.slice(1); // ".example.com"
        if (host.endsWith(suffix)) best = Math.max(best, 2);
      } else if (host.endsWith("." + d)) {
        best = Math.max(best, 1);
      }
    }
  }
  return best;
}

const MATCH_BADGE_KEYS: (MessageKey | null)[] = [
  null,
  "sites.match.suffix",
  "sites.match.wildcard",
  "sites.match.exact",
];

/**
 * 新建/编辑站点弹窗。
 *
 * 后端 store.Site 无独立 name 字段，host 即站点标识；bind 与 upstream_urls 为必填
 * （internal/admin/shared/site_upstreams.go 校验 upstream_urls 非空）。
 * TLS 证书下拉按站点 Host 智能排序：精确匹配 > 通配符 > 同主域 > 其余，匹配项带标注。
 */
function SiteFormModal({
  state,
  editing,
  certs,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  editing: SiteListItem | null;
  certs: Certificate[];
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [host, setHost] = useState(editing?.host ?? "");
  const [bind, setBind] = useState(editing?.bind ?? "");
  const [upstreamUrls, setUpstreamUrls] = useState(editing?.upstream_urls ?? "");
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [tlsEnabled, setTlsEnabled] = useState(editing?.tls_enabled ?? false);
  const [certId, setCertId] = useState(editing?.cert_id ? String(editing.cert_id) : "none");
  const [saving, setSaving] = useState(false);

  // 证书智能排序：与站点 Host 匹配的证书排前，附匹配方式标注
  const certOptions = useMemo(() => {
    const scored = certs.map((c) => ({ cert: c, score: certMatchScore(host, c.domain) }));
    scored.sort((a, b) => b.score - a.score || a.cert.id - b.cert.id);
    const items = scored.map(({ cert, score }) => ({
      key: String(cert.id),
      label:
        score > 0
          ? `${cert.name}（${cert.domain}）✓ ${t(MATCH_BADGE_KEYS[score]!)}`
          : `${cert.name}${cert.domain ? `（${cert.domain}）` : ""}`,
      matched: score > 0,
    }));
    // 「不使用证书」兜底项必须存在：certId 初始值即为 "none"，缺失会导致下拉显示原始值
    return [{ key: "none", label: t("sites.form.certNone"), matched: false }, ...items];
  }, [certs, host, t]);
  const matchedCount = certOptions.filter((o) => o.matched).length;

  async function handleSave() {
    if (!host.trim() || !bind.trim() || !upstreamUrls.trim()) {
      showError(t("sites.form.required"), t("sites.form.requiredHint"));
      return;
    }
    setSaving(true);
    const payload = {
      host: host.trim(),
      bind: bind.trim(),
      upstream_urls: upstreamUrls.trim(),
      enabled,
      tls_enabled: tlsEnabled,
      cert_id: certId === "none" ? null : Number(certId),
    };
    try {
      if (editing) {
        await apiPost(`/sites/${editing.id}/update`, payload);
      } else {
        await apiPost("/sites", payload);
      }
      showSuccess(editing ? t("sites.form.updated") : t("sites.form.created"));
      onSaved();
      state.close();
    } catch (err) {
      showError(t("sites.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
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
              <Modal.Heading>{editing ? t("sites.form.edit") : t("sites.form.create")}</Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-5">
              <TextField aria-label="Host" isRequired className="flex flex-col gap-1.5">
                <Label isRequired>{t("sites.form.host")}</Label>
                <Input
                  id="site-host"
                  placeholder={t("sites.form.hostPlaceholder")}
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("sites.form.bind")} isRequired className="flex flex-col gap-1.5">
                <Label isRequired>{t("sites.form.bind")}</Label>
                <Input
                  id="site-bind"
                  placeholder={t("sites.form.bindPlaceholder")}
                  value={bind}
                  onChange={(e) => setBind(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("sites.form.upstream")} isRequired className="flex flex-col gap-1.5">
                <Label isRequired>{t("sites.form.upstream")}</Label>
                <Input
                  id="site-upstream"
                  placeholder={t("sites.form.upstreamPlaceholder")}
                  value={upstreamUrls}
                  onChange={(e) => setUpstreamUrls(e.target.value)}
                />
              </TextField>
              <div className="flex items-center gap-8 py-1">
                <ToggleSwitch isSelected={enabled} onChange={setEnabled}>
                  {t("sites.form.enabled")}
                </ToggleSwitch>
                <ToggleSwitch isSelected={tlsEnabled} onChange={setTlsEnabled}>
                  {t("sites.form.tls")}
                </ToggleSwitch>
              </div>
              {tlsEnabled ? (
                <div className="flex flex-col gap-1.5">
                  <SimpleSelect
                    value={certId}
                    onChange={setCertId}
                    label={t("sites.form.cert")}
                    className="w-full"
                    options={certOptions}
                  />
                  <div className="text-muted text-xs">
                    {matchedCount > 0
                      ? t("sites.form.certMatched", { count: matchedCount })
                      : t("sites.form.certNoMatch")}
                  </div>
                </div>
              ) : null}
            </Modal.Body>
            <Modal.Footer>
              <Button variant="ghost" onPress={state.close}>
                {t("common.cancel")}
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

export default SitesClient;
