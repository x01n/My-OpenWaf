"use client";

/**
 * 证书管理：证书列表、手动录入、PEM 解析、应用到站点、ACME 设置与签发。
 *
 * 后端契约（internal/admin/system/certificate、internal/admin/system/acme.go）：
 * - 列表 GET /certificates → { items: Certificate[], total }
 * - 创建 POST /certificates；解析 POST /certificates/parse
 * - 应用 POST /certificates/:id/apply-to-sites（后端按证书域名自动匹配站点，body 的
 *   site_ids 仅为前端展示意图，后端忽略；响应含 applied_sites）
 * - 删除 POST /certificates/:id/delete（204）
 * - ACME 配置 GET/POST /certificates/acme/config（仅 admin）；签发 POST /certificates/acme/apply
 */

import { useCallback, useMemo, useState } from "react";
import {
  useOverlayState,
  Button,
  Modal,
  TextField,
  Input,
  TextArea,
  Checkbox,
  ScrollShadow,
} from "@heroui/react";
import { Plus, RefreshCw, FileSearch, Link2, Settings2, Sparkles, Pencil } from "lucide-react";
import { apiGet, apiPost, ApiError, type ListResponse } from "@/lib/api/client";
import { useList } from "@/lib/hooks/use-api";
import type { Certificate, CertificateParseResult } from "@/lib/types/site";
import type { CertificateApplyResponse, SiteListItem } from "@/lib/types/site-admin";
import { formatDateTime } from "@/lib/utils/format";
import {
  PageHeader,
  StatusChip,
  Toolbar,
  Pager,
  ErrorState,
} from "@/components/ui/primitives";
import { DataTable, type DataTableColumn } from "@/components/ui/data-table";
import { ConfirmButton } from "@/components/ui/confirm-button";
import { DetailRow } from "@/components/ui/detail-drawer";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";
import { AcmeConfigDrawer } from "./acme-drawer";

const RENEW_WINDOW_MS = 30 * 24 * 3600 * 1000;

/** 到期时间展示：30 天内告警、已过期红色 */
function ExpiryCell({ value }: { value: string | null | undefined }) {
  const { t } = useI18n();
  if (!value) return <span className="text-muted">-</span>;
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) return <span className="text-muted">{value}</span>;
  const overdue = time <= Date.now();
  const soon = time - Date.now() < RENEW_WINDOW_MS;
  return (
    <span className={`tabular ${overdue ? "text-danger" : soon ? "text-warning" : ""}`}>
      {formatDateTime(value)}
      {overdue
        ? t("certificates.expired")
        : soon
          ? t("certificates.expiringSoon")
          : ""}
    </span>
  );
}

function CertificatesClient() {
  const { t } = useI18n();
  const list = useList<Certificate>("/certificates");
  const sites = useList<SiteListItem>("/sites", {}, 100);

  const [createVisible, setCreateVisible] = useState(false);
  const [parseVisible, setParseVisible] = useState(false);
  const [applyVisible, setApplyVisible] = useState(false);
  const [issueVisible, setIssueVisible] = useState(false);
  const [editVisible, setEditVisible] = useState(false);
  const [applyTarget, setApplyTarget] = useState<Certificate | null>(null);
  const [editing, setEditing] = useState<Certificate | null>(null);
  const [renewingId, setRenewingId] = useState<number | null>(null);

  const createState = useOverlayState();
  const parseState = useOverlayState();
  const applyState = useOverlayState();
  const issueState = useOverlayState();
  const editState = useOverlayState();
  const acmeDrawerState = useOverlayState();

  const openCreate = useCallback(() => {
    setCreateVisible(true);
    createState.open();
  }, [createState]);

  const openParse = useCallback(() => {
    setParseVisible(true);
    parseState.open();
  }, [parseState]);

  const openIssue = useCallback(() => {
    setIssueVisible(true);
    issueState.open();
  }, [issueState]);

  const openApply = useCallback(
    (cert: Certificate) => {
      setApplyTarget(cert);
      setApplyVisible(true);
      applyState.open();
    },
    [applyState],
  );

  const openEdit = useCallback(
    (cert: Certificate) => {
      setEditing(cert);
      setEditVisible(true);
      editState.open();
    },
    [editState],
  );

  /** ACME 证书手动续期（仅 source=acme 可用） */
  const handleRenew = useCallback(
    async (cert: Certificate) => {
      setRenewingId(cert.id);
      try {
        await apiPost<{ message?: string; domain?: string }>(`/certificates/acme/${cert.id}/renew`);
        showSuccess(t("certificates.renewSuccess"), cert.domain ?? undefined);
        void list.reload();
      } catch (err) {
        showError(t("certificates.renewFailed"), err instanceof ApiError ? err.message : undefined);
      } finally {
        setRenewingId(null);
      }
    },
    [list, t],
  );

  const columns = useMemo<DataTableColumn<Certificate>[]>(
    () => [
      {
        header: t("certificates.col.name"),
        render: (row) => (
          <div>
            <div className="font-medium">{row.name}</div>
            {row.renew_error ? <div className="text-danger text-xs">{row.renew_error}</div> : null}
          </div>
        ),
      },
      {
        header: t("certificates.col.domain"),
        render: (row) => row.domain || <span className="text-muted">-</span>,
      },
      {
        header: t("certificates.col.source"),
        render: (row) => (
          <StatusChip tone={row.source === "acme" ? "info" : "neutral"}>
            {row.source === "acme"
              ? t("certificates.source.acme")
              : t("certificates.source.manual")}
          </StatusChip>
        ),
      },
      { header: t("certificates.col.expiresAt"), render: (row) => <ExpiryCell value={row.expires_at} /> },
      {
        header: t("certificates.col.autoRenew"),
        render: (row) => (
          <StatusChip tone={row.auto_renew ? "success" : "neutral"}>
            {row.auto_renew ? t("certificates.autoRenew.on") : t("certificates.autoRenew.off")}
          </StatusChip>
        ),
      },
      {
        header: t("common.actions"),
        render: (row) => (
          <div className="flex items-center gap-1.5">
            <Button size="sm" variant="outline" onPress={() => openApply(row)}>
              <Link2 className="size-3.5" /> {t("certificates.applyToSites")}
            </Button>
            <Button size="sm" variant="outline" onPress={() => openEdit(row)}>
              <Pencil className="size-3.5" /> {t("common.edit")}
            </Button>
            {row.source === "acme" ? (
              <Button
                size="sm"
                variant="outline"
                isPending={renewingId === row.id}
                onPress={() => void handleRenew(row)}
              >
                <RefreshCw className="size-3.5" /> {t("certificates.renew")}
              </Button>
            ) : null}
            <ConfirmButton
              confirmText={t("certificates.deleteConfirm", { name: row.name })}
              successText={t("certificates.deleted")}
              onConfirm={async () => {
                await apiPost(`/certificates/${row.id}/delete`);
                void list.reload();
              }}
            >
              {t("common.delete")}
            </ConfirmButton>
          </div>
        ),
      },
    ],
    [list, openApply, openEdit, handleRenew, renewingId, t],
  );

  return (
    <div>
      <PageHeader
        title={t("certificates.title")}
        description={t("certificates.description")}
        actions={
          <>
            <Button size="sm" variant="outline" onPress={openParse}>
              <FileSearch className="size-3.5" /> {t("certificates.parse")}
            </Button>
            <Button size="sm" variant="outline" onPress={openIssue}>
              <Sparkles className="size-3.5" /> {t("certificates.acmeIssue")}
            </Button>
            <Button size="sm" variant="outline" onPress={acmeDrawerState.open}>
              <Settings2 className="size-3.5" /> {t("certificates.acmeSettings")}
            </Button>
            <Button size="sm" variant="ghost" onPress={() => void list.reload()}>
              <RefreshCw className="size-3.5" /> {t("common.refresh")}
            </Button>
            <Button size="sm" variant="primary" onPress={openCreate}>
              <Plus className="size-3.5" /> {t("certificates.create")}
            </Button>
          </>
        }
      />

      {list.error ? (
        <ErrorState message={list.error} onRetry={list.reload} />
      ) : (
        <>
          <DataTable
            ariaLabel={t("certificates.listAria")}
            columns={columns}
            rows={list.items}
            loading={list.loading}
            emptyMessage={t("certificates.empty")}
          />
          <Pager
            page={list.page}
            pageSize={list.pageSize}
            total={list.total}
            onPageChange={list.setPage}
          />
        </>
      )}

      {createVisible ? (
        <CreateCertModal
          state={createState}
          onSaved={() => {
            void list.reload();
            setCreateVisible(false);
          }}
        />
      ) : null}

      {parseVisible ? <ParseCertModal state={parseState} /> : null}

      {issueVisible ? (
        <AcmeIssueModal
          state={issueState}
          onSaved={() => {
            void list.reload();
            setIssueVisible(false);
          }}
        />
      ) : null}

      {editVisible && editing ? (
        <EditCertModal
          key={`cert-edit-${editing.id}`}
          state={editState}
          cert={editing}
          onSaved={() => {
            void list.reload();
            setEditVisible(false);
          }}
        />
      ) : null}

      {applyVisible && applyTarget ? (
        <ApplyToSitesModal
          key={`apply-${applyTarget.id}`}
          state={applyState}
          cert={applyTarget}
          sites={sites.items}
          onApplied={() => {
            void list.reload();
            setApplyVisible(false);
          }}
        />
      ) : null}

      <AcmeConfigDrawer state={acmeDrawerState} />
    </div>
  );
}

/* ============================== 新建证书 ============================== */

function CreateCertModal({
  state,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!certPem.trim() || !keyPem.trim()) {
      showError(t("certificates.form.required"), t("certificates.form.requiredHint"));
      return;
    }
    setSaving(true);
    try {
      await apiPost("/certificates", {
        name: name.trim(),
        domain: domain.trim(),
        cert_pem: certPem,
        key_pem: keyPem,
      });
      showSuccess(t("certificates.form.created"));
      onSaved();
      state.close();
    } catch (err) {
      showError(t("certificates.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
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
              <Modal.Heading>{t("certificates.form.createTitle")}</Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <TextField aria-label={t("certificates.form.name")}>
                <Input
                  placeholder={t("certificates.form.namePlaceholder")}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("certificates.form.domain")}>
                <Input
                  placeholder={t("certificates.form.domainPlaceholder")}
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              </TextField>
              <TextArea
                aria-label={t("certificates.form.certPem")}
                className="min-h-32 font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----"
                value={certPem}
                onChange={(e) => setCertPem(e.target.value)}
              />
              <TextArea
                aria-label={t("certificates.form.keyPem")}
                className="min-h-32 font-mono text-xs"
                placeholder="-----BEGIN PRIVATE KEY-----"
                value={keyPem}
                onChange={(e) => setKeyPem(e.target.value)}
              />
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

/* ============================== 编辑证书 ============================== */

/**
 * 编辑证书弹窗：更新 name/domain/cert_pem/key_pem。
 * 后端 UpdateCertificate 用 BindJSON(existing) 合并更新，key_pem 在列表响应中已脱敏
 * 为空，因此私钥必须重新粘贴（否则 X509KeyPair 校验失败）。
 */
function EditCertModal({
  state,
  cert,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  cert: Certificate;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [name, setName] = useState(cert.name ?? "");
  const [domain, setDomain] = useState(cert.domain ?? "");
  const [certPem, setCertPem] = useState(cert.cert_pem ?? "");
  const [keyPem, setKeyPem] = useState("");
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!certPem.trim() || !keyPem.trim()) {
      showError(t("certificates.form.required"), t("certificates.form.requiredHintEdit"));
      return;
    }
    setSaving(true);
    try {
      await apiPost(`/certificates/${cert.id}/update`, {
        name: name.trim(),
        domain: domain.trim(),
        cert_pem: certPem,
        key_pem: keyPem,
      });
      showSuccess(t("certificates.form.updated"));
      onSaved();
      state.close();
    } catch (err) {
      showError(t("certificates.form.saveFailed"), err instanceof ApiError ? err.message : undefined);
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
              <Modal.Heading>{t("certificates.form.editTitle")}</Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <TextField aria-label={t("certificates.form.name")}>
                <Input
                  placeholder={t("certificates.form.namePlaceholderEdit")}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("certificates.form.domain")}>
                <Input
                  placeholder={t("certificates.form.domainPlaceholderEdit")}
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              </TextField>
              <TextArea
                aria-label={t("certificates.form.certPem")}
                className="min-h-32 font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----"
                value={certPem}
                onChange={(e) => setCertPem(e.target.value)}
              />
              <TextArea
                aria-label={t("certificates.form.keyPem")}
                className="min-h-32 font-mono text-xs"
                placeholder={t("certificates.form.keyPemPlaceholderEdit")}
                value={keyPem}
                onChange={(e) => setKeyPem(e.target.value)}
              />
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

/* ============================== 解析证书 ============================== */

function ParseCertModal({
  state,
}: {
  state: ReturnType<typeof useOverlayState>;
}) {
  const { t } = useI18n();
  const [certPem, setCertPem] = useState("");
  const [result, setResult] = useState<CertificateParseResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleParse() {
    if (!certPem.trim()) {
      showError(t("certificates.parse.empty"));
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await apiPost<CertificateParseResult>("/certificates/parse", {
        cert_pem: certPem,
      });
      setResult(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("certificates.parse.failed"));
    } finally {
      setLoading(false);
    }
  }

  const separator = t("certificates.parse.listSeparator");

  return (
    <Modal state={state}>
      <Modal.Backdrop>
        <Modal.Container size="lg">
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Heading>{t("certificates.parse.title")}</Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <TextArea
                aria-label={t("certificates.form.certPem")}
                className="min-h-32 font-mono text-xs"
                placeholder={t("certificates.parse.pemPlaceholder")}
                value={certPem}
                onChange={(e) => setCertPem(e.target.value)}
              />
              <Button variant="primary" isPending={loading} onPress={() => void handleParse()}>
                {t("certificates.parse.submit")}
              </Button>
              {error ? <div className="text-danger text-sm">{error}</div> : null}
              {result ? (
                <div className="bg-surface rounded-xl border border-separator px-4 py-1">
                  <DetailRow label={t("certificates.parse.commonName")}>
                    {result.common_name || "-"}
                  </DetailRow>
                  <DetailRow label={t("certificates.parse.dnsNames")}>
                    {result.dns_names?.length ? result.dns_names.join(separator) : "-"}
                  </DetailRow>
                  <DetailRow label={t("certificates.parse.ipAddresses")}>
                    {result.ip_addresses?.length ? result.ip_addresses.join(separator) : "-"}
                  </DetailRow>
                  <DetailRow label={t("certificates.parse.expiresAt")}>
                    <span className="tabular">{formatDateTime(result.expires_at)}</span>
                  </DetailRow>
                  <DetailRow label={t("certificates.parse.matchedSites")}>
                    {result.matched_sites?.length ? (
                      <span className="flex flex-col gap-0.5">
                        {result.matched_sites.map((s) => (
                          <span key={s}>{s}</span>
                        ))}
                      </span>
                    ) : (
                      t("certificates.parse.noMatch")
                    )}
                  </DetailRow>
                </div>
              ) : null}
            </Modal.Body>
            <Modal.Footer>
              <Button variant="ghost" onPress={state.close}>
                {t("common.close")}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}

/* ============================== 应用到站点 ============================== */

/**
 * 应用证书弹窗：展示可选站点多选。
 * 注意：后端按证书域名自动匹配站点并全量应用（ApplyCertificateToSites），
 * 这里的多选用于标记意向站点，提交时一并传给后端（后端忽略该字段）。
 */
function ApplyToSitesModal({
  state,
  cert,
  sites,
  onApplied,
}: {
  state: ReturnType<typeof useOverlayState>;
  cert: Certificate;
  sites: SiteListItem[];
  onApplied: () => void;
}) {
  const { t } = useI18n();
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [saving, setSaving] = useState(false);

  function toggle(id: number) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleApply() {
    setSaving(true);
    try {
      const resp = await apiPost<CertificateApplyResponse>(
        `/certificates/${cert.id}/apply-to-sites`,
        { site_ids: Array.from(selected) },
      );
      const applied = resp.applied_sites ?? [];
      showSuccess(
        t("certificates.apply.success"),
        applied.length > 0
          ? t("certificates.apply.successHint", {
              count: applied.length,
              hosts: applied.map((s) => s.host).join(t("certificates.parse.listSeparator")),
            })
          : t("certificates.apply.noMatch"),
      );
      onApplied();
      state.close();
    } catch (err) {
      showError(t("certificates.apply.failed"), err instanceof ApiError ? err.message : undefined);
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
              <Modal.Heading>{t("certificates.apply.title")}</Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <div className="text-muted text-sm">
                {t("certificates.apply.description", {
                  name: cert.name,
                  domain: cert.domain ? t("certificates.apply.domainSuffix", { domain: cert.domain }) : "",
                })}
              </div>
              <ScrollShadow className="bg-surface max-h-60 rounded-xl border border-separator p-3">
                {sites.length === 0 ? (
                  <div className="text-muted py-4 text-center text-sm">
                    {t("certificates.apply.noSites")}
                  </div>
                ) : (
                  <div className="flex flex-col gap-2">
                    {sites.map((s) => (
                      <Checkbox key={s.id} isSelected={selected.has(s.id)} onChange={() => toggle(s.id)}>
                        <span className="text-sm">{s.host}</span>
                        <span className="text-muted ml-2 text-xs">
                          {s.tls_enabled ? "TLS" : "HTTP"} · {s.listener_summary || t("certificates.apply.noListener")}
                        </span>
                      </Checkbox>
                    ))}
                  </div>
                )}
              </ScrollShadow>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="ghost" onPress={state.close}>
                {t("common.cancel")}
              </Button>
              <Button variant="primary" isPending={saving} onPress={() => void handleApply()}>
                {t("certificates.apply.submit")}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}

/* ============================== ACME 签发 ============================== */

type AcmeApplyResponse = Certificate & {
  applied_sites?: { id: number; host: string }[];
};

function AcmeIssueModal({
  state,
  onSaved,
}: {
  state: ReturnType<typeof useOverlayState>;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const [domain, setDomain] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);

  async function handleApply() {
    if (!domain.trim()) {
      showError(t("certificates.acme.domainRequired"));
      return;
    }
    setSaving(true);
    try {
      const resp = await apiPost<AcmeApplyResponse>("/certificates/acme/apply", {
        domain: domain.trim(),
        email: email.trim(),
        name: name.trim(),
      });
      const applied = resp.applied_sites ?? [];
      showSuccess(
        t("certificates.acme.success"),
        applied.length > 0
          ? t("certificates.acme.appliedHint", {
              hosts: applied.map((s) => s.host).join(t("certificates.parse.listSeparator")),
            })
          : resp.domain,
      );
      onSaved();
      state.close();
    } catch (err) {
      showError(t("certificates.acme.failed"), err instanceof ApiError ? err.message : undefined);
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
              <Modal.Heading>{t("certificates.acme.issueTitle")}</Modal.Heading>
              <Modal.CloseTrigger />
            </Modal.Header>
            <Modal.Body className="gap-3">
              <div className="text-muted text-sm">{t("certificates.acme.issueDescription")}</div>
              <TextField aria-label={t("certificates.form.domain")} isRequired>
                <Input
                  placeholder={t("certificates.acme.domainPlaceholder")}
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("certificates.acme.email")}>
                <Input
                  placeholder={t("certificates.acme.emailPlaceholder")}
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </TextField>
              <TextField aria-label={t("certificates.form.name")}>
                <Input
                  placeholder={t("certificates.acme.namePlaceholder")}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </TextField>
            </Modal.Body>
            <Modal.Footer>
              <Button variant="ghost" onPress={state.close}>
                {t("common.cancel")}
              </Button>
              <Button variant="primary" isPending={saving} onPress={() => void handleApply()}>
                {t("certificates.acme.submit")}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}

export default CertificatesClient;
