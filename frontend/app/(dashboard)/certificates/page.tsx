"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useCertificates, useCertificateMutation, useCertificateDelete } from "@/hooks/use-api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  IconPlus,
  IconTrash,
  IconCertificate,
  IconAlertTriangle,
} from "@tabler/icons-react";
import type { Certificate } from "@/lib/types";

export default function CertificatesPage() {
  const { t } = useTranslation();
  const { data, isLoading, mutate } = useCertificates();
  const { execute: mutateCert, loading: mutateLoading } = useCertificateMutation();
  const { execute: deleteCert, loading: deleteLoading } = useCertificateDelete();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<number | null>(null);
  const [form, setForm] = useState({
    name: "",
    cert_pem: "",
    key_pem: "",
    source: "manual" as "manual" | "acme" | "self_signed",
    domain: "",
    acme_email: "",
    auto_renew: false,
  });

  const certificates: Certificate[] = data || [];

  const daysUntilExpiry = (expiresAt?: string): number | null => {
    if (!expiresAt) return null;
    const diff = new Date(expiresAt).getTime() - Date.now();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  };

  const handleCreate = async () => {
    try {
      await mutateCert({ data: form });
      toast.success(t("certificates.createSuccess"));
      setDialogOpen(false);
      resetForm();
      mutate();
    } catch {
      toast.error(t("certificates.createFailed"));
    }
  };

  const confirmDelete = async () => {
    if (!deleteId) return;
    try {
      await deleteCert(deleteId);
      toast.success(t("common.deleteSuccess"));
      setDeleteId(null);
      mutate();
    } catch {
      toast.error(t("common.deleteFailed"));
    }
  };

  const resetForm = () => {
    setForm({
      name: "",
      cert_pem: "",
      key_pem: "",
      source: "manual",
      domain: "",
      acme_email: "",
      auto_renew: false,
    });
  };

  const columns = [
    {
      key: "name",
      title: t("certificates.name"),
      render: (row: Certificate) => (
        <div className="flex items-center gap-2">
          <IconCertificate className="h-4 w-4 text-primary" />
          <span className="font-medium">{row.name}</span>
        </div>
      ),
    },
    {
      key: "domain",
      title: t("certificates.domain"),
      render: (row: Certificate) => (
        <span className="text-sm">{row.domain || "-"}</span>
      ),
    },
    {
      key: "source",
      title: t("certificates.source"),
      width: "100px",
      render: (row: Certificate) => (
        <Badge variant="secondary">{row.source}</Badge>
      ),
    },
    {
      key: "expires_at",
      title: t("certificates.expiresAt"),
      width: "180px",
      render: (row: Certificate) => {
        const days = daysUntilExpiry(row.expires_at);
        if (!row.expires_at) return <span className="text-muted-foreground">-</span>;
        return (
          <div className="flex items-center gap-2">
            <span className="text-sm">
              {row.expires_at.slice(0, 10)}
            </span>
            {days !== null && days <= 30 && days > 0 && (
              <Badge variant="destructive" className="flex items-center gap-1">
                <IconAlertTriangle className="h-3 w-3" />
                {t("certificates.expiringDays", { days })}
              </Badge>
            )}
            {days !== null && days <= 0 && (
              <Badge variant="destructive">
                {t("certificates.expired")}
              </Badge>
            )}
          </div>
        );
      },
    },
    {
      key: "auto_renew",
      title: t("certificates.autoRenew"),
      width: "100px",
      render: (row: Certificate) => (
        <Badge variant={row.auto_renew ? "default" : "secondary"}>
          {row.auto_renew ? t("common.enabled") : t("common.disabled")}
        </Badge>
      ),
    },
    {
      key: "action",
      title: t("common.action"),
      width: "80px",
      render: (row: Certificate) => (
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setDeleteId(row.id)}
          title={t("common.delete")}
        >
          <IconTrash className="h-4 w-4 text-destructive" />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            {t("certificates.title")}
          </h1>
          <p className="text-sm text-muted-foreground">
            {t("certificates.description")}
          </p>
        </div>
        <Button onClick={() => setDialogOpen(true)}>
          <IconPlus className="h-4 w-4" />
          {t("certificates.add")}
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={certificates}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("certificates.empty")}
      />

      <Dialog open={dialogOpen} onOpenChange={(open) => {
        setDialogOpen(open);
        if (!open) resetForm();
      }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("certificates.addTitle")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t("certificates.name")}</Label>
              <Input
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder={t("certificates.namePlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("certificates.source")}</Label>
              <Select
                value={form.source}
                onValueChange={(v) =>
                  setForm((f) => ({ ...f, source: v as "manual" | "acme" | "self_signed" }))
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="manual">{t("certificates.sourceManual")}</SelectItem>
                  <SelectItem value="acme">{t("certificates.sourceAcme")}</SelectItem>
                  <SelectItem value="self_signed">{t("certificates.sourceSelfSigned")}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t("certificates.domain")}</Label>
              <Input
                value={form.domain}
                onChange={(e) => setForm((f) => ({ ...f, domain: e.target.value }))}
                placeholder={t("certificates.domainPlaceholder")}
              />
            </div>
            {form.source === "manual" && (
              <>
                <div className="space-y-2">
                  <Label>{t("certificates.certPem")}</Label>
                  <Textarea
                    value={form.cert_pem}
                    onChange={(e) => setForm((f) => ({ ...f, cert_pem: e.target.value }))}
                    placeholder={t("certificates.certPemPlaceholder")}
                    rows={5}
                    className="font-mono text-xs"
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t("certificates.keyPem")}</Label>
                  <Textarea
                    value={form.key_pem}
                    onChange={(e) => setForm((f) => ({ ...f, key_pem: e.target.value }))}
                    placeholder={t("certificates.keyPemPlaceholder")}
                    rows={5}
                    className="font-mono text-xs"
                  />
                </div>
              </>
            )}
            {form.source === "acme" && (
              <div className="space-y-2">
                <Label>{t("certificates.acmeEmail")}</Label>
                <Input
                  value={form.acme_email}
                  onChange={(e) => setForm((f) => ({ ...f, acme_email: e.target.value }))}
                  placeholder={t("certificates.acmeEmailPlaceholder")}
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleCreate} disabled={mutateLoading || !form.name}>
              {mutateLoading ? t("common.submitting") : t("common.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleteId}
        onOpenChange={(open) => !open && setDeleteId(null)}
        title={t("common.confirmDeleteTitle")}
        description={t("certificates.deleteConfirm")}
        confirmText={t("common.delete")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  );
}
