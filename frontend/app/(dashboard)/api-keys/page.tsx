"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useApiKeys, useApiKeyCreate, useApiKeyDelete } from "@/hooks/use-api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { IconPlus, IconTrash, IconCopy, IconKey } from "@tabler/icons-react";
import type { AdminAPIKey } from "@/lib/types";

function maskKey(name: string): string {
  if (name.length <= 8) return name;
  return `${name.slice(0, 4)}****${name.slice(-4)}`;
}

function formatTime(t: string | undefined | null): string {
  if (!t) return "-";
  return new Date(t).toLocaleString();
}

export default function ApiKeysPage() {
  const { t } = useTranslation();
  const { data, isLoading, mutate } = useApiKeys();
  const { execute: createKey, loading: createLoading } = useApiKeyCreate();
  const { execute: deleteKey, loading: deleteLoading } = useApiKeyDelete();

  const [createOpen, setCreateOpen] = useState(false);
  const [resultOpen, setResultOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<number | null>(null);
  const [name, setName] = useState("");
  const [createdToken, setCreatedToken] = useState("");

  const keys: AdminAPIKey[] = data || [];

  const handleCreate = async () => {
    if (!name.trim()) return;
    try {
      const result = await createKey({ name: name.trim() });
      setCreatedToken(result.token);
      setCreateOpen(false);
      setResultOpen(true);
      setName("");
      mutate();
    } catch {
      toast.error(t("apiKeys.createFailed"));
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(createdToken);
      toast.success(t("apiKeys.copied"));
    } catch {
      // fallback
      const el = document.createElement("textarea");
      el.value = createdToken;
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
      toast.success(t("apiKeys.copied"));
    }
  };

  const confirmDelete = async () => {
    if (!deleteId) return;
    try {
      await deleteKey(deleteId);
      toast.success(t("common.deleteSuccess"));
      setDeleteId(null);
      mutate();
    } catch {
      toast.error(t("common.deleteFailed"));
    }
  };

  const columns = [
    {
      key: "name",
      title: t("apiKeys.name"),
      render: (row: AdminAPIKey) => (
        <div className="flex items-center gap-2">
          <IconKey className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.name}</span>
        </div>
      ),
    },
    {
      key: "key_preview",
      title: t("apiKeys.key"),
      render: (row: AdminAPIKey) => (
        <code className="rounded bg-muted px-2 py-0.5 text-xs">
          owaf_{maskKey(String(row.id))}
        </code>
      ),
    },
    {
      key: "created_at",
      title: t("apiKeys.createdAt"),
      render: (row: AdminAPIKey) => (
        <span className="text-sm text-muted-foreground">
          {formatTime(row.created_at)}
        </span>
      ),
    },
    {
      key: "last_used_at",
      title: t("apiKeys.lastUsedAt"),
      render: (row: AdminAPIKey) => (
        <span className="text-sm text-muted-foreground">
          {row.last_used_at ? formatTime(row.last_used_at) : t("apiKeys.never")}
        </span>
      ),
    },
    {
      key: "actions",
      title: t("common.action"),
      width: "80px",
      render: (row: AdminAPIKey) => (
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => setDeleteId(row.id)}
          className="text-destructive hover:text-destructive"
        >
          <IconTrash className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("apiKeys.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">{t("apiKeys.description")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={() => setCreateOpen(true)}>
            <IconPlus className="mr-2 h-4 w-4" />
            {t("apiKeys.create")}
          </Button>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={keys}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("apiKeys.empty")}
      />

      {/* 创建密钥对话框 */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("apiKeys.create")}</DialogTitle>
            <DialogDescription>{t("apiKeys.description")}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="apikey-name">{t("apiKeys.name")}</Label>
              <Input
                id="apikey-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t("apiKeys.namePlaceholder")}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleCreate();
                }}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleCreate} disabled={createLoading || !name.trim()}>
              {createLoading ? t("common.submitting") : t("common.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 密钥展示对话框（仅显示一次） */}
      <Dialog open={resultOpen} onOpenChange={setResultOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("apiKeys.createSuccess")}</DialogTitle>
            <DialogDescription>{t("apiKeys.copyWarning")}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded border bg-muted p-3 text-sm font-mono break-all">
                {createdToken}
              </code>
              <Button variant="outline" size="icon-sm" onClick={handleCopy}>
                <IconCopy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => setResultOpen(false)}>
              {t("common.close")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 删除确认 */}
      <ConfirmDialog
        open={deleteId !== null}
        onOpenChange={(open) => !open && setDeleteId(null)}
        title={t("common.confirm")}
        description={t("apiKeys.deleteConfirm")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  );
}
