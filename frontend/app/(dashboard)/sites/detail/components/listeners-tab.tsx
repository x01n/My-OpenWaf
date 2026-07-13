"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { IconPlus, IconPencil, IconTrash } from "@tabler/icons-react";
import {
  useSiteListeners,
  useListenerCreate,
  useListenerUpdate,
  useListenerDelete,
} from "@/hooks/use-api";
import { DataTable } from "@/components/data-table";
import type { Site } from "@/lib/types";

interface ListenersTabProps {
  site: Site;
}

interface ListenerFormData {
  bind: string;
  tls_enabled: boolean;
  enabled: boolean;
}

function ListenerDialog({
  open,
  onOpenChange,
  siteId,
  listener,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  siteId: number;
  listener?: any; // eslint-disable-line @typescript-eslint/no-explicit-any
}) {
  const { t } = useTranslation();
  const createListener = useListenerCreate();
  const updateListener = useListenerUpdate();
  const [form, setForm] = useState<ListenerFormData>({
    bind: listener?.bind || ":80",
    tls_enabled: listener?.tls_enabled || false,
    enabled: listener?.enabled ?? true,
  });

  const isEdit = !!listener;

  const handleSubmit = async () => {
    if (!form.bind.trim()) {
      toast.error(t("sites.detail.bindRequired"));
      return;
    }
    try {
      if (isEdit) {
        await updateListener.execute({ siteId, lid: listener.id, data: form });
      } else {
        await createListener.execute({ siteId, data: form });
      }
      toast.success(isEdit ? t("common.updateSuccess") : t("common.createSuccess"));
      onOpenChange(false);
    } catch {
      toast.error(t("common.operationFailed"));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? t("sites.detail.editListener") : t("sites.detail.addListener")}
          </DialogTitle>
          <DialogDescription>
            {t("sites.detail.listenerDialogDesc")}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <Label>{t("sites.detail.bindAddress")}</Label>
            <Input
              value={form.bind}
              onChange={(e) => setForm({ ...form, bind: e.target.value })}
              placeholder=":80"
            />
          </div>
          <div className="flex items-center justify-between">
            <Label>{t("sites.detail.tls")}</Label>
            <Switch
              checked={form.tls_enabled}
              onCheckedChange={(v) => setForm({ ...form, tls_enabled: v })}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label>{t("common.enabled")}</Label>
            <Switch
              checked={form.enabled}
              onCheckedChange={(v) => setForm({ ...form, enabled: v })}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={createListener.loading || updateListener.loading}
          >
            {t("common.confirm")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ListenersTab({ site }: ListenersTabProps) {
  const { t } = useTranslation();
  const { data: listeners } = useSiteListeners(site.id);
  const deleteListener = useListenerDelete();

  const [showDlg, setShowDlg] = useState(false);
  const [editingListener, setEditingListener] = useState<any>(null); // eslint-disable-line @typescript-eslint/no-explicit-any

  const handleDelete = async (lid: number) => {
    try {
      await deleteListener.execute({ siteId: site.id, lid });
      toast.success(t("common.deleteSuccess"));
    } catch {
      toast.error(t("common.operationFailed"));
    }
  };

  const columns = [
    { key: "bind", title: t("sites.detail.bindAddress") },
    { key: "network", title: t("sites.detail.network") },
    {
      key: "tls_enabled",
      title: t("sites.detail.tls"),
      render: (row: any) => ( // eslint-disable-line @typescript-eslint/no-explicit-any
        <Badge variant={row.tls_enabled ? "default" : "outline"} className="h-5 text-[10px]">
          {row.tls_enabled ? "HTTPS" : "HTTP"}
        </Badge>
      ),
    },
    {
      key: "enabled",
      title: t("common.status"),
      render: (row: any) => ( // eslint-disable-line @typescript-eslint/no-explicit-any
        <Badge variant={row.enabled ? "default" : "secondary"} className="h-5 text-[10px]">
          {row.enabled ? t("sites.detail.listenerEnabled") : t("sites.detail.listenerDisabled")}
        </Badge>
      ),
    },
    {
      key: "_actions",
      title: t("common.actions"),
      render: (row: any) => ( // eslint-disable-line @typescript-eslint/no-explicit-any
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => {
              setEditingListener(row);
              setShowDlg(true);
            }}
          >
            <IconPencil className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-destructive"
            onClick={() => handleDelete(row.id)}
          >
            <IconTrash className="h-3.5 w-3.5" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <CardTitle className="text-base">{t("sites.detail.listeners")}</CardTitle>
          <Button
            size="sm"
            className="h-8"
            onClick={() => {
              setEditingListener(null);
              setShowDlg(true);
            }}
          >
            <IconPlus className="mr-1 h-4 w-4" />
            {t("sites.detail.addListener")}
          </Button>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={listeners?.items || []}
            loading={!listeners}
            rowKey={(row) => row.id}
            emptyText={t("sites.detail.noListeners")}
          />
        </CardContent>
      </Card>

      {showDlg && (
        <ListenerDialog
          open={showDlg}
          onOpenChange={setShowDlg}
          siteId={site.id}
          listener={editingListener}
        />
      )}
    </div>
  );
}
