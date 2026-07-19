"use client";

import { useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { IconDeviceFloppy } from "@tabler/icons-react";
import {
  useAccessUserCreate,
  useAccessUserUpdate,
} from "@/hooks/use-api";
import type { AccessUser } from "@/lib/types";

interface AccessUserDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  siteId: number;
  /** 编辑目标用户，为 null 时表示新建。 */
  user?: AccessUser | null;
}

/**
 * 本地用户添加/编辑对话框。
 * 新建时需输入用户名+密码；编辑时仅可重置密码与切换启用状态（用户名不可改）。
 */
export function AccessUserDialog({
  open,
  onOpenChange,
  siteId,
  user,
}: AccessUserDialogProps) {
  const { t } = useTranslation();
  const isEdit = !!user;

  // 表单初值用 useState 懒初始化从 props 同步；父组件以 key 重挂载触发刷新，避免 effect 内 setState。
  const [username, setUsername] = useState(() => user?.username ?? "");
  const [password, setPassword] = useState("");
  const [enabled, setEnabled] = useState(() => user?.enabled ?? true);

  const createMutation = useAccessUserCreate();
  const updateMutation = useAccessUserUpdate();
  const loading = createMutation.loading || updateMutation.loading;

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      try {
        if (isEdit && user) {
          await updateMutation.execute({
            siteId,
            uid: user.id,
            data: {
              password: password.trim() || undefined,
              enabled,
            },
          });
          toast.success(t("sites.detail.userUpdated"));
        } else {
          if (!username.trim() || !password.trim()) {
            toast.error(t("common.operationFailed"));
            return;
          }
          await createMutation.execute({
            siteId,
            data: { username: username.trim(), password, enabled },
          });
          toast.success(t("sites.detail.userCreated"));
        }
        onOpenChange(false);
      } catch {
        toast.error(t("common.operationFailed"));
      }
    },
    [isEdit, user, username, password, enabled, siteId, createMutation, updateMutation, onOpenChange, t]
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? t("sites.detail.editUser") : t("sites.detail.addUser")}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label>{t("sites.detail.username")}</Label>
            <Input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={isEdit}
              placeholder={isEdit ? undefined : "admin"}
            />
            {isEdit && (
              <p className="text-xs text-muted-foreground">
                {t("common.detail")}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label>{t("sites.detail.userPassword")}</Label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t("sites.detail.userPasswordPlaceholder")}
            />
            {isEdit && (
              <p className="text-xs text-muted-foreground">
                {t("sites.detail.userPasswordPlaceholder")}
              </p>
            )}
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label>{t("sites.detail.userEnabled")}</Label>
            </div>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={loading}>
              <IconDeviceFloppy className="mr-1 h-4 w-4" />
              {loading ? t("common.saving") : t("common.save")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
