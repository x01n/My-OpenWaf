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
import { NumberField } from "@/components/ui/number-field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { IconDeviceFloppy } from "@tabler/icons-react";
import {
  useAccessPathRuleCreate,
  useAccessPathRuleUpdate,
} from "@/hooks/use-api";
import type { AccessPathRule } from "@/lib/types";

interface AccessPathRuleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  siteId: number;
  /** 编辑目标规则，为 null 时表示新建。 */
  rule?: AccessPathRule | null;
}

/**
 * 路径访问控制规则添加/编辑对话框。
 * 字段：路径、动作（require_auth/allow/deny）、优先级、启用状态。
 */
export function AccessPathRuleDialog({
  open,
  onOpenChange,
  siteId,
  rule,
}: AccessPathRuleDialogProps) {
  const { t } = useTranslation();
  const isEdit = !!rule;

  // 表单初值用 useState 懒初始化从 props 同步；父组件以 key 重挂载触发刷新，避免 effect 内 setState。
  const [path, setPath] = useState(() => rule?.path ?? "");
  const [action, setAction] = useState<AccessPathRule["action"]>(() => rule?.action ?? "require_auth");
  const [priority, setPriority] = useState(() => rule?.priority ?? 100);
  const [enabled, setEnabled] = useState(() => rule?.enabled ?? true);

  const createMutation = useAccessPathRuleCreate();
  const updateMutation = useAccessPathRuleUpdate();
  const loading = createMutation.loading || updateMutation.loading;

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!path.trim()) {
        toast.error(t("common.operationFailed"));
        return;
      }
      try {
        if (isEdit && rule) {
          await updateMutation.execute({
            siteId,
            rid: rule.id,
            data: { path: path.trim(), action, priority, enabled },
          });
          toast.success(t("sites.detail.pathRuleUpdated"));
        } else {
          await createMutation.execute({
            siteId,
            data: { path: path.trim(), action, priority, enabled },
          });
          toast.success(t("sites.detail.pathRuleCreated"));
        }
        onOpenChange(false);
      } catch {
        toast.error(t("common.operationFailed"));
      }
    },
    [isEdit, rule, path, action, priority, enabled, siteId, createMutation, updateMutation, onOpenChange, t]
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? t("sites.detail.editPathRule") : t("sites.detail.addPathRule")}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label>{t("sites.detail.path")}</Label>
            <Input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder={t("sites.detail.pathPlaceholder")}
            />
          </div>

          <div className="space-y-2">
            <Label>{t("sites.detail.pathRuleAction")}</Label>
            <Select value={action} onValueChange={(v) => setAction(v as AccessPathRule["action"])}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="require_auth">
                  {t("sites.detail.actionRequireAuth")}
                </SelectItem>
                <SelectItem value="allow">{t("sites.detail.actionAllow")}</SelectItem>
                <SelectItem value="deny">{t("sites.detail.actionDeny")}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>{t("sites.detail.providerPriority")}</Label>
            <NumberField.Root
              value={priority}
              onValueChange={(v) => setPriority(v ?? 100)}
              min={0}
              className="w-32"
            >
              <NumberField.Group>
                <NumberField.Decrement />
                <NumberField.Input />
                <NumberField.Increment />
              </NumberField.Group>
            </NumberField.Root>
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label>{t("common.enabled")}</Label>
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
