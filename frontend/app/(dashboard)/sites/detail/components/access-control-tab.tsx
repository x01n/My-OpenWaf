"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  IconLock,
  IconPlus,
  IconTrash,
  IconDeviceFloppy,
  IconUsers,
  IconKey,
  IconRoute,
} from "@tabler/icons-react";
import { useSiteMutation } from "@/hooks/use-api";
import type { Site } from "@/lib/types";

interface AccessControlTabProps {
  site: Site;
}

export function AccessControlTab({ site }: AccessControlTabProps) {
  const { t } = useTranslation();
  const updateSite = useSiteMutation();

  const [accessEnabled, setAccessEnabled] = useState(false);
  const [sharedPassword, setSharedPassword] = useState("");
  const [showPasswordInput, setShowPasswordInput] = useState(false);
  const [saving, setSaving] = useState(false);

  const handleToggleAccess = async (enabled: boolean) => {
    setAccessEnabled(enabled);
    // TODO: 后端 API 就绪后实际保存
    toast.success(t("common.saveSuccess"));
  };

  const handleSavePassword = async () => {
    if (!sharedPassword.trim()) return;
    setSaving(true);
    try {
      // TODO: 后端 API 就绪后实际保存
      toast.success(t("common.saveSuccess"));
      setSharedPassword("");
      setShowPasswordInput(false);
    } catch {
      toast.error(t("common.operationFailed"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* 总开关 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconLock className="h-4 w-4" />
            {t("sites.detail.accessControl")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label className="text-sm font-medium">{t("sites.detail.enableAccessControl")}</Label>
              <p className="text-xs text-muted-foreground">{t("sites.detail.accessControlDesc")}</p>
            </div>
            <Switch checked={accessEnabled} onCheckedChange={handleToggleAccess} />
          </div>
        </CardContent>
      </Card>

      {/* 共享密码 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconKey className="h-4 w-4" />
            {t("sites.detail.sharedPassword")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-3">
            <Badge variant="outline" className="text-xs">
              {t("sites.detail.passwordNotSet")}
            </Badge>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={() => setShowPasswordInput(!showPasswordInput)}
            >
              {t("sites.detail.setPassword")}
            </Button>
          </div>

          {showPasswordInput && (
            <div className="flex items-center gap-2">
              <Input
                type="password"
                value={sharedPassword}
                onChange={(e) => setSharedPassword(e.target.value)}
                placeholder={t("sites.detail.enterPassword")}
                className="flex-1"
              />
              <Button size="sm" onClick={handleSavePassword} disabled={saving || !sharedPassword.trim()}>
                <IconDeviceFloppy className="mr-1 h-3.5 w-3.5" />
                {t("common.save")}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 认证提供方 */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-base">
              <IconUsers className="h-4 w-4" />
              {t("sites.detail.authProviders")}
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">
              <IconPlus className="mr-1 h-3.5 w-3.5" />
              {t("common.add")}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border">
            <div className="flex items-center bg-muted/50 px-4 py-2 text-xs text-muted-foreground">
              <span className="flex-1">{t("common.name")}</span>
              <span className="w-24">{t("common.type")}</span>
              <span className="w-20">{t("rules.priority")}</span>
              <span className="w-20 text-right">{t("common.actions")}</span>
            </div>
            <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
              {t("sites.detail.noAuthProviders")}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 本地用户 */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-base">
              <IconUsers className="h-4 w-4" />
              {t("sites.detail.localUsers")}
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">
              <IconPlus className="mr-1 h-3.5 w-3.5" />
              {t("common.add")}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border">
            <div className="flex items-center bg-muted/50 px-4 py-2 text-xs text-muted-foreground">
              <span className="flex-1">{t("sites.detail.username")}</span>
              <span className="w-24">{t("common.status")}</span>
              <span className="w-20 text-right">{t("common.actions")}</span>
            </div>
            <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
              {t("sites.detail.noLocalUsers")}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 路径规则 */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-base">
              <IconRoute className="h-4 w-4" />
              {t("sites.detail.pathRules")}
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">
              <IconPlus className="mr-1 h-3.5 w-3.5" />
              {t("common.add")}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border">
            <div className="flex items-center bg-muted/50 px-4 py-2 text-xs text-muted-foreground">
              <span className="flex-1">{t("sites.detail.path")}</span>
              <span className="w-24">{t("common.actions")}</span>
              <span className="w-20">{t("rules.priority")}</span>
              <span className="w-20 text-right">{t("common.actions")}</span>
            </div>
            <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
              {t("sites.detail.noPathRules")}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
